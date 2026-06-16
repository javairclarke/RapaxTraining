#!/usr/bin/env python3
"""
Unifi Device SNMP Poller Daemon
===============================

Collects Unifi-specific SNMP metrics from Ubiquiti network devices including:
    - Memory statistics (total, free, buffer, cache)
    - Load averages (1min, 5min, 15min)
    - Temperature sensors (CPU, board, PHY - if available)
    - Fan status (speed, duty level - if available)

This poller complements the core network-collection snmp-agentd by collecting
Ubiquiti-specific OIDs from the FROGFOOT-RESOURCES-MIB that are not covered
by standard MIB-2 polling.

Metrics are sent to Redis streams for processing by core-collection.

Author: Rapax Integration
"""

import os
import sys
import time
import threading
import argparse
import requests
import queue
import socket
from datetime import datetime
from logging.handlers import RotatingFileHandler
from urllib3.exceptions import InsecureRequestWarning

requests.urllib3.disable_warnings(InsecureRequestWarning)

# Environment setup
RAPAX_HOME = os.getenv('RAPAXHOME', '/opt/rapax')
sys.path.insert(0, os.path.join(RAPAX_HOME, 'lib'))

# Import third-party modules
try:
    from pysnmp.hlapi import *
except ImportError:
    print("Error: pysnmp not installed. Run: pip install pysnmp==4.4.12")
    sys.exit(1)

# Import rapax library
import rapax

SOURCE = 'unifi-snmp-pollerd'


class UnifiSNMPPoller:
    """SNMP poller for Ubiquiti/Unifi devices."""

    # Ubiquiti enterprise OID prefix
    UBIQUITI_ENTERPRISE_OID = '1.3.6.1.4.1.41112'

    # FROGFOOT-RESOURCES-MIB OIDs (Ubiquiti uses Frogfoot enterprise 10002)
    FROGFOOT_OIDS = {
        # Memory metrics
        'memTotal': '1.3.6.1.4.1.10002.1.1.1.1.1.0',      # Total memory (KB)
        'memFree': '1.3.6.1.4.1.10002.1.1.1.1.2.0',       # Free memory (KB)
        'memBuffer': '1.3.6.1.4.1.10002.1.1.1.1.3.0',     # Buffer memory (KB)
        'memCache': '1.3.6.1.4.1.10002.1.1.1.1.4.0',      # Cache memory (KB)
        # Load averages
        'loadAvg1': '1.3.6.1.4.1.10002.1.1.1.4.2.1.3.1',  # 1-minute load average
        'loadAvg5': '1.3.6.1.4.1.10002.1.1.1.4.2.1.3.2',  # 5-minute load average
        'loadAvg15': '1.3.6.1.4.1.10002.1.1.1.4.2.1.3.3', # 15-minute load average
    }

    # Temperature OIDs (may not be available on all devices)
    TEMPERATURE_OIDS = {
        'cpuTemp': '1.3.6.1.4.1.4413.1.1.43.1.8.1.5.1.0',    # CPU Temperature
        'boardTemp': '1.3.6.1.4.1.4413.1.1.43.1.15.1.2',     # Board Temperature
        'phyTemp': '1.3.6.1.4.1.4413.1.1.43.1.15.1.3',       # PHY Temperature
        'hostTemp': '1.3.6.1.4.1.41112.1.4.8.4',             # Ubiquiti Host Temperature
    }

    # Fan OIDs (may not be available on all devices)
    FAN_OIDS = {
        'fanSpeed': '1.3.6.1.4.1.4413.1.1.43.1.6.1.4',       # Fan Speed (RPM)
        'fanDutyLevel': '1.3.6.1.4.1.4413.1.1.43.1.6.1.5',   # Fan Duty Level (%)
    }

    # Standard MIB-2 OIDs for device identification
    SYSTEM_OIDS = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysObjectID': '1.3.6.1.2.1.1.2.0',
        'sysName': '1.3.6.1.2.1.1.5.0',
    }

    def __init__(self, args):
        self.config = rapax.load_config()
        self.logger = rapax.setup_logging()
        self._setup_file_logging()

        self.snmp_timeout = args.snmp_timeout
        self.poll_interval = args.poll_interval
        self.component_id = args.component_id
        self.config_update_interval = args.config_update_interval
        self.worker_threads = args.worker_threads

        self.devices = {}
        self.poll_queue = queue.Queue()
        self.config_lock = threading.Lock()
        self.running = True
        self.hostname = os.uname().nodename

        # Cache for device SNMP capabilities (which OIDs are available)
        self.device_capabilities = {}
        self.capabilities_lock = threading.Lock()

        # Cache for Unifi-capable devices (devices that respond to FROGFOOT MIB)
        # Key: IP address, Value: True (capable) or False (not capable)
        self.unifi_capable_cache = {}
        self.unifi_capable_lock = threading.Lock()

        self.logger.info(f"[Unifi SNMP] Initializing with {self.worker_threads} workers")
        self.logger.info(f"[Unifi SNMP] Poll interval: {self.poll_interval}s, Component ID: {self.component_id}")

    def _setup_file_logging(self):
        """Setup file logging for the daemon."""
        import logging
        log_dir = os.path.join(RAPAX_HOME, 'logs')
        os.makedirs(log_dir, exist_ok=True)

        log_file = os.path.join(log_dir, 'unifi-device-snmp-pollerd.log')
        file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def _is_valid_ip(self, ip):
        """Validate IP address format."""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def _probe_unifi_capable(self, mgmt_ip, community):
        """
        Probe device to determine if it responds to FROGFOOT MIB.
        This is the definitive test for Unifi-capable devices.
        Returns True if device responds to memTotal OID, False otherwise.
        """
        # Check cache first
        with self.unifi_capable_lock:
            if mgmt_ip in self.unifi_capable_cache:
                return self.unifi_capable_cache[mgmt_ip]

        # Probe FROGFOOT memTotal OID - if it responds, device is Unifi-capable
        result = self.snmp_get(mgmt_ip, community, self.FROGFOOT_OIDS['memTotal'], self.snmp_timeout)
        is_capable = result is not None

        # Cache the result (both positive and negative to avoid re-probing)
        with self.unifi_capable_lock:
            self.unifi_capable_cache[mgmt_ip] = is_capable

        return is_capable

    def _has_snmp_credentials(self, device):
        """Check if device has SNMP community string configured."""
        security_info = device.get('securityInformation', [])
        if not security_info:
            return False

        # Look for SNMP community string
        for cred in security_info:
            if cred.get('type') == 'snmp' or 'string' in cred.get('data', {}):
                return True

        return len(security_info) > 0

    def _get_community_string(self, device):
        """Extract SNMP community string from device security information."""
        security_info = device.get('securityInformation', [])
        for cred in security_info:
            data = cred.get('data', {})
            if 'string' in data:
                return data['string']
        return 'public'  # Default fallback

    def get_devices_from_opensearch(self):
        """
        Fetch devices from OpenSearch and probe for Unifi capability.

        New approach: Instead of complex vendor/sysDescr detection, we probe ALL
        devices with SNMP credentials using the FROGFOOT memTotal OID. If a device
        responds, it's Unifi-capable and will be polled.
        """
        try:
            opensearch_config = self.config['historical']['opensearch']
            url = f"{opensearch_config['url']}/devices-*/_search"

            query = {
                "query": {"match_all": {}},
                "sort": [{"lastSeen": {"order": "desc"}}],
                "size": 10000
            }

            auth = (opensearch_config['username'], opensearch_config['password'])
            headers = {'Content-Type': 'application/json'}

            self.logger.debug(f"[Unifi SNMP] Querying OpenSearch: {url}")
            response = requests.post(url, json=query, auth=auth, headers=headers, verify=False, timeout=30)
            response.raise_for_status()

            data = response.json()
            devices_raw = data.get('hits', {}).get('hits', [])

            self.logger.info(f"[Unifi SNMP] Retrieved {len(devices_raw)} total devices from OpenSearch")

            devices_by_ip = {}
            snmp_devices_count = 0
            unifi_capable_count = 0
            newly_discovered = 0
            cached_capable = 0
            not_capable = 0

            for device_hit in devices_raw:
                device = device_hit['_source']

                device_name = device.get('deviceName', '').strip().strip('"')
                if not device_name:
                    continue

                mgmt_ip = device.get('ManagementIpAddress', '').strip()
                if not mgmt_ip or not self._is_valid_ip(mgmt_ip):
                    continue

                # Skip devices without SNMP credentials
                if not self._has_snmp_credentials(device):
                    continue

                snmp_devices_count += 1
                community = self._get_community_string(device)

                # Check cache first
                with self.unifi_capable_lock:
                    cached_result = self.unifi_capable_cache.get(mgmt_ip)

                if cached_result is True:
                    # Already known to be Unifi-capable
                    cached_capable += 1
                    is_unifi_capable = True
                elif cached_result is False:
                    # Already known to NOT be Unifi-capable, skip
                    not_capable += 1
                    continue
                else:
                    # Not cached yet - probe the device
                    community_masked = community[:2] + '***' if len(community) > 2 else '***'
                    self.logger.info(f"[Unifi SNMP] Probing {device_name} ({mgmt_ip}) community={community_masked}")
                    is_unifi_capable = self._probe_unifi_capable(mgmt_ip, community)

                    if is_unifi_capable:
                        newly_discovered += 1
                        self.logger.info(f"[Unifi SNMP] Discovered Unifi-capable device: {device_name} ({mgmt_ip})")
                    else:
                        not_capable += 1
                        self.logger.info(f"[Unifi SNMP] {device_name} ({mgmt_ip}) - no FROGFOOT response")
                        continue

                if not is_unifi_capable:
                    continue

                unifi_capable_count += 1

                # Use most recent record for this IP
                last_seen = device.get('lastSeen', '')
                if mgmt_ip not in devices_by_ip or last_seen > devices_by_ip[mgmt_ip].get('lastSeen', ''):
                    devices_by_ip[mgmt_ip] = {
                        'deviceName': device_name,
                        'ManagementIpAddress': mgmt_ip,
                        'lastSeen': last_seen,
                        'deviceLocation': device.get('deviceLocation', ''),
                        'vendor': device.get('vendor', 'Ubiquiti'),
                        'deviceCategory': device.get('deviceCategory', ''),
                        'sysDescr': device.get('sysDescr', ''),
                        'securityInformation': device.get('securityInformation', []),
                    }

            self.logger.info(f"[Unifi SNMP] Device discovery summary:")
            self.logger.info(f"[Unifi SNMP]   Total SNMP devices: {snmp_devices_count}")
            self.logger.info(f"[Unifi SNMP]   Unifi-capable (cached): {cached_capable}")
            self.logger.info(f"[Unifi SNMP]   Unifi-capable (newly discovered): {newly_discovered}")
            self.logger.info(f"[Unifi SNMP]   Not Unifi-capable: {not_capable}")
            self.logger.info(f"[Unifi SNMP]   Total devices to poll: {len(devices_by_ip)}")

            return devices_by_ip

        except requests.exceptions.RequestException as e:
            self.logger.error(f"[Unifi SNMP] Failed to fetch devices from OpenSearch: {e}")
            return {}
        except Exception as e:
            self.logger.error(f"[Unifi SNMP] Unexpected error fetching devices: {e}")
            return {}

    def update_device_configuration(self):
        """Update device configuration from OpenSearch."""
        self.logger.info("[Unifi SNMP] Updating device configuration")

        new_devices = self.get_devices_from_opensearch()

        with self.config_lock:
            self.devices = new_devices

        self.logger.info(f"[Unifi SNMP] Device configuration updated: {len(self.devices)} Unifi devices")

    def snmp_get(self, host, community, oid, timeout_ms):
        """Perform SNMP GET operation."""
        try:
            timeout_s = timeout_ms / 1000.0
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(SnmpEngine(),
                       CommunityData(community),
                       UdpTransportTarget((host, 161), timeout=timeout_s, retries=1),
                       ContextData(),
                       ObjectType(ObjectIdentity(oid)))
            )

            if errorIndication:
                return None
            elif errorStatus:
                return None
            else:
                for oid_result, val in varBinds:
                    # Check for NoSuchObject or NoSuchInstance
                    val_str = str(val)
                    if 'noSuch' in val_str:
                        return None
                    # Return the value even if empty - a valid SNMP response means the OID exists
                    return val
        except Exception:
            return None

    def snmp_bulk_get(self, host, community, oid_list, timeout_ms):
        """Perform SNMP bulk GET operation."""
        try:
            timeout_s = timeout_ms / 1000.0
            object_types = [ObjectType(ObjectIdentity(oid)) for oid in oid_list]

            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(SnmpEngine(),
                       CommunityData(community),
                       UdpTransportTarget((host, 161), timeout=timeout_s, retries=1),
                       ContextData(),
                       *object_types)
            )

            if errorIndication or errorStatus:
                return {}

            results = {}
            for oid, val in varBinds:
                val_str = str(val)
                if 'noSuch' not in val_str:
                    results[str(oid)] = val
            return results
        except Exception:
            return {}

    def _probe_device_capabilities(self, device):
        """
        Probe device to determine which OIDs are available.
        Results are cached to avoid repeated probing.
        """
        device_name = device['deviceName']
        mgmt_ip = device['ManagementIpAddress']

        with self.capabilities_lock:
            if device_name in self.device_capabilities:
                return self.device_capabilities[device_name]

        community = self._get_community_string(device)
        capabilities = {
            'frogfoot': False,
            'temperature': [],
            'fan': [],
        }

        self.logger.info(f"[Unifi SNMP] Probing capabilities for {device_name} ({mgmt_ip})")

        # Test FROGFOOT memory OID
        result = self.snmp_get(mgmt_ip, community, self.FROGFOOT_OIDS['memTotal'], self.snmp_timeout)
        if result is not None:
            capabilities['frogfoot'] = True

        # Test temperature OIDs
        for name, oid in self.TEMPERATURE_OIDS.items():
            result = self.snmp_get(mgmt_ip, community, oid, self.snmp_timeout)
            if result is not None:
                capabilities['temperature'].append(name)

        # Test fan OIDs
        for name, oid in self.FAN_OIDS.items():
            result = self.snmp_get(mgmt_ip, community, oid, self.snmp_timeout)
            if result is not None:
                capabilities['fan'].append(name)

        # Log capability summary
        cap_summary = []
        if capabilities['frogfoot']:
            cap_summary.append("FROGFOOT(memory,load)")
        if capabilities['temperature']:
            cap_summary.append(f"Temp({','.join(capabilities['temperature'])})")
        if capabilities['fan']:
            cap_summary.append(f"Fan({','.join(capabilities['fan'])})")

        if cap_summary:
            self.logger.info(f"[Unifi SNMP] {device_name}: Available OIDs: {', '.join(cap_summary)}")
        else:
            self.logger.warning(f"[Unifi SNMP] {device_name}: No Unifi-specific OIDs available (SNMP timeout or unsupported)")

        with self.capabilities_lock:
            self.device_capabilities[device_name] = capabilities

        return capabilities

    def collect_memory_metrics(self, device, timestamp, community):
        """Collect memory metrics from FROGFOOT-MIB."""
        device_name = device['deviceName']
        mgmt_ip = device['ManagementIpAddress']

        # Collect all memory OIDs
        oids = [
            self.FROGFOOT_OIDS['memTotal'],
            self.FROGFOOT_OIDS['memFree'],
            self.FROGFOOT_OIDS['memBuffer'],
            self.FROGFOOT_OIDS['memCache'],
        ]

        results = self.snmp_bulk_get(mgmt_ip, community, oids, self.snmp_timeout)
        if not results:
            return

        try:
            mem_total = int(results.get(self.FROGFOOT_OIDS['memTotal'], 0))
            mem_free = int(results.get(self.FROGFOOT_OIDS['memFree'], 0))
            mem_buffer = int(results.get(self.FROGFOOT_OIDS['memBuffer'], 0))
            mem_cache = int(results.get(self.FROGFOOT_OIDS['memCache'], 0))

            if mem_total > 0:
                # Calculate memory usage percentage
                mem_used = mem_total - mem_free - mem_buffer - mem_cache
                mem_usage_pct = (mem_used / mem_total) * 100.0

                # Store metrics
                self._store_metric(timestamp, device_name, "Memory Usage%", mem_usage_pct, device, mgmt_ip)
                self._store_metric(timestamp, device_name, "Memory Total (KB)", mem_total, device, mgmt_ip)
                self._store_metric(timestamp, device_name, "Memory Free (KB)", mem_free, device, mgmt_ip)
                self._store_metric(timestamp, device_name, "Memory Buffer (KB)", mem_buffer, device, mgmt_ip)
                self._store_metric(timestamp, device_name, "Memory Cache (KB)", mem_cache, device, mgmt_ip)

        except (ValueError, TypeError, ZeroDivisionError) as e:
            self.logger.debug(f"[Unifi SNMP] Error processing memory metrics for {device_name}: {e}")

    def collect_load_metrics(self, device, timestamp, community):
        """Collect load average metrics from FROGFOOT-MIB."""
        device_name = device['deviceName']
        mgmt_ip = device['ManagementIpAddress']

        # Collect load average OIDs
        oids = [
            self.FROGFOOT_OIDS['loadAvg1'],
            self.FROGFOOT_OIDS['loadAvg5'],
            self.FROGFOOT_OIDS['loadAvg15'],
        ]

        results = self.snmp_bulk_get(mgmt_ip, community, oids, self.snmp_timeout)
        if not results:
            return

        try:
            # Load averages may be returned as strings or integers
            for name, oid, display_name in [
                ('loadAvg1', self.FROGFOOT_OIDS['loadAvg1'], 'Load Average (1min)'),
                ('loadAvg5', self.FROGFOOT_OIDS['loadAvg5'], 'Load Average (5min)'),
                ('loadAvg15', self.FROGFOOT_OIDS['loadAvg15'], 'Load Average (15min)'),
            ]:
                value = results.get(oid)
                if value is not None:
                    # Convert to float, handling string format
                    load_val = float(str(value))
                    self._store_metric(timestamp, device_name, display_name, load_val, device, mgmt_ip)

        except (ValueError, TypeError) as e:
            self.logger.debug(f"[Unifi SNMP] Error processing load metrics for {device_name}: {e}")

    def collect_temperature_metrics(self, device, timestamp, community, available_temps):
        """Collect temperature metrics (graceful skip if unavailable)."""
        device_name = device['deviceName']
        mgmt_ip = device['ManagementIpAddress']

        temp_display_names = {
            'cpuTemp': 'CPU Temperature (C)',
            'boardTemp': 'Board Temperature (C)',
            'phyTemp': 'PHY Temperature (C)',
            'hostTemp': 'Host Temperature (C)',
        }

        for temp_name in available_temps:
            oid = self.TEMPERATURE_OIDS.get(temp_name)
            if not oid:
                continue

            result = self.snmp_get(mgmt_ip, community, oid, self.snmp_timeout)
            if result is not None:
                try:
                    temp_val = float(str(result))
                    display_name = temp_display_names.get(temp_name, f'{temp_name} (C)')
                    self._store_metric(timestamp, device_name, display_name, temp_val, device, mgmt_ip)
                except (ValueError, TypeError):
                    pass

    def collect_fan_metrics(self, device, timestamp, community, available_fans):
        """Collect fan metrics (graceful skip if unavailable)."""
        device_name = device['deviceName']
        mgmt_ip = device['ManagementIpAddress']

        fan_display_names = {
            'fanSpeed': 'Fan Speed (RPM)',
            'fanDutyLevel': 'Fan Duty Level%',
        }

        for fan_name in available_fans:
            oid = self.FAN_OIDS.get(fan_name)
            if not oid:
                continue

            result = self.snmp_get(mgmt_ip, community, oid, self.snmp_timeout)
            if result is not None:
                try:
                    fan_val = float(str(result))
                    display_name = fan_display_names.get(fan_name, fan_name)
                    self._store_metric(timestamp, device_name, display_name, fan_val, device, mgmt_ip)
                except (ValueError, TypeError):
                    pass

    def _store_metric(self, timestamp, device_name, metric_name, value, device, mgmt_ip):
        """Store a metric using the rapax send_message function."""
        try:
            metric_data = {
                "@timestamp": timestamp,
                "deviceName": device_name,
                "metricName": metric_name,
                "value": float(value),
                "tags": {
                    "componentId": self.component_id,
                    "managementIP": mgmt_ip,
                    "location": device.get('deviceLocation', ''),
                    "source": SOURCE,
                    "vendor": device.get('vendor', 'Ubiquiti'),
                    "category": device.get('deviceCategory', '')
                }
            }

            rapax.send_message(self.logger, 'stats', metric_data)

        except Exception as e:
            self.logger.error(f"[Unifi SNMP] Error storing metric {metric_name} for {device_name}: {e}")

    def poll_device(self, device, timestamp):
        """Poll a single Unifi device for all metrics."""
        device_name = device['deviceName']
        mgmt_ip = device['ManagementIpAddress']
        community = self._get_community_string(device)

        # Probe device capabilities (cached after first probe)
        capabilities = self._probe_device_capabilities(device)

        if not capabilities['frogfoot'] and not capabilities['temperature'] and not capabilities['fan']:
            return

        # Track metrics collected
        metrics_collected = []

        # Collect metrics based on capabilities
        if capabilities['frogfoot']:
            self.collect_memory_metrics(device, timestamp, community)
            self.collect_load_metrics(device, timestamp, community)
            metrics_collected.extend(['memory', 'load'])

        if capabilities['temperature']:
            self.collect_temperature_metrics(device, timestamp, community, capabilities['temperature'])
            metrics_collected.append(f"temp({len(capabilities['temperature'])})")

        if capabilities['fan']:
            self.collect_fan_metrics(device, timestamp, community, capabilities['fan'])
            metrics_collected.append(f"fan({len(capabilities['fan'])})")

        self.logger.info(f"[Unifi SNMP] {device_name}: Collected {', '.join(metrics_collected)}")

    def poll_worker(self):
        """Worker thread for polling devices."""
        while self.running:
            work_item = None
            try:
                work_item = self.poll_queue.get(timeout=1)
                if work_item is None:
                    self.poll_queue.task_done()
                    break

                device = work_item['device']
                timestamp = work_item['timestamp']

                self.poll_device(device, timestamp)
                self.poll_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"[Unifi SNMP] Error in poll worker: {e}")
                if work_item is not None:
                    try:
                        self.poll_queue.task_done()
                    except ValueError:
                        pass

    def get_aligned_timestamp(self, interval):
        """Get timestamp aligned to the specified interval."""
        now = time.time()
        aligned = (now // interval) * interval
        return datetime.fromtimestamp(aligned).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    def initiate_poll_cycle(self):
        """Initiate a poll cycle by queuing all devices."""
        timestamp = self.get_aligned_timestamp(self.poll_interval)

        with self.config_lock:
            devices_to_poll = list(self.devices.values())

        if not devices_to_poll:
            self.logger.warning("[Unifi SNMP] No Unifi devices to poll")
            return timestamp, 0

        for device in devices_to_poll:
            work_item = {'device': device, 'timestamp': timestamp}
            self.poll_queue.put(work_item)

        self.logger.info(f"[Unifi SNMP] Initiated poll cycle at {timestamp} for {len(devices_to_poll)} devices")
        return timestamp, len(devices_to_poll)

    def monitor_poll_progress(self, poll_start_time, poll_timestamp, device_count):
        """Monitor poll progress and record duration."""
        while self.running:
            queue_size = self.poll_queue.qsize()
            current_time = time.time()
            duration = current_time - poll_start_time

            if queue_size == 0:
                self.logger.info(f"[Unifi SNMP] Poll cycle completed in {duration:.2f} seconds")

                # Store poll duration metric
                duration_data = {
                    "@timestamp": poll_timestamp,
                    "deviceName": self.hostname,
                    "metricName": f"Unifi SNMP {self.component_id} Poll Duration (s)",
                    "value": duration,
                    "tags": {"componentId": self.component_id, "deviceCount": device_count, "source": SOURCE}
                }
                rapax.send_message(self.logger, 'stats', duration_data)
                break

            if duration > self.poll_interval:
                self.logger.error(f"[Unifi SNMP] Poll duration ({duration:.2f}s) exceeded interval ({self.poll_interval}s)")
                self.logger.error(f"[Unifi SNMP] Queue still has {queue_size} items - poller is behind")
                self.running = False
                os._exit(1)

            time.sleep(1)

    def run(self):
        """Main execution loop."""
        self.logger.info("[Unifi SNMP] Starting Unifi SNMP poller daemon")

        # Initial device configuration load
        self.update_device_configuration()

        # Start worker threads
        workers = []
        for i in range(self.worker_threads):
            worker = threading.Thread(target=self.poll_worker, name=f"UnifiWorker-{i+1}")
            worker.daemon = True
            worker.start()
            workers.append(worker)

        self.logger.info(f"[Unifi SNMP] Started {len(workers)} worker threads")

        last_config_update = time.time()

        while self.running:
            try:
                current_time = time.time()

                # Periodically refresh device list
                if current_time - last_config_update >= self.config_update_interval:
                    self.update_device_configuration()
                    last_config_update = current_time

                # Calculate sleep time until next poll boundary
                next_poll_time = ((current_time // self.poll_interval) + 1) * self.poll_interval
                sleep_time = next_poll_time - current_time

                if sleep_time > 0:
                    time.sleep(sleep_time)

                # Initiate poll cycle
                poll_start_time = time.time()
                poll_timestamp, device_count = self.initiate_poll_cycle()

                if device_count > 0:
                    monitor_thread = threading.Thread(
                        target=self.monitor_poll_progress,
                        args=(poll_start_time, poll_timestamp, device_count),
                        name="PollMonitor"
                    )
                    monitor_thread.daemon = True
                    monitor_thread.start()

            except KeyboardInterrupt:
                self.logger.info("[Unifi SNMP] Received shutdown signal")
                self.running = False
                break
            except Exception as e:
                self.logger.error(f"[Unifi SNMP] Error in main loop: {e}")
                time.sleep(5)

        # Shutdown workers
        self.logger.info("[Unifi SNMP] Shutting down worker threads")
        for _ in workers:
            self.poll_queue.put(None)

        for worker in workers:
            worker.join(timeout=5)

        self.logger.info("[Unifi SNMP] Unifi SNMP poller stopped")


def main():
    parser = argparse.ArgumentParser(description='Rapax Unifi Device SNMP Poller Daemon')
    parser.add_argument('--snmp-timeout', type=int, default=1000,
                        help='SNMP timeout in ms (default: 1000)')
    parser.add_argument('--poll-interval', type=int, default=60,
                        help='Polling interval in seconds (default: 60)')
    parser.add_argument('--component-id', type=str, default='unifi-snmp-1',
                        help='Component ID for metrics (default: unifi-snmp-1)')
    parser.add_argument('--config-update-interval', type=int, default=3600,
                        help='Configuration update interval in seconds (default: 3600)')
    parser.add_argument('--worker-threads', type=int, default=5,
                        help='Number of worker threads (default: 5)')

    args = parser.parse_args()

    try:
        poller = UnifiSNMPPoller(args)
        poller.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
