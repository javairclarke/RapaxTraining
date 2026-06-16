#!/usr/bin/env python3
"""
Rapax Zabbix NMS Data Processor Daemon
======================================

Polls Zabbix REST API at configurable intervals and publishes data to Redis streams:
- stream:devices - Host inventory from Zabbix
- stream:stats - Numeric metrics from Zabbix items
- stream:services - Zabbix services
- stream:alerts - Heartbeat alerts for health monitoring

Credential retrieval:
1. Try Rapax credentials vault (http://rapax-core-api:5004/api/credentials/custom/zabbix)
2. Fall back to environment variables (ZABBIX_URL, ZABBIX_API_TOKEN, ZABBIX_USER, ZABBIX_PASSWORD)

Configuration (environment variables):
- POLL_INTERVAL: Seconds between polls (default: 60)
- ZABBIX_URL: Zabbix API URL (fallback)
- ZABBIX_API_TOKEN: API token (fallback)
- ZABBIX_USER: Username (fallback)
- ZABBIX_PASSWORD: Password (fallback)
- COMPONENT_ID: Unique identifier for this instance (default: zabbix-nms-1)

@author: Citus - Rapax Software
@version: 1.0.0
"""

import os
import sys
import json
import uuid
import time
import signal
import requests
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

# Set RAPAXHOME environment
RAPAXHOME = os.environ.get('RAPAXHOME', '/opt/rapax')
sys.path.append(os.path.join(RAPAXHOME, 'lib'))

# Import Rapax library
import rapax

# Configuration
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', '60'))
COMPONENT_ID = os.environ.get('COMPONENT_ID', 'zabbix-nms-1')
CREDENTIALS_URL = os.environ.get('CREDENTIALS_URL', 'http://rapax-core-api:5004')

# Zabbix fallback configuration
ZABBIX_URL = os.environ.get('ZABBIX_URL', '')
ZABBIX_API_TOKEN = os.environ.get('ZABBIX_API_TOKEN', '')
ZABBIX_USER = os.environ.get('ZABBIX_USER', 'Admin')
ZABBIX_PASSWORD = os.environ.get('ZABBIX_PASSWORD', '')

# Logging
LOG_DIR = os.path.join(RAPAXHOME, 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'zabbix-data-processord.log')

# Best practice SNMP items for network equipment
NETWORK_ITEM_KEYS = [
    # CPU and Memory
    'system.cpu.util',
    'vm.memory.utilization',
    'system.cpu.load',

    # Interface traffic (SNMP)
    'net.if.in',
    'net.if.out',
    'ifInOctets',
    'ifOutOctets',
    'ifHCInOctets',
    'ifHCOutOctets',

    # Interface errors and discards
    'ifInErrors',
    'ifOutErrors',
    'ifInDiscards',
    'ifOutDiscards',

    # Interface status
    'ifOperStatus',
    'ifAdminStatus',

    # ICMP/Availability
    'icmpping',
    'icmppingsec',
    'icmppingloss',

    # SNMP generic
    'sysUpTime',
    'sysDescr',

    # Bandwidth utilization
    'net.if.bandwidth',
    'ifSpeed',
    'ifHighSpeed',
]

# Global state
running = True
logger = None
zabbix_credentials = None


def setup_logging():
    """Setup logging to file and console."""
    global logger

    # Ensure log directory exists
    os.makedirs(LOG_DIR, exist_ok=True)

    # Create logger
    logger = logging.getLogger('zabbix-data-processord')
    logger.setLevel(logging.INFO)

    # File handler
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.INFO)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    global running
    logger.info(f"Received signal {signum}, shutting down...")
    running = False


def load_zabbix_credentials() -> Dict[str, str]:
    """
    Load Zabbix credentials from vault or environment.

    Returns:
        Dictionary with url, username, password, api_token
    """
    global zabbix_credentials

    # Try credentials vault first
    try:
        response = requests.get(
            f"{CREDENTIALS_URL}/api/credentials/custom/zabbix",
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            cred_data = data.get('data', {})

            zabbix_credentials = {
                'url': cred_data.get('url', ''),
                'external_url': cred_data.get('external_url', ''),
                'username': cred_data.get('username', 'Admin'),
                'password': cred_data.get('password', ''),
                'api_token': cred_data.get('api_token', '')
            }

            logger.info("Loaded Zabbix credentials from vault")
            return zabbix_credentials

    except requests.exceptions.RequestException as e:
        logger.warning(f"Could not load credentials from vault: {e}")

    # Fall back to environment variables
    zabbix_credentials = {
        'url': ZABBIX_URL,
        'external_url': ZABBIX_URL,
        'username': ZABBIX_USER,
        'password': ZABBIX_PASSWORD,
        'api_token': ZABBIX_API_TOKEN
    }

    if not zabbix_credentials['url']:
        raise Exception("Zabbix URL not configured")

    logger.info("Using Zabbix credentials from environment")
    return zabbix_credentials


class ZabbixClient:
    """Zabbix API client."""

    def __init__(self, url: str, api_token: str = None, username: str = None, password: str = None):
        """
        Initialize Zabbix client.

        Args:
            url: Zabbix API URL (e.g., http://zabbix/api_jsonrpc.php)
            api_token: API token (preferred)
            username: Username for session auth
            password: Password for session auth
        """
        self.url = url
        self.api_token = api_token
        self.auth_token = None
        self.username = username
        self.password = password
        self.request_id = 0

    def _call(self, method: str, params: Dict[str, Any] = None, skip_auth: bool = False) -> Any:
        """
        Make Zabbix API call.

        Args:
            method: API method name
            params: Method parameters
            skip_auth: If True, don't include auth token (required for apiinfo.version)

        Returns:
            API response result
        """
        self.request_id += 1

        request_data = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self.request_id
        }

        # Add authentication (unless skip_auth for methods like apiinfo.version)
        if self.api_token and not skip_auth:
            # API token auth (Zabbix 5.4+)
            headers = {
                "Content-Type": "application/json-rpc",
                "Authorization": f"Bearer {self.api_token}"
            }
        elif self.auth_token and not skip_auth:
            # Session auth
            headers = {"Content-Type": "application/json-rpc"}
            request_data["auth"] = self.auth_token
        else:
            headers = {"Content-Type": "application/json-rpc"}

        try:
            response = requests.post(
                self.url,
                headers=headers,
                json=request_data,
                timeout=30
            )
            response.raise_for_status()

            result = response.json()

            if "error" in result:
                error = result["error"]
                raise Exception(f"Zabbix API error: {error.get('message', '')} - {error.get('data', '')}")

            return result.get("result")

        except requests.exceptions.RequestException as e:
            raise Exception(f"Zabbix API request failed: {e}")

    def login(self) -> bool:
        """
        Login to Zabbix (if not using API token).

        Returns:
            True if login successful
        """
        if self.api_token:
            # Test API is reachable (apiinfo.version doesn't need auth)
            try:
                self._call("apiinfo.version", skip_auth=True)
                return True
            except Exception:
                return False

        if not self.username or not self.password:
            raise Exception("Username and password required for login")

        try:
            # Zabbix 6.0+ uses user.login with username/password
            self.auth_token = self._call("user.login", {
                "username": self.username,
                "password": self.password
            })
            return True
        except Exception:
            # Try older format (user/password)
            try:
                self.auth_token = self._call("user.login", {
                    "user": self.username,
                    "password": self.password
                })
                return True
            except Exception:
                return False

    def get_api_version(self) -> str:
        """Get Zabbix API version (called without auth per Zabbix API requirements)."""
        return self._call("apiinfo.version", skip_auth=True)

    def get_hosts(self, group_ids: List[str] = None) -> List[Dict]:
        """
        Get all hosts.

        Args:
            group_ids: Optional list of host group IDs to filter

        Returns:
            List of host dictionaries
        """
        params = {
            "output": [
                "hostid", "host", "name", "status", "available",
                "description", "error", "errors_from"
            ],
            "selectInterfaces": ["ip", "dns", "type", "port"],
            "selectGroups": ["groupid", "name"],
            "selectParentTemplates": ["templateid", "name"],
            "selectInventory": "extend",
            "selectTags": ["tag", "value"]
        }

        if group_ids:
            params["groupids"] = group_ids

        return self._call("host.get", params)

    def get_items(self, host_ids: List[str] = None, search_keys: List[str] = None) -> List[Dict]:
        """
        Get numeric items from hosts.

        Args:
            host_ids: Optional list of host IDs
            search_keys: Optional list of item key patterns to search

        Returns:
            List of item dictionaries with last values
        """
        params = {
            "output": [
                "itemid", "hostid", "name", "key_", "value_type",
                "lastvalue", "lastclock", "units", "state", "status"
            ],
            "selectHosts": ["hostid", "host", "name"],
            # Only get numeric items (value_type: 0=float, 3=integer)
            "filter": {
                "value_type": [0, 3],
                "status": 0,  # Enabled items only
                "state": 0    # Normal items only
            },
            "sortfield": "name",
            "limit": 10000
        }

        if host_ids:
            params["hostids"] = host_ids

        # Search for specific keys
        if search_keys:
            params["search"] = {"key_": search_keys}
            params["searchWildcardsEnabled"] = True
            params["searchByAny"] = True

        return self._call("item.get", params)

    def get_services(self) -> List[Dict]:
        """
        Get all services.

        Returns:
            List of service dictionaries
        """
        params = {
            "output": [
                "serviceid", "name", "algorithm", "sortorder",
                "weight", "status", "description"
            ],
            "selectChildren": ["serviceid", "name"],
            "selectParents": ["serviceid", "name"],
            "selectTags": ["tag", "value"],
            "selectProblemTags": ["tag", "value", "operator"]
        }

        return self._call("service.get", params)

    def get_problems(self, severity_min: int = 0) -> List[Dict]:
        """
        Get current problems (active alerts).

        Args:
            severity_min: Minimum severity (0-5)

        Returns:
            List of problem dictionaries
        """
        params = {
            "output": [
                "eventid", "objectid", "clock", "name", "severity",
                "acknowledged", "suppressed"
            ],
            "selectHosts": ["hostid", "host", "name"],
            "selectTags": ["tag", "value"],
            "severities": list(range(severity_min, 6)),
            "recent": True,
            "sortfield": "eventid",
            "sortorder": "DESC"
        }

        return self._call("problem.get", params)


def check_device_exists(logger, device_name: str) -> bool:
    """
    Check if a device already exists in Rapax.

    Args:
        logger: Logger instance
        device_name: Device name to check

    Returns:
        True if device exists
    """
    try:
        redis_client = rapax.get_redis_client()

        # Check for device key pattern
        pattern = f"DEVICE:{device_name}:*"
        cursor = 0
        cursor, keys = redis_client.scan(cursor, match=pattern.encode(), count=100)

        return len(keys) > 0

    except Exception as e:
        logger.debug(f"Error checking device existence: {e}")
        return False


def process_hosts(logger, zabbix: ZabbixClient) -> int:
    """
    Process Zabbix hosts and publish to stream:devices.

    Args:
        logger: Logger instance
        zabbix: ZabbixClient instance

    Returns:
        Number of hosts processed
    """
    try:
        hosts = zabbix.get_hosts()
        processed = 0

        for host in hosts:
            hostname = host.get('host', '')

            # Skip if device already exists
            if check_device_exists(logger, hostname):
                logger.debug(f"Skipping existing device: {hostname}")
                continue

            # Get primary IP from interfaces
            ip_address = ''
            interfaces = host.get('interfaces', [])
            for iface in interfaces:
                if iface.get('ip'):
                    ip_address = iface['ip']
                    break

            # Get inventory data
            inventory = host.get('inventory', {})
            if not isinstance(inventory, dict):
                inventory = {}

            # Infer device category from groups and templates
            device_category = 'Unknown'  # Default fallback
            groups = [g.get('name', '').lower() for g in host.get('groups', [])]
            templates = [t.get('name', '').lower() for t in host.get('parentTemplates', [])]
            all_hints = ' '.join(groups + templates)

            if 'server' in all_hints or 'linux' in all_hints or 'windows' in all_hints:
                device_category = 'Server'
            elif 'switch' in all_hints:
                device_category = 'Switch'
            elif 'router' in all_hints:
                device_category = 'Router'
            elif 'firewall' in all_hints:
                device_category = 'Firewall'
            elif 'ap' in all_hints or 'wireless' in all_hints or 'access point' in all_hints:
                device_category = 'AP'
            elif 'storage' in all_hints or 'nas' in all_hints:
                device_category = 'NAS'

            # Map Zabbix host to Rapax device format (matching discovery-agent.py schema)
            timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            device_data = {
                '@timestamp': timestamp,
                'deviceName': hostname,
                'deviceFQDN': host.get('name', hostname),
                'deviceDescription': host.get('description', ''),
                'ManagementIpAddress': ip_address,
                'deviceCategory': device_category,
                'deviceModel': inventory.get('model', ''),
                'deviceSerialNumber': inventory.get('serialno_a', ''),
                'deviceLocation': inventory.get('location', ''),
                'vendor': inventory.get('vendor', ''),
                'source': 'Zabbix',
                'lastSeen': timestamp,
                'securityInformation': [],
                'interfaces': [],
                'tags': [
                    {'name': 'Source', 'value': 'Zabbix'},
                    {'name': 'ZabbixHostId', 'value': host.get('hostid', '')},
                    {'name': 'ComponentId', 'value': COMPONENT_ID}
                ]
            }

            # Add Zabbix groups as tags
            for group in host.get('groups', []):
                device_data['tags'].append({
                    'name': 'ZabbixGroup',
                    'value': group.get('name', '')
                })

            # Add tags from Zabbix
            for tag in host.get('tags', []):
                device_data['tags'].append({
                    'name': tag.get('tag', ''),
                    'value': tag.get('value', '')
                })

            # Send to stream:devices
            rapax.send_message(logger, 'devices', device_data)
            processed += 1

            logger.debug(f"Published device: {hostname}")

        return processed

    except Exception as e:
        logger.error(f"Error processing hosts: {e}")
        return 0


def process_items(logger, zabbix: ZabbixClient) -> int:
    """
    Process Zabbix items and publish numeric metrics to stream:stats.

    Args:
        logger: Logger instance
        zabbix: ZabbixClient instance

    Returns:
        Number of items processed
    """
    try:
        # Get items matching network equipment patterns
        items = zabbix.get_items(search_keys=NETWORK_ITEM_KEYS)
        processed = 0

        for item in items:
            # Skip items without values
            if not item.get('lastvalue') or item.get('lastvalue') == '':
                continue

            # Get host info
            hosts = item.get('hosts', [])
            if not hosts:
                continue

            host = hosts[0]
            hostname = host.get('host', host.get('name', 'unknown'))

            # Skip template items (templates typically start with "Template")
            if hostname.startswith('Template ') or hostname.startswith('template '):
                continue

            # Parse value
            try:
                value = float(item['lastvalue'])
            except (ValueError, TypeError):
                continue

            # Get timestamp from lastclock
            lastclock = item.get('lastclock', '')
            if lastclock and lastclock != '0' and int(lastclock) > 0:
                try:
                    timestamp = datetime.utcfromtimestamp(int(lastclock)).isoformat() + 'Z'
                except (ValueError, TypeError):
                    timestamp = datetime.utcnow().isoformat() + 'Z'
            else:
                # Use current time if lastclock is 0 or empty (avoids 1970-01-01 index)
                timestamp = datetime.utcnow().isoformat() + 'Z'

            # Map to Rapax stats format (matching snmp-agentd.py schema)
            stat_data = {
                '@timestamp': timestamp,
                'deviceName': hostname,
                'metricName': item.get('name', item.get('key_', 'unknown')),
                'value': value,
                'tags': {
                    'componentId': COMPONENT_ID,
                    'managementIP': '',  # Not available from Zabbix item
                    'location': '',
                    'source': 'Zabbix',
                    'vendor': '',
                    'category': '',
                    'zabbixItemId': item.get('itemid', ''),
                    'units': item.get('units', '')
                }
            }

            # Send to stream:stats
            rapax.send_message(logger, 'stats', stat_data)
            processed += 1

        return processed

    except Exception as e:
        logger.error(f"Error processing items: {e}")
        return 0


def process_services(logger, zabbix: ZabbixClient) -> int:
    """
    Process Zabbix services and publish to stream:services.

    Args:
        logger: Logger instance
        zabbix: ZabbixClient instance

    Returns:
        Number of services processed
    """
    try:
        services = zabbix.get_services()
        processed = 0

        for service in services:
            # Map Zabbix service to Rapax service format
            service_data = {
                '@timestamp': datetime.utcnow().isoformat() + 'Z',
                'name': service.get('name', ''),
                'description': service.get('description', ''),
                'status': 'OK' if service.get('status', '0') == '0' else 'Problem',
                'children': [c.get('name', '') for c in service.get('children', [])],
                'parents': [p.get('name', '') for p in service.get('parents', [])],
                'source': 'Zabbix',
                'tags': [
                    {'name': 'Source', 'value': 'Zabbix'},
                    {'name': 'ZabbixServiceId', 'value': service.get('serviceid', '')},
                    {'name': 'ComponentId', 'value': COMPONENT_ID}
                ]
            }

            # Add Zabbix tags
            for tag in service.get('tags', []):
                service_data['tags'].append({
                    'name': tag.get('tag', ''),
                    'value': tag.get('value', '')
                })

            # Send to stream:services
            rapax.send_message(logger, 'services', service_data)
            processed += 1

        return processed

    except Exception as e:
        logger.error(f"Error processing services: {e}")
        return 0


def send_heartbeat(logger, success: bool, error_message: str = None, stats: Dict = None):
    """
    Send heartbeat alert to stream:alerts.

    Args:
        logger: Logger instance
        success: True if poll was successful
        error_message: Error message if failed
        stats: Collection statistics
    """
    timestamp = datetime.utcnow().isoformat() + 'Z'

    if success:
        state = "Up"
        status = "Clear"
        description = f"Zabbix NMS collector heartbeat - Poll successful"
        if stats:
            description += f" (devices: {stats.get('devices', 0)}, stats: {stats.get('stats', 0)}, services: {stats.get('services', 0)})"
    else:
        state = "Down"
        status = "Critical"
        description = f"Zabbix NMS collector failed: {error_message or 'Unknown error'}"

    heartbeat_alert = {
        'UUID': str(uuid.uuid4()),
        'Device': COMPONENT_ID,
        'Interface': 'Collector',
        'IP': '0.0.0.0',  # Placeholder IP for heartbeat alerts
        'Status': status,
        'State': state,
        'Category': 'heartbeat',
        'Source': 'zabbix-data-processord',
        'Location': '',
        'Description': description,
        'FirstOccurred': timestamp,
        'LastOccurred': timestamp,
        'Count': 1,
        'DeviceType': 'Integration',
        'Parent': '',
        'Notes': [],
        '@timestamp': timestamp
    }

    rapax.insert_alert(logger, heartbeat_alert)


def main_loop():
    """Main polling loop."""
    global running, zabbix_credentials

    logger.info(f"Starting Zabbix NMS data processor (component: {COMPONENT_ID})")
    logger.info(f"Poll interval: {POLL_INTERVAL} seconds")

    # Load Rapax config and connect to Redis
    rapax.load_config()

    # Initial credential load
    try:
        zabbix_credentials = load_zabbix_credentials()
    except Exception as e:
        logger.error(f"Failed to load Zabbix credentials: {e}")
        send_heartbeat(logger, False, str(e))
        return 1

    # Create Zabbix client
    zabbix = ZabbixClient(
        url=zabbix_credentials['url'],
        api_token=zabbix_credentials.get('api_token'),
        username=zabbix_credentials.get('username'),
        password=zabbix_credentials.get('password')
    )

    # Login to Zabbix
    try:
        if zabbix.login():
            version = zabbix.get_api_version()
            logger.info(f"Connected to Zabbix API version {version}")
        else:
            raise Exception("Login failed")
    except Exception as e:
        logger.error(f"Failed to connect to Zabbix: {e}")
        send_heartbeat(logger, False, str(e))
        return 1

    # Main loop
    poll_count = 0

    while running:
        poll_start = time.time()
        poll_count += 1

        logger.info(f"Starting poll cycle #{poll_count}")

        try:
            # Process hosts -> devices
            devices_count = process_hosts(logger, zabbix)
            logger.info(f"Processed {devices_count} new devices")

            # Process items -> stats
            stats_count = process_items(logger, zabbix)
            logger.info(f"Processed {stats_count} stats")

            # Process services -> services
            services_count = process_services(logger, zabbix)
            logger.info(f"Processed {services_count} services")

            # Send success heartbeat
            send_heartbeat(logger, True, stats={
                'devices': devices_count,
                'stats': stats_count,
                'services': services_count
            })

            poll_duration = time.time() - poll_start
            logger.info(f"Poll cycle #{poll_count} completed in {poll_duration:.2f}s")

        except Exception as e:
            logger.error(f"Poll cycle #{poll_count} failed: {e}")
            send_heartbeat(logger, False, str(e))

        # Wait for next poll
        sleep_time = max(0, POLL_INTERVAL - (time.time() - poll_start))
        if sleep_time > 0 and running:
            logger.debug(f"Sleeping {sleep_time:.2f}s until next poll")
            time.sleep(sleep_time)

    logger.info("Zabbix NMS data processor stopped")
    return 0


def main():
    """Main entry point."""
    global logger

    # Setup logging
    logger = setup_logging()

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("=" * 60)
    logger.info("Rapax Zabbix NMS Data Processor")
    logger.info("=" * 60)

    try:
        return main_loop()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
