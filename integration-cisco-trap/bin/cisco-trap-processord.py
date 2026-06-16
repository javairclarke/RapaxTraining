#!/usr/bin/env python3
"""
Cisco SNMP Trap Processor Daemon
================================

Processes SNMP traps from Cisco devices (and standard RFC/IETF traps) logged to syslog.
Reads /var/log/messages, filters for snmptrap-tagged entries, parses trap data,
and routes to Redis streams for alert generation or logging.

Supports:
- RFC 1157 Generic SNMP Traps (coldStart, warmStart, linkDown, linkUp, authenticationFailure)
- RFC 4273 BGP Traps
- RFC 1850 OSPF Traps
- Cisco Enterprise MIB Traps (Environment, HSRP, Config, Security, Wireless, etc.)

Author: Rapax Integration
"""

import os
import sys
import re
import json
import time
import signal
import argparse
import uuid
import hashlib
from datetime import datetime
from logging.handlers import RotatingFileHandler

# Environment setup
RAPAX_HOME = os.getenv('RAPAXHOME', '/opt/rapax')
sys.path.insert(0, os.path.join(RAPAX_HOME, 'lib'))

# Import rapax library
import rapax

SOURCE = 'cisco-trap-processord'
VERSION = '1.0.0'

# =============================================================================
# TRAP DEFINITIONS
# =============================================================================
# Hardcoded trap mappings with severity levels:
#   CRITICAL: Catastrophic outage (HA failover, dual-active, shutdown)
#   MAJOR: Outage (linkDown, BGP down, AP disassociated)
#   MINOR: Degradation (high CPU, errors, threshold warnings)
#   WARNING: Potential issue (config change, auth failure)
#   CLEAR: Recovery message (linkUp, BGP established, temp normal)
#   INFO: Informational (warmStart, status messages)
#   DEBUG: Debug level (low priority, non-actionable)
# =============================================================================

TRAP_DEFINITIONS = {
    # =========================================================================
    # RFC 1157 / SNMPv2-MIB Generic Traps
    # =========================================================================
    '1.3.6.1.6.3.1.1.5.1': {
        'name': 'coldStart',
        'severity': 'WARNING',
        'category': 'device-state',
        'description': 'Device has reinitialized (cold boot)',
        'actionable': True
    },
    '1.3.6.1.6.3.1.1.5.2': {
        'name': 'warmStart',
        'severity': 'INFO',
        'category': 'device-state',
        'description': 'Device has reinitialized (warm boot)',
        'actionable': False
    },
    '1.3.6.1.6.3.1.1.5.3': {
        'name': 'linkDown',
        'severity': 'MAJOR',
        'category': 'link-state',
        'description': 'Interface link is down',
        'actionable': True
    },
    '1.3.6.1.6.3.1.1.5.4': {
        'name': 'linkUp',
        'severity': 'CLEAR',
        'category': 'link-state',
        'description': 'Interface link is up',
        'actionable': True
    },
    '1.3.6.1.6.3.1.1.5.5': {
        'name': 'authenticationFailure',
        'severity': 'WARNING',
        'category': 'security',
        'description': 'SNMP authentication failure detected',
        'actionable': True
    },
    # Legacy SNMPv1 generic trap OIDs (some devices still use these)
    '1.3.6.1.4.1.9.0.1': {
        'name': 'coldStart',
        'severity': 'WARNING',
        'category': 'device-state',
        'description': 'Device has reinitialized (cold boot)',
        'actionable': True
    },

    # =========================================================================
    # IF-MIB Interface Traps (RFC 2863)
    # =========================================================================
    '1.3.6.1.2.1.2.2.0.1': {
        'name': 'linkDown',
        'severity': 'MAJOR',
        'category': 'link-state',
        'description': 'Interface link is down',
        'actionable': True
    },
    '1.3.6.1.2.1.2.2.0.2': {
        'name': 'linkUp',
        'severity': 'CLEAR',
        'category': 'link-state',
        'description': 'Interface link is up',
        'actionable': True
    },

    # =========================================================================
    # BGP Traps (RFC 4273)
    # =========================================================================
    '1.3.6.1.2.1.15.7.1': {
        'name': 'bgpEstablished',
        'severity': 'CLEAR',
        'category': 'routing',
        'description': 'BGP peer session established',
        'actionable': True
    },
    '1.3.6.1.2.1.15.7.2': {
        'name': 'bgpBackwardTransition',
        'severity': 'MAJOR',
        'category': 'routing',
        'description': 'BGP peer session down/backward transition',
        'actionable': True
    },

    # =========================================================================
    # OSPF Traps (RFC 1850)
    # =========================================================================
    '1.3.6.1.2.1.14.16.2.1': {
        'name': 'ospfVirtIfStateChange',
        'severity': 'MAJOR',
        'category': 'routing',
        'description': 'OSPF virtual interface state change',
        'actionable': True
    },
    '1.3.6.1.2.1.14.16.2.2': {
        'name': 'ospfNbrStateChange',
        'severity': 'MAJOR',
        'category': 'routing',
        'description': 'OSPF neighbor state change',
        'actionable': True
    },
    '1.3.6.1.2.1.14.16.2.3': {
        'name': 'ospfVirtNbrStateChange',
        'severity': 'MAJOR',
        'category': 'routing',
        'description': 'OSPF virtual neighbor state change',
        'actionable': True
    },
    '1.3.6.1.2.1.14.16.2.4': {
        'name': 'ospfIfConfigError',
        'severity': 'WARNING',
        'category': 'routing',
        'description': 'OSPF interface configuration error',
        'actionable': True
    },
    '1.3.6.1.2.1.14.16.2.5': {
        'name': 'ospfVirtIfConfigError',
        'severity': 'WARNING',
        'category': 'routing',
        'description': 'OSPF virtual interface configuration error',
        'actionable': True
    },
    '1.3.6.1.2.1.14.16.2.6': {
        'name': 'ospfIfAuthFailure',
        'severity': 'WARNING',
        'category': 'routing',
        'description': 'OSPF interface authentication failure',
        'actionable': True
    },
    '1.3.6.1.2.1.14.16.2.16': {
        'name': 'ospfIfStateChange',
        'severity': 'WARNING',
        'category': 'routing',
        'description': 'OSPF interface state change',
        'actionable': True
    },

    # =========================================================================
    # EIGRP Traps (Cisco)
    # =========================================================================
    '1.3.6.1.4.1.9.9.449.0.1': {
        'name': 'cEigrpNbrDownEvent',
        'severity': 'MAJOR',
        'category': 'routing',
        'description': 'EIGRP neighbor down',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.449.0.2': {
        'name': 'cEigrpNbrUpEvent',
        'severity': 'CLEAR',
        'category': 'routing',
        'description': 'EIGRP neighbor up',
        'actionable': True
    },

    # =========================================================================
    # Cisco Environment Monitoring (CISCO-ENVMON-MIB)
    # =========================================================================
    '1.3.6.1.4.1.9.9.13.3.0.1': {
        'name': 'ciscoEnvMonShutdownNotification',
        'severity': 'CRITICAL',
        'category': 'environment',
        'description': 'Environmental shutdown imminent',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.13.3.0.2': {
        'name': 'ciscoEnvMonVoltageNotification',
        'severity': 'MAJOR',
        'category': 'environment',
        'description': 'Voltage threshold exceeded',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.13.3.0.3': {
        'name': 'ciscoEnvMonTemperatureNotification',
        'severity': 'MAJOR',
        'category': 'environment',
        'description': 'Temperature threshold exceeded',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.13.3.0.4': {
        'name': 'ciscoEnvMonFanNotification',
        'severity': 'MAJOR',
        'category': 'environment',
        'description': 'Fan failure detected',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.13.3.0.5': {
        'name': 'ciscoEnvMonRedundantSupplyNotification',
        'severity': 'MAJOR',
        'category': 'environment',
        'description': 'Redundant power supply failure',
        'actionable': True
    },

    # =========================================================================
    # Cisco HSRP (CISCO-HSRP-MIB)
    # =========================================================================
    '1.3.6.1.4.1.9.9.106.2.0.1': {
        'name': 'cHsrpStateChange',
        'severity': 'CRITICAL',
        'category': 'redundancy',
        'description': 'HSRP state change (failover event)',
        'actionable': True
    },

    # =========================================================================
    # Cisco VRRP
    # =========================================================================
    '1.3.6.1.2.1.68.0.1': {
        'name': 'vrrpTrapNewMaster',
        'severity': 'CRITICAL',
        'category': 'redundancy',
        'description': 'VRRP new master elected (failover)',
        'actionable': True
    },
    '1.3.6.1.2.1.68.0.2': {
        'name': 'vrrpTrapAuthFailure',
        'severity': 'WARNING',
        'category': 'redundancy',
        'description': 'VRRP authentication failure',
        'actionable': True
    },

    # =========================================================================
    # Cisco Config Management (CISCO-CONFIG-MAN-MIB)
    # =========================================================================
    '1.3.6.1.4.1.9.9.43.2.0.1': {
        'name': 'ccmCLIRunningConfigChanged',
        'severity': 'WARNING',
        'category': 'config',
        'description': 'Running configuration changed via CLI',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.43.2.0.2': {
        'name': 'ccmCTIDRolledOver',
        'severity': 'INFO',
        'category': 'config',
        'description': 'Config change tracking ID rolled over',
        'actionable': False
    },
    '1.3.6.1.4.1.9.9.43.2.0.3': {
        'name': 'ciscoConfigManEvent',
        'severity': 'WARNING',
        'category': 'config',
        'description': 'Configuration management event',
        'actionable': True
    },

    # =========================================================================
    # Cisco CPU/Memory (CISCO-PROCESS-MIB)
    # =========================================================================
    '1.3.6.1.4.1.9.9.109.2.0.1': {
        'name': 'cpmCPURisingThreshold',
        'severity': 'MINOR',
        'category': 'performance',
        'description': 'CPU utilization rising threshold exceeded',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.109.2.0.2': {
        'name': 'cpmCPUFallingThreshold',
        'severity': 'CLEAR',
        'category': 'performance',
        'description': 'CPU utilization falling below threshold',
        'actionable': True
    },

    # =========================================================================
    # Cisco Memory Pool (CISCO-MEMORY-POOL-MIB)
    # =========================================================================
    '1.3.6.1.4.1.9.9.48.2.0.1': {
        'name': 'ciscoMemoryPoolLowMemoryNotif',
        'severity': 'MINOR',
        'category': 'performance',
        'description': 'Memory pool low memory condition',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.48.2.0.2': {
        'name': 'ciscoMemoryPoolLowMemoryRecoveryNotif',
        'severity': 'CLEAR',
        'category': 'performance',
        'description': 'Memory pool low memory condition recovered',
        'actionable': True
    },

    # =========================================================================
    # Cisco Security (Various MIBs)
    # =========================================================================
    '1.3.6.1.4.1.9.9.315.0.1': {
        'name': 'ciscoSecureViolation',
        'severity': 'WARNING',
        'category': 'security',
        'description': 'Port security violation detected',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.315.0.2': {
        'name': 'ciscoSecureMacAddrViolation',
        'severity': 'WARNING',
        'category': 'security',
        'description': 'MAC address security violation',
        'actionable': True
    },

    # =========================================================================
    # Cisco 802.1X (IEEE8021-PAE-MIB)
    # =========================================================================
    '1.3.6.1.4.1.9.9.656.0.1': {
        'name': 'cpaeAuthFailVlanNotif',
        'severity': 'WARNING',
        'category': 'security',
        'description': '802.1X authentication failure',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.656.0.2': {
        'name': 'cpaeAuthSuccessVlanNotif',
        'severity': 'INFO',
        'category': 'security',
        'description': '802.1X authentication success',
        'actionable': False
    },

    # =========================================================================
    # Cisco ASA/Firepower Failover
    # =========================================================================
    '1.3.6.1.4.1.9.9.147.0.1': {
        'name': 'cfwSecEventAlert',
        'severity': 'WARNING',
        'category': 'security',
        'description': 'Firewall security event alert',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.500.0.1': {
        'name': 'cefcFRURemoved',
        'severity': 'MAJOR',
        'category': 'hardware',
        'description': 'Field Replaceable Unit removed',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.500.0.2': {
        'name': 'cefcFRUInserted',
        'severity': 'CLEAR',
        'category': 'hardware',
        'description': 'Field Replaceable Unit inserted',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.500.0.3': {
        'name': 'cefcModuleStatusChange',
        'severity': 'MAJOR',
        'category': 'hardware',
        'description': 'Module status changed',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.500.0.4': {
        'name': 'cefcPowerStatusChange',
        'severity': 'MAJOR',
        'category': 'hardware',
        'description': 'Power supply status changed',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.500.0.5': {
        'name': 'cefcFanTrayStatusChange',
        'severity': 'MAJOR',
        'category': 'hardware',
        'description': 'Fan tray status changed',
        'actionable': True
    },

    # =========================================================================
    # Cisco Wireless (AIRESPACE-WIRELESS-MIB / CISCO-LWAPP-*)
    # =========================================================================
    '1.3.6.1.4.1.14179.2.6.3.1': {
        'name': 'bsnAPDisassociated',
        'severity': 'MAJOR',
        'category': 'wireless',
        'description': 'Access Point disassociated from controller',
        'actionable': True
    },
    '1.3.6.1.4.1.14179.2.6.3.2': {
        'name': 'bsnAPAssociated',
        'severity': 'CLEAR',
        'category': 'wireless',
        'description': 'Access Point associated with controller',
        'actionable': True
    },
    '1.3.6.1.4.1.14179.2.6.3.3': {
        'name': 'bsnAPIfUp',
        'severity': 'CLEAR',
        'category': 'wireless',
        'description': 'Access Point interface up',
        'actionable': True
    },
    '1.3.6.1.4.1.14179.2.6.3.4': {
        'name': 'bsnAPIfDown',
        'severity': 'MAJOR',
        'category': 'wireless',
        'description': 'Access Point interface down',
        'actionable': True
    },
    '1.3.6.1.4.1.14179.2.6.3.8': {
        'name': 'bsnRogueAPDetected',
        'severity': 'WARNING',
        'category': 'wireless',
        'description': 'Rogue Access Point detected',
        'actionable': True
    },
    '1.3.6.1.4.1.14179.2.6.3.9': {
        'name': 'bsnRogueAPRemoved',
        'severity': 'CLEAR',
        'category': 'wireless',
        'description': 'Rogue Access Point removed',
        'actionable': True
    },
    '1.3.6.1.4.1.14179.2.6.3.16': {
        'name': 'bsnAPCoverageHoleDetected',
        'severity': 'MINOR',
        'category': 'wireless',
        'description': 'Wireless coverage hole detected',
        'actionable': True
    },
    '1.3.6.1.4.1.14179.2.6.3.44': {
        'name': 'bsnDot11ClientAssoc',
        'severity': 'INFO',
        'category': 'wireless',
        'description': 'Wireless client associated',
        'actionable': False
    },
    '1.3.6.1.4.1.14179.2.6.3.45': {
        'name': 'bsnDot11ClientDisassoc',
        'severity': 'INFO',
        'category': 'wireless',
        'description': 'Wireless client disassociated',
        'actionable': False
    },

    # =========================================================================
    # Cisco Stack/Chassis (CISCO-STACKWISE-MIB)
    # =========================================================================
    '1.3.6.1.4.1.9.9.500.0.6': {
        'name': 'cswStackPortChange',
        'severity': 'MAJOR',
        'category': 'stack',
        'description': 'Stack port status changed',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.500.0.7': {
        'name': 'cswStackNewMaster',
        'severity': 'CRITICAL',
        'category': 'stack',
        'description': 'New stack master elected',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.500.0.8': {
        'name': 'cswStackMemberRemoved',
        'severity': 'MAJOR',
        'category': 'stack',
        'description': 'Stack member removed',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.500.0.9': {
        'name': 'cswStackMemberAdded',
        'severity': 'CLEAR',
        'category': 'stack',
        'description': 'Stack member added',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.500.0.10': {
        'name': 'cswStackRingRedundant',
        'severity': 'CLEAR',
        'category': 'stack',
        'description': 'Stack ring redundancy restored',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.500.0.11': {
        'name': 'cswStackRingNotRedundant',
        'severity': 'MAJOR',
        'category': 'stack',
        'description': 'Stack ring redundancy lost',
        'actionable': True
    },

    # =========================================================================
    # Cisco vPC (CISCO-VPC-MIB)
    # =========================================================================
    '1.3.6.1.4.1.9.9.807.0.1': {
        'name': 'cVpcPeerKeepAliveStatusChange',
        'severity': 'CRITICAL',
        'category': 'vpc',
        'description': 'vPC peer keepalive status changed',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.807.0.2': {
        'name': 'cVpcRoleChange',
        'severity': 'CRITICAL',
        'category': 'vpc',
        'description': 'vPC role change (primary/secondary)',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.807.0.3': {
        'name': 'cVpcPeerLinkStatusChange',
        'severity': 'CRITICAL',
        'category': 'vpc',
        'description': 'vPC peer link status changed',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.807.0.4': {
        'name': 'cVpcDualActiveDetected',
        'severity': 'CRITICAL',
        'category': 'vpc',
        'description': 'vPC dual-active (split-brain) detected',
        'actionable': True
    },

    # =========================================================================
    # Cisco Spanning Tree (CISCO-STP-EXTENSIONS-MIB)
    # =========================================================================
    '1.3.6.1.4.1.9.9.82.2.0.1': {
        'name': 'stpxInconsistencyUpdate',
        'severity': 'WARNING',
        'category': 'spanning-tree',
        'description': 'STP inconsistency detected',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.82.2.0.2': {
        'name': 'stpxRootInconsistencyUpdate',
        'severity': 'MAJOR',
        'category': 'spanning-tree',
        'description': 'STP root inconsistency detected',
        'actionable': True
    },
    '1.3.6.1.4.1.9.9.82.2.0.3': {
        'name': 'stpxLoopInconsistencyUpdate',
        'severity': 'CRITICAL',
        'category': 'spanning-tree',
        'description': 'STP loop inconsistency detected',
        'actionable': True
    },

    # =========================================================================
    # Entity MIB (RFC 4133)
    # =========================================================================
    '1.3.6.1.2.1.47.2.0.1': {
        'name': 'entConfigChange',
        'severity': 'INFO',
        'category': 'entity',
        'description': 'Entity configuration changed',
        'actionable': False
    },

    # =========================================================================
    # SNMP Target MIB
    # =========================================================================
    '1.3.6.1.6.3.12.1.4': {
        'name': 'snmpUnavailableContexts',
        'severity': 'WARNING',
        'category': 'snmp',
        'description': 'SNMP context unavailable',
        'actionable': True
    },
    '1.3.6.1.6.3.12.1.5': {
        'name': 'snmpUnknownContexts',
        'severity': 'WARNING',
        'category': 'snmp',
        'description': 'SNMP unknown context',
        'actionable': True
    },
}

# Regex patterns for parsing snmptrap log entries
# Pattern for multi-line snmptrapd format (default net-snmp logger output)
# Each trap spans multiple lines:
#   <UNKNOWN>
#   UDP: [source]:port->[dest]:162
#   iso.3.6.1.2.1.1.3.0 <uptime>
#   iso.3.6.1.6.3.1.1.4.1.0 iso.X.X.X.X  <-- trap OID
#   iso.X.X.X.X <value>  <-- varbinds

# Pattern to detect start of a new trap (the <UNKNOWN> line)
TRAP_START_PATTERN = re.compile(
    r'(?P<timestamp>[\d\-T:\.+]+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'snmptrap:\s*<UNKNOWN>'
)

# Pattern to extract UDP source info
UDP_PATTERN = re.compile(
    r'snmptrap:\s*UDP:\s*\[(?P<source_ip>[\d\.]+)\]:(?P<source_port>\d+)'
    r'\s*->\s*\[(?P<dest_ip>[\d\.]+)\]:(?P<dest_port>\d+)'
)

# Pattern to extract snmpTrapOID (iso.3.6.1.6.3.1.1.4.1.0)
# The value after this OID is the actual trap type
TRAP_OID_PATTERN = re.compile(
    r'snmptrap:\s*iso\.3\.6\.1\.6\.3\.1\.1\.4\.1\.0\s+(?P<trap_oid>iso\.[\d\.]+|[\d\.]+)'
)

# Pattern to extract varbind lines (OID followed by value)
VARBIND_LINE_PATTERN = re.compile(
    r'snmptrap:\s*(?P<oid>iso\.[\d\.]+|[\d\.]+)\s+(?P<value>.+)'
)

# Legacy single-line patterns (kept for compatibility)
SNMPTRAP_PATTERNS = [
    # Standard snmptrapd format: hostname snmptrapd[pid]: timestamp IP [UDP: [IP]:port->local]: OID ...
    re.compile(
        r'(?P<syslog_time>\w+\s+\d+\s+[\d:]+)\s+'
        r'(?P<syslog_host>\S+)\s+'
        r'snmptrap(?:d)?\[?\d*\]?:\s*'
        r'(?P<trap_time>[\d\-T:]+)?\s*'
        r'(?P<source_ip>[\d\.]+)\s*'
        r'(?:\[UDP:\s*\[(?P<udp_ip>[\d\.]+)\]:(?P<udp_port>\d+)\S*\])?\s*'
        r'(?P<trap_oid>[\d\.]+)\s*'
        r'(?P<varbinds>.*)'
    ),
    # Simpler format: hostname snmptrap: source_ip trap_oid varbinds
    re.compile(
        r'(?P<syslog_time>\w+\s+\d+\s+[\d:]+)\s+'
        r'(?P<syslog_host>\S+)\s+'
        r'snmptrap:\s*'
        r'(?P<source_ip>[\d\.]+)\s+'
        r'(?P<trap_oid>[\d\.]+)\s*'
        r'(?P<varbinds>.*)'
    ),
]

# Varbind parsing pattern for single-line format
VARBIND_PATTERN = re.compile(
    r'(?P<oid>[\d\.]+)\s*=\s*(?P<type>\w+):\s*(?P<value>[^\s]+(?:\s+[^\d\.][^\s]*)*)'
)


class CiscoTrapProcessor:
    """Main processor class for Cisco SNMP trap processing."""

    def __init__(self, args):
        """Initialize the processor."""
        self.config = rapax.load_config()
        self.logger = rapax.setup_logging()
        self._setup_file_logging()

        self.syslog_file = args.syslog_file
        self.component_id = args.component_id

        self.running = True
        self.metrics = {
            'traps_processed': 0,
            'alerts_generated': 0,
            'logs_generated': 0,
            'errors': 0,
            'unknown_traps': 0,
            'lines_skipped': 0
        }

        # Multi-line trap buffer
        self.trap_buffer = []
        self.current_trap_timestamp = None

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        self.logger.info(f"[{SOURCE}] Initializing Cisco Trap Processor v{VERSION}")
        self.logger.info(f"[{SOURCE}] Monitoring syslog file: {self.syslog_file}")
        self.logger.info(f"[{SOURCE}] Component ID: {self.component_id}")
        self.logger.info(f"[{SOURCE}] Loaded {len(TRAP_DEFINITIONS)} trap definitions")

    def _setup_file_logging(self):
        """Setup file logging for the daemon."""
        import logging
        log_dir = os.path.join(RAPAX_HOME, 'logs')
        os.makedirs(log_dir, exist_ok=True)

        log_file = os.path.join(log_dir, f'{SOURCE}.log')
        file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        self.logger.info(f"[{SOURCE}] Received signal {signum}, initiating shutdown...")
        self.running = False

    def _generate_alert_hash(self, device, interface, category, trap_name):
        """Generate a unique hash for alert deduplication."""
        key_string = f"{device}:{interface}:{category}:{trap_name}"
        return hashlib.md5(key_string.encode()).hexdigest()[:16]

    def _parse_varbinds(self, varbind_data):
        """Parse varbind data into structured format.

        Args:
            varbind_data: Either a dict (from JSON) or string (legacy format)

        Returns:
            dict: Varbinds with OID keys and value dicts
        """
        varbinds = {}

        if isinstance(varbind_data, dict):
            # JSON format - varbinds are already a dict
            for oid, value in varbind_data.items():
                varbinds[oid] = {'type': 'string', 'value': str(value)}
            return varbinds

        # Legacy string format
        if not varbind_data:
            return varbinds

        # Split on OID patterns and parse each
        parts = re.split(r'\s+(?=\d+\.)', str(varbind_data).strip())
        for part in parts:
            match = VARBIND_PATTERN.match(part.strip())
            if match:
                oid = match.group('oid')
                val_type = match.group('type')
                value = match.group('value').strip().strip('"')
                varbinds[oid] = {'type': val_type, 'value': value}

        return varbinds

    def _extract_interface_from_varbinds(self, varbinds):
        """Extract interface name from varbinds if present."""
        # Common interface OIDs
        interface_oids = [
            '1.3.6.1.2.1.2.2.1.2',    # ifDescr
            '1.3.6.1.2.1.31.1.1.1.1',  # ifName
            '1.3.6.1.2.1.2.2.1.1',     # ifIndex
        ]

        for oid_prefix in interface_oids:
            for oid, data in varbinds.items():
                if oid.startswith(oid_prefix):
                    return data.get('value', 'Unknown')

        return 'N/A'

    def _map_severity_to_status(self, severity):
        """Map trap severity to Rapax alert status."""
        mapping = {
            'CRITICAL': 'Critical',
            'MAJOR': 'Major',
            'MINOR': 'Minor',
            'WARNING': 'Warning',
            'CLEAR': 'Clear',
            'INFO': 'Info',
            'DEBUG': 'Debug'
        }
        return mapping.get(severity, 'Warning')

    def _parse_trap_line(self, line):
        """Parse a syslog line containing snmptrap data.

        Supports two formats:
        1. JSON format from rapax-traphandle.sh:
           {"timestamp":"...","source":"...","trap_oid":"...","varbinds":{...}}
        2. Legacy single-line formats (various patterns)
        """
        # Try JSON format first (from rapax-traphandle.sh)
        # Look for JSON object in the line
        json_start = line.find('{')
        if json_start != -1:
            try:
                json_str = line[json_start:]
                trap_data = json.loads(json_str)

                # Validate required fields
                if 'trap_oid' in trap_data and 'source' in trap_data:
                    return {
                        'trap_oid': trap_data.get('trap_oid', ''),
                        'source_ip': trap_data.get('source', 'Unknown'),
                        'varbinds': trap_data.get('varbinds', {}),
                        'syslog_time': trap_data.get('timestamp', ''),
                        'format': 'json'
                    }
            except json.JSONDecodeError:
                pass  # Not valid JSON, try legacy patterns

        # Try legacy single-line patterns
        for pattern in SNMPTRAP_PATTERNS:
            match = pattern.match(line)
            if match:
                result = match.groupdict()
                result['format'] = 'legacy'
                return result

        return None

    def _process_trap(self, parsed_data):
        """Process a parsed trap and generate alert or log."""
        trap_oid = parsed_data.get('trap_oid', '').strip()
        source_ip = parsed_data.get('source_ip', parsed_data.get('udp_ip', 'Unknown'))
        varbind_str = parsed_data.get('varbinds', '')
        syslog_time = parsed_data.get('syslog_time', '')

        if not trap_oid:
            self.metrics['lines_skipped'] += 1
            return

        # Parse varbinds
        varbinds = self._parse_varbinds(varbind_str)

        # Look up trap definition
        trap_def = TRAP_DEFINITIONS.get(trap_oid)

        if not trap_def:
            # Check for partial OID match (some traps have variable suffixes)
            for def_oid, definition in TRAP_DEFINITIONS.items():
                if trap_oid.startswith(def_oid):
                    trap_def = definition
                    break

        timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        if trap_def:
            trap_name = trap_def['name']
            severity = trap_def['severity']
            category = trap_def['category']
            description = trap_def['description']
            actionable = trap_def['actionable']

            # Extract interface if applicable
            interface = self._extract_interface_from_varbinds(varbinds)
            if interface == 'N/A' and category == 'link-state':
                interface = 'Interface'

            if actionable:
                # Generate alert
                # State is "Up" for CLEAR severity (recovery), "Down" for all others
                state = "Up" if severity == "CLEAR" else "Down"

                alert_data = {
                    'UUID': str(uuid.uuid4()),
                    'Device': source_ip,
                    'Interface': interface,
                    'IP': source_ip,
                    'Status': self._map_severity_to_status(severity),
                    'State': state,
                    'Category': category,
                    'Location': '',
                    'Description': f"{description} - {trap_name}",
                    'FirstOccurred': timestamp,
                    'LastOccurred': timestamp,
                    'Number': 1,
                    'DeviceType': 'Network',
                    'Parent': '',
                    'Notes': [],
                    'Tags': [
                        {'Source': SOURCE},
                        {'TrapOID': trap_oid},
                        {'ComponentID': self.component_id}
                    ],
                    'TrapData': {
                        'oid': trap_oid,
                        'name': trap_name,
                        'severity': severity,
                        'category': category,
                        'varbinds': varbinds,
                        'raw_syslog_time': syslog_time
                    }
                }

                try:
                    rapax.insert_alert(self.logger, alert_data)
                    self.metrics['alerts_generated'] += 1
                    self.logger.info(f"[{SOURCE}] Alert: {trap_name} from {source_ip} ({severity})")
                except Exception as e:
                    self.logger.error(f"[{SOURCE}] Error inserting alert: {e}")
                    self.metrics['errors'] += 1
            else:
                # Generate log entry
                log_data = {
                    '@timestamp': timestamp,
                    'level': severity,
                    'message': f"{description} - {trap_name}",
                    'source': SOURCE,
                    'device': source_ip,
                    'trap_name': trap_name,
                    'trap_oid': trap_oid,
                    'category': category,
                    'varbinds': varbinds,
                    'component_id': self.component_id,
                    'tags': ['snmp-trap', category, trap_name]
                }

                try:
                    rapax.send_message(self.logger, 'logs', log_data)
                    self.metrics['logs_generated'] += 1
                    self.logger.debug(f"[{SOURCE}] Log: {trap_name} from {source_ip} ({severity})")
                except Exception as e:
                    self.logger.error(f"[{SOURCE}] Error sending log: {e}")
                    self.metrics['errors'] += 1
        else:
            # Unknown trap - log it for analysis
            self.metrics['unknown_traps'] += 1
            log_data = {
                '@timestamp': timestamp,
                'level': 'DEBUG',
                'message': f"Unknown SNMP trap received",
                'source': SOURCE,
                'device': source_ip,
                'trap_oid': trap_oid,
                'varbinds': varbinds,
                'component_id': self.component_id,
                'tags': ['snmp-trap', 'unknown']
            }

            try:
                rapax.send_message(self.logger, 'logs', log_data)
                self.logger.debug(f"[{SOURCE}] Unknown trap OID: {trap_oid} from {source_ip}")
            except Exception as e:
                self.logger.error(f"[{SOURCE}] Error logging unknown trap: {e}")
                self.metrics['errors'] += 1

        self.metrics['traps_processed'] += 1

    def _log_metrics(self):
        """Log current processing metrics."""
        self.logger.info(
            f"[{SOURCE}] Metrics - Processed: {self.metrics['traps_processed']}, "
            f"Alerts: {self.metrics['alerts_generated']}, "
            f"Logs: {self.metrics['logs_generated']}, "
            f"Unknown: {self.metrics['unknown_traps']}, "
            f"Errors: {self.metrics['errors']}"
        )

    def run(self):
        """Main execution loop - tail the syslog file and process traps."""
        self.logger.info(f"[{SOURCE}] Starting trap processor daemon")

        # Check if syslog file exists
        if not os.path.exists(self.syslog_file):
            self.logger.error(f"[{SOURCE}] Syslog file not found: {self.syslog_file}")
            return

        # Open file and seek to end (tail -f behavior)
        try:
            with open(self.syslog_file, 'r') as f:
                # Seek to end of file
                f.seek(0, 2)
                self.logger.info(f"[{SOURCE}] Tailing {self.syslog_file} from current position")

                last_metrics_log = time.time()

                while self.running:
                    line = f.readline()

                    if line:
                        # Check if this is an snmptrap line
                        if 'snmptrap' in line.lower():
                            parsed = self._parse_trap_line(line.strip())
                            if parsed:
                                self._process_trap(parsed)
                            else:
                                self.metrics['lines_skipped'] += 1
                                self.logger.debug(f"[{SOURCE}] Could not parse: {line.strip()[:100]}")
                    else:
                        # No new data, sleep briefly
                        time.sleep(0.1)

                    # Log metrics periodically (every 60 seconds)
                    if time.time() - last_metrics_log >= 60:
                        self._log_metrics()
                        last_metrics_log = time.time()

        except FileNotFoundError:
            self.logger.error(f"[{SOURCE}] Syslog file disappeared: {self.syslog_file}")
        except PermissionError:
            self.logger.error(f"[{SOURCE}] Permission denied reading: {self.syslog_file}")
        except Exception as e:
            self.logger.error(f"[{SOURCE}] Unexpected error: {e}")

        # Final metrics log
        self._log_metrics()
        self.logger.info(f"[{SOURCE}] Trap processor stopped")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Cisco SNMP Trap Processor Daemon')
    parser.add_argument('--syslog-file', type=str, default='/var/log/messages',
                        help='Path to syslog file (default: /var/log/messages)')
    parser.add_argument('--component-id', type=str, default='cisco-trap-1',
                        help='Component ID for metrics/tracking (default: cisco-trap-1)')

    args = parser.parse_args()

    try:
        processor = CiscoTrapProcessor(args)
        processor.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
