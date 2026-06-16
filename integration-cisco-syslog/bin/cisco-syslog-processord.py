#!/usr/bin/env python3
"""
Cisco Syslog Processor Daemon
=============================

Processes syslog messages from Cisco devices logged to /var/log/messages.
Supports multiple Cisco platforms: IOS, IOS-XE, NX-OS, IOS-XR, and Meraki.

The processor detects the syslog format by locating the %FACILITY-SEVERITY-MNEMONIC
pattern and parsing device hostname/IP from the surrounding context.

Supports:
- Link state (LINK, LINEPROTO, PORT)
- Routing protocols (BGP, OSPF, EIGRP, ISIS, RIP, PIM)
- Spanning tree (SPANTREE, STP, RSTP)
- Security (SEC_LOGIN, AUTHMGR, DOT1X, SSH, CRYPTO)
- Hardware/Environment (ENVMON, FAN, POWER, PLATFORM, TRANSCEIVER)
- Redundancy (HSRP, VRRP, STACKMGR, REDUNDANCY, VPC)
- Configuration (SYS, CONFIG, PARSER)
- AAA (TACACS, RADIUS, AAA)
- Port security (PORTSEC, DHCP_SNOOPING, DAI)
- System (SNMP, NTP, MEMORY, CPU)
- Multicast (PIM, IGMP, MCAST)
- VPN (IPSEC, DMVPN, TUNNEL)
- Wireless (DOT11, CAPWAP, LWAPP)
- QoS (QOS, QUEUING, POLICING)

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

SOURCE = 'cisco-syslog-processord'
VERSION = '1.0.0'

# =============================================================================
# SYSLOG MESSAGE DEFINITIONS
# =============================================================================
# Cisco syslog format: %FACILITY-SEVERITY-MNEMONIC: message
#
# Severity levels (Cisco):
#   0 - Emergency: System unusable
#   1 - Alert: Immediate action needed
#   2 - Critical: Critical conditions
#   3 - Error: Error conditions
#   4 - Warning: Warning conditions
#   5 - Notice: Normal but significant
#   6 - Informational: Informational messages
#   7 - Debug: Debug-level messages
#
# Rapax severity mapping:
#   CRITICAL: Cisco 0-2 (Emergency, Alert, Critical)
#   MAJOR: Cisco 3 (Error)
#   MINOR: Cisco 4 (Warning)
#   WARNING: Cisco 5 (Notice) - selective actionable
#   INFO: Cisco 6 (Informational) - log only
#   DEBUG: Cisco 7 (Debug) - log only
#
# CLEAR: Determined by mnemonic keywords (UP, RESTORED, OK, ACTIVE, etc.)
# =============================================================================

SYSLOG_DEFINITIONS = {
    # =========================================================================
    # LINK STATE - Interface up/down events
    # =========================================================================
    'LINK-3-UPDOWN': {
        'facility': 'LINK',
        'mnemonic': 'UPDOWN',
        'cisco_severity': 3,
        'description': 'Interface link state changed',
        'category': 'link-state',
        'actionable': True,
        'clear_keywords': ['up'],
        'fault_keywords': ['down']
    },
    'LINK-5-CHANGED': {
        'facility': 'LINK',
        'mnemonic': 'CHANGED',
        'cisco_severity': 5,
        'description': 'Interface link state changed',
        'category': 'link-state',
        'actionable': True,
        'clear_keywords': ['up'],
        'fault_keywords': ['down']
    },
    'LINK-3-ERROR': {
        'facility': 'LINK',
        'mnemonic': 'ERROR',
        'cisco_severity': 3,
        'description': 'Interface link error',
        'category': 'link-state',
        'actionable': True
    },
    'LINK-2-BADUNIT': {
        'facility': 'LINK',
        'mnemonic': 'BADUNIT',
        'cisco_severity': 2,
        'description': 'Bad interface unit',
        'category': 'link-state',
        'actionable': True
    },
    'LINEPROTO-5-UPDOWN': {
        'facility': 'LINEPROTO',
        'mnemonic': 'UPDOWN',
        'cisco_severity': 5,
        'description': 'Line protocol state changed',
        'category': 'link-state',
        'actionable': True,
        'clear_keywords': ['up'],
        'fault_keywords': ['down']
    },
    'PORT-5-IF_UP': {
        'facility': 'PORT',
        'mnemonic': 'IF_UP',
        'cisco_severity': 5,
        'description': 'Interface is up',
        'category': 'link-state',
        'actionable': True,
        'is_clear': True
    },
    'PORT-5-IF_DOWN_LINK_FAILURE': {
        'facility': 'PORT',
        'mnemonic': 'IF_DOWN_LINK_FAILURE',
        'cisco_severity': 5,
        'description': 'Interface down due to link failure',
        'category': 'link-state',
        'actionable': True
    },
    'PORT-5-IF_DOWN_ADMIN_DOWN': {
        'facility': 'PORT',
        'mnemonic': 'IF_DOWN_ADMIN_DOWN',
        'cisco_severity': 5,
        'description': 'Interface administratively down',
        'category': 'link-state',
        'actionable': False
    },
    'PORT-5-IF_DOWN_CFG_CHANGE': {
        'facility': 'PORT',
        'mnemonic': 'IF_DOWN_CFG_CHANGE',
        'cisco_severity': 5,
        'description': 'Interface down due to configuration change',
        'category': 'link-state',
        'actionable': True
    },
    'IF-3-UPDOWN': {
        'facility': 'IF',
        'mnemonic': 'UPDOWN',
        'cisco_severity': 3,
        'description': 'Interface state changed',
        'category': 'link-state',
        'actionable': True,
        'clear_keywords': ['up'],
        'fault_keywords': ['down']
    },
    'ETHPORT-5-IF_UP': {
        'facility': 'ETHPORT',
        'mnemonic': 'IF_UP',
        'cisco_severity': 5,
        'description': 'Ethernet port is up',
        'category': 'link-state',
        'actionable': True,
        'is_clear': True
    },
    'ETHPORT-5-IF_DOWN': {
        'facility': 'ETHPORT',
        'mnemonic': 'IF_DOWN',
        'cisco_severity': 5,
        'description': 'Ethernet port is down',
        'category': 'link-state',
        'actionable': True
    },
    'ETHPORT-5-IF_DOWN_LINK_FAILURE': {
        'facility': 'ETHPORT',
        'mnemonic': 'IF_DOWN_LINK_FAILURE',
        'cisco_severity': 5,
        'description': 'Ethernet port down link failure',
        'category': 'link-state',
        'actionable': True
    },
    'ETHPORT-5-IF_SFP_WARNING': {
        'facility': 'ETHPORT',
        'mnemonic': 'IF_SFP_WARNING',
        'cisco_severity': 5,
        'description': 'SFP warning on ethernet port',
        'category': 'link-state',
        'actionable': True
    },
    'ETHPORT-5-SPEED': {
        'facility': 'ETHPORT',
        'mnemonic': 'SPEED',
        'cisco_severity': 5,
        'description': 'Ethernet port speed change',
        'category': 'link-state',
        'actionable': False
    },
    'TRANSCEIVER-3-NOT_COMPATIBLE': {
        'facility': 'TRANSCEIVER',
        'mnemonic': 'NOT_COMPATIBLE',
        'cisco_severity': 3,
        'description': 'Transceiver not compatible',
        'category': 'link-state',
        'actionable': True
    },
    'TRANSCEIVER-3-NOT_SUPPORTED': {
        'facility': 'TRANSCEIVER',
        'mnemonic': 'NOT_SUPPORTED',
        'cisco_severity': 3,
        'description': 'Transceiver not supported',
        'category': 'link-state',
        'actionable': True
    },
    'TRANSCEIVER-5-INSERTED': {
        'facility': 'TRANSCEIVER',
        'mnemonic': 'INSERTED',
        'cisco_severity': 5,
        'description': 'Transceiver inserted',
        'category': 'link-state',
        'actionable': False
    },
    'TRANSCEIVER-5-REMOVED': {
        'facility': 'TRANSCEIVER',
        'mnemonic': 'REMOVED',
        'cisco_severity': 5,
        'description': 'Transceiver removed',
        'category': 'link-state',
        'actionable': True
    },
    'ILPOWER-3-CONTROLLER_PORT_ERR': {
        'facility': 'ILPOWER',
        'mnemonic': 'CONTROLLER_PORT_ERR',
        'cisco_severity': 3,
        'description': 'PoE controller port error',
        'category': 'link-state',
        'actionable': True
    },
    'ILPOWER-5-POWER_GRANTED': {
        'facility': 'ILPOWER',
        'mnemonic': 'POWER_GRANTED',
        'cisco_severity': 5,
        'description': 'PoE power granted to device',
        'category': 'link-state',
        'actionable': False
    },
    'ILPOWER-5-POWER_DENIED': {
        'facility': 'ILPOWER',
        'mnemonic': 'POWER_DENIED',
        'cisco_severity': 5,
        'description': 'PoE power denied',
        'category': 'link-state',
        'actionable': True
    },
    'ILPOWER-5-IEEE_DISCONNECT': {
        'facility': 'ILPOWER',
        'mnemonic': 'IEEE_DISCONNECT',
        'cisco_severity': 5,
        'description': 'PoE device disconnected',
        'category': 'link-state',
        'actionable': True
    },
    'CDP-4-NATIVE_VLAN_MISMATCH': {
        'facility': 'CDP',
        'mnemonic': 'NATIVE_VLAN_MISMATCH',
        'cisco_severity': 4,
        'description': 'CDP native VLAN mismatch',
        'category': 'link-state',
        'actionable': True
    },
    'CDP-4-DUPLEX_MISMATCH': {
        'facility': 'CDP',
        'mnemonic': 'DUPLEX_MISMATCH',
        'cisco_severity': 4,
        'description': 'CDP duplex mismatch detected',
        'category': 'link-state',
        'actionable': True
    },

    # =========================================================================
    # BGP - Border Gateway Protocol
    # =========================================================================
    'BGP-5-ADJCHANGE': {
        'facility': 'BGP',
        'mnemonic': 'ADJCHANGE',
        'cisco_severity': 5,
        'description': 'BGP neighbor adjacency change',
        'category': 'routing',
        'actionable': True,
        'clear_keywords': ['up', 'established'],
        'fault_keywords': ['down']
    },
    'BGP-3-NOTIFICATION': {
        'facility': 'BGP',
        'mnemonic': 'NOTIFICATION',
        'cisco_severity': 3,
        'description': 'BGP notification received/sent',
        'category': 'routing',
        'actionable': True
    },
    'BGP-4-MAXPFX': {
        'facility': 'BGP',
        'mnemonic': 'MAXPFX',
        'cisco_severity': 4,
        'description': 'BGP maximum prefix limit reached',
        'category': 'routing',
        'actionable': True
    },
    'BGP-5-NBR_RESET': {
        'facility': 'BGP',
        'mnemonic': 'NBR_RESET',
        'cisco_severity': 5,
        'description': 'BGP neighbor reset',
        'category': 'routing',
        'actionable': True
    },
    'BGP-6-ASPATH_UNUSABLE': {
        'facility': 'BGP',
        'mnemonic': 'ASPATH_UNUSABLE',
        'cisco_severity': 6,
        'description': 'BGP AS path unusable',
        'category': 'routing',
        'actionable': False
    },
    'BGP-4-MSGDUMP': {
        'facility': 'BGP',
        'mnemonic': 'MSGDUMP',
        'cisco_severity': 4,
        'description': 'BGP message dump for debugging',
        'category': 'routing',
        'actionable': False
    },
    'BGP-3-CAPABILITY_RECEIVE_ERROR': {
        'facility': 'BGP',
        'mnemonic': 'CAPABILITY_RECEIVE_ERROR',
        'cisco_severity': 3,
        'description': 'BGP capability receive error',
        'category': 'routing',
        'actionable': True
    },
    'BGP_SESSION-5-ADJCHANGE': {
        'facility': 'BGP_SESSION',
        'mnemonic': 'ADJCHANGE',
        'cisco_severity': 5,
        'description': 'BGP session adjacency change',
        'category': 'routing',
        'actionable': True,
        'clear_keywords': ['up', 'established'],
        'fault_keywords': ['down']
    },

    # =========================================================================
    # OSPF - Open Shortest Path First
    # =========================================================================
    'OSPF-5-ADJCHG': {
        'facility': 'OSPF',
        'mnemonic': 'ADJCHG',
        'cisco_severity': 5,
        'description': 'OSPF neighbor adjacency change',
        'category': 'routing',
        'actionable': True,
        'clear_keywords': ['full'],
        'fault_keywords': ['down', 'exstart', 'init']
    },
    'OSPF-4-ERRRCV': {
        'facility': 'OSPF',
        'mnemonic': 'ERRRCV',
        'cisco_severity': 4,
        'description': 'OSPF received error packet',
        'category': 'routing',
        'actionable': True
    },
    'OSPF-4-NOVALIDKEY': {
        'facility': 'OSPF',
        'mnemonic': 'NOVALIDKEY',
        'cisco_severity': 4,
        'description': 'OSPF no valid authentication key',
        'category': 'routing',
        'actionable': True
    },
    'OSPF-4-BADLSTYPE': {
        'facility': 'OSPF',
        'mnemonic': 'BADLSTYPE',
        'cisco_severity': 4,
        'description': 'OSPF bad LSA type received',
        'category': 'routing',
        'actionable': True
    },
    'OSPF-5-NBRSTATE': {
        'facility': 'OSPF',
        'mnemonic': 'NBRSTATE',
        'cisco_severity': 5,
        'description': 'OSPF neighbor state change',
        'category': 'routing',
        'actionable': True,
        'clear_keywords': ['full'],
        'fault_keywords': ['down']
    },
    'OSPF-4-DUPRID': {
        'facility': 'OSPF',
        'mnemonic': 'DUPRID',
        'cisco_severity': 4,
        'description': 'OSPF duplicate router ID detected',
        'category': 'routing',
        'actionable': True
    },
    'OSPF-4-CONFLICTING_LSAID': {
        'facility': 'OSPF',
        'mnemonic': 'CONFLICTING_LSAID',
        'cisco_severity': 4,
        'description': 'OSPF conflicting LSA ID',
        'category': 'routing',
        'actionable': True
    },
    'OSPF-5-CONFIG_CHANGE': {
        'facility': 'OSPF',
        'mnemonic': 'CONFIG_CHANGE',
        'cisco_severity': 5,
        'description': 'OSPF configuration change',
        'category': 'routing',
        'actionable': False
    },
    'OSPF-6-NEIGHBOR': {
        'facility': 'OSPF',
        'mnemonic': 'NEIGHBOR',
        'cisco_severity': 6,
        'description': 'OSPF neighbor event',
        'category': 'routing',
        'actionable': False
    },
    'OSPF-3-INTRA_OVERFLOW': {
        'facility': 'OSPF',
        'mnemonic': 'INTRA_OVERFLOW',
        'cisco_severity': 3,
        'description': 'OSPF intra-area overflow',
        'category': 'routing',
        'actionable': True
    },

    # =========================================================================
    # EIGRP - Enhanced Interior Gateway Routing Protocol
    # =========================================================================
    'EIGRP-5-NBRCHANGE': {
        'facility': 'EIGRP',
        'mnemonic': 'NBRCHANGE',
        'cisco_severity': 5,
        'description': 'EIGRP neighbor change',
        'category': 'routing',
        'actionable': True,
        'clear_keywords': ['up', 'new adjacency'],
        'fault_keywords': ['down', 'went down', 'peer down', 'holding time expired']
    },
    'DUAL-5-NBRCHANGE': {
        'facility': 'DUAL',
        'mnemonic': 'NBRCHANGE',
        'cisco_severity': 5,
        'description': 'DUAL/EIGRP neighbor change',
        'category': 'routing',
        'actionable': True,
        'clear_keywords': ['up', 'new adjacency'],
        'fault_keywords': ['down', 'went down']
    },
    'EIGRP-4-AUTHFAIL': {
        'facility': 'EIGRP',
        'mnemonic': 'AUTHFAIL',
        'cisco_severity': 4,
        'description': 'EIGRP authentication failure',
        'category': 'routing',
        'actionable': True
    },
    'EIGRP-3-K_VALUE_MISMATCH': {
        'facility': 'EIGRP',
        'mnemonic': 'K_VALUE_MISMATCH',
        'cisco_severity': 3,
        'description': 'EIGRP K-value mismatch with neighbor',
        'category': 'routing',
        'actionable': True
    },
    'EIGRP-5-ROUTECHANGE': {
        'facility': 'EIGRP',
        'mnemonic': 'ROUTECHANGE',
        'cisco_severity': 5,
        'description': 'EIGRP route change',
        'category': 'routing',
        'actionable': False
    },

    # =========================================================================
    # ISIS - Intermediate System to Intermediate System
    # =========================================================================
    'ISIS-5-ADJCHANGE': {
        'facility': 'ISIS',
        'mnemonic': 'ADJCHANGE',
        'cisco_severity': 5,
        'description': 'IS-IS adjacency change',
        'category': 'routing',
        'actionable': True,
        'clear_keywords': ['up'],
        'fault_keywords': ['down']
    },
    'ISIS-4-AUTHFAIL': {
        'facility': 'ISIS',
        'mnemonic': 'AUTHFAIL',
        'cisco_severity': 4,
        'description': 'IS-IS authentication failure',
        'category': 'routing',
        'actionable': True
    },
    'ISIS-3-NOADJ': {
        'facility': 'ISIS',
        'mnemonic': 'NOADJ',
        'cisco_severity': 3,
        'description': 'IS-IS no adjacency possible',
        'category': 'routing',
        'actionable': True
    },
    'ISIS-4-LSPFULL': {
        'facility': 'ISIS',
        'mnemonic': 'LSPFULL',
        'cisco_severity': 4,
        'description': 'IS-IS LSP database full',
        'category': 'routing',
        'actionable': True
    },
    'ISIS-5-NEWADJ': {
        'facility': 'ISIS',
        'mnemonic': 'NEWADJ',
        'cisco_severity': 5,
        'description': 'IS-IS new adjacency formed',
        'category': 'routing',
        'actionable': True,
        'is_clear': True
    },

    # =========================================================================
    # RIP - Routing Information Protocol
    # =========================================================================
    'RIP-4-AUTHFAIL': {
        'facility': 'RIP',
        'mnemonic': 'AUTHFAIL',
        'cisco_severity': 4,
        'description': 'RIP authentication failure',
        'category': 'routing',
        'actionable': True
    },
    'RIP-3-BADPKT': {
        'facility': 'RIP',
        'mnemonic': 'BADPKT',
        'cisco_severity': 3,
        'description': 'RIP bad packet received',
        'category': 'routing',
        'actionable': True
    },

    # =========================================================================
    # PIM - Protocol Independent Multicast
    # =========================================================================
    'PIM-5-NBRCHG': {
        'facility': 'PIM',
        'mnemonic': 'NBRCHG',
        'cisco_severity': 5,
        'description': 'PIM neighbor change',
        'category': 'multicast',
        'actionable': True,
        'clear_keywords': ['up'],
        'fault_keywords': ['down', 'expired']
    },
    'PIM-4-INVALID_RP_ADDR': {
        'facility': 'PIM',
        'mnemonic': 'INVALID_RP_ADDR',
        'cisco_severity': 4,
        'description': 'PIM invalid RP address',
        'category': 'multicast',
        'actionable': True
    },
    'PIM-3-INVLD_RP_JOIN': {
        'facility': 'PIM',
        'mnemonic': 'INVLD_RP_JOIN',
        'cisco_severity': 3,
        'description': 'PIM invalid RP join',
        'category': 'multicast',
        'actionable': True
    },
    'PIM-5-DRCHG': {
        'facility': 'PIM',
        'mnemonic': 'DRCHG',
        'cisco_severity': 5,
        'description': 'PIM designated router changed',
        'category': 'multicast',
        'actionable': True
    },

    # =========================================================================
    # IGMP - Internet Group Management Protocol
    # =========================================================================
    'IGMP-3-INVALID_GROUP': {
        'facility': 'IGMP',
        'mnemonic': 'INVALID_GROUP',
        'cisco_severity': 3,
        'description': 'IGMP invalid group address',
        'category': 'multicast',
        'actionable': True
    },
    'IGMP-5-LIMIT_EXCEED': {
        'facility': 'IGMP',
        'mnemonic': 'LIMIT_EXCEED',
        'cisco_severity': 5,
        'description': 'IGMP group limit exceeded',
        'category': 'multicast',
        'actionable': True
    },
    'IGMPSNOOPING-5-GROUP_LIMIT': {
        'facility': 'IGMPSNOOPING',
        'mnemonic': 'GROUP_LIMIT',
        'cisco_severity': 5,
        'description': 'IGMP snooping group limit reached',
        'category': 'multicast',
        'actionable': True
    },

    # =========================================================================
    # SPANNING TREE - STP/RSTP/MST
    # =========================================================================
    'SPANTREE-2-BLOCK_PVID_LOCAL': {
        'facility': 'SPANTREE',
        'mnemonic': 'BLOCK_PVID_LOCAL',
        'cisco_severity': 2,
        'description': 'STP blocking port - PVID mismatch',
        'category': 'spanning-tree',
        'actionable': True
    },
    'SPANTREE-2-BLOCK_PVID_PEER': {
        'facility': 'SPANTREE',
        'mnemonic': 'BLOCK_PVID_PEER',
        'cisco_severity': 2,
        'description': 'STP blocking port - peer PVID mismatch',
        'category': 'spanning-tree',
        'actionable': True
    },
    'SPANTREE-2-CHNL_MISCFG': {
        'facility': 'SPANTREE',
        'mnemonic': 'CHNL_MISCFG',
        'cisco_severity': 2,
        'description': 'STP channel misconfiguration detected',
        'category': 'spanning-tree',
        'actionable': True
    },
    'SPANTREE-2-LOOPGUARD_BLOCK': {
        'facility': 'SPANTREE',
        'mnemonic': 'LOOPGUARD_BLOCK',
        'cisco_severity': 2,
        'description': 'STP loop guard blocking port',
        'category': 'spanning-tree',
        'actionable': True
    },
    'SPANTREE-2-LOOPGUARD_UNBLOCK': {
        'facility': 'SPANTREE',
        'mnemonic': 'LOOPGUARD_UNBLOCK',
        'cisco_severity': 2,
        'description': 'STP loop guard unblocking port',
        'category': 'spanning-tree',
        'actionable': True,
        'is_clear': True
    },
    'SPANTREE-2-ROOTGUARD_BLOCK': {
        'facility': 'SPANTREE',
        'mnemonic': 'ROOTGUARD_BLOCK',
        'cisco_severity': 2,
        'description': 'STP root guard blocking port',
        'category': 'spanning-tree',
        'actionable': True
    },
    'SPANTREE-2-ROOTGUARD_UNBLOCK': {
        'facility': 'SPANTREE',
        'mnemonic': 'ROOTGUARD_UNBLOCK',
        'cisco_severity': 2,
        'description': 'STP root guard unblocking port',
        'category': 'spanning-tree',
        'actionable': True,
        'is_clear': True
    },
    'SPANTREE-5-TOPOTRAP': {
        'facility': 'SPANTREE',
        'mnemonic': 'TOPOTRAP',
        'cisco_severity': 5,
        'description': 'STP topology change detected',
        'category': 'spanning-tree',
        'actionable': True
    },
    'SPANTREE-5-ROOTCHANGE': {
        'facility': 'SPANTREE',
        'mnemonic': 'ROOTCHANGE',
        'cisco_severity': 5,
        'description': 'STP root bridge change',
        'category': 'spanning-tree',
        'actionable': True
    },
    'SPANTREE-2-RECV_PVID_ERR': {
        'facility': 'SPANTREE',
        'mnemonic': 'RECV_PVID_ERR',
        'cisco_severity': 2,
        'description': 'STP received PVID error',
        'category': 'spanning-tree',
        'actionable': True
    },
    'SPANTREE-7-PORTDEL_SUCCESS': {
        'facility': 'SPANTREE',
        'mnemonic': 'PORTDEL_SUCCESS',
        'cisco_severity': 7,
        'description': 'STP port deletion successful',
        'category': 'spanning-tree',
        'actionable': False
    },
    'STP-2-INCONSISTENT': {
        'facility': 'STP',
        'mnemonic': 'INCONSISTENT',
        'cisco_severity': 2,
        'description': 'STP inconsistency detected',
        'category': 'spanning-tree',
        'actionable': True
    },
    'STP-5-ROLE_CHG': {
        'facility': 'STP',
        'mnemonic': 'ROLE_CHG',
        'cisco_severity': 5,
        'description': 'STP port role change',
        'category': 'spanning-tree',
        'actionable': False
    },
    'STP-6-PORT_STATE': {
        'facility': 'STP',
        'mnemonic': 'PORT_STATE',
        'cisco_severity': 6,
        'description': 'STP port state change',
        'category': 'spanning-tree',
        'actionable': False
    },
    'RSTP-5-TOPOLOGY_CHANGE': {
        'facility': 'RSTP',
        'mnemonic': 'TOPOLOGY_CHANGE',
        'cisco_severity': 5,
        'description': 'RSTP topology change',
        'category': 'spanning-tree',
        'actionable': True
    },
    'MST-5-TOPOLOGY_CHANGE': {
        'facility': 'MST',
        'mnemonic': 'TOPOLOGY_CHANGE',
        'cisco_severity': 5,
        'description': 'MST topology change',
        'category': 'spanning-tree',
        'actionable': True
    },
    'EC-5-BUNDLE': {
        'facility': 'EC',
        'mnemonic': 'BUNDLE',
        'cisco_severity': 5,
        'description': 'EtherChannel bundled',
        'category': 'spanning-tree',
        'actionable': True,
        'is_clear': True
    },
    'EC-5-UNBUNDLE': {
        'facility': 'EC',
        'mnemonic': 'UNBUNDLE',
        'cisco_severity': 5,
        'description': 'EtherChannel unbundled',
        'category': 'spanning-tree',
        'actionable': True
    },
    'EC-5-STAYDOWN': {
        'facility': 'EC',
        'mnemonic': 'STAYDOWN',
        'cisco_severity': 5,
        'description': 'EtherChannel member staying down',
        'category': 'spanning-tree',
        'actionable': True
    },
    'EC-5-CANNOT_BUNDLE': {
        'facility': 'EC',
        'mnemonic': 'CANNOT_BUNDLE',
        'cisco_severity': 5,
        'description': 'EtherChannel cannot bundle port',
        'category': 'spanning-tree',
        'actionable': True
    },
    'EC-5-COMPATIBLE': {
        'facility': 'EC',
        'mnemonic': 'COMPATIBLE',
        'cisco_severity': 5,
        'description': 'EtherChannel ports compatible',
        'category': 'spanning-tree',
        'actionable': False
    },

    # =========================================================================
    # SECURITY - Authentication, Login, SSH
    # =========================================================================
    'SEC_LOGIN-5-LOGIN_SUCCESS': {
        'facility': 'SEC_LOGIN',
        'mnemonic': 'LOGIN_SUCCESS',
        'cisco_severity': 5,
        'description': 'Login succeeded',
        'category': 'security',
        'actionable': False
    },
    'SEC_LOGIN-4-LOGIN_FAILED': {
        'facility': 'SEC_LOGIN',
        'mnemonic': 'LOGIN_FAILED',
        'cisco_severity': 4,
        'description': 'Login failed',
        'category': 'security',
        'actionable': True
    },
    'SEC_LOGIN-5-QUIET_MODE_OFF': {
        'facility': 'SEC_LOGIN',
        'mnemonic': 'QUIET_MODE_OFF',
        'cisco_severity': 5,
        'description': 'Quiet mode disabled - login allowed',
        'category': 'security',
        'actionable': False,
        'is_clear': True
    },
    'SEC_LOGIN-1-QUIET_MODE_ON': {
        'facility': 'SEC_LOGIN',
        'mnemonic': 'QUIET_MODE_ON',
        'cisco_severity': 1,
        'description': 'Quiet mode enabled - excessive failures',
        'category': 'security',
        'actionable': True
    },
    'SEC-6-IPACCESSLOGP': {
        'facility': 'SEC',
        'mnemonic': 'IPACCESSLOGP',
        'cisco_severity': 6,
        'description': 'IP access list log entry',
        'category': 'security',
        'actionable': False
    },
    'SEC-6-IPACCESSLOGNP': {
        'facility': 'SEC',
        'mnemonic': 'IPACCESSLOGNP',
        'cisco_severity': 6,
        'description': 'IP access list log entry (no port)',
        'category': 'security',
        'actionable': False
    },
    'SEC-6-IPACCESSLOGDP': {
        'facility': 'SEC',
        'mnemonic': 'IPACCESSLOGDP',
        'cisco_severity': 6,
        'description': 'IP access list deny log entry',
        'category': 'security',
        'actionable': False
    },
    'SSH-5-SSH2_USERAUTH': {
        'facility': 'SSH',
        'mnemonic': 'SSH2_USERAUTH',
        'cisco_severity': 5,
        'description': 'SSH user authentication',
        'category': 'security',
        'actionable': False
    },
    'SSH-5-SSH2_SESSION': {
        'facility': 'SSH',
        'mnemonic': 'SSH2_SESSION',
        'cisco_severity': 5,
        'description': 'SSH session event',
        'category': 'security',
        'actionable': False
    },
    'SSH-5-SSH2_CLOSE': {
        'facility': 'SSH',
        'mnemonic': 'SSH2_CLOSE',
        'cisco_severity': 5,
        'description': 'SSH session closed',
        'category': 'security',
        'actionable': False
    },
    'SSH-4-SSH2_UNEXPECTED_MSG': {
        'facility': 'SSH',
        'mnemonic': 'SSH2_UNEXPECTED_MSG',
        'cisco_severity': 4,
        'description': 'SSH unexpected message received',
        'category': 'security',
        'actionable': True
    },
    'AUTHMGR-5-START': {
        'facility': 'AUTHMGR',
        'mnemonic': 'START',
        'cisco_severity': 5,
        'description': 'Authentication started',
        'category': 'security',
        'actionable': False
    },
    'AUTHMGR-5-SUCCESS': {
        'facility': 'AUTHMGR',
        'mnemonic': 'SUCCESS',
        'cisco_severity': 5,
        'description': 'Authentication succeeded',
        'category': 'security',
        'actionable': False,
        'is_clear': True
    },
    'AUTHMGR-5-FAIL': {
        'facility': 'AUTHMGR',
        'mnemonic': 'FAIL',
        'cisco_severity': 5,
        'description': 'Authentication failed',
        'category': 'security',
        'actionable': True
    },
    'AUTHMGR-7-FAILOVER': {
        'facility': 'AUTHMGR',
        'mnemonic': 'FAILOVER',
        'cisco_severity': 7,
        'description': 'Authentication failover',
        'category': 'security',
        'actionable': False
    },
    'DOT1X-5-SUCCESS': {
        'facility': 'DOT1X',
        'mnemonic': 'SUCCESS',
        'cisco_severity': 5,
        'description': '802.1X authentication success',
        'category': 'security',
        'actionable': False,
        'is_clear': True
    },
    'DOT1X-5-FAIL': {
        'facility': 'DOT1X',
        'mnemonic': 'FAIL',
        'cisco_severity': 5,
        'description': '802.1X authentication failed',
        'category': 'security',
        'actionable': True
    },
    'DOT1X_SWITCH-5-ERR_ADDING_ADDRESS': {
        'facility': 'DOT1X_SWITCH',
        'mnemonic': 'ERR_ADDING_ADDRESS',
        'cisco_severity': 5,
        'description': '802.1X error adding address',
        'category': 'security',
        'actionable': True
    },
    'MAB-5-SUCCESS': {
        'facility': 'MAB',
        'mnemonic': 'SUCCESS',
        'cisco_severity': 5,
        'description': 'MAC Authentication Bypass success',
        'category': 'security',
        'actionable': False,
        'is_clear': True
    },
    'MAB-5-FAIL': {
        'facility': 'MAB',
        'mnemonic': 'FAIL',
        'cisco_severity': 5,
        'description': 'MAC Authentication Bypass failed',
        'category': 'security',
        'actionable': True
    },
    'CRYPTO-4-RECVD_PKT_INV_SPI': {
        'facility': 'CRYPTO',
        'mnemonic': 'RECVD_PKT_INV_SPI',
        'cisco_severity': 4,
        'description': 'Crypto received packet with invalid SPI',
        'category': 'security',
        'actionable': True
    },
    'CRYPTO-4-IKMP_NO_SA': {
        'facility': 'CRYPTO',
        'mnemonic': 'IKMP_NO_SA',
        'cisco_severity': 4,
        'description': 'IKE no security association',
        'category': 'security',
        'actionable': True
    },
    'CRYPTO-4-PKT_REPLAY_ERR': {
        'facility': 'CRYPTO',
        'mnemonic': 'PKT_REPLAY_ERR',
        'cisco_severity': 4,
        'description': 'Crypto packet replay error',
        'category': 'security',
        'actionable': True
    },
    'CRYPTO-5-SESSION_STATUS': {
        'facility': 'CRYPTO',
        'mnemonic': 'SESSION_STATUS',
        'cisco_severity': 5,
        'description': 'Crypto session status change',
        'category': 'security',
        'actionable': True,
        'clear_keywords': ['up', 'created', 'established'],
        'fault_keywords': ['down', 'deleted', 'removed']
    },

    # =========================================================================
    # PORT SECURITY
    # =========================================================================
    'PORTSEC-2-VIOLATION': {
        'facility': 'PORTSEC',
        'mnemonic': 'VIOLATION',
        'cisco_severity': 2,
        'description': 'Port security violation',
        'category': 'port-security',
        'actionable': True
    },
    'PM-4-ERR_DISABLE': {
        'facility': 'PM',
        'mnemonic': 'ERR_DISABLE',
        'cisco_severity': 4,
        'description': 'Port error disabled',
        'category': 'port-security',
        'actionable': True
    },
    'PM-4-ERR_RECOVER': {
        'facility': 'PM',
        'mnemonic': 'ERR_RECOVER',
        'cisco_severity': 4,
        'description': 'Port error recovered',
        'category': 'port-security',
        'actionable': True,
        'is_clear': True
    },
    'DHCP_SNOOPING-5-DHCP_SNOOPING_ERRDISABLE_WARNING': {
        'facility': 'DHCP_SNOOPING',
        'mnemonic': 'DHCP_SNOOPING_ERRDISABLE_WARNING',
        'cisco_severity': 5,
        'description': 'DHCP snooping error disable warning',
        'category': 'port-security',
        'actionable': True
    },
    'DHCP_SNOOPING-4-DHCP_SNOOPING_ERRDISABLE': {
        'facility': 'DHCP_SNOOPING',
        'mnemonic': 'DHCP_SNOOPING_ERRDISABLE',
        'cisco_severity': 4,
        'description': 'DHCP snooping port disabled',
        'category': 'port-security',
        'actionable': True
    },
    'DAI-4-DHCP_SNOOPING_DENY': {
        'facility': 'DAI',
        'mnemonic': 'DHCP_SNOOPING_DENY',
        'cisco_severity': 4,
        'description': 'Dynamic ARP Inspection denied packet',
        'category': 'port-security',
        'actionable': True
    },
    'DAI-4-PACKET_RATE_EXCEEDED': {
        'facility': 'DAI',
        'mnemonic': 'PACKET_RATE_EXCEEDED',
        'cisco_severity': 4,
        'description': 'DAI packet rate exceeded',
        'category': 'port-security',
        'actionable': True
    },
    'SW_DAI-4-DHCP_SNOOPING_DENY': {
        'facility': 'SW_DAI',
        'mnemonic': 'DHCP_SNOOPING_DENY',
        'cisco_severity': 4,
        'description': 'DAI denied ARP packet',
        'category': 'port-security',
        'actionable': True
    },
    'STORM_CONTROL-3-FILTERED': {
        'facility': 'STORM_CONTROL',
        'mnemonic': 'FILTERED',
        'cisco_severity': 3,
        'description': 'Storm control traffic filtered',
        'category': 'port-security',
        'actionable': True
    },
    'STORM_CONTROL-3-SHUTDOWN': {
        'facility': 'STORM_CONTROL',
        'mnemonic': 'SHUTDOWN',
        'cisco_severity': 3,
        'description': 'Storm control shutdown port',
        'category': 'port-security',
        'actionable': True
    },

    # =========================================================================
    # HARDWARE/ENVIRONMENT
    # =========================================================================
    'ENVMON-4-TEMPWARNING': {
        'facility': 'ENVMON',
        'mnemonic': 'TEMPWARNING',
        'cisco_severity': 4,
        'description': 'Temperature warning threshold exceeded',
        'category': 'hardware',
        'actionable': True
    },
    'ENVMON-2-TEMPSHUT': {
        'facility': 'ENVMON',
        'mnemonic': 'TEMPSHUT',
        'cisco_severity': 2,
        'description': 'Temperature critical - shutdown',
        'category': 'hardware',
        'actionable': True
    },
    'ENVMON-3-FAN_FAIL': {
        'facility': 'ENVMON',
        'mnemonic': 'FAN_FAIL',
        'cisco_severity': 3,
        'description': 'Fan failure detected',
        'category': 'hardware',
        'actionable': True
    },
    'ENVMON-5-FAN_OK': {
        'facility': 'ENVMON',
        'mnemonic': 'FAN_OK',
        'cisco_severity': 5,
        'description': 'Fan operating normally',
        'category': 'hardware',
        'actionable': True,
        'is_clear': True
    },
    'ENVMON-3-PS_FAIL': {
        'facility': 'ENVMON',
        'mnemonic': 'PS_FAIL',
        'cisco_severity': 3,
        'description': 'Power supply failure',
        'category': 'hardware',
        'actionable': True
    },
    'ENVMON-5-PS_OK': {
        'facility': 'ENVMON',
        'mnemonic': 'PS_OK',
        'cisco_severity': 5,
        'description': 'Power supply operating normally',
        'category': 'hardware',
        'actionable': True,
        'is_clear': True
    },
    'ENVMON-4-VOLTAGE_WARNING': {
        'facility': 'ENVMON',
        'mnemonic': 'VOLTAGE_WARNING',
        'cisco_severity': 4,
        'description': 'Voltage warning threshold exceeded',
        'category': 'hardware',
        'actionable': True
    },
    'ENVMON-2-VOLTAGE_CRITICAL': {
        'facility': 'ENVMON',
        'mnemonic': 'VOLTAGE_CRITICAL',
        'cisco_severity': 2,
        'description': 'Voltage critical condition',
        'category': 'hardware',
        'actionable': True
    },
    'FAN-3-FAN_FAILED': {
        'facility': 'FAN',
        'mnemonic': 'FAN_FAILED',
        'cisco_severity': 3,
        'description': 'Fan failed',
        'category': 'hardware',
        'actionable': True
    },
    'FAN-5-FAN_OK': {
        'facility': 'FAN',
        'mnemonic': 'FAN_OK',
        'cisco_severity': 5,
        'description': 'Fan operational',
        'category': 'hardware',
        'actionable': True,
        'is_clear': True
    },
    'FAN-6-FAN_RPM_CHANGE': {
        'facility': 'FAN',
        'mnemonic': 'FAN_RPM_CHANGE',
        'cisco_severity': 6,
        'description': 'Fan RPM changed',
        'category': 'hardware',
        'actionable': False
    },
    'POWER-3-POWER_FAIL': {
        'facility': 'POWER',
        'mnemonic': 'POWER_FAIL',
        'cisco_severity': 3,
        'description': 'Power supply failed',
        'category': 'hardware',
        'actionable': True
    },
    'POWER-5-POWER_OK': {
        'facility': 'POWER',
        'mnemonic': 'POWER_OK',
        'cisco_severity': 5,
        'description': 'Power supply OK',
        'category': 'hardware',
        'actionable': True,
        'is_clear': True
    },
    'PLATFORM-3-FAN_TRAY_FAIL': {
        'facility': 'PLATFORM',
        'mnemonic': 'FAN_TRAY_FAIL',
        'cisco_severity': 3,
        'description': 'Fan tray failure',
        'category': 'hardware',
        'actionable': True
    },
    'PLATFORM-5-FAN_TRAY_OK': {
        'facility': 'PLATFORM',
        'mnemonic': 'FAN_TRAY_OK',
        'cisco_severity': 5,
        'description': 'Fan tray OK',
        'category': 'hardware',
        'actionable': True,
        'is_clear': True
    },
    'PLATFORM-4-TEMP_WARNING': {
        'facility': 'PLATFORM',
        'mnemonic': 'TEMP_WARNING',
        'cisco_severity': 4,
        'description': 'Platform temperature warning',
        'category': 'hardware',
        'actionable': True
    },
    'PLATFORM-2-TEMP_CRITICAL': {
        'facility': 'PLATFORM',
        'mnemonic': 'TEMP_CRITICAL',
        'cisco_severity': 2,
        'description': 'Platform temperature critical',
        'category': 'hardware',
        'actionable': True
    },
    'PLATFORM-3-PS_FAIL': {
        'facility': 'PLATFORM',
        'mnemonic': 'PS_FAIL',
        'cisco_severity': 3,
        'description': 'Platform power supply failure',
        'category': 'hardware',
        'actionable': True
    },
    'PLATFORM-5-PS_OK': {
        'facility': 'PLATFORM',
        'mnemonic': 'PS_OK',
        'cisco_severity': 5,
        'description': 'Platform power supply OK',
        'category': 'hardware',
        'actionable': True,
        'is_clear': True
    },
    'PLATFORM-6-MODULE_INSERTED': {
        'facility': 'PLATFORM',
        'mnemonic': 'MODULE_INSERTED',
        'cisco_severity': 6,
        'description': 'Module inserted',
        'category': 'hardware',
        'actionable': False
    },
    'PLATFORM-6-MODULE_REMOVED': {
        'facility': 'PLATFORM',
        'mnemonic': 'MODULE_REMOVED',
        'cisco_severity': 6,
        'description': 'Module removed',
        'category': 'hardware',
        'actionable': True
    },
    'HARDWARE-3-CHASSIS_TEMP': {
        'facility': 'HARDWARE',
        'mnemonic': 'CHASSIS_TEMP',
        'cisco_severity': 3,
        'description': 'Chassis temperature alert',
        'category': 'hardware',
        'actionable': True
    },
    'SUPERVISOR-3-SUP_FAIL': {
        'facility': 'SUPERVISOR',
        'mnemonic': 'SUP_FAIL',
        'cisco_severity': 3,
        'description': 'Supervisor module failure',
        'category': 'hardware',
        'actionable': True
    },
    'PMAN-3-PROCFAILCRIT': {
        'facility': 'PMAN',
        'mnemonic': 'PROCFAILCRIT',
        'cisco_severity': 3,
        'description': 'Critical process failure',
        'category': 'hardware',
        'actionable': True
    },
    'MODULE-5-MOD_OK': {
        'facility': 'MODULE',
        'mnemonic': 'MOD_OK',
        'cisco_severity': 5,
        'description': 'Module online',
        'category': 'hardware',
        'actionable': True,
        'is_clear': True
    },
    'MODULE-3-MOD_FAIL': {
        'facility': 'MODULE',
        'mnemonic': 'MOD_FAIL',
        'cisco_severity': 3,
        'description': 'Module failed',
        'category': 'hardware',
        'actionable': True
    },
    'MODULE-5-MOD_DIAG_FAIL': {
        'facility': 'MODULE',
        'mnemonic': 'MOD_DIAG_FAIL',
        'cisco_severity': 5,
        'description': 'Module diagnostic failed',
        'category': 'hardware',
        'actionable': True
    },

    # =========================================================================
    # REDUNDANCY/HIGH AVAILABILITY
    # =========================================================================
    'HSRP-5-STATECHANGE': {
        'facility': 'HSRP',
        'mnemonic': 'STATECHANGE',
        'cisco_severity': 5,
        'description': 'HSRP state changed',
        'category': 'redundancy',
        'actionable': True,
        'clear_keywords': ['active', 'standby'],
        'fault_keywords': ['init', 'speak', 'listen']
    },
    'HSRP-6-STATECHANGE': {
        'facility': 'HSRP',
        'mnemonic': 'STATECHANGE',
        'cisco_severity': 6,
        'description': 'HSRP state changed',
        'category': 'redundancy',
        'actionable': True,
        'clear_keywords': ['active', 'standby'],
        'fault_keywords': ['init', 'speak', 'listen']
    },
    'VRRP-6-STATECHANGE': {
        'facility': 'VRRP',
        'mnemonic': 'STATECHANGE',
        'cisco_severity': 6,
        'description': 'VRRP state changed',
        'category': 'redundancy',
        'actionable': True,
        'clear_keywords': ['master', 'backup'],
        'fault_keywords': ['init']
    },
    'GLBP-5-STATECHANGE': {
        'facility': 'GLBP',
        'mnemonic': 'STATECHANGE',
        'cisco_severity': 5,
        'description': 'GLBP state changed',
        'category': 'redundancy',
        'actionable': True,
        'clear_keywords': ['active', 'standby'],
        'fault_keywords': ['init', 'speak', 'listen']
    },
    'REDUNDANCY-5-SWITCHOVER_HISTORY': {
        'facility': 'REDUNDANCY',
        'mnemonic': 'SWITCHOVER_HISTORY',
        'cisco_severity': 5,
        'description': 'Redundancy switchover event',
        'category': 'redundancy',
        'actionable': True
    },
    'REDUNDANCY-3-PEER_DOWN': {
        'facility': 'REDUNDANCY',
        'mnemonic': 'PEER_DOWN',
        'cisco_severity': 3,
        'description': 'Redundancy peer down',
        'category': 'redundancy',
        'actionable': True
    },
    'REDUNDANCY-5-PEER_UP': {
        'facility': 'REDUNDANCY',
        'mnemonic': 'PEER_UP',
        'cisco_severity': 5,
        'description': 'Redundancy peer up',
        'category': 'redundancy',
        'actionable': True,
        'is_clear': True
    },
    'STACKMGR-5-SWITCH_ADDED': {
        'facility': 'STACKMGR',
        'mnemonic': 'SWITCH_ADDED',
        'cisco_severity': 5,
        'description': 'Switch added to stack',
        'category': 'redundancy',
        'actionable': True,
        'is_clear': True
    },
    'STACKMGR-5-SWITCH_REMOVED': {
        'facility': 'STACKMGR',
        'mnemonic': 'SWITCH_REMOVED',
        'cisco_severity': 5,
        'description': 'Switch removed from stack',
        'category': 'redundancy',
        'actionable': True
    },
    'STACKMGR-4-SWITCH_REMOVED_CRASH': {
        'facility': 'STACKMGR',
        'mnemonic': 'SWITCH_REMOVED_CRASH',
        'cisco_severity': 4,
        'description': 'Switch removed from stack - crashed',
        'category': 'redundancy',
        'actionable': True
    },
    'STACKMGR-5-MASTER_ELECTED': {
        'facility': 'STACKMGR',
        'mnemonic': 'MASTER_ELECTED',
        'cisco_severity': 5,
        'description': 'New stack master elected',
        'category': 'redundancy',
        'actionable': True
    },
    'STACKMGR-3-STACK_LINK_CHANGE': {
        'facility': 'STACKMGR',
        'mnemonic': 'STACK_LINK_CHANGE',
        'cisco_severity': 3,
        'description': 'Stack link state changed',
        'category': 'redundancy',
        'actionable': True,
        'clear_keywords': ['up', 'ok'],
        'fault_keywords': ['down', 'failed']
    },
    'VPC-2-PEER_KEEP_ALIVE_RECV_FAIL': {
        'facility': 'VPC',
        'mnemonic': 'PEER_KEEP_ALIVE_RECV_FAIL',
        'cisco_severity': 2,
        'description': 'vPC peer keepalive receive failure',
        'category': 'redundancy',
        'actionable': True
    },
    'VPC-5-PEER_KEEP_ALIVE_RECV_SUCCESS': {
        'facility': 'VPC',
        'mnemonic': 'PEER_KEEP_ALIVE_RECV_SUCCESS',
        'cisco_severity': 5,
        'description': 'vPC peer keepalive receive success',
        'category': 'redundancy',
        'actionable': True,
        'is_clear': True
    },
    'VPC-2-DUAL_ACTIVE_DETECTED': {
        'facility': 'VPC',
        'mnemonic': 'DUAL_ACTIVE_DETECTED',
        'cisco_severity': 2,
        'description': 'vPC dual active (split-brain) detected',
        'category': 'redundancy',
        'actionable': True
    },
    'VPC-5-VPC_PEER_LINK_UP': {
        'facility': 'VPC',
        'mnemonic': 'VPC_PEER_LINK_UP',
        'cisco_severity': 5,
        'description': 'vPC peer link is up',
        'category': 'redundancy',
        'actionable': True,
        'is_clear': True
    },
    'VPC-2-VPC_PEER_LINK_DOWN': {
        'facility': 'VPC',
        'mnemonic': 'VPC_PEER_LINK_DOWN',
        'cisco_severity': 2,
        'description': 'vPC peer link is down',
        'category': 'redundancy',
        'actionable': True
    },
    'VPC-5-ROLE_CHANGE': {
        'facility': 'VPC',
        'mnemonic': 'ROLE_CHANGE',
        'cisco_severity': 5,
        'description': 'vPC role changed',
        'category': 'redundancy',
        'actionable': True
    },
    'ISSU-3-ABORT': {
        'facility': 'ISSU',
        'mnemonic': 'ABORT',
        'cisco_severity': 3,
        'description': 'ISSU upgrade aborted',
        'category': 'redundancy',
        'actionable': True
    },

    # =========================================================================
    # CONFIGURATION
    # =========================================================================
    'SYS-5-CONFIG_I': {
        'facility': 'SYS',
        'mnemonic': 'CONFIG_I',
        'cisco_severity': 5,
        'description': 'Configuration change by user',
        'category': 'config',
        'actionable': False
    },
    'SYS-5-CONFIG': {
        'facility': 'SYS',
        'mnemonic': 'CONFIG',
        'cisco_severity': 5,
        'description': 'Configuration changed',
        'category': 'config',
        'actionable': False
    },
    'SYS-5-RELOAD': {
        'facility': 'SYS',
        'mnemonic': 'RELOAD',
        'cisco_severity': 5,
        'description': 'System reloading',
        'category': 'config',
        'actionable': True
    },
    'SYS-5-RESTART': {
        'facility': 'SYS',
        'mnemonic': 'RESTART',
        'cisco_severity': 5,
        'description': 'System restarted',
        'category': 'config',
        'actionable': True
    },
    'SYS-6-CLOCKUPDATE': {
        'facility': 'SYS',
        'mnemonic': 'CLOCKUPDATE',
        'cisco_severity': 6,
        'description': 'System clock updated',
        'category': 'config',
        'actionable': False
    },
    'SYS-3-CPUHOG': {
        'facility': 'SYS',
        'mnemonic': 'CPUHOG',
        'cisco_severity': 3,
        'description': 'CPU hog condition detected',
        'category': 'performance',
        'actionable': True
    },
    'SYS-2-MALLOCFAIL': {
        'facility': 'SYS',
        'mnemonic': 'MALLOCFAIL',
        'cisco_severity': 2,
        'description': 'Memory allocation failure',
        'category': 'performance',
        'actionable': True
    },
    'SYS-3-LOGGER_FLUSHED': {
        'facility': 'SYS',
        'mnemonic': 'LOGGER_FLUSHED',
        'cisco_severity': 3,
        'description': 'System logger flushed - messages lost',
        'category': 'system',
        'actionable': True
    },
    'CONFIG-5-STARTUP_CONFIG': {
        'facility': 'CONFIG',
        'mnemonic': 'STARTUP_CONFIG',
        'cisco_severity': 5,
        'description': 'Startup config operation',
        'category': 'config',
        'actionable': False
    },
    'PARSER-5-CFGLOG_LOGGEDCMD': {
        'facility': 'PARSER',
        'mnemonic': 'CFGLOG_LOGGEDCMD',
        'cisco_severity': 5,
        'description': 'Configuration command logged',
        'category': 'config',
        'actionable': False
    },
    'PARSER-4-BADCFG': {
        'facility': 'PARSER',
        'mnemonic': 'BADCFG',
        'cisco_severity': 4,
        'description': 'Bad configuration syntax',
        'category': 'config',
        'actionable': True
    },
    'ARCHIVE-5-SNMP_COPY': {
        'facility': 'ARCHIVE',
        'mnemonic': 'SNMP_COPY',
        'cisco_severity': 5,
        'description': 'Archive SNMP copy operation',
        'category': 'config',
        'actionable': False
    },
    'ARCHIVE-3-UNABLE_ARCHIVE': {
        'facility': 'ARCHIVE',
        'mnemonic': 'UNABLE_ARCHIVE',
        'cisco_severity': 3,
        'description': 'Unable to archive configuration',
        'category': 'config',
        'actionable': True
    },

    # =========================================================================
    # AAA - Authentication, Authorization, Accounting
    # =========================================================================
    'TACACS-3-SERVER_UNREACHABLE': {
        'facility': 'TACACS',
        'mnemonic': 'SERVER_UNREACHABLE',
        'cisco_severity': 3,
        'description': 'TACACS+ server unreachable',
        'category': 'aaa',
        'actionable': True
    },
    'TACACS-5-SERVER_REACHABLE': {
        'facility': 'TACACS',
        'mnemonic': 'SERVER_REACHABLE',
        'cisco_severity': 5,
        'description': 'TACACS+ server reachable',
        'category': 'aaa',
        'actionable': True,
        'is_clear': True
    },
    'TACACS-4-AUTHEN_FAIL': {
        'facility': 'TACACS',
        'mnemonic': 'AUTHEN_FAIL',
        'cisco_severity': 4,
        'description': 'TACACS+ authentication failed',
        'category': 'aaa',
        'actionable': True
    },
    'RADIUS-3-NOSERVERS': {
        'facility': 'RADIUS',
        'mnemonic': 'NOSERVERS',
        'cisco_severity': 3,
        'description': 'No RADIUS servers available',
        'category': 'aaa',
        'actionable': True
    },
    'RADIUS-4-RADIUS_DEAD': {
        'facility': 'RADIUS',
        'mnemonic': 'RADIUS_DEAD',
        'cisco_severity': 4,
        'description': 'RADIUS server dead',
        'category': 'aaa',
        'actionable': True
    },
    'RADIUS-5-RADIUS_ALIVE': {
        'facility': 'RADIUS',
        'mnemonic': 'RADIUS_ALIVE',
        'cisco_severity': 5,
        'description': 'RADIUS server alive',
        'category': 'aaa',
        'actionable': True,
        'is_clear': True
    },
    'AAA-3-REJECT': {
        'facility': 'AAA',
        'mnemonic': 'REJECT',
        'cisco_severity': 3,
        'description': 'AAA authentication rejected',
        'category': 'aaa',
        'actionable': True
    },
    'AAA-4-ACCFAIL': {
        'facility': 'AAA',
        'mnemonic': 'ACCFAIL',
        'cisco_severity': 4,
        'description': 'AAA accounting failure',
        'category': 'aaa',
        'actionable': True
    },

    # =========================================================================
    # SYSTEM - General system messages
    # =========================================================================
    'SNMP-3-AUTHFAIL': {
        'facility': 'SNMP',
        'mnemonic': 'AUTHFAIL',
        'cisco_severity': 3,
        'description': 'SNMP authentication failure',
        'category': 'system',
        'actionable': True
    },
    'SNMP-5-COLDSTART': {
        'facility': 'SNMP',
        'mnemonic': 'COLDSTART',
        'cisco_severity': 5,
        'description': 'SNMP cold start',
        'category': 'system',
        'actionable': True
    },
    'SNMP-5-WARMSTART': {
        'facility': 'SNMP',
        'mnemonic': 'WARMSTART',
        'cisco_severity': 5,
        'description': 'SNMP warm start',
        'category': 'system',
        'actionable': False
    },
    'SNMP-4-NOTRAPIP': {
        'facility': 'SNMP',
        'mnemonic': 'NOTRAPIP',
        'cisco_severity': 4,
        'description': 'SNMP trap host unreachable',
        'category': 'system',
        'actionable': True
    },
    'NTP-4-SYNC_FAIL': {
        'facility': 'NTP',
        'mnemonic': 'SYNC_FAIL',
        'cisco_severity': 4,
        'description': 'NTP synchronization failed',
        'category': 'system',
        'actionable': True
    },
    'NTP-5-SYNC_OK': {
        'facility': 'NTP',
        'mnemonic': 'SYNC_OK',
        'cisco_severity': 5,
        'description': 'NTP synchronized',
        'category': 'system',
        'actionable': True,
        'is_clear': True
    },
    'NTP-4-PEER_DIST': {
        'facility': 'NTP',
        'mnemonic': 'PEER_DIST',
        'cisco_severity': 4,
        'description': 'NTP peer distance threshold exceeded',
        'category': 'system',
        'actionable': True
    },
    'NTP-5-PEERSYNC': {
        'facility': 'NTP',
        'mnemonic': 'PEERSYNC',
        'cisco_severity': 5,
        'description': 'NTP synchronized to peer',
        'category': 'system',
        'actionable': False
    },
    'MEMORY-3-MEMFRAGMENT': {
        'facility': 'MEMORY',
        'mnemonic': 'MEMFRAGMENT',
        'cisco_severity': 3,
        'description': 'Memory fragmentation detected',
        'category': 'performance',
        'actionable': True
    },
    'MEMORY-4-LOW': {
        'facility': 'MEMORY',
        'mnemonic': 'LOW',
        'cisco_severity': 4,
        'description': 'Memory low condition',
        'category': 'performance',
        'actionable': True
    },
    'MEMORY-2-CRITICAL': {
        'facility': 'MEMORY',
        'mnemonic': 'CRITICAL',
        'cisco_severity': 2,
        'description': 'Memory critical condition',
        'category': 'performance',
        'actionable': True
    },
    'CPU-4-HIGH': {
        'facility': 'CPU',
        'mnemonic': 'HIGH',
        'cisco_severity': 4,
        'description': 'CPU utilization high',
        'category': 'performance',
        'actionable': True
    },
    'CPU-5-NORMAL': {
        'facility': 'CPU',
        'mnemonic': 'NORMAL',
        'cisco_severity': 5,
        'description': 'CPU utilization normal',
        'category': 'performance',
        'actionable': True,
        'is_clear': True
    },

    # =========================================================================
    # VPN/TUNNEL
    # =========================================================================
    'CRYPTO-5-TUNNEL_UP': {
        'facility': 'CRYPTO',
        'mnemonic': 'TUNNEL_UP',
        'cisco_severity': 5,
        'description': 'Crypto tunnel up',
        'category': 'vpn',
        'actionable': True,
        'is_clear': True
    },
    'CRYPTO-5-TUNNEL_DOWN': {
        'facility': 'CRYPTO',
        'mnemonic': 'TUNNEL_DOWN',
        'cisco_severity': 5,
        'description': 'Crypto tunnel down',
        'category': 'vpn',
        'actionable': True
    },
    'IPSEC-3-SA_FAILURE': {
        'facility': 'IPSEC',
        'mnemonic': 'SA_FAILURE',
        'cisco_severity': 3,
        'description': 'IPSec SA failure',
        'category': 'vpn',
        'actionable': True
    },
    'IPSEC-5-TRANS_UP': {
        'facility': 'IPSEC',
        'mnemonic': 'TRANS_UP',
        'cisco_severity': 5,
        'description': 'IPSec transform up',
        'category': 'vpn',
        'actionable': True,
        'is_clear': True
    },
    'IPSEC-5-TRANS_DOWN': {
        'facility': 'IPSEC',
        'mnemonic': 'TRANS_DOWN',
        'cisco_severity': 5,
        'description': 'IPSec transform down',
        'category': 'vpn',
        'actionable': True
    },
    'DMVPN-5-NHRP_NHEC_UP': {
        'facility': 'DMVPN',
        'mnemonic': 'NHRP_NHEC_UP',
        'cisco_severity': 5,
        'description': 'DMVPN NHRP tunnel up',
        'category': 'vpn',
        'actionable': True,
        'is_clear': True
    },
    'DMVPN-5-NHRP_NHEC_DOWN': {
        'facility': 'DMVPN',
        'mnemonic': 'NHRP_NHEC_DOWN',
        'cisco_severity': 5,
        'description': 'DMVPN NHRP tunnel down',
        'category': 'vpn',
        'actionable': True
    },
    'TUNNEL-5-UPDOWN': {
        'facility': 'TUNNEL',
        'mnemonic': 'UPDOWN',
        'cisco_severity': 5,
        'description': 'Tunnel state changed',
        'category': 'vpn',
        'actionable': True,
        'clear_keywords': ['up'],
        'fault_keywords': ['down']
    },

    # =========================================================================
    # WIRELESS - Access Points, Controllers
    # =========================================================================
    'DOT11-6-ASSOC': {
        'facility': 'DOT11',
        'mnemonic': 'ASSOC',
        'cisco_severity': 6,
        'description': 'Wireless client associated',
        'category': 'wireless',
        'actionable': False
    },
    'DOT11-6-DISASSOC': {
        'facility': 'DOT11',
        'mnemonic': 'DISASSOC',
        'cisco_severity': 6,
        'description': 'Wireless client disassociated',
        'category': 'wireless',
        'actionable': False
    },
    'DOT11-4-MAXRETRIES': {
        'facility': 'DOT11',
        'mnemonic': 'MAXRETRIES',
        'cisco_severity': 4,
        'description': 'Wireless max retries reached',
        'category': 'wireless',
        'actionable': True
    },
    'CAPWAP-3-ERRORLOG': {
        'facility': 'CAPWAP',
        'mnemonic': 'ERRORLOG',
        'cisco_severity': 3,
        'description': 'CAPWAP error',
        'category': 'wireless',
        'actionable': True
    },
    'CAPWAP-5-DTLSREQSEND': {
        'facility': 'CAPWAP',
        'mnemonic': 'DTLSREQSEND',
        'cisco_severity': 5,
        'description': 'CAPWAP DTLS request sent',
        'category': 'wireless',
        'actionable': False
    },
    'LWAPP-5-CHANGED': {
        'facility': 'LWAPP',
        'mnemonic': 'CHANGED',
        'cisco_severity': 5,
        'description': 'LWAPP state changed',
        'category': 'wireless',
        'actionable': True
    },
    'LWAPP-3-ERR': {
        'facility': 'LWAPP',
        'mnemonic': 'ERR',
        'cisco_severity': 3,
        'description': 'LWAPP error',
        'category': 'wireless',
        'actionable': True
    },
    'AP-6-JOINED': {
        'facility': 'AP',
        'mnemonic': 'JOINED',
        'cisco_severity': 6,
        'description': 'Access point joined controller',
        'category': 'wireless',
        'actionable': True,
        'is_clear': True
    },
    'AP-3-DISASSOCIATED': {
        'facility': 'AP',
        'mnemonic': 'DISASSOCIATED',
        'cisco_severity': 3,
        'description': 'Access point disassociated from controller',
        'category': 'wireless',
        'actionable': True
    },
    'AP-4-ROGUE_DETECTED': {
        'facility': 'AP',
        'mnemonic': 'ROGUE_DETECTED',
        'cisco_severity': 4,
        'description': 'Rogue access point detected',
        'category': 'wireless',
        'actionable': True
    },

    # =========================================================================
    # QOS - Quality of Service
    # =========================================================================
    'QOS-4-POLICER_DROPPED': {
        'facility': 'QOS',
        'mnemonic': 'POLICER_DROPPED',
        'cisco_severity': 4,
        'description': 'QoS policer dropped packets',
        'category': 'qos',
        'actionable': True
    },
    'QOS-3-ERROR': {
        'facility': 'QOS',
        'mnemonic': 'ERROR',
        'cisco_severity': 3,
        'description': 'QoS error',
        'category': 'qos',
        'actionable': True
    },
    'QUEUING-3-ERROR': {
        'facility': 'QUEUING',
        'mnemonic': 'ERROR',
        'cisco_severity': 3,
        'description': 'Queuing error',
        'category': 'qos',
        'actionable': True
    },
    'POLICING-4-EXCEED': {
        'facility': 'POLICING',
        'mnemonic': 'EXCEED',
        'cisco_severity': 4,
        'description': 'Traffic exceeded policy',
        'category': 'qos',
        'actionable': True
    },

    # =========================================================================
    # VLAN
    # =========================================================================
    'VLAN-5-CREATED': {
        'facility': 'VLAN',
        'mnemonic': 'CREATED',
        'cisco_severity': 5,
        'description': 'VLAN created',
        'category': 'vlan',
        'actionable': False
    },
    'VLAN-5-DELETED': {
        'facility': 'VLAN',
        'mnemonic': 'DELETED',
        'cisco_severity': 5,
        'description': 'VLAN deleted',
        'category': 'vlan',
        'actionable': False
    },
    'VLAN-3-VLANMGR_CRITICAL': {
        'facility': 'VLAN',
        'mnemonic': 'VLANMGR_CRITICAL',
        'cisco_severity': 3,
        'description': 'VLAN manager critical error',
        'category': 'vlan',
        'actionable': True
    },
    'VTP-5-BADPWD': {
        'facility': 'VTP',
        'mnemonic': 'BADPWD',
        'cisco_severity': 5,
        'description': 'VTP bad password received',
        'category': 'vlan',
        'actionable': True
    },
    'VTP-5-MODECHANGE': {
        'facility': 'VTP',
        'mnemonic': 'MODECHANGE',
        'cisco_severity': 5,
        'description': 'VTP mode changed',
        'category': 'vlan',
        'actionable': False
    },
    'VTP-4-REVISION_HIGHER': {
        'facility': 'VTP',
        'mnemonic': 'REVISION_HIGHER',
        'cisco_severity': 4,
        'description': 'VTP received higher revision number',
        'category': 'vlan',
        'actionable': True
    },

    # =========================================================================
    # FIREWALL/ACL
    # =========================================================================
    'FW-6-DROP_PKT': {
        'facility': 'FW',
        'mnemonic': 'DROP_PKT',
        'cisco_severity': 6,
        'description': 'Firewall dropped packet',
        'category': 'security',
        'actionable': False
    },
    'FW-3-RESPONDER_WND_SCALE_INI_NO_SCALE': {
        'facility': 'FW',
        'mnemonic': 'RESPONDER_WND_SCALE_INI_NO_SCALE',
        'cisco_severity': 3,
        'description': 'Firewall responder window scale issue',
        'category': 'security',
        'actionable': True
    },
    'ACL-6-ACCESSLOGP': {
        'facility': 'ACL',
        'mnemonic': 'ACCESSLOGP',
        'cisco_severity': 6,
        'description': 'ACL log entry with port',
        'category': 'security',
        'actionable': False
    },
    'ACL-6-ACCESSLOGNP': {
        'facility': 'ACL',
        'mnemonic': 'ACCESSLOGNP',
        'cisco_severity': 6,
        'description': 'ACL log entry without port',
        'category': 'security',
        'actionable': False
    },

    # =========================================================================
    # MPLS/LABEL
    # =========================================================================
    'MPLS-5-IFUP': {
        'facility': 'MPLS',
        'mnemonic': 'IFUP',
        'cisco_severity': 5,
        'description': 'MPLS interface up',
        'category': 'routing',
        'actionable': True,
        'is_clear': True
    },
    'MPLS-5-IFDOWN': {
        'facility': 'MPLS',
        'mnemonic': 'IFDOWN',
        'cisco_severity': 5,
        'description': 'MPLS interface down',
        'category': 'routing',
        'actionable': True
    },
    'LDP-5-NBRCHG': {
        'facility': 'LDP',
        'mnemonic': 'NBRCHG',
        'cisco_severity': 5,
        'description': 'LDP neighbor change',
        'category': 'routing',
        'actionable': True,
        'clear_keywords': ['up'],
        'fault_keywords': ['down']
    },
    'MPLS_VPN-5-PREFIX_LIMIT': {
        'facility': 'MPLS_VPN',
        'mnemonic': 'PREFIX_LIMIT',
        'cisco_severity': 5,
        'description': 'MPLS VPN prefix limit reached',
        'category': 'routing',
        'actionable': True
    },

    # =========================================================================
    # BFD - Bidirectional Forwarding Detection
    # =========================================================================
    'BFD-6-BFD_SESS_CREATED': {
        'facility': 'BFD',
        'mnemonic': 'BFD_SESS_CREATED',
        'cisco_severity': 6,
        'description': 'BFD session created',
        'category': 'routing',
        'actionable': False
    },
    'BFD-6-BFD_SESS_UP': {
        'facility': 'BFD',
        'mnemonic': 'BFD_SESS_UP',
        'cisco_severity': 6,
        'description': 'BFD session up',
        'category': 'routing',
        'actionable': True,
        'is_clear': True
    },
    'BFD-6-BFD_SESS_DOWN': {
        'facility': 'BFD',
        'mnemonic': 'BFD_SESS_DOWN',
        'cisco_severity': 6,
        'description': 'BFD session down',
        'category': 'routing',
        'actionable': True
    },
    'BFD-3-BFD_SESSION_FAIL': {
        'facility': 'BFD',
        'mnemonic': 'BFD_SESSION_FAIL',
        'cisco_severity': 3,
        'description': 'BFD session failed',
        'category': 'routing',
        'actionable': True
    },

    # =========================================================================
    # LLDP/LACP
    # =========================================================================
    'LLDP-5-NBRINFO': {
        'facility': 'LLDP',
        'mnemonic': 'NBRINFO',
        'cisco_severity': 5,
        'description': 'LLDP neighbor information',
        'category': 'link-state',
        'actionable': False
    },
    'LACP-5-ACTIVITYCHANGED': {
        'facility': 'LACP',
        'mnemonic': 'ACTIVITYCHANGED',
        'cisco_severity': 5,
        'description': 'LACP activity changed',
        'category': 'link-state',
        'actionable': True
    },
    'LACP-3-SYSPRI_MISMATCH': {
        'facility': 'LACP',
        'mnemonic': 'SYSPRI_MISMATCH',
        'cisco_severity': 3,
        'description': 'LACP system priority mismatch',
        'category': 'link-state',
        'actionable': True
    },

    # =========================================================================
    # DHCP
    # =========================================================================
    'DHCPD-4-PING_CONFLICT': {
        'facility': 'DHCPD',
        'mnemonic': 'PING_CONFLICT',
        'cisco_severity': 4,
        'description': 'DHCP ping conflict detected',
        'category': 'system',
        'actionable': True
    },
    'DHCPD-6-LEASE': {
        'facility': 'DHCPD',
        'mnemonic': 'LEASE',
        'cisco_severity': 6,
        'description': 'DHCP lease event',
        'category': 'system',
        'actionable': False
    },
    'DHCP-6-ADDRESS_ASSIGN': {
        'facility': 'DHCP',
        'mnemonic': 'ADDRESS_ASSIGN',
        'cisco_severity': 6,
        'description': 'DHCP address assigned',
        'category': 'system',
        'actionable': False
    },

    # =========================================================================
    # BOOT/SYSTEM STARTUP
    # =========================================================================
    'BOOT-5-BOOTTIME': {
        'facility': 'BOOT',
        'mnemonic': 'BOOTTIME',
        'cisco_severity': 5,
        'description': 'System boot time',
        'category': 'system',
        'actionable': False
    },
    'IOSXE-3-PLATFORM': {
        'facility': 'IOSXE',
        'mnemonic': 'PLATFORM',
        'cisco_severity': 3,
        'description': 'IOS-XE platform error',
        'category': 'system',
        'actionable': True
    },
    'IOSXE-5-PLATFORM': {
        'facility': 'IOSXE',
        'mnemonic': 'PLATFORM',
        'cisco_severity': 5,
        'description': 'IOS-XE platform notification',
        'category': 'system',
        'actionable': False
    },

    # =========================================================================
    # LICENSE
    # =========================================================================
    'LICENSE-5-EVALUATION': {
        'facility': 'LICENSE',
        'mnemonic': 'EVALUATION',
        'cisco_severity': 5,
        'description': 'License in evaluation mode',
        'category': 'system',
        'actionable': True
    },
    'LICENSE-4-EXPIRING': {
        'facility': 'LICENSE',
        'mnemonic': 'EXPIRING',
        'cisco_severity': 4,
        'description': 'License expiring soon',
        'category': 'system',
        'actionable': True
    },
    'LICENSE-3-EXPIRED': {
        'facility': 'LICENSE',
        'mnemonic': 'EXPIRED',
        'cisco_severity': 3,
        'description': 'License expired',
        'category': 'system',
        'actionable': True
    },
    'LICENSE-5-INSTALLED': {
        'facility': 'LICENSE',
        'mnemonic': 'INSTALLED',
        'cisco_severity': 5,
        'description': 'License installed',
        'category': 'system',
        'actionable': True,
        'is_clear': True
    },

    # =========================================================================
    # NX-OS SPECIFIC
    # =========================================================================
    'ETHPORT-5-IF_ADMIN_UP': {
        'facility': 'ETHPORT',
        'mnemonic': 'IF_ADMIN_UP',
        'cisco_severity': 5,
        'description': 'Interface administratively up',
        'category': 'link-state',
        'actionable': True,
        'is_clear': True
    },
    'ETHPORT-5-IF_ADMIN_DOWN': {
        'facility': 'ETHPORT',
        'mnemonic': 'IF_ADMIN_DOWN',
        'cisco_severity': 5,
        'description': 'Interface administratively down',
        'category': 'link-state',
        'actionable': False
    },
    'VSHD-5-VSHD_SYSLOG_CONFIG_I': {
        'facility': 'VSHD',
        'mnemonic': 'VSHD_SYSLOG_CONFIG_I',
        'cisco_severity': 5,
        'description': 'VSH configuration change',
        'category': 'config',
        'actionable': False
    },
    'ACLMGR-5-ACLLOG': {
        'facility': 'ACLMGR',
        'mnemonic': 'ACLLOG',
        'cisco_severity': 5,
        'description': 'ACL manager log entry',
        'category': 'security',
        'actionable': False
    },

    # =========================================================================
    # IOS-XR SPECIFIC
    # =========================================================================
    'PKT_INFRA-LINK-3-UPDOWN': {
        'facility': 'PKT_INFRA-LINK',
        'mnemonic': 'UPDOWN',
        'cisco_severity': 3,
        'description': 'Interface link state changed (IOS-XR)',
        'category': 'link-state',
        'actionable': True,
        'clear_keywords': ['up'],
        'fault_keywords': ['down']
    },
    'IM-6-LINK_UP': {
        'facility': 'IM',
        'mnemonic': 'LINK_UP',
        'cisco_severity': 6,
        'description': 'Interface link up (IOS-XR)',
        'category': 'link-state',
        'actionable': True,
        'is_clear': True
    },
    'IM-6-LINK_DOWN': {
        'facility': 'IM',
        'mnemonic': 'LINK_DOWN',
        'cisco_severity': 6,
        'description': 'Interface link down (IOS-XR)',
        'category': 'link-state',
        'actionable': True
    },
    'ROUTING-BGP-5-ADJCHANGE': {
        'facility': 'ROUTING-BGP',
        'mnemonic': 'ADJCHANGE',
        'cisco_severity': 5,
        'description': 'BGP adjacency change (IOS-XR)',
        'category': 'routing',
        'actionable': True,
        'clear_keywords': ['up', 'established'],
        'fault_keywords': ['down']
    },
    'ROUTING-OSPF-5-ADJCHG': {
        'facility': 'ROUTING-OSPF',
        'mnemonic': 'ADJCHG',
        'cisco_severity': 5,
        'description': 'OSPF adjacency change (IOS-XR)',
        'category': 'routing',
        'actionable': True,
        'clear_keywords': ['full'],
        'fault_keywords': ['down', 'exstart']
    },

    # =========================================================================
    # MERAKI SPECIFIC (logged as standard syslog)
    # =========================================================================
    'MERAKI-5-AP_CONNECT': {
        'facility': 'MERAKI',
        'mnemonic': 'AP_CONNECT',
        'cisco_severity': 5,
        'description': 'Meraki AP connected to cloud',
        'category': 'wireless',
        'actionable': True,
        'is_clear': True
    },
    'MERAKI-3-AP_DISCONNECT': {
        'facility': 'MERAKI',
        'mnemonic': 'AP_DISCONNECT',
        'cisco_severity': 3,
        'description': 'Meraki AP disconnected from cloud',
        'category': 'wireless',
        'actionable': True
    },
    'MERAKI-4-CONFIG_CHANGE': {
        'facility': 'MERAKI',
        'mnemonic': 'CONFIG_CHANGE',
        'cisco_severity': 4,
        'description': 'Meraki configuration changed',
        'category': 'config',
        'actionable': False
    },
}

# Build a lookup dict by facility-mnemonic for faster matching
SYSLOG_LOOKUP = {}
for key, definition in SYSLOG_DEFINITIONS.items():
    # Key is already in format FACILITY-SEVERITY-MNEMONIC
    SYSLOG_LOOKUP[key] = definition
    # Also create lookup without severity for partial matching
    facility = definition['facility']
    mnemonic = definition['mnemonic']
    partial_key = f"{facility}-{mnemonic}"
    if partial_key not in SYSLOG_LOOKUP:
        SYSLOG_LOOKUP[partial_key] = definition


# =============================================================================
# SYSLOG FORMAT PATTERNS
# =============================================================================
# Multi-platform syslog format detection
# The key is finding %FACILITY-SEVERITY-MNEMONIC and parsing context around it

# Pattern to find the Cisco syslog message identifier
# Format: %FACILITY-SEVERITY-MNEMONIC
CISCO_MSG_PATTERN = re.compile(
    r'%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+)'
)

# Patterns for different platform formats (used to extract hostname/IP before the message)

# rsyslog format: "Feb  2 10:30:00 hostname %MSG" or "Feb  2 10:30:00 10.1.1.5 %MSG"
RSYSLOG_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>[\d:]+)\s+'
    r'(?P<host>[^\s:]+)\s+'
    r'(?P<rest>.*)'
)

# IOS format: "*Mar  1 00:00:00.000: %MSG" or "000001: *Mar  1 00:00:00.000: %MSG"
IOS_TIMESTAMP_PATTERN = re.compile(
    r'(?:\d+:\s*)?'  # Optional sequence number
    r'\*?(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+'
    r'(?P<time>[\d:\.]+)(?:\s+\w+)?:\s*'  # Timestamp with optional timezone
    r'(?P<rest>.*)'
)

# NX-OS format: "2026 Feb  2 10:30:00 hostname %MSG"
NXOS_TIMESTAMP_PATTERN = re.compile(
    r'^(?P<year>\d{4})\s+(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+'
    r'(?P<time>[\d:]+)\s+(?P<host>[^\s:]+)\s+'
    r'(?P<rest>.*)'
)

# IOS-XR format: "RP/0/RSP0/CPU0:Feb  2 10:30:00.000 : process[pid]: %MSG"
IOSXR_TIMESTAMP_PATTERN = re.compile(
    r'^(?P<location>[A-Z0-9/]+):(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+'
    r'(?P<time>[\d:\.]+)\s*:\s*(?P<process>\S+)\s*:\s*'
    r'(?P<rest>.*)'
)

# Interface extraction patterns for different message types
INTERFACE_PATTERNS = [
    re.compile(r'Interface\s+([A-Za-z0-9/\-\.]+)'),
    re.compile(r'interface\s+([A-Za-z0-9/\-\.]+)'),
    re.compile(r'Ethernet(\d+/\d+(?:/\d+)?)'),
    re.compile(r'(Gi(?:gabitEthernet)?[0-9/]+)'),
    re.compile(r'(Te(?:nGigabitEthernet)?[0-9/]+)'),
    re.compile(r'(Fa(?:stEthernet)?[0-9/]+)'),
    re.compile(r'(Po(?:rt-channel)?[0-9]+)'),
    re.compile(r'(Vlan[0-9]+)'),
    re.compile(r'(Loopback[0-9]+)'),
    re.compile(r'(Tunnel[0-9]+)'),
    re.compile(r'port\s+([A-Za-z0-9/\-\.]+)'),
]

# IP address extraction pattern
IP_PATTERN = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')


class CiscoSyslogProcessor:
    """Main processor class for Cisco syslog processing."""

    def __init__(self, args):
        """Initialize the processor."""
        self.config = rapax.load_config()
        self.logger = rapax.setup_logging()
        self._setup_file_logging()

        self.syslog_file = args.syslog_file
        self.component_id = args.component_id

        self.running = True
        self.metrics = {
            'messages_processed': 0,
            'alerts_generated': 0,
            'logs_generated': 0,
            'errors': 0,
            'unknown_messages': 0,
            'lines_skipped': 0
        }

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        self.logger.info(f"[{SOURCE}] Initializing Cisco Syslog Processor v{VERSION}")
        self.logger.info(f"[{SOURCE}] Monitoring syslog file: {self.syslog_file}")
        self.logger.info(f"[{SOURCE}] Component ID: {self.component_id}")
        self.logger.info(f"[{SOURCE}] Loaded {len(SYSLOG_DEFINITIONS)} syslog definitions")

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

    def _map_cisco_severity_to_rapax(self, cisco_severity, is_clear=False):
        """Map Cisco severity (0-7) to Rapax severity.

        Args:
            cisco_severity: Cisco severity level (0-7)
            is_clear: If True, this is a recovery/clear message

        Returns:
            Rapax severity string
        """
        if is_clear:
            return 'CLEAR'

        severity_map = {
            0: 'CRITICAL',  # Emergency
            1: 'CRITICAL',  # Alert
            2: 'CRITICAL',  # Critical
            3: 'MAJOR',     # Error
            4: 'MINOR',     # Warning
            5: 'WARNING',   # Notice
            6: 'INFO',      # Informational
            7: 'DEBUG'      # Debug
        }
        return severity_map.get(cisco_severity, 'WARNING')

    def _map_severity_to_status(self, severity):
        """Map Rapax severity to alert status string."""
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

    def _is_clear_message(self, definition, message_text):
        """Determine if this is a clear/recovery message.

        Args:
            definition: Syslog definition dict
            message_text: The actual syslog message text

        Returns:
            True if this is a clear/recovery message
        """
        # Check if definition explicitly marks this as clear
        if definition.get('is_clear', False):
            return True

        # Check for clear keywords in message
        clear_keywords = definition.get('clear_keywords', [])
        fault_keywords = definition.get('fault_keywords', [])

        message_lower = message_text.lower()

        # Check for explicit clear keywords
        for keyword in clear_keywords:
            if keyword.lower() in message_lower:
                # Make sure it's not also a fault (e.g., "went down" vs "down")
                is_fault = False
                for fault_kw in fault_keywords:
                    if fault_kw.lower() in message_lower:
                        is_fault = True
                        break
                if not is_fault:
                    return True

        return False

    def _extract_hostname_and_message(self, line):
        """Extract hostname/IP and message from syslog line.

        Supports multiple formats by detecting where %FACILITY-SEV-MNEM is located.

        Args:
            line: Raw syslog line

        Returns:
            dict with 'hostname', 'message', 'timestamp', 'platform' or None
        """
        # First, find the Cisco message pattern
        msg_match = CISCO_MSG_PATTERN.search(line)
        if not msg_match:
            return None

        msg_start = msg_match.start()
        prefix = line[:msg_start].strip()
        message = line[msg_match.start():].strip()

        result = {
            'hostname': 'unknown',
            'message': message,
            'timestamp': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            'platform': 'unknown',
            'facility': msg_match.group('facility'),
            'severity': int(msg_match.group('severity')),
            'mnemonic': msg_match.group('mnemonic')
        }

        # Try different format patterns on the prefix

        # Try rsyslog format first (most common when receiving from remote devices)
        rsyslog_match = RSYSLOG_PATTERN.match(line)
        if rsyslog_match:
            result['hostname'] = rsyslog_match.group('host')
            result['platform'] = 'rsyslog'
            return result

        # Try NX-OS format (has year at start)
        nxos_match = NXOS_TIMESTAMP_PATTERN.match(line)
        if nxos_match:
            result['hostname'] = nxos_match.group('host')
            result['platform'] = 'nxos'
            return result

        # Try IOS-XR format (has location prefix like RP/0/RSP0/CPU0:)
        iosxr_match = IOSXR_TIMESTAMP_PATTERN.match(line)
        if iosxr_match:
            result['hostname'] = iosxr_match.group('location').split('/')[0]
            result['platform'] = 'iosxr'
            return result

        # Try IOS format (has asterisk and/or sequence number)
        ios_match = IOS_TIMESTAMP_PATTERN.match(prefix)
        if ios_match:
            # IOS format doesn't include hostname in syslog line
            # It's typically added by rsyslog when received
            result['platform'] = 'ios'
            return result

        # Fallback: try to extract hostname from any position before the message
        # Look for word that could be a hostname or IP
        words = prefix.split()
        for word in reversed(words):
            # Skip common timestamp parts
            if re.match(r'^\d{1,2}:\d{2}:\d{2}', word):
                continue
            if word in ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                       'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']:
                continue
            if re.match(r'^\d{1,2}$', word):  # Day number
                continue
            if re.match(r'^\*?\w{3}$', word):  # Month abbreviation with optional *
                continue
            if re.match(r'^\d+:$', word):  # Sequence number
                continue
            # This could be hostname or IP
            result['hostname'] = word.rstrip(':')
            break

        return result

    def _extract_interface(self, message):
        """Extract interface name from syslog message.

        Args:
            message: Syslog message text

        Returns:
            Interface name or 'N/A'
        """
        for pattern in INTERFACE_PATTERNS:
            match = pattern.search(message)
            if match:
                return match.group(1)
        return 'N/A'

    def _extract_ip_from_message(self, message):
        """Extract IP address from syslog message if present.

        Args:
            message: Syslog message text

        Returns:
            IP address or None
        """
        match = IP_PATTERN.search(message)
        if match:
            return match.group(1)
        return None

    def _parse_syslog_line(self, line):
        """Parse a syslog line for Cisco messages.

        Args:
            line: Raw syslog line

        Returns:
            Parsed data dict or None
        """
        # Skip non-Cisco syslog lines
        if '%' not in line:
            return None

        parsed = self._extract_hostname_and_message(line)
        if not parsed:
            return None

        # Build lookup key
        facility = parsed['facility']
        severity = parsed['severity']
        mnemonic = parsed['mnemonic']

        # Try exact match first
        lookup_key = f"{facility}-{severity}-{mnemonic}"
        definition = SYSLOG_LOOKUP.get(lookup_key)

        # Try partial match (without severity)
        if not definition:
            partial_key = f"{facility}-{mnemonic}"
            definition = SYSLOG_LOOKUP.get(partial_key)

        parsed['definition'] = definition
        parsed['lookup_key'] = lookup_key
        parsed['raw_line'] = line

        return parsed

    def _process_message(self, parsed_data):
        """Process a parsed syslog message and generate alert or log.

        Args:
            parsed_data: Parsed syslog data dict
        """
        hostname = parsed_data.get('hostname', 'unknown')
        message = parsed_data.get('message', '')
        facility = parsed_data.get('facility', '')
        cisco_severity = parsed_data.get('severity', 5)
        mnemonic = parsed_data.get('mnemonic', '')
        definition = parsed_data.get('definition')
        lookup_key = parsed_data.get('lookup_key', '')

        timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        # Extract interface from message
        interface = self._extract_interface(message)

        # Try to get IP from hostname if it looks like an IP
        ip_address = hostname if IP_PATTERN.match(hostname) else ''
        if not ip_address:
            ip_address = self._extract_ip_from_message(message) or ''

        if definition:
            # Known message type
            category = definition.get('category', 'system')
            description = definition.get('description', message)
            actionable = definition.get('actionable', False)

            # Determine if this is a clear message
            is_clear = self._is_clear_message(definition, message)

            # Map severity
            rapax_severity = self._map_cisco_severity_to_rapax(cisco_severity, is_clear)

            if actionable:
                # Generate alert
                state = "Up" if is_clear else "Down"

                alert_data = {
                    'UUID': str(uuid.uuid4()),
                    'Device': hostname,
                    'Interface': interface,
                    'IP': ip_address,
                    'Status': self._map_severity_to_status(rapax_severity),
                    'State': state,
                    'Category': category,
                    'Location': '',
                    'Description': f"{description} - {facility}-{mnemonic}",
                    'FirstOccurred': timestamp,
                    'LastOccurred': timestamp,
                    'Number': 1,
                    'DeviceType': 'Network',
                    'Parent': '',
                    'Notes': [],
                    'Tags': [
                        {'Source': SOURCE},
                        {'Facility': facility},
                        {'Mnemonic': mnemonic},
                        {'ComponentID': self.component_id}
                    ],
                    'SyslogData': {
                        'facility': facility,
                        'cisco_severity': cisco_severity,
                        'mnemonic': mnemonic,
                        'message': message,
                        'category': category,
                        'platform': parsed_data.get('platform', 'unknown'),
                        'raw_line': parsed_data.get('raw_line', '')[:500]  # Truncate raw line
                    }
                }

                try:
                    rapax.insert_alert(self.logger, alert_data)
                    self.metrics['alerts_generated'] += 1
                    self.logger.info(
                        f"[{SOURCE}] Alert: {facility}-{mnemonic} from {hostname} "
                        f"({rapax_severity}, state={state})"
                    )
                except Exception as e:
                    self.logger.error(f"[{SOURCE}] Error inserting alert: {e}")
                    self.metrics['errors'] += 1
            else:
                # Generate log entry
                log_data = {
                    '@timestamp': timestamp,
                    'level': rapax_severity,
                    'message': f"{description} - {message}",
                    'source': SOURCE,
                    'device': hostname,
                    'facility': facility,
                    'mnemonic': mnemonic,
                    'cisco_severity': cisco_severity,
                    'category': category,
                    'interface': interface,
                    'component_id': self.component_id,
                    'platform': parsed_data.get('platform', 'unknown'),
                    'tags': ['cisco-syslog', category, facility]
                }

                try:
                    rapax.send_message(self.logger, 'logs', log_data)
                    self.metrics['logs_generated'] += 1
                    self.logger.debug(
                        f"[{SOURCE}] Log: {facility}-{mnemonic} from {hostname} ({rapax_severity})"
                    )
                except Exception as e:
                    self.logger.error(f"[{SOURCE}] Error sending log: {e}")
                    self.metrics['errors'] += 1
        else:
            # Unknown message type - log it for analysis
            self.metrics['unknown_messages'] += 1

            # Still determine basic severity from Cisco severity level
            rapax_severity = self._map_cisco_severity_to_rapax(cisco_severity)

            log_data = {
                '@timestamp': timestamp,
                'level': 'DEBUG',
                'message': f"Unknown Cisco syslog: {message}",
                'source': SOURCE,
                'device': hostname,
                'facility': facility,
                'mnemonic': mnemonic,
                'cisco_severity': cisco_severity,
                'lookup_key': lookup_key,
                'component_id': self.component_id,
                'platform': parsed_data.get('platform', 'unknown'),
                'tags': ['cisco-syslog', 'unknown']
            }

            try:
                rapax.send_message(self.logger, 'logs', log_data)
                self.logger.debug(
                    f"[{SOURCE}] Unknown: {facility}-{cisco_severity}-{mnemonic} from {hostname}"
                )
            except Exception as e:
                self.logger.error(f"[{SOURCE}] Error logging unknown message: {e}")
                self.metrics['errors'] += 1

        self.metrics['messages_processed'] += 1

    def _log_metrics(self):
        """Log current processing metrics."""
        self.logger.info(
            f"[{SOURCE}] Metrics - Processed: {self.metrics['messages_processed']}, "
            f"Alerts: {self.metrics['alerts_generated']}, "
            f"Logs: {self.metrics['logs_generated']}, "
            f"Unknown: {self.metrics['unknown_messages']}, "
            f"Errors: {self.metrics['errors']}"
        )

    def run(self):
        """Main execution loop - tail the syslog file and process messages."""
        self.logger.info(f"[{SOURCE}] Starting syslog processor daemon")

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
                        line = line.strip()
                        # Check if this could be a Cisco syslog line
                        if '%' in line and '-' in line:
                            parsed = self._parse_syslog_line(line)
                            if parsed:
                                self._process_message(parsed)
                            else:
                                self.metrics['lines_skipped'] += 1
                        else:
                            self.metrics['lines_skipped'] += 1
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
        self.logger.info(f"[{SOURCE}] Syslog processor stopped")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Cisco Syslog Processor Daemon')
    parser.add_argument('--syslog-file', type=str, default='/var/log/messages',
                        help='Path to syslog file (default: /var/log/messages)')
    parser.add_argument('--component-id', type=str, default='cisco-syslog-1',
                        help='Component ID for metrics/tracking (default: cisco-syslog-1)')

    args = parser.parse_args()

    try:
        processor = CiscoSyslogProcessor(args)
        processor.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
