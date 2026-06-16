#!/usr/bin/env python3
"""
Cisco Syslog Test Sender
========================

Generates test Cisco syslog messages for validation and load testing.
Sends UDP syslog messages to a target host in various Cisco platform formats.

Supports:
- All syslog message types defined in cisco-syslog-processord.py
- Multiple platform formats (IOS, NX-OS, IOS-XR, rsyslog)
- Continuous sending mode with configurable interval
- Burst mode for load testing
- Category filtering
- Dynamic value generation for realistic testing

Usage:
    # Send all message types once
    python cisco-syslog-sender.py --target 192.168.1.1:514 --all

    # Send specific category
    python cisco-syslog-sender.py --target 192.168.1.1:514 --category link-state

    # Continuous mode
    python cisco-syslog-sender.py --target 192.168.1.1:514 --continuous --interval 5

    # Burst mode for load testing
    python cisco-syslog-sender.py --target 192.168.1.1:514 --burst 100 --count 1000

Author: Rapax Integration
"""

import socket
import argparse
import time
import random
import sys
from datetime import datetime

VERSION = '1.0.0'

# =============================================================================
# TEST SYSLOG MESSAGE DEFINITIONS
# =============================================================================
# Matches all definitions in cisco-syslog-processord.py
# Each entry includes sample message text for testing

SYSLOG_MESSAGES = [
    # =========================================================================
    # LINK STATE
    # =========================================================================
    {
        'key': 'LINK-3-UPDOWN',
        'category': 'link-state',
        'messages': [
            'Interface {interface}, changed state to down',
            'Interface {interface}, changed state to up'
        ],
        'interfaces': True
    },
    {
        'key': 'LINK-5-CHANGED',
        'category': 'link-state',
        'messages': [
            'Interface {interface}, changed state to down',
            'Interface {interface}, changed state to up'
        ],
        'interfaces': True
    },
    {
        'key': 'LINEPROTO-5-UPDOWN',
        'category': 'link-state',
        'messages': [
            'Line protocol on Interface {interface}, changed state to down',
            'Line protocol on Interface {interface}, changed state to up'
        ],
        'interfaces': True
    },
    {
        'key': 'PORT-5-IF_UP',
        'category': 'link-state',
        'messages': ['Interface {interface} is up'],
        'interfaces': True
    },
    {
        'key': 'PORT-5-IF_DOWN_LINK_FAILURE',
        'category': 'link-state',
        'messages': ['Interface {interface} is down (Link failure)'],
        'interfaces': True
    },
    {
        'key': 'PORT-5-IF_DOWN_ADMIN_DOWN',
        'category': 'link-state',
        'messages': ['Interface {interface} is down (Administratively down)'],
        'interfaces': True
    },
    {
        'key': 'IF-3-UPDOWN',
        'category': 'link-state',
        'messages': [
            'Interface {interface} is down',
            'Interface {interface} is up'
        ],
        'interfaces': True
    },
    {
        'key': 'ETHPORT-5-IF_UP',
        'category': 'link-state',
        'messages': ['Interface {interface} is up'],
        'interfaces': True
    },
    {
        'key': 'ETHPORT-5-IF_DOWN',
        'category': 'link-state',
        'messages': ['Interface {interface} is down'],
        'interfaces': True
    },
    {
        'key': 'ETHPORT-5-IF_DOWN_LINK_FAILURE',
        'category': 'link-state',
        'messages': ['Interface {interface} is down (Link failure)'],
        'interfaces': True
    },
    {
        'key': 'ETHPORT-5-IF_SFP_WARNING',
        'category': 'link-state',
        'messages': ['Interface {interface}: SFP validation warning'],
        'interfaces': True
    },
    {
        'key': 'TRANSCEIVER-3-NOT_COMPATIBLE',
        'category': 'link-state',
        'messages': ['Transceiver on {interface} is not compatible'],
        'interfaces': True
    },
    {
        'key': 'TRANSCEIVER-3-NOT_SUPPORTED',
        'category': 'link-state',
        'messages': ['Transceiver on {interface} is not supported'],
        'interfaces': True
    },
    {
        'key': 'TRANSCEIVER-5-INSERTED',
        'category': 'link-state',
        'messages': ['Transceiver module inserted in {interface}'],
        'interfaces': True
    },
    {
        'key': 'TRANSCEIVER-5-REMOVED',
        'category': 'link-state',
        'messages': ['Transceiver module removed from {interface}'],
        'interfaces': True
    },
    {
        'key': 'ILPOWER-3-CONTROLLER_PORT_ERR',
        'category': 'link-state',
        'messages': ['Controller port error on {interface}'],
        'interfaces': True
    },
    {
        'key': 'ILPOWER-5-POWER_GRANTED',
        'category': 'link-state',
        'messages': ['Interface {interface}: Power granted'],
        'interfaces': True
    },
    {
        'key': 'ILPOWER-5-POWER_DENIED',
        'category': 'link-state',
        'messages': ['Interface {interface}: Power denied - over budget'],
        'interfaces': True
    },
    {
        'key': 'ILPOWER-5-IEEE_DISCONNECT',
        'category': 'link-state',
        'messages': ['Interface {interface}: Device disconnected'],
        'interfaces': True
    },
    {
        'key': 'CDP-4-NATIVE_VLAN_MISMATCH',
        'category': 'link-state',
        'messages': ['Native VLAN mismatch on {interface} (our vlan 1, their vlan 10)'],
        'interfaces': True
    },
    {
        'key': 'CDP-4-DUPLEX_MISMATCH',
        'category': 'link-state',
        'messages': ['Duplex mismatch on {interface} (our half, their full)'],
        'interfaces': True
    },

    # =========================================================================
    # BGP
    # =========================================================================
    {
        'key': 'BGP-5-ADJCHANGE',
        'category': 'routing',
        'messages': [
            'neighbor {peer_ip} Down BGP Notification sent',
            'neighbor {peer_ip} Up',
            'neighbor {peer_ip} Down Hold time expired',
            'neighbor {peer_ip} Down Interface flap'
        ],
        'peer_ip': True
    },
    {
        'key': 'BGP-3-NOTIFICATION',
        'category': 'routing',
        'messages': [
            'received from neighbor {peer_ip} 6/4 (Administrative Reset)',
            'sent to neighbor {peer_ip} 6/2 (Peer De-configured)'
        ],
        'peer_ip': True
    },
    {
        'key': 'BGP-4-MAXPFX',
        'category': 'routing',
        'messages': ['neighbor {peer_ip} maximum prefix limit (1000) reached'],
        'peer_ip': True
    },
    {
        'key': 'BGP-5-NBR_RESET',
        'category': 'routing',
        'messages': ['neighbor {peer_ip} reset (Admin. shutdown)'],
        'peer_ip': True
    },
    {
        'key': 'BGP_SESSION-5-ADJCHANGE',
        'category': 'routing',
        'messages': [
            'neighbor {peer_ip} IPv4 Unicast topology base removed from session',
            'neighbor {peer_ip} Up'
        ],
        'peer_ip': True
    },

    # =========================================================================
    # OSPF
    # =========================================================================
    {
        'key': 'OSPF-5-ADJCHG',
        'category': 'routing',
        'messages': [
            'Process 1, Nbr {peer_ip} on {interface} from FULL to DOWN, Neighbor Down',
            'Process 1, Nbr {peer_ip} on {interface} from LOADING to FULL, Loading Done'
        ],
        'peer_ip': True,
        'interfaces': True
    },
    {
        'key': 'OSPF-4-ERRRCV',
        'category': 'routing',
        'messages': ['Received invalid packet: mismatch area ID from backbone area'],
        'peer_ip': True
    },
    {
        'key': 'OSPF-4-NOVALIDKEY',
        'category': 'routing',
        'messages': ['No valid authentication key on {interface}'],
        'interfaces': True
    },
    {
        'key': 'OSPF-4-DUPRID',
        'category': 'routing',
        'messages': ['Duplicate router id {peer_ip} detected'],
        'peer_ip': True
    },
    {
        'key': 'OSPF-5-NBRSTATE',
        'category': 'routing',
        'messages': [
            'Neighbor {peer_ip}, interface {interface} state changed to FULL',
            'Neighbor {peer_ip}, interface {interface} state changed to DOWN'
        ],
        'peer_ip': True,
        'interfaces': True
    },

    # =========================================================================
    # EIGRP
    # =========================================================================
    {
        'key': 'EIGRP-5-NBRCHANGE',
        'category': 'routing',
        'messages': [
            'EIGRP-IPv4 1: Neighbor {peer_ip} ({interface}) is down: holding time expired',
            'EIGRP-IPv4 1: Neighbor {peer_ip} ({interface}) is up: new adjacency'
        ],
        'peer_ip': True,
        'interfaces': True
    },
    {
        'key': 'DUAL-5-NBRCHANGE',
        'category': 'routing',
        'messages': [
            'EIGRP-IPv4 1: Neighbor {peer_ip} ({interface}) is down: peer restarted',
            'EIGRP-IPv4 1: Neighbor {peer_ip} ({interface}) is up: new adjacency'
        ],
        'peer_ip': True,
        'interfaces': True
    },
    {
        'key': 'EIGRP-4-AUTHFAIL',
        'category': 'routing',
        'messages': ['EIGRP authentication failed from {peer_ip}'],
        'peer_ip': True
    },
    {
        'key': 'EIGRP-3-K_VALUE_MISMATCH',
        'category': 'routing',
        'messages': ['K-value mismatch with neighbor {peer_ip}'],
        'peer_ip': True
    },

    # =========================================================================
    # ISIS
    # =========================================================================
    {
        'key': 'ISIS-5-ADJCHANGE',
        'category': 'routing',
        'messages': [
            'Adjacency to {peer_ip} ({interface}) Up, new adjacency',
            'Adjacency to {peer_ip} ({interface}) Down, hold time expired'
        ],
        'peer_ip': True,
        'interfaces': True
    },
    {
        'key': 'ISIS-4-AUTHFAIL',
        'category': 'routing',
        'messages': ['Authentication failed for IS-IS on {interface}'],
        'interfaces': True
    },
    {
        'key': 'ISIS-5-NEWADJ',
        'category': 'routing',
        'messages': ['New adjacency formed with {peer_ip} on {interface}'],
        'peer_ip': True,
        'interfaces': True
    },

    # =========================================================================
    # RIP
    # =========================================================================
    {
        'key': 'RIP-4-AUTHFAIL',
        'category': 'routing',
        'messages': ['Authentication failed for RIP on {interface}'],
        'interfaces': True
    },
    {
        'key': 'RIP-3-BADPKT',
        'category': 'routing',
        'messages': ['Bad RIP packet from {peer_ip}'],
        'peer_ip': True
    },

    # =========================================================================
    # PIM/IGMP (Multicast)
    # =========================================================================
    {
        'key': 'PIM-5-NBRCHG',
        'category': 'multicast',
        'messages': [
            'Neighbor {peer_ip} on {interface} is up',
            'Neighbor {peer_ip} on {interface} is down (neighbor timeout)'
        ],
        'peer_ip': True,
        'interfaces': True
    },
    {
        'key': 'PIM-4-INVALID_RP_ADDR',
        'category': 'multicast',
        'messages': ['Invalid RP address 224.0.0.0 received'],
    },
    {
        'key': 'PIM-5-DRCHG',
        'category': 'multicast',
        'messages': ['Designated Router changed to {peer_ip} on {interface}'],
        'peer_ip': True,
        'interfaces': True
    },
    {
        'key': 'IGMP-3-INVALID_GROUP',
        'category': 'multicast',
        'messages': ['Invalid group address 0.0.0.0 received on {interface}'],
        'interfaces': True
    },
    {
        'key': 'IGMP-5-LIMIT_EXCEED',
        'category': 'multicast',
        'messages': ['IGMP group limit exceeded on {interface}'],
        'interfaces': True
    },

    # =========================================================================
    # SPANNING TREE
    # =========================================================================
    {
        'key': 'SPANTREE-2-BLOCK_PVID_LOCAL',
        'category': 'spanning-tree',
        'messages': ['Blocking {interface} on VLAN0001. Inconsistent local PVID.'],
        'interfaces': True
    },
    {
        'key': 'SPANTREE-2-CHNL_MISCFG',
        'category': 'spanning-tree',
        'messages': ['Detected possible channel misconfiguration on {interface}'],
        'interfaces': True
    },
    {
        'key': 'SPANTREE-2-LOOPGUARD_BLOCK',
        'category': 'spanning-tree',
        'messages': ['Loop guard blocking port {interface} on VLAN0001'],
        'interfaces': True
    },
    {
        'key': 'SPANTREE-2-LOOPGUARD_UNBLOCK',
        'category': 'spanning-tree',
        'messages': ['Loop guard unblocking port {interface} on VLAN0001'],
        'interfaces': True
    },
    {
        'key': 'SPANTREE-2-ROOTGUARD_BLOCK',
        'category': 'spanning-tree',
        'messages': ['Root guard blocking port {interface} on VLAN0001'],
        'interfaces': True
    },
    {
        'key': 'SPANTREE-2-ROOTGUARD_UNBLOCK',
        'category': 'spanning-tree',
        'messages': ['Root guard unblocking port {interface} on VLAN0001'],
        'interfaces': True
    },
    {
        'key': 'SPANTREE-5-TOPOTRAP',
        'category': 'spanning-tree',
        'messages': ['Topology change trap for VLAN 1'],
    },
    {
        'key': 'SPANTREE-5-ROOTCHANGE',
        'category': 'spanning-tree',
        'messages': ['Root changed for VLAN 1: new root port is {interface}'],
        'interfaces': True
    },
    {
        'key': 'STP-2-INCONSISTENT',
        'category': 'spanning-tree',
        'messages': ['Spanning tree inconsistency detected on {interface}'],
        'interfaces': True
    },
    {
        'key': 'RSTP-5-TOPOLOGY_CHANGE',
        'category': 'spanning-tree',
        'messages': ['RSTP Topology change on {interface}'],
        'interfaces': True
    },
    {
        'key': 'MST-5-TOPOLOGY_CHANGE',
        'category': 'spanning-tree',
        'messages': ['MST Topology change on {interface} in MST instance 0'],
        'interfaces': True
    },
    {
        'key': 'EC-5-BUNDLE',
        'category': 'spanning-tree',
        'messages': ['{interface} is added to port-channel 1'],
        'interfaces': True
    },
    {
        'key': 'EC-5-UNBUNDLE',
        'category': 'spanning-tree',
        'messages': ['{interface} is removed from port-channel 1'],
        'interfaces': True
    },
    {
        'key': 'EC-5-STAYDOWN',
        'category': 'spanning-tree',
        'messages': ['{interface} will be held down in port-channel 1'],
        'interfaces': True
    },
    {
        'key': 'EC-5-CANNOT_BUNDLE',
        'category': 'spanning-tree',
        'messages': ['{interface} is not compatible with port-channel 1'],
        'interfaces': True
    },

    # =========================================================================
    # SECURITY
    # =========================================================================
    {
        'key': 'SEC_LOGIN-5-LOGIN_SUCCESS',
        'category': 'security',
        'messages': ['Login Success [user: admin] [Source: {peer_ip}] [localport: 22]'],
        'peer_ip': True
    },
    {
        'key': 'SEC_LOGIN-4-LOGIN_FAILED',
        'category': 'security',
        'messages': ['Login failed [user: admin] [Source: {peer_ip}] [localport: 22] [Reason: Bad password]'],
        'peer_ip': True
    },
    {
        'key': 'SEC_LOGIN-1-QUIET_MODE_ON',
        'category': 'security',
        'messages': ['Quiet Mode is ON for 60 seconds [user: admin] [Source: {peer_ip}]'],
        'peer_ip': True
    },
    {
        'key': 'SEC_LOGIN-5-QUIET_MODE_OFF',
        'category': 'security',
        'messages': ['Quiet Mode is OFF [user: admin]'],
    },
    {
        'key': 'SSH-5-SSH2_USERAUTH',
        'category': 'security',
        'messages': ['User admin login via SSH from {peer_ip} (line vty0)'],
        'peer_ip': True
    },
    {
        'key': 'SSH-5-SSH2_SESSION',
        'category': 'security',
        'messages': ['SSH session from {peer_ip} (line vty0) opened'],
        'peer_ip': True
    },
    {
        'key': 'SSH-5-SSH2_CLOSE',
        'category': 'security',
        'messages': ['SSH session from {peer_ip} (line vty0) closed'],
        'peer_ip': True
    },
    {
        'key': 'AUTHMGR-5-START',
        'category': 'security',
        'messages': ['Starting authentication for client on {interface}'],
        'interfaces': True
    },
    {
        'key': 'AUTHMGR-5-SUCCESS',
        'category': 'security',
        'messages': ['Authentication successful for client on {interface}'],
        'interfaces': True
    },
    {
        'key': 'AUTHMGR-5-FAIL',
        'category': 'security',
        'messages': ['Authentication failed for client on {interface}'],
        'interfaces': True
    },
    {
        'key': 'DOT1X-5-SUCCESS',
        'category': 'security',
        'messages': ['Authentication successful for client ({mac}) on {interface}'],
        'interfaces': True,
        'mac': True
    },
    {
        'key': 'DOT1X-5-FAIL',
        'category': 'security',
        'messages': ['Authentication failed for client ({mac}) on {interface}'],
        'interfaces': True,
        'mac': True
    },
    {
        'key': 'MAB-5-SUCCESS',
        'category': 'security',
        'messages': ['MAC Authentication Bypass succeeded for client ({mac}) on {interface}'],
        'interfaces': True,
        'mac': True
    },
    {
        'key': 'MAB-5-FAIL',
        'category': 'security',
        'messages': ['MAC Authentication Bypass failed for client ({mac}) on {interface}'],
        'interfaces': True,
        'mac': True
    },
    {
        'key': 'CRYPTO-4-RECVD_PKT_INV_SPI',
        'category': 'security',
        'messages': ['Received packet with invalid SPI from {peer_ip}'],
        'peer_ip': True
    },
    {
        'key': 'CRYPTO-5-SESSION_STATUS',
        'category': 'security',
        'messages': [
            'Crypto session to {peer_ip} is up',
            'Crypto session to {peer_ip} is down'
        ],
        'peer_ip': True
    },

    # =========================================================================
    # PORT SECURITY
    # =========================================================================
    {
        'key': 'PORTSEC-2-VIOLATION',
        'category': 'port-security',
        'messages': ['Security violation on {interface}, mac address {mac}'],
        'interfaces': True,
        'mac': True
    },
    {
        'key': 'PM-4-ERR_DISABLE',
        'category': 'port-security',
        'messages': ['{interface} put in err-disable state due to bpduguard'],
        'interfaces': True
    },
    {
        'key': 'PM-4-ERR_RECOVER',
        'category': 'port-security',
        'messages': ['{interface} recovering from err-disable state'],
        'interfaces': True
    },
    {
        'key': 'DHCP_SNOOPING-4-DHCP_SNOOPING_ERRDISABLE',
        'category': 'port-security',
        'messages': ['{interface} err-disabled due to DHCP snooping violation'],
        'interfaces': True
    },
    {
        'key': 'DAI-4-DHCP_SNOOPING_DENY',
        'category': 'port-security',
        'messages': ['DAI denied ARP packet: Invalid ARP entry on {interface}'],
        'interfaces': True
    },
    {
        'key': 'STORM_CONTROL-3-FILTERED',
        'category': 'port-security',
        'messages': ['Storm control filtering broadcast on {interface}'],
        'interfaces': True
    },
    {
        'key': 'STORM_CONTROL-3-SHUTDOWN',
        'category': 'port-security',
        'messages': ['Storm control shutdown {interface}'],
        'interfaces': True
    },

    # =========================================================================
    # HARDWARE/ENVIRONMENT
    # =========================================================================
    {
        'key': 'ENVMON-4-TEMPWARNING',
        'category': 'hardware',
        'messages': ['Temperature sensor {sensor} warning: temperature {temp}C exceeds warning threshold'],
        'sensor': True,
        'temp': True
    },
    {
        'key': 'ENVMON-2-TEMPSHUT',
        'category': 'hardware',
        'messages': ['Temperature sensor {sensor} critical: temperature {temp}C exceeds critical threshold, shutting down'],
        'sensor': True,
        'temp': True
    },
    {
        'key': 'ENVMON-3-FAN_FAIL',
        'category': 'hardware',
        'messages': ['Fan {fan_num} failure detected'],
        'fan_num': True
    },
    {
        'key': 'ENVMON-5-FAN_OK',
        'category': 'hardware',
        'messages': ['Fan {fan_num} operating normally'],
        'fan_num': True
    },
    {
        'key': 'ENVMON-3-PS_FAIL',
        'category': 'hardware',
        'messages': ['Power supply {ps_num} failure'],
        'ps_num': True
    },
    {
        'key': 'ENVMON-5-PS_OK',
        'category': 'hardware',
        'messages': ['Power supply {ps_num} operating normally'],
        'ps_num': True
    },
    {
        'key': 'FAN-3-FAN_FAILED',
        'category': 'hardware',
        'messages': ['Fan {fan_num} in slot 1 failed'],
        'fan_num': True
    },
    {
        'key': 'FAN-5-FAN_OK',
        'category': 'hardware',
        'messages': ['Fan {fan_num} in slot 1 is OK'],
        'fan_num': True
    },
    {
        'key': 'POWER-3-POWER_FAIL',
        'category': 'hardware',
        'messages': ['Power supply {ps_num} failed'],
        'ps_num': True
    },
    {
        'key': 'POWER-5-POWER_OK',
        'category': 'hardware',
        'messages': ['Power supply {ps_num} is OK'],
        'ps_num': True
    },
    {
        'key': 'PLATFORM-3-FAN_TRAY_FAIL',
        'category': 'hardware',
        'messages': ['Fan tray {fan_num} failure'],
        'fan_num': True
    },
    {
        'key': 'PLATFORM-5-FAN_TRAY_OK',
        'category': 'hardware',
        'messages': ['Fan tray {fan_num} OK'],
        'fan_num': True
    },
    {
        'key': 'PLATFORM-4-TEMP_WARNING',
        'category': 'hardware',
        'messages': ['Temperature sensor {sensor} warning: {temp}C'],
        'sensor': True,
        'temp': True
    },
    {
        'key': 'PLATFORM-2-TEMP_CRITICAL',
        'category': 'hardware',
        'messages': ['Temperature sensor {sensor} critical: {temp}C'],
        'sensor': True,
        'temp': True
    },
    {
        'key': 'PLATFORM-6-MODULE_INSERTED',
        'category': 'hardware',
        'messages': ['Module {module} inserted in slot {slot}'],
        'module': True,
        'slot': True
    },
    {
        'key': 'PLATFORM-6-MODULE_REMOVED',
        'category': 'hardware',
        'messages': ['Module {module} removed from slot {slot}'],
        'module': True,
        'slot': True
    },
    {
        'key': 'MODULE-5-MOD_OK',
        'category': 'hardware',
        'messages': ['Module {module} is online'],
        'module': True
    },
    {
        'key': 'MODULE-3-MOD_FAIL',
        'category': 'hardware',
        'messages': ['Module {module} has failed'],
        'module': True
    },
    {
        'key': 'PMAN-3-PROCFAILCRIT',
        'category': 'hardware',
        'messages': ['Critical process {process} has failed'],
        'process': True
    },

    # =========================================================================
    # REDUNDANCY/HA
    # =========================================================================
    {
        'key': 'HSRP-5-STATECHANGE',
        'category': 'redundancy',
        'messages': [
            'Group {group} on {interface} state Standby -> Active',
            'Group {group} on {interface} state Active -> Speak',
            'Group {group} on {interface} state Speak -> Standby'
        ],
        'interfaces': True,
        'group': True
    },
    {
        'key': 'HSRP-6-STATECHANGE',
        'category': 'redundancy',
        'messages': [
            'Group {group} on {interface} state Standby -> Active',
            'Group {group} on {interface} state Active -> Init'
        ],
        'interfaces': True,
        'group': True
    },
    {
        'key': 'VRRP-6-STATECHANGE',
        'category': 'redundancy',
        'messages': [
            'Group {group} on {interface} state Backup -> Master',
            'Group {group} on {interface} state Master -> Backup'
        ],
        'interfaces': True,
        'group': True
    },
    {
        'key': 'GLBP-5-STATECHANGE',
        'category': 'redundancy',
        'messages': [
            'Group {group} on {interface} state Standby -> Active',
            'Group {group} on {interface} state Active -> Speak'
        ],
        'interfaces': True,
        'group': True
    },
    {
        'key': 'REDUNDANCY-5-SWITCHOVER_HISTORY',
        'category': 'redundancy',
        'messages': ['Switchover history: standby switched to active'],
    },
    {
        'key': 'REDUNDANCY-3-PEER_DOWN',
        'category': 'redundancy',
        'messages': ['Redundancy peer is down'],
    },
    {
        'key': 'REDUNDANCY-5-PEER_UP',
        'category': 'redundancy',
        'messages': ['Redundancy peer is up'],
    },
    {
        'key': 'STACKMGR-5-SWITCH_ADDED',
        'category': 'redundancy',
        'messages': ['Switch {switch_num} has been added to the stack'],
        'switch_num': True
    },
    {
        'key': 'STACKMGR-5-SWITCH_REMOVED',
        'category': 'redundancy',
        'messages': ['Switch {switch_num} has been removed from the stack'],
        'switch_num': True
    },
    {
        'key': 'STACKMGR-4-SWITCH_REMOVED_CRASH',
        'category': 'redundancy',
        'messages': ['Switch {switch_num} has crashed and been removed'],
        'switch_num': True
    },
    {
        'key': 'STACKMGR-5-MASTER_ELECTED',
        'category': 'redundancy',
        'messages': ['Switch {switch_num} has become the new master'],
        'switch_num': True
    },
    {
        'key': 'STACKMGR-3-STACK_LINK_CHANGE',
        'category': 'redundancy',
        'messages': [
            'Stack link on switch {switch_num} is down',
            'Stack link on switch {switch_num} is up'
        ],
        'switch_num': True
    },
    {
        'key': 'VPC-2-PEER_KEEP_ALIVE_RECV_FAIL',
        'category': 'redundancy',
        'messages': ['VPC peer keepalive receive failed'],
    },
    {
        'key': 'VPC-5-PEER_KEEP_ALIVE_RECV_SUCCESS',
        'category': 'redundancy',
        'messages': ['VPC peer keepalive receive success'],
    },
    {
        'key': 'VPC-2-DUAL_ACTIVE_DETECTED',
        'category': 'redundancy',
        'messages': ['VPC dual-active detected! Suspending VPC ports'],
    },
    {
        'key': 'VPC-5-VPC_PEER_LINK_UP',
        'category': 'redundancy',
        'messages': ['VPC peer-link is up'],
    },
    {
        'key': 'VPC-2-VPC_PEER_LINK_DOWN',
        'category': 'redundancy',
        'messages': ['VPC peer-link is down'],
    },
    {
        'key': 'VPC-5-ROLE_CHANGE',
        'category': 'redundancy',
        'messages': ['VPC role changed to primary'],
    },

    # =========================================================================
    # CONFIGURATION
    # =========================================================================
    {
        'key': 'SYS-5-CONFIG_I',
        'category': 'config',
        'messages': ['Configured from console by admin on vty0 ({peer_ip})'],
        'peer_ip': True
    },
    {
        'key': 'SYS-5-CONFIG',
        'category': 'config',
        'messages': ['Configuration was changed by admin'],
    },
    {
        'key': 'SYS-5-RELOAD',
        'category': 'config',
        'messages': ['System reloading by admin'],
    },
    {
        'key': 'SYS-5-RESTART',
        'category': 'config',
        'messages': ['System restarted'],
    },
    {
        'key': 'SYS-3-CPUHOG',
        'category': 'performance',
        'messages': ['Task ran for {ms}ms, Process={process}'],
        'ms': True,
        'process': True
    },
    {
        'key': 'SYS-2-MALLOCFAIL',
        'category': 'performance',
        'messages': ['Memory allocation of {bytes} bytes failed, pool {pool}'],
        'bytes': True,
        'pool': True
    },
    {
        'key': 'CONFIG-5-STARTUP_CONFIG',
        'category': 'config',
        'messages': ['Startup config loaded'],
    },
    {
        'key': 'PARSER-5-CFGLOG_LOGGEDCMD',
        'category': 'config',
        'messages': ['User admin: logging configuration command'],
    },
    {
        'key': 'PARSER-4-BADCFG',
        'category': 'config',
        'messages': ['Unexpected end of command'],
    },
    {
        'key': 'ARCHIVE-3-UNABLE_ARCHIVE',
        'category': 'config',
        'messages': ['Unable to archive config to tftp://{peer_ip}/config'],
        'peer_ip': True
    },

    # =========================================================================
    # AAA
    # =========================================================================
    {
        'key': 'TACACS-3-SERVER_UNREACHABLE',
        'category': 'aaa',
        'messages': ['TACACS+ server {peer_ip} is unreachable'],
        'peer_ip': True
    },
    {
        'key': 'TACACS-5-SERVER_REACHABLE',
        'category': 'aaa',
        'messages': ['TACACS+ server {peer_ip} is reachable'],
        'peer_ip': True
    },
    {
        'key': 'TACACS-4-AUTHEN_FAIL',
        'category': 'aaa',
        'messages': ['TACACS+ authentication failed for user admin from {peer_ip}'],
        'peer_ip': True
    },
    {
        'key': 'RADIUS-3-NOSERVERS',
        'category': 'aaa',
        'messages': ['No RADIUS servers available'],
    },
    {
        'key': 'RADIUS-4-RADIUS_DEAD',
        'category': 'aaa',
        'messages': ['RADIUS server {peer_ip} is dead'],
        'peer_ip': True
    },
    {
        'key': 'RADIUS-5-RADIUS_ALIVE',
        'category': 'aaa',
        'messages': ['RADIUS server {peer_ip} is alive'],
        'peer_ip': True
    },
    {
        'key': 'AAA-3-REJECT',
        'category': 'aaa',
        'messages': ['AAA authentication rejected for user admin'],
    },
    {
        'key': 'AAA-4-ACCFAIL',
        'category': 'aaa',
        'messages': ['AAA accounting request failed'],
    },

    # =========================================================================
    # SYSTEM
    # =========================================================================
    {
        'key': 'SNMP-3-AUTHFAIL',
        'category': 'system',
        'messages': ['Authentication failure for SNMP request from {peer_ip}'],
        'peer_ip': True
    },
    {
        'key': 'SNMP-5-COLDSTART',
        'category': 'system',
        'messages': ['SNMP coldStart notification'],
    },
    {
        'key': 'SNMP-5-WARMSTART',
        'category': 'system',
        'messages': ['SNMP warmStart notification'],
    },
    {
        'key': 'NTP-4-SYNC_FAIL',
        'category': 'system',
        'messages': ['NTP synchronization with {peer_ip} failed'],
        'peer_ip': True
    },
    {
        'key': 'NTP-5-SYNC_OK',
        'category': 'system',
        'messages': ['NTP synchronized to {peer_ip}'],
        'peer_ip': True
    },
    {
        'key': 'MEMORY-4-LOW',
        'category': 'performance',
        'messages': ['Memory low: {percent}% used'],
        'percent': True
    },
    {
        'key': 'MEMORY-2-CRITICAL',
        'category': 'performance',
        'messages': ['Memory critical: {percent}% used'],
        'percent': True
    },
    {
        'key': 'CPU-4-HIGH',
        'category': 'performance',
        'messages': ['CPU utilization high: {percent}%'],
        'percent': True
    },
    {
        'key': 'CPU-5-NORMAL',
        'category': 'performance',
        'messages': ['CPU utilization normal: {percent}%'],
        'percent': True
    },

    # =========================================================================
    # VPN/TUNNEL
    # =========================================================================
    {
        'key': 'CRYPTO-5-TUNNEL_UP',
        'category': 'vpn',
        'messages': ['Crypto tunnel to {peer_ip} is up'],
        'peer_ip': True
    },
    {
        'key': 'CRYPTO-5-TUNNEL_DOWN',
        'category': 'vpn',
        'messages': ['Crypto tunnel to {peer_ip} is down'],
        'peer_ip': True
    },
    {
        'key': 'IPSEC-3-SA_FAILURE',
        'category': 'vpn',
        'messages': ['IPSec SA failure for peer {peer_ip}'],
        'peer_ip': True
    },
    {
        'key': 'IPSEC-5-TRANS_UP',
        'category': 'vpn',
        'messages': ['IPSec transform to {peer_ip} is up'],
        'peer_ip': True
    },
    {
        'key': 'IPSEC-5-TRANS_DOWN',
        'category': 'vpn',
        'messages': ['IPSec transform to {peer_ip} is down'],
        'peer_ip': True
    },
    {
        'key': 'DMVPN-5-NHRP_NHEC_UP',
        'category': 'vpn',
        'messages': ['DMVPN NHRP tunnel to {peer_ip} is up'],
        'peer_ip': True
    },
    {
        'key': 'DMVPN-5-NHRP_NHEC_DOWN',
        'category': 'vpn',
        'messages': ['DMVPN NHRP tunnel to {peer_ip} is down'],
        'peer_ip': True
    },
    {
        'key': 'TUNNEL-5-UPDOWN',
        'category': 'vpn',
        'messages': [
            'Interface Tunnel{tunnel_num}, changed state to up',
            'Interface Tunnel{tunnel_num}, changed state to down'
        ],
        'tunnel_num': True
    },

    # =========================================================================
    # WIRELESS
    # =========================================================================
    {
        'key': 'DOT11-6-ASSOC',
        'category': 'wireless',
        'messages': ['Client {mac} associated to AP {ap_name}'],
        'mac': True,
        'ap_name': True
    },
    {
        'key': 'DOT11-6-DISASSOC',
        'category': 'wireless',
        'messages': ['Client {mac} disassociated from AP {ap_name}'],
        'mac': True,
        'ap_name': True
    },
    {
        'key': 'DOT11-4-MAXRETRIES',
        'category': 'wireless',
        'messages': ['Max retries reached for client {mac}'],
        'mac': True
    },
    {
        'key': 'CAPWAP-3-ERRORLOG',
        'category': 'wireless',
        'messages': ['CAPWAP error: connection to controller failed'],
    },
    {
        'key': 'AP-6-JOINED',
        'category': 'wireless',
        'messages': ['AP {ap_name} joined controller'],
        'ap_name': True
    },
    {
        'key': 'AP-3-DISASSOCIATED',
        'category': 'wireless',
        'messages': ['AP {ap_name} disassociated from controller'],
        'ap_name': True
    },
    {
        'key': 'AP-4-ROGUE_DETECTED',
        'category': 'wireless',
        'messages': ['Rogue AP detected: BSSID {mac}'],
        'mac': True
    },

    # =========================================================================
    # QOS
    # =========================================================================
    {
        'key': 'QOS-4-POLICER_DROPPED',
        'category': 'qos',
        'messages': ['QoS policer dropped {packets} packets on {interface}'],
        'packets': True,
        'interfaces': True
    },
    {
        'key': 'QOS-3-ERROR',
        'category': 'qos',
        'messages': ['QoS error: policy-map application failed on {interface}'],
        'interfaces': True
    },
    {
        'key': 'POLICING-4-EXCEED',
        'category': 'qos',
        'messages': ['Traffic exceeded policy on {interface}'],
        'interfaces': True
    },

    # =========================================================================
    # VLAN
    # =========================================================================
    {
        'key': 'VLAN-5-CREATED',
        'category': 'vlan',
        'messages': ['VLAN {vlan} created'],
        'vlan': True
    },
    {
        'key': 'VLAN-5-DELETED',
        'category': 'vlan',
        'messages': ['VLAN {vlan} deleted'],
        'vlan': True
    },
    {
        'key': 'VTP-5-BADPWD',
        'category': 'vlan',
        'messages': ['VTP bad password received from {peer_ip}'],
        'peer_ip': True
    },
    {
        'key': 'VTP-4-REVISION_HIGHER',
        'category': 'vlan',
        'messages': ['VTP received configuration with higher revision from {peer_ip}'],
        'peer_ip': True
    },

    # =========================================================================
    # MPLS/BFD
    # =========================================================================
    {
        'key': 'MPLS-5-IFUP',
        'category': 'routing',
        'messages': ['MPLS interface {interface} is up'],
        'interfaces': True
    },
    {
        'key': 'MPLS-5-IFDOWN',
        'category': 'routing',
        'messages': ['MPLS interface {interface} is down'],
        'interfaces': True
    },
    {
        'key': 'LDP-5-NBRCHG',
        'category': 'routing',
        'messages': [
            'LDP neighbor {peer_ip} is up',
            'LDP neighbor {peer_ip} is down'
        ],
        'peer_ip': True
    },
    {
        'key': 'BFD-6-BFD_SESS_UP',
        'category': 'routing',
        'messages': ['BFD session to {peer_ip} on {interface} is up'],
        'peer_ip': True,
        'interfaces': True
    },
    {
        'key': 'BFD-6-BFD_SESS_DOWN',
        'category': 'routing',
        'messages': ['BFD session to {peer_ip} on {interface} is down'],
        'peer_ip': True,
        'interfaces': True
    },
    {
        'key': 'BFD-3-BFD_SESSION_FAIL',
        'category': 'routing',
        'messages': ['BFD session to {peer_ip} failed'],
        'peer_ip': True
    },

    # =========================================================================
    # LACP/LLDP
    # =========================================================================
    {
        'key': 'LACP-5-ACTIVITYCHANGED',
        'category': 'link-state',
        'messages': ['LACP activity changed on {interface}'],
        'interfaces': True
    },
    {
        'key': 'LACP-3-SYSPRI_MISMATCH',
        'category': 'link-state',
        'messages': ['LACP system priority mismatch on {interface}'],
        'interfaces': True
    },
    {
        'key': 'LLDP-5-NBRINFO',
        'category': 'link-state',
        'messages': ['LLDP neighbor info changed on {interface}'],
        'interfaces': True
    },

    # =========================================================================
    # LICENSE
    # =========================================================================
    {
        'key': 'LICENSE-5-EVALUATION',
        'category': 'system',
        'messages': ['License for feature is in evaluation mode'],
    },
    {
        'key': 'LICENSE-4-EXPIRING',
        'category': 'system',
        'messages': ['License expires in 30 days'],
    },
    {
        'key': 'LICENSE-3-EXPIRED',
        'category': 'system',
        'messages': ['License has expired'],
    },
    {
        'key': 'LICENSE-5-INSTALLED',
        'category': 'system',
        'messages': ['License installed successfully'],
    },

    # =========================================================================
    # NX-OS SPECIFIC
    # =========================================================================
    {
        'key': 'ETHPORT-5-IF_ADMIN_UP',
        'category': 'link-state',
        'messages': ['Interface {interface} is administratively up'],
        'interfaces': True
    },
    {
        'key': 'ETHPORT-5-IF_ADMIN_DOWN',
        'category': 'link-state',
        'messages': ['Interface {interface} is administratively down'],
        'interfaces': True
    },
    {
        'key': 'VSHD-5-VSHD_SYSLOG_CONFIG_I',
        'category': 'config',
        'messages': ['Configured from vty by admin on {peer_ip}'],
        'peer_ip': True
    },

    # =========================================================================
    # IOS-XR SPECIFIC
    # =========================================================================
    {
        'key': 'PKT_INFRA-LINK-3-UPDOWN',
        'category': 'link-state',
        'messages': [
            'Interface {interface}, changed state to Down',
            'Interface {interface}, changed state to Up'
        ],
        'interfaces': True
    },
    {
        'key': 'IM-6-LINK_UP',
        'category': 'link-state',
        'messages': ['Interface {interface} link up'],
        'interfaces': True
    },
    {
        'key': 'IM-6-LINK_DOWN',
        'category': 'link-state',
        'messages': ['Interface {interface} link down'],
        'interfaces': True
    },
    {
        'key': 'ROUTING-BGP-5-ADJCHANGE',
        'category': 'routing',
        'messages': [
            'neighbor {peer_ip} Up',
            'neighbor {peer_ip} Down'
        ],
        'peer_ip': True
    },
    {
        'key': 'ROUTING-OSPF-5-ADJCHG',
        'category': 'routing',
        'messages': [
            'Nbr {peer_ip} on {interface} from FULL to DOWN',
            'Nbr {peer_ip} on {interface} from LOADING to FULL'
        ],
        'peer_ip': True,
        'interfaces': True
    },

    # =========================================================================
    # MERAKI SPECIFIC
    # =========================================================================
    {
        'key': 'MERAKI-5-AP_CONNECT',
        'category': 'wireless',
        'messages': ['AP {ap_name} connected to cloud'],
        'ap_name': True
    },
    {
        'key': 'MERAKI-3-AP_DISCONNECT',
        'category': 'wireless',
        'messages': ['AP {ap_name} disconnected from cloud'],
        'ap_name': True
    },
]

# Device simulation data
DEVICE_TYPES = {
    'router': {
        'hostname_prefix': 'rtr',
        'ip_prefix': '10.1.1.',
        'interfaces': [
            'GigabitEthernet0/0', 'GigabitEthernet0/1', 'GigabitEthernet0/2',
            'GigabitEthernet0/0/0', 'GigabitEthernet0/0/1',
            'TenGigabitEthernet0/0', 'TenGigabitEthernet0/1',
            'Serial0/0/0', 'Serial0/0/1',
            'Tunnel0', 'Tunnel1', 'Tunnel100',
            'Loopback0', 'Loopback1'
        ]
    },
    'switch': {
        'hostname_prefix': 'sw',
        'ip_prefix': '10.1.2.',
        'interfaces': [
            'GigabitEthernet0/1', 'GigabitEthernet0/2', 'GigabitEthernet0/3',
            'GigabitEthernet0/4', 'GigabitEthernet0/5', 'GigabitEthernet0/6',
            'GigabitEthernet1/0/1', 'GigabitEthernet1/0/2', 'GigabitEthernet1/0/3',
            'TenGigabitEthernet1/0/1', 'TenGigabitEthernet1/0/2',
            'Port-channel1', 'Port-channel2', 'Port-channel10',
            'Vlan1', 'Vlan10', 'Vlan100', 'Vlan200'
        ]
    },
    'nexus': {
        'hostname_prefix': 'nxos',
        'ip_prefix': '10.1.3.',
        'interfaces': [
            'Ethernet1/1', 'Ethernet1/2', 'Ethernet1/3', 'Ethernet1/4',
            'Ethernet1/5', 'Ethernet1/6', 'Ethernet1/7', 'Ethernet1/8',
            'port-channel1', 'port-channel2', 'port-channel100',
            'Vlan10', 'Vlan20', 'Vlan100'
        ]
    },
    'firewall': {
        'hostname_prefix': 'fw',
        'ip_prefix': '10.1.4.',
        'interfaces': [
            'GigabitEthernet0/0', 'GigabitEthernet0/1', 'GigabitEthernet0/2',
            'Management0/0', 'inside', 'outside', 'dmz'
        ]
    },
    'wlc': {
        'hostname_prefix': 'wlc',
        'ip_prefix': '10.1.5.',
        'interfaces': [
            'GigabitEthernet0/0/1', 'GigabitEthernet0/0/2',
            'Port-channel1'
        ]
    }
}

AP_NAMES = [
    'AP-Floor1-East', 'AP-Floor1-West', 'AP-Floor1-North', 'AP-Floor1-South',
    'AP-Floor2-East', 'AP-Floor2-West', 'AP-Floor2-North', 'AP-Floor2-South',
    'AP-Lobby', 'AP-Conference-A', 'AP-Conference-B', 'AP-Cafeteria',
    'AP-Warehouse-1', 'AP-Warehouse-2', 'AP-Office-101', 'AP-Office-102'
]


def generate_mac():
    """Generate a random MAC address."""
    return ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])


def generate_peer_ip():
    """Generate a random peer IP."""
    prefixes = ['10.0.', '172.16.', '192.168.']
    prefix = random.choice(prefixes)
    return f"{prefix}{random.randint(1, 254)}.{random.randint(1, 254)}"


def generate_timestamp(platform='ios'):
    """Generate a timestamp in various Cisco formats."""
    now = datetime.now()

    if platform == 'ios':
        # IOS format: *Mar  1 00:00:00.000:
        return now.strftime("*%b %d %H:%M:%S.000:")
    elif platform == 'nxos':
        # NX-OS format: 2026 Feb  2 10:30:00
        return now.strftime("%Y %b %d %H:%M:%S")
    elif platform == 'iosxr':
        # IOS-XR format: RP/0/RSP0/CPU0:Feb  2 10:30:00.000 :
        return f"RP/0/RSP0/CPU0:{now.strftime('%b %d %H:%M:%S.000')} :"
    else:
        # rsyslog format: Feb  2 10:30:00
        return now.strftime("%b %d %H:%M:%S")


def format_syslog_message(key, message, hostname, platform='rsyslog'):
    """Format a complete syslog message line."""
    timestamp = generate_timestamp(platform)

    if platform == 'ios':
        # IOS: sequence: *timestamp: %MSG
        seq = random.randint(1, 999999)
        return f"{seq:06d}: {timestamp} %{key}: {message}"
    elif platform == 'nxos':
        # NX-OS: timestamp hostname %MSG
        return f"{timestamp} {hostname} %{key}: {message}"
    elif platform == 'iosxr':
        # IOS-XR: location:timestamp : process: %MSG
        process = random.choice(['ifmgr', 'bgp', 'ospf', 'syslog', 'config'])
        return f"{timestamp} {process}[{random.randint(100, 9999)}]: %{key}: {message}"
    else:
        # rsyslog: timestamp hostname %MSG
        return f"{timestamp} {hostname} %{key}: {message}"


def send_syslog(sock, target_host, target_port, message, facility=1, severity=5):
    """Send a syslog message via UDP.

    Args:
        sock: UDP socket
        target_host: Target hostname or IP
        target_port: Target port (usually 514)
        message: Syslog message content
        facility: Syslog facility (default 1 = user)
        severity: Syslog severity (default 5 = notice)
    """
    # Calculate PRI value
    pri = (facility * 8) + severity

    # Format syslog packet
    packet = f"<{pri}>{message}"

    try:
        sock.sendto(packet.encode(), (target_host, target_port))
        return True
    except Exception as e:
        print(f"Error sending syslog: {e}")
        return False


def expand_message(msg_def, device_type='switch'):
    """Expand a message template with dynamic values."""
    device = DEVICE_TYPES.get(device_type, DEVICE_TYPES['switch'])
    messages = []

    for template in msg_def['messages']:
        message = template

        # Replace placeholders
        if msg_def.get('interfaces') and '{interface}' in message:
            message = message.replace('{interface}', random.choice(device['interfaces']))

        if msg_def.get('peer_ip') and '{peer_ip}' in message:
            message = message.replace('{peer_ip}', generate_peer_ip())

        if msg_def.get('mac') and '{mac}' in message:
            message = message.replace('{mac}', generate_mac())

        if msg_def.get('ap_name') and '{ap_name}' in message:
            message = message.replace('{ap_name}', random.choice(AP_NAMES))

        if msg_def.get('sensor') and '{sensor}' in message:
            message = message.replace('{sensor}', random.choice(['1', '2', '3', 'CPU', 'Inlet', 'Outlet']))

        if msg_def.get('temp') and '{temp}' in message:
            message = message.replace('{temp}', str(random.randint(45, 95)))

        if msg_def.get('fan_num') and '{fan_num}' in message:
            message = message.replace('{fan_num}', str(random.randint(1, 6)))

        if msg_def.get('ps_num') and '{ps_num}' in message:
            message = message.replace('{ps_num}', str(random.randint(1, 2)))

        if msg_def.get('module') and '{module}' in message:
            message = message.replace('{module}', random.choice(['Supervisor', 'Line Card', 'Power Supply', 'Fan']))

        if msg_def.get('slot') and '{slot}' in message:
            message = message.replace('{slot}', str(random.randint(1, 8)))

        if msg_def.get('group') and '{group}' in message:
            message = message.replace('{group}', str(random.randint(1, 10)))

        if msg_def.get('switch_num') and '{switch_num}' in message:
            message = message.replace('{switch_num}', str(random.randint(1, 8)))

        if msg_def.get('tunnel_num') and '{tunnel_num}' in message:
            message = message.replace('{tunnel_num}', str(random.randint(0, 100)))

        if msg_def.get('vlan') and '{vlan}' in message:
            message = message.replace('{vlan}', str(random.randint(1, 4094)))

        if msg_def.get('process') and '{process}' in message:
            message = message.replace('{process}', random.choice(['bgp', 'ospf', 'snmpd', 'iosd', 'fman']))

        if msg_def.get('ms') and '{ms}' in message:
            message = message.replace('{ms}', str(random.randint(2000, 60000)))

        if msg_def.get('bytes') and '{bytes}' in message:
            message = message.replace('{bytes}', str(random.randint(1024, 1048576)))

        if msg_def.get('pool') and '{pool}' in message:
            message = message.replace('{pool}', random.choice(['Processor', 'I/O', 'Driver', 'System']))

        if msg_def.get('percent') and '{percent}' in message:
            message = message.replace('{percent}', str(random.randint(75, 99)))

        if msg_def.get('packets') and '{packets}' in message:
            message = message.replace('{packets}', str(random.randint(100, 100000)))

        messages.append(message)

    return messages


def get_categories():
    """Get list of unique categories."""
    categories = set()
    for msg in SYSLOG_MESSAGES:
        categories.add(msg['category'])
    return sorted(categories)


def main():
    parser = argparse.ArgumentParser(
        description='Cisco Syslog Test Sender',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Send all message types once
    %(prog)s --target 192.168.1.1:514 --all

    # Send specific category
    %(prog)s --target 192.168.1.1:514 --category link-state

    # Continuous mode with 5 second interval
    %(prog)s --target 192.168.1.1:514 --continuous --interval 5

    # Burst mode - 100 messages per interval, 1000 total
    %(prog)s --target 192.168.1.1:514 --burst 100 --count 1000

    # List available categories
    %(prog)s --list-categories

    # List all message types
    %(prog)s --list-messages
        """
    )

    parser.add_argument('--target', type=str, default='localhost:514',
                        help='Target host:port (default: localhost:514)')
    parser.add_argument('--all', action='store_true',
                        help='Send all message types')
    parser.add_argument('--category', type=str,
                        help='Send only messages from this category')
    parser.add_argument('--message', type=str,
                        help='Send specific message by key (e.g., LINK-3-UPDOWN)')
    parser.add_argument('--continuous', action='store_true',
                        help='Send messages continuously')
    parser.add_argument('--interval', type=float, default=5.0,
                        help='Seconds between messages (default: 5)')
    parser.add_argument('--burst', type=int, default=1,
                        help='Messages per interval in continuous mode (default: 1)')
    parser.add_argument('--count', type=int, default=0,
                        help='Total messages to send (0=unlimited in continuous mode)')
    parser.add_argument('--devices', type=int, default=3,
                        help='Number of simulated devices (default: 3)')
    parser.add_argument('--platform', type=str, default='rsyslog',
                        choices=['ios', 'nxos', 'iosxr', 'rsyslog'],
                        help='Syslog format platform (default: rsyslog)')
    parser.add_argument('--list-categories', action='store_true',
                        help='List available message categories')
    parser.add_argument('--list-messages', action='store_true',
                        help='List all message types')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')

    args = parser.parse_args()

    # Handle list commands
    if args.list_categories:
        print("Available categories:")
        for cat in get_categories():
            count = sum(1 for m in SYSLOG_MESSAGES if m['category'] == cat)
            print(f"  {cat}: {count} message types")
        print(f"\nTotal: {len(SYSLOG_MESSAGES)} message types")
        return 0

    if args.list_messages:
        print("Available message types:")
        current_cat = None
        for msg in sorted(SYSLOG_MESSAGES, key=lambda x: (x['category'], x['key'])):
            if msg['category'] != current_cat:
                current_cat = msg['category']
                print(f"\n[{current_cat}]")
            print(f"  {msg['key']}")
        print(f"\nTotal: {len(SYSLOG_MESSAGES)} message types")
        return 0

    # Parse target
    if ':' in args.target:
        target_host, target_port = args.target.rsplit(':', 1)
        target_port = int(target_port)
    else:
        target_host = args.target
        target_port = 514

    # Filter messages
    messages_to_send = SYSLOG_MESSAGES

    if args.category:
        messages_to_send = [m for m in messages_to_send if m['category'] == args.category]
        if not messages_to_send:
            print(f"Error: No messages found for category '{args.category}'")
            print(f"Available categories: {', '.join(get_categories())}")
            return 1

    if args.message:
        messages_to_send = [m for m in messages_to_send if m['key'] == args.message]
        if not messages_to_send:
            print(f"Error: Message type '{args.message}' not found")
            return 1

    if not args.all and not args.category and not args.message and not args.continuous:
        print("Error: Specify --all, --category, --message, or --continuous")
        parser.print_help()
        return 1

    # Generate device list
    devices = []
    device_types = list(DEVICE_TYPES.keys())
    for i in range(args.devices):
        dtype = device_types[i % len(device_types)]
        device_info = DEVICE_TYPES[dtype]
        devices.append({
            'type': dtype,
            'hostname': f"{device_info['hostname_prefix']}-{i+1:02d}",
            'ip': f"{device_info['ip_prefix']}{i+10}"
        })

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"Cisco Syslog Test Sender v{VERSION}")
    print(f"Target: {target_host}:{target_port}")
    print(f"Platform format: {args.platform}")
    print(f"Devices: {len(devices)}")
    print(f"Message types: {len(messages_to_send)}")
    print()

    sent_count = 0

    try:
        if args.continuous:
            print(f"Continuous mode: {args.burst} msg/interval, interval={args.interval}s")
            if args.count > 0:
                print(f"Will stop after {args.count} messages")
            print("Press Ctrl+C to stop\n")

            while True:
                for _ in range(args.burst):
                    # Pick random message and device
                    msg_def = random.choice(messages_to_send)
                    device = random.choice(devices)
                    expanded = expand_message(msg_def, device['type'])
                    message_text = random.choice(expanded)

                    # Format and send
                    hostname = device['hostname'] if args.platform != 'ios' else device['ip']
                    full_message = format_syslog_message(
                        msg_def['key'], message_text, hostname, args.platform
                    )

                    if send_syslog(sock, target_host, target_port, full_message):
                        sent_count += 1
                        print(f"[{sent_count}] {msg_def['key']}: {message_text[:60]}...")

                    if args.count > 0 and sent_count >= args.count:
                        print(f"\nReached count limit ({args.count})")
                        return 0

                time.sleep(args.interval)
        else:
            # Send all messages once
            for msg_def in messages_to_send:
                device = random.choice(devices)
                expanded = expand_message(msg_def, device['type'])

                for message_text in expanded:
                    hostname = device['hostname'] if args.platform != 'ios' else device['ip']
                    full_message = format_syslog_message(
                        msg_def['key'], message_text, hostname, args.platform
                    )

                    if send_syslog(sock, target_host, target_port, full_message):
                        sent_count += 1
                        print(f"[{sent_count}] {msg_def['key']}: {message_text[:60]}...")

                    time.sleep(0.01)  # Small delay between messages

            print(f"\nSent {sent_count} messages")

    except KeyboardInterrupt:
        print(f"\n\nInterrupted. Sent {sent_count} messages total.")
    finally:
        sock.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
