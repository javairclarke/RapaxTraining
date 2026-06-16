#!/usr/bin/env python3
"""
Cisco SNMP Trap Test Sender
===========================

Sends test SNMP traps (v1 and v2c) to validate the cisco-trap-processord.
Supports multiple device type simulations and trap categories.

Usage:
    cisco-trap-sender.py --target localhost:162 --all
    cisco-trap-sender.py --target localhost:162 --category link-state
    cisco-trap-sender.py --target localhost:162 --trap 1.3.6.1.6.3.1.1.5.3
    cisco-trap-sender.py --target localhost:162 --continuous --interval 5

Author: Rapax Integration
"""

import os
import sys
import argparse
import time
import random
import socket

try:
    from pysnmp.hlapi import *
    from pysnmp.proto.api import v2c
except ImportError:
    print("Error: pysnmp not installed. Run: pip install pysnmp==4.4.12")
    sys.exit(1)

VERSION = '1.0.0'

# =============================================================================
# TEST TRAP DEFINITIONS
# =============================================================================
# Each trap includes:
#   - oid: The trap OID
#   - name: Human-readable name
#   - category: Category for filtering
#   - version: 'v1', 'v2c', or 'both'
#   - varbinds: List of (oid, type, value) tuples
#   - device_type: Type of device that would send this trap
# =============================================================================

TEST_TRAPS = [
    # =========================================================================
    # RFC 1157 / SNMPv2-MIB Generic Traps
    # =========================================================================
    {'oid': '1.3.6.1.6.3.1.1.5.1', 'name': 'coldStart', 'category': 'device-state', 'version': 'both', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.2.1.1.3.0', 'TimeTicks', 0)]},
    {'oid': '1.3.6.1.6.3.1.1.5.2', 'name': 'warmStart', 'category': 'device-state', 'version': 'both', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.2.1.1.3.0', 'TimeTicks', 100)]},
    {'oid': '1.3.6.1.6.3.1.1.5.3', 'name': 'linkDown', 'category': 'link-state', 'version': 'both', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.2.2.1.1.1', 'Integer32', 1), ('1.3.6.1.2.1.2.2.1.2.1', 'OctetString', 'GigabitEthernet0/0/1'), ('1.3.6.1.2.1.2.2.1.8.1', 'Integer32', 2)]},
    {'oid': '1.3.6.1.6.3.1.1.5.4', 'name': 'linkUp', 'category': 'link-state', 'version': 'both', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.2.2.1.1.1', 'Integer32', 1), ('1.3.6.1.2.1.2.2.1.2.1', 'OctetString', 'GigabitEthernet0/0/1'), ('1.3.6.1.2.1.2.2.1.8.1', 'Integer32', 1)]},
    {'oid': '1.3.6.1.6.3.1.1.5.5', 'name': 'authenticationFailure', 'category': 'security', 'version': 'both', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.1.3.0', 'TimeTicks', 12345678)]},
    # Legacy SNMPv1 coldStart
    {'oid': '1.3.6.1.4.1.9.0.1', 'name': 'coldStart-legacy', 'category': 'device-state', 'version': 'v1', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.2.1.1.3.0', 'TimeTicks', 0)]},

    # =========================================================================
    # IF-MIB Interface Traps (RFC 2863)
    # =========================================================================
    {'oid': '1.3.6.1.2.1.2.2.0.1', 'name': 'linkDown-ifmib', 'category': 'link-state', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.2.2.1.1.1', 'Integer32', 1), ('1.3.6.1.2.1.2.2.1.2.1', 'OctetString', 'Ethernet0/1')]},
    {'oid': '1.3.6.1.2.1.2.2.0.2', 'name': 'linkUp-ifmib', 'category': 'link-state', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.2.2.1.1.1', 'Integer32', 1), ('1.3.6.1.2.1.2.2.1.2.1', 'OctetString', 'Ethernet0/1')]},

    # =========================================================================
    # BGP Traps (RFC 4273)
    # =========================================================================
    {'oid': '1.3.6.1.2.1.15.7.1', 'name': 'bgpEstablished', 'category': 'routing', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.15.3.1.2', 'IpAddress', '10.0.0.1'), ('1.3.6.1.2.1.15.3.1.7', 'Integer32', 65001)]},
    {'oid': '1.3.6.1.2.1.15.7.2', 'name': 'bgpBackwardTransition', 'category': 'routing', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.15.3.1.2', 'IpAddress', '10.0.0.1'), ('1.3.6.1.2.1.15.3.1.7', 'Integer32', 65001)]},

    # =========================================================================
    # OSPF Traps (RFC 1850)
    # =========================================================================
    {'oid': '1.3.6.1.2.1.14.16.2.1', 'name': 'ospfVirtIfStateChange', 'category': 'routing', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.14.9.1.1', 'IpAddress', '0.0.0.0'), ('1.3.6.1.2.1.14.9.1.5', 'Integer32', 1)]},
    {'oid': '1.3.6.1.2.1.14.16.2.2', 'name': 'ospfNbrStateChange', 'category': 'routing', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.14.10.1.1', 'IpAddress', '192.168.1.1'), ('1.3.6.1.2.1.14.10.1.3', 'IpAddress', '1.1.1.1'), ('1.3.6.1.2.1.14.10.1.6', 'Integer32', 1)]},
    {'oid': '1.3.6.1.2.1.14.16.2.3', 'name': 'ospfVirtNbrStateChange', 'category': 'routing', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.14.11.1.1', 'IpAddress', '0.0.0.0'), ('1.3.6.1.2.1.14.11.1.5', 'Integer32', 1)]},
    {'oid': '1.3.6.1.2.1.14.16.2.4', 'name': 'ospfIfConfigError', 'category': 'routing', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.14.7.1.1', 'IpAddress', '192.168.1.1'), ('1.3.6.1.2.1.14.7.1.8', 'Integer32', 1)]},
    {'oid': '1.3.6.1.2.1.14.16.2.5', 'name': 'ospfVirtIfConfigError', 'category': 'routing', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.14.9.1.1', 'IpAddress', '0.0.0.0')]},
    {'oid': '1.3.6.1.2.1.14.16.2.6', 'name': 'ospfIfAuthFailure', 'category': 'routing', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.14.7.1.1', 'IpAddress', '192.168.1.1'), ('1.3.6.1.2.1.14.7.1.8', 'Integer32', 2)]},
    {'oid': '1.3.6.1.2.1.14.16.2.16', 'name': 'ospfIfStateChange', 'category': 'routing', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.14.7.1.1', 'IpAddress', '192.168.1.1'), ('1.3.6.1.2.1.14.7.1.12', 'Integer32', 1)]},

    # =========================================================================
    # EIGRP Traps (Cisco)
    # =========================================================================
    {'oid': '1.3.6.1.4.1.9.9.449.0.1', 'name': 'cEigrpNbrDownEvent', 'category': 'routing', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.4.1.9.9.449.1.4.1.1.2', 'IpAddress', '10.1.1.2'), ('1.3.6.1.4.1.9.9.449.1.4.1.1.3', 'OctetString', 'Gi0/1')]},
    {'oid': '1.3.6.1.4.1.9.9.449.0.2', 'name': 'cEigrpNbrUpEvent', 'category': 'routing', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.4.1.9.9.449.1.4.1.1.2', 'IpAddress', '10.1.1.2'), ('1.3.6.1.4.1.9.9.449.1.4.1.1.3', 'OctetString', 'Gi0/1')]},

    # =========================================================================
    # Cisco Environment Monitoring (CISCO-ENVMON-MIB)
    # =========================================================================
    {'oid': '1.3.6.1.4.1.9.9.13.3.0.1', 'name': 'ciscoEnvMonShutdownNotification', 'category': 'environment', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.13.1.3.1.3', 'Integer32', 3), ('1.3.6.1.4.1.9.9.13.1.3.1.6', 'OctetString', 'System shutdown imminent')]},
    {'oid': '1.3.6.1.4.1.9.9.13.3.0.2', 'name': 'ciscoEnvMonVoltageNotification', 'category': 'environment', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.13.1.2.1.3', 'Integer32', 3300), ('1.3.6.1.4.1.9.9.13.1.2.1.7', 'OctetString', 'Voltage Sensor 1')]},
    {'oid': '1.3.6.1.4.1.9.9.13.3.0.3', 'name': 'ciscoEnvMonTemperatureNotification', 'category': 'environment', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.13.1.3.1.3', 'Integer32', 75), ('1.3.6.1.4.1.9.9.13.1.3.1.6', 'OctetString', 'Temperature Sensor 1')]},
    {'oid': '1.3.6.1.4.1.9.9.13.3.0.4', 'name': 'ciscoEnvMonFanNotification', 'category': 'environment', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.13.1.4.1.2', 'OctetString', 'Fan Tray 1'), ('1.3.6.1.4.1.9.9.13.1.4.1.3', 'Integer32', 3)]},
    {'oid': '1.3.6.1.4.1.9.9.13.3.0.5', 'name': 'ciscoEnvMonRedundantSupplyNotification', 'category': 'environment', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.13.1.5.1.2', 'OctetString', 'Power Supply 2'), ('1.3.6.1.4.1.9.9.13.1.5.1.3', 'Integer32', 3)]},

    # =========================================================================
    # Cisco HSRP (CISCO-HSRP-MIB)
    # =========================================================================
    {'oid': '1.3.6.1.4.1.9.9.106.2.0.1', 'name': 'cHsrpStateChange', 'category': 'redundancy', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.4.1.9.9.106.1.2.1.1.15', 'Integer32', 6), ('1.3.6.1.4.1.9.9.106.1.2.1.1.11', 'IpAddress', '192.168.1.1')]},

    # =========================================================================
    # VRRP Traps
    # =========================================================================
    {'oid': '1.3.6.1.2.1.68.0.1', 'name': 'vrrpTrapNewMaster', 'category': 'redundancy', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.68.1.3.1.3', 'IpAddress', '10.0.0.1')]},
    {'oid': '1.3.6.1.2.1.68.0.2', 'name': 'vrrpTrapAuthFailure', 'category': 'redundancy', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.2.1.68.1.3.1.3', 'IpAddress', '10.0.0.1')]},

    # =========================================================================
    # Cisco Config Management (CISCO-CONFIG-MAN-MIB)
    # =========================================================================
    {'oid': '1.3.6.1.4.1.9.9.43.2.0.1', 'name': 'ccmCLIRunningConfigChanged', 'category': 'config', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.4.1.9.9.43.1.1.6.1.3', 'Integer32', 1), ('1.3.6.1.4.1.9.9.43.1.1.6.1.5', 'Integer32', 1)]},
    {'oid': '1.3.6.1.4.1.9.9.43.2.0.2', 'name': 'ccmCTIDRolledOver', 'category': 'config', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.4.1.9.9.43.1.1.1.0', 'Integer32', 1)]},
    {'oid': '1.3.6.1.4.1.9.9.43.2.0.3', 'name': 'ciscoConfigManEvent', 'category': 'config', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.4.1.9.9.43.1.1.6.1.3', 'Integer32', 1)]},

    # =========================================================================
    # Cisco CPU/Memory (CISCO-PROCESS-MIB)
    # =========================================================================
    {'oid': '1.3.6.1.4.1.9.9.109.2.0.1', 'name': 'cpmCPURisingThreshold', 'category': 'performance', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.4.1.9.9.109.1.1.1.1.8', 'Integer32', 95), ('1.3.6.1.4.1.9.9.109.1.1.1.1.9', 'Integer32', 80)]},
    {'oid': '1.3.6.1.4.1.9.9.109.2.0.2', 'name': 'cpmCPUFallingThreshold', 'category': 'performance', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.4.1.9.9.109.1.1.1.1.8', 'Integer32', 45), ('1.3.6.1.4.1.9.9.109.1.1.1.1.9', 'Integer32', 80)]},

    # =========================================================================
    # Cisco Memory Pool (CISCO-MEMORY-POOL-MIB)
    # =========================================================================
    {'oid': '1.3.6.1.4.1.9.9.48.2.0.1', 'name': 'ciscoMemoryPoolLowMemoryNotif', 'category': 'performance', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.4.1.9.9.48.1.1.1.2', 'OctetString', 'Processor'), ('1.3.6.1.4.1.9.9.48.1.1.1.5', 'Integer32', 1024000)]},
    {'oid': '1.3.6.1.4.1.9.9.48.2.0.2', 'name': 'ciscoMemoryPoolLowMemoryRecoveryNotif', 'category': 'performance', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.4.1.9.9.48.1.1.1.2', 'OctetString', 'Processor'), ('1.3.6.1.4.1.9.9.48.1.1.1.5', 'Integer32', 10240000)]},

    # =========================================================================
    # Cisco Security (Various MIBs)
    # =========================================================================
    {'oid': '1.3.6.1.4.1.9.9.315.0.1', 'name': 'ciscoSecureViolation', 'category': 'security', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.315.1.2.1.1.2', 'OctetString', 'Fa0/1'), ('1.3.6.1.4.1.9.9.315.1.2.1.1.10', 'OctetString', 'aa:bb:cc:dd:ee:ff')]},
    {'oid': '1.3.6.1.4.1.9.9.315.0.2', 'name': 'ciscoSecureMacAddrViolation', 'category': 'security', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.315.1.2.1.1.2', 'OctetString', 'Gi0/1'), ('1.3.6.1.4.1.9.9.315.1.2.1.1.10', 'OctetString', 'de:ad:be:ef:00:01')]},

    # =========================================================================
    # Cisco 802.1X (IEEE8021-PAE-MIB)
    # =========================================================================
    {'oid': '1.3.6.1.4.1.9.9.656.0.1', 'name': 'cpaeAuthFailVlanNotif', 'category': 'security', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.656.1.4.1.1.2', 'OctetString', 'Gi0/1'), ('1.3.6.1.4.1.9.9.656.1.4.1.1.3', 'Integer32', 100)]},
    {'oid': '1.3.6.1.4.1.9.9.656.0.2', 'name': 'cpaeAuthSuccessVlanNotif', 'category': 'security', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.656.1.4.1.1.2', 'OctetString', 'Gi0/1'), ('1.3.6.1.4.1.9.9.656.1.4.1.1.3', 'Integer32', 10)]},

    # =========================================================================
    # Cisco ASA/Firepower
    # =========================================================================
    {'oid': '1.3.6.1.4.1.9.9.147.0.1', 'name': 'cfwSecEventAlert', 'category': 'security', 'version': 'v2c', 'device_type': 'firewall',
     'varbinds': [('1.3.6.1.4.1.9.9.147.1.2.1.1.1.2', 'OctetString', 'Firewall event')]},

    # =========================================================================
    # Cisco Entity FRU Control (Hardware)
    # =========================================================================
    {'oid': '1.3.6.1.4.1.9.9.500.0.1', 'name': 'cefcFRURemoved', 'category': 'hardware', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.2.1.47.1.1.1.1.7', 'OctetString', 'Supervisor Module')]},
    {'oid': '1.3.6.1.4.1.9.9.500.0.2', 'name': 'cefcFRUInserted', 'category': 'hardware', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.2.1.47.1.1.1.1.7', 'OctetString', 'Line Card Module 1')]},
    {'oid': '1.3.6.1.4.1.9.9.500.0.3', 'name': 'cefcModuleStatusChange', 'category': 'hardware', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.2.1.47.1.1.1.1.7', 'OctetString', 'Module 1'), ('1.3.6.1.4.1.9.9.117.1.2.1.1.2', 'Integer32', 2)]},
    {'oid': '1.3.6.1.4.1.9.9.500.0.4', 'name': 'cefcPowerStatusChange', 'category': 'hardware', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.2.1.47.1.1.1.1.7', 'OctetString', 'Power Supply 1'), ('1.3.6.1.4.1.9.9.117.1.1.2.1.2', 'Integer32', 2)]},
    {'oid': '1.3.6.1.4.1.9.9.500.0.5', 'name': 'cefcFanTrayStatusChange', 'category': 'hardware', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.2.1.47.1.1.1.1.7', 'OctetString', 'Fan Tray 1'), ('1.3.6.1.4.1.9.9.117.1.4.1.1.1', 'Integer32', 2)]},

    # =========================================================================
    # Cisco Wireless (AIRESPACE-WIRELESS-MIB / CISCO-LWAPP-*)
    # =========================================================================
    {'oid': '1.3.6.1.4.1.14179.2.6.3.1', 'name': 'bsnAPDisassociated', 'category': 'wireless', 'version': 'v2c', 'device_type': 'wireless-controller',
     'varbinds': [('1.3.6.1.4.1.14179.2.2.1.1.3', 'OctetString', 'AP-Floor1-East'), ('1.3.6.1.4.1.14179.2.2.1.1.6', 'OctetString', 'aa:bb:cc:dd:ee:01')]},
    {'oid': '1.3.6.1.4.1.14179.2.6.3.2', 'name': 'bsnAPAssociated', 'category': 'wireless', 'version': 'v2c', 'device_type': 'wireless-controller',
     'varbinds': [('1.3.6.1.4.1.14179.2.2.1.1.3', 'OctetString', 'AP-Floor1-East'), ('1.3.6.1.4.1.14179.2.2.1.1.6', 'OctetString', 'aa:bb:cc:dd:ee:01')]},
    {'oid': '1.3.6.1.4.1.14179.2.6.3.3', 'name': 'bsnAPIfUp', 'category': 'wireless', 'version': 'v2c', 'device_type': 'wireless-controller',
     'varbinds': [('1.3.6.1.4.1.14179.2.2.1.1.3', 'OctetString', 'AP-Floor2-West'), ('1.3.6.1.4.1.14179.2.2.2.1.2', 'Integer32', 1)]},
    {'oid': '1.3.6.1.4.1.14179.2.6.3.4', 'name': 'bsnAPIfDown', 'category': 'wireless', 'version': 'v2c', 'device_type': 'wireless-controller',
     'varbinds': [('1.3.6.1.4.1.14179.2.2.1.1.3', 'OctetString', 'AP-Floor2-West'), ('1.3.6.1.4.1.14179.2.2.2.1.2', 'Integer32', 1)]},
    {'oid': '1.3.6.1.4.1.14179.2.6.3.8', 'name': 'bsnRogueAPDetected', 'category': 'wireless', 'version': 'v2c', 'device_type': 'wireless-controller',
     'varbinds': [('1.3.6.1.4.1.14179.2.1.7.1.1', 'OctetString', 'de:ad:be:ef:00:01'), ('1.3.6.1.4.1.14179.2.1.7.1.4', 'OctetString', 'RogueNetwork')]},
    {'oid': '1.3.6.1.4.1.14179.2.6.3.9', 'name': 'bsnRogueAPRemoved', 'category': 'wireless', 'version': 'v2c', 'device_type': 'wireless-controller',
     'varbinds': [('1.3.6.1.4.1.14179.2.1.7.1.1', 'OctetString', 'de:ad:be:ef:00:01')]},
    {'oid': '1.3.6.1.4.1.14179.2.6.3.16', 'name': 'bsnAPCoverageHoleDetected', 'category': 'wireless', 'version': 'v2c', 'device_type': 'wireless-controller',
     'varbinds': [('1.3.6.1.4.1.14179.2.2.1.1.3', 'OctetString', 'AP-Lobby')]},
    {'oid': '1.3.6.1.4.1.14179.2.6.3.44', 'name': 'bsnDot11ClientAssoc', 'category': 'wireless', 'version': 'v2c', 'device_type': 'wireless-controller',
     'varbinds': [('1.3.6.1.4.1.14179.2.1.4.1.1', 'OctetString', 'aa:bb:cc:11:22:33')]},
    {'oid': '1.3.6.1.4.1.14179.2.6.3.45', 'name': 'bsnDot11ClientDisassoc', 'category': 'wireless', 'version': 'v2c', 'device_type': 'wireless-controller',
     'varbinds': [('1.3.6.1.4.1.14179.2.1.4.1.1', 'OctetString', 'aa:bb:cc:11:22:33')]},

    # =========================================================================
    # Cisco Stack/Chassis (CISCO-STACKWISE-MIB)
    # =========================================================================
    {'oid': '1.3.6.1.4.1.9.9.500.0.6', 'name': 'cswStackPortChange', 'category': 'stack', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.500.1.2.2.1.1', 'Integer32', 1)]},
    {'oid': '1.3.6.1.4.1.9.9.500.0.7', 'name': 'cswStackNewMaster', 'category': 'stack', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.500.1.2.1.1.1', 'Integer32', 2)]},
    {'oid': '1.3.6.1.4.1.9.9.500.0.8', 'name': 'cswStackMemberRemoved', 'category': 'stack', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.500.1.2.1.1.1', 'Integer32', 3)]},
    {'oid': '1.3.6.1.4.1.9.9.500.0.9', 'name': 'cswStackMemberAdded', 'category': 'stack', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.500.1.2.1.1.1', 'Integer32', 4)]},
    {'oid': '1.3.6.1.4.1.9.9.500.0.10', 'name': 'cswStackRingRedundant', 'category': 'stack', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.500.1.1.3.0', 'Integer32', 1)]},
    {'oid': '1.3.6.1.4.1.9.9.500.0.11', 'name': 'cswStackRingNotRedundant', 'category': 'stack', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.500.1.1.3.0', 'Integer32', 2)]},

    # =========================================================================
    # Cisco vPC (CISCO-VPC-MIB)
    # =========================================================================
    {'oid': '1.3.6.1.4.1.9.9.807.0.1', 'name': 'cVpcPeerKeepAliveStatusChange', 'category': 'vpc', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.807.1.1.1.0', 'Integer32', 2)]},
    {'oid': '1.3.6.1.4.1.9.9.807.0.2', 'name': 'cVpcRoleChange', 'category': 'vpc', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.807.1.1.2.0', 'Integer32', 1)]},
    {'oid': '1.3.6.1.4.1.9.9.807.0.3', 'name': 'cVpcPeerLinkStatusChange', 'category': 'vpc', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.807.1.2.1.1.1', 'Integer32', 2)]},
    {'oid': '1.3.6.1.4.1.9.9.807.0.4', 'name': 'cVpcDualActiveDetected', 'category': 'vpc', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.807.1.1.3.0', 'Integer32', 1)]},

    # =========================================================================
    # Cisco Spanning Tree (CISCO-STP-EXTENSIONS-MIB)
    # =========================================================================
    {'oid': '1.3.6.1.4.1.9.9.82.2.0.1', 'name': 'stpxInconsistencyUpdate', 'category': 'spanning-tree', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.82.1.1.1.1.1', 'Integer32', 1), ('1.3.6.1.4.1.9.9.82.1.1.1.1.2', 'OctetString', 'Gi1/0/1')]},
    {'oid': '1.3.6.1.4.1.9.9.82.2.0.2', 'name': 'stpxRootInconsistencyUpdate', 'category': 'spanning-tree', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.82.1.1.1.1.1', 'Integer32', 1), ('1.3.6.1.4.1.9.9.82.1.1.1.1.2', 'OctetString', 'Gi1/0/2')]},
    {'oid': '1.3.6.1.4.1.9.9.82.2.0.3', 'name': 'stpxLoopInconsistencyUpdate', 'category': 'spanning-tree', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.4.1.9.9.82.1.1.1.1.1', 'Integer32', 1), ('1.3.6.1.4.1.9.9.82.1.1.1.1.2', 'OctetString', 'Gi1/0/3')]},

    # =========================================================================
    # Entity MIB (RFC 4133)
    # =========================================================================
    {'oid': '1.3.6.1.2.1.47.2.0.1', 'name': 'entConfigChange', 'category': 'entity', 'version': 'v2c', 'device_type': 'switch',
     'varbinds': [('1.3.6.1.2.1.47.1.4.1.0', 'TimeTicks', 12345678)]},

    # =========================================================================
    # SNMP Target MIB
    # =========================================================================
    {'oid': '1.3.6.1.6.3.12.1.4', 'name': 'snmpUnavailableContexts', 'category': 'snmp', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.6.3.12.1.1.0', 'Integer32', 1)]},
    {'oid': '1.3.6.1.6.3.12.1.5', 'name': 'snmpUnknownContexts', 'category': 'snmp', 'version': 'v2c', 'device_type': 'router',
     'varbinds': [('1.3.6.1.6.3.12.1.2.0', 'Integer32', 1)]},
]

# Device type simulations with different source IPs
DEVICE_SIMULATIONS = {
    'router': {
        'ip_prefix': '10.1.1.',
        'names': ['core-rtr-01', 'edge-rtr-02', 'branch-rtr-03', 'wan-rtr-04', 'dc-rtr-05']
    },
    'switch': {
        'ip_prefix': '10.1.2.',
        'names': ['access-sw-01', 'dist-sw-02', 'core-sw-03', 'tor-sw-04', 'mgmt-sw-05']
    },
    'firewall': {
        'ip_prefix': '10.1.3.',
        'names': ['fw-dmz-01', 'fw-internal-02', 'fw-edge-03']
    },
    'wireless-controller': {
        'ip_prefix': '10.1.4.',
        'names': ['wlc-primary-01', 'wlc-secondary-02']
    }
}

# Interface name templates for generating varied interfaces
INTERFACE_TEMPLATES = [
    'GigabitEthernet0/0/{}',
    'GigabitEthernet0/1/{}',
    'GigabitEthernet1/0/{}',
    'TenGigabitEthernet0/0/{}',
    'TenGigabitEthernet1/0/{}',
    'FastEthernet0/{}',
    'Ethernet{}',
    'Port-channel{}',
    'Vlan{}',
    'Loopback{}',
    'Tunnel{}',
]

# BGP peer templates
BGP_PEERS = [
    ('10.0.0.1', 65001), ('10.0.0.2', 65002), ('10.0.0.3', 65003),
    ('172.16.1.1', 65100), ('172.16.2.1', 65200), ('172.16.3.1', 65300),
    ('192.168.100.1', 64512), ('192.168.100.2', 64513), ('192.168.100.3', 64514),
]

# OSPF neighbor templates
OSPF_NEIGHBORS = [
    ('192.168.1.1', '1.1.1.1'), ('192.168.1.2', '2.2.2.2'), ('192.168.1.3', '3.3.3.3'),
    ('10.255.0.1', '10.0.0.1'), ('10.255.0.2', '10.0.0.2'), ('10.255.0.3', '10.0.0.3'),
]

# AP names for wireless
AP_NAMES = [
    'AP-Floor1-East', 'AP-Floor1-West', 'AP-Floor1-North', 'AP-Floor1-South',
    'AP-Floor2-East', 'AP-Floor2-West', 'AP-Floor2-North', 'AP-Floor2-South',
    'AP-Floor3-East', 'AP-Floor3-West', 'AP-Floor3-North', 'AP-Floor3-South',
    'AP-Lobby', 'AP-Cafeteria', 'AP-Conference-A', 'AP-Conference-B',
    'AP-Warehouse-1', 'AP-Warehouse-2', 'AP-Warehouse-3', 'AP-Warehouse-4',
]


def generate_interface_name():
    """Generate a random interface name."""
    template = random.choice(INTERFACE_TEMPLATES)
    return template.format(random.randint(1, 48))


def generate_mac_address():
    """Generate a random MAC address."""
    return ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])


def generate_dynamic_trap(base_trap):
    """Generate a trap with randomized varbinds based on the trap type."""
    trap = base_trap.copy()
    trap['varbinds'] = list(base_trap['varbinds'])  # Copy varbinds list

    category = trap['category']
    name = trap['name']

    # Generate dynamic varbinds based on trap type
    if category == 'link-state':
        interface = generate_interface_name()
        if_index = random.randint(1, 100)
        trap['varbinds'] = [
            ('1.3.6.1.2.1.2.2.1.1.{}'.format(if_index), 'Integer32', if_index),
            ('1.3.6.1.2.1.2.2.1.2.{}'.format(if_index), 'OctetString', interface),
            ('1.3.6.1.2.1.2.2.1.3.{}'.format(if_index), 'Integer32', 6),
            ('1.3.6.1.2.1.2.2.1.7.{}'.format(if_index), 'Integer32', 1 if 'Up' in name else 2),
            ('1.3.6.1.2.1.2.2.1.8.{}'.format(if_index), 'Integer32', 1 if 'Up' in name else 2),
        ]

    elif category == 'routing' and 'bgp' in name.lower():
        peer_ip, peer_as = random.choice(BGP_PEERS)
        state = 6 if 'Established' in name else random.choice([1, 2, 3])
        trap['varbinds'] = [
            ('1.3.6.1.2.1.15.3.1.2', 'IpAddress', peer_ip),
            ('1.3.6.1.2.1.15.3.1.7', 'Integer32', peer_as),
            ('1.3.6.1.2.1.15.3.1.2', 'Integer32', state),
        ]

    elif category == 'routing' and 'ospf' in name.lower():
        nbr_ip, rtr_id = random.choice(OSPF_NEIGHBORS)
        state = random.randint(1, 8)
        trap['varbinds'] = [
            ('1.3.6.1.2.1.14.10.1.1', 'IpAddress', nbr_ip),
            ('1.3.6.1.2.1.14.10.1.3', 'IpAddress', rtr_id),
            ('1.3.6.1.2.1.14.10.1.6', 'Integer32', state),
        ]

    elif category == 'routing' and 'eigrp' in name.lower():
        interface = generate_interface_name()
        trap['varbinds'] = [
            ('1.3.6.1.4.1.9.9.449.1.4.1.1.2', 'IpAddress', f'10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}'),
            ('1.3.6.1.4.1.9.9.449.1.4.1.1.3', 'OctetString', interface),
        ]

    elif category == 'environment':
        sensor_num = random.randint(1, 8)
        value = random.randint(70, 95) if 'Temperature' in name else random.randint(1, 5)
        trap['varbinds'] = [
            ('1.3.6.1.4.1.9.9.13.1.3.1.3', 'Integer32', value),
            ('1.3.6.1.4.1.9.9.13.1.3.1.6', 'OctetString', f'Sensor {sensor_num}'),
        ]

    elif category == 'wireless':
        ap_name = random.choice(AP_NAMES)
        ap_mac = generate_mac_address()
        trap['varbinds'] = [
            ('1.3.6.1.4.1.14179.2.2.1.1.3', 'OctetString', ap_name),
            ('1.3.6.1.4.1.14179.2.2.1.1.6', 'OctetString', ap_mac),
        ]

    elif category == 'security':
        interface = generate_interface_name()
        mac = generate_mac_address()
        trap['varbinds'] = [
            ('1.3.6.1.4.1.9.9.315.1.2.1.1.2', 'OctetString', interface),
            ('1.3.6.1.4.1.9.9.315.1.2.1.1.10', 'OctetString', mac),
        ]

    elif category == 'stack':
        member_num = random.randint(1, 9)
        trap['varbinds'] = [
            ('1.3.6.1.4.1.9.9.500.1.2.1.1.1', 'Integer32', member_num),
        ]

    elif category == 'vpc':
        status = random.randint(1, 3)
        trap['varbinds'] = [
            ('1.3.6.1.4.1.9.9.807.1.1.1.0', 'Integer32', status),
        ]

    elif category == 'redundancy':
        vip = f'192.168.{random.randint(1, 254)}.{random.randint(1, 254)}'
        trap['varbinds'] = [
            ('1.3.6.1.4.1.9.9.106.1.2.1.1.15', 'Integer32', random.randint(1, 6)),
            ('1.3.6.1.4.1.9.9.106.1.2.1.1.11', 'IpAddress', vip),
        ]

    elif category == 'spanning-tree':
        vlan = random.randint(1, 4094)
        interface = generate_interface_name()
        trap['varbinds'] = [
            ('1.3.6.1.4.1.9.9.82.1.1.1.1.1', 'Integer32', vlan),
            ('1.3.6.1.4.1.9.9.82.1.1.1.1.2', 'OctetString', interface),
        ]

    elif category == 'performance':
        cpu_value = random.randint(80, 99)
        threshold = random.randint(70, 85)
        trap['varbinds'] = [
            ('1.3.6.1.4.1.9.9.109.1.1.1.1.8', 'Integer32', cpu_value),
            ('1.3.6.1.4.1.9.9.109.1.1.1.1.9', 'Integer32', threshold),
        ]

    elif category == 'hardware':
        fru_names = ['Supervisor Module', 'Line Card 1', 'Line Card 2', 'Power Supply 1', 'Power Supply 2', 'Fan Tray 1', 'Fan Tray 2']
        trap['varbinds'] = [
            ('1.3.6.1.2.1.47.1.1.1.1.7', 'OctetString', random.choice(fru_names)),
        ]

    return trap


def get_categories():
    """Get list of available trap categories."""
    categories = set()
    for trap in TEST_TRAPS:
        categories.add(trap['category'])
    return sorted(categories)


def get_traps_by_category(category):
    """Get traps filtered by category."""
    return [t for t in TEST_TRAPS if t['category'] == category]


def get_trap_by_oid(oid):
    """Get trap by OID."""
    for trap in TEST_TRAPS:
        if trap['oid'] == oid:
            return trap
    return None


def create_varbind_objects(varbinds):
    """Convert varbind definitions to pysnmp objects."""
    result = []
    for oid, val_type, value in varbinds:
        if val_type == 'Integer32':
            result.append(ObjectType(ObjectIdentity(oid), Integer32(value)))
        elif val_type == 'OctetString':
            result.append(ObjectType(ObjectIdentity(oid), OctetString(value)))
        elif val_type == 'IpAddress':
            result.append(ObjectType(ObjectIdentity(oid), IpAddress(value)))
        elif val_type == 'TimeTicks':
            result.append(ObjectType(ObjectIdentity(oid), TimeTicks(value)))
        elif val_type == 'Counter32':
            result.append(ObjectType(ObjectIdentity(oid), Counter32(value)))
        elif val_type == 'Gauge32':
            result.append(ObjectType(ObjectIdentity(oid), Gauge32(value)))
        else:
            result.append(ObjectType(ObjectIdentity(oid), OctetString(str(value))))
    return result


def send_trap_v2c(target_host, target_port, community, trap_oid, varbinds, source_ip=None):
    """Send SNMPv2c trap."""
    try:
        # Create varbind objects
        varbind_objects = create_varbind_objects(varbinds)

        # Build the notification
        error_indication, error_status, error_index, var_binds = next(
            sendNotification(
                SnmpEngine(),
                CommunityData(community, mpModel=1),  # v2c
                UdpTransportTarget((target_host, target_port)),
                ContextData(),
                'trap',
                NotificationType(ObjectIdentity(trap_oid)).addVarBinds(*varbind_objects)
            )
        )

        if error_indication:
            print(f"  Error: {error_indication}")
            return False
        return True

    except Exception as e:
        print(f"  Exception sending trap: {e}")
        return False


def send_trap_v1(target_host, target_port, community, trap_oid, varbinds, enterprise_oid=None):
    """Send SNMPv1 trap."""
    try:
        # Create varbind objects
        varbind_objects = create_varbind_objects(varbinds)

        # For v1, we need enterprise OID
        if enterprise_oid is None:
            enterprise_oid = '1.3.6.1.4.1.9'  # Cisco enterprise

        error_indication, error_status, error_index, var_binds = next(
            sendNotification(
                SnmpEngine(),
                CommunityData(community, mpModel=0),  # v1
                UdpTransportTarget((target_host, target_port)),
                ContextData(),
                'trap',
                NotificationType(ObjectIdentity(trap_oid)).addVarBinds(*varbind_objects)
            )
        )

        if error_indication:
            print(f"  Error: {error_indication}")
            return False
        return True

    except Exception as e:
        print(f"  Exception sending trap: {e}")
        return False


def send_trap(trap_def, target_host, target_port, community, version='v2c'):
    """Send a trap based on definition."""
    trap_oid = trap_def['oid']
    varbinds = trap_def['varbinds']

    print(f"  Sending {trap_def['name']} ({trap_def['category']}) - {version}")

    if version == 'v1':
        return send_trap_v1(target_host, target_port, community, trap_oid, varbinds)
    else:
        return send_trap_v2c(target_host, target_port, community, trap_oid, varbinds)


def main():
    parser = argparse.ArgumentParser(
        description='Cisco SNMP Trap Test Sender',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target localhost:162 --all
  %(prog)s --target localhost:162 --category link-state
  %(prog)s --target localhost:162 --trap 1.3.6.1.6.3.1.1.5.3
  %(prog)s --target localhost:162 --continuous --interval 5
  %(prog)s --list-categories
  %(prog)s --list-traps
        """
    )

    parser.add_argument('--target', type=str, default='localhost:162',
                        help='Target host:port (default: localhost:162)')
    parser.add_argument('--community', type=str, default='public',
                        help='SNMP community string (default: public)')
    parser.add_argument('--version', type=str, choices=['v1', 'v2c', 'both'], default='v2c',
                        help='SNMP version (default: v2c)')

    # Selection modes
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--all', action='store_true',
                            help='Send all defined test traps')
    mode_group.add_argument('--category', type=str,
                            help='Send traps from specific category')
    mode_group.add_argument('--trap', type=str,
                            help='Send specific trap by OID')
    mode_group.add_argument('--list-categories', action='store_true',
                            help='List available trap categories')
    mode_group.add_argument('--list-traps', action='store_true',
                            help='List all available traps')

    # Continuous mode
    parser.add_argument('--continuous', action='store_true',
                        help='Send traps continuously in a loop')
    parser.add_argument('--interval', type=float, default=0.1,
                        help='Interval between traps in continuous mode (default: 0.1s)')
    parser.add_argument('--count', type=int, default=0,
                        help='Number of traps to send (0=infinite in continuous, all in normal)')

    # Burst/load testing mode
    parser.add_argument('--burst', type=int, default=0,
                        help='Send N traps as fast as possible (burst mode)')
    parser.add_argument('--devices', type=int, default=10,
                        help='Number of simulated devices (default: 10)')
    parser.add_argument('--dynamic', action='store_true',
                        help='Generate dynamic/varied varbinds for each trap')

    args = parser.parse_args()

    # Handle list modes
    if args.list_categories:
        print("Available trap categories:")
        for cat in get_categories():
            count = len(get_traps_by_category(cat))
            print(f"  {cat}: {count} trap(s)")
        return

    if args.list_traps:
        print("Available test traps:")
        for trap in TEST_TRAPS:
            print(f"  [{trap['category']}] {trap['name']}: {trap['oid']}")
        return

    # Parse target
    if ':' in args.target:
        target_host, target_port = args.target.split(':')
        target_port = int(target_port)
    else:
        target_host = args.target
        target_port = 162

    print(f"=" * 60)
    print(f"Cisco SNMP Trap Test Sender v{VERSION}")
    print(f"=" * 60)
    print(f"Target: {target_host}:{target_port}")
    print(f"Community: {args.community}")
    print(f"Version: {args.version}")
    print(f"=" * 60)

    # Determine which traps to send
    traps_to_send = []

    if args.all:
        traps_to_send = TEST_TRAPS.copy()
        print(f"Sending all {len(traps_to_send)} test traps")

    elif args.category:
        traps_to_send = get_traps_by_category(args.category)
        if not traps_to_send:
            print(f"Error: Unknown category '{args.category}'")
            print(f"Available categories: {', '.join(get_categories())}")
            return
        print(f"Sending {len(traps_to_send)} traps from category '{args.category}'")

    elif args.trap:
        trap = get_trap_by_oid(args.trap)
        if not trap:
            print(f"Error: Unknown trap OID '{args.trap}'")
            return
        traps_to_send = [trap]
        print(f"Sending trap: {trap['name']}")

    else:
        # Default: send a few common traps
        default_traps = ['linkDown', 'linkUp', 'coldStart', 'authenticationFailure']
        traps_to_send = [t for t in TEST_TRAPS if t['name'] in default_traps]
        print(f"Sending {len(traps_to_send)} default traps")

    if not traps_to_send:
        print("No traps to send!")
        return

    print(f"Dynamic mode: {'enabled' if args.dynamic else 'disabled'}")
    print(f"Simulated devices: {args.devices}")
    print(f"=" * 60)

    # Send traps
    sent_count = 0
    error_count = 0
    start_time = time.time()

    # Burst mode - send N traps as fast as possible
    if args.burst > 0:
        print(f"Burst mode: sending {args.burst} traps as fast as possible...")
        try:
            for i in range(args.burst):
                trap = random.choice(traps_to_send)

                # Generate dynamic varbinds if requested
                if args.dynamic:
                    trap = generate_dynamic_trap(trap)

                # Determine version to use
                if args.version == 'both':
                    version = random.choice(['v1', 'v2c'])
                else:
                    version = args.version

                # Skip if trap doesn't support this version
                if trap['version'] not in ['both', version]:
                    trap = random.choice([t for t in traps_to_send if t['version'] in ['both', version]])
                    if args.dynamic:
                        trap = generate_dynamic_trap(trap)

                if send_trap(trap, target_host, target_port, args.community, version):
                    sent_count += 1
                else:
                    error_count += 1

                # Progress update every 100 traps
                if (i + 1) % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = (i + 1) / elapsed if elapsed > 0 else 0
                    print(f"  Progress: {i + 1}/{args.burst} traps sent ({rate:.1f} traps/sec)")

        except KeyboardInterrupt:
            print("\nInterrupted by user")

    elif args.continuous:
        print(f"Continuous mode: interval={args.interval}s, count={'infinite' if args.count == 0 else args.count}")
        iteration = 0
        try:
            while args.count == 0 or iteration < args.count:
                trap = random.choice(traps_to_send)

                # Generate dynamic varbinds if requested
                if args.dynamic:
                    trap = generate_dynamic_trap(trap)

                # Determine version to use
                if args.version == 'both':
                    version = random.choice(['v1', 'v2c'])
                else:
                    version = args.version

                # Skip if trap doesn't support this version
                if trap['version'] not in ['both', version]:
                    continue

                if send_trap(trap, target_host, target_port, args.community, version):
                    sent_count += 1
                else:
                    error_count += 1

                iteration += 1

                # Progress update every 100 traps
                if iteration % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = iteration / elapsed if elapsed > 0 else 0
                    print(f"  Progress: {iteration} traps sent ({rate:.1f} traps/sec)")

                time.sleep(args.interval)

        except KeyboardInterrupt:
            print("\nInterrupted by user")

    elif args.count > 0:
        # Send specified count of random traps
        print(f"Sending {args.count} random traps...")
        try:
            for i in range(args.count):
                trap = random.choice(traps_to_send)

                # Generate dynamic varbinds if requested
                if args.dynamic:
                    trap = generate_dynamic_trap(trap)

                # Determine version to use
                if args.version == 'both':
                    version = random.choice(['v1', 'v2c'])
                else:
                    version = args.version

                if trap['version'] not in ['both', version]:
                    trap = random.choice([t for t in traps_to_send if t['version'] in ['both', version]])
                    if args.dynamic:
                        trap = generate_dynamic_trap(trap)

                if send_trap(trap, target_host, target_port, args.community, version):
                    sent_count += 1
                else:
                    error_count += 1

                # Progress update every 100 traps
                if (i + 1) % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = (i + 1) / elapsed if elapsed > 0 else 0
                    print(f"  Progress: {i + 1}/{args.count} traps sent ({rate:.1f} traps/sec)")

                time.sleep(0.05)  # Small delay

        except KeyboardInterrupt:
            print("\nInterrupted by user")

    else:
        # Send each trap once (original behavior)
        for trap in traps_to_send:
            # Generate dynamic varbinds if requested
            if args.dynamic:
                trap = generate_dynamic_trap(trap)

            versions_to_send = []

            if args.version == 'both':
                if trap['version'] in ['both', 'v1']:
                    versions_to_send.append('v1')
                if trap['version'] in ['both', 'v2c']:
                    versions_to_send.append('v2c')
            else:
                if trap['version'] in ['both', args.version]:
                    versions_to_send.append(args.version)

            for ver in versions_to_send:
                if send_trap(trap, target_host, target_port, args.community, ver):
                    sent_count += 1
                else:
                    error_count += 1

            time.sleep(0.05)  # Small delay between traps

    elapsed = time.time() - start_time
    rate = sent_count / elapsed if elapsed > 0 else 0
    print(f"=" * 60)
    print(f"Summary: {sent_count} traps sent, {error_count} errors")
    print(f"Time: {elapsed:.2f}s, Rate: {rate:.1f} traps/sec")
    print(f"=" * 60)


if __name__ == "__main__":
    main()
