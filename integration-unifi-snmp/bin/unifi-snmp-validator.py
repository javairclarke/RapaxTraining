#!/usr/bin/env python3
"""
Unifi SNMP Validator
====================

Validates SNMP connectivity and OID availability for Unifi devices.
Use this script to test if a Unifi device supports the OIDs polled by
the unifi-device-snmp-pollerd daemon.

Usage:
    python3 unifi-snmp-validator.py --target 192.168.1.10 --community public
    python3 unifi-snmp-validator.py --target 192.168.1.10 --community public --verbose
    python3 unifi-snmp-validator.py --target 192.168.1.10 --community public --timeout 2000

Author: Rapax Integration
"""

import argparse
import sys

try:
    from pysnmp.hlapi import *
except ImportError:
    print("Error: pysnmp not installed. Run: pip install pysnmp==4.4.12")
    sys.exit(1)


# OID definitions (same as poller)
SYSTEM_OIDS = {
    'sysDescr': ('1.3.6.1.2.1.1.1.0', 'System Description'),
    'sysObjectID': ('1.3.6.1.2.1.1.2.0', 'System Object ID'),
    'sysName': ('1.3.6.1.2.1.1.5.0', 'System Name'),
    'sysUpTime': ('1.3.6.1.2.1.1.3.0', 'System Uptime'),
}

FROGFOOT_OIDS = {
    'memTotal': ('1.3.6.1.4.1.10002.1.1.1.1.1.0', 'Memory Total (KB)'),
    'memFree': ('1.3.6.1.4.1.10002.1.1.1.1.2.0', 'Memory Free (KB)'),
    'memBuffer': ('1.3.6.1.4.1.10002.1.1.1.1.3.0', 'Memory Buffer (KB)'),
    'memCache': ('1.3.6.1.4.1.10002.1.1.1.1.4.0', 'Memory Cache (KB)'),
    'loadAvg1': ('1.3.6.1.4.1.10002.1.1.1.4.2.1.3.1', 'Load Average (1min)'),
    'loadAvg5': ('1.3.6.1.4.1.10002.1.1.1.4.2.1.3.2', 'Load Average (5min)'),
    'loadAvg15': ('1.3.6.1.4.1.10002.1.1.1.4.2.1.3.3', 'Load Average (15min)'),
}

TEMPERATURE_OIDS = {
    'cpuTemp': ('1.3.6.1.4.1.4413.1.1.43.1.8.1.5.1.0', 'CPU Temperature (C)'),
    'boardTemp': ('1.3.6.1.4.1.4413.1.1.43.1.15.1.2', 'Board Temperature (C)'),
    'phyTemp': ('1.3.6.1.4.1.4413.1.1.43.1.15.1.3', 'PHY Temperature (C)'),
    'hostTemp': ('1.3.6.1.4.1.41112.1.4.8.4', 'Host Temperature (C)'),
}

FAN_OIDS = {
    'fanSpeed': ('1.3.6.1.4.1.4413.1.1.43.1.6.1.4', 'Fan Speed (RPM)'),
    'fanDutyLevel': ('1.3.6.1.4.1.4413.1.1.43.1.6.1.5', 'Fan Duty Level (%)'),
}


class Colors:
    """ANSI color codes for terminal output."""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


def snmp_get(host, port, community, oid, timeout_ms):
    """Perform SNMP GET operation."""
    try:
        timeout_s = timeout_ms / 1000.0
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                   CommunityData(community),
                   UdpTransportTarget((host, port), timeout=timeout_s, retries=1),
                   ContextData(),
                   ObjectType(ObjectIdentity(oid)))
        )

        if errorIndication:
            return None, str(errorIndication)
        elif errorStatus:
            return None, str(errorStatus.prettyPrint())
        else:
            for oid_result, val in varBinds:
                val_str = str(val)
                if 'noSuch' in val_str:
                    return None, 'Not available'
                return val, None
    except Exception as e:
        return None, str(e)


def print_section(title):
    """Print a section header."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}=== {title} ==={Colors.END}")


def print_result(name, description, value, error, verbose=False):
    """Print a test result."""
    if value is not None:
        print(f"  {Colors.GREEN}[OK]{Colors.END} {description}: {value}")
        return True
    else:
        if verbose:
            print(f"  {Colors.RED}[--]{Colors.END} {description}: {error}")
        else:
            print(f"  {Colors.RED}[--]{Colors.END} {description}: Not available")
        return False


def is_unifi_device(sys_descr, sys_oid):
    """Check if device appears to be a Unifi device."""
    # Unifi product prefixes
    UNIFI_PREFIXES = ['usw-', 'usw ', 'udm-', 'udm ', 'uap-', 'uap ', 'ucg-', 'ucg ',
                      'us-', 'unifi switch', 'unifi ap', 'unifi dream']

    if sys_descr:
        sys_descr_lower = str(sys_descr).lower()
        # Check for ubiquiti/unifi keywords
        if 'ubiquiti' in sys_descr_lower or 'unifi' in sys_descr_lower:
            return True
        # Check for product prefixes (USW-Pro-24, UDM-Pro, etc.)
        for prefix in UNIFI_PREFIXES:
            if prefix in sys_descr_lower:
                return True

    if sys_oid:
        sys_oid_str = str(sys_oid)
        # Ubiquiti enterprise OID
        if sys_oid_str.startswith('1.3.6.1.4.1.41112'):
            return True
        # EdgeSwitch OID (used by USW switches)
        if sys_oid_str.startswith('1.3.6.1.4.1.4413'):
            return True

    return False


def main():
    parser = argparse.ArgumentParser(
        description='Validate SNMP connectivity and OID availability for Unifi devices',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target 192.168.1.10 --community public
  %(prog)s --target switch.local --community mySecretCommunity --verbose
  %(prog)s --target 10.0.0.1 --community public --port 161 --timeout 2000
        """
    )
    parser.add_argument('--target', '-t', required=True,
                        help='Target device IP or hostname')
    parser.add_argument('--community', '-c', default='public',
                        help='SNMP community string (default: public)')
    parser.add_argument('--port', '-p', type=int, default=161,
                        help='SNMP port (default: 161)')
    parser.add_argument('--timeout', type=int, default=1000,
                        help='SNMP timeout in milliseconds (default: 1000)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show detailed error messages')

    args = parser.parse_args()

    print(f"\n{Colors.BOLD}Unifi SNMP Validator{Colors.END}")
    print(f"Testing connectivity to {args.target}:{args.port} with community '{args.community}'")
    print(f"Timeout: {args.timeout}ms")

    results = {
        'system': {'total': 0, 'success': 0},
        'frogfoot': {'total': 0, 'success': 0},
        'temperature': {'total': 0, 'success': 0},
        'fan': {'total': 0, 'success': 0},
    }

    # Test system OIDs first
    print_section("System Information")
    sys_descr = None
    sys_oid = None

    for name, (oid, description) in SYSTEM_OIDS.items():
        results['system']['total'] += 1
        value, error = snmp_get(args.target, args.port, args.community, oid, args.timeout)
        if print_result(name, description, value, error, args.verbose):
            results['system']['success'] += 1
            if name == 'sysDescr':
                sys_descr = value
            elif name == 'sysObjectID':
                sys_oid = value

    # Check if this is a Unifi device
    if results['system']['success'] == 0:
        print(f"\n{Colors.RED}ERROR: Cannot connect to device. Check IP, community string, and firewall rules.{Colors.END}")
        sys.exit(1)

    if is_unifi_device(sys_descr, sys_oid):
        print(f"\n{Colors.GREEN}Device identified as Ubiquiti/Unifi{Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}WARNING: Device may not be a Unifi device{Colors.END}")

    # Test FROGFOOT-RESOURCES-MIB OIDs
    print_section("FROGFOOT-RESOURCES-MIB (Memory & Load)")
    for name, (oid, description) in FROGFOOT_OIDS.items():
        results['frogfoot']['total'] += 1
        value, error = snmp_get(args.target, args.port, args.community, oid, args.timeout)
        if print_result(name, description, value, error, args.verbose):
            results['frogfoot']['success'] += 1

    # Calculate memory usage if all memory OIDs available
    if results['frogfoot']['success'] >= 4:
        try:
            mem_total, _ = snmp_get(args.target, args.port, args.community, FROGFOOT_OIDS['memTotal'][0], args.timeout)
            mem_free, _ = snmp_get(args.target, args.port, args.community, FROGFOOT_OIDS['memFree'][0], args.timeout)
            mem_buffer, _ = snmp_get(args.target, args.port, args.community, FROGFOOT_OIDS['memBuffer'][0], args.timeout)
            mem_cache, _ = snmp_get(args.target, args.port, args.community, FROGFOOT_OIDS['memCache'][0], args.timeout)

            if all([mem_total, mem_free, mem_buffer, mem_cache]):
                total = int(mem_total)
                free = int(mem_free)
                buffer = int(mem_buffer)
                cache = int(mem_cache)
                used = total - free - buffer - cache
                usage_pct = (used / total) * 100.0
                print(f"  {Colors.BLUE}[**]{Colors.END} Calculated Memory Usage: {usage_pct:.1f}%")
        except Exception:
            pass

    # Test Temperature OIDs
    print_section("Temperature Sensors (optional)")
    for name, (oid, description) in TEMPERATURE_OIDS.items():
        results['temperature']['total'] += 1
        value, error = snmp_get(args.target, args.port, args.community, oid, args.timeout)
        if print_result(name, description, value, error, args.verbose):
            results['temperature']['success'] += 1

    # Test Fan OIDs
    print_section("Fan Status (optional)")
    for name, (oid, description) in FAN_OIDS.items():
        results['fan']['total'] += 1
        value, error = snmp_get(args.target, args.port, args.community, oid, args.timeout)
        if print_result(name, description, value, error, args.verbose):
            results['fan']['success'] += 1

    # Print summary
    print_section("Summary")
    total_oids = sum(r['total'] for r in results.values())
    total_success = sum(r['success'] for r in results.values())

    print(f"  System OIDs:      {results['system']['success']}/{results['system']['total']}")
    print(f"  FROGFOOT OIDs:    {results['frogfoot']['success']}/{results['frogfoot']['total']}")
    print(f"  Temperature OIDs: {results['temperature']['success']}/{results['temperature']['total']}")
    print(f"  Fan OIDs:         {results['fan']['success']}/{results['fan']['total']}")
    print(f"  {Colors.BOLD}Total:            {total_success}/{total_oids}{Colors.END}")

    # Determine overall status
    if results['system']['success'] == 0:
        print(f"\n{Colors.RED}FAILED: No SNMP connectivity{Colors.END}")
        return 1
    elif results['frogfoot']['success'] == 0:
        print(f"\n{Colors.YELLOW}WARNING: FROGFOOT-MIB not available - limited metrics{Colors.END}")
        if results['temperature']['success'] > 0 or results['fan']['success'] > 0:
            print(f"{Colors.GREEN}Temperature/Fan metrics available{Colors.END}")
            return 0
        return 1
    else:
        print(f"\n{Colors.GREEN}SUCCESS: Device is ready for Unifi SNMP polling{Colors.END}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
