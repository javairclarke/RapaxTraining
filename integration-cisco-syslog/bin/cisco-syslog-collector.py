#!/usr/bin/env python3
"""
Cisco Syslog Data Collector
===========================

Collects raw Cisco syslog messages from /var/log/messages for debugging,
analysis, and training purposes.

Modes:
- Duration: Collect for N seconds
- Count: Collect N messages
- Tail: Continuous collection until Ctrl+C
- Existing: Dump existing Cisco syslog entries from file

Author: Rapax Integration
"""

import os
import sys
import re
import argparse
import time
import signal
from datetime import datetime

VERSION = '1.0.0'

# Pattern to identify Cisco syslog messages
CISCO_MSG_PATTERN = re.compile(r'%[A-Z0-9_]+-\d-[A-Z0-9_]+')


class SyslogCollector:
    """Collector for Cisco syslog messages."""

    def __init__(self, syslog_file, output_file=None):
        """Initialize collector.

        Args:
            syslog_file: Path to syslog file to read
            output_file: Optional file to write collected messages
        """
        self.syslog_file = syslog_file
        self.output_file = output_file
        self.running = True
        self.collected = []
        self.stats = {
            'total_lines': 0,
            'cisco_messages': 0,
            'facilities': {},
            'severities': {}
        }

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print("\nStopping collection...")
        self.running = False

    def _is_cisco_syslog(self, line):
        """Check if line contains a Cisco syslog message."""
        return bool(CISCO_MSG_PATTERN.search(line))

    def _parse_cisco_message(self, line):
        """Parse Cisco message components.

        Returns:
            dict with facility, severity, mnemonic or None
        """
        match = CISCO_MSG_PATTERN.search(line)
        if not match:
            return None

        msg_id = match.group()
        # Parse %FACILITY-SEVERITY-MNEMONIC
        parts = msg_id[1:].split('-')  # Remove % prefix
        if len(parts) >= 3:
            return {
                'facility': parts[0],
                'severity': int(parts[1]),
                'mnemonic': parts[2],
                'full_id': msg_id,
                'line': line.strip()
            }
        return None

    def _update_stats(self, parsed):
        """Update statistics with parsed message."""
        if not parsed:
            return

        facility = parsed['facility']
        severity = parsed['severity']

        self.stats['facilities'][facility] = self.stats['facilities'].get(facility, 0) + 1
        self.stats['severities'][severity] = self.stats['severities'].get(severity, 0) + 1

    def collect_existing(self, lines=1000, output_raw=False):
        """Collect existing Cisco syslog messages from file.

        Args:
            lines: Number of lines to scan from end of file
            output_raw: If True, output raw lines only
        """
        print(f"Scanning last {lines} lines of {self.syslog_file}")

        if not os.path.exists(self.syslog_file):
            print(f"Error: File not found: {self.syslog_file}")
            return

        try:
            with open(self.syslog_file, 'r') as f:
                # Read last N lines
                all_lines = f.readlines()
                scan_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines

                for line in scan_lines:
                    self.stats['total_lines'] += 1
                    if self._is_cisco_syslog(line):
                        self.stats['cisco_messages'] += 1
                        parsed = self._parse_cisco_message(line)
                        self._update_stats(parsed)

                        if output_raw:
                            print(line.strip())
                        else:
                            self.collected.append(line.strip())

        except PermissionError:
            print(f"Error: Permission denied reading {self.syslog_file}")
            return
        except Exception as e:
            print(f"Error: {e}")
            return

        if not output_raw:
            self._print_summary()

    def collect_duration(self, seconds):
        """Collect messages for specified duration.

        Args:
            seconds: Duration in seconds
        """
        print(f"Collecting for {seconds} seconds from {self.syslog_file}")
        print("Press Ctrl+C to stop early\n")

        if not os.path.exists(self.syslog_file):
            print(f"Error: File not found: {self.syslog_file}")
            return

        start_time = time.time()
        end_time = start_time + seconds

        try:
            with open(self.syslog_file, 'r') as f:
                # Seek to end
                f.seek(0, 2)

                while self.running and time.time() < end_time:
                    line = f.readline()
                    if line:
                        self.stats['total_lines'] += 1
                        if self._is_cisco_syslog(line):
                            self.stats['cisco_messages'] += 1
                            parsed = self._parse_cisco_message(line)
                            self._update_stats(parsed)
                            self.collected.append(line.strip())
                            print(f"[{self.stats['cisco_messages']}] {line.strip()[:100]}")
                    else:
                        time.sleep(0.1)

                    # Progress indicator
                    elapsed = time.time() - start_time
                    remaining = seconds - elapsed
                    if int(elapsed) % 10 == 0 and int(elapsed) > 0:
                        sys.stdout.write(f"\r{int(remaining)}s remaining, {self.stats['cisco_messages']} messages collected")
                        sys.stdout.flush()

        except Exception as e:
            print(f"Error: {e}")
            return

        print("\n")
        self._print_summary()

    def collect_count(self, count):
        """Collect specified number of messages.

        Args:
            count: Number of messages to collect
        """
        print(f"Collecting {count} Cisco syslog messages from {self.syslog_file}")
        print("Press Ctrl+C to stop early\n")

        if not os.path.exists(self.syslog_file):
            print(f"Error: File not found: {self.syslog_file}")
            return

        try:
            with open(self.syslog_file, 'r') as f:
                # Seek to end
                f.seek(0, 2)

                while self.running and self.stats['cisco_messages'] < count:
                    line = f.readline()
                    if line:
                        self.stats['total_lines'] += 1
                        if self._is_cisco_syslog(line):
                            self.stats['cisco_messages'] += 1
                            parsed = self._parse_cisco_message(line)
                            self._update_stats(parsed)
                            self.collected.append(line.strip())
                            print(f"[{self.stats['cisco_messages']}/{count}] {line.strip()[:100]}")
                    else:
                        time.sleep(0.1)

        except Exception as e:
            print(f"Error: {e}")
            return

        print("\n")
        self._print_summary()

    def collect_tail(self):
        """Continuously collect messages until stopped."""
        print(f"Tailing {self.syslog_file} for Cisco syslog messages")
        print("Press Ctrl+C to stop\n")

        if not os.path.exists(self.syslog_file):
            print(f"Error: File not found: {self.syslog_file}")
            return

        try:
            with open(self.syslog_file, 'r') as f:
                # Seek to end
                f.seek(0, 2)

                while self.running:
                    line = f.readline()
                    if line:
                        self.stats['total_lines'] += 1
                        if self._is_cisco_syslog(line):
                            self.stats['cisco_messages'] += 1
                            parsed = self._parse_cisco_message(line)
                            self._update_stats(parsed)
                            self.collected.append(line.strip())

                            # Format output
                            timestamp = datetime.now().strftime('%H:%M:%S')
                            print(f"[{timestamp}] {line.strip()}")
                    else:
                        time.sleep(0.1)

        except Exception as e:
            print(f"Error: {e}")
            return

        print("\n")
        self._print_summary()

    def _print_summary(self):
        """Print collection summary."""
        print("=" * 60)
        print("Collection Summary")
        print("=" * 60)
        print(f"Total lines scanned: {self.stats['total_lines']}")
        print(f"Cisco syslog messages: {self.stats['cisco_messages']}")
        print()

        if self.stats['facilities']:
            print("Facilities:")
            for facility, count in sorted(self.stats['facilities'].items(),
                                         key=lambda x: x[1], reverse=True)[:20]:
                print(f"  {facility}: {count}")

        print()

        if self.stats['severities']:
            severity_names = {
                0: 'Emergency', 1: 'Alert', 2: 'Critical', 3: 'Error',
                4: 'Warning', 5: 'Notice', 6: 'Info', 7: 'Debug'
            }
            print("Severities:")
            for sev, count in sorted(self.stats['severities'].items()):
                name = severity_names.get(sev, f'Level {sev}')
                print(f"  {sev} ({name}): {count}")

        print()

        # Write to output file if specified
        if self.output_file and self.collected:
            try:
                with open(self.output_file, 'w') as f:
                    f.write(f"# Cisco Syslog Collection\n")
                    f.write(f"# Collected: {datetime.now().isoformat()}\n")
                    f.write(f"# Source: {self.syslog_file}\n")
                    f.write(f"# Messages: {len(self.collected)}\n")
                    f.write("#" + "=" * 59 + "\n\n")
                    for line in self.collected:
                        f.write(line + "\n")
                print(f"Saved {len(self.collected)} messages to {self.output_file}")
            except Exception as e:
                print(f"Error writing output file: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Cisco Syslog Data Collector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Collect for 60 seconds
    %(prog)s --duration 60

    # Collect 100 messages
    %(prog)s --count 100

    # Tail mode (continuous)
    %(prog)s --tail

    # Scan existing messages
    %(prog)s --existing --lines 5000

    # Save to file
    %(prog)s --duration 60 --output collected.txt
        """
    )

    parser.add_argument('--syslog-file', type=str, default='/var/log/messages',
                        help='Path to syslog file (default: /var/log/messages)')
    parser.add_argument('--output', '-o', type=str,
                        help='Output file for collected messages')

    # Collection modes (mutually exclusive)
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--duration', type=int,
                           help='Collect for N seconds')
    mode_group.add_argument('--count', type=int,
                           help='Collect N messages')
    mode_group.add_argument('--tail', action='store_true',
                           help='Tail mode - collect until Ctrl+C')
    mode_group.add_argument('--existing', action='store_true',
                           help='Collect existing messages from file')

    parser.add_argument('--lines', type=int, default=1000,
                        help='Lines to scan for --existing mode (default: 1000)')
    parser.add_argument('--raw', action='store_true',
                        help='Output raw lines only (for --existing)')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')

    args = parser.parse_args()

    print(f"Cisco Syslog Collector v{VERSION}")
    print()

    collector = SyslogCollector(args.syslog_file, args.output)

    if args.duration:
        collector.collect_duration(args.duration)
    elif args.count:
        collector.collect_count(args.count)
    elif args.tail:
        collector.collect_tail()
    elif args.existing:
        collector.collect_existing(args.lines, args.raw)

    return 0


if __name__ == "__main__":
    sys.exit(main())
