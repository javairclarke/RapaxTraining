#!/usr/bin/env python3
"""
Cisco SNMP Trap Data Collector
==============================

Captures raw SNMP trap data from /var/log/messages into a sample file.
Used for debugging, analysis, and helping Bruce understand actual trap formats.

Usage:
    cisco-trap-collector.py --output /path/to/sample.txt --duration 60
    cisco-trap-collector.py --output /path/to/sample.txt --count 100
    cisco-trap-collector.py --output /path/to/sample.txt --tail

Author: Rapax Integration
"""

import os
import sys
import argparse
import time
import signal
from datetime import datetime

VERSION = '1.0.0'


class TrapCollector:
    """Collector class for capturing SNMP trap data from syslog."""

    def __init__(self, syslog_file, output_file, mode='duration', value=60):
        """
        Initialize the collector.

        Args:
            syslog_file: Path to syslog file (e.g., /var/log/messages)
            output_file: Path to output sample file
            mode: Collection mode ('duration', 'count', or 'tail')
            value: Duration in seconds or count of entries
        """
        self.syslog_file = syslog_file
        self.output_file = output_file
        self.mode = mode
        self.value = value
        self.running = True
        self.collected_count = 0
        self.start_time = None

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print(f"\nReceived signal {signum}, stopping collection...")
        self.running = False

    def _is_snmptrap_line(self, line):
        """Check if a line contains snmptrap data."""
        return 'snmptrap' in line.lower()

    def _should_stop(self):
        """Determine if collection should stop based on mode."""
        if not self.running:
            return True

        if self.mode == 'duration':
            elapsed = time.time() - self.start_time
            return elapsed >= self.value

        elif self.mode == 'count':
            return self.collected_count >= self.value

        # 'tail' mode runs until interrupted
        return False

    def collect(self):
        """Main collection loop."""
        print(f"=" * 60)
        print(f"Cisco SNMP Trap Data Collector v{VERSION}")
        print(f"=" * 60)
        print(f"Syslog file: {self.syslog_file}")
        print(f"Output file: {self.output_file}")
        print(f"Mode: {self.mode}")
        if self.mode != 'tail':
            print(f"Value: {self.value}")
        print(f"=" * 60)

        # Check if syslog file exists
        if not os.path.exists(self.syslog_file):
            print(f"Error: Syslog file not found: {self.syslog_file}")
            return False

        # Create output directory if needed
        output_dir = os.path.dirname(self.output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        self.start_time = time.time()

        try:
            with open(self.syslog_file, 'r') as syslog, \
                 open(self.output_file, 'w') as output:

                # Write header
                output.write(f"# Cisco SNMP Trap Data Collection\n")
                output.write(f"# Collected: {datetime.now().isoformat()}\n")
                output.write(f"# Source: {self.syslog_file}\n")
                output.write(f"# Mode: {self.mode}\n")
                output.write(f"#\n")
                output.write(f"# Format: Raw syslog lines containing 'snmptrap'\n")
                output.write(f"# " + "=" * 58 + "\n\n")

                # Seek to end of file (tail -f behavior)
                syslog.seek(0, 2)
                print(f"Tailing {self.syslog_file} for snmptrap entries...")
                print(f"Press Ctrl+C to stop\n")

                while not self._should_stop():
                    line = syslog.readline()

                    if line:
                        if self._is_snmptrap_line(line):
                            # Write to output file
                            output.write(line)
                            output.flush()

                            self.collected_count += 1

                            # Print progress
                            print(f"[{self.collected_count}] {line.strip()[:80]}...")

                            # Check count limit
                            if self.mode == 'count' and self.collected_count >= self.value:
                                break
                    else:
                        # No new data, sleep briefly
                        time.sleep(0.1)

                    # Check duration limit
                    if self.mode == 'duration':
                        elapsed = time.time() - self.start_time
                        if elapsed >= self.value:
                            break

                # Write footer
                output.write(f"\n# " + "=" * 58 + "\n")
                output.write(f"# Collection completed: {datetime.now().isoformat()}\n")
                output.write(f"# Total entries collected: {self.collected_count}\n")
                output.write(f"# Duration: {time.time() - self.start_time:.2f} seconds\n")

        except PermissionError:
            print(f"Error: Permission denied reading {self.syslog_file}")
            return False
        except Exception as e:
            print(f"Error: {e}")
            return False

        print(f"\n" + "=" * 60)
        print(f"Collection complete!")
        print(f"Entries collected: {self.collected_count}")
        print(f"Duration: {time.time() - self.start_time:.2f} seconds")
        print(f"Output file: {self.output_file}")
        print(f"=" * 60)

        return True

    def collect_existing(self, lines=1000):
        """
        Collect existing snmptrap entries from the syslog file.
        Useful for grabbing historical data.

        Args:
            lines: Number of lines to scan from end of file
        """
        print(f"=" * 60)
        print(f"Cisco SNMP Trap Data Collector v{VERSION}")
        print(f"=" * 60)
        print(f"Mode: Collecting existing entries")
        print(f"Scanning last {lines} lines of {self.syslog_file}")
        print(f"=" * 60)

        if not os.path.exists(self.syslog_file):
            print(f"Error: Syslog file not found: {self.syslog_file}")
            return False

        # Create output directory if needed
        output_dir = os.path.dirname(self.output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        try:
            # Read last N lines from syslog
            with open(self.syslog_file, 'r') as f:
                # Simple tail implementation
                all_lines = f.readlines()
                recent_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines

            # Filter for snmptrap entries
            trap_lines = [l for l in recent_lines if self._is_snmptrap_line(l)]

            # Write to output
            with open(self.output_file, 'w') as output:
                output.write(f"# Cisco SNMP Trap Data Collection (Historical)\n")
                output.write(f"# Collected: {datetime.now().isoformat()}\n")
                output.write(f"# Source: {self.syslog_file}\n")
                output.write(f"# Scanned lines: {len(recent_lines)}\n")
                output.write(f"#\n")
                output.write(f"# " + "=" * 58 + "\n\n")

                for line in trap_lines:
                    output.write(line)
                    self.collected_count += 1

                output.write(f"\n# " + "=" * 58 + "\n")
                output.write(f"# Total entries collected: {self.collected_count}\n")

            print(f"\nCollection complete!")
            print(f"Scanned: {len(recent_lines)} lines")
            print(f"Found: {self.collected_count} snmptrap entries")
            print(f"Output: {self.output_file}")

        except Exception as e:
            print(f"Error: {e}")
            return False

        return True


def main():
    parser = argparse.ArgumentParser(
        description='Cisco SNMP Trap Data Collector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect traps for 60 seconds
  %(prog)s --output /tmp/traps.txt --duration 60

  # Collect exactly 100 trap entries
  %(prog)s --output /tmp/traps.txt --count 100

  # Tail mode - collect until Ctrl+C
  %(prog)s --output /tmp/traps.txt --tail

  # Collect existing/historical trap entries
  %(prog)s --output /tmp/traps.txt --existing --lines 5000

  # Use a different syslog file
  %(prog)s --syslog /var/log/syslog --output /tmp/traps.txt --duration 30
        """
    )

    parser.add_argument('--syslog', type=str, default='/var/log/messages',
                        help='Path to syslog file (default: /var/log/messages)')
    parser.add_argument('--output', '-o', type=str, required=True,
                        help='Output file path for collected data')

    # Collection mode group
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--duration', '-d', type=int,
                            help='Collect for specified duration in seconds')
    mode_group.add_argument('--count', '-c', type=int,
                            help='Collect specified number of trap entries')
    mode_group.add_argument('--tail', '-t', action='store_true',
                            help='Tail mode - collect until interrupted')
    mode_group.add_argument('--existing', '-e', action='store_true',
                            help='Collect existing/historical entries')

    # Options for existing mode
    parser.add_argument('--lines', '-l', type=int, default=1000,
                        help='Number of lines to scan in existing mode (default: 1000)')

    args = parser.parse_args()

    # Determine mode and value
    if args.duration:
        mode = 'duration'
        value = args.duration
    elif args.count:
        mode = 'count'
        value = args.count
    elif args.tail:
        mode = 'tail'
        value = 0
    elif args.existing:
        mode = 'existing'
        value = args.lines
    else:
        print("Error: Must specify --duration, --count, --tail, or --existing")
        return 1

    collector = TrapCollector(args.syslog, args.output, mode, value)

    if mode == 'existing':
        success = collector.collect_existing(args.lines)
    else:
        success = collector.collect()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
