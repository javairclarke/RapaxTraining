#!/bin/bash
# Health check for Cisco Syslog Processor

# Check if supervisor is running
if ! pgrep -x supervisord > /dev/null; then
    echo "supervisord not running"
    exit 1
fi

# Check if processor process is running
if ! supervisorctl status cisco-syslog-processord | grep -q "RUNNING"; then
    echo "cisco-syslog-processord not running"
    exit 1
fi

# Check if log file was written to recently (within last 5 minutes)
LOG_FILE="/opt/rapax/logs/cisco-syslog-processord.log"
if [ -f "$LOG_FILE" ]; then
    # Get file age in seconds
    FILE_AGE=$(( $(date +%s) - $(stat -c %Y "$LOG_FILE") ))
    if [ $FILE_AGE -gt 300 ]; then
        echo "Log file not updated in last 5 minutes"
        # Don't fail on this - just warn
    fi
fi

echo "healthy"
exit 0
