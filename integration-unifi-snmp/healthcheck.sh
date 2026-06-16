#!/bin/bash

# Health check script for Unifi SNMP Integration
# Checks if the poller process is running

# Check if supervisord is running
if ! pgrep -x "supervisord" > /dev/null; then
    echo "supervisord is not running"
    exit 1
fi

# Check if the poller process is running
if ! pgrep -f "unifi-device-snmp-pollerd" > /dev/null; then
    echo "unifi-device-snmp-pollerd is not running"
    exit 1
fi

# Check if log file has been updated recently (within last 5 minutes)
LOG_FILE="/opt/rapax/logs/unifi-device-snmp-pollerd.log"
if [ -f "$LOG_FILE" ]; then
    # Get file modification time
    FILE_MOD_TIME=$(stat -c %Y "$LOG_FILE" 2>/dev/null || stat -f %m "$LOG_FILE" 2>/dev/null)
    CURRENT_TIME=$(date +%s)
    TIME_DIFF=$((CURRENT_TIME - FILE_MOD_TIME))

    # If log hasn't been updated in 5 minutes, something might be wrong
    if [ $TIME_DIFF -gt 300 ]; then
        echo "Log file not updated in last 5 minutes"
        # Don't fail, just warn - the poller might not have devices to poll
    fi
fi

echo "healthy"
exit 0
