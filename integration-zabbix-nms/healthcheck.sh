#!/bin/bash
#
# Healthcheck script for Zabbix NMS data processor
#
# Checks:
# 1. Process is running
# 2. Log file is being updated (activity within last 5 minutes)

LOG_FILE="/opt/rapax/logs/zabbix-data-processord.log"
MAX_AGE_SECONDS=300  # 5 minutes

# Check if process is running
if ! pgrep -f "zabbix-data-processord.py" > /dev/null; then
    echo "UNHEALTHY: Process not running"
    exit 1
fi

# Check if log file exists and is recent
if [ -f "$LOG_FILE" ]; then
    # Get file modification time
    FILE_AGE=$(($(date +%s) - $(stat -c %Y "$LOG_FILE" 2>/dev/null || echo 0)))

    if [ "$FILE_AGE" -gt "$MAX_AGE_SECONDS" ]; then
        echo "UNHEALTHY: Log file not updated in $FILE_AGE seconds"
        exit 1
    fi
fi

echo "HEALTHY: Process running, last activity ${FILE_AGE}s ago"
exit 0
