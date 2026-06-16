#!/bin/bash
# Health check script for MariaDB Exporter

# Check if the process is running
if ! pgrep -f "rapax-mariadb-data-exporterd" > /dev/null; then
    echo "Exporter process not running"
    exit 1
fi

# Check if supervisor reports healthy (socket is at /tmp/supervisor.sock)
if ! supervisorctl -c /etc/supervisor/conf.d/supervisord.conf status mariadb-exporter 2>/dev/null | grep -q "RUNNING"; then
    echo "Supervisor reports unhealthy"
    exit 1
fi

# Check if log file was recently updated (within last 5 minutes)
LOG_FILE="/opt/rapax/logs/mariadb-exporter.log"
if [ -f "$LOG_FILE" ]; then
    FILE_AGE=$(($(date +%s) - $(stat -c %Y "$LOG_FILE" 2>/dev/null || echo 0)))
    if [ $FILE_AGE -gt 300 ]; then
        echo "Log file not updated in 5 minutes"
        exit 1
    fi
fi

echo "Healthy"
exit 0
