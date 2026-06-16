#!/bin/bash
#
# Health check script for integration-slack-notification-exporter container
#
# Checks:
# 1. Supervisor is running
# 2. slack-notification-exporter-processord is running
#

# Check if supervisord is running
if ! pgrep -x "supervisord" > /dev/null; then
    echo "UNHEALTHY: supervisord is not running"
    exit 1
fi

# Check if slack-notification-exporter-processord is running via supervisor
PROCESS_STATUS=$(supervisorctl status slack-notification-exporter-processord 2>/dev/null | awk '{print $2}')
if [ "$PROCESS_STATUS" != "RUNNING" ]; then
    echo "UNHEALTHY: slack-notification-exporter-processord is not running (status: $PROCESS_STATUS)"
    exit 1
fi

echo "HEALTHY: All checks passed"
exit 0
