#!/bin/bash
#
# Healthcheck script for Zabbix webhook processor
#
# Checks:
# 1. Process is running
# 2. HTTP health endpoint responds

WEBHOOK_PORT="${WEBHOOK_PORT:-6543}"

# Check if process is running
if ! pgrep -f "zabbix-webhook-processord.py" > /dev/null; then
    echo "UNHEALTHY: Process not running"
    exit 1
fi

# Check HTTP health endpoint
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${WEBHOOK_PORT}/health" 2>/dev/null || echo "000")

if [ "$HTTP_CODE" != "200" ]; then
    echo "UNHEALTHY: Health endpoint returned $HTTP_CODE"
    exit 1
fi

echo "HEALTHY: Process running, HTTP responding"
exit 0
