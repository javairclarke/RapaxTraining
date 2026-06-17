#!/bin/bash
#
# Health check script for integration-juniper-trap container
#
# Checks:
# 1. Supervisor is running
# 2. juniper-trap-processord is running
# 3. Syslog file is accessible
#

# Check if supervisord is running
if ! pgrep -x "supervisord" > /dev/null; then
    echo "UNHEALTHY: supervisord is not running"
    exit 1
fi

# Check if juniper-trap-processord is running via supervisor
PROCESS_STATUS=$(supervisorctl status juniper-trap-processord 2>/dev/null | awk '{print $2}')
if [ "$PROCESS_STATUS" != "RUNNING" ]; then
    echo "UNHEALTHY: juniper-trap-processord is not running (status: $PROCESS_STATUS)"
    exit 1
fi

# Check if syslog file is readable
if [ ! -r "${SYSLOG_FILE:-/var/log/messages}" ]; then
    echo "UNHEALTHY: Cannot read syslog file: ${SYSLOG_FILE:-/var/log/messages}"
    exit 1
fi

echo "HEALTHY: All checks passed"
exit 0
