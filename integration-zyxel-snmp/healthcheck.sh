#!/bin/bash
#
# Health check script for integration-zyxel-snmp container
#
# Checks:
# 1. Supervisor is running
# 2. zyxel-snmp-pollerd is running
#

# Check if supervisord is running
if ! pgrep -x "supervisord" > /dev/null; then
    echo "UNHEALTHY: supervisord is not running"
    exit 1
fi

# Check if zyxel-snmp-pollerd is running via supervisor
PROCESS_STATUS=$(supervisorctl status zyxel-snmp-pollerd 2>/dev/null | awk '{print $2}')
if [ "$PROCESS_STATUS" != "RUNNING" ]; then
    echo "UNHEALTHY: zyxel-snmp-pollerd is not running (status: $PROCESS_STATUS)"
    exit 1
fi

echo "HEALTHY: All checks passed"
exit 0
