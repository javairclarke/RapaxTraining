#!/bin/bash
set -e

# Ensure log directory exists and is writable
mkdir -p /opt/rapax/logs
chmod 755 /opt/rapax/logs

# Log startup information
echo "Starting Rapax Unifi SNMP Integration"
echo "  REDIS_HOST: ${REDIS_HOST}"
echo "  REDIS_PORT: ${REDIS_PORT}"
echo "  SNMP_POLL_INTERVAL: ${SNMP_POLL_INTERVAL}s"
echo "  SNMP_TIMEOUT: ${SNMP_TIMEOUT}ms"
echo "  SNMP_WORKERS: ${SNMP_WORKERS}"
echo "  CONFIG_UPDATE_INTERVAL: ${CONFIG_UPDATE_INTERVAL}s"
echo "  COMPONENT_ID: ${COMPONENT_ID}"
echo "  LOG_LEVEL: ${LOG_LEVEL}"

# Execute the main command
exec "$@"
