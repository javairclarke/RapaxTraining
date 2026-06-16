#!/bin/bash
# Docker entrypoint for Cisco Syslog Processor

set -e

echo "================================================"
echo "Cisco Syslog Processor - Starting"
echo "================================================"
echo "RAPAXHOME: ${RAPAXHOME:-/opt/rapax}"
echo "REDIS_HOST: ${REDIS_HOST:-rapax-redis}"
echo "REDIS_PORT: ${REDIS_PORT:-6379}"
echo "SYSLOG_FILE: ${SYSLOG_FILE:-/var/log/messages}"
echo "COMPONENT_ID: ${COMPONENT_ID:-cisco-syslog-1}"
echo "LOG_LEVEL: ${LOG_LEVEL:-INFO}"
echo "================================================"

# Create log directory if it doesn't exist
mkdir -p /opt/rapax/logs

# Check if syslog file exists
if [ ! -f "${SYSLOG_FILE:-/var/log/messages}" ]; then
    echo "WARNING: Syslog file ${SYSLOG_FILE:-/var/log/messages} not found"
    echo "The processor will wait for the file to appear..."
fi

# Check if rapax.py library is available
if [ ! -f "/opt/rapax/lib/rapax.py" ]; then
    echo "WARNING: /opt/rapax/lib/rapax.py not found"
    echo "Make sure the rapax lib volume is mounted correctly"
fi

# Execute the command
exec "$@"
