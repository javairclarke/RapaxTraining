#!/bin/bash
set -e

echo "================================================"
echo "Rapax Custom Integration Container Starting"
echo "================================================"

# Create logs directory if it doesn't exist
mkdir -p /opt/rapax/logs

# Display configuration
echo "Configuration:"
echo "  REDIS_HOST: ${REDIS_HOST}"
echo "  REDIS_PORT: ${REDIS_PORT}"
echo "  COMPONENT_ID: ${COMPONENT_ID}"
echo "  LOG_LEVEL: ${LOG_LEVEL}"
echo "================================================"

# Check if rapax library is available
if [ ! -f "/opt/rapax/lib/rapax.py" ]; then
    echo "WARNING: rapax.py library not found in /opt/rapax/lib/"
    echo "  Make sure the rapax lib directory is mounted"
fi

# Check if credentials file exists
if [ -f "/opt/rapax/etc/credentials" ]; then
    echo "Credentials file found - using encrypted credentials"
else
    echo "No credentials file - using environment variables"
fi

echo "================================================"
echo "Starting supervisord..."
echo "================================================"

# Execute the main command (supervisord)
exec "$@"
