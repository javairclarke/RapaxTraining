#!/bin/bash
set -e

# Rapax MariaDB Data Exporter - Docker Entrypoint

echo "================================================"
echo "  Rapax MariaDB Data Exporter"
echo "================================================"
echo ""

# Environment info
echo "Environment:"
echo "  RAPAXHOME:    ${RAPAXHOME:-/opt/rapax}"
echo "  LOG_LEVEL:    ${LOG_LEVEL:-INFO}"
echo "  REDIS_HOST:   ${REDIS_HOST:-rapax-redis}"
echo "  MARIADB_HOST: ${MARIADB_HOST:-rapax-mariadb}"
echo ""

# Create directories if they don't exist
mkdir -p /opt/rapax/logs
mkdir -p /opt/rapax/etc/mariadb-exporter

# Copy default configs if not present (volume mounts may override)
if [ ! -f /opt/rapax/etc/mariadb-exporter/rotate.cfg ]; then
    cp /opt/rapax/etc/mariadb-exporter/rotate.cfg.default /opt/rapax/etc/mariadb-exporter/rotate.cfg 2>/dev/null || true
fi
if [ ! -f /opt/rapax/etc/mariadb-exporter/batch.cfg ]; then
    cp /opt/rapax/etc/mariadb-exporter/batch.cfg.default /opt/rapax/etc/mariadb-exporter/batch.cfg 2>/dev/null || true
fi

# Wait for Redis
echo "Waiting for Redis..."
MAX_WAIT=60
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if python3 -c "
import os
import redis
r = redis.Redis(
    host=os.environ.get('REDIS_HOST', 'rapax-redis'),
    port=int(os.environ.get('REDIS_PORT', 6379)),
    password=os.environ.get('REDIS_PASSWORD') or None
)
r.ping()
" 2>/dev/null; then
        echo "Redis is ready"
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
    echo -n "."
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo ""
    echo "WARNING: Redis not available after ${MAX_WAIT}s, continuing anyway..."
fi

# Wait for MariaDB
echo "Waiting for MariaDB..."
MAX_WAIT=120
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if python3 -c "
import os
import mysql.connector
conn = mysql.connector.connect(
    host=os.environ.get('MARIADB_HOST', 'rapax-mariadb'),
    port=int(os.environ.get('MARIADB_PORT', 3306)),
    user=os.environ.get('MARIADB_USER', 'rapax'),
    password=os.environ.get('MARIADB_PASSWORD', '')
)
conn.close()
" 2>/dev/null; then
        echo "MariaDB is ready"
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
    echo -n "."
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo ""
    echo "WARNING: MariaDB not available after ${MAX_WAIT}s, continuing anyway..."
fi

echo ""
echo "Starting supervisor..."
echo ""

# Execute the main command
exec "$@"
