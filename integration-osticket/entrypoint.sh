#!/bin/bash
#
# Entrypoint script for Rapax OSTicket Integration Container
# Starts the osticket-agentd daemon for automatic ticket creation
#

echo "========================================================================"
echo "Rapax OSTicket Integration Container Starting"
echo "========================================================================"
echo ""

# Configuration
RAPAXHOME="${RAPAXHOME:-/opt/rapax}"
RAPAX_HOME="${RAPAX_HOME:-/opt/rapax}"
LOG_DIR="${RAPAXHOME}/logs"
LOG_FILE="${LOG_DIR}/osticket-agentd.log"
DAEMON_INTERVAL="${DAEMON_INTERVAL:-60}"

# Ensure log directory exists and is writable
mkdir -p "${LOG_DIR}" 2>/dev/null || true
if [ ! -w "${LOG_DIR}" ]; then
    echo "WARNING: Log directory ${LOG_DIR} is not writable, logging to /tmp"
    LOG_DIR="/tmp"
    LOG_FILE="${LOG_DIR}/osticket-agentd.log"
fi

# Check required environment variables
echo "Checking environment..."
echo "  RAPAXHOME: ${RAPAXHOME}"
echo "  RAPAX_HOME: ${RAPAX_HOME}"
echo "  DAEMON_INTERVAL: ${DAEMON_INTERVAL}s"
echo "  LOG_FILE: ${LOG_FILE}"
echo ""

# Check if rapax library is available
if [ ! -f "${RAPAXHOME}/lib/rapax.py" ]; then
    echo "ERROR: rapax.py library not found at ${RAPAXHOME}/lib/rapax.py"
    echo "Make sure to mount the rapax lib directory:"
    echo "  -v /opt/rapax/lib:/opt/rapax/lib:ro"
    exit 1
fi

# Check if credentials file exists
if [ ! -f "${RAPAXHOME}/etc/credentials" ]; then
    echo "WARNING: Credentials file not found at ${RAPAXHOME}/etc/credentials"
    echo "Make sure to mount the rapax etc directory:"
    echo "  -v /opt/rapax/etc:/opt/rapax/etc:ro"
fi

# Check if machine-id is mounted (required for credential decryption)
if [ ! -f "/etc/machine-id" ]; then
    echo "WARNING: /etc/machine-id not found. Credential decryption may fail."
    echo "Make sure to mount: -v /etc/machine-id:/etc/machine-id:ro"
fi

# Check if ticket configuration exists
if [ ! -f "${RAPAXHOME}/etc/ticket.cfg" ]; then
    echo "ERROR: Ticket configuration not found at ${RAPAXHOME}/etc/ticket.cfg"
    echo "Run install-osticket.sh first to create the configuration"
    exit 1
fi

echo "Environment OK"
echo ""

# Start OSTicket Integration daemon with output to both file and stdout
echo "Starting OSTicket Integration daemon..."
python3 /app/osticket-agentd.py --daemon ${DAEMON_INTERVAL} 2>&1 | tee -a "${LOG_FILE}" &
DAEMON_PID=$!
echo "OSTicket Integration daemon started (PID: ${DAEMON_PID})"
echo "  Interval: ${DAEMON_INTERVAL}s"
echo "  Log file: ${LOG_FILE}"
echo ""

echo "========================================================================"
echo "Rapax OSTicket Integration Container Running"
echo "========================================================================"
echo ""
echo "Daemon:"
echo "  - OSTicket Integration: PID ${DAEMON_PID}"
echo ""
echo "Features:"
echo "  - Scans Redis for alerts needing tickets"
echo "  - Creates tickets via OSTicket JSON API"
echo "  - Updates alerts with ticket IDs"
echo "  - Supports multiple alert formats"
echo ""
echo "Log files:"
echo "  - ${LOG_FILE}"
echo ""
echo "Press Ctrl+C to stop..."
echo "========================================================================"
echo ""

# Function to handle shutdown
shutdown() {
    echo ""
    echo "Shutdown signal received..."
    echo "Stopping daemon..."

    if [ ! -z "$DAEMON_PID" ]; then
        kill $DAEMON_PID 2>/dev/null || true
        echo "  Stopped OSTicket Integration daemon (PID: ${DAEMON_PID})"
    fi

    echo "Shutdown complete"
    exit 0
}

# Trap signals
trap shutdown SIGTERM SIGINT

# Monitor process and restart if it crashes
while true; do
    # Check if OSTicket Integration daemon is still running
    if ! kill -0 $DAEMON_PID 2>/dev/null; then
        echo "[$(date)] OSTicket Integration daemon exited, restarting in 10s..."
        echo "[$(date)] Last 20 lines of log:"
        tail -20 "${LOG_FILE}" 2>/dev/null || true
        sleep 10
        echo "[$(date)] Restarting OSTicket Integration daemon..."
        python3 /app/osticket-agentd.py --daemon ${DAEMON_INTERVAL} 2>&1 | tee -a "${LOG_FILE}" &
        DAEMON_PID=$!
        echo "[$(date)] OSTicket Integration daemon restarted (PID: ${DAEMON_PID})"
    fi

    # Sleep before next check
    sleep 10
done
