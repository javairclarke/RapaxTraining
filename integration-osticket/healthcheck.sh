#!/bin/sh
#
# Health check script for Rapax OSTicket Integration container
# Verifies that the osticket-agentd daemon is running
#

# Check if osticket-agentd.py is running
if ! pgrep -f "osticket-agentd.py" > /dev/null; then
    echo "ERROR: osticket-agentd.py is not running"
    exit 1
fi

# All checks passed
exit 0
