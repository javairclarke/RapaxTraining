#
# Rapax OSTicket Integration Container
# Provides automatic ticket creation from Rapax alerts
#
FROM python:3.11-slim

LABEL maintainer="Rapax Team"
LABEL description="Rapax OSTicket Integration - Automatic ticket creation from alerts"
LABEL version="1.0.0"

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY osticket-agentd.py /app/osticket-agentd.py

# Copy entrypoint and healthcheck scripts
COPY entrypoint.sh /app/entrypoint.sh
COPY healthcheck.sh /app/healthcheck.sh

# Make scripts executable
RUN chmod +x /app/*.sh /app/*.py

# Create rapax user (non-root)
RUN groupadd -g 1000 rapax && \
    useradd -u 1000 -g rapax -s /bin/bash -m rapax

# Create required directories and set permissions
RUN mkdir -p /opt/rapax/logs && \
    chown -R rapax:rapax /app /opt/rapax

# Switch to non-root user
USER rapax

# Environment variables
ENV RAPAXHOME=/opt/rapax \
    RAPAX_HOME=/opt/rapax \
    PYTHONPATH=/opt/rapax/lib \
    PYTHONUNBUFFERED=1 \
    LOG_LEVEL=INFO \
    TZ=UTC \
    DAEMON_INTERVAL=60

# Health check - verify the daemon is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD /app/healthcheck.sh

# No exposed ports - this is a background processing container

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
