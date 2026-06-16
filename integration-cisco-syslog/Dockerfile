# Cisco Syslog Integration Processor
# Processes Cisco syslog messages from /var/log/messages and routes to Redis

FROM python:3.11-slim

LABEL maintainer="Rapax Integration"
LABEL description="Cisco Syslog Processor for Rapax"
LABEL version="1.0.0"

# Install supervisor for process management
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create application directories
RUN mkdir -p /opt/rapax/bin \
             /opt/rapax/lib \
             /opt/rapax/etc \
             /opt/rapax/logs

# Copy requirements and install Python dependencies
COPY integration-cisco-syslog/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Copy application files
COPY integration-cisco-syslog/bin/cisco-syslog-processord.py /opt/rapax/bin/
COPY integration-cisco-syslog/bin/cisco-syslog-sender.py /opt/rapax/bin/
COPY integration-cisco-syslog/bin/cisco-syslog-collector.py /opt/rapax/bin/

# Make scripts executable
RUN chmod +x /opt/rapax/bin/*.py

# Copy supervisor configuration
COPY integration-cisco-syslog/supervisord.conf /etc/supervisor/conf.d/cisco-syslog.conf

# Copy entrypoint and healthcheck
COPY integration-cisco-syslog/docker-entrypoint.sh /docker-entrypoint.sh
COPY integration-cisco-syslog/healthcheck.sh /healthcheck.sh
RUN chmod +x /docker-entrypoint.sh /healthcheck.sh

# Environment variables
ENV RAPAXHOME=/opt/rapax
ENV RAPAX_HOME=/opt/rapax
ENV PYTHONPATH=/opt/rapax/lib
ENV PYTHONUNBUFFERED=1
ENV LOG_LEVEL=INFO
ENV REDIS_HOST=rapax-redis
ENV REDIS_PORT=6379
ENV SYSLOG_FILE=/var/log/messages
ENV COMPONENT_ID=cisco-syslog-1

# Working directory
WORKDIR /opt/rapax

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD /healthcheck.sh

# Entrypoint
ENTRYPOINT ["/docker-entrypoint.sh"]

# Default command - run supervisor
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
