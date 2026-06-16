FROM python:3.11-slim

LABEL org.opencontainers.image.title="Rapax Cisco Trap Integration"
LABEL org.opencontainers.image.description="Cisco SNMP trap processor for Rapax platform"
LABEL org.opencontainers.image.vendor="Rapax"
LABEL org.opencontainers.image.source="https://github.com/ennissh/rapax-cloud"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    redis \
    opensearch-py \
    pysnmp==4.4.12 \
    pyasn1==0.4.8 \
    pyyaml \
    requests \
    cryptography

# Create directory structure
RUN mkdir -p /opt/rapax/bin \
    /opt/rapax/lib \
    /opt/rapax/etc \
    /opt/rapax/logs

# Copy library
COPY lib/rapax.py /opt/rapax/lib/

# Copy processor and utility scripts
COPY bin/cisco-trap-processord.py /opt/rapax/bin/
COPY bin/cisco-trap-sender.py /opt/rapax/bin/
COPY bin/cisco-trap-collector.py /opt/rapax/bin/

# Copy supervisord configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Copy startup and health check scripts
COPY docker-entrypoint.sh /docker-entrypoint.sh
COPY healthcheck.sh /healthcheck.sh
RUN chmod +x /docker-entrypoint.sh /healthcheck.sh

# Make scripts executable
RUN chmod +x /opt/rapax/bin/*.py

# Environment variables with defaults
ENV RAPAXHOME=/opt/rapax
ENV REDIS_HOST=rapax-redis
ENV REDIS_PORT=6379
ENV REDIS_PASSWORD=""
ENV SYSLOG_FILE=/var/log/messages
ENV COMPONENT_ID=cisco-trap-1
ENV LOG_LEVEL=INFO

WORKDIR /opt/rapax

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD /healthcheck.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
