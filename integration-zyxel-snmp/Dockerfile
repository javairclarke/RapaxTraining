FROM python:3.11-slim

LABEL org.opencontainers.image.title="Rapax Zyxel Integration"
LABEL org.opencontainers.image.description="Zyxel integration processor for Rapax platform"
LABEL org.opencontainers.image.vendor="Rapax"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Create directory structure
RUN mkdir -p /opt/rapax/bin \
    /opt/rapax/lib \
    /opt/rapax/etc \
    /opt/rapax/logs

# Copy processor
COPY bin/zyxel-snmp-pollerd.py /opt/rapax/bin/
RUN chmod +x /opt/rapax/bin/zyxel-snmp-pollerd.py

# Copy supervisord configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Copy startup and health check scripts
COPY docker-entrypoint.sh /docker-entrypoint.sh
COPY healthcheck.sh /healthcheck.sh
RUN chmod +x /docker-entrypoint.sh /healthcheck.sh

# Environment variables with defaults
ENV RAPAXHOME=/opt/rapax
ENV PYTHONPATH=/opt/rapax/lib
ENV REDIS_HOST=rapax-redis
ENV REDIS_PORT=6379
ENV REDIS_PASSWORD=""
ENV COMPONENT_ID=zyxel-snmp-1
ENV LOG_LEVEL=INFO

WORKDIR /opt/rapax

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD /healthcheck.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
