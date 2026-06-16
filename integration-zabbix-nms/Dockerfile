# Rapax Zabbix NMS Integration Container
# ========================================
#
# Polls Zabbix REST API and publishes data to Redis streams:
# - stream:devices (host inventory)
# - stream:stats (numeric metrics)
# - stream:services (Zabbix services)
# - stream:alerts (heartbeat)

FROM python:3.11-slim

LABEL maintainer="Citus Technologies"
LABEL version="1.0.0"
LABEL description="Rapax Zabbix NMS data collector"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    supervisor \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create application directories
RUN mkdir -p /opt/rapax/bin /opt/rapax/lib /opt/rapax/logs /opt/rapax/etc

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy application files
COPY lib/rapax.py /opt/rapax/lib/
COPY bin/zabbix-data-processord.py /opt/rapax/bin/

# Make scripts executable
RUN chmod +x /opt/rapax/bin/*.py

# Copy supervisor configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Copy healthcheck script
COPY healthcheck.sh /opt/rapax/bin/
RUN chmod +x /opt/rapax/bin/healthcheck.sh

# Set environment variables
ENV RAPAXHOME=/opt/rapax
ENV PYTHONPATH=/opt/rapax/lib
ENV PYTHONUNBUFFERED=1

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD /opt/rapax/bin/healthcheck.sh

# Run supervisor
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
