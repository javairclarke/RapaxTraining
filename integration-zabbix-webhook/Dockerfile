# Rapax Zabbix Webhook Integration Container
# ===========================================
#
# Flask-based webhook receiver for Zabbix alerts.
# Receives alerts via HTTP POST and publishes to Redis streams.

FROM python:3.11-slim

LABEL maintainer="Citus Technologies"
LABEL version="1.0.0"
LABEL description="Rapax Zabbix webhook receiver"

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
COPY bin/zabbix-webhook-processord.py /opt/rapax/bin/
COPY bin/configure-zabbix.py /opt/rapax/bin/

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
ENV WEBHOOK_PORT=6543

# Expose webhook port
EXPOSE 6543

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /opt/rapax/bin/healthcheck.sh

# Run supervisor
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
