# Rapax MariaDB Data Exporter
# Exports data from Redis streams to MariaDB with date-based table partitioning

FROM python:3.11-slim

LABEL maintainer="Rapax Team"
LABEL description="Rapax MariaDB Data Exporter"
LABEL version="1.0.0"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false -u 1000 rapax

# Create directories
RUN mkdir -p /opt/rapax/bin \
             /opt/rapax/lib \
             /opt/rapax/etc/mariadb-exporter \
             /opt/rapax/logs \
    && chown -R rapax:rapax /opt/rapax

# Set working directory
WORKDIR /opt/rapax

# Copy requirements and install dependencies
COPY integration-mariadb-exporter/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy application files
COPY integration-mariadb-exporter/bin/rapax-mariadb-data-exporterd.py /opt/rapax/bin/
COPY integration-mariadb-exporter/lib/rapax.py /opt/rapax/lib/
COPY integration-mariadb-exporter/etc/rotate.cfg /opt/rapax/etc/mariadb-exporter/
COPY integration-mariadb-exporter/etc/batch.cfg /opt/rapax/etc/mariadb-exporter/

# Copy container management files
COPY integration-mariadb-exporter/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY integration-mariadb-exporter/docker-entrypoint.sh /docker-entrypoint.sh
COPY integration-mariadb-exporter/healthcheck.sh /healthcheck.sh

# Make scripts executable
RUN chmod +x /opt/rapax/bin/rapax-mariadb-data-exporterd.py \
             /docker-entrypoint.sh \
             /healthcheck.sh

# Set permissions
RUN chown -R rapax:rapax /opt/rapax

# Environment variables
ENV RAPAXHOME=/opt/rapax
ENV RAPAX_HOME=/opt/rapax
ENV PYTHONPATH=/opt/rapax/lib
ENV LOG_LEVEL=INFO

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /healthcheck.sh

# Entry point
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
