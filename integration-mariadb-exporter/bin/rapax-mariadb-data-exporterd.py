#!/usr/bin/env python3
"""
Rapax MariaDB Data Exporter Daemon

Exports data from Redis streams (devices, stats, alerts, logs, services) to MariaDB
with date-based table partitioning and automatic rotation.

Features:
- 5 stream reader threads (one per stream type)
- 1 table rotation thread (runs every 12 hours)
- Redis consumer groups for reliable message processing
- Batch writes with INSERT IGNORE / ON DUPLICATE KEY UPDATE
- Automatic table creation for today + tomorrow
- Configurable retention periods per stream type
- Metrics logging

Author: Rapax Team
Version: 1.0.0
"""

import os
import sys
import json
import time
import logging
import signal
import threading
import configparser
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from queue import Queue, Empty
import traceback

# Add rapax lib to path
sys.path.insert(0, os.environ.get('PYTHONPATH', '/opt/rapax/lib'))

import redis
import mysql.connector
from mysql.connector import pooling
import requests

# Configuration
COMPONENT_NAME = "rapax-mariadb-exporter"
CONSUMER_GROUP = "rapax_mariadb_exporter"
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
RAPAX_HOME = os.environ.get('RAPAXHOME', '/opt/rapax')
CONFIG_DIR = os.path.join(RAPAX_HOME, 'etc', 'mariadb-exporter')
CREDENTIALS_URL = os.environ.get('CREDENTIALS_URL', 'http://rapax-core-api:5004')

# Stream names
STREAMS = ['devices', 'stats', 'alerts', 'logs', 'services']

# Setup logging - stdout only, supervisor redirects to log file
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(COMPONENT_NAME)


@dataclass
class StreamConfig:
    """Configuration for a single stream."""
    name: str
    batch_size: int = 1
    bulk_size: int = 1
    retention_days: int = 30


@dataclass
class Metrics:
    """Thread-safe metrics tracking."""
    records_processed: Dict[str, int] = field(default_factory=dict)
    records_failed: Dict[str, int] = field(default_factory=dict)
    batches_written: Dict[str, int] = field(default_factory=dict)
    last_write_time: Dict[str, float] = field(default_factory=dict)
    tables_created: int = 0
    tables_dropped: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def increment(self, stream: str, field_name: str, count: int = 1):
        with self._lock:
            current = getattr(self, field_name, {})
            current[stream] = current.get(stream, 0) + count
            setattr(self, field_name, current)

    def set_last_write(self, stream: str):
        with self._lock:
            self.last_write_time[stream] = time.time()

    def to_dict(self) -> dict:
        with self._lock:
            return {
                'records_processed': dict(self.records_processed),
                'records_failed': dict(self.records_failed),
                'batches_written': dict(self.batches_written),
                'last_write_time': {k: datetime.fromtimestamp(v).isoformat()
                                   for k, v in self.last_write_time.items()},
                'tables_created': self.tables_created,
                'tables_dropped': self.tables_dropped
            }


# Table schemas for each stream type
TABLE_SCHEMAS = {
    'devices': """
        CREATE TABLE IF NOT EXISTS {table_name} (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            device_name VARCHAR(255) NOT NULL,
            device_fqdn VARCHAR(255),
            device_description TEXT,
            management_ip VARCHAR(45),
            device_category VARCHAR(100),
            device_model VARCHAR(255),
            device_serial VARCHAR(100),
            device_location VARCHAR(255),
            vendor VARCHAR(100),
            source VARCHAR(100),
            last_seen DATETIME(6),
            security_info JSON,
            interfaces JSON,
            tags JSON,
            created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
            updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
            UNIQUE KEY uk_device_name (device_name),
            INDEX idx_created_at (created_at),
            INDEX idx_management_ip (management_ip),
            INDEX idx_device_category (device_category),
            INDEX idx_vendor (vendor)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    'stats': """
        CREATE TABLE IF NOT EXISTS {table_name} (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            device_name VARCHAR(255) NOT NULL,
            metric_name VARCHAR(255) NOT NULL,
            value DOUBLE NOT NULL,
            tags JSON,
            timestamp DATETIME(6) NOT NULL,
            created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
            INDEX idx_device_metric (device_name, metric_name),
            INDEX idx_timestamp (timestamp),
            INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    'alerts': """
        CREATE TABLE IF NOT EXISTS {table_name} (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            uuid VARCHAR(36) NOT NULL,
            device VARCHAR(255),
            interface VARCHAR(255),
            ip VARCHAR(45),
            status VARCHAR(50),
            state VARCHAR(10),
            category VARCHAR(100),
            source VARCHAR(100),
            location VARCHAR(255),
            description TEXT,
            first_occurred DATETIME(6),
            last_occurred DATETIME(6),
            count INT DEFAULT 1,
            device_type VARCHAR(100),
            parent VARCHAR(255),
            notes JSON,
            tags JSON,
            alert_key VARCHAR(500),
            created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
            updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
            UNIQUE KEY uk_uuid (uuid),
            INDEX idx_device (device),
            INDEX idx_status_state (status, state),
            INDEX idx_category (category),
            INDEX idx_created_at (created_at),
            INDEX idx_last_occurred (last_occurred)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    'logs': """
        CREATE TABLE IF NOT EXISTS {table_name} (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            level VARCHAR(20),
            message TEXT,
            source VARCHAR(100),
            device VARCHAR(255),
            application VARCHAR(100),
            agent VARCHAR(100),
            ip_address VARCHAR(45),
            tags TEXT,
            process_id INT,
            thread VARCHAR(100),
            event_type VARCHAR(100),
            username VARCHAR(100),
            user_agent TEXT,
            extra_data JSON,
            timestamp DATETIME(6) NOT NULL,
            created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
            INDEX idx_level (level),
            INDEX idx_device (device),
            INDEX idx_source (source),
            INDEX idx_timestamp (timestamp),
            INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    'services': """
        CREATE TABLE IF NOT EXISTS {table_name} (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            status VARCHAR(50),
            health VARCHAR(50),
            children JSON,
            parents JSON,
            source VARCHAR(100),
            last_seen DATETIME(6),
            tags JSON,
            created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
            updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
            UNIQUE KEY uk_name (name),
            INDEX idx_status (status),
            INDEX idx_health (health),
            INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """
}

# INSERT statements for each stream type
INSERT_STATEMENTS = {
    'devices': """
        INSERT INTO {table_name} (
            device_name, device_fqdn, device_description, management_ip,
            device_category, device_model, device_serial, device_location,
            vendor, source, last_seen, security_info, interfaces, tags
        ) VALUES (
            %(device_name)s, %(device_fqdn)s, %(device_description)s, %(management_ip)s,
            %(device_category)s, %(device_model)s, %(device_serial)s, %(device_location)s,
            %(vendor)s, %(source)s, %(last_seen)s, %(security_info)s, %(interfaces)s, %(tags)s
        )
        ON DUPLICATE KEY UPDATE
            device_fqdn = VALUES(device_fqdn),
            device_description = VALUES(device_description),
            management_ip = VALUES(management_ip),
            device_category = VALUES(device_category),
            device_model = VALUES(device_model),
            device_serial = VALUES(device_serial),
            device_location = VALUES(device_location),
            vendor = VALUES(vendor),
            source = VALUES(source),
            last_seen = VALUES(last_seen),
            security_info = VALUES(security_info),
            interfaces = VALUES(interfaces),
            tags = VALUES(tags)
    """,
    'stats': """
        INSERT INTO {table_name} (
            device_name, metric_name, value, tags, timestamp
        ) VALUES (
            %(device_name)s, %(metric_name)s, %(value)s, %(tags)s, %(timestamp)s
        )
    """,
    'alerts': """
        INSERT INTO {table_name} (
            uuid, device, interface, ip, status, state, category, source,
            location, description, first_occurred, last_occurred, count,
            device_type, parent, notes, tags, alert_key
        ) VALUES (
            %(uuid)s, %(device)s, %(interface)s, %(ip)s, %(status)s, %(state)s,
            %(category)s, %(source)s, %(location)s, %(description)s,
            %(first_occurred)s, %(last_occurred)s, %(count)s, %(device_type)s,
            %(parent)s, %(notes)s, %(tags)s, %(alert_key)s
        )
        ON DUPLICATE KEY UPDATE
            status = VALUES(status),
            state = VALUES(state),
            last_occurred = VALUES(last_occurred),
            count = VALUES(count),
            description = VALUES(description),
            notes = VALUES(notes),
            tags = VALUES(tags)
    """,
    'logs': """
        INSERT INTO {table_name} (
            level, message, source, device, application, agent,
            ip_address, tags, process_id, thread, event_type,
            username, user_agent, extra_data, timestamp
        ) VALUES (
            %(level)s, %(message)s, %(source)s, %(device)s, %(application)s,
            %(agent)s, %(ip_address)s, %(tags)s, %(process_id)s, %(thread)s,
            %(event_type)s, %(username)s, %(user_agent)s, %(extra_data)s, %(timestamp)s
        )
    """,
    'services': """
        INSERT INTO {table_name} (
            name, description, status, health, children, parents,
            source, last_seen, tags
        ) VALUES (
            %(name)s, %(description)s, %(status)s, %(health)s, %(children)s,
            %(parents)s, %(source)s, %(last_seen)s, %(tags)s
        )
        ON DUPLICATE KEY UPDATE
            description = VALUES(description),
            status = VALUES(status),
            health = VALUES(health),
            children = VALUES(children),
            parents = VALUES(parents),
            source = VALUES(source),
            last_seen = VALUES(last_seen),
            tags = VALUES(tags)
    """
}


class MariaDBExporter:
    """Main exporter class managing all threads and connections."""

    def __init__(self):
        self.running = True
        self.metrics = Metrics()
        self.threads: List[threading.Thread] = []

        # Load configurations
        self.stream_configs = self._load_stream_configs()
        self.retention_config = self._load_retention_config()

        # Initialize connections
        self.redis_client = self._init_redis()
        self.db_pool = self._init_mariadb()

        # Ensure consumer group exists for all streams
        self._init_consumer_groups()

        # Create initial tables (today + tomorrow)
        self._create_initial_tables()

        # Signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        logger.info(f"[{COMPONENT_NAME}] Initialized")

    def _load_stream_configs(self) -> Dict[str, StreamConfig]:
        """Load stream configuration from batch.cfg."""
        configs = {}
        config_file = os.path.join(CONFIG_DIR, 'batch.cfg')

        # Defaults matching core-collection
        defaults = {
            'devices': StreamConfig('devices', batch_size=1, bulk_size=1),
            'stats': StreamConfig('stats', batch_size=20, bulk_size=100),
            'alerts': StreamConfig('alerts', batch_size=1, bulk_size=1),
            'logs': StreamConfig('logs', batch_size=5, bulk_size=5),
            'services': StreamConfig('services', batch_size=1, bulk_size=1),
        }

        if os.path.exists(config_file):
            parser = configparser.ConfigParser()
            parser.read(config_file)

            for stream in STREAMS:
                section = f'stream:{stream}'
                if parser.has_section(section):
                    configs[stream] = StreamConfig(
                        name=stream,
                        batch_size=parser.getint(section, 'batch_size', fallback=defaults[stream].batch_size),
                        bulk_size=parser.getint(section, 'bulk_size', fallback=defaults[stream].bulk_size)
                    )
                else:
                    configs[stream] = defaults[stream]

            logger.info(f"[{COMPONENT_NAME}] Loaded batch config from {config_file}")
        else:
            configs = defaults
            logger.info(f"[{COMPONENT_NAME}] Using default batch configuration")

        for stream, config in configs.items():
            logger.info(f"  {stream}: batch_size={config.batch_size}, bulk_size={config.bulk_size}")

        return configs

    def _load_retention_config(self) -> Dict[str, int]:
        """Load retention configuration from rotate.cfg."""
        config_file = os.path.join(CONFIG_DIR, 'rotate.cfg')

        # Defaults
        retention = {
            'devices': 365,
            'stats': 7,
            'alerts': 30,
            'logs': 7,
            'services': 365,
        }

        if os.path.exists(config_file):
            parser = configparser.ConfigParser()
            parser.read(config_file)

            if parser.has_section('retention'):
                for stream in STREAMS:
                    retention[stream] = parser.getint('retention', stream, fallback=retention[stream])

            logger.info(f"[{COMPONENT_NAME}] Loaded retention config from {config_file}")
        else:
            logger.info(f"[{COMPONENT_NAME}] Using default retention configuration")

        for stream, days in retention.items():
            logger.info(f"  {stream}: {days} days")

        return retention

    def _load_mariadb_credentials(self) -> dict:
        """Load MariaDB credentials from vault or environment."""
        # Try vault first
        try:
            response = requests.get(
                f"{CREDENTIALS_URL}/api/credentials/custom/mariadb",
                timeout=10
            )
            if response.status_code == 200:
                cred = response.json().get('credential', {}).get('data', {})
                if cred.get('host'):
                    logger.info(f"[{COMPONENT_NAME}] Loaded credentials from vault")
                    return cred
        except Exception as e:
            logger.debug(f"[{COMPONENT_NAME}] Could not load from vault: {e}")

        # Try local file
        cred_file = os.path.join(RAPAX_HOME, 'etc', 'mariadb-credentials.json')
        if os.path.exists(cred_file):
            try:
                with open(cred_file, 'r') as f:
                    data = json.load(f)
                    logger.info(f"[{COMPONENT_NAME}] Loaded credentials from {cred_file}")
                    return data.get('data', {})
            except Exception as e:
                logger.debug(f"[{COMPONENT_NAME}] Could not load from file: {e}")

        # Fallback to environment
        logger.info(f"[{COMPONENT_NAME}] Using credentials from environment")
        return {
            'host': os.environ.get('MARIADB_HOST', 'rapax-mariadb'),
            'port': int(os.environ.get('MARIADB_PORT', 3306)),
            'database': os.environ.get('MARIADB_DATABASE', 'rapax'),
            'username': os.environ.get('MARIADB_USER', 'rapax'),
            'password': os.environ.get('MARIADB_PASSWORD', ''),
        }

    def _init_redis(self) -> redis.Redis:
        """Initialize Redis connection."""
        host = os.environ.get('REDIS_HOST', 'rapax-redis')
        port = int(os.environ.get('REDIS_PORT', 6379))
        password = os.environ.get('REDIS_PASSWORD', '')

        # Try to load password from config
        if not password:
            redis_conf = os.path.join(RAPAX_HOME, 'etc', 'redis.conf')
            if os.path.exists(redis_conf):
                with open(redis_conf, 'r') as f:
                    for line in f:
                        if line.strip().startswith('requirepass'):
                            password = line.split()[1].strip()
                            break

        client = redis.Redis(
            host=host,
            port=port,
            password=password or None,
            decode_responses=True
        )

        client.ping()
        logger.info(f"[{COMPONENT_NAME}] Redis connected: {host}:{port}")

        return client

    def _init_mariadb(self) -> pooling.MySQLConnectionPool:
        """Initialize MariaDB connection pool."""
        creds = self._load_mariadb_credentials()

        pool = pooling.MySQLConnectionPool(
            pool_name="rapax_exporter_pool",
            pool_size=10,
            pool_reset_session=True,
            host=creds.get('host', 'rapax-mariadb'),
            port=creds.get('port', 3306),
            database=creds.get('database', 'rapax'),
            user=creds.get('username', 'rapax'),
            password=creds.get('password', ''),
            charset='utf8mb4',
            collation='utf8mb4_unicode_ci',
            autocommit=False
        )

        # Test connection
        conn = pool.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT VERSION()")
        version = cursor.fetchone()[0]
        cursor.close()
        conn.close()

        logger.info(f"[{COMPONENT_NAME}] MariaDB connected: {creds.get('host')}:{creds.get('port')} (version {version})")

        return pool

    def _init_consumer_groups(self):
        """Initialize Redis consumer groups for all streams."""
        consumer_name = f"{COMPONENT_NAME}-{os.environ.get('HOSTNAME', 'default')}"

        for stream in STREAMS:
            stream_key = f"stream:{stream}"
            try:
                # Try to create the consumer group
                self.redis_client.xgroup_create(
                    stream_key,
                    CONSUMER_GROUP,
                    id='0',
                    mkstream=True
                )
                logger.info(f"[{COMPONENT_NAME}] Created consumer group for {stream_key}")
            except redis.exceptions.ResponseError as e:
                if "BUSYGROUP" in str(e):
                    # Consumer group already exists
                    logger.debug(f"[{COMPONENT_NAME}] Consumer group already exists for {stream_key}")
                else:
                    raise

    def _get_table_name(self, stream: str, date: datetime = None) -> str:
        """Get table name for a stream and date."""
        if date is None:
            date = datetime.utcnow()
        return f"{stream}_{date.strftime('%Y_%m_%d')}"

    def _create_table(self, stream: str, date: datetime = None) -> bool:
        """Create table for a stream if it doesn't exist."""
        table_name = self._get_table_name(stream, date)
        schema = TABLE_SCHEMAS[stream].format(table_name=table_name)

        conn = None
        try:
            conn = self.db_pool.get_connection()
            cursor = conn.cursor()
            cursor.execute(schema)
            conn.commit()
            cursor.close()
            logger.info(f"[{COMPONENT_NAME}] Created/verified table: {table_name}")
            self.metrics.tables_created += 1
            return True
        except Exception as e:
            logger.error(f"[{COMPONENT_NAME}] Failed to create table {table_name}: {e}")
            return False
        finally:
            if conn:
                conn.close()

    def _create_initial_tables(self):
        """Create tables for today and tomorrow for all streams."""
        today = datetime.utcnow()
        tomorrow = today + timedelta(days=1)

        for stream in STREAMS:
            self._create_table(stream, today)
            self._create_table(stream, tomorrow)

    def _drop_old_tables(self, stream: str):
        """Drop tables older than retention period."""
        retention_days = self.retention_config.get(stream, 30)
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

        conn = None
        try:
            conn = self.db_pool.get_connection()
            cursor = conn.cursor()

            # Get list of tables for this stream
            cursor.execute(f"SHOW TABLES LIKE '{stream}_%'")
            tables = cursor.fetchall()

            for (table_name,) in tables:
                # Parse date from table name
                try:
                    date_str = table_name.replace(f"{stream}_", "")
                    table_date = datetime.strptime(date_str, "%Y_%m_%d")

                    if table_date < cutoff_date:
                        cursor.execute(f"DROP TABLE IF EXISTS `{table_name}`")
                        conn.commit()
                        logger.info(f"[{COMPONENT_NAME}] Dropped old table: {table_name}")
                        self.metrics.tables_dropped += 1
                except ValueError:
                    # Skip tables that don't match the expected format
                    pass

            cursor.close()
        except Exception as e:
            logger.error(f"[{COMPONENT_NAME}] Error dropping old tables for {stream}: {e}")
        finally:
            if conn:
                conn.close()

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"[{COMPONENT_NAME}] Received signal {signum}, shutting down...")
        self.running = False

    def _transform_device(self, data: dict) -> dict:
        """Transform device data for MariaDB insert."""
        timestamp = data.get('@timestamp') or data.get('lastSeen')
        if timestamp:
            try:
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()

        # Get device name - try multiple field name variations
        device_name = (
            data.get('deviceName') or
            data.get('device_name') or
            data.get('DeviceName') or
            data.get('name') or
            data.get('Name') or
            data.get('hostname') or
            data.get('host') or
            ''
        )

        # If still no device name, try to use IP or generate unique ID
        if not device_name:
            device_name = (
                data.get('ManagementIpAddress') or
                data.get('management_ip') or
                data.get('ip') or
                data.get('IP') or
                f"unknown-{hash(json.dumps(data, sort_keys=True, default=str)) % 1000000}"
            )
            logger.warning(f"[{COMPONENT_NAME}] Device missing name, using: {device_name}")

        return {
            'device_name': device_name,
            'device_fqdn': data.get('deviceFQDN') or data.get('device_fqdn') or data.get('fqdn') or '',
            'device_description': data.get('deviceDescription') or data.get('description') or '',
            'management_ip': data.get('ManagementIpAddress') or data.get('management_ip') or data.get('ip') or '',
            'device_category': data.get('deviceCategory') or data.get('device_category') or data.get('category') or '',
            'device_model': data.get('deviceModel') or data.get('device_model') or data.get('model') or '',
            'device_serial': data.get('deviceSerialNumber') or data.get('device_serial') or data.get('serial') or '',
            'device_location': data.get('deviceLocation') or data.get('device_location') or data.get('location') or '',
            'vendor': data.get('vendor') or data.get('Vendor') or '',
            'source': data.get('source') or data.get('Source') or '',
            'last_seen': timestamp,
            'security_info': json.dumps(data.get('securityInformation') or data.get('security_info') or []),
            'interfaces': json.dumps(data.get('interfaces') or {}),
            'tags': json.dumps(data.get('tags') or []),
        }

    def _transform_stats(self, data: dict) -> dict:
        """Transform stats data for MariaDB insert."""
        timestamp = data.get('@timestamp')
        if timestamp:
            try:
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()

        return {
            'device_name': data.get('deviceName', ''),
            'metric_name': data.get('metricName', ''),
            'value': float(data.get('value', 0)),
            'tags': json.dumps(data.get('tags', {})),
            'timestamp': timestamp,
        }

    def _transform_alert(self, data: dict) -> dict:
        """Transform alert data for MariaDB insert."""
        import uuid as uuid_module

        first_occurred = data.get('FirstOccurred') or data.get('first_occurred') or data.get('firstOccurred')
        last_occurred = data.get('LastOccurred') or data.get('last_occurred') or data.get('lastOccurred')

        for ts_field in ['first_occurred', 'last_occurred']:
            ts_value = first_occurred if ts_field == 'first_occurred' else last_occurred
            if ts_value:
                try:
                    if isinstance(ts_value, str):
                        ts_value = datetime.fromisoformat(ts_value.replace('Z', '+00:00'))
                except:
                    ts_value = datetime.utcnow()
            else:
                ts_value = datetime.utcnow()

            if ts_field == 'first_occurred':
                first_occurred = ts_value
            else:
                last_occurred = ts_value

        # Get UUID - try multiple field name variations
        alert_uuid = (
            data.get('UUID') or
            data.get('uuid') or
            data.get('Id') or
            data.get('id') or
            data.get('_id') or
            ''
        )

        # If no UUID, generate one to ensure unique key
        if not alert_uuid:
            alert_uuid = str(uuid_module.uuid4())
            logger.warning(f"[{COMPONENT_NAME}] Alert missing UUID, generated: {alert_uuid}")

        return {
            'uuid': alert_uuid,
            'device': data.get('Device') or data.get('device') or data.get('hostname') or data.get('host') or '',
            'interface': data.get('Interface') or data.get('interface') or '',
            'ip': data.get('IP') or data.get('ip') or data.get('ipAddress') or '0.0.0.0',
            'status': data.get('Status') or data.get('status') or data.get('severity') or '',
            'state': data.get('State') or data.get('state') or '',
            'category': data.get('Category') or data.get('category') or '',
            'source': data.get('Source') or data.get('source') or '',
            'location': data.get('Location') or data.get('location') or '',
            'description': data.get('Description') or data.get('description') or data.get('message') or data.get('summary') or '',
            'first_occurred': first_occurred,
            'last_occurred': last_occurred,
            'count': int(data.get('Count') or data.get('count') or data.get('Number') or data.get('number') or 1),
            'device_type': data.get('DeviceType') or data.get('device_type') or data.get('deviceType') or '',
            'parent': data.get('Parent') or data.get('parent') or '',
            'notes': json.dumps(data.get('Notes') or data.get('notes') or []),
            'tags': json.dumps(data.get('Tags') or data.get('tags') or []),
            'alert_key': data.get('key') or data.get('Key') or data.get('alert_key') or '',
        }

    def _transform_log(self, data: dict) -> dict:
        """Transform log data for MariaDB insert."""
        timestamp = data.get('@timestamp') or data.get('timestamp')
        if timestamp:
            try:
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()

        # Extract known fields, put rest in extra_data
        known_fields = {'@timestamp', 'timestamp', 'level', 'message', 'source', 'device',
                       'application', 'agent', 'ipaddress', 'ip_address', 'tags',
                       'processid', 'process_id', 'thread', 'event_type', 'username', 'user_agent'}
        extra_data = {k: v for k, v in data.items() if k not in known_fields}

        return {
            'level': data.get('level', ''),
            'message': data.get('message', ''),
            'source': data.get('source', ''),
            'device': data.get('device', ''),
            'application': data.get('application', ''),
            'agent': data.get('agent', ''),
            'ip_address': data.get('ip_address') or data.get('ipaddress', ''),
            'tags': data.get('tags', ''),
            'process_id': data.get('process_id') or data.get('processid'),
            'thread': data.get('thread', ''),
            'event_type': data.get('event_type', ''),
            'username': data.get('username', ''),
            'user_agent': data.get('user_agent', ''),
            'extra_data': json.dumps(extra_data) if extra_data else None,
            'timestamp': timestamp,
        }

    def _transform_service(self, data: dict) -> dict:
        """Transform service data for MariaDB insert."""
        timestamp = data.get('@timestamp') or data.get('lastSeen') or data.get('last_seen')
        if timestamp:
            try:
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()

        # Get service name - try multiple field name variations
        service_name = (
            data.get('name') or
            data.get('Name') or
            data.get('serviceName') or
            data.get('service_name') or
            data.get('ServiceName') or
            ''
        )

        # If no name, generate one to ensure unique key
        if not service_name:
            service_name = f"unknown-{hash(json.dumps(data, sort_keys=True, default=str)) % 1000000}"
            logger.warning(f"[{COMPONENT_NAME}] Service missing name, using: {service_name}")

        return {
            'name': service_name,
            'description': data.get('description') or data.get('Description') or '',
            'status': data.get('status') or data.get('Status') or '',
            'health': data.get('health') or data.get('Health') or '',
            'children': json.dumps(data.get('children') or data.get('Children') or []),
            'parents': json.dumps(data.get('parents') or data.get('Parents') or []),
            'source': data.get('source') or data.get('Source') or '',
            'last_seen': timestamp,
            'tags': json.dumps(data.get('tags') or data.get('Tags') or []),
        }

    def _transform_data(self, stream: str, data: dict) -> dict:
        """Transform stream data for MariaDB insert."""
        transformers = {
            'devices': self._transform_device,
            'stats': self._transform_stats,
            'alerts': self._transform_alert,
            'logs': self._transform_log,
            'services': self._transform_service,
        }
        return transformers[stream](data)

    def _write_batch(self, stream: str, records: List[dict]) -> int:
        """Write a batch of records to MariaDB."""
        if not records:
            return 0

        table_name = self._get_table_name(stream)
        insert_stmt = INSERT_STATEMENTS[stream].format(table_name=table_name)

        conn = None
        written = 0
        try:
            conn = self.db_pool.get_connection()
            cursor = conn.cursor()

            for record in records:
                try:
                    transformed = self._transform_data(stream, record)
                    cursor.execute(insert_stmt, transformed)
                    written += 1
                except Exception as e:
                    logger.warning(f"[{COMPONENT_NAME}] Failed to write record to {stream}: {e}")
                    self.metrics.increment(stream, 'records_failed')

            conn.commit()
            cursor.close()

            self.metrics.increment(stream, 'records_processed', written)
            self.metrics.increment(stream, 'batches_written')
            self.metrics.set_last_write(stream)

            return written
        except Exception as e:
            logger.error(f"[{COMPONENT_NAME}] Batch write failed for {stream}: {e}")
            if conn:
                conn.rollback()
            return 0
        finally:
            if conn:
                conn.close()

    def _stream_worker(self, stream: str):
        """Worker thread for processing a single stream."""
        stream_key = f"stream:{stream}"
        consumer_name = f"{COMPONENT_NAME}-{stream}-{os.getpid()}"
        config = self.stream_configs[stream]

        buffer = []
        last_flush_time = time.time()

        logger.info(f"[{COMPONENT_NAME}] Stream worker started for {stream}")

        while self.running:
            try:
                # Read from stream using consumer group
                messages = self.redis_client.xreadgroup(
                    CONSUMER_GROUP,
                    consumer_name,
                    {stream_key: '>'},
                    count=config.batch_size,
                    block=5000  # 5 second timeout
                )

                if messages:
                    for stream_name, stream_messages in messages:
                        for msg_id, msg_data in stream_messages:
                            # Parse message data
                            try:
                                # Debug: log first few messages to understand structure
                                if self.metrics.records_processed.get(stream, 0) < 3:
                                    logger.info(f"[{COMPONENT_NAME}] DEBUG {stream} msg_data keys: {list(msg_data.keys())}")
                                    logger.info(f"[{COMPONENT_NAME}] DEBUG {stream} msg_data: {str(msg_data)[:500]}")

                                # Parse data from various field names used by rapax
                                if 'data' in msg_data:
                                    data = json.loads(msg_data['data'])
                                elif 'message' in msg_data:
                                    data = json.loads(msg_data['message'])
                                else:
                                    data = msg_data

                                # Debug: log parsed data keys
                                if self.metrics.records_processed.get(stream, 0) < 3:
                                    logger.info(f"[{COMPONENT_NAME}] DEBUG {stream} parsed data keys: {list(data.keys())}")

                                buffer.append(data)

                                # ACK the message
                                self.redis_client.xack(stream_key, CONSUMER_GROUP, msg_id)
                            except json.JSONDecodeError as e:
                                logger.warning(f"[{COMPONENT_NAME}] Invalid JSON in {stream}: {e}")
                                logger.warning(f"[{COMPONENT_NAME}] Raw msg_data: {msg_data}")
                                self.redis_client.xack(stream_key, CONSUMER_GROUP, msg_id)

                # Check if we should flush the buffer
                buffer_age = time.time() - last_flush_time
                should_flush = (
                    len(buffer) >= config.bulk_size or
                    (len(buffer) > 0 and buffer_age >= 30)  # Max 30 second buffer age
                )

                if should_flush:
                    written = self._write_batch(stream, buffer)
                    if written > 0:
                        logger.debug(f"[{COMPONENT_NAME}] Wrote {written} records to {stream}")
                    buffer = []
                    last_flush_time = time.time()

            except redis.exceptions.ConnectionError as e:
                logger.error(f"[{COMPONENT_NAME}] Redis connection error in {stream}: {e}")
                time.sleep(5)
            except Exception as e:
                logger.error(f"[{COMPONENT_NAME}] Error in {stream} worker: {e}")
                logger.debug(traceback.format_exc())
                time.sleep(1)

        # Flush remaining buffer on shutdown
        if buffer:
            self._write_batch(stream, buffer)

        logger.info(f"[{COMPONENT_NAME}] Stream worker stopped for {stream}")

    def _rotation_worker(self):
        """Worker thread for table rotation (runs every 12 hours)."""
        logger.info(f"[{COMPONENT_NAME}] Rotation worker started")

        while self.running:
            try:
                # Create tables for tomorrow
                tomorrow = datetime.utcnow() + timedelta(days=1)
                for stream in STREAMS:
                    self._create_table(stream, tomorrow)

                # Drop old tables
                for stream in STREAMS:
                    self._drop_old_tables(stream)

                logger.info(f"[{COMPONENT_NAME}] Table rotation complete")

                # Sleep for 12 hours (checking every minute for shutdown)
                for _ in range(12 * 60):
                    if not self.running:
                        break
                    time.sleep(60)

            except Exception as e:
                logger.error(f"[{COMPONENT_NAME}] Error in rotation worker: {e}")
                logger.debug(traceback.format_exc())
                time.sleep(60)

        logger.info(f"[{COMPONENT_NAME}] Rotation worker stopped")

    def _metrics_worker(self):
        """Worker thread for logging metrics periodically."""
        logger.info(f"[{COMPONENT_NAME}] Metrics worker started")

        while self.running:
            try:
                # Log metrics every 60 seconds
                for _ in range(60):
                    if not self.running:
                        break
                    time.sleep(1)

                if self.running:
                    metrics = self.metrics.to_dict()
                    logger.info(f"[{COMPONENT_NAME}] Metrics: {json.dumps(metrics)}")

            except Exception as e:
                logger.error(f"[{COMPONENT_NAME}] Error in metrics worker: {e}")

        logger.info(f"[{COMPONENT_NAME}] Metrics worker stopped")

    def run(self):
        """Start all worker threads and run the exporter."""
        logger.info(f"[{COMPONENT_NAME}] Starting exporter daemon")

        # Start stream worker threads
        for stream in STREAMS:
            thread = threading.Thread(
                target=self._stream_worker,
                args=(stream,),
                name=f"stream-{stream}",
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
            logger.info(f"[{COMPONENT_NAME}] Started stream worker: {stream}")

        # Start rotation worker thread
        rotation_thread = threading.Thread(
            target=self._rotation_worker,
            name="rotation",
            daemon=True
        )
        rotation_thread.start()
        self.threads.append(rotation_thread)
        logger.info(f"[{COMPONENT_NAME}] Started rotation worker")

        # Start metrics worker thread
        metrics_thread = threading.Thread(
            target=self._metrics_worker,
            name="metrics",
            daemon=True
        )
        metrics_thread.start()
        self.threads.append(metrics_thread)
        logger.info(f"[{COMPONENT_NAME}] Started metrics worker")

        # Wait for shutdown signal
        try:
            while self.running:
                time.sleep(1)

                # Check if any thread has died unexpectedly
                for thread in self.threads:
                    if not thread.is_alive() and self.running:
                        logger.error(f"[{COMPONENT_NAME}] Thread {thread.name} died unexpectedly!")
                        self.running = False
                        break

        except KeyboardInterrupt:
            logger.info(f"[{COMPONENT_NAME}] Keyboard interrupt received")
            self.running = False

        # Wait for threads to finish
        logger.info(f"[{COMPONENT_NAME}] Waiting for threads to finish...")
        for thread in self.threads:
            thread.join(timeout=10)

        # Final metrics
        logger.info(f"[{COMPONENT_NAME}] Final metrics: {json.dumps(self.metrics.to_dict())}")
        logger.info(f"[{COMPONENT_NAME}] Exporter daemon stopped")


def main():
    """Main entry point."""
    # Ensure log directory exists
    log_dir = os.path.join(RAPAX_HOME, 'logs')
    os.makedirs(log_dir, exist_ok=True)

    # Ensure config directory exists
    os.makedirs(CONFIG_DIR, exist_ok=True)

    logger.info(f"[{COMPONENT_NAME}] Starting...")
    logger.info(f"[{COMPONENT_NAME}] RAPAX_HOME: {RAPAX_HOME}")
    logger.info(f"[{COMPONENT_NAME}] CONFIG_DIR: {CONFIG_DIR}")
    logger.info(f"[{COMPONENT_NAME}] LOG_LEVEL: {LOG_LEVEL}")

    try:
        exporter = MariaDBExporter()
        exporter.run()
    except Exception as e:
        logger.error(f"[{COMPONENT_NAME}] Fatal error: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
