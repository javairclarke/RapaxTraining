# Rapax MariaDB Data Exporter

The MariaDB Data Exporter is an integration component that exports data from Rapax Redis streams to MariaDB with automatic date-based table partitioning and retention management.

## Overview

This component listens to the five Redis streams created by core-collection:
- `stream:devices` - Device inventory data
- `stream:stats` - Performance metrics
- `stream:alerts` - Alert events
- `stream:logs` - Log events
- `stream:services` - Service definitions

Data is exported to MariaDB tables organized by date (e.g., `devices_2026_01_30`, `stats_2026_01_30`).

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  rapax-mariadb-exporter                         │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │         rapax-mariadb-data-exporterd.py                   │ │
│  │                                                           │ │
│  │  ┌─────────────────────────────────────────────────────┐  │ │
│  │  │  Table Rotation Thread (every 12 hours)             │  │ │
│  │  │  - Creates tomorrow's tables                        │  │ │
│  │  │  - Drops tables older than retention period         │  │ │
│  │  └─────────────────────────────────────────────────────┘  │ │
│  │                                                           │ │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐  │ │
│  │  │devices │ │ stats  │ │ alerts │ │  logs  │ │services│  │ │
│  │  │ thread │ │ thread │ │ thread │ │ thread │ │ thread │  │ │
│  │  └───┬────┘ └───┬────┘ └───┬────┘ └───┬────┘ └───┬────┘  │ │
│  └──────│──────────│──────────│──────────│──────────│────────┘ │
└─────────│──────────│──────────│──────────│──────────│──────────┘
          │          │          │          │          │
    ┌─────▼──────────▼──────────▼──────────▼──────────▼─────┐
    │                     Redis Streams                      │
    │  stream:devices, stream:stats, stream:alerts,         │
    │  stream:logs, stream:services                          │
    └───────────────────────────────────────────────────────┘
                              │
                              ▼
    ┌───────────────────────────────────────────────────────┐
    │                    rapax-mariadb                       │
    │   Database: rapax                                      │
    │   Tables: devices_2026_01_30, stats_2026_01_30, etc.  │
    └───────────────────────────────────────────────────────┘
```

## Features

- **Multi-threaded Processing**: 5 dedicated threads for parallel stream processing
- **Automatic Table Rotation**: Creates future tables and drops expired ones
- **Configurable Retention**: Different retention periods per data type
- **Batching**: Efficient batch writes matching core-collection settings
- **Consumer Groups**: Redis consumer groups for reliable message processing
- **Deduplication**: Uses `ON DUPLICATE KEY UPDATE` with unique constraints
- **Metrics Logging**: Periodic metrics output for monitoring
- **Flexible Field Parsing**: Handles multiple field name variations (camelCase, snake_case, PascalCase)

## Redis Stream Message Format

The exporter reads from Redis streams where messages are stored with the JSON payload in a `message` field:

```
stream:devices
  msg_id: 1234567890-0
  msg_data: {'message': '{"deviceName": "router1", "deviceFQDN": "router1.example.com", ...}'}
```

The exporter parses this by checking for both `data` and `message` fields:
```python
if 'data' in msg_data:
    data = json.loads(msg_data['data'])
elif 'message' in msg_data:
    data = json.loads(msg_data['message'])
```

### Field Name Handling

The transform functions handle multiple field name variations to ensure compatibility:

| Target Field | Accepted Variations |
|--------------|---------------------|
| device_name | `deviceName`, `device_name`, `DeviceName`, `name`, `hostname` |
| uuid | `UUID`, `uuid`, `Id`, `id`, `_id` |
| service name | `name`, `Name`, `serviceName`, `service_name` |
| management_ip | `ManagementIpAddress`, `management_ip`, `ip`, `IP` |

If a unique key field is missing, the exporter generates a fallback value to prevent deduplication issues.

## Installation

### Prerequisites

1. Rapax core installation
2. Docker
3. MariaDB container

### Install MariaDB

```bash
cd /opt/rapax-cloud/installers
sudo ./install-mariadb.sh
```

### Install MariaDB Exporter

```bash
cd /opt/rapax-cloud/installers
sudo ./install-mariadb-exporter.sh
```

## Configuration

### Retention Configuration

Edit `/opt/rapax/etc/mariadb-exporter/rotate.cfg`:

```ini
[retention]
# Days to retain data per stream type
alerts = 30      # Keep alerts for 30 days
logs = 7         # Keep logs for 7 days
stats = 7        # Keep stats for 7 days
devices = 365    # Keep device history for 1 year
services = 365   # Keep service history for 1 year
```

### Batch Configuration

Edit `/opt/rapax/etc/mariadb-exporter/batch.cfg`:

```ini
[stream:alerts]
batch_size = 1    # Messages per Redis read
bulk_size = 1     # Records before DB write

[stream:logs]
batch_size = 5
bulk_size = 5

[stream:stats]
batch_size = 20
bulk_size = 100

[stream:devices]
batch_size = 1
bulk_size = 1

[stream:services]
batch_size = 1
bulk_size = 1
```

## Logging

All logs are written to `/opt/rapax/logs/mariadb-exporter.log`.

### View Logs

```bash
# Real-time logs
tail -f /opt/rapax/logs/mariadb-exporter.log

# Docker logs
docker logs -f rapax-mariadb-exporter
```

### Log Format

```
2026-01-30 10:30:00,123 - rapax-mariadb-exporter - INFO - [rapax-mariadb-exporter] Wrote 100 records to stats
2026-01-30 10:30:00,456 - rapax-mariadb-exporter - INFO - [rapax-mariadb-exporter] Metrics: {"records_processed": {...}, ...}
```

### Metrics

Metrics are logged every 60 seconds:

```json
{
  "records_processed": {"devices": 50, "stats": 10000, "alerts": 25, "logs": 500, "services": 10},
  "records_failed": {"devices": 0, "stats": 2, "alerts": 0, "logs": 0, "services": 0},
  "batches_written": {"devices": 50, "stats": 100, "alerts": 25, "logs": 100, "services": 10},
  "tables_created": 10,
  "tables_dropped": 5
}
```

## Database Schema

### devices_YYYY_MM_DD

| Column | Type | Description |
|--------|------|-------------|
| id | BIGINT | Auto-increment primary key |
| device_name | VARCHAR(255) | Unique device identifier |
| device_fqdn | VARCHAR(255) | Fully qualified domain name |
| device_description | TEXT | Device description |
| management_ip | VARCHAR(45) | Management IP address |
| device_category | VARCHAR(100) | Category (Router, Switch, etc.) |
| device_model | VARCHAR(255) | Device model |
| device_serial | VARCHAR(100) | Serial number |
| device_location | VARCHAR(255) | Physical location |
| vendor | VARCHAR(100) | Vendor name |
| source | VARCHAR(100) | Data source |
| last_seen | DATETIME(6) | Last seen timestamp |
| security_info | JSON | Security information |
| interfaces | JSON | Interface details |
| tags | JSON | Tags array |
| created_at | DATETIME(6) | Record creation time |
| updated_at | DATETIME(6) | Last update time |

### stats_YYYY_MM_DD

| Column | Type | Description |
|--------|------|-------------|
| id | BIGINT | Auto-increment primary key |
| device_name | VARCHAR(255) | Device identifier |
| metric_name | VARCHAR(255) | Metric name |
| value | DOUBLE | Metric value |
| tags | JSON | Tags dictionary |
| timestamp | DATETIME(6) | Metric timestamp |
| created_at | DATETIME(6) | Record creation time |

### alerts_YYYY_MM_DD

| Column | Type | Description |
|--------|------|-------------|
| id | BIGINT | Auto-increment primary key |
| uuid | VARCHAR(36) | Unique alert identifier |
| device | VARCHAR(255) | Device name |
| interface | VARCHAR(255) | Interface name |
| ip | VARCHAR(45) | IP address |
| status | VARCHAR(50) | Alert status (Critical, Major, etc.) |
| state | VARCHAR(10) | State (Up/Down) |
| category | VARCHAR(100) | Alert category |
| source | VARCHAR(100) | Alert source |
| location | VARCHAR(255) | Location |
| description | TEXT | Alert description |
| first_occurred | DATETIME(6) | First occurrence time |
| last_occurred | DATETIME(6) | Last occurrence time |
| count | INT | Occurrence count |
| device_type | VARCHAR(100) | Device type |
| parent | VARCHAR(255) | Parent device |
| notes | JSON | Notes array |
| tags | JSON | Tags array |
| alert_key | VARCHAR(500) | Deduplication key |
| created_at | DATETIME(6) | Record creation time |
| updated_at | DATETIME(6) | Last update time |

### logs_YYYY_MM_DD

| Column | Type | Description |
|--------|------|-------------|
| id | BIGINT | Auto-increment primary key |
| level | VARCHAR(20) | Log level (INFO, ERROR, etc.) |
| message | TEXT | Log message |
| source | VARCHAR(100) | Log source |
| device | VARCHAR(255) | Related device |
| application | VARCHAR(100) | Application name |
| agent | VARCHAR(100) | Agent identifier |
| ip_address | VARCHAR(45) | IP address |
| tags | TEXT | Tags string |
| process_id | INT | Process ID |
| thread | VARCHAR(100) | Thread name |
| event_type | VARCHAR(100) | Event type |
| username | VARCHAR(100) | Username |
| user_agent | TEXT | User agent |
| extra_data | JSON | Additional data |
| timestamp | DATETIME(6) | Log timestamp |
| created_at | DATETIME(6) | Record creation time |

### services_YYYY_MM_DD

| Column | Type | Description |
|--------|------|-------------|
| id | BIGINT | Auto-increment primary key |
| name | VARCHAR(255) | Unique service name |
| description | TEXT | Service description |
| status | VARCHAR(50) | Status (OK, Problem) |
| health | VARCHAR(50) | Health status |
| children | JSON | Child services array |
| parents | JSON | Parent services array |
| source | VARCHAR(100) | Data source |
| last_seen | DATETIME(6) | Last seen timestamp |
| tags | JSON | Tags array |
| created_at | DATETIME(6) | Record creation time |
| updated_at | DATETIME(6) | Last update time |

## Querying Data

### Connect to MariaDB

```bash
docker exec -it rapax-mariadb mariadb -urapax -p rapax
```

### Example Queries

```sql
-- List all tables
SHOW TABLES;

-- Count records in today's alerts table
SELECT COUNT(*) FROM alerts_2026_01_30;

-- Get recent alerts
SELECT device, interface, status, state, description, last_occurred
FROM alerts_2026_01_30
ORDER BY last_occurred DESC
LIMIT 10;

-- Get device statistics
SELECT device_name, metric_name, AVG(value) as avg_value, MAX(value) as max_value
FROM stats_2026_01_30
WHERE metric_name LIKE '%CPU%'
GROUP BY device_name, metric_name;

-- Get devices by category
SELECT device_category, COUNT(*) as count
FROM devices_2026_01_30
GROUP BY device_category;
```

## Troubleshooting

### Container Not Starting

```bash
# Check container status
docker ps -a | grep mariadb-exporter

# View container logs
docker logs rapax-mariadb-exporter

# Check if MariaDB is accessible
docker exec rapax-mariadb-exporter python3 -c "
import mysql.connector
conn = mysql.connector.connect(
    host='rapax-mariadb',
    user='rapax',
    password='<password>'
)
print('Connected!')
"
```

### No Data in Tables

1. Check if Redis streams have data:
```bash
docker exec rapax-redis redis-cli XLEN stream:alerts
```

2. Check consumer group status:
```bash
docker exec rapax-redis redis-cli XINFO GROUPS stream:alerts
```

3. Check exporter logs for errors:
```bash
grep -i error /opt/rapax/logs/mariadb-exporter.log
```

### Only 1 Row Per Table (Deduplication Issue)

If all records are being treated as duplicates (e.g., 200 records processed but only 1 row in table):

1. Check the DEBUG logs to see what field names are in the data:
```bash
docker logs rapax-mariadb-exporter 2>&1 | grep "DEBUG.*parsed data keys"
```

2. Verify the message field is being parsed correctly:
```bash
docker logs rapax-mariadb-exporter 2>&1 | grep "DEBUG.*msg_data keys"
# Should show: ['message'] or ['data']
# After parsing, should show actual field names like: ['deviceName', 'deviceFQDN', ...]
```

3. If parsed data keys only shows `['message']`, the JSON is not being extracted. The exporter checks for both `data` and `message` fields in the Redis stream message.

4. Check for "missing name" warnings which indicate fallback values are being used:
```bash
docker logs rapax-mariadb-exporter 2>&1 | grep "missing"
```

### Reset Consumer Groups

To reprocess all messages from the beginning:
```bash
REDIS_PASS=$(grep requirepass /opt/rapax/etc/redis.conf | awk '{print $2}')
for stream in devices stats alerts logs services; do
  docker exec rapax-redis redis-cli -a "$REDIS_PASS" XGROUP DESTROY stream:$stream rapax_mariadb_exporter
done
# Then restart the exporter
docker restart rapax-mariadb-exporter
```

### Tables Not Being Created

Check the rotation thread in logs:
```bash
grep -i "Table rotation" /opt/rapax/logs/mariadb-exporter.log
```

### High Memory Usage

Reduce batch sizes in `/opt/rapax/etc/mariadb-exporter/batch.cfg`:
```ini
[stream:stats]
batch_size = 10
bulk_size = 50
```

## Management Commands

```bash
# Restart exporter
docker restart rapax-mariadb-exporter

# Stop exporter
docker stop rapax-mariadb-exporter

# Remove exporter
docker rm -f rapax-mariadb-exporter

# Rebuild and reinstall
cd /opt/rapax-cloud/integration-mariadb-exporter
./build-and-push.sh --local
cd /opt/rapax-cloud/installers
sudo ./install-mariadb-exporter.sh
```

## Extending the Exporter

### Adding New Streams

1. Add stream name to `STREAMS` list in the daemon
2. Add table schema to `TABLE_SCHEMAS`
3. Add INSERT statement to `INSERT_STATEMENTS`
4. Add transform function `_transform_<stream>`
5. Update retention defaults

### Custom Metrics

The exporter logs metrics every 60 seconds. To add custom metrics:

1. Add fields to the `Metrics` dataclass
2. Update `to_dict()` method
3. Increment metrics in appropriate locations

## Version History

- **1.0.0** - Initial release
  - Multi-threaded stream processing
  - Date-based table partitioning
  - Automatic rotation and retention
  - Configurable batching
