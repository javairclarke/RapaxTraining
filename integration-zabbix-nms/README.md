# Rapax Zabbix NMS Integration

This integration collects data from Zabbix NMS via REST API and publishes it to Rapax Redis streams.

## Architecture

```
┌─────────────────────┐
│  Zabbix NMS Server  │
│   (REST API)        │
└─────────┬───────────┘
          │ Poll every 60s (configurable)
          ▼
┌─────────────────────────────────────────┐
│   integration-zabbix-nms Container      │
│                                         │
│   zabbix-data-processord.py             │
│   - Fetches hosts -> stream:devices     │
│   - Fetches items -> stream:stats       │
│   - Fetches services -> stream:services │
│   - Sends heartbeat -> stream:alerts    │
└─────────┬───────────────────────────────┘
          │
          ▼
┌─────────────────────┐
│    Rapax Redis      │
│  (Stream Queues)    │
└─────────────────────┘
          │
          ▼
┌─────────────────────┐
│ rapax-core-collection│
│ (Indexes to OpenSearch)
└─────────────────────┘
```

## Data Flow

### Devices (stream:devices)
Zabbix hosts are mapped to Rapax devices using the standard schema:

```python
device_data = {
    '@timestamp': timestamp,
    'deviceName': hostname,
    'deviceFQDN': host_display_name,
    'deviceDescription': description,
    'ManagementIpAddress': ip_address,
    'deviceCategory': category,  # Inferred from groups/templates
    'deviceModel': inventory_model,
    'deviceSerialNumber': inventory_serial,
    'deviceLocation': inventory_location,
    'vendor': inventory_vendor,
    'source': 'Zabbix',
    'lastSeen': timestamp,
    'securityInformation': [],
    'interfaces': [],
    'tags': [
        {'name': 'Source', 'value': 'Zabbix'},
        {'name': 'ZabbixHostId', 'value': hostid},
        {'name': 'ZabbixGroup', 'value': group_name}
    ]
}
```

**Device Category Detection**: Category is inferred from Zabbix groups and templates:
- Groups/templates containing "server", "linux", "windows" → `Server`
- "switch" → `Switch`
- "router" → `Router`
- "firewall" → `Firewall`
- "ap", "wireless", "access point" → `AP`
- "storage", "nas" → `NAS`
- Default fallback → `Unknown`

### Stats (stream:stats)
Numeric items matching network equipment patterns are collected:
- CPU/Memory utilization
- Interface traffic (in/out octets)
- Interface errors/discards
- ICMP availability (ping, latency, loss)
- SNMP uptime and descriptions

**Important**: Template items are filtered out. Items from hosts starting with "Template " are skipped to avoid polluting stats with non-device data.

Stats format:
```python
stat_data = {
    '@timestamp': timestamp,
    'deviceName': hostname,
    'metricName': item_name,
    'value': float_value,
    'tags': {
        'componentId': COMPONENT_ID,
        'source': 'Zabbix',
        'zabbixItemId': item_id,
        'units': item_units
    }
}
```

### Services (stream:services)
Zabbix services are mapped to Rapax services:
- Name, description, status
- Parent/child relationships
- Tags

### Heartbeat (stream:alerts)
Every poll cycle sends a heartbeat alert:
- **Success**: State=Up, Status=Clear
- **Failure**: State=Down, Status=Critical with error message
- Device=<component-id>, Category=heartbeat

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `POLL_INTERVAL` | 60 | Seconds between API polls |
| `COMPONENT_ID` | zabbix-nms-1 | Unique identifier for this instance |
| `CREDENTIALS_URL` | http://rapax-core-api:5004 | Credentials vault URL |
| `REDIS_HOST` | rapax-redis | Redis server hostname |
| `REDIS_PORT` | 6379 | Redis server port |
| `REDIS_PASSWORD` | - | Redis password |
| `ZABBIX_URL` | - | Zabbix API URL (fallback) |
| `ZABBIX_API_TOKEN` | - | API token (fallback) |
| `ZABBIX_USER` | Admin | Username (fallback) |
| `ZABBIX_PASSWORD` | - | Password (fallback) |

### Credentials Vault

Primary credential source: `custom/zabbix` in Rapax vault

```json
{
  "url": "http://rapax-zabbix:80/api_jsonrpc.php",
  "external_url": "http://localhost:8081/api_jsonrpc.php",
  "username": "Admin",
  "password": "<password>",
  "api_token": "<token>"
}
```

## Logging

Logs are written to:
- `/opt/rapax/logs/zabbix-data-processord.log` - Main application log
- `/opt/rapax/logs/zabbix-data-processord.err.log` - Error output
- `/opt/rapax/logs/zabbix-data-processord.out.log` - Standard output
- `/opt/rapax/logs/supervisord.log` - Supervisor log

Mount `$RAPAXHOME/logs` to persist logs on the Docker host.

## Installation

### Using the installer

```bash
# From the rapax-cloud repository
sudo ./installers/integrations/zabbix-nms.install.sh
```

### Manual Docker run

```bash
docker run -d \
  --name rapax-zabbix-nms \
  --network rapax-dev-network \
  --restart unless-stopped \
  -v /opt/rapax/logs:/opt/rapax/logs \
  -v /opt/rapax/lib:/opt/rapax/lib:ro \
  -v /opt/rapax/etc:/opt/rapax/etc:ro \
  -e REDIS_HOST=rapax-redis \
  -e REDIS_PASSWORD="$REDIS_PASSWORD" \
  -e POLL_INTERVAL=60 \
  -e COMPONENT_ID=zabbix-nms-1 \
  ghcr.io/citus-cloud/integration-zabbix-nms:latest
```

## Device Alignment

Devices are created in Rapax with:
- **Source**: `Zabbix` - identifies the data source
- **Tags**: `Source=Zabbix`, `ZabbixHostId=<id>` for correlation

To configure which devices are collected:
1. Configure Zabbix network discovery (see install-zabbix.sh)
2. Discovered hosts automatically appear in stream:devices
3. Existing devices (by hostname) are skipped

## Extending

### Adding new item keys

Edit `NETWORK_ITEM_KEYS` in `zabbix-data-processord.py`:

```python
NETWORK_ITEM_KEYS = [
    'system.cpu.util',
    'vm.memory.utilization',
    # Add your custom keys here
    'custom.metric.key',
]
```

### Custom device mapping

Modify `process_hosts()` to add additional device fields:

```python
device_data = {
    # ... existing fields
    'customField': host.get('inventory', {}).get('custom_field', ''),
}
```

## Zabbix Version Compatibility

### Zabbix 4.x Notes
- **API Authentication**: `apiinfo.version` must be called WITHOUT auth token
- **Global Macros**: Use `usermacro.createglobal`/`updateglobal`/`deleteglobal` methods
- **User field**: Use `user` instead of `username` for authentication
- **API Tokens**: Not supported; use session-based auth with username/password

### Zabbix 5.x+ Notes
- Standard `usermacro.create` works for global macros
- Use `username` field for authentication
- API tokens supported

## Troubleshooting

### Check container logs
```bash
docker logs rapax-zabbix-nms
```

### Check application logs
```bash
tail -f /opt/rapax/logs/zabbix-data-processord.log
```

### Verify Redis streams
```bash
docker exec rapax-redis redis-cli -a "$REDIS_PASSWORD" XLEN stream:devices
docker exec rapax-redis redis-cli -a "$REDIS_PASSWORD" XLEN stream:stats
docker exec rapax-redis redis-cli -a "$REDIS_PASSWORD" XLEN stream:services
```

### Check heartbeat alerts
```bash
docker exec rapax-redis redis-cli -a "$REDIS_PASSWORD" KEYS "ALERT:zabbix-nms*"
```

### Test Zabbix API connection
```bash
docker exec rapax-zabbix-nms python3 -c "
import sys
sys.path.append('/opt/rapax/lib')
from zabbix_data_processord import *
setup_logging()
creds = load_zabbix_credentials()
print(f'URL: {creds[\"url\"]}')
zabbix = ZabbixClient(
    url=creds['url'],
    api_token=creds.get('api_token'),
    username=creds.get('username'),
    password=creds.get('password')
)
zabbix.login()
print(f'API Version: {zabbix.get_api_version()}')
print(f'Hosts: {len(zabbix.get_hosts())}')
"
```

## Build

```bash
cd integration-zabbix-nms
./build-and-push.sh --local  # Local build only
./build-and-push.sh          # Build and push to registry
```
