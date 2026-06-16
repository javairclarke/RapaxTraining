# Rapax Zabbix Webhook Integration

This integration receives real-time alerts from Zabbix via webhook and publishes them to Rapax Redis streams.

## Architecture

```
┌─────────────────────────────────────────┐
│         Zabbix NMS Server               │
│                                         │
│  Trigger fires -> Media Type -> Webhook │
└─────────────────┬───────────────────────┘
                  │ HTTP POST (real-time)
                  ▼
┌─────────────────────────────────────────┐
│   integration-zabbix-webhook Container  │
│                                         │
│   zabbix-webhook-processord.py          │
│   - POST /webhook                       │
│   - Maps severity to Rapax format       │
│   - Publishes to stream:alerts          │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│            Rapax Redis                  │
│         (stream:alerts)                 │
└─────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│      rapax-core-correlation             │
│   (Alert processing & OpenSearch)       │
└─────────────────────────────────────────┘
```

## Webhook Payload Format

The webhook expects JSON with Zabbix macros expanded:

```json
{
    "event_id": "{EVENT.ID}",
    "trigger_id": "{TRIGGER.ID}",
    "host": "{HOST.NAME}",
    "host_ip": "{HOST.IP}",
    "trigger_name": "{TRIGGER.NAME}",
    "trigger_severity": "{TRIGGER.SEVERITY}",
    "trigger_status": "{TRIGGER.STATUS}",
    "event_value": "{EVENT.VALUE}",
    "event_date": "{EVENT.DATE}",
    "event_time": "{EVENT.TIME}",
    "item_name": "{ITEM.NAME}",
    "item_value": "{ITEM.VALUE}",
    "event_tags": "{EVENT.TAGS}"
}
```

## Severity Mapping

| Zabbix Severity | Code | Rapax Status | Rapax State |
|-----------------|------|--------------|-------------|
| Not classified  | 0    | Info         | Down        |
| Information     | 1    | Info         | Down        |
| Warning         | 2    | Warning      | Down        |
| Average         | 3    | Minor        | Down        |
| High            | 4    | Major        | Down        |
| Disaster        | 5    | Critical     | Down        |
| RESOLVED        | -    | Clear        | Up          |

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/webhook` | POST | Receive Zabbix alerts |
| `/webhook/test` | POST/GET | Create test alert |
| `/health` | GET | Health check |
| `/api/v1/health` | GET | Health check (standard) |
| `/` | GET | Service info |

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBHOOK_PORT` | 6543 | Port for webhook receiver |
| `COMPONENT_ID` | zabbix-webhook-1 | Unique identifier |
| `REDIS_HOST` | rapax-redis | Redis server hostname |
| `REDIS_PORT` | 6379 | Redis server port |
| `REDIS_PASSWORD` | - | Redis password |
| `CREDENTIALS_URL` | http://rapax-core-api:5004 | Vault URL |

### Configuring Zabbix

Use the configuration script to set up Zabbix:

```bash
# From inside the container
docker exec rapax-zabbix-webhook python3 /opt/rapax/bin/configure-zabbix.py

# Options:
#   --webhook-url URL    Override webhook URL
#   --dry-run            Show what would be done
#   --cleanup            Remove webhook configuration
```

The script creates:
1. Global macro `{$RAPAX_WEBHOOK_URL}` with webhook URL
2. Webhook media type with JavaScript handler
3. User `rapax-webhook` with media configured
4. Action `Rapax Webhook Alerts` for all triggers

### Manual Zabbix Configuration

If you prefer manual configuration:

1. **Create Media Type** (Administration -> Media types):
   - Name: Rapax Webhook
   - Type: Webhook
   - Script: (see `configure-zabbix.py` for script)
   - Parameters: (see `WEBHOOK_PARAMS` in script)

2. **Create User** (Administration -> Users):
   - Username: rapax-webhook
   - Groups: Zabbix administrators
   - Media: Rapax Webhook, sendto: rapax

3. **Create Action** (Configuration -> Actions):
   - Name: Rapax Webhook Alerts
   - Conditions: (leave empty for all triggers)
   - Operations: Send message to rapax-webhook user

## Zabbix Version Compatibility

### Zabbix 4.x Webhook Script
Zabbix 4.x uses Duktape JavaScript engine with different APIs:
- Use `CurlHttpRequest` instead of `HttpRequest`
- Methods are capitalized: `AddHeader()`, `Post()` instead of `addHeader()`, `post()`
- `Zabbix.log()` is NOT available

```javascript
// Zabbix 4.x compatible webhook script
var req = new CurlHttpRequest();
req.AddHeader('Content-Type: application/json');
var resp = req.Post(url, JSON.stringify(payload));
```

### Zabbix 5.x+ Webhook Script
Uses the standard JavaScript HttpRequest:
```javascript
var req = new HttpRequest();
req.addHeader('Content-Type: application/json');
var resp = req.post(url, JSON.stringify(payload));
Zabbix.log(4, 'Response: ' + resp);
```

## Logging

Logs are written to:
- `/opt/rapax/logs/zabbix-webhook-processord.log` - Main application log
- `/opt/rapax/logs/zabbix-webhook-processord.err.log` - Error output
- `/opt/rapax/logs/zabbix-webhook-processord.out.log` - Standard output

Mount `$RAPAXHOME/logs` to persist logs on the Docker host.

## Installation

### Using the installer

```bash
sudo ./installers/integrations/zabbix-webhook.install.sh
```

### Manual Docker run

```bash
docker run -d \
  --name rapax-zabbix-webhook \
  --network rapax-dev-network \
  --restart unless-stopped \
  -p 6543:6543 \
  -v /opt/rapax/logs:/opt/rapax/logs \
  -v /opt/rapax/lib:/opt/rapax/lib:ro \
  -v /opt/rapax/etc:/opt/rapax/etc:ro \
  -e REDIS_HOST=rapax-redis \
  -e REDIS_PASSWORD="$REDIS_PASSWORD" \
  -e WEBHOOK_PORT=6543 \
  -e COMPONENT_ID=zabbix-webhook-1 \
  ghcr.io/citus-cloud/integration-zabbix-webhook:latest
```

## Testing

### Test endpoint

```bash
# Create test alert
curl -X POST http://localhost:6543/webhook/test

# Manual webhook test
curl -X POST http://localhost:6543/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "event_id": "12345",
    "trigger_id": "67890",
    "host": "test-server",
    "host_ip": "192.168.1.100",
    "trigger_name": "High CPU usage",
    "trigger_severity": "4",
    "trigger_status": "PROBLEM",
    "event_value": "1",
    "event_date": "2025.01.15",
    "event_time": "14:30:00",
    "item_name": "CPU utilization",
    "item_value": "95.5",
    "event_tags": "cpu:high"
  }'
```

### Verify alerts in Redis

```bash
docker exec rapax-redis redis-cli -a "$REDIS_PASSWORD" \
  XRANGE stream:alerts - + COUNT 5
```

## Troubleshooting

### Check container logs
```bash
docker logs rapax-zabbix-webhook
```

### Check application logs
```bash
tail -f /opt/rapax/logs/zabbix-webhook-processord.log
```

### Test connectivity
```bash
curl http://localhost:6543/health
```

### Verify Zabbix can reach webhook
From Zabbix server:
```bash
curl -X POST http://rapax-zabbix-webhook:6543/webhook/test
```

### Debug webhook reception
Enable debug logging:
```bash
docker exec rapax-zabbix-webhook sh -c \
  'export LOG_LEVEL=DEBUG && python3 /opt/rapax/bin/zabbix-webhook-processord.py'
```

## Build

```bash
cd integration-zabbix-webhook
./build-and-push.sh --local  # Local build only
./build-and-push.sh          # Build and push to registry
```
