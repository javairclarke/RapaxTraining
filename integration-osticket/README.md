# Rapax OSTicket Integration

Automatic ticket creation, bidirectional notes synchronization, and alert status tracking between Rapax and OSTicket.

## Features

- **Automatic Ticket Creation**: Creates OSTicket tickets from Rapax alerts with empty `Ticket` tags
- **Bidirectional Notes Sync**: Notes added in Rapax flow to OSTicket, and notes added in OSTicket flow back to Rapax
- **Alert Clear Notifications**: When an alert clears (Status changes to "Up" or "Clear"), the associated ticket is updated with a notification
- **API Key IP Auto-Correction**: Automatically updates the API key IP in OSTicket when the container IP changes (common after Docker restarts)

## Prerequisites

- Rapax core installation (`/opt/rapax/lib/rapax.py`)
- OSTicket installed and configured (run `install-osticket.sh`)
- Redis container running (`rapax-redis`)
- Docker network `rapax-dev-network`
- Ticket configuration at `/opt/rapax/etc/ticket.cfg`
- Encrypted credentials at `/opt/rapax/etc/credentials` (contains MySQL root password)

## Installation

### Using the Installer (Recommended)

```bash
sudo /opt/rapax/installers/integration-osticket-install.sh
```

The installer will:
- Verify prerequisites (Redis, OSTicket, network)
- Allow you to review/edit `ticket.cfg`
- Build the container from local source (if available) or pull from registry
- Start the container with proper mounts and network configuration

### Manual Installation

```bash
# Build the image locally
cd /path/to/rapax-cloud/rapax-integration-osticket
docker build -t ghcr.io/citus-cloud/integration-osticket:latest .

# Run the container
docker run -d \
  --name rapax-integration-osticket \
  --hostname "$(hostname)" \
  --network rapax-dev-network \
  -v /opt/rapax/lib:/opt/rapax/lib:ro \
  -v /opt/rapax/etc:/opt/rapax/etc:ro \
  -v /opt/rapax/logs:/opt/rapax/logs \
  -v /etc/machine-id:/etc/machine-id:ro \
  -e RAPAXHOME=/opt/rapax \
  -e RAPAX_HOME=/opt/rapax \
  -e DAEMON_INTERVAL=60 \
  --restart unless-stopped \
  ghcr.io/citus-cloud/integration-osticket:latest
```

## Configuration

### ticket.cfg

Located at `$RAPAXHOME/etc/ticket.cfg` (created by `install-osticket.sh`):

```yaml
ticketing:
  # OSTicket server connection (internal Docker network)
  host: "rapax-ticketing:80"
  external_host: "192.168.1.100:8080"

  # API authentication
  api_key: "your-64-character-api-key"

  # Ticket creation format
  ticket_format:
    subject: "Alert: <Device> - <Description>"
    message: |
      Device: <Device>
      Interface: <Interface>
      Description: <Description>
      Status: <Status>
      Category: <Category>
      Location: <Location>
      IP Address: <IP>
      First Occurred: <FirstOccurred>
      Last Occurred: <LastOccurred>
      Alert UUID: <UUID>
    email: "alerts@rapax.local"
    name: "Rapax System"
    phone: ""
    topicId: 1
    department: 1

daemon:
  interval: 60
  log_level: INFO
  max_tickets_per_cycle: 10
```

### Template Variables

The following variables are replaced in `subject` and `message` templates:

| Variable | Description |
|----------|-------------|
| `<Device>` | Device name/hostname |
| `<Interface>` | Interface identifier |
| `<Description>` | Alert description |
| `<Status>` | Alert status (Critical, Major, etc.) |
| `<Category>` | Alert category |
| `<Location>` | Device location |
| `<DeviceType>` | Type of device |
| `<IP>` | IP address |
| `<FirstOccurred>` | First occurrence timestamp |
| `<LastOccurred>` | Last occurrence timestamp |
| `<UUID>` | Alert unique identifier |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RAPAXHOME` | `/opt/rapax` | Rapax installation directory |
| `RAPAX_HOME` | `/opt/rapax` | Alias for RAPAXHOME |
| `DAEMON_INTERVAL` | `60` | Polling interval in seconds |
| `LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |

## How It Works

### Alert Tag Format

For an alert to have a ticket created, it must have a `Ticket` tag with an empty value:

```json
{
  "UUID": "alert-12345",
  "Device": "router-01",
  "Description": "Interface down",
  "Status": "Critical",
  "Tags": [
    {"Ticket": ""}
  ]
}
```

After ticket creation, the tag is updated with the ticket number:

```json
{
  "Tags": [
    {"Ticket": "646123"}
  ]
}
```

### Processing Cycle

Each daemon cycle (default: every 60 seconds) performs three operations:

1. **Ticket Creation**: Scans for alerts with empty `Ticket` tags and creates OSTicket tickets
2. **Notes Sync**: Synchronizes notes bidirectionally between Rapax alerts and their linked OSTicket tickets
3. **Clear Detection**: Detects alerts that have cleared and posts notifications to their tickets

### Ticket Creation Flow

1. Daemon scans Redis for `ALERT:*` keys
2. Checks each alert for `{"Ticket": ""}` tag
3. Formats ticket data using `ticket_format` template
4. POSTs to OSTicket JSON API (`/api/tickets.json`)
5. On success, updates alert tag to `{"Ticket": "123456"}`
6. Publishes alert update to Redis `alerts` channel

### Bidirectional Notes Sync

**Push (Rapax → OSTicket):**
- Notes in the alert's `Notes` array that don't have `SyncedToOSTicket: true` are pushed to OSTicket
- Notes are inserted directly into OSTicket's MySQL database (`ost_thread_entry` table)
- After successful push, the note is marked with `SyncedToOSTicket: true`
- Notes with `Source: "osticket"` are skipped (already came from OSTicket)

**Pull (OSTicket → Rapax):**
- Thread entries from OSTicket are pulled via MySQL query
- Entries already imported are tracked by `OSTicketEntryId`
- Entries that start with `[Rapax Note` or `[Rapax Alert Cleared]` are skipped (originated from Rapax)
- Imported notes are added to the alert's `Notes` array with `Source: "osticket"`

**Deduplication:**
- Push side: `SyncedToOSTicket` flag prevents re-pushing
- Pull side: `OSTicketEntryId` tracking prevents re-importing
- Origin detection: Body prefix and Source field prevent circular sync loops

### Alert Clear Notifications

When an alert's Status changes to "Up" or "Clear":
1. The daemon detects the status change
2. Posts an internal note to the linked OSTicket ticket with clear details
3. Sets `TicketCleared: "true"` tag on the alert to prevent duplicate notifications

Example notification posted to OSTicket:
```
[Rapax Alert Cleared]

The originating alert has been cleared.

Device: router-01
Status: Up
Description: Interface down
Cleared at: 2026-01-28T14:30:00.000Z
```

### API Key IP Auto-Correction

Docker assigns new IP addresses when containers are recreated. OSTicket validates API requests against the IP stored in `ost_api_key`. On startup, the daemon:

1. Detects the container's current IP address
2. Queries `ost_api_key` for the Rapax API key
3. Updates the IP address if it has changed
4. Logs the change for debugging

This prevents 401 errors after container restarts.

## Building

```bash
cd rapax-integration-osticket

# Build locally
./build-and-push.sh

# Build with specific version
./build-and-push.sh 1.0.0
```

## Container Management

```bash
# View logs (follow mode)
docker logs -f rapax-integration-osticket

# View recent logs
docker logs rapax-integration-osticket --tail 100

# View persistent log file
docker exec rapax-integration-osticket cat /opt/rapax/logs/osticket-agentd.log

# Restart
docker restart rapax-integration-osticket

# Stop
docker stop rapax-integration-osticket

# Remove
docker rm -f rapax-integration-osticket

# Check health
docker inspect --format='{{.State.Health.Status}}' rapax-integration-osticket

# Re-run installer (rebuilds from source)
sudo /opt/rapax/installers/integration-osticket-install.sh
```

## Troubleshooting

### Container won't start

Check that required mounts exist:
```bash
ls -la /opt/rapax/lib/rapax.py
ls -la /opt/rapax/etc/ticket.cfg
ls -la /opt/rapax/etc/credentials
```

Verify the Docker network exists:
```bash
docker network ls | grep rapax
```

### No tickets being created

1. Verify OSTicket is accessible from the container:
   ```bash
   docker exec rapax-integration-osticket curl -I http://rapax-ticketing/api/tickets.json
   ```

2. Check API key is configured in OSTicket admin panel:
   - Log into `http://<host>/scp/`
   - Navigate to: Admin Panel > Manage > API Keys
   - Ensure API key exists with "Can Create Tickets" enabled

3. Verify alerts have empty Ticket tag:
   ```bash
   docker exec rapax-redis redis-cli GET "ALERT:your-alert-key" | python3 -m json.tool
   ```

4. Check daemon logs for errors:
   ```bash
   docker logs rapax-integration-osticket --tail 100 | grep -i error
   ```

### API key 401 errors

The daemon auto-corrects the API key IP on startup. If you still get 401 errors:

1. Check the startup log for IP correction:
   ```bash
   docker logs rapax-integration-osticket | grep "API key IP"
   ```

2. Manually verify the IP in OSTicket database:
   ```bash
   docker exec rapax-ticketing-mysql mysql -u root -p osticket \
     -e "SELECT ipaddr, notes FROM ost_api_key WHERE isactive=1"
   ```

3. Ensure the container can reach MySQL:
   ```bash
   docker exec rapax-integration-osticket python3 -c "import pymysql; print('PyMySQL OK')"
   ```

### Notes not syncing

1. Check that the alert has an associated ticket:
   ```bash
   docker exec rapax-redis redis-cli GET "ALERT:your-alert-key" | grep -o '"Ticket":"[^"]*"'
   ```

2. Verify MySQL connectivity (notes sync uses direct MySQL access):
   ```bash
   docker logs rapax-integration-osticket | grep -i "mysql\|thread\|note"
   ```

3. Check for sync activity in logs:
   ```bash
   docker logs rapax-integration-osticket | grep -i "sync\|pull\|posted note"
   ```

4. Verify the credentials file contains MySQL password:
   ```bash
   # The encrypted credentials should include ticketing.mysql_root_password
   ls -la /opt/rapax/etc/credentials
   ```

### Clear notifications not appearing

1. Verify the alert status is "Up" or "Clear":
   ```bash
   docker exec rapax-redis redis-cli GET "ALERT:your-alert-key" | grep -o '"Status":"[^"]*"'
   ```

2. Check if already notified (TicketCleared tag):
   ```bash
   docker exec rapax-redis redis-cli GET "ALERT:your-alert-key" | grep TicketCleared
   ```

3. Look for clear detection in logs:
   ```bash
   docker logs rapax-integration-osticket | grep -i "clear"
   ```

### Viewing OSTicket thread entries directly

To debug note sync issues, query the OSTicket database directly:

```bash
docker exec rapax-ticketing-mysql mysql -u root -p osticket -e "
  SELECT te.id, te.poster, te.type, te.created, LEFT(te.body, 50) as body_preview
  FROM ost_thread_entry te
  JOIN ost_thread t ON te.thread_id = t.id
  JOIN ost_ticket tk ON t.object_id = tk.ticket_id AND t.object_type = 'T'
  WHERE tk.number = '646123'
  ORDER BY te.created DESC
  LIMIT 10;
"
```

### Common log messages

| Message | Meaning |
|---------|---------|
| `Posted note to ticket X (thread_id=Y)` | Successfully pushed a note to OSTicket |
| `Pulled note #X from ticket Y` | Successfully imported a note from OSTicket |
| `Posted clear notification to ticket X` | Alert cleared, ticket was notified |
| `API key IP already correct` | No IP update needed on startup |
| `Updated API key IP from X to Y` | IP was corrected after container restart |
| `Ticket X not found in database` | Ticket number doesn't exist in OSTicket |
| `Thread not found for ticket X` | Database inconsistency (ticket exists but no thread) |

## Files

| File | Description |
|------|-------------|
| `Dockerfile` | Container build definition |
| `build-and-push.sh` | Build and push to GHCR |
| `entrypoint.sh` | Container startup script |
| `healthcheck.sh` | Health check script |
| `osticket-agentd.py` | Main integration daemon |
| `requirements.txt` | Python dependencies (redis, requests, pyyaml, pymysql, cryptography, opensearch-py, pytz) |

## Database Schema Reference

The daemon interacts with these OSTicket tables:

| Table | Purpose |
|-------|---------|
| `ost_ticket` | Main ticket table; `number` is external ID, `ticket_id` is internal |
| `ost_thread` | Links threads to tickets via `object_id` and `object_type='T'` |
| `ost_thread_entry` | Contains notes, responses, messages; `type='N'` for internal notes |
| `ost_api_key` | API key configuration including IP restrictions |

## Related

- `installers/install-osticket.sh` - Install OSTicket and MySQL containers
- `installers/integration-osticket-install.sh` - Install this integration container
- `rapax-core-api/html/alert-info.html` - Alert info popup (uses UUID for fresh data)
