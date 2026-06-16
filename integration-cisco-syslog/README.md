# Cisco Syslog Integration for Rapax

Processes Cisco syslog messages from network devices and routes them to Rapax for alerting and logging.

## Overview

The Cisco Syslog Integration reads syslog messages from `/var/log/messages`, identifies Cisco-format messages (`%FACILITY-SEVERITY-MNEMONIC`), and routes them to Redis streams based on severity and actionability.

### Architecture

```
Cisco Devices (UDP 514)
         │
         ▼
┌─────────────────────┐
│  rsyslog (host)     │
│  /var/log/messages  │
└─────────────────────┘
         │ (volume mount, read-only)
         ▼
┌─────────────────────────────────────────┐
│  Docker: integration-cisco-syslog       │
│                                         │
│  cisco-syslog-processord.py             │
│  ├─ Multi-platform format detection     │
│  │   ├─ IOS, IOS-XE                     │
│  │   ├─ NX-OS                           │
│  │   ├─ IOS-XR                          │
│  │   └─ Meraki                          │
│  ├─ 200+ syslog message definitions     │
│  ├─ Hybrid severity mapping             │
│  └─ Alert/Log routing                   │
└─────────────────────────────────────────┘
         │
         ▼
┌─────────────────────┐
│  Redis Streams      │
│  ├─ stream:alerts   │ → core-correlation
│  └─ stream:logs     │ → core-collection
└─────────────────────┘
```

### Supported Platforms

| Platform | Syslog Format Example |
|----------|----------------------|
| **IOS/IOS-XE** | `*Mar  1 00:00:00.000: %LINK-3-UPDOWN: Interface Gi0/1...` |
| **NX-OS** | `2026 Feb  2 10:30:00 switch01 %LINK-3-UPDOWN: Interface Eth1/1...` |
| **IOS-XR** | `RP/0/RSP0/CPU0:Feb 2 10:30:00 : ifmgr[317]: %PKT_INFRA-LINK-3-UPDOWN...` |
| **rsyslog** | `Feb  2 10:30:00 10.1.1.5 %LINK-3-UPDOWN: Interface Gi0/1...` |
| **Meraki** | `Feb  2 10:30:00 meraki-ap %MERAKI-5-AP_CONNECT: AP connected...` |

### Message Categories

| Category | Facilities | Example Messages |
|----------|-----------|-----------------|
| **link-state** | LINK, LINEPROTO, PORT, ETHPORT | Interface up/down, transceiver events |
| **routing** | BGP, OSPF, EIGRP, ISIS, MPLS, BFD | Neighbor adjacency changes |
| **spanning-tree** | SPANTREE, STP, RSTP, MST, EC | Topology changes, port blocking |
| **security** | SEC_LOGIN, AUTHMGR, DOT1X, SSH | Login events, authentication |
| **hardware** | ENVMON, FAN, POWER, PLATFORM | Temperature, fan, power alerts |
| **redundancy** | HSRP, VRRP, STACKMGR, VPC | Failover events |
| **config** | SYS, CONFIG, PARSER | Configuration changes |
| **aaa** | TACACS, RADIUS, AAA | Authentication server events |
| **port-security** | PORTSEC, DHCP_SNOOPING, DAI | Security violations |
| **performance** | CPU, MEMORY, SYS | CPU hog, memory issues |
| **vpn** | CRYPTO, IPSEC, DMVPN, TUNNEL | VPN tunnel up/down |
| **wireless** | DOT11, CAPWAP, AP, MERAKI | AP events, client events |
| **qos** | QOS, POLICING, QUEUING | QoS policy events |

## Installation

### Prerequisites

- Rapax platform installed and running
- Docker installed
- rsyslog configured and running (typically installed with network-collection)
- Network devices configured to send syslog to this host

### Quick Install

```bash
sudo ./installers/integrations/cisco-syslog.install.sh
```

### Manual Install

1. **Build the container:**
   ```bash
   cd integration-cisco-syslog
   ./build-and-push.sh --local
   ```

2. **Run the container:**
   ```bash
   docker run -d \
       --name integration-cisco-syslog \
       --network rapax-dev-network \
       --restart unless-stopped \
       -v /var/log/messages:/var/log/messages:ro \
       -v /opt/rapax/lib:/opt/rapax/lib:ro \
       -v /opt/rapax/etc:/opt/rapax/etc:ro \
       -v /opt/rapax/logs:/opt/rapax/logs \
       -v /etc/machine-id:/etc/machine-id:ro \
       -e REDIS_HOST=rapax-redis \
       -e REDIS_PORT=6379 \
       -e REDIS_PASSWORD="your-password" \
       ghcr.io/citus-cloud/integration-cisco-syslog:latest
   ```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | rapax-redis | Redis server hostname |
| `REDIS_PORT` | 6379 | Redis server port |
| `REDIS_PASSWORD` | (empty) | Redis authentication password |
| `SYSLOG_FILE` | /var/log/messages | Path to syslog file |
| `COMPONENT_ID` | cisco-syslog-1 | Component identifier for metrics |
| `LOG_LEVEL` | INFO | Logging level (DEBUG, INFO, WARNING, ERROR) |

### rsyslog Configuration

To receive syslog from remote devices, ensure rsyslog is configured to accept UDP:

```bash
# /etc/rsyslog.conf
module(load="imudp")
input(type="imudp" port="514")
```

Then restart rsyslog:
```bash
sudo systemctl restart rsyslog
```

### Firewall Configuration

Open UDP port 514 for syslog:

```bash
# firewalld
sudo firewall-cmd --permanent --add-port=514/udp
sudo firewall-cmd --reload

# ufw
sudo ufw allow 514/udp
```

## Severity Mapping

### Cisco to Rapax Severity

| Cisco Level | Cisco Name | Rapax Severity | Actionable |
|-------------|------------|----------------|------------|
| 0 | Emergency | CRITICAL | Yes |
| 1 | Alert | CRITICAL | Yes |
| 2 | Critical | CRITICAL | Yes |
| 3 | Error | MAJOR | Yes |
| 4 | Warning | MINOR | Yes |
| 5 | Notice | WARNING | Selective |
| 6 | Informational | INFO | No (log only) |
| 7 | Debug | DEBUG | No (log only) |

### Clear Message Detection

Messages are identified as "clear" (recovery) based on:
1. Explicit `is_clear: True` in definition
2. Keywords in message: `up`, `restored`, `ok`, `active`, `established`

Clear messages set `State: Up` in alerts, while fault messages set `State: Down`.

## Alert Format

Alerts sent to Redis follow the Rapax standard:

```json
{
    "UUID": "unique-id",
    "Device": "switch-01",
    "Interface": "GigabitEthernet0/1",
    "IP": "10.1.1.5",
    "Status": "Major",
    "State": "Down",
    "Category": "link-state",
    "Description": "Interface link is down - LINK-UPDOWN",
    "FirstOccurred": "2026-02-02T10:30:00.000Z",
    "LastOccurred": "2026-02-02T10:30:00.000Z",
    "Number": 1,
    "DeviceType": "Network",
    "Tags": [
        {"Source": "cisco-syslog-processord"},
        {"Facility": "LINK"},
        {"Mnemonic": "UPDOWN"},
        {"ComponentID": "cisco-syslog-1"}
    ],
    "SyslogData": {
        "facility": "LINK",
        "cisco_severity": 3,
        "mnemonic": "UPDOWN",
        "message": "Interface GigabitEthernet0/1, changed state to down",
        "category": "link-state",
        "platform": "rsyslog"
    }
}
```

## Testing

### Test Sender

Send test syslog messages to validate the integration:

```bash
# Send all message types once
docker exec integration-cisco-syslog python3 /opt/rapax/bin/cisco-syslog-sender.py \
    --target $(hostname -I | awk '{print $1}'):514 --all

# Send specific category
docker exec integration-cisco-syslog python3 /opt/rapax/bin/cisco-syslog-sender.py \
    --target $(hostname -I | awk '{print $1}'):514 --category link-state

# Continuous mode (for load testing)
docker exec integration-cisco-syslog python3 /opt/rapax/bin/cisco-syslog-sender.py \
    --target $(hostname -I | awk '{print $1}'):514 --continuous --interval 5 --burst 10

# List available categories
docker exec integration-cisco-syslog python3 /opt/rapax/bin/cisco-syslog-sender.py --list-categories

# List all message types
docker exec integration-cisco-syslog python3 /opt/rapax/bin/cisco-syslog-sender.py --list-messages
```

### Data Collector

Collect raw syslog data for debugging:

```bash
# Collect for 60 seconds
docker exec integration-cisco-syslog python3 /opt/rapax/bin/cisco-syslog-collector.py \
    --duration 60

# Collect 100 messages
docker exec integration-cisco-syslog python3 /opt/rapax/bin/cisco-syslog-collector.py \
    --count 100

# Tail mode (continuous)
docker exec integration-cisco-syslog python3 /opt/rapax/bin/cisco-syslog-collector.py \
    --tail

# Scan existing messages
docker exec integration-cisco-syslog python3 /opt/rapax/bin/cisco-syslog-collector.py \
    --existing --lines 5000
```

## Logs

| Log File | Description |
|----------|-------------|
| `/opt/rapax/logs/cisco-syslog-processord.log` | Main processor log |
| `/opt/rapax/logs/cisco-syslog-processord-stdout.log` | Supervisor stdout |
| `/opt/rapax/logs/cisco-syslog-processord-stderr.log` | Supervisor stderr |
| `/opt/rapax/logs/supervisord.log` | Supervisor daemon log |

### Viewing Logs

```bash
# Container logs
docker logs integration-cisco-syslog

# Processor log
tail -f /opt/rapax/logs/cisco-syslog-processord.log

# Monitor incoming syslog
tail -f /var/log/messages | grep '%'
```

## Metrics

The processor logs metrics every 60 seconds:

```
Metrics - Processed: 1234, Alerts: 456, Logs: 789, Unknown: 12, Errors: 0
```

| Metric | Description |
|--------|-------------|
| `messages_processed` | Total Cisco syslog messages processed |
| `alerts_generated` | Alerts created/updated in Redis |
| `logs_generated` | Log entries sent to stream:logs |
| `unknown_messages` | Messages with unrecognized facility/mnemonic |
| `errors` | Processing errors |

## Extending

### Adding New Message Types

Edit `SYSLOG_DEFINITIONS` in `cisco-syslog-processord.py`:

```python
'NEWFACILITY-3-NEWMNEMONIC': {
    'facility': 'NEWFACILITY',
    'mnemonic': 'NEWMNEMONIC',
    'cisco_severity': 3,
    'description': 'Description of the message',
    'category': 'category-name',
    'actionable': True,  # True creates alerts, False logs only
    'clear_keywords': ['up', 'restored'],  # Optional
    'fault_keywords': ['down', 'failed'],  # Optional
    'is_clear': False  # Optional, explicitly marks as recovery
}
```

### Adding to Test Sender

Edit `SYSLOG_MESSAGES` in `cisco-syslog-sender.py`:

```python
{
    'key': 'NEWFACILITY-3-NEWMNEMONIC',
    'category': 'category-name',
    'messages': [
        'Message template with {interface} placeholder',
        'Another message variant'
    ],
    'interfaces': True,  # Use interface placeholders
    'peer_ip': True      # Use IP placeholders
}
```

## Directory Structure

```
integration-cisco-syslog/
├── bin/
│   ├── cisco-syslog-processord.py    # Main processor daemon
│   ├── cisco-syslog-sender.py        # Test syslog sender
│   └── cisco-syslog-collector.py     # Data collector for debugging
├── Dockerfile                        # Container build definition
├── supervisord.conf                  # Process manager config
├── docker-entrypoint.sh              # Container startup script
├── healthcheck.sh                    # Health check script
├── docker-compose.yml                # Deployment config
├── build-and-push.sh                 # Build script
├── requirements.txt                  # Python dependencies
└── README.md                         # This file
```

## Troubleshooting

### No messages being processed

1. **Check syslog file permissions:**
   ```bash
   ls -la /var/log/messages
   ```

2. **Verify rsyslog is receiving messages:**
   ```bash
   tail -f /var/log/messages | grep '%'
   ```

3. **Check container is running:**
   ```bash
   docker ps | grep cisco-syslog
   docker logs integration-cisco-syslog
   ```

4. **Verify Redis connection:**
   ```bash
   docker exec integration-cisco-syslog redis-cli -h rapax-redis ping
   ```

### High unknown message count

Unknown messages indicate syslog formats not in `SYSLOG_DEFINITIONS`. Check logs for the facility/mnemonic and add a definition.

```bash
grep "Unknown:" /opt/rapax/logs/cisco-syslog-processord.log
```

### Container keeps restarting

1. **Check logs for errors:**
   ```bash
   docker logs integration-cisco-syslog
   ```

2. **Verify rapax.py library is mounted:**
   ```bash
   docker exec integration-cisco-syslog ls -la /opt/rapax/lib/
   ```

3. **Check Redis connectivity:**
   ```bash
   docker exec integration-cisco-syslog python3 -c "import redis; r=redis.Redis(host='rapax-redis'); print(r.ping())"
   ```

## License

Rapax Integration - Cisco Syslog Processor
