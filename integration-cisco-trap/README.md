# Rapax Cisco Trap Integration

SNMP trap processor for Cisco network devices. Processes traps logged to syslog and generates alerts/logs for the Rapax platform.

## Overview

This integration monitors `/var/log/messages` on the Docker host for SNMP trap entries (tagged `snmptrap` by snmptrapd), parses them, and routes them to Redis streams for processing by Rapax core components.

### Supported Traps

The processor supports 72 trap types across these categories:

| Category | Description | Examples |
|----------|-------------|----------|
| **link-state** | Interface up/down events | linkDown, linkUp |
| **device-state** | Device reboot/restart | coldStart, warmStart |
| **routing** | BGP, OSPF, EIGRP events | bgpBackwardTransition, ospfNbrStateChange |
| **redundancy** | HSRP, VRRP failover | cHsrpStateChange, vrrpTrapNewMaster |
| **environment** | Temperature, fan, power | ciscoEnvMonTemperatureNotification |
| **config** | Configuration changes | ccmCLIRunningConfigChanged |
| **performance** | CPU/memory thresholds | cpmCPURisingThreshold |
| **security** | Auth failures, violations | authenticationFailure, ciscoSecureViolation |
| **wireless** | AP events, rogue detection | bsnAPDisassociated, bsnRogueAPDetected |
| **stack** | Stack member changes | cswStackNewMaster, cswStackMemberRemoved |
| **vpc** | Nexus vPC events | cVpcDualActiveDetected |
| **spanning-tree** | STP inconsistencies | stpxLoopInconsistencyUpdate |
| **hardware** | FRU insert/remove | cefcFRURemoved, cefcFRUInserted |
| **entity** | Entity configuration changes | entConfigChange |
| **snmp** | SNMP context errors | snmpUnavailableContexts, snmpUnknownContexts |

### Severity Mapping

| Severity | Description | Alert Status |
|----------|-------------|--------------|
| CRITICAL | Catastrophic outage (HA failover, dual-active, shutdown) | Critical |
| MAJOR | Service outage (linkDown, BGP down, AP down) | Major |
| MINOR | Service degradation (high CPU, errors) | Minor |
| WARNING | Potential issue (config change, auth failure) | Warning |
| CLEAR | Recovery message (linkUp, BGP established) | Clear |
| INFO | Informational (warmStart) | → Logs only |
| DEBUG | Debug level | → Logs only |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Docker Host                                  │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  snmptrapd (UDP 162) → logger -t snmptrap → /var/log/messages │  │
│  │  (installed by network-collection or cisco-trap installer)     │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                │                                     │
│                                ▼                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  integration-cisco-trap container                              │  │
│  │  ┌─────────────────────────────────────────────────────────┐  │  │
│  │  │  cisco-trap-processord.py                               │  │  │
│  │  │  - Tails /var/log/messages (read-only mount)            │  │  │
│  │  │  - Filters for snmptrap entries                         │  │  │
│  │  │  - Parses trap OID and varbinds                         │  │  │
│  │  │  - Maps to trap definitions (severity, category)        │  │  │
│  │  │  - Routes: Actionable → Alerts, Info/Debug → Logs       │  │  │
│  │  └─────────────────────────────────────────────────────────┘  │  │
│  │                            │                                   │  │
│  │                            ▼                                   │  │
│  │  rapax.send_message() → Redis Streams                          │  │
│  │    - stream:alerts (actionable events)                         │  │
│  │    - stream:logs (informational events)                        │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                │                                     │
│                                ▼                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  core-correlation → core-collection → OpenSearch               │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Docker host with snmptrapd and rsyslog installed
- Network devices configured to send SNMP traps to the Docker host (UDP 162)
- Rapax platform running (Redis, core-collection, etc.)

### Using the Installer

```bash
# Run the installer
sudo /opt/rapax/installers/integrations/cisco-trap.install.sh

# The installer will:
# 1. Verify/install snmptrapd
# 2. Verify/configure rsyslog
# 3. Ensure /var/log/messages exists
# 4. Configure snmptrapd to log traps via logger
```

### Manual Installation

1. **Install snmptrapd** (if not already installed):
   ```bash
   # Debian/Ubuntu
   apt-get install snmpd snmptrapd

   # RHEL/CentOS
   yum install net-snmp net-snmp-utils
   ```

2. **Configure snmptrapd** (`/etc/snmp/snmptrapd.conf`):
   ```
   # Accept traps from any source
   authCommunity log,execute,net public

   # Log all traps to syslog via logger
   traphandle default /usr/bin/logger -t snmptrap
   ```

3. **Start snmptrapd**:
   ```bash
   systemctl enable snmptrapd
   systemctl start snmptrapd
   ```

4. **Deploy the container**:
   ```bash
   docker-compose up -d
   ```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | rapax-redis | Redis server hostname |
| `REDIS_PORT` | 6379 | Redis server port |
| `REDIS_PASSWORD` | (empty) | Redis password (optional) |
| `SYSLOG_FILE` | /var/log/messages | Path to syslog file |
| `COMPONENT_ID` | cisco-trap-1 | Unique identifier for this processor |
| `LOG_LEVEL` | INFO | Logging level (DEBUG, INFO, WARNING, ERROR) |

### Volume Mounts

| Container Path | Host Path | Mode | Description |
|----------------|-----------|------|-------------|
| `/var/log/messages` | `/var/log/messages` | ro | Syslog file |
| `/opt/rapax/logs` | `$RAPAXHOME/logs` | rw | Processor logs |
| `/opt/rapax/lib` | `$RAPAXHOME/lib` | ro | rapax.py library |
| `/opt/rapax/etc` | `$RAPAXHOME/etc` | ro | Configuration/credentials |

## Running

### Using Docker Compose

```bash
cd /opt/rapax/integration-cisco-trap
docker-compose up -d
```

### Using Docker Run

```bash
docker run -d \
  --name rapax-cisco-trap \
  --network rapax-dev-network \
  -v /var/log/messages:/var/log/messages:ro \
  -v /opt/rapax/logs:/opt/rapax/logs \
  -v /opt/rapax/lib:/opt/rapax/lib:ro \
  -v /opt/rapax/etc:/opt/rapax/etc:ro \
  -e REDIS_HOST=rapax-redis \
  -e REDIS_PORT=6379 \
  -e COMPONENT_ID=cisco-trap-1 \
  ghcr.io/${GHCR_USER:-citus-cloud}/integration-cisco-trap:latest
```

## Testing

### Send Test Traps

Use the included test sender to validate the processor:

```bash
# Send all test traps
python3 bin/cisco-trap-sender.py --target localhost:162 --all

# Send traps from a specific category
python3 bin/cisco-trap-sender.py --target localhost:162 --category link-state

# Send a specific trap
python3 bin/cisco-trap-sender.py --target localhost:162 --trap 1.3.6.1.6.3.1.1.5.3

# Continuous mode for load testing
python3 bin/cisco-trap-sender.py --target localhost:162 --continuous --interval 2

# List available categories
python3 bin/cisco-trap-sender.py --list-categories

# List all available traps
python3 bin/cisco-trap-sender.py --list-traps
```

### Collect Sample Data

Capture raw trap data for debugging or analysis:

```bash
# Collect traps for 60 seconds
python3 bin/cisco-trap-collector.py --output /tmp/traps.txt --duration 60

# Collect 100 trap entries
python3 bin/cisco-trap-collector.py --output /tmp/traps.txt --count 100

# Tail mode (until Ctrl+C)
python3 bin/cisco-trap-collector.py --output /tmp/traps.txt --tail

# Collect existing/historical entries
python3 bin/cisco-trap-collector.py --output /tmp/traps.txt --existing --lines 5000
```

## Log Locations

| Log File | Description |
|----------|-------------|
| `$RAPAXHOME/logs/cisco-trap-processord.log` | Main processor log (rotating, 10MB x 5) |
| `$RAPAXHOME/logs/cisco-trap-processord-stdout.log` | Supervisor stdout capture |
| `$RAPAXHOME/logs/cisco-trap-processord-stderr.log` | Supervisor stderr capture |
| `$RAPAXHOME/logs/supervisord.log` | Supervisor daemon log |

## Extending/Adding New Traps

To add support for additional trap types, edit `bin/cisco-trap-processord.py` and add entries to the `TRAP_DEFINITIONS` dictionary:

```python
TRAP_DEFINITIONS = {
    # ... existing definitions ...

    # Add new trap
    '1.3.6.1.4.1.9.9.XXX.Y.Z': {
        'name': 'newTrapName',
        'severity': 'MAJOR',  # CRITICAL, MAJOR, MINOR, WARNING, CLEAR, INFO, DEBUG
        'category': 'new-category',
        'description': 'Description of what this trap indicates',
        'actionable': True  # True = create alert, False = log only
    },
}
```

After editing, rebuild and redeploy the container:

```bash
./build-and-push.sh --local
docker-compose down && docker-compose up -d
```

## Troubleshooting

### No traps appearing

1. **Check snmptrapd is receiving traps**:
   ```bash
   tcpdump -i any udp port 162
   ```

2. **Check snmptrapd is logging**:
   ```bash
   tail -f /var/log/messages | grep snmptrap
   ```

3. **Check container can read syslog**:
   ```bash
   docker exec rapax-cisco-trap cat /var/log/messages | tail -5
   ```

4. **Check processor logs**:
   ```bash
   docker logs rapax-cisco-trap
   cat /opt/rapax/logs/cisco-trap-processord.log
   ```

### Unknown trap warnings

If you see "Unknown trap OID" in logs, the trap is not in the definitions. Either:
- Add the trap to `TRAP_DEFINITIONS`
- The trap is being logged for analysis (check `stream:logs`)

### Redis connection issues

```bash
# Check Redis is reachable
docker exec rapax-cisco-trap redis-cli -h rapax-redis ping
```

## Future Enhancements

- **SNMPv3 Support**: Add credentials vault integration for SNMPv3 trap authentication
- **Dynamic Configuration**: Load trap definitions from external config file
- **Trap Correlation**: Built-in clear/set correlation before sending to core-correlation
- **MIB Translation**: Translate OIDs to human-readable names using MIB files

## Building

```bash
# Build locally
./build-and-push.sh --local

# Build without cache
./build-and-push.sh --local --no-cache

# Build and push to registry
./build-and-push.sh

# Build specific version
./build-and-push.sh --version 1.0.0
```

## License

Copyright (c) Rapax. All rights reserved.
