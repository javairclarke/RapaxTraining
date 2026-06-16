# Rapax Unifi SNMP Integration

SNMP poller for Ubiquiti/Unifi network devices. Collects Unifi-specific metrics from the FROGFOOT-RESOURCES-MIB that complement the standard MIB-2 metrics collected by the core network-collection SNMP agent.

## Overview

This integration polls Unifi devices (switches and UDM) for:
- **Memory metrics**: Total, free, buffer, cache, and calculated usage percentage
- **Load averages**: 1-minute, 5-minute, and 15-minute system load
- **Temperature sensors**: CPU, board, PHY, and host temperatures (if available)
- **Fan status**: Speed and duty level (if available)

### Supported Devices

| Device Type | SNMP Support | Notes |
|------------|--------------|-------|
| UDM Pro | Limited | Requires manual SNMP configuration via SSH |
| USW Pro 24 | Yes | Full support |
| USW Lite 16 PoE | Yes | Full support |
| USW Lite 8 PoE | Yes | Full support |
| USW Flex/Ultra | No | SNMP not supported |
| U6 IW / U6 LR / AC LR | No | Access points have no native SNMP agent |

### Metrics Collected

**FROGFOOT-RESOURCES-MIB (1.3.6.1.4.1.10002.1.1.1):**

| Metric | OID | Unit | Description |
|--------|-----|------|-------------|
| Memory Usage% | (derived) | % | Calculated memory utilization |
| Memory Total (KB) | .1.1.0 | KB | Total usable memory |
| Memory Free (KB) | .1.2.0 | KB | Available memory |
| Memory Buffer (KB) | .1.3.0 | KB | Buffer memory |
| Memory Cache (KB) | .1.4.0 | KB | Cache memory |
| Load Average (1min) | .4.2.1.3.1 | float | 1-minute load average |
| Load Average (5min) | .4.2.1.3.2 | float | 5-minute load average |
| Load Average (15min) | .4.2.1.3.3 | float | 15-minute load average |

**Temperature OIDs (graceful skip if unavailable):**

| Metric | OID | Unit |
|--------|-----|------|
| CPU Temperature (C) | 1.3.6.1.4.1.4413.1.1.43.1.8.1.5.1.0 | Celsius |
| Board Temperature (C) | 1.3.6.1.4.1.4413.1.1.43.1.15.1.2 | Celsius |
| PHY Temperature (C) | 1.3.6.1.4.1.4413.1.1.43.1.15.1.3 | Celsius |
| Host Temperature (C) | 1.3.6.1.4.1.41112.1.4.8.4 | Celsius |

**Fan OIDs (graceful skip if unavailable):**

| Metric | OID | Unit |
|--------|-----|------|
| Fan Speed (RPM) | 1.3.6.1.4.1.4413.1.1.43.1.6.1.4 | RPM |
| Fan Duty Level% | 1.3.6.1.4.1.4413.1.1.43.1.6.1.5 | Percentage |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         OpenSearch (devices-*)                       │
│                                                                      │
│  Device Detection: Capability probing (not vendor filtering)         │
│  - Fetches ALL devices with SNMP credentials                        │
│  - Probes each with FROGFOOT memTotal OID                           │
│  - If device responds, it is Unifi-capable and will be polled       │
│  - Results cached per-IP to avoid repeated probing                  │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                 integration-unifi-snmp container                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │              unifi-device-snmp-pollerd.py                      │  │
│  │                                                                 │  │
│  │  1. Fetch all SNMP devices from OpenSearch (hourly refresh)    │  │
│  │  2. Get SNMP credentials from device.securityInformation       │  │
│  │  3. Probe device capabilities (cache which OIDs are available) │  │
│  │  4. Poll FROGFOOT-MIB metrics (memory, load)                   │  │
│  │  5. Poll temperature/fan OIDs (graceful skip if unavailable)   │  │
│  │  6. Publish metrics to Redis stream:stats                       │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  Managed by: supervisord                                             │
│  Logs: /opt/rapax/logs/unifi-device-snmp-pollerd.log                │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Redis (stream:stats)                            │
│                              │                                       │
│                              ▼                                       │
│              core-collection → OpenSearch (stats-YYYY-MM-DD)         │
└─────────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Rapax platform running (Redis, OpenSearch, core-collection)
- Unifi devices with SNMP enabled (Settings > CyberSecure > Traffic Logging)
- Devices discovered and present in OpenSearch with SNMP credentials

### Enable SNMP on Unifi Devices

1. In UniFi Network, go to **Settings > CyberSecure > Traffic Logging**
2. Scroll to the **SNMP** section and enable it
3. Set a community string (default: `public`, but change for security)
4. Ensure UDP port 161 is accessible from the Rapax host

### Using the Installer

```bash
# Run the installer (when available)
sudo /opt/rapax/installers/integrations/unifi-snmp.install.sh
```

### Manual Installation

```bash
# Build the image
cd /opt/rapax/integration-unifi-snmp
./build-and-push.sh --local

# Start with docker-compose
docker-compose up -d

# Or with docker run
docker run -d \
  --name rapax-unifi-snmp \
  --network rapax-dev-network \
  -v /opt/rapax/logs:/opt/rapax/logs \
  -v /opt/rapax/lib:/opt/rapax/lib:ro \
  -v /opt/rapax/etc:/opt/rapax/etc:ro \
  -e REDIS_HOST=rapax-redis \
  -e REDIS_PORT=6379 \
  -e COMPONENT_ID=unifi-snmp-1 \
  ghcr.io/citus-cloud/integration-unifi-snmp:latest
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | rapax-redis | Redis server hostname |
| `REDIS_PORT` | 6379 | Redis server port |
| `REDIS_PASSWORD` | (empty) | Redis password (optional) |
| `SNMP_POLL_INTERVAL` | 60 | Polling interval in seconds |
| `SNMP_TIMEOUT` | 1000 | SNMP timeout in milliseconds |
| `SNMP_WORKERS` | 5 | Number of worker threads |
| `CONFIG_UPDATE_INTERVAL` | 3600 | Device list refresh interval (seconds) |
| `COMPONENT_ID` | unifi-snmp-1 | Unique identifier for this poller |
| `LOG_LEVEL` | INFO | Logging level (DEBUG, INFO, WARNING, ERROR) |

### Volume Mounts

| Container Path | Host Path | Mode | Description |
|----------------|-----------|------|-------------|
| `/opt/rapax/logs` | `$RAPAXHOME/logs` | rw | Poller logs |
| `/opt/rapax/lib` | `$RAPAXHOME/lib` | ro | rapax.py library |
| `/opt/rapax/etc` | `$RAPAXHOME/etc` | ro | Configuration/credentials |
| `/etc/machine-id` | `/etc/machine-id` | ro | For credential decryption |

**Important**: The container hostname must match the host's hostname for credential decryption to work. Use `--hostname "$(hostname)"` when running manually.

### Device Requirements

For a device to be polled by this integration, it must:

1. **Be detected as a Unifi device** via one of:
   - `vendor` field contains "Ubiquiti" or "UniFi"
   - `sysDescr` contains "Ubiquiti" or "UniFi"
   - `sysObjectID` starts with `1.3.6.1.4.1.41112`
   - `deviceCategory` contains "UniFi"

2. **Have SNMP credentials** in the `securityInformation` array with a community string

## Testing

### Validate SNMP Connectivity

Use the included validator script to test if a Unifi device supports the OIDs:

```bash
# Basic validation
python3 bin/unifi-snmp-validator.py --target 192.168.1.10 --community public

# With verbose error messages
python3 bin/unifi-snmp-validator.py --target 192.168.1.10 --community public --verbose

# Custom timeout
python3 bin/unifi-snmp-validator.py --target 192.168.1.10 --community public --timeout 2000
```

**Example output:**
```
Unifi SNMP Validator
Testing connectivity to 192.168.1.10:161 with community 'public'
Timeout: 1000ms

=== System Information ===
  [OK] System Description: Linux USW-Pro-24 4.14.116 #1 SMP...
  [OK] System Object ID: 1.3.6.1.4.1.41112.1.6.36
  [OK] System Name: switch-office
  [OK] System Uptime: 123456789

Device identified as Ubiquiti/Unifi

=== FROGFOOT-RESOURCES-MIB (Memory & Load) ===
  [OK] Memory Total (KB): 1024000
  [OK] Memory Free (KB): 512000
  [OK] Memory Buffer (KB): 64000
  [OK] Memory Cache (KB): 128000
  [OK] Load Average (1min): 0.15
  [OK] Load Average (5min): 0.12
  [OK] Load Average (15min): 0.10
  [**] Calculated Memory Usage: 31.3%

=== Temperature Sensors (optional) ===
  [OK] CPU Temperature (C): 45
  [--] Board Temperature (C): Not available
  [--] PHY Temperature (C): Not available
  [--] Host Temperature (C): Not available

=== Fan Status (optional) ===
  [--] Fan Speed (RPM): Not available
  [--] Fan Duty Level (%): Not available

=== Summary ===
  System OIDs:      4/4
  FROGFOOT OIDs:    7/7
  Temperature OIDs: 1/4
  Fan OIDs:         0/2
  Total:            12/17

SUCCESS: Device is ready for Unifi SNMP polling
```

### Test from Inside Container

```bash
# Run validator from container
docker exec rapax-unifi-snmp python3 /opt/rapax/bin/unifi-snmp-validator.py \
  --target 192.168.1.10 --community public
```

## Log Locations

| Log File | Description |
|----------|-------------|
| `$RAPAXHOME/logs/unifi-device-snmp-pollerd.log` | Main poller log (rotating, 10MB x 5) |
| `$RAPAXHOME/logs/unifi-device-snmp-pollerd-stdout.log` | Supervisor stdout capture |
| `$RAPAXHOME/logs/unifi-device-snmp-pollerd-stderr.log` | Supervisor stderr capture |
| `$RAPAXHOME/logs/supervisord.log` | Supervisor daemon log |

### Log Format

```
2026-02-03 10:30:00 - INFO - [Unifi SNMP] Starting Unifi SNMP poller daemon
2026-02-03 10:30:00 - INFO - [Unifi SNMP] Initializing with 5 workers
2026-02-03 10:30:00 - INFO - [Unifi SNMP] Poll interval: 60s, Component ID: unifi-snmp-1
2026-02-03 10:30:01 - INFO - [Unifi SNMP] Retrieved 100 total devices from OpenSearch
2026-02-03 10:30:01 - INFO - [Unifi SNMP] Found 8 Unifi devices with SNMP credentials
2026-02-03 10:30:01 - INFO - [Unifi SNMP] Skipped 2 Unifi devices without SNMP credentials
2026-02-03 10:31:00 - INFO - [Unifi SNMP] Initiated poll cycle at 2026-02-03T10:31:00.000000Z for 8 devices
2026-02-03 10:31:05 - INFO - [Unifi SNMP] Poll cycle completed in 5.23 seconds
```

## Extending

### Adding New OIDs

To add additional Unifi-specific OIDs, edit `bin/unifi-device-snmp-pollerd.py`:

```python
# Add to appropriate OID dictionary
CUSTOM_OIDS = {
    'newMetric': '1.3.6.1.4.1.XXXXX.Y.Z.0',
}

# Add collection method
def collect_custom_metrics(self, device, timestamp, community):
    # Implementation here
    pass
```

After editing, rebuild and redeploy:

```bash
./build-and-push.sh --local
docker-compose down && docker-compose up -d
```

### Device Capability Caching

The poller probes each device once to determine which OIDs are available, then caches the results. This avoids repeated failed SNMP queries for unavailable OIDs. The cache persists until the container restarts.

## Troubleshooting

### No Unifi devices found

1. **Check OpenSearch has devices**:
   ```bash
   curl -k -u admin:password "https://localhost:9200/devices-*/_search?pretty" \
     -H 'Content-Type: application/json' \
     -d '{"query":{"match":{"vendor":"Ubiquiti"}}}'
   ```

2. **Check devices have SNMP credentials**:
   - Devices need `securityInformation` array with `{"data": {"string": "community"}}`

3. **Check container logs**:
   ```bash
   docker logs rapax-unifi-snmp
   cat /opt/rapax/logs/unifi-device-snmp-pollerd.log
   ```

### SNMP timeouts

1. **Check firewall allows UDP 161**:
   ```bash
   firewall-cmd --list-ports | grep 161
   ```

2. **Test SNMP connectivity**:
   ```bash
   snmpwalk -v2c -c public 192.168.1.10 sysDescr
   ```

3. **Increase timeout**:
   ```bash
   docker run ... -e SNMP_TIMEOUT=3000 ...
   ```

### Metrics not appearing

1. **Check Redis stream**:
   ```bash
   redis-cli -h localhost XLEN stream:stats
   redis-cli -h localhost XREAD COUNT 5 STREAMS stream:stats 0
   ```

2. **Check device has FROGFOOT-MIB support**:
   ```bash
   python3 bin/unifi-snmp-validator.py --target <device-ip> --community <community>
   ```

### Poll duration exceeded interval

If logs show "Poll duration exceeded interval", the poller is taking too long. Solutions:
- Increase `SNMP_WORKERS` (more parallel threads)
- Increase `SNMP_POLL_INTERVAL` (longer between polls)
- Decrease `SNMP_TIMEOUT` (fail faster on unresponsive devices)

## Comparison with network-collection snmp-agentd

| Aspect | network-collection snmp-agentd | integration-unifi-snmp |
|--------|-------------------------------|------------------------|
| **Scope** | All SNMP devices | Unifi devices only |
| **OIDs** | Standard MIB-2 (IF-MIB, HOST-RESOURCES-MIB) | FROGFOOT-MIB, Ubiquiti enterprise OIDs |
| **Metrics** | Interface bandwidth, CPU, memory, disk | Unifi memory, load average, temperature, fan |
| **Overlap** | None | Complementary metrics |

Both pollers can run simultaneously without conflict, as they collect different OIDs from devices.

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
