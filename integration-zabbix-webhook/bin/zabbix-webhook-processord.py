#!/usr/bin/env python3
"""
Rapax Zabbix Webhook Processor Daemon
=====================================

Flask-based webhook receiver that receives real-time alerts from Zabbix
and publishes them to the Rapax Redis alert stream.

Webhook endpoint: POST /webhook

Expected payload format (configured in Zabbix):
{
    "event_id": "{EVENT.ID}",
    "trigger_id": "{TRIGGER.ID}",
    "host": "{HOST.NAME}",
    "host_ip": "{HOST.IP}",
    "trigger_name": "{TRIGGER.NAME}",
    "trigger_severity": "{TRIGGER.SEVERITY}",
    "trigger_status": "{TRIGGER.STATUS}",
    "event_value": "{EVENT.VALUE}",
    "event_time": "{EVENT.TIME}",
    "event_date": "{EVENT.DATE}",
    "item_name": "{ITEM.NAME}",
    "item_value": "{ITEM.VALUE}",
    "event_tags": "{EVENT.TAGS}"
}

Severity Mapping:
- Zabbix 0 (Not classified) -> Rapax Info
- Zabbix 1 (Information) -> Rapax Info
- Zabbix 2 (Warning) -> Rapax Warning
- Zabbix 3 (Average) -> Rapax Minor
- Zabbix 4 (High) -> Rapax Major
- Zabbix 5 (Disaster) -> Rapax Critical
- RESOLVED -> Rapax Clear

Configuration (environment variables):
- WEBHOOK_PORT: Port to listen on (default: 6543)
- COMPONENT_ID: Unique identifier for this instance (default: zabbix-webhook-1)
- REDIS_HOST, REDIS_PORT, REDIS_PASSWORD: Redis connection

@author: Citus - Rapax Software
@version: 1.0.0
"""

import os
import sys
import json
import uuid
import logging
from datetime import datetime
from flask import Flask, request, jsonify

# Set RAPAXHOME environment
RAPAXHOME = os.environ.get('RAPAXHOME', '/opt/rapax')
sys.path.append(os.path.join(RAPAXHOME, 'lib'))

# Import Rapax library
import rapax

# Configuration
WEBHOOK_PORT = int(os.environ.get('WEBHOOK_PORT', '6543'))
COMPONENT_ID = os.environ.get('COMPONENT_ID', 'zabbix-webhook-1')

# Logging
LOG_DIR = os.path.join(RAPAXHOME, 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'zabbix-webhook-processord.log')

# Severity mapping: Zabbix severity -> (Rapax Status, Rapax State)
SEVERITY_MAP = {
    '0': ('Info', 'Down'),       # Not classified
    '1': ('Info', 'Down'),       # Information
    '2': ('Warning', 'Down'),    # Warning
    '3': ('Minor', 'Down'),      # Average
    '4': ('Major', 'Down'),      # High
    '5': ('Critical', 'Down'),   # Disaster
}

# Initialize Flask app
app = Flask(__name__)

# Global logger
logger = None


def setup_logging():
    """Setup logging to file and console."""
    global logger

    # Ensure log directory exists
    os.makedirs(LOG_DIR, exist_ok=True)

    # Create logger
    logger = logging.getLogger('zabbix-webhook-processord')
    logger.setLevel(logging.INFO)

    # Clear existing handlers
    logger.handlers.clear()

    # File handler
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.INFO)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def parse_zabbix_timestamp(date_str: str, time_str: str) -> str:
    """
    Parse Zabbix date and time strings to ISO format.

    Args:
        date_str: Date in format YYYY.MM.DD
        time_str: Time in format HH:MM:SS

    Returns:
        ISO 8601 timestamp string
    """
    try:
        # Zabbix format: 2025.01.15 14:30:45
        dt_str = f"{date_str} {time_str}"
        dt = datetime.strptime(dt_str, "%Y.%m.%d %H:%M:%S")
        return dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')
    except (ValueError, TypeError):
        return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z')


def map_severity(zabbix_severity: str, event_value: str, trigger_status: str) -> tuple:
    """
    Map Zabbix severity to Rapax status and state.

    Args:
        zabbix_severity: Zabbix severity (0-5)
        event_value: Event value (0=resolved, 1=problem)
        trigger_status: Trigger status (PROBLEM or RESOLVED)

    Returns:
        Tuple of (rapax_status, rapax_state)
    """
    # Check for resolved/recovery
    if event_value == '0' or trigger_status.upper() == 'RESOLVED' or trigger_status.upper() == 'OK':
        return ('Clear', 'Up')

    # Map severity
    return SEVERITY_MAP.get(str(zabbix_severity), ('Info', 'Down'))


def process_webhook_payload(payload: dict) -> dict:
    """
    Process Zabbix webhook payload and convert to Rapax alert format.

    Args:
        payload: Zabbix webhook payload

    Returns:
        Rapax alert dictionary
    """
    # Extract fields from payload
    host = payload.get('host', 'unknown')
    host_ip = payload.get('host_ip', '') or '0.0.0.0'  # Fallback for OpenSearch IP type
    trigger_name = payload.get('trigger_name', 'Unknown trigger')
    trigger_severity = payload.get('trigger_severity', '1')
    trigger_status = payload.get('trigger_status', 'PROBLEM')
    event_value = payload.get('event_value', '1')
    event_date = payload.get('event_date', '')
    event_time = payload.get('event_time', '')
    item_name = payload.get('item_name', '')
    item_value = payload.get('item_value', '')
    event_id = payload.get('event_id', '')
    trigger_id = payload.get('trigger_id', '')
    event_tags = payload.get('event_tags', '')

    # Map severity
    rapax_status, rapax_state = map_severity(trigger_severity, event_value, trigger_status)

    # Parse timestamp
    timestamp = parse_zabbix_timestamp(event_date, event_time)

    # Build description
    description = trigger_name
    if item_name and item_value:
        description += f" ({item_name}: {item_value})"

    # Determine category based on trigger name patterns
    category = 'zabbix-alert'
    trigger_lower = trigger_name.lower()
    if 'interface' in trigger_lower or 'link' in trigger_lower:
        category = 'link-state'
    elif 'cpu' in trigger_lower or 'memory' in trigger_lower or 'disk' in trigger_lower:
        category = 'performance'
    elif 'unreachable' in trigger_lower or 'down' in trigger_lower or 'unavailable' in trigger_lower:
        category = 'device-state'
    elif 'icmp' in trigger_lower or 'ping' in trigger_lower:
        category = 'availability'

    # Build alert (matching Rapax alert schema from rapax.html)
    alert = {
        'UUID': str(uuid.uuid4()),
        'Device': host,
        'Interface': item_name if item_name else 'System',
        'IP': host_ip,
        'Status': rapax_status,
        'State': rapax_state,
        'Category': category,
        'Source': 'zabbix-webhook',
        'Location': '',
        'Description': description,
        'FirstOccurred': timestamp,
        'LastOccurred': timestamp,
        'Count': 1,
        'DeviceType': 'Network',
        'Parent': '',
        'Notes': [],
        '@timestamp': timestamp
    }

    return alert


@app.route('/health', methods=['GET'])
@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'rapax-zabbix-webhook',
        'version': '1.0.0',
        'timestamp': datetime.utcnow().isoformat(),
        'component_id': COMPONENT_ID
    })


@app.route('/webhook', methods=['POST'])
def receive_webhook():
    """
    Receive webhook from Zabbix.

    Accepts JSON payload with alert information.
    """
    try:
        # Get payload
        if request.is_json:
            payload = request.get_json()
        else:
            # Try to parse form data or raw body
            payload = request.form.to_dict() or {}
            if not payload:
                try:
                    payload = json.loads(request.get_data(as_text=True))
                except json.JSONDecodeError:
                    logger.warning("Received non-JSON payload")
                    payload = {}

        logger.info(f"Received webhook: host={payload.get('host', 'unknown')}, "
                    f"trigger={payload.get('trigger_name', 'unknown')}, "
                    f"status={payload.get('trigger_status', 'unknown')}")

        logger.debug(f"Full payload: {json.dumps(payload)}")

        # Process payload
        alert = process_webhook_payload(payload)

        # Insert alert to Redis
        rapax.insert_alert(logger, alert)

        logger.info(f"Alert created: {alert['Device']}:{alert['Interface']} - "
                    f"{alert['Status']}/{alert['State']}")

        return jsonify({
            'status': 'OK',
            'message': 'Alert processed',
            'alert_id': alert['UUID']
        }), 200

    except Exception as e:
        logger.error(f"Error processing webhook: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/webhook/test', methods=['POST', 'GET'])
def test_webhook():
    """
    Test endpoint - creates a test alert.
    """
    try:
        test_payload = {
            'event_id': '99999',
            'trigger_id': '88888',
            'host': 'test-device',
            'host_ip': '192.168.1.100',
            'trigger_name': 'Test Alert from Webhook',
            'trigger_severity': '2',
            'trigger_status': 'PROBLEM',
            'event_value': '1',
            'event_date': datetime.utcnow().strftime('%Y.%m.%d'),
            'event_time': datetime.utcnow().strftime('%H:%M:%S'),
            'item_name': 'Test Item',
            'item_value': '42',
            'event_tags': 'test:true'
        }

        alert = process_webhook_payload(test_payload)
        rapax.insert_alert(logger, alert)

        logger.info("Test alert created")

        return jsonify({
            'status': 'OK',
            'message': 'Test alert created',
            'alert': alert
        }), 200

    except Exception as e:
        logger.error(f"Error creating test alert: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/', methods=['GET'])
def index():
    """Root endpoint with info."""
    return jsonify({
        'service': 'Rapax Zabbix Webhook Receiver',
        'version': '1.0.0',
        'endpoints': {
            '/webhook': 'POST - Receive Zabbix alerts',
            '/webhook/test': 'POST/GET - Create test alert',
            '/health': 'GET - Health check',
            '/api/v1/health': 'GET - Health check'
        },
        'component_id': COMPONENT_ID
    })


def main():
    """Main entry point."""
    global logger

    # Setup logging
    logger = setup_logging()

    logger.info("=" * 60)
    logger.info("Rapax Zabbix Webhook Processor")
    logger.info("=" * 60)
    logger.info(f"Component ID: {COMPONENT_ID}")
    logger.info(f"Webhook Port: {WEBHOOK_PORT}")

    # Load Rapax config and connect to Redis
    try:
        rapax.load_config()
        redis_client = rapax.get_redis_client()
        redis_client.ping()
        logger.info("Connected to Redis")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        return 1

    # Start Flask app
    logger.info(f"Starting webhook server on port {WEBHOOK_PORT}")
    app.run(
        host='0.0.0.0',
        port=WEBHOOK_PORT,
        debug=False,
        threaded=True
    )

    return 0


if __name__ == '__main__':
    sys.exit(main())
