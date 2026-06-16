#!/usr/bin/env python3
"""
integration-slack-notification-exporter - Data Exporter Integration

Export Rapax data to external systems.
Generated from data-exporter template.

Features:
- Multiple destination support
- Filtering and selection
- Batching for efficiency
- Retry logic

Generated: 2026-06-16T21:13:10.655272
"""

import os
import sys
import json
import time
import logging
import signal
from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import deque

# Add rapax lib to path
sys.path.insert(0, os.environ.get('PYTHONPATH', '/opt/rapax/lib'))

try:
    from rapax import load_config, setup_logging
except ImportError:
    def load_config():
        return {}
    def setup_logging(name):
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger(name)

import redis
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configuration
INTEGRATION_NAME = "integration-slack-notification-exporter"
TARGET_SYSTEM = "Custom"
EXPORT_INTERVAL = int(os.environ.get('EXPORT_INTERVAL', 60))
BATCH_SIZE = int(os.environ.get('BATCH_SIZE', 100))
MAX_RETRIES = int(os.environ.get('MAX_RETRIES', 3))
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

# Setup logging
logger = setup_logging(INTEGRATION_NAME)
logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))


class ExportError(Exception):
    """Custom exception for export errors."""
    pass


class IntegrationSlackNotificationExporter:
    """
    Custom data exporter integration.
    """

    def __init__(self):
        """Initialize the integration."""
        self.running = True
        self.config = load_config()

        # Redis connection
        self.redis_client = self._init_redis()

        # Custom configuration
        self.destination_url = os.environ.get('CUSTOM_URL', '')
        self.api_token = os.environ.get('CUSTOM_API_TOKEN', '')

        # Export configuration
        self.export_pattern = os.environ.get('EXPORT_PATTERN', 'ALERT:*')
        self.export_filter = os.environ.get('EXPORT_FILTER', '')  # Tag filter
        self.exported_set = f"EXPORTED:{INTEGRATION_NAME}"

        # HTTP session with retry
        self.session = self._init_session()

        # Retry queue for failed exports
        self.retry_queue: deque = deque(maxlen=1000)

        # Metrics
        self.metrics = {
            'exported': 0,
            'failed': 0,
            'retried': 0,
            'filtered': 0,
            'batches': 0,
            'last_export': None
        }

        # Signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        logger.info(f"[{INTEGRATION_NAME}] Initialized")
        logger.info(f"[{INTEGRATION_NAME}] Destination: {self.destination_url}")
        logger.info(f"[{INTEGRATION_NAME}] Export pattern: {self.export_pattern}")
        logger.info(f"[{INTEGRATION_NAME}] Export interval: {EXPORT_INTERVAL}s")

    def _init_redis(self) -> redis.Redis:
        """Initialize Redis connection."""
        host = os.environ.get('REDIS_HOST', 'rapax-redis')
        port = int(os.environ.get('REDIS_PORT', 6379))
        password = os.environ.get('REDIS_PASSWORD', '')

        if not password:
            redis_conf = '/opt/rapax/etc/redis.conf'
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
        logger.info(f"[{INTEGRATION_NAME}] Redis connected: {host}:{port}")

        return client

    def _init_session(self) -> requests.Session:
        """Initialize HTTP session with retry logic."""
        session = requests.Session()

        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"[{INTEGRATION_NAME}] Received signal {signum}, shutting down...")
        self.running = False

    def _get_headers(self) -> Dict[str, str]:
        """Get API request headers."""
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        if self.api_token:
            headers['Authorization'] = f'Bearer {self.api_token}'
        return headers

    def should_export(self, key: str, data: Dict) -> bool:
        """
        Check if a record should be exported.

        Override this method to implement custom filtering.

        Args:
            key: Redis key
            data: Record data

        Returns:
            True if should export
        """
        # Check if already exported
        if self.redis_client.sismember(self.exported_set, key):
            return False

        # Apply tag filter if configured
        if self.export_filter:
            tags = data.get('Tags', [])
            filter_parts = self.export_filter.split('=')
            if len(filter_parts) == 2:
                tag_name, tag_value = filter_parts
                found = False
                for tag in tags:
                    if isinstance(tag, dict) and tag_name in tag:
                        if tag_value == '*' or tag[tag_name] == tag_value:
                            found = True
                            break
                if not found:
                    return False

        return True

    def transform_for_export(self, key: str, data: Dict) -> Dict:
        """
        Transform data for export to Custom.

        Override this method to customize the export format.

        Args:
            key: Redis key
            data: Record data

        Returns:
            Transformed data for export
        """
        # TODO: Customize transformation for Custom
        # Example webhook format:
        return {
            'source': 'rapax',
            'event_type': 'alert',
            'timestamp': datetime.utcnow().isoformat(),
            'key': key,
            'data': {
                'device': data.get('Device', 'Unknown'),
                'interface': data.get('Interface', 'N/A'),
                'status': data.get('Status', 'Unknown'),
                'description': data.get('Description', ''),
                'tags': data.get('Tags', []),
                'uuid': data.get('UUID', '')
            }
        }

    def export_single(self, key: str, data: Dict) -> bool:
        """
        Export a single record to Custom.

        Override this method with your Custom API implementation.

        Args:
            key: Redis key
            data: Transformed data

        Returns:
            True if exported successfully
        """
        # TODO: Implement Custom export
        # Example webhook implementation:
        #
        # try:
        #     response = self.session.post(
        #         self.destination_url,
        #         headers=self._get_headers(),
        #         json=data,
        #         timeout=30
        #     )
        #     response.raise_for_status()
        #     return True
        # except requests.RequestException as e:
        #     logger.error(f"[{INTEGRATION_NAME}] Export failed: {e}")
        #     raise ExportError(str(e))

        if not self.destination_url:
            logger.warning(f"[{INTEGRATION_NAME}] No destination URL configured")
            return False

        try:
            response = self.session.post(
                self.destination_url,
                headers=self._get_headers(),
                json=data,
                timeout=30
            )
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            raise ExportError(str(e))

    def export_batch(self, records: List[Dict]) -> bool:
        """
        Export a batch of records.

        Override this method if Custom supports batch operations.

        Args:
            records: List of transformed records

        Returns:
            True if all exported successfully
        """
        # Default: export one by one
        success = True
        for record in records:
            try:
                if not self.export_single(record['key'], record['data']):
                    success = False
            except ExportError:
                success = False
        return success

    def mark_exported(self, key: str):
        """Mark a record as exported."""
        self.redis_client.sadd(self.exported_set, key)

    def collect_records(self) -> List[Dict]:
        """
        Collect records to export.

        Returns:
            List of records with keys and transformed data
        """
        records = []

        for key in self.redis_client.scan_iter(match=self.export_pattern, count=100):
            if len(records) >= BATCH_SIZE:
                break

            try:
                raw_data = self.redis_client.get(key)
                if not raw_data:
                    continue

                data = json.loads(raw_data)

                if not self.should_export(key, data):
                    self.metrics['filtered'] += 1
                    continue

                transformed = self.transform_for_export(key, data)
                records.append({
                    'key': key,
                    'data': transformed
                })

            except Exception as e:
                logger.warning(f"[{INTEGRATION_NAME}] Error collecting {key}: {e}")

        return records

    def process_retry_queue(self):
        """Process records in the retry queue."""
        retries = min(len(self.retry_queue), 10)

        for _ in range(retries):
            if not self.retry_queue:
                break

            record = self.retry_queue.popleft()
            try:
                if self.export_single(record['key'], record['data']):
                    self.mark_exported(record['key'])
                    self.metrics['retried'] += 1
                    logger.info(f"[{INTEGRATION_NAME}] Retry successful: {record['key']}")
                else:
                    self.retry_queue.append(record)
            except ExportError:
                self.retry_queue.append(record)

    def run_cycle(self):
        """Run a single export cycle."""
        logger.info(f"[{INTEGRATION_NAME}] Starting export cycle")
        self.metrics['last_export'] = datetime.utcnow().isoformat()

        # Collect records
        records = self.collect_records()

        if not records:
            logger.debug(f"[{INTEGRATION_NAME}] No records to export")
            # Still process retry queue
            self.process_retry_queue()
            return

        logger.info(f"[{INTEGRATION_NAME}] Exporting {len(records)} records")
        self.metrics['batches'] += 1

        exported = 0
        failed = 0

        for record in records:
            try:
                if self.export_single(record['key'], record['data']):
                    self.mark_exported(record['key'])
                    exported += 1
                else:
                    failed += 1
                    self.retry_queue.append(record)
            except ExportError as e:
                logger.warning(f"[{INTEGRATION_NAME}] Export error: {e}")
                failed += 1
                self.retry_queue.append(record)

        self.metrics['exported'] += exported
        self.metrics['failed'] += failed

        # Process retry queue
        self.process_retry_queue()

        logger.info(
            f"[{INTEGRATION_NAME}] Cycle complete: "
            f"exported={exported}, failed={failed}, "
            f"retry_queue={len(self.retry_queue)}"
        )

    def run_daemon(self):
        """Run the integration daemon loop."""
        logger.info(f"[{INTEGRATION_NAME}] Starting daemon (interval: {EXPORT_INTERVAL}s)")

        while self.running:
            try:
                self.run_cycle()
            except Exception as e:
                logger.error(f"[{INTEGRATION_NAME}] Daemon error: {e}", exc_info=True)

            # Sleep with interrupt checking
            for _ in range(EXPORT_INTERVAL):
                if not self.running:
                    break
                time.sleep(1)

        logger.info(f"[{INTEGRATION_NAME}] Daemon stopped")
        logger.info(f"[{INTEGRATION_NAME}] Final metrics: {self.metrics}")

    def run_once(self):
        """Run a single export cycle."""
        logger.info(f"[{INTEGRATION_NAME}] Running single cycle")
        self.run_cycle()
        logger.info(f"[{INTEGRATION_NAME}] Cycle complete")


def main():
    """Main entry point."""
    integration = IntegrationSlackNotificationExporter()

    if '--daemon' in sys.argv:
        integration.run_daemon()
    else:
        integration.run_once()


if __name__ == '__main__':
    main()