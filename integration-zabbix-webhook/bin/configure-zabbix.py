#!/usr/bin/env python3
"""
Rapax Zabbix Webhook Configuration Script
==========================================

Configures Zabbix to send alerts to the Rapax webhook receiver.

This script:
1. Loads Zabbix credentials from Rapax vault
2. Creates a webhook media type in Zabbix
3. Creates a user for webhook notifications
4. Creates an action to trigger webhook on all alerts

Usage:
    python3 configure-zabbix.py [OPTIONS]

Options:
    --webhook-url URL     Webhook URL (default: http://rapax-zabbix-webhook:6543/webhook)
    --dry-run             Show what would be done without making changes
    --cleanup             Remove webhook configuration from Zabbix

@author: Citus - Rapax Software
@version: 1.0.0
"""

import os
import sys
import json
import argparse
import requests
from typing import Dict, Any, Optional

# Configuration
CREDENTIALS_URL = os.environ.get('CREDENTIALS_URL', 'http://rapax-core-api:5004')
DEFAULT_WEBHOOK_URL = os.environ.get('WEBHOOK_URL', 'http://rapax-zabbix-webhook:6543/webhook')

# Webhook media type script (Zabbix JavaScript)
# Zabbix 4.x uses CurlHttpRequest, 5.x+ uses HttpRequest
# This script is compatible with Zabbix 4.4+
WEBHOOK_SCRIPT = '''
try {
    var params = JSON.parse(value);
    var req = new CurlHttpRequest();
    req.AddHeader('Content-Type: application/json');

    var payload = {
        event_id: params.event_id,
        trigger_id: params.trigger_id,
        host: params.host,
        host_ip: params.host_ip,
        trigger_name: params.trigger_name,
        trigger_severity: params.trigger_severity,
        trigger_status: params.trigger_status,
        event_value: params.event_value,
        event_date: params.event_date,
        event_time: params.event_time,
        item_name: params.item_name,
        item_value: params.item_value,
        event_tags: params.event_tags
    };

    var resp = req.Post(params.webhook_url, JSON.stringify(payload));

    return 'OK';
} catch (error) {
    throw 'Rapax webhook error: ' + error;
}
'''

# Webhook parameters
WEBHOOK_PARAMS = [
    {"name": "webhook_url", "value": "{$RAPAX_WEBHOOK_URL}"},
    {"name": "event_id", "value": "{EVENT.ID}"},
    {"name": "trigger_id", "value": "{TRIGGER.ID}"},
    {"name": "host", "value": "{HOST.NAME}"},
    {"name": "host_ip", "value": "{HOST.IP}"},
    {"name": "trigger_name", "value": "{TRIGGER.NAME}"},
    {"name": "trigger_severity", "value": "{TRIGGER.SEVERITY}"},
    {"name": "trigger_status", "value": "{TRIGGER.STATUS}"},
    {"name": "event_value", "value": "{EVENT.VALUE}"},
    {"name": "event_date", "value": "{EVENT.DATE}"},
    {"name": "event_time", "value": "{EVENT.TIME}"},
    {"name": "item_name", "value": "{ITEM.NAME}"},
    {"name": "item_value", "value": "{ITEM.VALUE}"},
    {"name": "event_tags", "value": "{EVENT.TAGS}"}
]


def load_zabbix_credentials() -> Dict[str, str]:
    """Load Zabbix credentials from vault."""
    try:
        response = requests.get(
            f"{CREDENTIALS_URL}/api/credentials/custom/zabbix",
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            cred_data = data.get('data', {})
            return {
                'url': cred_data.get('url', ''),
                'username': cred_data.get('username', 'Admin'),
                'password': cred_data.get('password', ''),
                'api_token': cred_data.get('api_token', '')
            }

    except requests.exceptions.RequestException as e:
        print(f"Error loading credentials: {e}")

    # Try environment fallback
    return {
        'url': os.environ.get('ZABBIX_URL', ''),
        'username': os.environ.get('ZABBIX_USER', 'Admin'),
        'password': os.environ.get('ZABBIX_PASSWORD', ''),
        'api_token': os.environ.get('ZABBIX_API_TOKEN', '')
    }


class ZabbixClient:
    """Zabbix API client."""

    def __init__(self, url: str, api_token: str = None, username: str = None, password: str = None):
        self.url = url
        self.api_token = api_token
        self.auth_token = None
        self.username = username
        self.password = password
        self.request_id = 0
        self.version = None  # Set after login
        self.major_version = 0  # For version-specific API handling

    def _call(self, method: str, params: Dict[str, Any] = None, skip_auth: bool = False) -> Any:
        """Make Zabbix API call.

        Args:
            method: Zabbix API method name
            params: Method parameters
            skip_auth: If True, don't include auth token (required for apiinfo.version)
        """
        self.request_id += 1

        request_data = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self.request_id
        }

        if self.api_token and not skip_auth:
            headers = {
                "Content-Type": "application/json-rpc",
                "Authorization": f"Bearer {self.api_token}"
            }
        elif self.auth_token and not skip_auth:
            headers = {"Content-Type": "application/json-rpc"}
            request_data["auth"] = self.auth_token
        else:
            headers = {"Content-Type": "application/json-rpc"}

        response = requests.post(
            self.url,
            headers=headers,
            json=request_data,
            timeout=30
        )
        response.raise_for_status()

        result = response.json()

        if "error" in result:
            error = result["error"]
            raise Exception(f"Zabbix API error: {error.get('message', '')} - {error.get('data', '')}")

        return result.get("result")

    def login(self) -> bool:
        """Login to Zabbix."""
        if self.api_token:
            try:
                # Verify API is reachable (apiinfo.version doesn't need auth)
                self._call("apiinfo.version", skip_auth=True)
                return True
            except Exception:
                return False

        if not self.username or not self.password:
            return False

        try:
            self.auth_token = self._call("user.login", {
                "username": self.username,
                "password": self.password
            })
            return True
        except Exception:
            try:
                self.auth_token = self._call("user.login", {
                    "user": self.username,
                    "password": self.password
                })
                return True
            except Exception:
                return False

    def get_version(self) -> str:
        """Get API version (called without auth per Zabbix API requirements)."""
        self.version = self._call("apiinfo.version", skip_auth=True)
        # Parse major version for API compatibility (e.g., "4.4.6" -> 4)
        try:
            self.major_version = int(self.version.split('.')[0])
        except (ValueError, IndexError):
            self.major_version = 0
        return self.version


def create_webhook_mediatype(zabbix: ZabbixClient, webhook_url: str, dry_run: bool = False) -> Optional[str]:
    """
    Create webhook media type in Zabbix.

    Returns:
        Media type ID or None
    """
    print("Creating webhook media type...")

    # Check if already exists
    existing = zabbix._call("mediatype.get", {
        "output": ["mediatypeid", "name"],
        "filter": {"name": "Rapax Webhook"}
    })

    if existing:
        print(f"  Media type already exists (ID: {existing[0]['mediatypeid']})")
        return existing[0]['mediatypeid']

    if dry_run:
        print("  [DRY RUN] Would create media type")
        return None

    # Create media type
    result = zabbix._call("mediatype.create", {
        "name": "Rapax Webhook",
        "type": 4,  # Webhook
        "status": 0,  # Enabled
        "description": "Send alerts to Rapax via webhook",
        "script": WEBHOOK_SCRIPT,
        "parameters": WEBHOOK_PARAMS,
        "process_tags": 1,
        "event_menu": 0,
        "message_templates": [
            {
                "eventsource": 0,  # Triggers
                "recovery": 0,  # Problem
                "subject": "{TRIGGER.STATUS}: {TRIGGER.NAME}",
                "message": "{EVENT.ID}"
            },
            {
                "eventsource": 0,  # Triggers
                "recovery": 1,  # Recovery
                "subject": "Resolved: {TRIGGER.NAME}",
                "message": "{EVENT.ID}"
            }
        ]
    })

    mediatype_id = result['mediatypeids'][0]
    print(f"  Created media type (ID: {mediatype_id})")

    return mediatype_id


def create_macro(zabbix: ZabbixClient, webhook_url: str, dry_run: bool = False) -> bool:
    """Create global macro for webhook URL."""
    print("Creating global macro...")

    # Check if exists
    existing = zabbix._call("usermacro.get", {
        "output": ["globalmacroid", "macro", "value"],
        "globalmacro": True,
        "filter": {"macro": "{$RAPAX_WEBHOOK_URL}"}
    })

    if existing:
        print(f"  Macro already exists, updating...")
        if not dry_run:
            # Zabbix 4.x uses usermacro.updateglobal, 5.x+ uses usermacro.update
            if zabbix.major_version < 5:
                zabbix._call("usermacro.updateglobal", {
                    "globalmacroid": existing[0]['globalmacroid'],
                    "value": webhook_url
                })
            else:
                zabbix._call("usermacro.update", {
                    "globalmacroid": existing[0]['globalmacroid'],
                    "value": webhook_url
                })
        return True

    if dry_run:
        print(f"  [DRY RUN] Would create macro: {{$RAPAX_WEBHOOK_URL}} = {webhook_url}")
        return True

    # Zabbix 4.x uses usermacro.createglobal, 5.x+ uses usermacro.create with globalmacro param
    if zabbix.major_version < 5:
        # Zabbix 4.x API
        zabbix._call("usermacro.createglobal", {
            "macro": "{$RAPAX_WEBHOOK_URL}",
            "value": webhook_url
        })
    else:
        # Zabbix 5.x+ API
        zabbix._call("usermacro.create", {
            "macro": "{$RAPAX_WEBHOOK_URL}",
            "value": webhook_url,
            "type": 0,  # Text
            "description": "Rapax webhook receiver URL"
        })

    print(f"  Created macro: {{$RAPAX_WEBHOOK_URL}} = {webhook_url}")
    return True


def create_webhook_user(zabbix: ZabbixClient, mediatype_id: str, dry_run: bool = False) -> Optional[str]:
    """Create user for webhook notifications."""
    print("Creating webhook user...")

    # Check if exists
    existing = zabbix._call("user.get", {
        "output": ["userid", "username"],
        "filter": {"username": "rapax-webhook"}
    })

    if existing:
        print(f"  User already exists (ID: {existing[0]['userid']})")
        return existing[0]['userid']

    if dry_run:
        print("  [DRY RUN] Would create user: rapax-webhook")
        return None

    # Get Super admin role
    roles = zabbix._call("role.get", {
        "output": ["roleid", "name"],
        "filter": {"name": "Super admin role"}
    })

    role_id = roles[0]['roleid'] if roles else "3"  # Default super admin role

    # Get admin group
    groups = zabbix._call("usergroup.get", {
        "output": ["usrgrpid", "name"],
        "filter": {"name": "Zabbix administrators"}
    })

    group_id = groups[0]['usrgrpid'] if groups else "7"  # Default admin group

    # Create user
    result = zabbix._call("user.create", {
        "username": "rapax-webhook",
        "name": "Rapax",
        "surname": "Webhook",
        "passwd": str(__import__('uuid').uuid4()),  # Random password
        "roleid": role_id,
        "usrgrps": [{"usrgrpid": group_id}],
        "medias": [
            {
                "mediatypeid": mediatype_id,
                "sendto": "rapax",
                "active": 0,
                "severity": 63,  # All severities
                "period": "1-7,00:00-24:00"  # All times
            }
        ] if mediatype_id else []
    })

    user_id = result['userids'][0]
    print(f"  Created user (ID: {user_id})")

    return user_id


def create_webhook_action(zabbix: ZabbixClient, user_id: str, dry_run: bool = False) -> Optional[str]:
    """Create action to send alerts via webhook."""
    print("Creating webhook action...")

    # Check if exists
    existing = zabbix._call("action.get", {
        "output": ["actionid", "name"],
        "filter": {"name": "Rapax Webhook Alerts"}
    })

    if existing:
        print(f"  Action already exists (ID: {existing[0]['actionid']})")
        return existing[0]['actionid']

    if dry_run:
        print("  [DRY RUN] Would create action: Rapax Webhook Alerts")
        return None

    # Create action
    result = zabbix._call("action.create", {
        "name": "Rapax Webhook Alerts",
        "eventsource": 0,  # Triggers
        "status": 0,  # Enabled
        "esc_period": "60s",
        "filter": {
            "evaltype": 0,  # AND/OR
            "conditions": []  # All triggers
        },
        "operations": [
            {
                "operationtype": 0,  # Send message
                "esc_period": "0",
                "esc_step_from": 1,
                "esc_step_to": 1,
                "opmessage": {
                    "default_msg": 1,
                    "mediatypeid": "0"  # All media types
                },
                "opmessage_usr": [
                    {"userid": user_id}
                ] if user_id else []
            }
        ],
        "recovery_operations": [
            {
                "operationtype": 0,  # Send message
                "opmessage": {
                    "default_msg": 1,
                    "mediatypeid": "0"
                },
                "opmessage_usr": [
                    {"userid": user_id}
                ] if user_id else []
            }
        ]
    })

    action_id = result['actionids'][0]
    print(f"  Created action (ID: {action_id})")

    return action_id


def cleanup_webhook_config(zabbix: ZabbixClient, dry_run: bool = False):
    """Remove webhook configuration from Zabbix."""
    print("Cleaning up webhook configuration...")

    # Delete action
    actions = zabbix._call("action.get", {
        "output": ["actionid"],
        "filter": {"name": "Rapax Webhook Alerts"}
    })
    if actions:
        if dry_run:
            print(f"  [DRY RUN] Would delete action ID: {actions[0]['actionid']}")
        else:
            zabbix._call("action.delete", [actions[0]['actionid']])
            print(f"  Deleted action")

    # Delete user
    users = zabbix._call("user.get", {
        "output": ["userid"],
        "filter": {"username": "rapax-webhook"}
    })
    if users:
        if dry_run:
            print(f"  [DRY RUN] Would delete user ID: {users[0]['userid']}")
        else:
            zabbix._call("user.delete", [users[0]['userid']])
            print(f"  Deleted user")

    # Delete media type
    mediatypes = zabbix._call("mediatype.get", {
        "output": ["mediatypeid"],
        "filter": {"name": "Rapax Webhook"}
    })
    if mediatypes:
        if dry_run:
            print(f"  [DRY RUN] Would delete media type ID: {mediatypes[0]['mediatypeid']}")
        else:
            zabbix._call("mediatype.delete", [mediatypes[0]['mediatypeid']])
            print(f"  Deleted media type")

    # Delete macro
    macros = zabbix._call("usermacro.get", {
        "output": ["globalmacroid"],
        "globalmacro": True,
        "filter": {"macro": "{$RAPAX_WEBHOOK_URL}"}
    })
    if macros:
        if dry_run:
            print(f"  [DRY RUN] Would delete macro ID: {macros[0]['globalmacroid']}")
        else:
            # Zabbix 4.x uses usermacro.deleteglobal, 5.x+ uses usermacro.delete
            if zabbix.major_version < 5:
                zabbix._call("usermacro.deleteglobal", [macros[0]['globalmacroid']])
            else:
                zabbix._call("usermacro.delete", [macros[0]['globalmacroid']])
            print(f"  Deleted macro")

    print("Cleanup complete")


def main():
    parser = argparse.ArgumentParser(description='Configure Zabbix webhook for Rapax')
    parser.add_argument('--webhook-url', default=DEFAULT_WEBHOOK_URL,
                        help=f'Webhook URL (default: {DEFAULT_WEBHOOK_URL})')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be done')
    parser.add_argument('--cleanup', action='store_true',
                        help='Remove webhook configuration')

    args = parser.parse_args()

    print("=" * 60)
    print("Rapax Zabbix Webhook Configuration")
    print("=" * 60)
    print()

    if args.dry_run:
        print("DRY RUN MODE - No changes will be made")
        print()

    # Load credentials
    print("Loading Zabbix credentials...")
    creds = load_zabbix_credentials()

    if not creds['url']:
        print("ERROR: Zabbix URL not configured")
        print("Store credentials in vault: POST /api/credentials/custom/zabbix")
        return 1

    print(f"  URL: {creds['url']}")
    print()

    # Connect to Zabbix
    print("Connecting to Zabbix...")
    zabbix = ZabbixClient(
        url=creds['url'],
        api_token=creds.get('api_token'),
        username=creds.get('username'),
        password=creds.get('password')
    )

    if not zabbix.login():
        print("ERROR: Failed to login to Zabbix")
        return 1

    print(f"  Connected (version: {zabbix.get_version()})")
    print()

    if args.cleanup:
        cleanup_webhook_config(zabbix, args.dry_run)
        return 0

    # Configure webhook
    print(f"Webhook URL: {args.webhook_url}")
    print()

    # Create macro for webhook URL
    create_macro(zabbix, args.webhook_url, args.dry_run)
    print()

    # Create media type
    mediatype_id = create_webhook_mediatype(zabbix, args.webhook_url, args.dry_run)
    print()

    # Create user
    user_id = create_webhook_user(zabbix, mediatype_id, args.dry_run)
    print()

    # Create action
    create_webhook_action(zabbix, user_id, args.dry_run)
    print()

    print("=" * 60)
    print("Configuration complete!")
    print("=" * 60)
    print()
    print("Zabbix will now send alerts to:")
    print(f"  {args.webhook_url}")
    print()
    print("Test with: curl -X POST {}/webhook/test".format(
        args.webhook_url.replace('/webhook', '')
    ))

    return 0


if __name__ == '__main__':
    sys.exit(main())
