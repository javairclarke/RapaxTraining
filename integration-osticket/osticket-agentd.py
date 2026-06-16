#!/usr/bin/env python3
"""
OSTicket Integration Script for Rapax Service Assurance Platform

This script monitors Redis for alert records that need tickets created,
integrates with OSTicket 1.18.2 JSON API to create tickets automatically,
and updates alert records with the returned ticket IDs.

Supports both user field (for existing OSTicket users) and name/email 
(for auto-creating users) ticket creation methods.

Usage: python osticket_integration.py
       python osticket_integration.py --daemon [interval]
"""

import os
import sys
import json
import re
import time
import logging
import socket
import redis
import requests
import yaml
import pymysql
from datetime import datetime

# Add the rapax library to the path
RAPAX_HOME = os.getenv('RAPAX_HOME', '/opt/rapax')
sys.path.append(os.path.join(RAPAX_HOME, 'lib'))

# Import rapax functions
from rapax import load_config, setup_logging, load_credentials, RapaxConfig

class OSTicketIntegration:
    def __init__(self):
        """Initialize the OSTicket integration service."""
        self.config = load_config()
        self.logger = setup_logging()

        # Add file handler so logs persist at RAPAXHOME/logs/osticket-agentd.log
        log_dir = os.path.join(RAPAX_HOME, 'logs')
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, 'osticket-agentd.log')
        try:
            fh = logging.FileHandler(log_file)
            fh.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            ))
            self.logger.addHandler(fh)
        except (OSError, PermissionError) as e:
            self.logger.warning(f"[OSTicket Integration] Could not create log file {log_file}: {e}")

        self.logger.info("[OSTicket Integration] Service starting up...")
        
        # Load ticket configuration
        self.ticket_config = self._load_ticket_config()
        
        # Initialize Redis connection
        self.redis_client = self._init_redis()
        
        # OSTicket API settings
        self.osticket_host = self.ticket_config['ticketing']['host']
        self.api_key = self.ticket_config['ticketing']['api_key']
        self.ticket_format = self.ticket_config['ticketing']['ticket_format']
        
        self.logger.info(f"[OSTicket Integration] Initialized with OSTicket host: {self.osticket_host}")

        # Update API key IP in OSTicket database to match this container's current IP
        # Docker assigns new IPs when containers are recreated, so we must self-correct
        self._update_api_key_ip()

        # Ensure configured user exists in OSTicket
        self._ensure_user_exists()

    def _load_ticket_config(self):
        """Load ticket configuration from ticket.cfg file."""
        try:
            config_file = os.path.join(RAPAX_HOME, 'etc', 'ticket.cfg')
            with open(config_file, 'r') as file:
                config = yaml.safe_load(file)
            self.logger.debug(f"[OSTicket Integration] Loaded ticket configuration from {config_file}")
            return config
        except Exception as e:
            self.logger.error(f"[OSTicket Integration] Failed to load ticket configuration: {e}")
            raise

    def _init_redis(self):
        """Initialize Redis connection using rapax configuration."""
        try:
            redis_config = self.config['realtime']['alerts']
            host = redis_config.get('ipv4', redis_config.get('host', 'rapax-redis'))
            port = redis_config.get('port', 6379)
            password = redis_config.get('password', '')
            
            if password:
                client = redis.Redis(host=host, port=port, password=password, db=0, decode_responses=True)
            else:
                client = redis.Redis(host=host, port=port, db=0, decode_responses=True)
            
            # Test connection
            client.ping()
            self.logger.info(f"[OSTicket Integration] Connected to Redis at {host}:{port}")
            return client
            
        except Exception as e:
            self.logger.error(f"[OSTicket Integration] Failed to connect to Redis: {e}")
            raise

    def _update_api_key_ip(self):
        """Update the API key IP in OSTicket database to this container's current IP.

        Docker assigns new IPs when containers are recreated, which causes
        OSTicket to reject API requests (401) because the ost_api_key table
        still has the old IP. This method detects the container's current IP
        and updates the database on every startup.
        """
        try:
            # Detect this container's IP address
            container_ip = socket.gethostbyname(socket.gethostname())
            self.logger.info(f"[OSTicket Integration] Container IP: {container_ip}")

            # Load encrypted credentials to get MySQL root password
            credentials = load_credentials()
            mysql_root_pass = credentials.get('ticketing', {}).get('mysql_root_password', '')

            if not mysql_root_pass:
                self.logger.warning("[OSTicket Integration] No MySQL root password in credentials, cannot update API key IP")
                return

            # Connect to OSTicket MySQL database
            conn = pymysql.connect(
                host='rapax-ticketing-mysql',
                port=3306,
                user='root',
                password=mysql_root_pass,
                database='osticket',
                connect_timeout=10
            )

            try:
                with conn.cursor() as cursor:
                    # Check current API key IP
                    cursor.execute(
                        "SELECT id, ipaddr FROM ost_api_key WHERE notes LIKE %s AND isactive=1",
                        ('%Rapax%',)
                    )
                    rows = cursor.fetchall()

                    if not rows:
                        self.logger.warning("[OSTicket Integration] No active Rapax API key found in database")
                        return

                    current_ip = rows[0][1]
                    if current_ip == container_ip:
                        self.logger.info(f"[OSTicket Integration] API key IP already correct: {container_ip}")
                        return

                    # Update to current container IP
                    cursor.execute(
                        "UPDATE ost_api_key SET ipaddr=%s WHERE notes LIKE %s AND isactive=1",
                        (container_ip, '%Rapax%')
                    )
                    conn.commit()

                    updated = cursor.rowcount
                    self.logger.info(
                        f"[OSTicket Integration] Updated API key IP from {current_ip} to {container_ip} "
                        f"({updated} row(s) updated)"
                    )
            finally:
                conn.close()

        except Exception as e:
            self.logger.warning(f"[OSTicket Integration] Could not update API key IP: {e}")
            self.logger.warning("[OSTicket Integration] API requests may fail with 401 if container IP changed")

    def _get_user_id(self, username):
        """Get user ID from OSTicket by username or email."""
        try:
            # Try to get user info by email (most reliable method)
            url = f"http://{self.osticket_host}/api/users.json"
            headers = {
                'X-API-Key': self.api_key,
                'Content-Type': 'application/json'
            }
            
            # OSTicket API typically uses email for user lookup
            params = {'email': self.ticket_format['email']}
            
            self.logger.debug(f"[OSTicket Integration] Looking up user: {username} by email: {self.ticket_format['email']}")
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                users = response.json()
                if users and len(users) > 0:
                    user_id = users[0].get('id')
                    self.logger.info(f"[OSTicket Integration] Found user ID {user_id} for {username}")
                    return user_id
            
            self.logger.warning(f"[OSTicket Integration] User {username} not found, will use email/name instead")
            return None
            
        except Exception as e:
            self.logger.warning(f"[OSTicket Integration] Error looking up user {username}: {e}")
            return None

    def _ensure_user_exists(self):
        """Ensure the configured user exists in OSTicket, create if needed."""
        try:
            if 'user' not in self.ticket_format or not self.ticket_format['user']:
                self.logger.info("[OSTicket Integration] No specific user configured, will use name/email for tickets")
                return True  # No specific user configured, will use name/email
            
            # Check if user exists
            user_id = self._get_user_id(self.ticket_format['user'])
            if user_id:
                self.logger.info(f"[OSTicket Integration] User '{self.ticket_format['user']}' exists with ID: {user_id}")
                return True
            
            # User doesn't exist, create them
            url = f"http://{self.osticket_host}/api/users.json"
            headers = {
                'X-API-Key': self.api_key,
                'Content-Type': 'application/json'
            }
            
            user_payload = {
                'name': self.ticket_format.get('name', self.ticket_format['user']),
                'email': self.ticket_format['email'],
                'phone': self.ticket_format.get('phone', ''),
                'notes': f'Auto-created user for Rapax Service Assurance Platform (username: {self.ticket_format["user"]})'
            }
            
            self.logger.info(f"[OSTicket Integration] Creating user '{self.ticket_format['user']}' in OSTicket")
            
            response = requests.post(url, json=user_payload, headers=headers, timeout=30)
            
            if response.status_code in [201, 200]:
                self.logger.info(f"[OSTicket Integration] Successfully created user '{self.ticket_format['user']}'")
                return True
            else:
                self.logger.warning(f"[OSTicket Integration] Failed to create user: {response.status_code} - {response.text}")
                self.logger.warning(f"[OSTicket Integration] Will use name/email fallback for ticket creation")
                return False
                
        except Exception as e:
            self.logger.warning(f"[OSTicket Integration] Error ensuring user exists: {e}")
            self.logger.warning(f"[OSTicket Integration] Will use name/email fallback for ticket creation")
            return False

    def _scan_alerts_needing_tickets(self):
        """Scan Redis for alert records that need tickets created."""
        alerts_needing_tickets = []
        
        try:
            # Scan for all ALERT: keys
            for key in self.redis_client.scan_iter(match="ALERT:*"):
                alert_data = self.redis_client.get(key)
                if alert_data:
                    try:
                        alert = json.loads(alert_data)
                        
                        # Check if alert has Tags field and needs a ticket
                        if self._needs_ticket(alert):
                            alerts_needing_tickets.append((key, alert))
                            self.logger.debug(f"[OSTicket Integration] Found alert needing ticket: {key}")
                            
                    except json.JSONDecodeError as e:
                        self.logger.warning(f"[OSTicket Integration] Failed to parse alert data for key {key}: {e}")
                        
        except Exception as e:
            self.logger.error(f"[OSTicket Integration] Error scanning alerts: {e}")
            
        self.logger.info(f"[OSTicket Integration] Found {len(alerts_needing_tickets)} alerts needing tickets")
        return alerts_needing_tickets

    def _needs_ticket(self, alert):
        """Check if an alert needs a ticket created."""
        # Check if alert has Tags field
        if 'Tags' not in alert or not isinstance(alert['Tags'], list):
            return False
            
        # Look for Ticket tag with empty value
        for tag in alert['Tags']:
            if isinstance(tag, dict) and 'Ticket' in tag:
                ticket_value = tag['Ticket']
                # If ticket value is empty string or None, needs a ticket
                if not ticket_value or ticket_value.strip() == "":
                    return True
                    
        return False

    def _format_ticket_data(self, alert):
        """Format alert data into OSTicket API format."""
        try:
            # Replace placeholders in subject and message templates
            subject = self.ticket_format['subject']
            message = self.ticket_format['message']
            
            # Replace template variables
            replacements = {
                '<Device>': alert.get('Device', 'Unknown'),
                '<Interface>': alert.get('Interface', 'Unknown'),
                '<Description>': alert.get('Description', 'No description'),
                '<FirstOccurred>': alert.get('FirstOccurred', 'Unknown'),
                '<LastOccurred>': alert.get('LastOccurred', 'Unknown'),
                '<UUID>': alert.get('UUID', 'Unknown'),
                '<Status>': alert.get('Status', 'Unknown'),
                '<Category>': alert.get('Category', 'Unknown'),
                '<Location>': alert.get('Location', 'Unknown'),
                '<DeviceType>': alert.get('DeviceType', 'Unknown'),
                '<IP>': alert.get('IP', 'Unknown')
            }
            
            for placeholder, value in replacements.items():
                subject = subject.replace(placeholder, str(value))
                message = message.replace(placeholder, str(value))
            
            # Base ticket data
            ticket_data = {
                'subject': subject,
                'message': message,
                'ip': alert.get('IP', ''),
                'source': 'API',
                'priority': self._map_status_to_priority(alert.get('Status', 'Normal')),
                'autorespond': False,
                'alertUser': False
            }
            
            # Handle user specification - try user field first, then fall back to name/email
            if 'user' in self.ticket_format and self.ticket_format['user']:
                # Try to get user ID for existing user
                user_id = self._get_user_id(self.ticket_format['user'])
                if user_id:
                    ticket_data['user'] = user_id
                    self.logger.debug(f"[OSTicket Integration] Using existing user ID: {user_id}")
                else:
                    # Fall back to creating with name/email if user not found
                    ticket_data['name'] = self.ticket_format.get('name', self.ticket_format['user'])
                    ticket_data['email'] = self.ticket_format['email']
                    self.logger.debug(f"[OSTicket Integration] User not found, using name/email fallback")
            else:
                # Use name/email for new user creation
                ticket_data['name'] = self.ticket_format.get('name', 'Rapax System')
                ticket_data['email'] = self.ticket_format['email']
            
            # Add optional fields if configured
            if 'phone' in self.ticket_format:
                ticket_data['phone'] = self.ticket_format['phone']
            if 'topicId' in self.ticket_format:
                ticket_data['topicId'] = self.ticket_format['topicId']
            if 'department' in self.ticket_format:
                ticket_data['deptId'] = self.ticket_format['department']
            
            self.logger.debug(f"[OSTicket Integration] Formatted ticket data for alert {alert.get('UUID', 'Unknown')}")
            return ticket_data
            
        except Exception as e:
            self.logger.error(f"[OSTicket Integration] Error formatting ticket data: {e}")
            return None

    def _map_status_to_priority(self, status):
        """Map alert status to OSTicket priority."""
        priority_map = {
            'Critical': 'Emergency',
            'Major': 'High', 
            'Minor': 'Normal',
            'Warning': 'Low',
            'Clear': 'Low'
        }
        return priority_map.get(status, 'Normal')

    def _create_osticket(self, ticket_data):
        """Create ticket in OSTicket via JSON API."""
        try:
            url = f"http://{self.osticket_host}/api/tickets.json"
            headers = {
                'X-API-Key': self.api_key,
                'Content-Type': 'application/json'
            }
            
            self.logger.debug(f"[OSTicket Integration] Creating ticket via API: {url}")
            self.logger.debug(f"[OSTicket Integration] Ticket payload: {json.dumps(ticket_data, indent=2)}")
            
            response = requests.post(url, json=ticket_data, headers=headers, timeout=30)
            
            if response.status_code == 201:
                # OSTicket typically returns ticket ID in response
                ticket_id = response.text.strip()
                self.logger.info(f"[OSTicket Integration] Successfully created ticket: {ticket_id}")
                return ticket_id
            else:
                self.logger.error(f"[OSTicket Integration] Failed to create ticket. Status: {response.status_code}")
                self.logger.error(f"[OSTicket Integration] Response headers: {dict(response.headers)}")
                self.logger.error(f"[OSTicket Integration] Response body: {response.text}")
                
                # If user-related error, try alternative approach
                if "user" in response.text.lower() and 'user' in ticket_data:
                    self.logger.warning(f"[OSTicket Integration] User-related error detected, trying with name/email instead")
                    # Remove user field and try with name/email
                    fallback_data = ticket_data.copy()
                    del fallback_data['user']
                    fallback_data['name'] = self.ticket_format.get('name', self.ticket_format.get('user', 'Rapax System'))
                    fallback_data['email'] = self.ticket_format['email']
                    
                    self.logger.debug(f"[OSTicket Integration] Fallback payload: {json.dumps(fallback_data, indent=2)}")
                    
                    fallback_response = requests.post(url, json=fallback_data, headers=headers, timeout=30)
                    if fallback_response.status_code == 201:
                        ticket_id = fallback_response.text.strip()
                        self.logger.info(f"[OSTicket Integration] Successfully created ticket with fallback method: {ticket_id}")
                        return ticket_id
                    else:
                        self.logger.error(f"[OSTicket Integration] Fallback also failed: Status {fallback_response.status_code}")
                        self.logger.error(f"[OSTicket Integration] Fallback response: {fallback_response.text}")
                
                # Try to parse error details if JSON
                try:
                    error_data = response.json()
                    self.logger.error(f"[OSTicket Integration] Error details: {json.dumps(error_data, indent=2)}")
                except:
                    pass
                    
                return None
                
        except requests.exceptions.Timeout:
            self.logger.error(f"[OSTicket Integration] Timeout creating ticket")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"[OSTicket Integration] Request error creating ticket: {e}")
            return None
        except Exception as e:
            self.logger.error(f"[OSTicket Integration] Unexpected error creating ticket: {e}")
            return None

    def _update_alert_with_ticket_id(self, alert_key, alert_data, ticket_id):
        """Update alert record in Redis with the ticket ID."""
        try:
            # Update the Tags field with ticket ID
            updated_alert = alert_data.copy()
            
            # Find and update the Ticket tag
            if 'Tags' in updated_alert and isinstance(updated_alert['Tags'], list):
                for tag in updated_alert['Tags']:
                    if isinstance(tag, dict) and 'Ticket' in tag:
                        tag['Ticket'] = ticket_id
                        break
            else:
                # Create Tags field if it doesn't exist
                updated_alert['Tags'] = [{'Ticket': ticket_id}]
            
            # Update LastOccurred timestamp
            updated_alert['LastOccurred'] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            
            # Save back to Redis
            self.redis_client.set(alert_key, json.dumps(updated_alert))
            
            # Publish update to alerts channel
            updated_alert['key'] = alert_key
            self.redis_client.publish('alerts', json.dumps(updated_alert))
            
            self.logger.info(f"[OSTicket Integration] Updated alert {alert_key} with ticket ID: {ticket_id}")
            return True

        except Exception as e:
            self.logger.error(f"[OSTicket Integration] Failed to update alert {alert_key} with ticket ID: {e}")
            return False

    # ------------------------------------------------------------------
    # Bidirectional notes sync and status change detection
    # ------------------------------------------------------------------

    def _get_mysql_connection(self):
        """Get a connection to the OSTicket MySQL database."""
        credentials = load_credentials()
        mysql_root_pass = credentials.get('ticketing', {}).get('mysql_root_password', '')

        if not mysql_root_pass:
            raise Exception("No MySQL root password in credentials")

        return pymysql.connect(
            host='rapax-ticketing-mysql',
            port=3306,
            user='root',
            password=mysql_root_pass,
            database='osticket',
            connect_timeout=10
        )

    def _get_ticket_number(self, alert):
        """Extract ticket number from alert Tags."""
        if 'Tags' not in alert or not isinstance(alert['Tags'], list):
            return None
        for tag in alert['Tags']:
            if isinstance(tag, dict) and 'Ticket' in tag:
                ticket_value = tag['Ticket']
                if ticket_value and str(ticket_value).strip():
                    return str(ticket_value).strip()
        return None

    def _has_tag(self, alert, tag_name):
        """Check if alert has a specific tag with a truthy value."""
        if 'Tags' not in alert or not isinstance(alert['Tags'], list):
            return False
        for tag in alert['Tags']:
            if isinstance(tag, dict) and tag_name in tag and tag[tag_name]:
                return True
        return False

    def _set_tag(self, alert, tag_name, tag_value):
        """Set a tag value on an alert, creating Tags array if needed."""
        if 'Tags' not in alert or not isinstance(alert['Tags'], list):
            alert['Tags'] = []
        for tag in alert['Tags']:
            if isinstance(tag, dict) and tag_name in tag:
                tag[tag_name] = tag_value
                return
        alert['Tags'].append({tag_name: tag_value})

    def _post_note_to_osticket(self, ticket_number, note_body):
        """Post an internal note to an existing OSTicket ticket via MySQL INSERT.

        OSTicket's REST API does not support adding notes to tickets, so we
        directly insert into the ost_thread_entry table.
        """
        try:
            conn = self._get_mysql_connection()
            try:
                with conn.cursor() as cursor:
                    # Get ticket_id from ticket number
                    cursor.execute(
                        "SELECT ticket_id FROM ost_ticket WHERE number = %s",
                        (ticket_number,)
                    )
                    row = cursor.fetchone()
                    if not row:
                        self.logger.warning(
                            f"[OSTicket Integration] Ticket {ticket_number} not found in database"
                        )
                        return False
                    ticket_id = row[0]

                    # Get thread_id for this ticket
                    cursor.execute(
                        "SELECT id FROM ost_thread WHERE object_id = %s AND object_type = 'T'",
                        (ticket_id,)
                    )
                    row = cursor.fetchone()
                    if not row:
                        self.logger.warning(
                            f"[OSTicket Integration] Thread not found for ticket {ticket_number}"
                        )
                        return False
                    thread_id = row[0]

                    # Insert the note into ost_thread_entry
                    # type='N' is internal note, 'R' is response, 'M' is message
                    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    cursor.execute("""
                        INSERT INTO ost_thread_entry
                            (thread_id, staff_id, user_id, type, poster, body, format, created, updated)
                        VALUES
                            (%s, 0, 0, 'N', 'Rapax', %s, 'text', %s, %s)
                    """, (thread_id, note_body, now, now))
                    conn.commit()

                    self.logger.info(
                        f"[OSTicket Integration] Posted note to ticket {ticket_number} "
                        f"(thread_id={thread_id})"
                    )
                    return True

            finally:
                conn.close()

        except Exception as e:
            self.logger.warning(
                f"[OSTicket Integration] Error posting note to ticket {ticket_number}: {e}"
            )
            return False

    def _pull_notes_from_osticket(self, alert_key, alert, ticket_number):
        """Pull new notes from an OSTicket ticket into the alert's Notes array.

        Queries the OSTicket MySQL database for thread entries (notes, responses)
        that haven't already been synced to the alert.  Uses OSTicketEntryId to
        avoid importing duplicates, and skips entries that originated from Rapax
        to prevent circular sync loops.
        """
        try:
            conn = self._get_mysql_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT te.id, te.poster, te.body, te.created, te.type
                        FROM ost_thread_entry te
                        JOIN ost_thread t ON te.thread_id = t.id
                        JOIN ost_ticket tk ON t.object_id = tk.ticket_id
                            AND t.object_type = 'T'
                        WHERE tk.number = %s
                        ORDER BY te.created ASC
                    """, (ticket_number,))
                    entries = cursor.fetchall()
            finally:
                conn.close()

            if not entries:
                return False

            # Collect entry IDs already imported
            existing_ids = set()
            if alert.get('Notes') and isinstance(alert['Notes'], list):
                for note in alert['Notes']:
                    eid = note.get('OSTicketEntryId')
                    if eid is not None:
                        existing_ids.add(int(eid))

            # Import new entries
            if 'Notes' not in alert or not isinstance(alert['Notes'], list):
                alert['Notes'] = []

            updated = False
            for entry_id, poster, body, created, entry_type in entries:
                if entry_id in existing_ids:
                    continue

                # Skip entries posted by Rapax (circular-sync guard)
                body_str = str(body) if body else ''
                if body_str.startswith('[Rapax Note') or body_str.startswith('[Rapax Alert Cleared]'):
                    continue

                type_label = {
                    'N': 'Internal Note', 'R': 'Response', 'M': 'Message'
                }.get(entry_type, 'Note')

                # Strip HTML tags (OSTicket stores rich-text HTML)
                clean_body = re.sub(r'<[^>]+>', '', body_str).strip()
                if not clean_body:
                    continue

                ts = (created.strftime('%Y-%m-%dT%H:%M:%S.000Z')
                      if hasattr(created, 'strftime') else str(created))

                alert['Notes'].append({
                    'Timestamp': ts,
                    'Author': f"OSTicket: {poster or 'System'} ({type_label})",
                    'Entry': clean_body,
                    'Source': 'osticket',
                    'OSTicketEntryId': entry_id
                })
                updated = True
                self.logger.info(
                    f"[OSTicket Integration] Pulled note #{entry_id} from ticket "
                    f"{ticket_number} (by {poster}, type={entry_type})"
                )

            if updated:
                self.redis_client.set(alert_key, json.dumps(alert))
                publish_alert = {**alert, 'key': alert_key}
                self.redis_client.publish('alerts', json.dumps(publish_alert))
                self.logger.info(
                    f"[OSTicket Integration] Updated alert {alert_key} with "
                    f"notes from ticket {ticket_number}"
                )

            return updated

        except Exception as e:
            self.logger.warning(
                f"[OSTicket Integration] Error pulling notes from ticket {ticket_number}: {e}"
            )
            return False

    def _sync_notes(self):
        """Synchronize notes bidirectionally between Rapax alerts and OSTicket.

        Push direction:  New notes in the alert's Notes array (that did not
                         originate from OSTicket) are posted to the OSTicket
                         ticket as internal notes.
        Pull direction:  New thread entries in OSTicket (that did not originate
                         from Rapax) are imported into the alert's Notes array.
        Deduplication:   * Pushed notes are flagged with SyncedToOSTicket=True.
                         * Pulled notes carry Source='osticket' and an
                           OSTicketEntryId; the push path skips those.
        """
        synced_count = 0

        try:
            for key in self.redis_client.scan_iter(match="ALERT:*"):
                alert_data = self.redis_client.get(key)
                if not alert_data:
                    continue

                try:
                    alert = json.loads(alert_data)
                except (json.JSONDecodeError, TypeError):
                    continue

                ticket_number = self._get_ticket_number(alert)
                if not ticket_number:
                    continue

                key_str = key if isinstance(key, str) else key.decode('utf-8')
                push_modified = False

                # --- Push: Rapax notes -> OSTicket ---
                if alert.get('Notes') and isinstance(alert['Notes'], list):
                    for note in alert['Notes']:
                        if note.get('SyncedToOSTicket'):
                            continue
                        if note.get('Source') == 'osticket':
                            continue

                        entry = note.get('Entry', '')
                        if not entry:
                            continue

                        author = note.get('Author', 'Rapax')
                        timestamp = note.get('Timestamp', '')
                        body = f"[Rapax Note - {author} @ {timestamp}]\n\n{entry}"

                        if self._post_note_to_osticket(ticket_number, body):
                            note['SyncedToOSTicket'] = True
                            push_modified = True
                            synced_count += 1

                # Save push-side changes before pull (pull saves its own changes)
                if push_modified:
                    self.redis_client.set(key_str, json.dumps(alert))

                # --- Pull: OSTicket notes -> Rapax ---
                if self._pull_notes_from_osticket(key_str, alert, ticket_number):
                    synced_count += 1

        except Exception as e:
            self.logger.error(f"[OSTicket Integration] Error in notes sync: {e}")

        if synced_count > 0:
            self.logger.info(
                f"[OSTicket Integration] Notes sync complete: {synced_count} sync operations"
            )
        return synced_count

    def _check_cleared_alerts(self):
        """Detect alerts that have cleared and post a notification to their OSTicket ticket.

        When an alert's Status changes to "Up" or "Clear" and it has an
        associated ticket, an internal note is posted to the ticket.  A
        TicketCleared tag is set on the alert to prevent duplicate notifications.
        """
        cleared_count = 0

        try:
            for key in self.redis_client.scan_iter(match="ALERT:*"):
                alert_data = self.redis_client.get(key)
                if not alert_data:
                    continue

                try:
                    alert = json.loads(alert_data)
                except (json.JSONDecodeError, TypeError):
                    continue

                ticket_number = self._get_ticket_number(alert)
                if not ticket_number:
                    continue

                status = alert.get('Status', '').strip()
                if status not in ('Up', 'Clear'):
                    continue

                # Already notified for this clear
                if self._has_tag(alert, 'TicketCleared'):
                    continue

                key_str = key if isinstance(key, str) else key.decode('utf-8')

                device = alert.get('Device', 'Unknown')
                description = alert.get('Description', '')
                last_occurred = alert.get('LastOccurred', '')

                note_body = (
                    f"[Rapax Alert Cleared]\n\n"
                    f"The originating alert has been cleared.\n\n"
                    f"Device: {device}\n"
                    f"Status: {status}\n"
                    f"Description: {description}\n"
                    f"Cleared at: {last_occurred}\n"
                )

                if self._post_note_to_osticket(ticket_number, note_body):
                    self._set_tag(alert, 'TicketCleared', 'true')
                    self.redis_client.set(key_str, json.dumps(alert))
                    publish_alert = {**alert, 'key': key_str}
                    self.redis_client.publish('alerts', json.dumps(publish_alert))
                    cleared_count += 1
                    self.logger.info(
                        f"[OSTicket Integration] Posted clear notification to "
                        f"ticket {ticket_number} for alert {key_str}"
                    )

        except Exception as e:
            self.logger.error(f"[OSTicket Integration] Error checking cleared alerts: {e}")

        if cleared_count > 0:
            self.logger.info(
                f"[OSTicket Integration] Cleared alerts: {cleared_count} tickets notified"
            )
        return cleared_count

    def process_alerts(self):
        """Main processing loop to handle alerts needing tickets."""
        self.logger.info("[OSTicket Integration] Starting alert processing cycle")
        
        try:
            # Scan for alerts needing tickets
            alerts_needing_tickets = self._scan_alerts_needing_tickets()
            
            tickets_created = 0
            for alert_key, alert_data in alerts_needing_tickets:
                try:
                    # Format ticket data
                    ticket_data = self._format_ticket_data(alert_data)
                    if not ticket_data:
                        continue
                    
                    # Create ticket in OSTicket
                    ticket_id = self._create_osticket(ticket_data)
                    if ticket_id:
                        # Update alert with ticket ID
                        if self._update_alert_with_ticket_id(alert_key, alert_data, ticket_id):
                            tickets_created += 1
                        
                except Exception as e:
                    self.logger.error(f"[OSTicket Integration] Error processing alert {alert_key}: {e}")
                    continue
            
            self.logger.info(f"[OSTicket Integration] Ticket creation complete. Created {tickets_created} tickets")

            # Synchronize notes bidirectionally for alerts that already have tickets
            notes_synced = self._sync_notes()

            # Check for alerts that have cleared and notify their tickets
            alerts_cleared = self._check_cleared_alerts()

            self.logger.info(
                f"[OSTicket Integration] Processing cycle complete. "
                f"Tickets created: {tickets_created}, Notes synced: {notes_synced}, "
                f"Clear notifications: {alerts_cleared}"
            )
            return tickets_created

        except Exception as e:
            self.logger.error(f"[OSTicket Integration] Error in processing cycle: {e}")
            return 0

    def run_daemon(self, interval=60):
        """Run the integration as a daemon process."""
        self.logger.info(f"[OSTicket Integration] Starting daemon mode with {interval}s interval")
        
        try:
            while True:
                self.process_alerts()
                self.logger.debug(f"[OSTicket Integration] Sleeping for {interval} seconds")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.logger.info("[OSTicket Integration] Daemon stopped by user")
        except Exception as e:
            self.logger.error(f"[OSTicket Integration] Daemon error: {e}")
            raise

def main():
    """Main entry point."""
    try:
        integration = OSTicketIntegration()
        
        # Check command line arguments
        if len(sys.argv) > 1 and sys.argv[1] == '--daemon':
            # Run as daemon
            interval = int(sys.argv[2]) if len(sys.argv) > 2 else 60
            integration.run_daemon(interval)
        else:
            # Run once
            tickets_created = integration.process_alerts()
            print(f"Created {tickets_created} tickets")
            
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
