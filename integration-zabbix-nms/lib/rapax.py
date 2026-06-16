import redis
import json
import logging
import os
import hashlib
import base64
from datetime import datetime
from opensearchpy import OpenSearch

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Global configuration object
RapaxConfig = None

# Global connection objects (singletons)
_redis_client = None
_opensearch_client = None

# Global credentials cache
_credentials_cache = None


def _derive_encryption_key():
    """
    Derive encryption key from machine-id and hostname.

    Uses PBKDF2 with machine-id as password and hostname as salt.
    This makes the key unique per machine but deterministic.

    Returns:
        Fernet encryption key
    """
    if not CRYPTO_AVAILABLE:
        raise Exception("cryptography library not available. Install with: pip install cryptography")

    try:
        # Read machine-id (unique per installation)
        with open('/etc/machine-id', 'r') as f:
            machine_id = f.read().strip()
    except FileNotFoundError:
        # Fallback for systems without machine-id
        machine_id = "rapax-default-key"

    # Get hostname as additional entropy
    hostname = os.uname().nodename

    # Combine for password and salt
    password = f"rapax-{machine_id}".encode()
    salt = f"{hostname}-salt".encode()

    # Derive key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def load_credentials(credentials_file=None):
    """
    Load and decrypt credentials from the credentials file.

    Args:
        credentials_file: Path to credentials file (defaults to $RAPAXHOME/credentials)

    Returns:
        Dictionary with decrypted credentials:
        {
            'redis': {'password': '...'},
            'opensearch': {'username': '...', 'password': '...'},
            'portainer': {'password': '...'}
        }

    Raises:
        Exception if credentials file doesn't exist or decryption fails
    """
    global _credentials_cache

    # Return cached credentials if available
    if _credentials_cache is not None:
        return _credentials_cache

    # Default credentials file location
    if credentials_file is None:
        rapax_home = os.environ.get('RAPAXHOME', '/opt/rapax')
        credentials_file = os.path.join(rapax_home, 'etc', 'credentials')

    # Check if file exists
    if not os.path.exists(credentials_file):
        raise Exception(f"Credentials file not found: {credentials_file}")

    if not CRYPTO_AVAILABLE:
        raise Exception("cryptography library not available")

    try:
        # Read encrypted credentials
        with open(credentials_file, 'rb') as f:
            encrypted_data = f.read()

        # Derive encryption key
        key = _derive_encryption_key()
        fernet = Fernet(key)

        # Decrypt
        decrypted_data = fernet.decrypt(encrypted_data)
        credentials = json.loads(decrypted_data.decode())

        # Cache for future calls
        _credentials_cache = credentials

        return credentials

    except Exception as e:
        raise Exception(f"Failed to load credentials: {e}")


def save_credentials(credentials, credentials_file=None):
    """
    Encrypt and save credentials to file.

    Args:
        credentials: Dictionary with credentials to save
        credentials_file: Path to credentials file (defaults to $RAPAXHOME/credentials)

    Example:
        credentials = {
            'redis': {'password': 'secure_redis_pass'},
            'opensearch': {'username': 'admin', 'password': 'secure_os_pass'},
            'portainer': {'password': 'secure_portainer_pass'}
        }
        save_credentials(credentials)
    """
    global _credentials_cache

    # Default credentials file location
    if credentials_file is None:
        rapax_home = os.environ.get('RAPAXHOME', '/opt/rapax')
        credentials_file = os.path.join(rapax_home, 'etc', 'credentials')

    if not CRYPTO_AVAILABLE:
        raise Exception("cryptography library not available")

    try:
        # Derive encryption key
        key = _derive_encryption_key()
        fernet = Fernet(key)

        # Encrypt credentials
        json_data = json.dumps(credentials, indent=2).encode()
        encrypted_data = fernet.encrypt(json_data)

        # Write to file with restricted permissions
        with open(credentials_file, 'wb') as f:
            f.write(encrypted_data)

        # Set file permissions to 600 (owner read/write only)
        os.chmod(credentials_file, 0o600)

        # Clear cache
        _credentials_cache = None

    except Exception as e:
        raise Exception(f"Failed to save credentials: {e}")


def load_config():
    """
    Load Rapax configuration from credentials file or environment variables.

    Priority:
    1. Try to load from encrypted credentials file ($RAPAXHOME/credentials)
    2. Fall back to environment variables if credentials file doesn't exist

    Returns configuration dict with structure expected by Flask APIs
    """
    global RapaxConfig

    # Try to load from credentials file first
    try:
        credentials = load_credentials()
        redis_password = credentials.get('redis', {}).get('password', '')
        opensearch_user = credentials.get('opensearch', {}).get('username', 'admin')
        opensearch_password = credentials.get('opensearch', {}).get('password', 'admin')
    except Exception:
        # Fall back to environment variables (backward compatibility)
        redis_password = os.environ.get('REDIS_PASSWORD', '')
        opensearch_user = os.environ.get('OPENSEARCH_USER', 'admin')
        opensearch_password = os.environ.get('OPENSEARCH_PASSWORD', 'admin')

    # Get other configuration from environment variables
    redis_host = os.environ.get('REDIS_HOST', 'rapax-redis')
    redis_port = int(os.environ.get('REDIS_PORT', '6379'))

    opensearch_hosts = os.environ.get('OPENSEARCH_HOSTS', 'https://rapax-opensearch:9200')
    opensearch_verify_certs = os.environ.get('OPENSEARCH_VERIFY_CERTS', 'false').lower() == 'true'

    # Server configuration for internal API access (bypasses nginx auth)
    server_host = os.environ.get('SERVER_HOST', 'localhost')
    server_port = os.environ.get('SERVER_PORT', '5000')

    # Build configuration structure
    RapaxConfig = {
        'server': {
            'ipv4': f"{server_host}:{server_port}"
        },
        'realtime': {
            'redis': {
                'ipv4': redis_host,
                'port': redis_port,
                'password': redis_password
            },
            'alerts': {
                'channel': 'alerts',
                'host': redis_host,
                'port': redis_port,
                'password': redis_password
            }
        },
        'historical': {
            'opensearch': {
                'url': opensearch_hosts,
                'username': opensearch_user,
                'password': opensearch_password,
                'verify_certs': opensearch_verify_certs
            }
        }
    }

    return RapaxConfig


def setup_logging(log_level=None):
    """
    Setup Python logging for Flask APIs

    Args:
        log_level: Optional logging level (defaults to INFO)

    Returns:
        Logger instance
    """
    if log_level is None:
        log_level_str = os.environ.get('LOG_LEVEL', 'INFO')
        log_level = getattr(logging, log_level_str.upper(), logging.INFO)

    # Configure logging format
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Create and return logger
    logger = logging.getLogger('rapax')
    return logger


def get_redis_client():
    """
    Get singleton Redis client instance

    Creates connection on first call, then reuses it.
    Uses configuration from RapaxConfig loaded by load_config().

    Returns:
        Redis client instance

    Raises:
        Exception if RapaxConfig not loaded or connection fails
    """
    global _redis_client

    if _redis_client is not None:
        return _redis_client

    if RapaxConfig is None:
        raise Exception("RapaxConfig not loaded. Call load_config() first.")

    redis_config = RapaxConfig['realtime']['redis']
    host = redis_config['ipv4']
    port = redis_config['port']
    password = redis_config.get('password', '')

    try:
        _redis_client = redis.Redis(
            host=host,
            port=port,
            password=password if password else None,
            db=0,
            decode_responses=False,
            socket_connect_timeout=5,
            socket_timeout=5,
            socket_keepalive=True,
            health_check_interval=30
        )

        # Test connection
        _redis_client.ping()

        return _redis_client
    except Exception as e:
        raise Exception(f"Failed to connect to Redis at {host}:{port}: {e}")


def get_opensearch_client():
    """
    Get singleton OpenSearch client instance

    Creates connection on first call, then reuses it.
    Uses configuration from RapaxConfig loaded by load_config().

    Returns:
        OpenSearch client instance

    Raises:
        Exception if RapaxConfig not loaded or connection fails
    """
    global _opensearch_client

    if _opensearch_client is not None:
        return _opensearch_client

    if RapaxConfig is None:
        raise Exception("RapaxConfig not loaded. Call load_config() first.")

    opensearch_config = RapaxConfig['historical']['opensearch']
    hosts = opensearch_config['url']
    username = opensearch_config['username']
    password = opensearch_config['password']
    verify_certs = opensearch_config.get('verify_certs', False)

    try:
        _opensearch_client = OpenSearch(
            hosts=[hosts],
            http_auth=(username, password),
            use_ssl=True,
            verify_certs=verify_certs,
            ssl_show_warn=False,
            timeout=30,
            max_retries=3,
            retry_on_timeout=True,
            pool_maxsize=10
        )

        # Test connection
        _opensearch_client.info()

        return _opensearch_client
    except Exception as e:
        raise Exception(f"Failed to connect to OpenSearch at {hosts}: {e}")


def send_message(logger, key, message):
    """
    Send message to Redis Stream for core-collection ingestion

    Replaces legacy TCP socket approach with Redis Streams.
    Messages are sent to stream:{key} for processing by core-collection container.
    Uses singleton Redis client from get_redis_client().

    Args:
        logger: Python logger instance
        key: Stream type - one of 'logs', 'alerts', 'devices', 'stats', 'services'
        message: JSON string or dict to send

    Example:
        log_data = {
            '@timestamp': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            'level': 'INFO',
            'message': 'Device polling completed',
            'source': 'snmp-poller',
            'device': 'router-01'
        }
        send_message(logger, 'logs', json.dumps(log_data))
    """
    stream_key = f"stream:{key}"

    try:
        # Use singleton Redis client
        redis_client = get_redis_client()

        # Parse message if it's a JSON string
        if isinstance(message, str):
            try:
                message_dict = json.loads(message)
            except json.JSONDecodeError:
                logger.error(f"[redis stream]: Invalid JSON in message: {message[:100]}")
                return None
        else:
            message_dict = message

        # Ensure @timestamp exists for logs and stats
        if key in ['logs', 'stats'] and '@timestamp' not in message_dict:
            message_dict['@timestamp'] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        # Add to stream with automatic trimming
        message_id = redis_client.xadd(
            stream_key,
            {'message': json.dumps(message_dict)},
            maxlen=10000,
            approximate=True
        )

        logger.debug(f"[redis stream]: Message sent to {stream_key} with ID {message_id}")
        return message_id

    except Exception as e:
        logger.error(f"[redis stream]: Error sending to {stream_key} - {e}")
        raise


def insert_alert(logger, AlertHash):
    """
    Insert or update alert in Redis with deduplication, then send to stream for indexing

    This function:
    1. Creates Redis key: ALERT:{device}:{interface}:{category}:{state}
    2. Checks if alert already exists (deduplication)
    3. If exists: Updates LastOccurred and increments Number count
    4. If new: Stores fresh alert
    5. Sends alert to stream:alerts for core-collection to index to OpenSearch

    Uses singleton Redis client from get_redis_client().

    Args:
        logger: Python logger instance
        AlertHash: Dictionary with alert fields

    Example:
        alert_hash = {
            'UUID': str(uuid.uuid4()),
            'Device': 'router-01',
            'Interface': 'GigabitEthernet0/0/1',
            'IP': '192.168.1.1',
            'Status': 'Critical',
            'State': 'Down',
            'Category': 'InterfaceDown',
            'Location': 'DataCenter1',
            'Description': 'Interface is down',
            'FirstOccurred': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            'LastOccurred': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            'Number': 1,
            'DeviceType': 'Router',
            'Parent': '',
            'Notes': []
        }
        insert_alert(logger, alert_hash)
    """
    device = AlertHash['Device']
    interface = AlertHash['Interface']
    category = AlertHash['Category']
    state = AlertHash['State']

    key = f"ALERT:{device}:{interface}:{category}:{state}"

    try:
        # Use singleton Redis client (with decode_responses for key-value operations)
        redis_client = get_redis_client()

        # For key-value operations, we need string responses
        # Create a separate client instance with decode_responses=True
        redis_config = RapaxConfig['realtime']['redis']
        redis_kv_client = redis.Redis(
            host=redis_config['ipv4'],
            port=redis_config['port'],
            password=redis_config.get('password') if redis_config.get('password') else None,
            db=0,
            decode_responses=True
        )

        # Check if alert already exists (deduplication)
        existing_alert_json = redis_kv_client.get(key)

        if existing_alert_json:
            # Alert exists - update it
            logger.debug(f"[redis]: Found existing alert: {key}")

            try:
                AlertCurrentHash = json.loads(existing_alert_json)

                # Increment count
                AlertCurrentHash['Number'] = int(AlertCurrentHash.get('Number', 0)) + int(AlertHash.get('Number', 1))

                # Update mutable fields (don't touch immutable fields like UUID, Device, etc.)
                AlertCurrentHash['LastOccurred'] = AlertHash.get('LastOccurred', datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
                AlertCurrentHash['Status'] = AlertHash.get('Status', AlertCurrentHash.get('Status'))
                AlertCurrentHash['Description'] = AlertHash.get('Description', AlertCurrentHash.get('Description'))

                # Update @timestamp for indexing
                AlertCurrentHash['@timestamp'] = AlertCurrentHash['LastOccurred']

                logger.info(f"[redis]: Updated alert [{key}] - Count: {AlertCurrentHash['Number']}")

                # Save updated alert to Redis
                redis_kv_client.set(key, json.dumps(AlertCurrentHash))

                # Send to stream for core-collection
                send_message(logger, 'alerts', AlertCurrentHash)

            except json.JSONDecodeError as e:
                logger.error(f"[redis]: Failed to parse existing alert {key}: {e}")
                # Treat as new alert
                AlertHash['@timestamp'] = AlertHash.get('LastOccurred', datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
                redis_kv_client.set(key, json.dumps(AlertHash))
                send_message(logger, 'alerts', AlertHash)
        else:
            # New alert
            logger.info(f"[redis]: New alert [{key}]")

            # Ensure required fields
            if 'Number' not in AlertHash:
                AlertHash['Number'] = 1
            if 'FirstOccurred' not in AlertHash:
                AlertHash['FirstOccurred'] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            if 'LastOccurred' not in AlertHash:
                AlertHash['LastOccurred'] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            # Add @timestamp for indexing
            AlertHash['@timestamp'] = AlertHash['LastOccurred']

            # Add key for reference
            AlertHash['key'] = key

            # Save to Redis
            redis_kv_client.set(key, json.dumps(AlertHash))

            # Send to stream for core-collection
            send_message(logger, 'alerts', AlertHash)

    except Exception as e:
        logger.error(f"[redis]: Error in insert_alert for {key} - {e}")
        raise
