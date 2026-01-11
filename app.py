from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import json
import time
import os
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
import threading
from queue import Queue
import atexit
import secrets
import hashlib
import copy
import bcrypt
from zxcvbn import zxcvbn

app = Flask(__name__, 
            static_folder='static',
            static_url_path='/static')

# CORS disabled for security - not needed since Flask serves both HTML and API from same origin
# Each access method (local IP, domain, localhost) works without CORS
# Only enable if you have a separate frontend application calling this API
# CORS(app)

# Session configuration with security flags
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['start_time'] = time.time()  # Set start time at module load

# Session security flags
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie (XSS protection)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection - cookies only sent on same-site requests
# Note: SESSION_COOKIE_SECURE is set dynamically based on request protocol (see @app.before_request below)
# This allows both HTTP (local IP) and HTTPS (domain) access to work correctly

# Rate limiting configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,  # Rate limit by IP address
    default_limits=["200 per day", "50 per hour"],  # Default limits for all routes
    storage_uri="memory://",  # Use in-memory storage (simple, no external dependencies)
)

CONFIG_FILE = '/config/config.json'
LOG_DIR = '/config/logs'
WEBHOOK_QUEUE = Queue()
WORKER_THREAD = None
WORKER_STARTED = False

# Configure logging
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

file_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, 'app.log'),
    maxBytes=10485760,
    backupCount=10
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
))
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

DEFAULT_CONFIG = {
    'auth': {
        'username': '',
        'password_hash': '',
        'secret_key': '',
        'setup_complete': False
    },
    'overseerr': {
        'url': 'http://overseerr:5055',
        'api_key': '',
        'timeout': 30
    },
    'sonarr': {
        'url': 'http://sonarr:8989',
        'api_key': '',
        'timeout': 30
    },
    'radarr': {
        'url': 'http://radarr:7878',
        'api_key': '',
        'timeout': 30
    },
    'webhook': {
        'auth_header': '',
        'enabled': True
    },
    'processing': {
        'retry_attempts': 3,
        'retry_delay': 5,
        'queue_enabled': True
    }
}

def hash_password(password):
    """Hash a password using bcrypt"""
    # Generate salt and hash the password
    salt = bcrypt.gensalt(rounds=12)  # 12 rounds is a good balance of security and performance
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
    return password_hash.decode('utf-8')  # Store as string

def is_legacy_sha256_hash(password_hash):
    """Check if a password hash is the old SHA-256 format"""
    # Old SHA-256 hashes are exactly 64 hexadecimal characters
    if not password_hash:
        return False
    return len(password_hash) == 64 and all(c in '0123456789abcdef' for c in password_hash.lower())

def verify_password_legacy(password, password_hash):
    """Verify password against legacy SHA-256 hash"""
    legacy_hash = hashlib.sha256(password.encode()).hexdigest()
    return legacy_hash == password_hash

def verify_password(password, password_hash):
    """
    Verify a password against a hash.
    Supports both bcrypt (new) and SHA-256 (legacy) hashes for migration.
    Returns tuple: (is_valid, needs_upgrade)
    """
    if not password_hash:
        return False, False
    
    # Check if it's a legacy SHA-256 hash
    if is_legacy_sha256_hash(password_hash):
        is_valid = verify_password_legacy(password, password_hash)
        return is_valid, is_valid  # If valid, needs upgrade to bcrypt
    
    # It's a bcrypt hash
    try:
        is_valid = bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        return is_valid, False  # Already bcrypt, no upgrade needed
    except Exception as e:
        app.logger.error(f"Error verifying bcrypt password: {e}")
        return False, False

def check_password_strength(password, user_inputs=None):
    """
    Check password strength using zxcvbn.
    
    Args:
        password: The password to check
        user_inputs: Optional list of user-specific strings (username, email, etc.)
    
    Returns:
        tuple: (is_acceptable, score, feedback_dict)
            is_acceptable: bool - True if password meets minimum requirements
            score: int - Strength score from 0-4
            feedback_dict: dict - Contains warning, suggestions, and score_text
    """
    if not password:
        return False, 0, {
            'warning': 'Password is required',
            'suggestions': [],
            'score_text': 'Too weak'
        }
    
    # Minimum length check (fail fast)
    if len(password) < 8:
        return False, 0, {
            'warning': 'Password is too short',
            'suggestions': ['Use at least 8 characters'],
            'score_text': 'Too weak'
        }
    
    # Use zxcvbn to analyze password strength
    result = zxcvbn(password, user_inputs=user_inputs or [])
    
    score = result['score']  # 0-4 scale
    warning = result['feedback'].get('warning', '')
    suggestions = result['feedback'].get('suggestions', [])
    
    # Map score to text
    score_map = {
        0: 'Too weak',
        1: 'Weak',
        2: 'Fair',
        3: 'Strong',
        4: 'Very strong'
    }
    
    score_text = score_map.get(score, 'Unknown')
    
    # Determine if password is acceptable
    # Score 0-1: Reject (too weak)
    # Score 2+: Accept (fair or better)
    is_acceptable = score >= 2
    
    feedback_dict = {
        'warning': warning,
        'suggestions': suggestions,
        'score_text': score_text,
        'crack_time': result.get('crack_times_display', {}).get('offline_slow_hashing_1e4_per_second', 'Unknown')
    }
    
    return is_acceptable, score, feedback_dict

def load_config():
    try:
        app.logger.info(f"Loading configuration from: {CONFIG_FILE}")
        
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                
                merged = merge_configs(copy.deepcopy(DEFAULT_CONFIG), config)
                
                # Generate secret key if not present
                if not merged['auth'].get('secret_key'):
                    app.logger.warning("Secret key missing, generating new one")
                    merged['auth']['secret_key'] = secrets.token_hex(32)
                    save_config(merged)
                
                # Set Flask secret key
                app.secret_key = merged['auth']['secret_key']
                
                app.logger.info(f"Configuration loaded successfully - User: {merged['auth'].get('username', 'unknown')}, Setup complete: {merged['auth'].get('setup_complete', False)}")
                
                return merged
        else:
            # First run - generate secret key but don't set credentials
            app.logger.info("Config file does not exist - first run, creating default config")
            config = copy.deepcopy(DEFAULT_CONFIG)
            config['auth']['secret_key'] = secrets.token_hex(32)
            app.secret_key = config['auth']['secret_key']
            save_config(config)
            return config
    except Exception as e:
        app.logger.error(f"Error loading config: {e}", exc_info=True)
        config = copy.deepcopy(DEFAULT_CONFIG)
        config['auth']['secret_key'] = secrets.token_hex(32)
        app.secret_key = config['auth']['secret_key']
        return config

def merge_configs(default, custom):
    for key, value in custom.items():
        if key in default and isinstance(default[key], dict) and isinstance(value, dict):
            default[key] = merge_configs(default[key], value)
        else:
            default[key] = value
    return default

def save_config(config):
    try:
        app.logger.info(f"Saving configuration to: {CONFIG_FILE}")
        
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Set secure permissions
        os.chmod(os.path.dirname(CONFIG_FILE), 0o700)  # /config directory
        os.chmod(CONFIG_FILE, 0o600)  # config.json
        
        app.logger.info("Configuration saved successfully")
        return True
    except Exception as e:
        app.logger.error(f"Error saving config: {e}", exc_info=True)
        return False

def is_setup_complete():
    """Check if initial setup has been completed"""
    config = load_config()
    setup_complete = config['auth'].get('setup_complete', False)
    has_password = bool(config['auth'].get('password_hash', ''))
    
    return setup_complete and has_password

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if setup is complete
        if not is_setup_complete():
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Setup required'}), 503
            return redirect(url_for('setup'))
        
        if 'logged_in' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def validate_config(config):
    errors = []
    for service in ['overseerr', 'sonarr', 'radarr']:
        url = config.get(service, {}).get('url', '')
        if not url.startswith('http://') and not url.startswith('https://'):
            errors.append(f"{service} URL must start with http:// or https://")
    for service in ['overseerr', 'sonarr', 'radarr']:
        api_key = config.get(service, {}).get('api_key', '')
        if not api_key or len(api_key) < 10:
            errors.append(f"{service} API key appears invalid")
    return errors

def make_request(method, url, **kwargs):
    try:
        timeout = kwargs.pop('timeout', 30)
        app.logger.debug(f"{method} {url}")
        response = requests.request(method, url, timeout=timeout, **kwargs)
        response.raise_for_status()
        return response
    except requests.exceptions.Timeout:
        app.logger.error(f"Request timeout: {url}")
        raise
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Request failed: {url} - {e}")
        raise

def ensure_worker_started():
    """Ensure the worker thread is started (call this on first request)"""
    global WORKER_THREAD, WORKER_STARTED
    
    if WORKER_STARTED:
        return
    
    config = load_config()
    if config['processing'].get('queue_enabled', True):
        app.logger.info("Starting webhook worker thread...")
        WORKER_THREAD = threading.Thread(target=webhook_worker, daemon=True, name="WebhookWorker")
        WORKER_THREAD.start()
        WORKER_STARTED = True
        app.logger.info(f"Webhook worker thread started: {WORKER_THREAD.is_alive()}")
    else:
        app.logger.info("Queue processing is disabled in config")

@app.before_request
def before_request():
    """
    Run before each request:
    1. Ensure worker thread is started
    2. Set SESSION_COOKIE_SECURE flag dynamically based on request protocol
    """
    # Ensure worker is started on first request
    ensure_worker_started()
    
    # Set Secure cookie flag dynamically based on request protocol
    # This allows both HTTP (local IP) and HTTPS (domain) access
    if request.headers.get('X-Forwarded-Proto') == 'https':
        app.config['SESSION_COOKIE_SECURE'] = True
    else:
        app.config['SESSION_COOKIE_SECURE'] = False

@app.route('/setup', methods=['GET', 'POST'])
@limiter.limit("10 per hour")  # Strict rate limit for setup attempts
def setup():
    # If setup is already complete, redirect to login
    if is_setup_complete():
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not password:
            return render_template('setup.html', error='Username and password are required')
        
        if len(username) < 3:
            return render_template('setup.html', error='Username must be at least 3 characters')
        
        if len(password) < 8:
            return render_template('setup.html', error='Password must be at least 8 characters')
        
        if password != confirm_password:
            return render_template('setup.html', error='Passwords do not match')
        
        # Check password strength using zxcvbn
        is_acceptable, score, feedback = check_password_strength(password, user_inputs=[username])
        
        if not is_acceptable:
            # Build error message with suggestions
            error_msg = f"Password is too weak ({feedback['score_text']})"
            if feedback['warning']:
                error_msg += f": {feedback['warning']}"
            if feedback['suggestions']:
                error_msg += ". " + ". ".join(feedback['suggestions'])
            return render_template('setup.html', error=error_msg)
        
        # Save credentials
        config = load_config()
        config['auth']['username'] = username
        config['auth']['password_hash'] = hash_password(password)
        config['auth']['setup_complete'] = True
        
        if save_config(config):
            app.logger.info(f"Initial setup completed - User account created: {username}")
            return redirect(url_for('login'))
        else:
            return render_template('setup.html', error='Failed to save configuration')
    
    return render_template('setup.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Strict rate limit to prevent brute force attacks
def login():
    # Check if setup is complete
    if not is_setup_complete():
        return redirect(url_for('setup'))
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        config = load_config()
        stored_username = config['auth']['username']
        
        # Verify password (returns is_valid, needs_upgrade)
        is_valid, needs_upgrade = verify_password(password, config['auth']['password_hash'])
        
        # Use constant-time comparison to prevent timing attacks
        # This prevents attackers from determining valid usernames by measuring response time
        username_valid = secrets.compare_digest(username, stored_username) if username and stored_username else False
        
        if username_valid and is_valid:
            # If using legacy SHA-256 hash, upgrade to bcrypt
            if needs_upgrade:
                app.logger.info(f"Migrating password hash from SHA-256 to bcrypt for user: {username}")
                config['auth']['password_hash'] = hash_password(password)
                save_config(config)
                app.logger.info("Password hash migration completed successfully")
            
            session['logged_in'] = True
            session['username'] = username
            session.permanent = True
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    # If already logged in, redirect to index
    if 'logged_in' in session:
        return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session.get('username', 'admin'))

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

@app.route('/api/config', methods=['GET', 'POST'])
@login_required
def handle_config():
    if request.method == 'GET':
        config = load_config()
        masked_config = mask_sensitive_data(config)
        return jsonify(masked_config)
    else:
        try:
            app.logger.info("Configuration update request received")
            
            incoming_config = request.json
            current_config = load_config()
            config = unmask_sensitive_data(incoming_config, current_config)
            
            # Validate
            errors = validate_config(config)
            if errors:
                app.logger.error(f"Config validation failed: {errors}")
                return jsonify({'status': 'error', 'errors': errors}), 400
            
            # Test connections
            test_results = test_connections(config)
            
            if not all(test_results.values()):
                if save_config(config):
                    return jsonify({
                        'status': 'warning',
                        'message': 'Configuration saved but some services are unreachable',
                        'test_results': test_results
                    }), 200
            
            if save_config(config):
                return jsonify({
                    'status': 'success',
                    'message': 'Configuration saved and all services are reachable',
                    'test_results': test_results
                })
            else:
                return jsonify({'status': 'error', 'message': 'Failed to save configuration'}), 500
        except Exception as e:
            app.logger.error(f"Error handling config: {e}", exc_info=True)
            return jsonify({'status': 'error', 'message': 'Failed to process configuration'}), 500

@app.route('/api/change-password', methods=['POST'])
@limiter.limit("3 per hour")  # Strict rate limit for password changes
@login_required
def change_password():
    try:
        data = request.json
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
        
        config = load_config()
        
        # Verify current password (returns is_valid, needs_upgrade)
        is_valid, needs_upgrade = verify_password(current_password, config['auth']['password_hash'])
        
        if not is_valid:
            return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 401
        
        # Check new password strength using zxcvbn
        username = config['auth']['username']
        is_acceptable, score, feedback = check_password_strength(new_password, user_inputs=[username])
        
        if not is_acceptable:
            # Build error message with suggestions
            error_msg = f"New password is too weak ({feedback['score_text']})"
            if feedback['warning']:
                error_msg += f": {feedback['warning']}"
            if feedback['suggestions']:
                error_msg += ". " + ". ".join(feedback['suggestions'])
            return jsonify({'status': 'error', 'message': error_msg}), 400
        
        # Hash new password with bcrypt
        config['auth']['password_hash'] = hash_password(new_password)
        
        if save_config(config):
            # If old password was SHA-256, log the migration
            if needs_upgrade:
                app.logger.info("Password changed and migrated from SHA-256 to bcrypt")
            else:
                app.logger.info("Password changed successfully")
            return jsonify({'status': 'success', 'message': 'Password changed successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to save new password'}), 500
            
    except Exception as e:
        app.logger.error(f"Error changing password: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Failed to change password'}), 500

@app.route('/api/check-password-strength', methods=['POST'])
@limiter.exempt  # Exempt from rate limiting - allows real-time typing without hitting limits
def check_password_strength_api():
    """
    API endpoint to check password strength in real-time.
    No authentication required (for setup page).
    Exempt from rate limiting to allow multiple checks during password entry.
    """
    try:
        data = request.json
        password = data.get('password', '')
        username = data.get('username', '')
        
        if not password:
            return jsonify({
                'score': 0,
                'score_text': 'Too weak',
                'is_acceptable': False,
                'warning': '',
                'suggestions': []
            })
        
        # Check password strength
        is_acceptable, score, feedback = check_password_strength(password, user_inputs=[username] if username else None)
        
        return jsonify({
            'score': score,
            'score_text': feedback['score_text'],
            'is_acceptable': is_acceptable,
            'warning': feedback['warning'],
            'suggestions': feedback['suggestions'],
            'crack_time': feedback.get('crack_time', 'Unknown')
        })
    except Exception as e:
        app.logger.error(f"Error checking password strength: {e}", exc_info=True)
        return jsonify({
            'score': 0,
            'score_text': 'Error',
            'is_acceptable': False,
            'warning': 'Error checking password strength',
            'suggestions': []
        }), 500

def mask_sensitive_data(config):
    masked = copy.deepcopy(config)
    
    # Don't send password hash to client, but preserve setup_complete
    if 'auth' in masked:
        masked['auth'] = {
            'username': masked['auth'].get('username', ''),
            'setup_complete': masked['auth'].get('setup_complete', False)
        }
    
    for service in ['overseerr', 'sonarr', 'radarr']:
        if service in masked and 'api_key' in masked[service]:
            key = masked[service]['api_key']
            if key:
                masked[service]['api_key'] = '********' + key[-4:] if len(key) > 4 else '********'
    if 'webhook' in masked and 'auth_header' in masked['webhook']:
        auth = masked['webhook']['auth_header']
        if auth:
            masked['webhook']['auth_header'] = '********' + auth[-4:] if len(auth) > 4 else '********'
    return masked

def unmask_sensitive_data(new_config, current_config):
    unmasked = copy.deepcopy(new_config)
    
    # If auth section is missing entirely from new_config, restore it from current
    if 'auth' not in unmasked or not unmasked['auth']:
        app.logger.info("Auth section missing from client request - restoring from stored config")
        unmasked['auth'] = copy.deepcopy(current_config.get('auth', {}))
    else:
        # Restore auth fields from current config (never sent to client or shouldn't be changed via this API)
        if 'auth' in current_config:
            # ALWAYS preserve these from current config - NEVER trust client
            unmasked['auth']['username'] = current_config['auth'].get('username', '')
            unmasked['auth']['password_hash'] = current_config['auth'].get('password_hash', '')
            unmasked['auth']['secret_key'] = current_config['auth'].get('secret_key', secrets.token_hex(32))
            unmasked['auth']['setup_complete'] = current_config['auth'].get('setup_complete', False)
    
    app.logger.info(f"Configuration unmasked - preserving authentication settings")
    
    for service in ['overseerr', 'sonarr', 'radarr']:
        if service in unmasked and 'api_key' in unmasked[service]:
            if unmasked[service]['api_key'].startswith('********'):
                unmasked[service]['api_key'] = current_config.get(service, {}).get('api_key', '')
    if 'webhook' in unmasked and 'auth_header' in unmasked['webhook']:
        if unmasked['webhook']['auth_header'].startswith('********'):
            unmasked['webhook']['auth_header'] = current_config.get('webhook', {}).get('auth_header', '')
    return unmasked

def test_connections(config):
    results = {}
    try:
        response = make_request(
            'GET',
            f"{config['overseerr']['url']}/api/v1/settings/main",
            headers={'X-Api-Key': config['overseerr']['api_key']},
            timeout=config['overseerr'].get('timeout', 30)
        )
        results['overseerr'] = True
    except:
        results['overseerr'] = False
    
    try:
        response = make_request(
            'GET',
            f"{config['sonarr']['url']}/api/v3/system/status",
            params={'apikey': config['sonarr']['api_key']},
            timeout=config['sonarr'].get('timeout', 30)
        )
        results['sonarr'] = True
    except:
        results['sonarr'] = False
    
    try:
        response = make_request(
            'GET',
            f"{config['radarr']['url']}/api/v3/system/status",
            params={'apikey': config['radarr']['api_key']},
            timeout=config['radarr'].get('timeout', 30)
        )
        results['radarr'] = True
    except:
        results['radarr'] = False
    
    return results

@app.route('/api/test', methods=['POST'])
@login_required
def test_connections_endpoint():
    config = load_config()
    results = test_connections(config)
    return jsonify(results)

@app.route('/api/webhook', methods=['POST'])
def handle_webhook():
    """Webhook endpoint - no authentication required"""
    config = load_config()
    
    auth_header = config['webhook'].get('auth_header', '')
    if auth_header:
        request_auth = request.headers.get('Authorization', '')
        # Use constant-time comparison to prevent timing attacks on webhook auth token
        if not secrets.compare_digest(request_auth, auth_header):
            app.logger.warning(f"Webhook authentication failed")
            return jsonify({'error': 'Unauthorized'}), 401
    
    if not config['webhook'].get('enabled', True):
        app.logger.warning("Webhook received but webhooks are disabled")
        return jsonify({'error': 'Webhooks are disabled'}), 403
    
    try:
        data = request.json
        
        # Validate payload has required fields
        if not data:
            app.logger.warning("Webhook received with empty payload")
            return jsonify({'error': 'Invalid payload'}), 400
        
        required_fields = ['notification_type', 'subject']
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            app.logger.warning(f"Webhook missing required fields: {missing_fields}")
            return jsonify({'error': 'Invalid payload - missing required fields'}), 400
        
        # For ISSUE_CREATED, validate additional required fields
        if data.get('notification_type') == 'ISSUE_CREATED':
            if 'issue' not in data or not isinstance(data['issue'], dict):
                app.logger.warning("Webhook ISSUE_CREATED missing 'issue' object")
                return jsonify({'error': 'Invalid payload - missing issue data'}), 400
            
            if 'media' not in data or not isinstance(data['media'], dict):
                app.logger.warning("Webhook ISSUE_CREATED missing 'media' object")
                return jsonify({'error': 'Invalid payload - missing media data'}), 400
        
        app.logger.info(f"Webhook received: {data.get('subject', 'unknown')}")
        
        if config['processing'].get('queue_enabled', True):
            WEBHOOK_QUEUE.put({
                'data': data,
                'timestamp': datetime.now().isoformat()
            })
            app.logger.info(f"Webhook queued. Queue size: {WEBHOOK_QUEUE.qsize()}")
            return jsonify({'status': 'queued', 'queue_size': WEBHOOK_QUEUE.qsize()})
        else:
            result = process_webhook(data, config)
            return jsonify(result)
            
    except Exception as e:
        app.logger.error(f"Error handling webhook: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

def process_webhook(data, config):
    """Process a webhook payload"""
    notification_type = data.get('notification_type', '')
    subject = data.get('subject', '')
    
    app.logger.info(f"Processing webhook - Type: {notification_type}, Subject: {subject}")
    
    if notification_type != 'ISSUE_CREATED':
        app.logger.info(f"Ignoring notification type: {notification_type}")
        return {'status': 'ignored', 'reason': 'Not an ISSUE_CREATED notification'}
    
    issue = data.get('issue', {})
    issue_id = issue.get('issue_id')
    issue_type = issue.get('issue_type')
    media = data.get('media', {})
    media_type = media.get('media_type')
    
    app.logger.info(f"Issue ID: {issue_id}, Issue Type: {issue_type}, Media Type: {media_type}")
    
    # Handle both numeric (1) and string ("VIDEO") issue types
    #if issue_type not in [1, 'VIDEO', 'video']:
    #    app.logger.info(f"Ignoring non-video issue (type {issue_type})")
    #    return {'status': 'ignored', 'reason': 'Not a video issue'}
    
    try:
        if media_type == 'tv':
            return process_tv_issue(issue_id, media, data.get('extra', []), config)
        elif media_type == 'movie':
            return process_movie_issue(issue_id, media, config)
        else:
            app.logger.warning(f"Unknown media type: {media_type}")
            return {'status': 'error', 'message': f'Unknown media type: {media_type}'}
    except Exception as e:
        app.logger.error(f"Error processing {media_type} issue: {e}", exc_info=True)
        return {'status': 'error', 'message': 'Failed to process issue'}

def process_movie_issue(issue_id, media, config):
    """Process a movie issue"""
    app.logger.info(f"=== Processing Movie Issue {issue_id} ===")
    
    try:
        radarr_url = config['radarr']['url']
        radarr_key = config['radarr']['api_key']
        timeout = config['radarr'].get('timeout', 30)
        
        tmdb_id = media.get('tmdbId')
        if not tmdb_id:
            raise ValueError("No TMDB ID found in media data")
        
        app.logger.info(f"Step 1: Looking up movie with TMDB ID {tmdb_id}")
        response = make_request(
            'GET',
            f"{radarr_url}/api/v3/movie/lookup",
            params={'term': f'tmdb:{tmdb_id}', 'apikey': radarr_key},
            timeout=timeout
        )
        movie_data = response.json()
        
        if not movie_data:
            raise ValueError(f"Movie not found with TMDB ID {tmdb_id}")
        
        app.logger.info(movie_data)
        movie_id = movie_data[0]['id']
        app.logger.info(f"Found movie ID: {movie_id}")
        
        time.sleep(0.5)
        
        app.logger.info(f"Step 2: Getting movie details for ID {movie_id}")
        response = make_request(
            'GET',
            f"{radarr_url}/api/v3/movie/{movie_id}",
            params={'apikey': radarr_key},
            timeout=timeout
        )
        movie = response.json()
        
        if not movie.get('hasFile'):
            app.logger.warning("Movie has no file")
            return {'status': 'error', 'message': 'Movie has no file'}
        
        movie_file_id = movie['movieFile']['id']
        app.logger.info(f"Movie file ID: {movie_file_id}")
        
        time.sleep(0.5)
        
        app.logger.info(f"Step 3: Getting history for movieId={movie_id}, eventType=grabbed")
        response = make_request(
            'GET',
            f"{radarr_url}/api/v3/history/movie",
            params={'movieId': movie_id, 'apikey': radarr_key, 'eventType': 'grabbed'},
            timeout=timeout
        )
        history = response.json()
        
        time.sleep(0.2)
        
        app.logger.info(f"Step 4: Deleting movie file {movie_file_id}")
        make_request(
            'DELETE',
            f"{radarr_url}/api/v3/moviefile/{movie_file_id}",
            params={'apikey': radarr_key},
            timeout=timeout
        )
        app.logger.info(f"Deleted movie file {movie_file_id}")
        
        time.sleep(0.2)
        
        if history and len(history) > 0:
            history_id = history[0]['id']
            app.logger.info(f"Step 5: Marking history {history_id} as failed")
            make_request(
                'POST',
                f"{radarr_url}/api/v3/history/failed/{history_id}",
                params={'apikey': radarr_key},
                timeout=timeout
            )
            app.logger.info(f"Marked movie history {history_id} as failed")
        else:
            app.logger.warning(f"No history found for movie {movie_id}")
        
        app.logger.info(f"Step 6: Adding comment to issue {issue_id}")
        comment_issue(issue_id, config)
        
        time.sleep(1)
        
        app.logger.info(f"Step 7: Closing issue {issue_id}")
        close_issue(issue_id, config)
        
        app.logger.info(f"Movie issue {issue_id} processed successfully")
        return {'status': 'success', 'message': 'Movie issue processed'}
        
    except Exception as e:
        app.logger.error(f"Error processing movie issue: {e}", exc_info=True)
        raise

def process_tv_issue(issue_id, media, extra, config):
    """Process a TV show issue"""
    app.logger.info(f"=== Processing TV Issue {issue_id} ===")
    
    try:
        sonarr_url = config['sonarr']['url']
        sonarr_key = config['sonarr']['api_key']
        timeout = config['sonarr'].get('timeout', 30)
        
        tvdb_id = media.get('tvdbId')
        if not tvdb_id:
            raise ValueError("No TVDB ID found in media data")
        
        app.logger.info(f"Step 1: Looking up series with TVDB ID {tvdb_id}")
        response = make_request(
            'GET',
            f"{sonarr_url}/api/v3/series/lookup",
            params={'term': f'tvdb:{tvdb_id}', 'apikey': sonarr_key},
            timeout=timeout
        )
        series_list = response.json()
        
        if not series_list:
            raise ValueError(f"Series not found with TVDB ID {tvdb_id}")
        
        series = series_list[0]
        series_id = series['id']
        app.logger.info(f"Found series ID: {series_id}")
        
        time.sleep(0.5)
        
        season_num = None
        episode_num = None
        
        for item in extra:
            name = item.get('name', '')
            if 'Season' in name:
                season_num = item.get('value')
            elif 'Episode' in name:
                episode_num = item.get('value')
        
        app.logger.info(f"Season: {season_num}, Episode: {episode_num}")
        
        params = {
            'seriesId': series_id,
            'apikey': sonarr_key
        }
        if season_num:
            params['seasonNumber'] = season_num
        
        app.logger.info(f"Step 2: Getting episodes with params: {params}")
        response = make_request(
            'GET',
            f"{sonarr_url}/api/v3/episode",
            params=params,
            timeout=timeout
        )
        episodes = response.json()
        app.logger.info(f"Retrieved {len(episodes)} episodes")
        
        if episode_num:
            episodes = [e for e in episodes if str(e['episodeNumber']) == str(episode_num)]
            app.logger.info(f"Filtered to {len(episodes)} episodes matching episode number {episode_num}")
        
        episodes = [e for e in episodes if e.get('episodeFileId', 0) != 0]
        app.logger.info(f"Processing {len(episodes)} episode(s) with files")
        
        if not episodes:
            app.logger.warning("No episodes with files found")
            return {'status': 'error', 'message': 'No episodes with files found'}
        
        for idx, episode in enumerate(episodes):
            app.logger.info(f"Processing episode {idx+1}/{len(episodes)}: ID {episode['id']}")
            time.sleep(0.1)
            
            episode_file_id = episode['episodeFileId']
            episode_id = episode['id']
            
            app.logger.info(f"Step 3: Getting history for episodeId={episode_id}, eventType=1")
            response = make_request(
                'GET',
                f"{sonarr_url}/api/v3/history",
                params={'episodeId': episode_id, 'apikey': sonarr_key, 'eventType': '1'},
                timeout=timeout
            )
            history = response.json()
            app.logger.info(f"History response has {len(history.get('records', []))} records")
            
            time.sleep(0.1)
            
            app.logger.info(f"Step 4: Deleting episode file {episode_file_id}")
            make_request(
                'DELETE',
                f"{sonarr_url}/api/v3/episodefile/{episode_file_id}",
                params={'apikey': sonarr_key},
                timeout=timeout
            )
            app.logger.info(f"Deleted episode file {episode_file_id}")
            
            time.sleep(0.2)
            
            if history.get('records') and len(history['records']) > 0:
                history_id = history['records'][0]['id']
                app.logger.info(f"Step 5: Marking history {history_id} as failed")
                make_request(
                    'POST',
                    f"{sonarr_url}/api/v3/history/failed/{history_id}",
                    params={'apikey': sonarr_key},
                    timeout=timeout
                )
                app.logger.info(f"Marked episode history {history_id} as failed")
            else:
                app.logger.warning(f"No history found for episode {episode_id}")
        
        app.logger.info(f"Step 6: Adding comment to issue {issue_id}")
        comment_issue(issue_id, config)
        
        time.sleep(1)
        
        app.logger.info(f"Step 7: Closing issue {issue_id}")
        close_issue(issue_id, config)
        
        app.logger.info(f"TV issue {issue_id} processed successfully")
        return {'status': 'success', 'message': 'TV issue processed'}
        
    except Exception as e:
        app.logger.error(f"Error processing TV issue: {e}", exc_info=True)
        raise

def comment_issue(issue_id, config):
    overseerr_url = config['overseerr']['url']
    overseerr_key = config['overseerr']['api_key']
    timeout = config['overseerr'].get('timeout', 30)
    
    make_request(
        'POST',
        f"{overseerr_url}/api/v1/issue/{issue_id}/comment",
        headers={'X-Api-Key': overseerr_key},
        json={'message': 'File/s has been automatically deleted, and a new search/download triggered.'},
        timeout=timeout
    )
    app.logger.info(f"Added comment to issue {issue_id}")

def close_issue(issue_id, config):
    overseerr_url = config['overseerr']['url']
    overseerr_key = config['overseerr']['api_key']
    timeout = config['overseerr'].get('timeout', 30)
    
    make_request(
        'POST',
        f"{overseerr_url}/api/v1/issue/{issue_id}/resolved",
        headers={'X-Api-Key': overseerr_key},
        timeout=timeout
    )
    app.logger.info(f"Closed issue {issue_id}")

@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs():
    try:
        lines = int(request.args.get('lines', 100))
        log_file = os.path.join(LOG_DIR, 'app.log')
        
        if not os.path.exists(log_file):
            return jsonify({'logs': []})
        
        with open(log_file, 'r') as f:
            all_lines = f.readlines()
            recent_lines = all_lines[-lines:]
            
        return jsonify({'logs': recent_lines})
    except Exception as e:
        app.logger.error(f"Error retrieving logs: {e}", exc_info=True)
        return jsonify({'error': 'Failed to retrieve logs'}), 500

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    try:
        stats = {
            'queue_size': WEBHOOK_QUEUE.qsize(),
            'uptime': time.time() - app.config.get('start_time', time.time()),
            'config_valid': os.path.exists(CONFIG_FILE),
            'log_size': os.path.getsize(os.path.join(LOG_DIR, 'app.log')) if os.path.exists(os.path.join(LOG_DIR, 'app.log')) else 0,
            'worker_alive': WORKER_THREAD.is_alive() if WORKER_THREAD else False
        }
        return jsonify(stats)
    except Exception as e:
        app.logger.error(f"Error retrieving stats: {e}", exc_info=True)
        return jsonify({'error': 'Failed to retrieve statistics'}), 500

@app.route('/api/health', methods=['GET'])
@limiter.exempt  # Exempt from rate limiting - required for Docker health checks and monitoring
def health_check():
    """Health check endpoint - no authentication required"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'worker_alive': WORKER_THREAD.is_alive() if WORKER_THREAD else False
    })

def webhook_worker():
    """Background worker that processes queued webhooks"""
    app.logger.info("=== WEBHOOK WORKER THREAD STARTED ===")
    app.logger.info(f"Worker thread ID: {threading.get_ident()}")
    
    while True:
        item = None
        try:
            #app.logger.info("Worker: Waiting for items in queue...")
            item = WEBHOOK_QUEUE.get(timeout=1)
            
            app.logger.info(f"Worker: Got item from queue! Processing webhook from {item['timestamp']}")
            
            config = load_config()
            
            result = process_webhook(item['data'], config)
            app.logger.info(f"Worker: Successfully processed webhook: {result}")
            
        except Exception as e:
            if "Empty" not in str(type(e).__name__):
                app.logger.error(f"Worker: Error processing webhook: {e}", exc_info=True)
        finally:
            if item is not None:
                WEBHOOK_QUEUE.task_done()
                app.logger.info("Worker: Marked task as done")

if __name__ == '__main__':
    config = load_config()
    if config['processing'].get('queue_enabled', True):
        app.logger.info("Starting webhook worker at startup...")
        WORKER_THREAD = threading.Thread(target=webhook_worker, daemon=True, name="WebhookWorker")
        WORKER_THREAD.start()
        WORKER_STARTED = True
        app.logger.info(f"Worker started: {WORKER_THREAD.is_alive()}")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
