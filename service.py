#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PACON Service - v1.2.4
=======================
v1.2.4 changes:
  - Canonical device ID merging: devices with same (hostname, public_ip)
    are unified under the most recently-active device ID.
  - Pending-registration rejection: devices that register but never poll
    are hidden from /api/devices.
  - Better diagnostics showing raw vs canonical IDs.
  - /api/devices trusts last_poll over last_seen when they disagree.
"""

import os
import sys
import json
import time
import uuid
import hmac
import signal
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
from typing import Dict, List, Optional, Tuple
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

BASE_DIR       = Path.home() / '.pacon'
SCREENSHOT_DIR = BASE_DIR / 'screenshots'
LOGS_DIR       = BASE_DIR / 'logs'
DATA_DIR       = BASE_DIR / 'data'
CAMERA_DIR     = BASE_DIR / 'camera'
FILES_DIR      = BASE_DIR / 'files'
UPLOAD_DIR     = BASE_DIR / 'uploads'
DEVICE_DIR     = BASE_DIR / 'devices'

for d in [BASE_DIR, SCREENSHOT_DIR, LOGS_DIR, DATA_DIR,
          CAMERA_DIR, FILES_DIR, UPLOAD_DIR, DEVICE_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ============================================================
# WEB DIRECTORY
# ============================================================
IS_RENDER = os.environ.get('RENDER', 'false').lower() == 'true'
if IS_RENDER:
    WEB_DIR = Path('/opt/render/project/src/web/public')
else:
    SCRIPT_DIR  = Path(__file__).parent
    PROJECT_DIR = SCRIPT_DIR.parent
    WEB_DIR     = PROJECT_DIR / 'web' / 'public'
WEB_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# LOGGER
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================
# AUTH
# ============================================================
PARENT_PIN = os.environ.get('PARENT_PIN', '').strip()
AGENT_PIN  = os.environ.get('AGENT_PIN',  '').strip()

if not PARENT_PIN:
    logger.warning("⚠️ PARENT_PIN not set — dashboard UNPROTECTED")
elif not PARENT_PIN.isdigit() or len(PARENT_PIN) != 6:
    logger.error("❌ PARENT_PIN must be exactly 6 digits"); PARENT_PIN = ""

if not AGENT_PIN:
    logger.warning("⚠️ AGENT_PIN not set — agents UNPROTECTED")
elif not AGENT_PIN.isdigit() or len(AGENT_PIN) != 6:
    logger.error("❌ AGENT_PIN must be exactly 6 digits"); AGENT_PIN = ""

sessions = {}
SESSION_TTL    = 24 * 3600
SESSION_COOKIE = "pacon_session"
login_attempts = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW       = 300

# ============================================================
# FLASK APP
# ============================================================
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
ALLOWED_ORIGINS = [
    'https://service-ur14.onrender.com',
    'http://localhost:5001',
    'http://127.0.0.1:5001',
]
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

# ============================================================
# DATA STORE
# ============================================================
devices             = {}         # device_id -> device dict
screenshots         = []
camera_photos       = []
locations           = []
app_usage           = []
installed_apps      = {}         # device_id -> [app dicts]
browser_history     = []
activities          = []
activity_counter    = 0
device_screens      = {}         # device_id -> {width, height, density}

command_queues      = defaultdict(deque)
command_results     = {}
control_devices     = {}         # device_id -> last_poll_ts
device_online_state = {}         # device_id -> bool
device_agent_pid    = {}         # device_id -> {pid, version, first_seen}

# v1.2.4: Fingerprint-based canonical ID mapping.
# (hostname, public_ip) -> canonical device_id
# This handles the case where two different agents on the same physical
# machine register with two different IDs.
device_fingerprint  = {}         # fingerprint -> canonical_device_id
fingerprint_lock    = threading.Lock()

ping_thread  = None
ping_running = False
ping_interval = 240

# Thresholds
OFFLINE_THRESHOLD = 15       # seconds without poll = offline
OFFLINE_GRACE     = 30
STALE_CUTOFF      = 300
ORPHAN_CUTOFF     = 600
RESULT_TTL        = 300
PENDING_TTL       = 90       # v1.2.4: how long a "registered but never
                             # polled" device is kept in `devices`

_stop_event = threading.Event()

# ============================================================
# UTILITY
# ============================================================
def add_activity(action: str, details: str, device_id: str = "unknown"):
    global activity_counter
    activity_counter += 1
    activities.append({
        'id':        activity_counter,
        'timestamp': datetime.now().isoformat(),
        'action':    action,
        'details':   details,
        'device_id': device_id,
        'type':      'info',
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

def _is_device_online(device_id: str, now: Optional[float] = None) -> bool:
    if now is None:
        now = time.time()
    return (now - control_devices.get(device_id, 0)) < OFFLINE_THRESHOLD

def _device_age(device_id: str, now: Optional[float] = None) -> Optional[float]:
    if now is None:
        now = time.time()
    last_poll = control_devices.get(device_id, 0)
    if not last_poll:
        return None
    return now - last_poll

# ============================================================
# v1.2.4 — CANONICAL ID RESOLUTION
# ============================================================
def _fingerprint_for(hostname: str, public_ip: str) -> Optional[str]:
    """Return a stable fingerprint for a physical machine."""
    if not hostname and not public_ip:
        return None
    return f"{(hostname or '').strip().lower()}|{(public_ip or '').strip()}"

def _resolve_canonical_id(incoming_id: str,
                          hostname: str = "",
                          public_ip: str = "") -> str:
    """
    Return the canonical device ID to use for a given incoming ID.
    If another device is already active with the same fingerprint,
    return that one; otherwise return the incoming one and register it.
    """
    fp = _fingerprint_for(hostname, public_ip)
    if not fp:
        return incoming_id

    with fingerprint_lock:
        existing = device_fingerprint.get(fp)
        if existing and existing != incoming_id:
            # Is the existing one still alive?
            now = time.time()
            last_poll = control_devices.get(existing, 0)
            existing_age = now - last_poll if last_poll else None
            if existing_age is not None and existing_age < OFFLINE_THRESHOLD * 4:
                logger.warning(
                    f"🔀 Device fingerprint collision: incoming "
                    f"{incoming_id[:8]} → reusing canonical {existing[:8]} "
                    f"(host={hostname}, ip={public_ip})"
                )
                return existing
            else:
                # Existing is stale — let the new one take over
                logger.info(
                    f"🔀 Canonical takeover: {existing[:8]} stale → "
                    f"adopting {incoming_id[:8]}"
                )
                device_fingerprint[fp] = incoming_id
                return incoming_id
        else:
            device_fingerprint[fp] = incoming_id
            return incoming_id

def _get_public_ip_from_request() -> str:
    """Extract the client's public IP from the request."""
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        # First IP in the list is the original client
        return xff.split(',')[0].strip()
    return request.remote_addr or ''

# ============================================================
# AUTH CORE
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

def _clear_login_attempts(ip: str):
    login_attempts.pop(ip, None)

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
    'default':    (240, 60),
    'control':    (600, 60),
    'screenshot': (300, 60),
    'login':      (10, 300),
    'telegram':   (30, 60),
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
                return jsonify({
                    'success': False,
                    'error': 'rate limit exceeded',
                    'retry_after': window,
                }), 429
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
    while ping_running and not _stop_event.is_set():
        try:
            req = urllib.request.Request(url, method='GET')
            req.add_header('User-Agent', 'PACON-SelfPing/1.2.4')
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status == 200:
                    logger.debug("✅ Self-ping OK")
        except Exception as e:
            logger.warning(f"⚠️ Self-ping failed: {e}")
        _stop_event.wait(ping_interval)

def start_ping_system():
    global ping_thread, ping_running
    if ping_running:
        return
    ping_running = True
    ping_thread = threading.Thread(target=ping_server, daemon=True, name="self-ping")
    ping_thread.start()
    logger.info(f"🔄 Self-ping started ({get_server_url()})")

# ============================================================
# TELEGRAM
# ============================================================
TELEGRAM_CONFIG_FILE = DATA_DIR / "telegram.json"

telegram_config = {
    "bot_token":      "",
    "chat_id":        "",
    "enabled":        False,
    "notify_online":  True,
    "notify_offline": True,
}

def _load_telegram_config():
    global telegram_config
    try:
        if TELEGRAM_CONFIG_FILE.exists():
            with open(TELEGRAM_CONFIG_FILE, "r", encoding="utf-8") as f:
                telegram_config.update(json.load(f))
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
    if not telegram_config.get("enabled"):
        return {"success": False, "error": "Telegram is disabled"}
    if not telegram_config.get("bot_token"):
        return {"success": False, "error": "Bot token is empty"}
    if not telegram_config.get("chat_id"):
        return {"success": False, "error": "Chat ID is empty"}
    try:
        import urllib.parse
        url = _telegram_api_url("sendMessage")
        payload = urllib.parse.urlencode({
            "chat_id":                  telegram_config["chat_id"],
            "text":                     text[:4096],
            "parse_mode":               parse_mode,
            "disable_web_page_preview": "true",
        }).encode("utf-8")
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=30) as r:
            body = json.loads(r.read().decode("utf-8"))
            if body.get("ok"):
                return {"success": True, "result": body}
            return {"success": False, "error": body.get("description", "unknown")}
    except urllib.error.HTTPError as he:
        try:
            err_body = he.read().decode("utf-8")
            try:
                err_desc = json.loads(err_body).get("description", err_body[:200])
            except Exception:
                err_desc = err_body[:200]
            return {"success": False, "error": f"HTTP {he.code}: {err_desc}"}
        except Exception:
            return {"success": False, "error": f"HTTP {he.code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def _telegram_upload(endpoint: str, field: str, filepath: Path, caption: str = "") -> dict:
    if not telegram_config.get("enabled"):
        return {"success": False, "error": "Telegram is disabled"}
    if not telegram_config.get("bot_token"):
        return {"success": False, "error": "Bot token is empty"}
    if not telegram_config.get("chat_id"):
        return {"success": False, "error": "Chat ID is empty"}
    if not filepath.exists():
        return {"success": False, "error": f"File not found: {filepath.name}"}
    file_size = filepath.stat().st_size
    if file_size == 0:
        return {"success": False, "error": "File is empty"}
    if field == "photo" and file_size > 10 * 1024 * 1024:
        return _telegram_upload("sendDocument", "document", filepath, caption)
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
            if resp.get("ok"):
                return {"success": True, "result": resp}
            return {"success": False, "error": resp.get("description", "unknown")}
    except urllib.error.HTTPError as he:
        try:
            err_body = he.read().decode("utf-8")
            try:
                err_desc = json.loads(err_body).get("description", err_body[:200])
            except Exception:
                err_desc = err_body[:200]
            return {"success": False, "error": f"HTTP {he.code}: {err_desc}"}
        except Exception:
            return {"success": False, "error": f"HTTP {he.code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def _telegram_send_photo(filepath: Path, caption: str = "") -> dict:
    return _telegram_upload("sendPhoto", "photo", filepath, caption)

def _telegram_send_document(filepath: Path, caption: str = "") -> dict:
    return _telegram_upload("sendDocument", "document", filepath, caption)

# ============================================================
# ONLINE / OFFLINE STATE
# ============================================================
def _notify_state_change(device_id: str, is_online: bool):
    info  = devices.get(device_id, {})
    name  = info.get('name', 'Unknown')
    model = info.get('model', 'Unknown')
    if is_online and telegram_config.get("notify_online", True):
        _telegram_send_message(
            f"🟢 <b>Device Online</b>\n"
            f"👤 {name}\n💻 {model}\n"
            f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        logger.info(f"📲 Sent ONLINE notification for {device_id[:8]}")
    elif (not is_online) and telegram_config.get("notify_offline", True):
        _telegram_send_message(
            f"🔴 <b>Device Offline</b>\n"
            f"👤 {name}\n💻 {model}\n"
            f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        logger.info(f"📲 Sent OFFLINE notification for {device_id[:8]}")

def _mark_device_online(device_id: str):
    was_online = device_online_state.get(device_id)
    device_online_state[device_id] = True
    if was_online is False:
        _notify_state_change(device_id, True)

def _purge_device_data(device_id: str):
    try:
        removed_apps = len(installed_apps.pop(device_id, []))
        device_screens.pop(device_id, None)
        command_queues.pop(device_id, None)

        global screenshots
        before = len(screenshots)
        screenshots = [s for s in screenshots if s.get('device_id') != device_id]
        removed_shots = before - len(screenshots)

        if device_id in devices:
            devices[device_id]['status']    = 'offline'
            devices[device_id]['last_seen'] = datetime.now().isoformat()

        stale_cids = [cid for cid, r in command_results.items()
                      if r.get('deviceId') == device_id]
        for cid in stale_cids:
            command_results.pop(cid, None)

        logger.info(f"🧹 Purged {device_id[:8]}: "
                    f"{removed_apps} apps, {removed_shots} shots, "
                    f"{len(stale_cids)} results")
        add_activity('purge', f'Purged cached data for {device_id[:8]}', device_id)
    except Exception as e:
        logger.warning(f"Purge error for {device_id[:8]}: {e}")

def _cleanup_pending_registrations():
    """
    v1.2.4: Remove devices that have registered but never polled
    within PENDING_TTL seconds. Prevents ghost device registrations.
    """
    now = time.time()
    removed = []
    for did, info in list(devices.items()):
        if did in control_devices:
            continue   # it has polled at least once
        last_seen = info.get('last_seen', '')
        if not last_seen:
            continue
        try:
            seen_age = now - datetime.fromisoformat(last_seen).timestamp()
        except Exception:
            continue
        if seen_age > PENDING_TTL:
            devices.pop(did, None)
            device_agent_pid.pop(did, None)
            device_online_state.pop(did, None)
            removed.append(did)
    if removed:
        logger.info(f"🧹 Removed {len(removed)} pending (never-polled) "
                    f"device(s): {[d[:8] for d in removed]}")

def _cleanup_orphans():
    now = time.time()
    removed = []
    all_ids = set(devices.keys()) | set(control_devices.keys())
    for did in all_ids:
        info = devices.get(did, {})
        last_poll = control_devices.get(did, 0)
        poll_age = (now - last_poll) if last_poll else None
        reg_age = None
        ls = info.get('last_seen', '')
        if ls:
            try:
                reg_age = now - datetime.fromisoformat(ls).timestamp()
            except Exception:
                reg_age = None
        ages = [a for a in (poll_age, reg_age) if a is not None]
        age = min(ages) if ages else None

        if age is not None and age > ORPHAN_CUTOFF:
            devices.pop(did, None)
            installed_apps.pop(did, None)
            device_screens.pop(did, None)
            control_devices.pop(did, None)
            device_online_state.pop(did, None)
            command_queues.pop(did, None)
            device_agent_pid.pop(did, None)
            screenshots[:] = [s for s in screenshots if s.get('device_id') != did]
            removed.append(did)
            # Also clean any fingerprints pointing at this ID
            with fingerprint_lock:
                for fp, cid in list(device_fingerprint.items()):
                    if cid == did:
                        device_fingerprint.pop(fp, None)
    if removed:
        logger.info(f"🧹 Orphan cleanup: removed {len(removed)} stale device(s): "
                    f"{[d[:8] for d in removed]}")

def _cleanup_command_results():
    now = time.time()
    stale = [cid for cid, r in command_results.items()
             if now - r.get('timestamp', 0) > RESULT_TTL]
    for cid in stale:
        command_results.pop(cid, None)
    if stale:
        logger.debug(f"🧹 Cleaned {len(stale)} expired command results")

def _device_watchdog():
    last_cleanup = time.time()
    while not _stop_event.is_set():
        try:
            _stop_event.wait(10)
            if _stop_event.is_set():
                break
            now = time.time()
            for device_id in list(device_online_state.keys()):
                last_poll  = control_devices.get(device_id, 0)
                is_online  = (now - last_poll) < OFFLINE_THRESHOLD
                was_online = device_online_state.get(device_id)

                if was_online and not is_online:
                    device_online_state[device_id] = False
                    _notify_state_change(device_id, False)

                    def _delayed_purge(did, delay=OFFLINE_GRACE):
                        _stop_event.wait(delay)
                        if _stop_event.is_set():
                            return
                        last = control_devices.get(did, 0)
                        if (time.time() - last) >= OFFLINE_THRESHOLD:
                            _purge_device_data(did)
                    threading.Thread(target=_delayed_purge,
                                     args=(device_id,), daemon=True).start()

            if now - last_cleanup > 30:
                _cleanup_orphans()
                _cleanup_command_results()
                _cleanup_pending_registrations()
                last_cleanup = now
        except Exception as e:
            logger.debug(f"Watchdog error: {e}")

_watchdog_thread = None
def start_watchdog():
    global _watchdog_thread
    if _watchdog_thread is None or not _watchdog_thread.is_alive():
        _watchdog_thread = threading.Thread(
            target=_device_watchdog, daemon=True, name="watchdog"
        )
        _watchdog_thread.start()
        logger.info("👁️ Device watchdog started")

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
            'error': 'too many attempts',
            'retry_after': LOGIN_WINDOW,
        }), 429
    data = request.json or {}
    pin  = str(data.get('pin', '')).strip()
    if not pin.isdigit() or len(pin) != 6:
        _record_login_attempt(ip)
        return jsonify({'success': False, 'error': 'PIN must be 6 digits'}), 400
    if not _safe_eq(pin, PARENT_PIN):
        _record_login_attempt(ip)
        logger.warning(f"🚫 Wrong PIN from {ip}")
        return jsonify({'success': False, 'error': 'incorrect PIN'}), 401
    _clear_login_attempts(ip)
    token = _create_session()
    logger.info(f"✅ Login success from {ip}")
    add_activity('login', f'Parent login from {ip}')
    resp = make_response(jsonify({'success': True}))
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite='Lax',
                    secure=IS_RENDER, max_age=SESSION_TTL)
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
        'success':       True,
        'requires_pin':  bool(PARENT_PIN),
        'has_session':   _is_valid_session(request.cookies.get(SESSION_COOKIE, '')),
    })

# ============================================================
# WEB UI
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
    <h1>🛡️ PACON v1.2.4</h1><p>index.html not found in web/public/</p></body></html>'''

# ============================================================
# HEALTH & DIAGNOSTICS
# ============================================================
@app.route('/api/health', methods=['GET'])
def health_check():
    now = time.time()
    online_agents = sum(1 for did in devices
                        if _is_device_online(did, now))
    return jsonify({
        "success":          True,
        "service":          "PACON API",
        "status":           "running",
        "version":          "1.2.4",
        "platform":         platform.system(),
        "devices":          len(devices),
        "online_agents":    online_agents,
        "fingerprints":     len(device_fingerprint),
        "is_render":        IS_RENDER,
        "requires_pin":     bool(PARENT_PIN),
        "telegram_enabled": telegram_config.get("enabled", False),
        "self_ping":        ping_running,
        "watchdog_alive":   bool(_watchdog_thread and _watchdog_thread.is_alive()),
        "results_cached":   len(command_results),
        "queued_commands":  sum(len(q) for q in command_queues.values()),
        "timestamp":        datetime.now().isoformat(),
    })

@app.route('/api/debug/devices', methods=['GET'])
@require_parent_auth
def debug_devices():
    now = time.time()
    out = {}
    for did, info in devices.items():
        age = _device_age(did, now)
        pid_info = device_agent_pid.get(did, {})
        has_polled = did in control_devices
        out[did] = {
            'name':             info.get('name'),
            'model':            info.get('model'),
            'hostname':         info.get('hostname'),
            'machine_guid':     info.get('machine_guid'),
            'public_ip':        info.get('public_ip'),
            'last_seen':        info.get('last_seen'),
            'status':           info.get('status', 'unknown'),
            'last_poll_secs':   int(age) if age is not None else None,
            'online':           (age is not None and age < OFFLINE_THRESHOLD),
            'has_polled':       has_polled,
            'has_apps':         did in installed_apps,
            'app_count':        len(installed_apps.get(did, [])),
            'has_screen_info':  did in device_screens,
            'queued_cmds':      len(command_queues.get(did, [])),
            'agent_pid':        pid_info.get('pid'),
            'agent_version':    pid_info.get('version'),
            'agent_first_seen': pid_info.get('first_seen'),
        }
    # Also expose fingerprints
    fp_out = {}
    with fingerprint_lock:
        for fp, cid in device_fingerprint.items():
            fp_out[fp] = cid[:8] if cid else None

    return jsonify({
        'success':           True,
        'devices':           out,
        'fingerprints':      fp_out,
        'server_now':        datetime.now().isoformat(),
        'offline_threshold': OFFLINE_THRESHOLD,
        'offline_grace':     OFFLINE_GRACE,
        'stale_cutoff':      STALE_CUTOFF,
        'orphan_cutoff':     ORPHAN_CUTOFF,
        'pending_ttl':       PENDING_TTL,
        'result_ttl':        RESULT_TTL,
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
            'full_name':     first.get('name', ''),
            'email':         first.get('email', ''),
            'company':       first.get('company', ''),
            'computer_name': first.get('model', 'Unknown'),
            'device_count':  len(devices),
        }
    now = time.time()
    online_states = {d: _is_device_online(d, now) for d in devices.keys()}
    return jsonify({
        "success":         True,
        "is_running":      True,
        "active_children": list(devices.keys()),
        "platform":        platform.system(),
        "user_info":       user_info,
        "online_agents":   online_states,
        "stats": {
            "screenshots":     len(screenshots),
            "camera_photos":   len(camera_photos),
            "locations":       len(locations),
            "app_usage":       len(app_usage),
            "installed_apps":  sum(len(v) for v in installed_apps.values()),
            "devices":         len(devices),
            "control_devices": len(control_devices),
        },
        "devices":   devices,
        "timestamp": datetime.now().isoformat(),
    })

@app.route('/api/devices', methods=['GET'])
@require_parent_auth
def get_devices():
    """
    v1.2.4: returns only devices that have POLLED recently.
    A device that has only registered (no poll) is hidden.
    Uses poll age, not registration age, as authoritative.
    """
    now = time.time()
    enriched = {}
    for did, info in devices.items():
        # Must have polled at least once
        if did not in control_devices:
            # Give it a chance: if registration is very recent, show as pending
            ls = info.get('last_seen', '')
            if ls:
                try:
                    reg_age = now - datetime.fromisoformat(ls).timestamp()
                    if reg_age < PENDING_TTL:
                        d = dict(info)
                        d['online'] = False
                        d['pending'] = True
                        d['last_poll_secs'] = None
                        d['agent_pid'] = device_agent_pid.get(did, {}).get('pid')
                        enriched[did] = d
                except Exception:
                    pass
            continue

        age = _device_age(did, now)
        if age is None or age > STALE_CUTOFF:
            continue

        d = dict(info)
        d['online'] = age < OFFLINE_THRESHOLD
        d['pending'] = False
        d['last_poll_secs'] = int(age)
        d['agent_pid'] = device_agent_pid.get(did, {}).get('pid')
        d['agent_version'] = device_agent_pid.get(did, {}).get('version')
        enriched[did] = d

    return jsonify({"success": True, "devices": enriched})

@app.route('/api/device/<device_id>/stats', methods=['GET'])
@require_parent_auth
def device_stats(device_id):
    now = time.time()
    if device_id not in devices:
        return jsonify({'success': False, 'error': 'device not found'}), 404
    age = _device_age(device_id, now)
    return jsonify({
        'success':          True,
        'device_id':        device_id,
        'online':           _is_device_online(device_id, now),
        'last_poll_secs':   int(age) if age is not None else None,
        'app_count':        len(installed_apps.get(device_id, [])),
        'screenshot_count': sum(1 for s in screenshots if s.get('device_id') == device_id),
        'queued_cmds':      len(command_queues.get(device_id, [])),
        'agent_pid':        device_agent_pid.get(device_id, {}).get('pid'),
        'agent_version':    device_agent_pid.get(device_id, {}).get('version'),
    })

# ============================================================
# SCREENSHOTS
# ============================================================
def _add_cache_headers(resp, seconds: int = 2):
    resp.headers['Cache-Control'] = f'public, max-age={seconds}'
    return resp

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
                        'filename':  file.name,
                        'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'size':      stat.st_size,
                        'url':       f'/api/screenshots/{file.name}',
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
            resp = send_file(filepath, mimetype=mime)
            return _add_cache_headers(resp, seconds=2)
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
                    'filename':  file.name,
                    'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'size':      stat.st_size,
                    'url':       f'/api/camera/photos/{file.name}',
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
            resp = send_file(filepath, mimetype='image/jpeg')
            return _add_cache_headers(resp, seconds=2)
    return jsonify({"error": "File not found"}), 404

# ============================================================
# FILES / ACTIVITY
# ============================================================
@app.route('/api/files/list', methods=['GET'])
@require_parent_auth
def list_files():
    limit = request.args.get('limit', 50, type=int)
    files = []
    for file in sorted(FILES_DIR.glob('*'),
                       key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
        files.append({
            'name':           file.name,
            'size':           file.stat().st_size,
            'size_formatted': f"{file.stat().st_size / 1024:.1f} KB",
            'modified':       datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
        })
    return jsonify(files)

@app.route('/api/activity', methods=['GET'])
@require_parent_auth
def get_activity():
    limit = request.args.get('limit', 20, type=int)
    return jsonify({
        "success":    True,
        "activities": activities[-limit:],
        "count":      len(activities),
    })

# ============================================================
# APP ENDPOINTS
# ============================================================
@app.route('/api/apps', methods=['GET'])
@require_parent_auth
def get_apps():
    device_id = request.args.get('deviceId', '')
    limit     = request.args.get('limit', 50, type=int)
    now       = time.time()

    if device_id:
        if not _is_device_online(device_id, now):
            return jsonify([])
        return jsonify(installed_apps.get(device_id, [])[:limit])

    result = []
    for did, apps in installed_apps.items():
        if _is_device_online(did, now):
            result.extend(apps)
    return jsonify(result[:limit])

@app.route('/api/apps/list', methods=['GET'])
@require_parent_auth
def apps_list():
    device_id = request.args.get('deviceId', '')
    if not device_id:
        return jsonify([])
    if not _is_device_online(device_id):
        return jsonify([])
    return jsonify(installed_apps.get(device_id, []))

@app.route('/api/apps/search', methods=['GET'])
@require_parent_auth
def apps_search():
    q = request.args.get('q', '').lower()
    device_id = request.args.get('deviceId', '')
    if not q:
        return jsonify([])
    source = []
    if device_id and _is_device_online(device_id):
        source = installed_apps.get(device_id, [])
    elif not device_id:
        now = time.time()
        for did, apps in installed_apps.items():
            if _is_device_online(did, now):
                source.extend(apps)
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
    device_id = request.args.get('deviceId', '')
    if device_id and device_id in devices:
        info = devices[device_id]
        return jsonify({
            "success":       True,
            "full_name":     info.get('name', 'User'),
            "email":         info.get('email', ''),
            "company":       info.get('company', ''),
            "computer_name": info.get('model', 'Unknown'),
            "device_id":     device_id,
        })
    for device_id, info in devices.items():
        return jsonify({
            "success":       True,
            "full_name":     info.get('name', 'User'),
            "email":         info.get('email', ''),
            "company":       info.get('company', ''),
            "computer_name": info.get('model', 'Unknown'),
            "device_id":     device_id,
        })
    return jsonify({"success": True, "full_name": "Unknown"})

@app.route('/api/system/info', methods=['GET'])
@require_parent_auth
def system_info():
    return jsonify({
        "success":        True,
        "platform":       platform.system(),
        "hostname":       socket.gethostname(),
        "python_version": sys.version.split()[0],
        "is_render":      IS_RENDER,
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
            "web_dir":      str(WEB_DIR),
            "exists":       WEB_DIR.exists(),
            "files":        [f.name for f in files],
            "index_exists": (WEB_DIR / 'index.html').exists(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/ping/status', methods=['GET'])
@require_parent_auth
def ping_status():
    return jsonify({
        "success":       True,
        "ping_running":  ping_running,
        "ping_interval": ping_interval,
    })

# ============================================================
# AGENT MONITORING ENDPOINTS
# ============================================================
@app.route('/api/monitor/user', methods=['POST'])
@require_agent_auth
def monitor_user():
    try:
        data = request.json or {}
        incoming_id = data.get('deviceId', 'unknown')
        pid         = data.get('pid')
        version     = data.get('agent_version', 'unknown')
        mguid       = data.get('machine_guid', '')
        hostname    = data.get('hostname', data.get('deviceModel', ''))
        # v1.2.4: use the client's public IP from the request
        req_ip      = _get_public_ip_from_request()
        public_ip   = data.get('public_ip', '') or req_ip

        # v1.2.4: canonicalize the ID
        device_id = _resolve_canonical_id(incoming_id, hostname, public_ip)
        if device_id != incoming_id:
            logger.info(f"🔀 Canonicalized {incoming_id[:8]} → {device_id[:8]} "
                        f"(host={hostname}, ip={public_ip})")

        # Duplicate-agent detection
        prev = device_agent_pid.get(device_id)
        if prev and prev.get('pid') != pid:
            logger.warning(
                f"⚠️ Device {device_id[:8]} re-registered by new agent "
                f"(old PID {prev.get('pid')}, new PID {pid}). Replacing."
            )

        device_agent_pid[device_id] = {
            'pid':        pid,
            'version':    version,
            'first_seen': prev.get('first_seen') if prev else datetime.now().isoformat(),
        }

        existing_first_seen = devices.get(device_id, {}).get('first_seen',
                                datetime.now().isoformat())

        devices[device_id] = {
            'id':              device_id,
            'name':            data.get('name', 'User'),
            'email':           data.get('email', ''),
            'company':         data.get('company', ''),
            'model':           data.get('deviceModel', 'Unknown'),
            'android_version': data.get('androidVersion', data.get('os_version', 'Unknown')),
            'public_ip':       public_ip,
            'hostname':        hostname or data.get('deviceModel', 'Unknown'),
            'machine_guid':    mguid,
            'agent_version':   version,
            'first_seen':      existing_first_seen,
            'last_seen':       datetime.now().isoformat(),
            'status':          'active' if device_id in control_devices else 'pending',
        }
        add_activity('user_registered',
                     f"{data.get('name','User')} from {data.get('deviceModel','Unknown')}",
                     device_id)
        logger.info(f"✅ User registered: {data.get('name')} ({data.get('deviceModel')}) "
                    f"pid={pid} v={version} id={device_id[:8]}")
        _mark_device_online(device_id)
        return jsonify({
            "success": True,
            "device_id": device_id,
            "canonical_id": device_id,
            "was_merged": device_id != incoming_id,
        })
    except Exception as e:
        logger.error(f"User error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/monitor/screenshot', methods=['POST'])
@require_agent_auth
@rate_limit('screenshot')
def monitor_screenshot():
    try:
        data = request.json or {}
        filename   = safe_filename(data.get('filename',
                        f'screenshot_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png'))
        image_data = data.get('data')
        incoming_id = data.get('deviceId', 'unknown')
        width      = data.get('width', 0)
        height     = data.get('height', 0)
        hostname   = data.get('deviceModel', '')
        public_ip  = _get_public_ip_from_request()

        # Canonicalize ID
        device_id = _resolve_canonical_id(incoming_id, hostname, public_ip)

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
            'filename':     filename,
            'device_id':    device_id,
            'device_model': hostname or 'Unknown',
            'timestamp':    datetime.now().isoformat(),
            'size':         filepath.stat().st_size,
            'width':        width,
            'height':       height,
            'url':          f'/api/screenshots/{filename}',
        })
        if len(screenshots) > 500:
            screenshots[:] = screenshots[-500:]
        return jsonify({"success": True, "filename": filename,
                        "device_id": device_id})
    except Exception as e:
        logger.error(f"Screenshot error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/monitor/camera', methods=['POST'])
@require_agent_auth
def monitor_camera():
    try:
        data = request.json or {}
        filename   = safe_filename(data.get('filename',
                        f'camera_{datetime.now().strftime("%Y%m%d_%H%M%S")}.jpg'))
        image_data = data.get('data')
        incoming_id = data.get('deviceId', 'unknown')
        hostname    = data.get('deviceModel', '')
        public_ip   = _get_public_ip_from_request()
        device_id = _resolve_canonical_id(incoming_id, hostname, public_ip)

        if not image_data:
            return jsonify({"success": False, "error": "No image data"}), 400
        image_bytes = base64.b64decode(image_data)
        filepath = UPLOAD_DIR / filename
        with open(filepath, 'wb') as f:
            f.write(image_bytes)
        if device_id in devices:
            devices[device_id]['last_seen'] = datetime.now().isoformat()
        camera_photos.append({
            'filename':  filename,
            'device_id': device_id,
            'timestamp': datetime.now().isoformat(),
            'url':       f'/api/camera/photos/{filename}',
        })
        return jsonify({"success": True, "filename": filename})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/monitor/location', methods=['POST'])
@require_agent_auth
def monitor_location():
    try:
        data = request.json or {}
        incoming_id = data.get('deviceId', 'unknown')
        hostname    = data.get('deviceModel', '')
        public_ip   = _get_public_ip_from_request()
        device_id = _resolve_canonical_id(incoming_id, hostname, public_ip)

        lat = data.get('latitude'); lon = data.get('longitude')
        if lat is None or lon is None:
            return jsonify({"success": False, "error": "No location"}), 400
        if device_id in devices:
            devices[device_id]['last_seen'] = datetime.now().isoformat()
        locations.append({
            'device_id': device_id,
            'latitude':  lat,
            'longitude': lon,
            'accuracy':  data.get('accuracy', 0),
            'timestamp': datetime.now().isoformat(),
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
        incoming_id = data.get('deviceId', 'unknown')
        hostname    = data.get('deviceModel', '')
        public_ip   = _get_public_ip_from_request()
        device_id = _resolve_canonical_id(incoming_id, hostname, public_ip)

        apps = data.get('apps', [])
        if device_id in devices:
            devices[device_id]['last_seen'] = datetime.now().isoformat()
        if apps and isinstance(apps[0], dict) and 'label' in apps[0]:
            installed_apps[device_id] = apps
            logger.info(f"📱 Installed apps: {len(apps)} from {device_id[:8]}")
        else:
            app_usage.append({
                'device_id': device_id,
                'apps':      apps,
                'count':     len(apps),
                'timestamp': datetime.now().isoformat(),
            })
            if len(app_usage) > 500:
                app_usage[:] = app_usage[-500:]
        return jsonify({"success": True, "count": len(apps),
                        "device_id": device_id})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/monitor/running-apps', methods=['POST'])
@require_agent_auth
def monitor_running_apps():
    try:
        data = request.json or {}
        incoming_id = data.get('deviceId', 'unknown')
        hostname    = data.get('deviceModel', '')
        public_ip   = _get_public_ip_from_request()
        device_id = _resolve_canonical_id(incoming_id, hostname, public_ip)

        apps = data.get('apps', [])
        if device_id in devices:
            devices[device_id]['last_seen'] = datetime.now().isoformat()
        app_usage.append({
            'device_id': device_id,
            'apps':      apps,
            'count':     len(apps),
            'timestamp': datetime.now().isoformat(),
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
        incoming_id = data.get('deviceId', 'unknown')
        hostname    = data.get('deviceModel', '')
        public_ip   = _get_public_ip_from_request()
        device_id = _resolve_canonical_id(incoming_id, hostname, public_ip)

        device_screens[device_id] = {
            'width':   data.get('width', 1080),
            'height':  data.get('height', 2400),
            'density': data.get('density', 0),
        }
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ============================================================
# REMOTE CONTROL
# ============================================================
class DeviceOfflineError(Exception):
    """Raised when queueing a command for an offline device."""
    pass

def _enqueue(device_id: str, action: str,
             params: dict = None, ttl: float = 12.0) -> str:
    now = time.time()
    last_poll = control_devices.get(device_id, 0)

    if not last_poll:
        ls = devices.get(device_id, {}).get('last_seen', '')
        if ls:
            try:
                last_poll = datetime.fromisoformat(ls).timestamp()
            except Exception:
                last_poll = 0

    if not last_poll:
        raise DeviceOfflineError(
            f"device {device_id[:8]} has never polled"
        )

    age = now - last_poll
    if age > OFFLINE_THRESHOLD:
        shown_age = min(int(age), 86400 * 365)
        raise DeviceOfflineError(
            f"device {device_id[:8]} offline for {shown_age}s"
        )

    cmd_id = str(uuid.uuid4())
    item = {
        'id':      cmd_id,
        'action':  action,
        'params':  params or {},
        'created': now,
        'ttl':     ttl,
    }
    command_queues[device_id].append(item)
    logger.info(f"🎮 Queued '{action}' for {device_id[:8]} (id={cmd_id[:8]})")
    return cmd_id

def _enqueue_response(device_id, action, params=None, ttl=12.0):
    try:
        cid = _enqueue(device_id, action, params, ttl)
        return {'success': True, 'id': cid}, 200
    except DeviceOfflineError as e:
        logger.warning(f"❌ Refused command '{action}': {e}")
        return {'success': False, 'error': str(e), 'offline': True}, 503

@app.route('/api/control/poll', methods=['GET', 'OPTIONS'])
@require_agent_auth
def control_poll():
    if request.method == 'OPTIONS':
        return '', 204
    incoming_id = request.args.get('deviceId', 'unknown')
    public_ip   = _get_public_ip_from_request()
    # v1.2.4: canonicalize using only public_ip (no hostname in poll request)
    device_id = _resolve_canonical_id(incoming_id, "", public_ip)

    # Mark this ID as polling
    control_devices[device_id] = time.time()

    # v1.2.4: also update last_seen so orphan cleanup knows it's alive
    if device_id in devices:
        devices[device_id]['last_seen'] = datetime.now().isoformat()
        devices[device_id]['status']    = 'active'
    else:
        # Provisional entry so /api/devices can show it even before
        # /api/monitor/user arrives
        devices[device_id] = {
            'id':              device_id,
            'name':            f"Device {device_id[:8]}",
            'email':           '',
            'company':         '',
            'model':           'Unknown (registering...)',
            'android_version': 'Unknown',
            'public_ip':       public_ip,
            'hostname':        'Unknown',
            'machine_guid':    '',
            'agent_version':   'unknown',
            'first_seen':      datetime.now().isoformat(),
            'last_seen':       datetime.now().isoformat(),
            'status':          'active',
            'provisional':     True,
        }
        logger.info(f"🆕 Provisional device from poll: {device_id[:8]}")

    _mark_device_online(device_id)
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
    cid  = data.get('id')
    if cid:
        ok = bool(data.get('ok'))
        command_results[cid] = {
            'ok':        ok,
            'error':     data.get('error', ''),
            'data':      data.get('data'),
            'action':    data.get('action', ''),
            'timestamp': time.time(),
            'deviceId':  data.get('deviceId', 'unknown'),
        }
        status = "✅" if ok else f"❌ {data.get('error', '')[:80]}"
        add_activity('control',
                     f'Action {cid[:8]} ({data.get("action","?")}) → {status}',
                     data.get('deviceId', 'unknown'))
    return jsonify({'success': True})

# ---- Input commands ----
@app.route('/api/control/tap', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_tap():
    d = request.json or {}
    payload, code = _enqueue_response(
        d.get('deviceId', 'unknown'), 'tap',
        {'x': d.get('x', 0), 'y': d.get('y', 0)})
    return jsonify(payload), code

@app.route('/api/control/longpress', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_longpress():
    d = request.json or {}
    payload, code = _enqueue_response(
        d.get('deviceId', 'unknown'), 'longpress',
        {'x': d.get('x', 0), 'y': d.get('y', 0)})
    return jsonify(payload), code

@app.route('/api/control/swipe', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_swipe():
    d = request.json or {}
    payload, code = _enqueue_response(
        d.get('deviceId', 'unknown'), 'swipe', {
            'x1': d.get('x1', 0), 'y1': d.get('y1', 0),
            'x2': d.get('x2', 0), 'y2': d.get('y2', 0),
            'duration': d.get('duration', 300),
        })
    return jsonify(payload), code

@app.route('/api/control/text', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_text():
    d = request.json or {}
    payload, code = _enqueue_response(
        d.get('deviceId', 'unknown'), 'text', {'text': d.get('text', '')})
    return jsonify(payload), code

@app.route('/api/control/backspace', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_backspace():
    d = request.json or {}
    payload, code = _enqueue_response(
        d.get('deviceId', 'unknown'), 'backspace', {})
    return jsonify(payload), code

@app.route('/api/control/key', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_key():
    d = request.json or {}
    key = d.get('key', 'home')
    valid = ('home', 'back', 'recents', 'notifications',
             'lock', 'wake', 'screenshot')
    if key not in valid:
        return jsonify({'success': False, 'error': 'unknown key'}), 400
    payload, code = _enqueue_response(d.get('deviceId', 'unknown'), key, {})
    return jsonify(payload), code

@app.route('/api/control/rightclick', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_rightclick():
    d = request.json or {}
    payload, code = _enqueue_response(
        d.get('deviceId', 'unknown'), 'rightclick',
        {'x': d.get('x', 0), 'y': d.get('y', 0)})
    return jsonify(payload), code

@app.route('/api/control/doubleclick', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_doubleclick():
    d = request.json or {}
    payload, code = _enqueue_response(
        d.get('deviceId', 'unknown'), 'doubleclick',
        {'x': d.get('x', 0), 'y': d.get('y', 0)})
    return jsonify(payload), code

@app.route('/api/control/scroll', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_scroll():
    d = request.json or {}
    payload, code = _enqueue_response(
        d.get('deviceId', 'unknown'), 'scroll', {
            'x': d.get('x', 0), 'y': d.get('y', 0),
            'amount': d.get('amount', 0),
        })
    return jsonify(payload), code

@app.route('/api/control/hotkey', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_hotkey():
    d = request.json or {}
    keys = d.get('keys', '')
    if not keys:
        return jsonify({'success': False, 'error': 'keys required'}), 400
    payload, code = _enqueue_response(
        d.get('deviceId', 'unknown'), 'hotkey', {'keys': keys})
    return jsonify(payload), code

@app.route('/api/control/launch', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_launch():
    d = request.json or {}
    device_id = d.get('deviceId', 'unknown')
    package   = d.get('package', '')
    if not package:
        return jsonify({'success': False, 'error': 'package required'}), 400
    payload, code = _enqueue_response(device_id, 'launch', {'package': package})
    if code == 200:
        add_activity('launch', f'Launch: {package[:60]}', device_id)
    return jsonify(payload), code

@app.route('/api/control/launch-history', methods=['GET'])
@require_parent_auth
def control_launch_history():
    device_id = request.args.get('deviceId', '')
    limit     = request.args.get('limit', 20, type=int)
    launches  = [
        a for a in activities[-200:]
        if a.get('action') == 'launch'
        or (a.get('action') == 'control' and 'launch' in a.get('details', '').lower())
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

@app.route('/api/control/status-batch', methods=['POST'])
@require_parent_auth
def control_status_batch():
    ids = (request.json or {}).get('ids', [])
    out = {}
    for cid in ids:
        r = command_results.get(cid)
        if r:
            out[cid] = r
    return jsonify({'success': True, 'results': out})

@app.route('/api/control/devices', methods=['GET'])
@require_parent_auth
def control_devices_list():
    now = time.time()
    online = {k: _is_device_online(k, now) for k in devices.keys()}
    return jsonify({'success': True, 'devices': online})

# ============================================================
# GODMODE CONTROL ENDPOINTS
# ============================================================
@app.route('/api/control/clipboard-get', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_clipboard_get():
    d = request.json or {}
    payload, code = _enqueue_response(
        d.get('deviceId', 'unknown'), 'clipboard_get', {}, ttl=20.0)
    return jsonify(payload), code

@app.route('/api/control/clipboard-set', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_clipboard_set():
    d = request.json or {}
    payload, code = _enqueue_response(
        d.get('deviceId', 'unknown'), 'clipboard_set',
        {'text': d.get('text', '')}, ttl=20.0)
    return jsonify(payload), code

@app.route('/api/control/power', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_power():
    d = request.json or {}
    payload, code = _enqueue_response(
        d.get('deviceId', 'unknown'), 'power',
        {'action': d.get('action', '')}, ttl=15.0)
    return jsonify(payload), code

@app.route('/api/control/list-dir', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_list_dir():
    d = request.json or {}
    payload, code = _enqueue_response(
        d.get('deviceId', 'unknown'), 'list_dir',
        {'path': d.get('path', '')}, ttl=20.0)
    return jsonify(payload), code

@app.route('/api/control/kill', methods=['POST'])
@require_parent_auth
@rate_limit('control')
def control_kill():
    d = request.json or {}
    payload, code = _enqueue_response(
        d.get('deviceId', 'unknown'), 'kill',
        {'name': d.get('name', '')}, ttl=15.0)
    return jsonify(payload), code

# ============================================================
# TELEGRAM ENDPOINTS
# ============================================================
@app.route('/api/telegram/status', methods=['GET'])
@require_parent_auth
def telegram_status():
    return jsonify({
        "success":        True,
        "enabled":        telegram_config.get("enabled", False),
        "configured":     bool(telegram_config.get("bot_token") and telegram_config.get("chat_id")),
        "notify_online":  telegram_config.get("notify_online", True),
        "notify_offline": telegram_config.get("notify_offline", True),
    })

@app.route('/api/telegram/config', methods=['GET', 'POST'])
@require_parent_auth
def telegram_config_endpoint():
    global telegram_config
    if request.method == 'GET':
        return jsonify({
            'success': True,
            'config': {
                'bot_token':      telegram_config.get('bot_token', ''),
                'chat_id':        telegram_config.get('chat_id', ''),
                'enabled':        telegram_config.get('enabled', False),
                'notify_online':  telegram_config.get('notify_online', True),
                'notify_offline': telegram_config.get('notify_offline', True),
            }
        })
    data = request.json or {}
    if 'bot_token'      in data: telegram_config['bot_token']      = str(data['bot_token']).strip()
    if 'chat_id'        in data: telegram_config['chat_id']        = str(data['chat_id']).strip()
    if 'enabled'        in data: telegram_config['enabled']        = bool(data['enabled'])
    if 'notify_online'  in data: telegram_config['notify_online']  = bool(data['notify_online'])
    if 'notify_offline' in data: telegram_config['notify_offline'] = bool(data['notify_offline'])
    _save_telegram_config()
    logger.info(f"📲 Telegram config updated (enabled={telegram_config['enabled']})")
    return jsonify({'success': True})

@app.route('/api/telegram/test', methods=['POST'])
@require_parent_auth
@rate_limit('telegram')
def telegram_test():
    r = _telegram_send_message(
        "🛡️ <b>PACON</b>\n\n✅ Telegram integration is connected.\n"
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
    return jsonify({'success': False, 'error': f'File not found: {filename}'}), 404

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
    return jsonify({'success': False, 'error': f'File not found: {filename}'}), 404

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
    return jsonify({'success': False, 'error': f'File not found: {filename}'}), 404

@app.route('/api/telegram/send-apps', methods=['POST'])
@require_parent_auth
@rate_limit('telegram')
def telegram_send_apps():
    data = request.json or {}
    device_id = data.get('deviceId', '')
    apps = installed_apps.get(device_id, []) if device_id else []
    if not apps and not device_id:
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
    r = _telegram_send_message("\n".join(lines))
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
    logger.exception(f"Unhandled: {e}")
    return jsonify({"success": False, "error": str(e)}), 500

# ============================================================
# GRACEFUL SHUTDOWN
# ============================================================
def _on_signal(signum, frame):
    logger.info(f"🛑 Received signal {signum}; shutting down")
    _stop_event.set()

try:
    signal.signal(signal.SIGINT,  _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)
except Exception:
    pass

# ============================================================
# MAIN
# ============================================================
def main():
    print("=" * 70)
    print("  PACON SERVICE v1.2.4 — GODMODE")
    print("=" * 70)
    logger.info(f"Web dir: {WEB_DIR}")
    logger.info(f"Running on Render: {IS_RENDER}")
    logger.info(f"Parent PIN: {'SET' if PARENT_PIN else 'NOT SET (unprotected)'}")
    logger.info(f"Agent PIN:  {'SET' if AGENT_PIN else 'NOT SET (unprotected)'}")
    logger.info(f"Telegram:   {'ENABLED' if telegram_config.get('enabled') else 'disabled'}")

    start_ping_system()
    start_watchdog()

    try:
        app.run(host='0.0.0.0', port=5001, debug=False, threaded=True)
    except KeyboardInterrupt:
        logger.info("🛑 Interrupted by user")
    finally:
        _stop_event.set()

if __name__ == '__main__':
    main()