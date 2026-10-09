"""Sphaira-compatible IPv4 LAN discovery, independent of the HTTP API."""
import json
import logging
import os
import socket
import threading
import uuid

from app.constants import APP_VERSION, CONFIG_DIR
from app.settings import load_settings

logger = logging.getLogger('main')
DISCOVERY_PORT = 8465
DISCOVERY_REQUEST = b'OWNFOIL_DISCOVER'
_responder = None
_lock = threading.Lock()
_http_port = 8465


def _server_uid():
    path = os.path.join(CONFIG_DIR, 'discovery_uid')
    try:
        with open(path, encoding='utf-8') as handle:
            return str(uuid.UUID(handle.read().strip()))
    except (FileNotFoundError, ValueError):
        os.makedirs(CONFIG_DIR, exist_ok=True)
        value = str(uuid.uuid4())
        temporary = path + '.tmp'
        with open(temporary, 'w', encoding='utf-8') as handle:
            handle.write(value)
        os.replace(temporary, path)
        return value


def discovery_payload(uid, http_port):
    shop = load_settings().get('shop', {})
    return {
        'magic': 'OWNFOIL',
        'uid': uid,
        'name': shop.get('discovery_name') or 'AeroFoil',
        'version': APP_VERSION,
        'port': shop.get('discovery_http_port') or http_port,
        'remote': str(shop.get('host') or '')[:255],
        'public': bool(shop.get('public', False)),
    }


class DiscoveryResponder(threading.Thread):
    def __init__(self, uid, http_port, port=DISCOVERY_PORT):
        super().__init__(daemon=True, name='lan-discovery')
        self.uid = uid
        self.http_port = http_port
        self.port = port
        self.sock = None
        self.stopping = threading.Event()

    def bind(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # An exclusive listener prevents multiple instances stealing replies.
            sock.bind(('0.0.0.0', self.port))
            sock.settimeout(0.2)
        except OSError:
            sock.close()
            raise
        self.sock = sock
        self.port = sock.getsockname()[1]

    def run(self):
        while not self.stopping.is_set():
            try:
                request, sender = self.sock.recvfrom(1024)
                if request.strip() != DISCOVERY_REQUEST:
                    continue
                payload = discovery_payload(self.uid, self.http_port)
                self.sock.sendto(json.dumps(payload).encode('utf-8'), sender)
            except socket.timeout:
                continue
            except Exception:
                if not self.stopping.is_set():
                    logger.exception('Could not answer LAN discovery request')
                self.stopping.wait(0.2)

    def stop(self):
        self.stopping.set()
        self.join(timeout=2)
        self.sock.close()


def reconcile(http_port=None):
    """Apply the toggle at startup and immediately after saving shop settings."""
    global _responder, _http_port
    with _lock:
        if http_port is not None:
            _http_port = http_port
        enabled = load_settings().get('shop', {}).get('discovery_enabled', False)
        if not enabled:
            _stop_locked()
        elif _responder is None:
            try:
                responder = DiscoveryResponder(_server_uid(), _http_port)
                responder.bind()
                responder.start()
                _responder = responder
                logger.info('LAN discovery listening on UDP port %s', responder.port)
            except OSError as exc:
                logger.warning('LAN discovery unavailable: %s', exc)


def _stop_locked():
    global _responder
    if _responder is not None:
        _responder.stop()
        _responder = None


def stop():
    with _lock:
        _stop_locked()
