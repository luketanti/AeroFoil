import os

APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(APP_DIR)
DATA_DIR = os.path.join(APP_DIR, 'data')
CONFIG_DIR = os.path.join(APP_DIR, 'config')
_legacy_db_file = os.path.join(CONFIG_DIR, 'ownfoil.db')
_default_db_file = os.path.join(CONFIG_DIR, 'aerofoil.db')
_configured_db_file = os.environ.get('AEROFOIL_DB_FILE') or os.environ.get('OWNFOIL_DB_FILE')
if _configured_db_file:
    DB_FILE = _configured_db_file
elif os.path.exists(_legacy_db_file) and not os.path.exists(_default_db_file):
    DB_FILE = _legacy_db_file
else:
    DB_FILE = _default_db_file
CONFIG_FILE = os.path.join(CONFIG_DIR, 'settings.yaml')
KEYS_FILE = os.path.join(CONFIG_DIR, 'keys.txt')
CACHE_DIR = os.path.join(DATA_DIR, 'cache')
LIBRARY_CACHE_FILE = os.path.join(CACHE_DIR, 'library.json')
SHOP_SECTIONS_CACHE_FILE = os.path.join(CACHE_DIR, 'shop_sections.json')
ALEMBIC_DIR = os.path.join(APP_DIR, 'migrations')
ALEMBIC_CONF = os.path.join(ALEMBIC_DIR, 'alembic.ini')
TITLEDB_DIR = os.path.join(DATA_DIR, 'titledb')
TITLEDB_URL = 'https://github.com/blawar/titledb.git'
TITLEDB_ARTEFACTS_URL = 'https://nightly.link/luketanti/aerofoil/workflows/region_titles/master/titledb.zip'
TITLEDB_DESCRIPTIONS_BASE_URL = 'https://raw.githubusercontent.com/blawar/titledb/master'
TITLEDB_DESCRIPTIONS_DEFAULT_FILE = 'US.en.json'
TITLEDB_DEFAULT_FILES = [
    'cnmts.json',
    'versions.json',
    'versions.txt',
    'languages.json',
]

APP_VERSION = os.environ.get('AEROFOIL_VERSION') or os.environ.get('OWNFOIL_VERSION') or os.environ.get('APP_VERSION') or 'dev'

AEROFOIL_DB = 'sqlite:///' + DB_FILE
# Backward-compatible alias for older imports.
OWNFOIL_DB = AEROFOIL_DB

DEFAULT_SETTINGS = {
    "security": {
        # When true, the application will not re-enter "setup mode" even if all admin
        # accounts are removed. Recovery must be done via environment-initialized users.
        "setup_complete": False,
        # When no admin exists yet, only allow bootstrap endpoints from private networks.
        "bootstrap_private_networks_only": True,
        # If running behind a reverse proxy (eg Nginx Proxy Manager), list its IP/CIDR here
        # so AeroFoil can safely trust X-Forwarded-For.
        # Examples: ["172.18.0.0/16", "192.168.1.10"]
        "trusted_proxies": [],
        # When true, use X-Forwarded-For only if request.remote_addr is trusted.
        "trust_proxy_headers": False,
        # Temporary lockout after repeated failed login attempts from same client IP.
        "auth_ip_lockout_enabled": True,
        "auth_ip_lockout_threshold": 5,
        "auth_ip_lockout_window_seconds": 600,
        "auth_ip_lockout_duration_seconds": 1800,
        # Permanent deny-list of IP/CIDR entries for authentication endpoints.
        "auth_permanent_ip_blacklist": [],
    },
    "library": {
        "paths": ["/games"],
        "auto_maintenance": False,
        "maintenance_interval_minutes": 720,
        "maintenance_delete_updates": True,
        "naming_templates": {
            "active": "default",
            "templates": {
                "default": {
                    "base": {
                        "folder": "{title} [{title_id}]/Base",
                        "filename": "{title} [{title_id}] [BASE][v{version}].{ext}",
                    },
                    "update": {
                        "folder": "{title} [{title_id}]/Updates/v{version}",
                        "filename": "{title} [{title_id}] [UPDATE][v{version}].{ext}",
                    },
                    "dlc": {
                        "folder": "{title} [{title_id}]/DLC/{dlc_name} [{app_id}]",
                        "filename": "{title} - {dlc_name} [{app_id}] [DLC][v{version}].{ext}",
                    },
                    "other": {
                        "folder": "{title} [{title_id}]/Other",
                        "filename": "{title} [{title_id}] [UNKNOWN].{ext}",
                    },
                },
            },
        },
    },
    "titles": {
        "language": "en",
        "region": "US",
        "valid_keys": False,
        "manual_overrides": {},
    },
    "downloads": {
        "enabled": False,
        "interval_minutes": 60,
        "min_seeders": 2,
        "required_terms": [],
        "blacklist_terms": [],
        "search_prefix": "Nintendo Switch",
        "search_suffix": "",
        "search_char_replacements": [
            {"from": "™", "to": ""},
            {"from": "®", "to": ""},
            {"from": "©", "to": ""},
            {"from": "é", "to": "e"},
        ],
        "prowlarr": {
            "url": "",
            "api_key": "",
            "indexer_ids": [],
            "categories": [],
            "timeout_seconds": 15
        },
        "torrent_client": {
            "type": "qbittorrent",
            "url": "",
            "username": "",
            "password": "",
            "category": "aerofoil",
            "download_path": ""
        }
    },
    "shop": {
        "motd": "Welcome to your own shop!",
        "public": False,
        "encrypt": True,
        "fast_transfer_mode": False,
        "public_key": "",
        "clientCertPub": "-----BEGIN PUBLIC KEY-----",
        "clientCertKey": "-----BEGIN PRIVATE KEY-----",
        "host": "",
        "hauth": "",
    }
}

TINFOIL_HEADERS = [
    'Theme',
    'Uid',
    'Version',
    'Revision',
    'Language',
    'Hauth',
    'Uauth'
]

ALLOWED_EXTENSIONS = [
    'nsp',
    'nsz',
    'xci',
    'xcz',
]

APP_TYPE_BASE = 'BASE'
APP_TYPE_UPD = 'UPDATE'
APP_TYPE_DLC = 'DLC'
APP_TYPE_MAP = {
    128: APP_TYPE_BASE,
    129: APP_TYPE_UPD,
    130: APP_TYPE_DLC,
}
