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
TITLEDB_OPTIONAL_FILES = [
    'cnmts-fixed.json',
]

GEOLITE_DB_DIR = os.path.join(DATA_DIR, 'geoip')
GEOLITE_DB_FILE = os.path.join(GEOLITE_DB_DIR, 'GeoLite2-City.mmdb')
GEOLITE_DB_URL = 'https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb'

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
        # ISO country codes (eg "US", "GB") to deny at request edge.
        "auth_blocked_country_codes": [],
        # Optional ISO country whitelist. When set, only these countries are allowed.
        "auth_allowed_country_codes": [],
    },
    "library": {
        "paths": ["/games"],
        "auto_maintenance": False,
        "maintenance_interval_minutes": 720,
        "maintenance_delete_updates": True,
        "conversion_staging_dir": "",
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
                        "filename": "{title} [{app_id}] [UPDATE][v{version}].{ext}",
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
        "prefer_english_metadata": False,
        "valid_keys": False,
        "manual_overrides": {},
    },
    "downloads": {
        "enabled": False,
        "interval_minutes": 60,
        "category": "aerofoil",
        "required_terms": [],
        "required_terms_match": "all",
        "blacklist_terms": [],
        "search_prefix": "",
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
            "timeout_seconds": 15,
            "search_limit": 100
        },
        "torrent_client": {
            "type": "qbittorrent",
            "url": "",
            "username": "",
            "password": "",
            "category": "aerofoil",
            "download_path": "",
            "min_seeders": 2,
            "remove_completed_torrents_on_finish": True,
            "use_hardlinks_when_seeding": False,
        },
        "usenet_client": {
            "type": "sabnzbd",
            "url": "",
            "api_key": "",
            "category": "aerofoil",
            "min_age_minutes": 0,
        }
    },
    "shop": {
        "motd_enabled": True,
        "motd": "Welcome to your own shop!",
        "motd_api_url": "",
        "public": False,
        "external_tinfoil_only": False,
        "encrypt": True,
        "tinfoil_only_mode": False,
        "fast_transfer_mode": False,
        "cyberfoil_virtual_compressed_stream": True,
        "public_key": "",
        "clientCertPub": "-----BEGIN PUBLIC KEY-----",
        "clientCertKey": "-----BEGIN PRIVATE KEY-----",
        "host": "",
        "hauth": "",
    },
    "cheats": {
        "enabled": True,
        # Optional URL to a ZIP archive whose entries include
        # <title-id>/<build-id>.txt.  Leave empty to use manual imports only.
        "sync_url": "",
    },
    "content_filter": {
        # When a user has an age cap (max_rating) set, also hide/block titles
        # that have no known rating (homebrew, unidentified files, or titles
        # missing from TitleDB). True = fail-closed (safest for child accounts).
        "block_unrated": True,
    }
}

BUILTIN_TITLE_MANUAL_OVERRIDES = {
    "018FCC923D8D0000": {
        "name": "The Simpsons: Hit & Run [Port]",
        "description": "Community port of The Simpsons: Hit & Run for Nintendo Switch. Requires the original Windows game files to run.",
        "iconUrl": "https://static.simpsonswiki.com/images/5/5f/The_Simpsons_Hit_and_Run_cover.png",
        "bannerUrl": "https://static.simpsonswiki.com/images/5/5f/The_Simpsons_Hit_and_Run_cover.png",
        "screenshots": [],
    },
    "056783A0CC4A0000": {
        "name": "Ship of Harkinian",
        "description": "Open-source port of The Legend of Zelda: Ocarina of Time with modern enhancements for Nintendo Switch and other platforms.",
        "iconUrl": "https://raw.githubusercontent.com/HarbourMasters/shipofharkinian.com/9c5639c054cb3bc952760758307473a3e425fd33/public/logo.png",
        "bannerUrl": "https://raw.githubusercontent.com/HarbourMasters/shipofharkinian.com/9c5639c054cb3bc952760758307473a3e425fd33/public/splash_poster.jpg",
        "screenshots": [],
    },
    "0500D22512158000": {
        "name": "Sonic Dimensions",
        "description": "Fan-made homebrew port of the 2D Sonic fangame Sonic Dimensions for Nintendo Switch.",
        "iconUrl": "https://dlhb.gamebrew.org/switchhomebrews/images/SonicDimensionsSwitch-01.png",
        "bannerUrl": "https://dlhb.gamebrew.org/switchhomebrews/images/SonicDimensionsSwitch-02.png",
        "screenshots": [],
    },
    "010CAF78CF713000": {
        "name": "The Legend of Zelda - A Link to the Past",
        "description": "Community homebrew port of The Legend of Zelda: A Link to the Past for Nintendo Switch with quality-of-life and widescreen enhancements.",
        "iconUrl": "https://dlhb.gamebrew.org/switchhomebrews/images/zeldalinktothepastnx2.png",
        "bannerUrl": "https://dlhb.gamebrew.org/switchhomebrews/images/zeldalinktothepastnx3.png",
        "screenshots": [],
    },
    # Unverified port candidates, add only after confirming the Switch NSP app ID:
    # "TODO_APP_ID_2SHIP2HARKINIAN": {
    #     "name": "2 Ship 2 Harkinian",
    #     "description": "Community port of The Legend of Zelda: Majora's Mask for Nintendo Switch.",
    #     "iconUrl": "https://github.com/user-attachments/assets/a12851e2-1eb7-428c-973c-86fdfad73dd3",
    #     "bannerUrl": "https://github.com/user-attachments/assets/a12851e2-1eb7-428c-973c-86fdfad73dd3",
    #     "screenshots": [],
    # },
    # "TODO_APP_ID_STARSHIP": {
    #     "name": "Starship",
    #     "description": "Community port of Star Fox 64 for Nintendo Switch.",
    #     "iconUrl": "https://raw.githubusercontent.com/HarbourMasters/Starship/62eb5a198bc5a8806f8c1b43551cd689e929455e/logo.png",
    #     "bannerUrl": "https://raw.githubusercontent.com/HarbourMasters/Starship/62eb5a198bc5a8806f8c1b43551cd689e929455e/nx-logo.jpg",
    #     "screenshots": [],
    # },
    # "TODO_APP_ID_SUPER_METROID_SWITCH": {
    #     "name": "Super Metroid Switch",
    #     "description": "Community port of Super Metroid for Nintendo Switch.",
    #     "iconUrl": "",
    #     "bannerUrl": "",
    #     "screenshots": [],
    # },
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

# ESRB content rating scale. The numeric "age" matches TitleDB's `rating` field
# (the eShop minimum-age recommendation, e.g. Breath of the Wild = 10 = E10+).
# Filtering compares numerically, so it also works for PEGI-region TitleDB data;
# the labels assume the US (ESRB) region.
ESRB_RATINGS = [
    {"code": "E", "age": 0, "label": "Everyone"},
    {"code": "E10", "age": 10, "label": "Everyone 10+"},
    {"code": "T", "age": 13, "label": "Teen"},
    {"code": "M", "age": 17, "label": "Mature 17+"},
    {"code": "AO", "age": 18, "label": "Adults Only 18+"},
]
ESRB_AGE_BY_CODE = {item["code"]: item["age"] for item in ESRB_RATINGS}
ESRB_VALID_AGES = [item["age"] for item in ESRB_RATINGS]

# Bump to force a one-time rebuild of the titles SQLite index when its on-disk
# schema changes (the `rating` column was added in this version).
TITLES_INDEX_SCHEMA_VERSION = 'rating-v1'
