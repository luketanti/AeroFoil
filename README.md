# AeroFoil

[![Latest Release](https://img.shields.io/docker/v/luketanti/aerofoil?sort=semver)](https://github.com/luketanti/aerofoil/releases/latest)
[![Docker Pulls](https://img.shields.io/docker/pulls/luketanti/aerofoil)](https://hub.docker.com/r/luketanti/aerofoil)
[![Docker Image Size](https://img.shields.io/docker/image-size/luketanti/aerofoil/latest?arch=amd64)](https://hub.docker.com/r/luketanti/aerofoil/tags)
![Platforms](https://img.shields.io/badge/platforms-amd64%20%7C%20arm64-8A2BE2)
[![Discord](https://img.shields.io/badge/Discord-Join%20Server-5865F2?logo=discord&logoColor=white)](https://discord.gg/gGy7hWxJeP)


AeroFoil is a Personal library manager that turns your library into a fully customizable, self-hosted Remote. The goal of this project is to manage your library, identify any missing content (DLCs or updates) and provide a user friendly way to browse your content. Some of the features include:

 - multi user authentication
 - web interface for configuration
 - web interface for browsing the library
 - content identification
 - remote customization

The project is still in development, expect things to break or change without notice.

## Index

- [Installation](#installation)
  - [Docker](#using-docker)
  - [Environment variables](#environment-variables)
  - [Python](#using-python)
  - [CyberFoil setup](#cyberfoil-setup)
  - [Cheats](#cheats)
  - [Save backups](#save-backups-save-sync)
  - [Requests](#requests)
- [Usage](#usage)
  - [Library](#library-administration)
  - [Content rating controls](#content-rating-controls-esrb)
  - [Game information](#game-info-titledb)
  - [Automatic downloads](#automatic-update-downloads-prowlarr--download-clients)
  - [Titles configuration](#titles-configuration)
  - [Remote customization](#remote-customization)
- [Deployment notes](#deployment-notes)
  - [Reverse proxy](#reverse-proxy-real-client-ip-activity-page)
  - [TitleDB sources](#titledb-sources-and-downloads)
- [Roadmap](#roadmap)

<a id="installation"></a>
<details open>
<summary><strong>Installation</strong></summary>

## Using Docker
### Docker run

Running this command will start the remote on port `8465` with the library in `/your/game/directory`:

    docker run -d -p 8465:8465 \
      -v /your/game/directory:/games \
      -v /your/config/directory:/app/config \
      -v /your/data/directory:/app/data \
      --name aerofoil \
      luketanti/aerofoil:latest

The remote is now accessible with your computer/server IP and port, i.e. `http://localhost:8465` from the same computer or `http://192.168.1.100:8465` from a device in your network.

### Docker compose
Create a file named `docker-compose.yml` with the following content:
```
version: "3"

services:
  aerofoil:
    container_name: aerofoil
    image: luketanti/aerofoil:latest
    # environment:
    #   # For write permission in config directory
    #   - PUID=1000
    #   - PGID=1000
    #   # to create/update an admin user at startup
    #   - USER_ADMIN_NAME=admin
    #   - USER_ADMIN_PASSWORD=asdvnf!546
    #   # to create/update a regular user at startup
    #   - USER_GUEST_NAME=guest
    #   - USER_GUEST_PASSWORD=oerze!@8981
    #   # cache TTLs (seconds): use none/unset for rebuild-only
    #   - SHOP_SECTIONS_CACHE_TTL_S=none
    #   - MEDIA_INDEX_TTL_S=none
    volumes:
      - /your/game/directory:/games
      - ./config:/app/config
      - ./data:/app/data
      - ./conversion-tmp:/app/conversion-tmp
      - /your/downloads/directory:/downloads
    ports:
      - "8465:8465"
```
> [!NOTE]
> You can control the `UID` and `GID` of the user running the app in the container with the `PUID` and `PGID` environment variables. By default the user is created with `1000:1000`. If you want to have the same ownership for mounted directories, you need to set those variables with the UID and GID returned by the `id` command.

You can then create and start the container with the command (executed in the same directory as the docker-compose file):

    docker compose up -d

This is useful if you don't want to remember the `docker run` command and want a persistent, reproducible container configuration.

## Environment variables
New `AEROFOIL_*` variables are preferred. Legacy `OWNFOIL_*` names are still accepted for backward compatibility.

- `PUID` / `PGID`: control the user ID/group ID inside the container (default `1000:1000`).
- `USER_ADMIN_NAME` / `USER_ADMIN_PASSWORD`: create or update an admin user at startup (default: unset).
- `USER_GUEST_NAME` / `USER_GUEST_PASSWORD`: create or update a regular user at startup (default: unset).
- `AEROFOIL_DB_FILE`: override SQLite database file path (legacy `OWNFOIL_DB_FILE` also supported).
- `AEROFOIL_VERSION`: override app version label (legacy `OWNFOIL_VERSION` and `APP_VERSION` also supported).
- `AEROFOIL_SECRET_KEY`: Flask secret key used for sessions/cookies. Recommended to set a long random value in production (default: auto-generated at startup).
- `AEROFOIL_TRUST_PROXY_HEADERS`: enable trusting `X-Forwarded-For` when the proxy is in the trusted list (`true`/`false`, default: `false`).
- `AEROFOIL_TRUSTED_PROXIES`: comma-separated proxy IPs/CIDRs (default: empty), for example `172.16.0.0/12,192.168.0.0/16`.
- `AEROFOIL_AUTH_BLOCKED_COUNTRY_CODES`: comma-separated ISO country codes to block at auth boundary (legacy `OWNFOIL_AUTH_BLOCKED_COUNTRY_CODES` also supported).
- `AEROFOIL_AUTH_ALLOWED_COUNTRY_CODES`: comma-separated ISO country codes allowlist at auth boundary (legacy `OWNFOIL_AUTH_ALLOWED_COUNTRY_CODES` also supported).
- `AEROFOIL_CONVERSION_STAGING_ENABLED`: enable fixed Docker staging path (`/app/conversion-tmp`) for temporary NSP/XCI conversion output (`true`/`false`, default: unset/disabled).
- `AEROFOIL_CONVERSION_STAGING_DIR`: absolute path for temporary NSP/XCI conversion output (default: empty, which keeps direct in-library conversion output).
- `SHOP_SECTIONS_CACHE_TTL_S`: cache TTL for `/api/shop/sections` (seconds). Use `none`/unset for rebuild-only (default), `0` to disable caching. Recommended: `none` for stable libraries, or `600`-`900` for periodic refresh.
- `SHOP_SECTIONS_ALL_ITEMS_CAP`: max number of items retained per discovery section before per-request slicing (default: `300`).
- `SHOP_SECTIONS_ALL_ITEMS_CAP_NO_TITLEDB`: max number of items retained per discovery section when TitleDB is unavailable (default: `120`).
- `MEDIA_INDEX_TTL_S`: cache TTL for icon/banner media index (seconds). Use `none`/unset for rebuild-only (default), `0` to disable caching. Recommended: `none` or `600`-`900`.
- `AEROFOIL_TITLES_TOTAL_CACHE_TTL_S`: cache TTL for `/api/titles` total-count cache (seconds, default: `300`; legacy `OWNFOIL_TITLES_TOTAL_CACHE_TTL_S` also supported).
- `AEROFOIL_TITLES_TOTAL_CACHE_MAX_ENTRIES`: max entries for `/api/titles` total-count cache (default: `256`; clamped to `16..4096`; legacy `OWNFOIL_TITLES_TOTAL_CACHE_MAX_ENTRIES` also supported).
- `AEROFOIL_ACCESS_EVENTS_QUERY_MAX`: max rows returned by access-events API queries (legacy `OWNFOIL_ACCESS_EVENTS_QUERY_MAX` also supported; default `10000`).
- `AEROFOIL_ACTIVITY_API_MAX_LIMIT`: max rows returned by activity API queries (legacy `OWNFOIL_ACTIVITY_API_MAX_LIMIT` also supported; default `10000`).
- `AEROFOIL_CLIENTS_HISTORY_API_MAX_LIMIT`: max rows returned by clients-history API queries (legacy `OWNFOIL_CLIENTS_HISTORY_API_MAX_LIMIT` also supported; default `20000`).
- `AEROFOIL_CLIENTS_HISTORY_CSV_MAX_LIMIT`: max rows exported by clients-history CSV endpoints (legacy `OWNFOIL_CLIENTS_HISTORY_CSV_MAX_LIMIT` also supported; default `50000`).
- `AEROFOIL_HOST`: bind host for the web server (default: `0.0.0.0`).
- `AEROFOIL_PORT`: bind port for the web server (default: `8465`).
- `AEROFOIL_WSGI_THREADS`: Waitress worker thread count (default: `32`).
- `AEROFOIL_WSGI_CONNECTION_LIMIT`: max concurrent Waitress channels (default: `1000`).
- `AEROFOIL_WSGI_CHANNEL_TIMEOUT_S`: idle channel timeout in seconds (default: `120`).
- `AEROFOIL_WSGI_CLEANUP_INTERVAL_S`: Waitress cleanup interval in seconds (default: `30`).
- `AEROFOIL_WSGI_MAX_REQUEST_BODY_SIZE`: max HTTP request body size in bytes for Waitress (default: `68853694464`, about `64.125 GB`).
- `AEROFOIL_UPLOAD_TMP_DIR`: directory for temporary multipart upload files during request parsing (default: `<data>/tmp/uploads`; ensure enough free disk space for very large uploads).
- `AEROFOIL_USE_FLASK_DEV`: set to `true`/`1` to force Flask dev server instead of Waitress.
- `AEROFOIL_STATIC_MAX_AGE_S`: static asset cache max-age in seconds (legacy `OWNFOIL_STATIC_MAX_AGE_S` also supported; default `3600`).
- `WATCHDOG_POLLING`: set to `1`/`true`/`yes` to force polling-based file watcher observer.
- `LOG_LEVEL`: Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO)

## Using Python
Clone the repository using `git`, install the dependencies and you're good to go:
```
$ git clone https://github.com/luketanti/aerofoil
$ cd aerofoil
$ pip install -r requirements.txt
$ python app/app.py
```
To update the app you will need to pull the latest commits.

By default, `python app/app.py` runs AeroFoil with the Waitress WSGI server (production-oriented). Set `AEROFOIL_USE_FLASK_DEV=true` only if you need the Flask development server for debugging.

## CyberFoil setup
In CyberFoil, set the AeroFoil Remote URL in Settings:
 - URL: `http://<server-ip>:8465` (or `https://` if using an SSL-enabled reverse proxy) and port 443
 - Username: username as created in AeroFoil settings (if the remote is private)
 - Password: password as created in AeroFoil settings (if the remote is private)

## Cheats

AeroFoil includes an admin Cheat Manager under **Content → Cheats** for Atmosphère-compatible cheat files. Cheats are associated with a title ID and build ID, then stored as `<build-id>.txt`.

- Choose a title from the library search or enter a title ID manually for a title that is not yet in the library.
- Add a cheat by uploading a `.txt` file or pasting its text directly. An optional note is shown in the manager list.
- Download or delete individual cheat files from the list.
- Optionally sync a ZIP archive. The importer recognizes common structures, including `<title-id>/cheats/<build-id>.txt` and `atmosphere/contents/<title-id>/cheats/<build-id>.txt`.
- The [switch-cheats-db latest `titles_complete.zip`](https://github.com/HamletDuFromage/switch-cheats-db/releases/latest/download/titles_complete.zip) archive is a compatible sync source.

Enable **Show the Cheats section in CyberFoil** at the top of the manager and save the setting to advertise a versioned **Cheats** section to CyberFoil. Only cheats whose title has an owned base title in the library are included in that section.

Cheat management is admin-only. In **Users**, enable the **Cheats** permission for each account that may browse or download cheats from a private shop. Disabling it hides the CyberFoil Cheats section and denies the cheat APIs for that user. Public shops cannot apply this permission because requests have no per-user identity.

## Save backups (Save Sync)
AeroFoil supports per-user save backup management when the user has the **Backup** flag enabled:
- Save archives are stored per user under `data/saves/<username>/`.
- Multiple backup versions per title are supported.
- Each uploaded version can include a note.
- Backups can be uploaded, downloaded, or deleted from:
  - CyberFoil `Saves` section,
  - AeroFoil web page `Save Data Backups` (title picker + upload, download, delete).

Save sync API endpoints:
- `GET /api/saves/list`
- `POST /api/saves/upload/<title_id>`
- `GET /api/saves/download/<title_id>/<save_id>.zip`
- `DELETE /api/saves/delete/<title_id>/<save_id>` (also accepts `POST` for compatibility)

## Requests
AeroFoil supports title request tracking across users:
- A game request entry is shared by title, and multiple users can be linked to that request.
- Users can view their own requests and current request state in the Web UI.
- Admins can review all requests, run download search from request entries, deny requests, and delete requests.
- Open requests are automatically closed when the title becomes available in the library.

</details>

<a id="usage"></a>
<details open>
<summary><strong>Usage</strong></summary>

Once AeroFoil is running you can access the Remote Web UI by navigating to the `http://<computer/server IP>:8465`.

## User administration
AeroFoil requires an `admin` user to be created to enable Authentication for your Remote. Go to the `Settings` to create a first user that will have admin rights. Then you can add more users to your remote the same way.

## Content rating controls (ESRB)
AeroFoil can restrict each user's catalog and downloads using the ESRB age rating supplied by TitleDB. The restriction is applied per user: users without a maximum rating remain unrestricted.

The available maximum ratings are:

- `Everyone (E)` — 0
- `Everyone 10+ (E10+)` — 10
- `Teen (T)` — 13
- `Mature 17+ (M)` — 17
- `Adults Only (AO)` — 18

When a user has a maximum rating, titles above that limit are hidden from the web library, discovery sections, and the Tinfoil/Remote catalog. Direct download requests for blocked content are also rejected.

### Setup
1. Open **Users** and create or edit the account you want to restrict.
2. Set **Max rating** to the highest ESRB tier that user may access. Select **No limit** to leave the user unrestricted.
3. In **Settings**, choose whether **Hide unrated titles from age-capped users** should remain enabled. It is enabled by default and recommended for child accounts.

With that option enabled, homebrew, unidentified files, and titles without a known TitleDB rating are hidden from users who have a maximum rating. Disable it only if you want unrated content to remain visible to those users.

## Library administration
In the `Settings` page under the `Library` section, you can add directories containing your content. You can then manually trigger the library scan: AeroFoil will scan the content of the directories and try to identify every supported file (currently `nsp`, `nsz`, `xci`, `xcz`).
There is watchdog in place for all your added directories: files moved, renamed, added or removed will be reflected directly in your library.

## Library management
In the `Manage` page, you can organize your library structure, delete older update files, delete scoped library content, clean up orphaned add-ons, and convert `nsp`/`xci` to `nsz`.

## Library browser UI
- Card view: the Base/Update/DLC status icons are displayed above the action buttons.
- Icon view: the `Game info` button is shown as an overlay on the game tile.

### Discovery sections (`New` and `Recommended`)
The home-page discovery rows are generated from **owned BASE titles only** (not update/DLC rows), and only when a real library file is linked.

- `New`: sorted by most recent library file id (newest first), then the first items are used for the section.
- `Recommended`: sorted by highest `download_count` first. If every candidate has `download_count = 0`, AeroFoil falls back to the same ordering as `New`.

For the Web UI, these sections are returned through `/api/titles` as `discovery.newest` and `discovery.recommended`.

## Game info (TitleDB)
The `Game info` modal uses TitleDB metadata:
- `description`: shown as the game summary.
- `screenshots`: displayed in a grid; click a screenshot to open it larger.
- `DLC search`: admins can trigger a download search for related add-ons directly from the details flow.
- `Expand/Collapse toggle`: toggles the details card width (between standard `modal-lg` and `90vw` expanded layout) to provide more screen space when browsing. This preference is saved for the duration of the browser session.

AeroFoil will download the TitleDB descriptions/screenshot dataset on demand to `./data/titledb/US.en.json` (Docker path: `/app/data/titledb/US.en.json`).

> [!NOTE]
> On first boot, game titles may temporarily appear as `Unrecognized` while TitleDB is being downloaded in the background.
> Once the download finishes, refresh the page and names/metadata will appear.

Conversion details:
- Uses the installed Python `nsz` package (with progress output).
- Uses the same `keys.txt` uploaded in the `Settings` page.
- Optional conversion staging directory lets you run temporary conversion IO on a different disk/pool before finalizing output into the library path.
- Shows live status, per-file progress, and the current filename.
- Filters out files smaller than 50 MB from the manual conversion dropdown.
- The `Verbose` checkbox shows detailed task output; otherwise the task output stays clean.

## Automatic update downloads (Prowlarr + Download Clients)
AeroFoil can automatically search for missing updates using Prowlarr, route torrent results to a configured torrent client, route usenet results to a configured usenet client, and ingest completed downloads back into the library. The UI is modeled after apps like Sonarr/Radarr with explicit connection tests.

### Setup
1. Open the `Settings` page and scroll to the **Downloads** section.
2. Enable **Automatic downloads** and configure:
   - **Search interval (minutes)**: how often AeroFoil will look for missing updates.
   - **Minimum seeders**: skip torrent results below this count. Leave blank or set `0` to include zero-seeder results.
   - **Required terms**: case-insensitive, comma-separated title filters. **All terms** (the default) requires every term; **Any term** accepts a result containing at least one term. Leave this field blank to avoid title-term filtering.
   - **Blacklist terms**: case-insensitive, comma-separated terms that always exclude a result.
   - **Search prefix / suffix**: optional text added to search queries. Both are blank by default.
   - **Torrent category/tag**: used to tag managed torrent downloads (default `aerofoil`).
3. Configure **Prowlarr**:
   - **Prowlarr URL** (e.g. `http://localhost:9696`)
   - **API Key**
   - **Indexer IDs** (optional, comma separated). If set, AeroFoil will limit searches to these indexers; leave blank to use all enabled Prowlarr indexers.
   - **Categories** (optional, comma separated). Leave blank to search without a Prowlarr category restriction.
   - Use **Test Prowlarr** to validate connectivity and indexer IDs (missing IDs show as warnings).
4. Configure **Torrent Client**:
   - **Client**: multiple clients are supported, including qBittorrent, Transmission, Deluge, rTorrent, and others listed in the Settings UI.
   - **Client URL** and credentials.
   - **Download path** (optional): if set, AeroFoil will warn if it doesn't exist or isn't writable.
   - **Remove finished torrents from client**: disable this to retain completed torrents for seeding.
   - **Use hardlinks instead of copying when seeding**: optional, and only used when completed torrents are retained. AeroFoil attempts a hardlink for each imported file, then safely falls back to copying if hardlinks are unavailable. The torrent client's download path and AeroFoil library path must be on the same share or volume—such as the shared-volume layout commonly used by Unraid Trash Guides setups—for hardlinks to work.
   - Use **Test torrent client** to validate connectivity.
5. Configure **Usenet Client** if you want Prowlarr usenet results to queue automatically:
   - **Client**: multiple usenet clients are supported, including SABnzbd, NZBGet, Download Station, NZBVortex, and others listed in the Settings UI.
   - **Client URL** and **API Key**.
   - **SABnzbd category**: AeroFoil uses this to identify managed usenet downloads.
   - Use **Test usenet client** to validate connectivity.

### Notes
- Prowlarr is used for searching and ranking results; AeroFoil routes each match to the configured torrent or usenet client based on the result protocol.
- Warnings do not block tests; they highlight misconfigurations (e.g. missing indexer IDs or invalid download paths).
- The downloader runs on a schedule and respects the configured interval, skipping runs if the interval has not elapsed.
- Completed downloads are detected by torrent category/tag or SABnzbd category and trigger a library scan + refresh.
- Manual search results include protocol-aware filtering, and pending queue entries can be removed from the downloads page if they become stale.
- Rejected duplicate imports now support two actions in Downloads:
  - `Delete file`: deletes the duplicate file from disk when a concrete local path is available.
  - `Remove`: dismisses the duplicate entry from the list without deleting files.
- The downloads page shows both pending queue state and active client summaries, adjusting torrent-only columns when only usenet activity is present.
- Successfully imported items are removed from the pending queue and no longer shown in Downloads (this page is for active/pending state, not historical completed items).

## Titles configuration
In the `Settings` page under the `Titles` section is where you specify the language of your Remote (currently the same for all users).

This is where you can also upload your `console keys` file to enable content identification using decryption, instead of only using filenames. If you do not provide keys, AeroFoil expects the files to be named `[APP_ID][vVERSION]`.

## Remote customization
In the `Settings` page under the Remote section is where you customize your Remote, including the message displayed when accessing the remote from Tinfoil and whether the remote is private or public.
MOTD supports variables and optional API-backed variables:
- Built-in variables: `{username}`, `{user_id}`, `{is_admin}`, `{shop_access}`, `{backup_access}`, `{frozen}`, `{client_uid}`, `{remote_addr}`, `{user_agent}`, `{host}`, `{path}`, `{date}`, `{time}`, `{datetime}`, `{timestamp}`.
- Optional custom MOTD API URL:
  - Plain text response is exposed as `{api_text}`.
  - JSON object responses expose `{api_<key>}` for each key (for example `{"reason":"..."}` gives `{api_reason}`).
- `Enable MOTD` can disable MOTD output entirely while keeping other remote behavior unchanged.
The encryption option only affects the Tinfoil payload; the web interface and admin UI remain accessible as normal.
Encryption uses the Tinfoil public key and AES, and requires the `pycryptodome` dependency.
`Fast transfer mode` prioritizes throughput for `/api/get_game` by skipping per-chunk transfer accounting; Activity live byte counters and exact transfer bytes may be less precise.
`CyberFoil virtual compressed streaming` controls how CyberFoil receives compressed Switch content:
- Enabled (default): `.nsz`, `.ncz`, and `.xcz` files are streamed as virtual uncompressed `.nsp`, `.nca`, and `.xci` data, so CyberFoil does not need to decompress them after download.
- Disabled: AeroFoil serves the original compressed files unchanged, matching the legacy behavior.

Virtual streams support CyberFoil's single byte-range requests. AeroFoil logs each use as `CyberFoil virtual stream: <source> -> <virtual output>`.
The same section also includes login protection controls: temporary IP lockout after repeated failed auth attempts, a permanent IP/CIDR blacklist, and an admin view to list and unlock current temporary lockouts.

</details>

<a id="deployment-notes"></a>
<details open>
<summary><strong>Deployment notes</strong></summary>

- Recommended volumes: `/games`, `/app/config`, and `/app/data`.
- Optional conversion staging volume: `/app/conversion-tmp` (recommended on SSD when libraries are on slower pools).
- Map port `8465` from the container to any host port you prefer.
- To bootstrap an admin account, set `USER_ADMIN_NAME` and `USER_ADMIN_PASSWORD` when starting the container.
- Optional env var: `AEROFOIL_CONVERSION_STAGING_DIR` (or legacy `OWNFOIL_CONVERSION_STAGING_DIR`) to force a staging path from environment.
- Cache TTL env vars (seconds):
  - `SHOP_SECTIONS_CACHE_TTL_S`: cache for `/api/shop/sections` (use `none`/unset for rebuild-only, `0` to disable caching).
  - `SHOP_SECTIONS_ALL_ITEMS_CAP`: max discovery-section item cap before slicing (default: `300`).
  - `SHOP_SECTIONS_ALL_ITEMS_CAP_NO_TITLEDB`: max discovery-section item cap without TitleDB (default: `120`).
  - `MEDIA_INDEX_TTL_S`: media cache index for icons/banners (use `none`/unset for rebuild-only, `0` to disable caching).
  - `AEROFOIL_TITLES_TOTAL_CACHE_TTL_S` (legacy `OWNFOIL_TITLES_TOTAL_CACHE_TTL_S`): `/api/titles` total-count cache TTL (default: `300`).
  - `AEROFOIL_TITLES_TOTAL_CACHE_MAX_ENTRIES` (legacy `OWNFOIL_TITLES_TOTAL_CACHE_MAX_ENTRIES`): `/api/titles` total-count cache capacity (default: `256`, clamped to `16..4096`).
- Update the container with `docker pull luketanti/aerofoil:latest` and restart it.

## Reverse proxy: real client IP (Activity page)
If you run AeroFoil behind a reverse proxy (e.g. Nginx Proxy Manager), AeroFoil will only trust `X-Forwarded-For` when explicitly configured.

You can set this via `settings.yaml` or with environment variables (`AEROFOIL_TRUST_PROXY_HEADERS` and `AEROFOIL_TRUSTED_PROXIES`).

In `config/settings.yaml`:
```yaml
security:
  trust_proxy_headers: true
  trusted_proxies:
    - 172.16.0.0/12
    - 192.168.0.0/16
```

Set `trusted_proxies` to your proxy IP(s) and/or your Docker network subnet so the Activity page shows the WAN/client IP instead of the proxy's LAN IP.

## TitleDB sources and downloads
- TitleDB artifacts are downloaded separately from the metadata dataset.
- The descriptions/screenshot dataset (`US.en.json`) is downloaded to `/app/data/titledb/US.en.json` and is not part of the TitleDB artifacts zip.
- The TitleDB artifacts zip may be very large (multi-GB) depending on the upstream workflow output.

</details>

<a id="roadmap"></a>
<details open>
<summary><strong>Roadmap</strong></summary>

Planned feature, in no particular order.
 - Library browser:
    - [x] Add "details" view for every content, to display versions etc
 - Library management:
    - [x] Rename and organize library after content identification
    - [x] Delete older updates
    - [x] Automatic nsp/xci -> nsz conversion
 - Remote customization:
    - [x] Encrypt remote
 - Saves manager:
    - [ ] Automatically discover Switch device based on Tinfoil connection
    - [x] Per-user save backup storage and access control (Backup flag required)
    - [x] Multiple backup versions per title (timestamp + note)
    - [x] Download/delete save backups from both CyberFoil and AeroFoil web UI
 - External services:
    - [x] Prowlarr integration for automatic update downloads (via torrent and usenet clients)
    - [x] Automated update downloader pipeline (search -> download -> ingest)

</details>
