# AeroFoil

[![Latest Release](https://img.shields.io/docker/v/luketanti/aerofoil?sort=semver)](https://github.com/luketanti/aerofoil/releases/latest)
[![Docker Pulls](https://img.shields.io/docker/pulls/luketanti/aerofoil)](https://hub.docker.com/r/luketanti/aerofoil)
[![Docker Image Size](https://img.shields.io/docker/image-size/luketanti/aerofoil/latest?arch=amd64)](https://hub.docker.com/r/luketanti/aerofoil/tags)
![Platforms](https://img.shields.io/badge/platforms-amd64%20%7C%20arm64-8A2BE2)
[![Discord](https://img.shields.io/badge/Discord-Join%20Server-5865F2?logo=discord&logoColor=white)](https://discord.gg/gGy7hWxJeP)


AeroFoil is a Personal library manager that turns your library into a fully customizable, self-hosted Shop. The goal of this project is to manage your library, identify any missing content (DLCs or updates) and provide a user friendly way to browse your content. Some of the features include:

 - multi user authentication
 - web interface for configuration
 - web interface for browsing the library
 - content identification
 - shop customization

The project is still in development, expect things to break or change without notice.

# Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Roadmap](#roadmap)

# Installation
## Using Docker
### Docker run

Running this command will start the shop on port `8465` with the library in `/your/game/directory`:

    docker run -d -p 8465:8465 \
      -v /your/game/directory:/games \
      -v /your/config/directory:/app/config \
      -v /your/data/directory:/app/data \
      --name aerofoil \
      luketanti/aerofoil:latest

The shop is now accessible with your computer/server IP and port, i.e. `http://localhost:8465` from the same computer or `http://192.168.1.100:8465` from a device in your network.

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
    ports:
      - "8465:8465"
```
> [!NOTE]
> You can control the `UID` and `GID` of the user running the app in the container with the `PUID` and `PGID` environment variables. By default the user is created with `1000:1000`. If you want to have the same ownership for mounted directories, you need to set those variables with the UID and GID returned by the `id` command.

You can then create and start the container with the command (executed in the same directory as the docker-compose file):

    docker-compose up -d

This is usefull if you don't want to remember the `docker run` command and have a persistent and reproductible container configuration.

## Environment variables
New `AEROFOIL_*` variables are preferred. Legacy `OWNFOIL_*` names are still accepted for backward compatibility.

- `PUID` / `PGID`: control the user ID/group ID inside the container (default `1000:1000`).
- `USER_ADMIN_NAME` / `USER_ADMIN_PASSWORD`: create or update an admin user at startup (default: unset).
- `USER_GUEST_NAME` / `USER_GUEST_PASSWORD`: create or update a regular user at startup (default: unset).
- `AEROFOIL_SECRET_KEY`: Flask secret key used for sessions/cookies. Recommended to set a long random value in production (default: auto-generated at startup).
- `AEROFOIL_TRUST_PROXY_HEADERS`: enable trusting `X-Forwarded-For` when the proxy is in the trusted list (`true`/`false`, default: `false`).
- `AEROFOIL_TRUSTED_PROXIES`: comma-separated proxy IPs/CIDRs (default: empty), for example `172.16.0.0/12,192.168.0.0/16`.
- `SHOP_SECTIONS_CACHE_TTL_S`: cache TTL for `/api/shop/sections` (seconds). Use `none`/unset for rebuild-only (default), `0` to disable caching. Recommended: `none` for stable libraries, or `600`-`900` for periodic refresh.
- `MEDIA_INDEX_TTL_S`: cache TTL for icon/banner media index (seconds). Use `none`/unset for rebuild-only (default), `0` to disable caching. Recommended: `none` or `600`-`900`.
- `AEROFOIL_HOST`: bind host for the web server (default: `0.0.0.0`).
- `AEROFOIL_PORT`: bind port for the web server (default: `8465`).
- `AEROFOIL_WSGI_THREADS`: Waitress worker thread count (default: `32`).
- `AEROFOIL_WSGI_CONNECTION_LIMIT`: max concurrent Waitress channels (default: `1000`).
- `AEROFOIL_WSGI_CHANNEL_TIMEOUT_S`: idle channel timeout in seconds (default: `120`).
- `AEROFOIL_WSGI_CLEANUP_INTERVAL_S`: Waitress cleanup interval in seconds (default: `30`).
- `AEROFOIL_USE_FLASK_DEV`: set to `true`/`1` to force Flask dev server instead of Waitress.

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
In CyberFoil, set the AeroFoil eShop URL in Settings:
 - URL: `http://<server-ip>:8465` (or `https://` if using an SSL-enabled reverse proxy)
 - Username: username as created in AeroFoil settings (if the shop is Private)
 - Password: password as created in AeroFoil settings (if the shop is Private)

## Save backups (Save Sync)
AeroFoil supports per-user save backup management when the user has the **Backup** flag enabled:
- Save archives are stored per user under `data/saves/<username>/`.
- Multiple backup versions per title are supported.
- Each uploaded version can include a note.
- Backups can be downloaded or deleted from:
  - CyberFoil `Saves` section (upload/download/delete),
  - AeroFoil web page `Saves Files` (download/delete).

Save sync API endpoints:
- `GET /api/saves/list`
- `POST /api/saves/upload/<title_id>`
- `GET /api/saves/download/<title_id>/<save_id>.zip`
- `DELETE /api/saves/delete/<title_id>/<save_id>` (also accepts `POST` for compatibility)

# Usage
Once AeroFoil is running you can access the Shop Web UI by navigating to the `http://<computer/server IP>:8465`.

## User administration
AeroFoil requires an `admin` user to be created to enable Authentication for your Shop. Go to the `Settings` to create a first user that will have admin rights. Then you can add more users to your shop the same way.

## Library administration
In the `Settings` page under the `Library` section, you can add directories containing your content. You can then manually trigger the library scan: AeroFoil will scan the content of the directories and try to identify every supported file (currently `nsp`, `nsz`, `xci`, `xcz`).
There is watchdog in place for all your added directories: files moved, renamed, added or removed will be reflected directly in your library.

## Library management
In the `Manage` page, you can organize your library structure, delete older update files, and convert `nsp`/`xci` to `nsz`.

## Library browser UI
- Card view: the Base/Update/DLC status icons are displayed above the action buttons.
- Icon view: the `Game info` button is shown as an overlay on the game tile.

## Game info (TitleDB)
The `Game info` modal uses TitleDB metadata (not Nintendo website scraping):
- `description`: shown as the game summary.
- `screenshots`: displayed in a grid; click a screenshot to open it larger.

AeroFoil will download the TitleDB descriptions/screenshot dataset on demand to `./data/titledb/US.en.json` (Docker path: `/app/data/titledb/US.en.json`).

> [!NOTE]
> On first boot, game titles may temporarily appear as `Unrecognized` while TitleDB is being downloaded in the background.
> Once the download finishes, refresh the page and names/metadata will appear.

Conversion details:
- Uses the installed Python `nsz` package (with progress output).
- Uses the same `keys.txt` uploaded in the `Settings` page.
- Shows live status, per-file progress, and the current filename.
- Filters out files smaller than 50 MB from the manual conversion dropdown.
- The `Verbose` checkbox shows detailed task output; otherwise the task output stays clean.

## Automatic update downloads (Prowlarr + Torrent Client)
AeroFoil can automatically search for missing updates using Prowlarr, send matches to a torrent client (qBittorrent or Transmission), and ingest completed downloads back into the library. The UI is modeled after apps like Sonarr/Radarr with explicit connection tests.

### Setup
1. Open the `Settings` page and scroll to the **Downloads** section.
2. Enable **Automatic downloads** and configure:
   - **Search interval (minutes)**: how often AeroFoil will look for missing updates.
   - **Minimum seeders**: skip low‑availability results.
   - **Required terms / Blacklist terms**: fine‑tune search matches (comma separated).
   - **Torrent category/tag**: used to tag downloads in the client (default `aerofoil`).
3. Configure **Prowlarr**:
   - **Prowlarr URL** (e.g. `http://localhost:9696`)
   - **API Key**
   - **Indexer IDs** (optional, comma separated). If set, AeroFoil will limit searches to these indexers.
   - Use **Test Prowlarr** to validate connectivity and indexer IDs (missing IDs show as warnings).
4. Configure **Torrent Client**:
   - **Client**: qBittorrent or Transmission.
   - **Client URL** and credentials.
   - **Download path** (optional): if set, AeroFoil will warn if it doesn't exist or isn't writable.
   - Use **Test torrent client** to validate connectivity.

### Notes
- Prowlarr is used for searching and ranking results; the torrent client handles the actual downloads.
- Warnings do not block tests; they highlight misconfigurations (e.g. missing indexer IDs or invalid download paths).
- The downloader runs on a schedule and respects the configured interval, skipping runs if the interval has not elapsed.
- Completed downloads are detected by category/tag and trigger a library scan + refresh.

## Titles configuration
In the `Settings` page under the `Titles` section is where you specify the language of your Shop (currently the same for all users).

This is where you can also upload your `console keys` file to enable content identification using decryption, instead of only using filenames. If you do not provide keys, AeroFoil expects the files to be named `[APP_ID][vVERSION]`.

## Shop customization
In the `Settings` page under the `Shop` section is where you customize your Shop, like the message displayed when successfully accessing the shop from Tinfoil or if the shop is private or public.
The `Encrypt shop` option only affects the Tinfoil payload; the web interface and admin UI remain accessible as normal.
Encryption uses the Tinfoil public key and AES, and requires the `pycryptodome` dependency.
`Fast transfer mode` prioritizes throughput for `/api/get_game` by skipping per-chunk transfer accounting; Activity live byte counters and exact transfer bytes may be less precise.
The same section also includes login protection controls: temporary IP lockout after repeated failed auth attempts, a permanent IP/CIDR blacklist, and an admin view to list and unlock current temporary lockouts.

# Deployment notes
- Recommended volumes: `/games`, `/app/config`, and `/app/data`.
- Map port `8465` from the container to any host port you prefer.
- To bootstrap an admin account, set `USER_ADMIN_NAME` and `USER_ADMIN_PASSWORD` when starting the container.
- Cache TTL env vars (seconds):
  - `SHOP_SECTIONS_CACHE_TTL_S`: cache for `/api/shop/sections` (use `none`/unset for rebuild-only, `0` to disable caching).
  - `MEDIA_INDEX_TTL_S`: media cache index for icons/banners (use `none`/unset for rebuild-only, `0` to disable caching).
- Update the container with `docker pull luketanti/aerofoil:latest` and restart it.

## Reverse proxy: real client IP (Activity page)
If you run AeroFoil behind a reverse proxy (e.g. Nginx Proxy Manager), AeroFoil will only trust `X-Forwarded-For` when explicitly configured.

You can set this via `settings.yaml` or with environment variables (`AEROFOIL_TRUST_PROXY_HEADERS` and `AEROFOIL_TRUSTED_PROXIES`).

In `config/settings.json`:
```json
{
  "security": {
    "trust_proxy_headers": true,
    "trusted_proxies": ["172.16.0.0/12", "192.168.0.0/16"]
  }
}
```

Set `trusted_proxies` to your proxy IP(s) and/or your Docker network subnet so the Activity page shows the WAN/client IP instead of the proxy's LAN IP.

## TitleDB sources and downloads
- TitleDB artifacts are downloaded separately from the metadata dataset.
- The descriptions/screenshot dataset (`US.en.json`) is downloaded to `/app/data/titledb/US.en.json` and is not part of the TitleDB artifacts zip.
- The TitleDB artifacts zip may be very large (multi-GB) depending on the upstream workflow output.

# Roadmap
Planned feature, in no particular order.
 - Library browser:
    - [x] Add "details" view for every content, to display versions etc
 - Library management:
    - [x] Rename and organize library after content identification
    - [x] Delete older updates
    - [x] Automatic nsp/xci -> nsz conversion
 - Shop customization:
    - [x] Encrypt shop
 - Saves manager:
    - [ ] Automatically discover Switch device based on Tinfoil connection
    - [x] Per-user save backup storage and access control (Backup flag required)
    - [x] Multiple backup versions per title (timestamp + note)
    - [x] Download/delete save backups from both CyberFoil and AeroFoil web UI
 - External services:
    - [x] Prowlarr integration for automatic update downloads (via torrent client)
    - [x] Automated update downloader pipeline (search -> download -> ingest)


