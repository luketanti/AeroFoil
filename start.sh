#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  ./start.sh [--admin-user <username>] [--admin-password <password>] [--flask-key <secret>]

Options:
  --admin-user       Admin username (default: admin)
  --admin-password   Admin password (default: admin)
  --flask-key        Flask secret key (default: MyyR9E6O9mAeJMUTtsBgLxbuY9OZdT742psExUsnPnT72veQ7rnPkAdhiDNihNR_KPvCj5K85DgL0Rmo4hUiSQj)
  -h, --help         Show this help

Notes:
  - This script starts app/app.py directly.
USAGE
}

ADMIN_USER="admin"
ADMIN_PASSWORD="admin"
FLASK_KEY="MyyR9E6O9mAeJMUTtsBgLxbuY9OZdT742psExUsnPnT72veQ7rnPkAdhiDNihNR_KPvCj5K85DgL0Rmo4hUiSQj"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin-user)
      [[ $# -ge 2 ]] || { echo "Missing value for --admin-user" >&2; usage; exit 1; }
      ADMIN_USER="$2"
      shift 2
      ;;
    --admin-password)
      [[ $# -ge 2 ]] || { echo "Missing value for --admin-password" >&2; usage; exit 1; }
      ADMIN_PASSWORD="$2"
      shift 2
      ;;
    --flask-key)
      [[ $# -ge 2 ]] || { echo "Missing value for --flask-key" >&2; usage; exit 1; }
      FLASK_KEY="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

export USER_ADMIN_NAME="$ADMIN_USER"
export USER_ADMIN_PASSWORD="$ADMIN_PASSWORD"
export OWNFOIL_SECRET_KEY="$FLASK_KEY"

exec python app/app.py
