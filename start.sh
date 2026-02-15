#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  ./start.sh [--admin-user <username>] [--admin-password <password>] [--flask-key <secret>]

Options:
  --admin-user       Admin username (default: admin)
  --admin-password   Admin password (default: (prompted if TTY, else required))
  --flask-key        Flask secret key (default: auto-generated + persisted)
  -h, --help         Show this help

Notes:
  - This script starts app/app.py directly.
  - If --flask-key is not provided, a key is generated and saved to .aerofoil_secret_key (chmod 600).
  - Passing --admin-password on the command line may expose it via shell history / process list.
    Prefer omitting it and entering it at the prompt when possible.
USAGE
}

ADMIN_USER="admin"
ADMIN_PASSWORD=""
FLASK_KEY=""

# Where to persist the generated Flask/Aerofoil secret key
KEY_FILE=".aerofoil_secret_key"

prompt_password() {
  local pw1 pw2
  # -s: silent, -r: don't treat backslashes specially
  read -r -s -p "Admin password: " pw1
  echo
  read -r -s -p "Confirm password: " pw2
  echo
  if [[ "$pw1" != "$pw2" ]]; then
    echo "Passwords do not match." >&2
    exit 1
  fi
  if [[ -z "$pw1" ]]; then
    echo "Password cannot be empty." >&2
    exit 1
  fi
  ADMIN_PASSWORD="$pw1"
}

generate_secret_key() {
  # Prefer openssl if available; otherwise fallback to python.
  if command -v openssl >/dev/null 2>&1; then
    # 32 bytes => 64 hex chars
    openssl rand -hex 32
  elif command -v python >/dev/null 2>&1; then
    python - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
  elif command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
  else
    echo "Could not generate a secret key: need openssl or python/python3." >&2
    exit 1
  fi
}

load_or_create_secret_key() {
  # If user supplied one, use it (do not persist unless you want to—keeping behavior simple).
  if [[ -n "${FLASK_KEY}" ]]; then
    return 0
  fi

  # If key file exists, read it safely.
  if [[ -f "$KEY_FILE" ]]; then
    # Trim whitespace/newlines defensively
    FLASK_KEY="$(tr -d ' \t\r\n' < "$KEY_FILE" || true)"
    if [[ -n "$FLASK_KEY" ]]; then
      return 0
    fi
    echo "Warning: $KEY_FILE exists but is empty; regenerating." >&2
  fi

  # Generate and persist.
  FLASK_KEY="$(generate_secret_key)"
  umask 077
  printf '%s' "$FLASK_KEY" > "$KEY_FILE"
  chmod 600 "$KEY_FILE" 2>/dev/null || true
  echo "Generated and persisted Flask/Aerofoil secret key in $KEY_FILE."
}

# --- Arg parsing (same UX) ---
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

# --- Safer defaults ---
# Admin password:
# - If provided via CLI, accept it (but note: not ideal).
# - If not provided:
#   - If interactive (TTY), prompt securely.
#   - If non-interactive, require USER_ADMIN_PASSWORD env var or CLI.
if [[ -z "${ADMIN_PASSWORD}" ]]; then
  if [[ -t 0 ]]; then
    prompt_password
  else
    # Non-interactive: allow env var as an alternative
    if [[ -n "${USER_ADMIN_PASSWORD:-}" ]]; then
      ADMIN_PASSWORD="${USER_ADMIN_PASSWORD}"
    else
      echo "Admin password not provided. In non-interactive mode, set --admin-password or USER_ADMIN_PASSWORD." >&2
      exit 1
    fi
  fi
fi

# Secret key:
# - If not provided, reuse from file or generate + persist.
load_or_create_secret_key

# Export vars for the app
export USER_ADMIN_NAME="$ADMIN_USER"
export USER_ADMIN_PASSWORD="$ADMIN_PASSWORD"
export AEROFOIL_SECRET_KEY="$FLASK_KEY"

exec python app/app.py