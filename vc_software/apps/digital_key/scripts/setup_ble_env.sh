#!/usr/bin/env bash
# Bootstrap or update the BLE virtual environment used by the digital_key project.
set -euo pipefail

ENV_DIR="${1:-$HOME/dk-ble-env}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

log() {
  printf '[setup-ble-env] %s\n' "$1"
}

if [ ! -d "$ENV_DIR" ]; then
  log "Creating virtualenv at $ENV_DIR"
  "$PYTHON_BIN" -m venv "$ENV_DIR"
else
  log "Using existing virtualenv at $ENV_DIR"
fi

log "Upgrading pip/setuptools"
"$ENV_DIR/bin/python" -m pip --disable-pip-version-check install --upgrade --quiet pip setuptools

log "Installing BLE dependencies"
"$ENV_DIR/bin/python" -m pip --disable-pip-version-check install --upgrade --quiet \
  bluezero requests python-dotenv cryptography dbus-python

log "Verifying bluezero import"
"$ENV_DIR/bin/python" - <<'PY'
import sys
try:
    import bluezero
except ImportError as exc:
    print(f'bluezero import failed: {exc}', file=sys.stderr)
    sys.exit(1)
version = getattr(bluezero, "__version__", "unknown")
print(f'bluezero ready (version {version})')
PY

log "Done. Activate with: source $ENV_DIR/bin/activate"
