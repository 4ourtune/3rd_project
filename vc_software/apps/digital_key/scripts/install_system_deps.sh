#!/usr/bin/env bash
# Install system-level packages required by the digital_key BLE stack.
set -euo pipefail

REQUIRED_PACKAGES=(
  python3
  python3-venv
  python3-dbus
  python3-gi
  gir1.2-glib-2.0
  libgirepository1.0-dev # required for GObject introspection/pycairo build
  libcairo2              # runtime library for pycairo
  libcairo2-dev          # pycairo build dependency
  pkg-config             # used by pycairo's build tooling
  libdbus-1-dev          # dbus-python build dependency
  bluez
  bluez-tools
  bluetooth
)

SUDOERS_USER="${DIGITAL_KEY_SUDOERS_USER:-pi}"
SKIP_SUDOERS="${SKIP_DIGITAL_KEY_SUDOERS:-0}"
SUDOERS_SNIPPET="/etc/sudoers.d/digital_key"

log() {
  printf '[install-system-deps] %s\n' "$1"
}

run_as_root() {
  if [[ $EUID -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      sudo "$@"
    else
      log "sudo가 필요하지만 찾을 수 없습니다. root 사용자로 다시 실행하세요."
      exit 1
    fi
  else
    "$@"
  fi
}

log "Updating apt package index"
run_as_root apt-get update -y

log "Installing required packages: ${REQUIRED_PACKAGES[*]}"
run_as_root apt-get install -y "${REQUIRED_PACKAGES[@]}"

log "Enabling bluetooth service"
run_as_root systemctl enable --now bluetooth.service

configure_sudoers() {
  local user="$1"
  local snippet="$2"
  if [[ -z "$user" ]]; then
    log "Skipping sudoers update (no user specified)"
    return
  fi

  local content="$user ALL=(ALL) NOPASSWD: /usr/bin/btmgmt, /usr/bin/bluetoothctl"

  if run_as_root test -f "$snippet"; then
    if run_as_root grep -qF "$content" "$snippet"; then
      log "Sudoers snippet already up to date for user $user"
      return
    fi
  fi

  log "Configuring passwordless sudo for btmgmt/bluetoothctl (user=$user)"
  run_as_root bash -c "cat <<'EOF' > \"$snippet\"
$content
EOF"
  run_as_root chmod 440 "$snippet"
  if command -v visudo >/dev/null 2>&1; then
    run_as_root visudo -cf "$snippet"
  fi
}

if [[ "$SKIP_SUDOERS" != "1" ]]; then
  configure_sudoers "$SUDOERS_USER" "$SUDOERS_SNIPPET"
else
  log "Skipping sudoers snippet creation (SKIP_DIGITAL_KEY_SUDOERS=1)"
  log "Manual snippet:\n  echo \"$SUDOERS_USER ALL=(ALL) NOPASSWD: /usr/bin/btmgmt, /usr/bin/bluetoothctl\" | sudo tee $SUDOERS_SNIPPET"
fi

log "System dependencies installed. Reboot 후 bluetooth 상태를 확인하세요."
