#!/usr/bin/env bash
# Prepare the BLE environment and launch the Raspberry Pi digital key server.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$PROJECT_ROOT/logs"
LOG_FILE="$LOG_DIR/ble-server.log"
ENV_DIR="$HOME/dk-ble-env"
ADAPTER_MAC="${VEHICLE_ADAPTER_MAC:-}"
ENV_FILE="$PROJECT_ROOT/.env"
RUN_SERVER=1
SERVER_ARGS=()
PAIR_AGENT_PID=""
SERVER_PID=""

log() {
  printf '[init-vehicle] %s\n' "$*"
}

usage() {
  cat <<'USAGE'
Usage: init_vehicle.sh [options] [-- <additional python args>]
Options:
  --env PATH        Override virtualenv location (default: ~/dk-ble-env)
  --adapter MAC     Override Bluetooth adapter MAC (overrides VEHICLE_ADAPTER_MAC)
  --adapter-index N Override btmgmt adapter index (default: 0 or VEHICLE_ADAPTER_INDEX)
  --no-server       Only prepare the environment, do not start the BLE server
  -h, --help        Show this help message
USAGE
}

ADAPTER_INDEX="${VEHICLE_ADAPTER_INDEX:-0}"
SERVER_SCRIPT="$PROJECT_ROOT/scripts/run_vehicle.py"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env)
      ENV_DIR="$2"
      shift 2
      ;;
    --adapter)
      ADAPTER_MAC="$2"
      shift 2
      ;;
    --adapter-index)
      ADAPTER_INDEX="$2"
      shift 2
      ;;
    --no-server)
      RUN_SERVER=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      SERVER_ARGS+=("$@")
      break
      ;;
    *)
      SERVER_ARGS+=("$1")
      shift
      ;;
  esac
done

mkdir -p "$LOG_DIR"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

"$PROJECT_ROOT/scripts/setup_ble_env.sh" "$ENV_DIR"

if [[ "$RUN_SERVER" -ne 1 ]]; then
  exit 0
fi

ensure_discoverable() {
  if ! command -v bluetoothctl >/dev/null 2>&1; then
    return
  fi
  bluetoothctl <<'EOF' >/dev/null
discoverable-timeout 0
pairable on
discoverable on
EOF
  log "bluetoothctl discoverable/pairable enabled (timeout=0)"
}

disable_adapter_advertising() {
  if ! command -v bluetoothctl >/dev/null 2>&1; then
    return
  fi
  bluetoothctl <<'EOF' >/dev/null
advertise off
EOF
  log "bluetoothctl advertising disabled (handled by service)"
}

disconnect_connected_devices() {
  if ! command -v bluetoothctl >/dev/null 2>&1; then
    return
  fi
  local addr
  while read -r _ addr _; do
    if [[ -n "$addr" ]]; then
      bluetoothctl disconnect "$addr" >/dev/null 2>&1 || true
      log "Disconnected device $addr"
    fi
  done < <(bluetoothctl devices Connected 2>/dev/null || true)
}

clear_stuck_advertisements() {
  if command -v btmgmt >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    for handle in 0 1 2 3 4 5; do
      printf 'remove-advertisement %s\nquit\n' "$handle" | sudo -n btmgmt --index "$ADAPTER_INDEX" >/dev/null 2>&1 || true
    done
  fi
}

reset_advertising_handles() {
  if command -v btmgmt >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    clear_stuck_advertisements
    sudo -n btmgmt --index "$ADAPTER_INDEX" advertising off >/dev/null 2>&1 || true
    sudo -n btmgmt --index "$ADAPTER_INDEX" advertising on >/dev/null 2>&1 || true
    log "btmgmt advertising reset (index=${ADAPTER_INDEX})"
    return
  fi
  if command -v bluetoothctl >/dev/null 2>&1; then
    bluetoothctl <<'EOF' >/dev/null
advertise off
advertise on
EOF
    log "bluetoothctl advertising toggled"
  fi
}

start_pairing_agent() {
  local agent_path="$PROJECT_ROOT/scripts/auto_pair_agent.py"
  if [[ ! -f "$agent_path" ]]; then
    return
  fi
  if sudo -n true 2>/dev/null; then
    sudo -n pkill -f auto_pair_agent.py >/dev/null 2>&1 || true
    sudo -n python3 -u "$agent_path" >/tmp/auto-pair-agent.log 2>&1 &
    PAIR_AGENT_PID=$!
    log "auto pair agent started (log: /tmp/auto-pair-agent.log, pid=$PAIR_AGENT_PID)"
  else
    log "sudo privileges required to auto-approve BLE pairing requests"
  fi
}

cleanup_agents() {
  if [[ -n "$PAIR_AGENT_PID" ]]; then
    sudo -n pkill -f auto_pair_agent.py >/dev/null 2>&1 || true
    PAIR_AGENT_PID=""
  fi
}

stop_ble_server() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    log "Stopping BLE server (pid=$SERVER_PID)"
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  SERVER_PID=""
}

on_exit() {
  stop_ble_server
  cleanup_agents
}

on_signal() {
  local signame="$1"
  log "Signal received (${signame}); shutting down BLE server"
  stop_ble_server
  exit 0
}

trap on_exit EXIT
trap 'on_signal SIGINT' SIGINT
trap 'on_signal SIGTERM' SIGTERM

stop_existing_server() {
  local existing
  if existing=$(pgrep -f "$SERVER_SCRIPT"); then
    log "Existing BLE server detected (pids: $existing); stopping"
    # shellcheck disable=SC2086
    kill $existing >/dev/null 2>&1 || true
    # shellcheck disable=SC2086
    wait $existing >/dev/null 2>&1 || true
    log "Existing BLE server processes terminated"
  fi
}

wait_for_advertisement() {
  local attempts=12
  local log_snapshot
  log_snapshot=$(mktemp)
  tail -n 0 "$LOG_FILE" >"$log_snapshot"
  while (( attempts-- > 0 )); do
    if busctl tree org.bluez 2>/dev/null | grep -q "/org/bluez/hci0/advertising"; then
      log "BLE advertisement registered (dbus)"
      rm -f "$log_snapshot"
      return 0
    fi
    if grep -q "Advertisement registered" "$LOG_FILE"; then
      log "BLE advertisement registered (log)"
      rm -f "$log_snapshot"
      return 0
    fi
    sleep 1
  done
  rm -f "$log_snapshot"
  log "BLE advertisement not visible after timeout"
  return 1
}

PYTHON_BIN="$ENV_DIR/bin/python"
export PYTHONPATH="$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONUNBUFFERED=1

CMD=("$PYTHON_BIN" "$SERVER_SCRIPT")

if [[ -n "$ADAPTER_MAC" ]]; then
  CMD+=("$ADAPTER_MAC")
fi

if [[ ${#SERVER_ARGS[@]} -gt 0 ]]; then
  CMD+=("${SERVER_ARGS[@]}")
fi

if command -v stdbuf >/dev/null 2>&1; then
  CMD=("stdbuf" "-oL" "-eL" "${CMD[@]}")
fi

start_ble_server() {
  log "Starting BLE server with: ${CMD[*]}"
  log "BLE log: $LOG_FILE"
  "${CMD[@]}" >>"$LOG_FILE" 2>&1 &
  SERVER_PID=$!
  log "BLE server launched (pid=$SERVER_PID)"
}

restart_bluetoothd() {
  if command -v systemctl >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    log "Restarting bluetooth service"
    sudo -n systemctl restart bluetooth >/dev/null 2>&1 || log "Failed to restart bluetooth service"
    # allow time for bluetoothd to settle
    sleep 2
  else
    log "Cannot restart bluetooth service automatically (missing sudo or systemctl)"
  fi
}

stop_existing_server
disconnect_connected_devices
reset_advertising_handles
ensure_discoverable
disable_adapter_advertising
start_pairing_agent

MAX_ATTEMPTS=3
attempt=1
success=0

while (( attempt <= MAX_ATTEMPTS )); do
  start_ble_server
  if wait_for_advertisement; then
    success=1
    break
  fi
  log "BLE advertisement not visible after startup attempt ${attempt}"
  stop_ble_server
  if (( attempt == 1 )); then
    restart_bluetoothd
    reset_advertising_handles
    ensure_discoverable
    disable_adapter_advertising
    disconnect_connected_devices
  fi
  ((attempt++))
done

if (( success == 0 )); then
  log "Failed to launch BLE server after ${MAX_ATTEMPTS} attempts"
  exit 1
fi

wait "$SERVER_PID" && EXIT_CODE=$? || EXIT_CODE=$?
SERVER_PID=""
exit "$EXIT_CODE"
