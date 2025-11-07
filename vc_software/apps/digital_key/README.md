# digital_key Service

Lightweight BLE digital key prototype for Raspberry Pi. Key entry points:

- `scripts/install_system_deps.sh`: install BlueZ/DBus prerequisites and create the sudoers snippet (`pi ALL=(ALL) NOPASSWD: /usr/bin/btmgmt, /usr/bin/bluetoothctl`). Override the target user with `DIGITAL_KEY_SUDOERS_USER=<user>` or skip with `SKIP_DIGITAL_KEY_SUDOERS=1`.
- `scripts/setup_ble_env.sh`: create/update the Python virtualenv used for BLE services.
- `scripts/init_vehicle.sh`: bootstrap environment, auto-approve pairing, and launch the BLE peripheral.
- `digital_key/vehicle_ble.py`: BLE server implementation.

Runtime artifacts (logs, session exports) are written into `logs/` and cache data lives in `~/.cache/dks`.
