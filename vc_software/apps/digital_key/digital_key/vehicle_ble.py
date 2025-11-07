"""Digital Key BLE peripheral skeleton for Raspberry Pi."""
from __future__ import annotations

import atexit
import logging
import os
import signal
import sys
import time
from typing import Any, Dict

from bluezero import adapter, peripheral

from .certificates import build_static_provider_from_env
from .chunks import CommandChunkAssembler
from .command_handler import CommandHandler
from .config import ensure_runtime_dirs
from .key_store import KeyStore
from .pairing import PairingManager
from .pairing_client import build_client

LOGGER = logging.getLogger(__name__)

DIGITAL_KEY_SERVICE_UUID = "12345678-1234-1234-1234-123456789abc"
COMMAND_CHARACTERISTIC_UUID = "87654321-4321-4321-4321-cba987654321"
PAIRING_CHALLENGE_UUID = "87654321-4321-4321-4321-cba987654322"
PAIRING_RESULT_UUID = "87654321-4321-4321-4321-cba987654323"

SERVICE_ID = 1
PAIRING_CHALLENGE_ID = 1
PAIRING_RESULT_ID = 2
COMMAND_CHAR_ID = 3

LOCAL_NAME = os.environ.get("VEHICLE_LOCAL_NAME", "Raspberry Pi Vehicle")


def _json_to_dbus_bytes(data: Dict[str, Any]) -> list[int]:
    return list(PairingManager.encode_payload(data))


def _bytes_to_json(raw: list[int]) -> Dict[str, Any]:
    return PairingManager.decode_payload(bytes(raw))


class VehicleBleServer:
    """Wrap bluezero peripheral setup for the digital key service."""

    def __init__(self, adapter_address: str) -> None:
        self.key_store = KeyStore()
        self.pairing_manager = PairingManager(self.key_store, api_client=build_client())
        self.certificate_provider = build_static_provider_from_env()
        if self.certificate_provider is None:
            LOGGER.info("Certificate provider unavailable; cert_request will be rejected")
        self.command_handler = CommandHandler(
            self.key_store,
            certificate_provider=self.certificate_provider,
            pairing_manager=self.pairing_manager,
        )
        self.pairing_manager.register_session_observer(self._on_pin_session_update)
        self._last_command_response: list[int] = _json_to_dbus_bytes(
            {"success": True, "command": "INIT"}
        )
        self._command_notify_enabled = False
        self._command_read_available = True
        self.peripheral = peripheral.Peripheral(
            adapter_address=adapter_address,
            local_name=LOCAL_NAME,
        )
        self.command_char = None
        self.pairing_challenge_char = None
        self.pairing_result_char = None
        ensure_runtime_dirs()
        self._chunk_assembler = CommandChunkAssembler()
        self._pairing_result_assembler = CommandChunkAssembler()
        self._setup_services()
        self._is_shutting_down = False

    # Setup --------------------------------------------------------------
    def _setup_services(self) -> None:
        self.peripheral.add_service(SERVICE_ID, DIGITAL_KEY_SERVICE_UUID, True)

        # Pairing challenge characteristic (Read)
        initial_challenge = (
            {
                "status": "READY",
                "message": "Awaiting pairing challenge read",
            }
            if self.pairing_manager.is_pairing_allowed()
            else {
                "status": "DISABLED",
                "message": "Pairing not enabled",
            }
        )

        self.peripheral.add_characteristic(
            SERVICE_ID,
            PAIRING_CHALLENGE_ID,
            PAIRING_CHALLENGE_UUID,
            value=_json_to_dbus_bytes(initial_challenge),
            notifying=False,
            flags=["read", "encrypt-read"],
            read_callback=self._on_pairing_challenge_read,
        )
        self.pairing_challenge_char = self.peripheral.characteristics[-1]

        # Pairing result characteristic (Write/Notify)
        self.peripheral.add_characteristic(
            SERVICE_ID,
            PAIRING_RESULT_ID,
            PAIRING_RESULT_UUID,
            value=_json_to_dbus_bytes({"status": "INIT"}),
            notifying=False,
            flags=["write", "write-without-response", "notify", "encrypt-write"],
            write_callback=self._on_pairing_result_write,
        )
        self.pairing_result_char = self.peripheral.characteristics[-1]

        # Command characteristic (Write/Notify)
        self.peripheral.add_characteristic(
            SERVICE_ID,
            COMMAND_CHAR_ID,
            COMMAND_CHARACTERISTIC_UUID,
            value=_json_to_dbus_bytes({"success": True, "command": "INIT"}),
            notifying=False,
            flags=["read", "write", "notify", "encrypt-read", "encrypt-write"],
            read_callback=self._on_command_read,
            write_callback=self._on_command_write,
            notify_callback=self._on_command_notify_state,
        )
        self.command_char = self.peripheral.characteristics[-1]

    # Characteristic callbacks ------------------------------------------
    def _on_pairing_challenge_read(self, _options: Dict[str, Any]) -> list[int]:
        challenge = self.pairing_manager.build_challenge()
        LOGGER.info("Serving pairing challenge")
        encoded = _json_to_dbus_bytes(challenge)
        if self.pairing_challenge_char:
            self.pairing_challenge_char.set_value(encoded)
        return encoded

    def _on_pairing_result_write(self, value: list[int], _options: Dict[str, Any]) -> None:
        LOGGER.debug("Pairing result write: %s", value)
        try:
            payload = _bytes_to_json(value)
            aggregated = None
            if isinstance(payload, dict):
                try:
                    aggregated = self._pairing_result_assembler.ingest(payload)
                except ValueError as chunk_exc:
                    LOGGER.warning("Failed to assemble pairing result chunks: %s", chunk_exc)
                    if self.pairing_result_char:
                        error_payload = {
                            "status": "ERROR",
                            "message": f"chunk_assembly_failed: {chunk_exc}",
                            "timestamp": int(time.time() * 1000),
                        }
                        self.pairing_result_char.set_value(_json_to_dbus_bytes(error_payload))
                    return
            if aggregated is None:
                if isinstance(payload, dict) and any(k in payload for k in ("index", "total", "chunkIndex")):
                    LOGGER.debug("Waiting for additional pairing_result chunks")
                    return
                aggregated = payload
            payload = aggregated
            LOGGER.info("Pairing result payload: %s", payload)
            ok, response = self.pairing_manager.handle_pairing_result(payload)
            if self.pairing_result_char:
                self.pairing_result_char.set_value(_json_to_dbus_bytes(response))
            LOGGER.info("Pairing result processed (ok=%s)", ok)
        except Exception as exc:  # pylint: disable=broad-except
            LOGGER.exception("Failed to handle pairing result: %s", exc)
            if self.pairing_result_char:
                error_payload = {
                    "status": "ERROR",
                    "message": str(exc),
                    "timestamp": 0,
                }
                self.pairing_result_char.set_value(_json_to_dbus_bytes(error_payload))

    def _on_command_write(self, value: list[int], _options: Dict[str, Any]) -> None:
        LOGGER.info("Command write: %s", value)
        try:
            payload = _bytes_to_json(value)
            try:
                aggregated = self._chunk_assembler.ingest(payload)
            except ValueError as chunk_exc:
                LOGGER.warning("Failed to assemble chunked command payload: %s", chunk_exc)
                error_payload = {
                    "success": False,
                    "error": f"chunk_assembly_failed: {chunk_exc}",
                    "timestamp": int(time.time() * 1000),
                }
                self._publish_command_response(_json_to_dbus_bytes(error_payload), source="chunk-error")
                return

            if aggregated is None:
                LOGGER.debug("Waiting for additional command chunks")
                return

            if not isinstance(aggregated, dict):
                raise ValueError("Assembled command payload is not an object")

            payload = aggregated
            ok, response = self.command_handler.process(payload)
            if response is None:
                LOGGER.info("Command processed (ok=%s, response suppressed)", ok)
                return
            encoded = _json_to_dbus_bytes(response)
            self._publish_command_response(encoded, source="write")
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug("Command response: %s", response)
            else:
                LOGGER.info(
                    "Command processed (ok=%s, type=%s)",
                    ok,
                    response.get("type") or response.get("command"),
                )
        except Exception as exc:  # pylint: disable=broad-except
            LOGGER.exception("Failed to handle command: %s", exc)
            error_payload = {
                "success": False,
                "error": str(exc),
                "timestamp": 0,
            }
            encoded_error = _json_to_dbus_bytes(error_payload)
            self._publish_command_response(encoded_error, source="error")

    def _on_command_read(self, options: Dict[str, Any]) -> list[int]:
        offset = 0
        if options:
            raw_offset = options.get("offset")
            if raw_offset not in (None, -1):
                try:
                    offset = int(raw_offset)
                except (TypeError, ValueError):
                    offset = 0

        if not self._command_read_available:
            LOGGER.info(
                "Command read ignored (notifications active, offset=%d total=%d)",
                offset,
                len(self._last_command_response),
            )
            return []

        total_len = len(self._last_command_response)
        if offset >= total_len:
            LOGGER.info(
                "Command read beyond end (offset=%d, total=%d) -> returning empty", offset, total_len
            )
            return []

        max_chunk = 512
        chunk = self._last_command_response[offset : offset + max_chunk]

        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug(
                "Command read offset=%d chunk=%d total=%d", offset, len(chunk), total_len
            )
        else:
            LOGGER.info(
                "Command read returning bytes=%d (offset=%d total=%d)",
                len(chunk),
                offset,
                total_len,
            )
        return list(chunk)

    def _on_command_notify_state(self, notifying: bool, _characteristic) -> None:
        self._command_notify_enabled = notifying
        if not notifying:
            self._command_read_available = True
        LOGGER.info("Command notify %s", "enabled" if notifying else "disabled")
        if notifying and self._last_command_response:
            self._publish_command_response(self._last_command_response, source="notify_resume")

    def _publish_command_response(self, encoded: list[int], source: str) -> None:
        self._last_command_response = encoded
        if not self.command_char:
            return

        total_len = len(encoded)
        LOGGER.info("Prepared command response bytes=%d (source=%s)", total_len, source)

        if not encoded:
            self.command_char.set_value([])
            return

        if self._command_notify_enabled:
            self._command_read_available = False
            chunk_size = 180  # stay well below common ATT MTU to avoid fragmentation
            chunk_count = 0
            for offset in range(0, total_len, chunk_size):
                chunk = encoded[offset : offset + chunk_size]
                self.command_char.set_value(chunk)
                chunk_count += 1
                if chunk_count > 1:
                    # brief pause so notifications are emitted in order
                    time.sleep(0.005)
            if chunk_count > 1:
                LOGGER.info(
                    "Command response notified in %d chunks (chunk_size=%d)",
                    chunk_count,
                    chunk_size,
                )
            # Clear characteristic backing value so read fallback does not replay chunks.
            self.command_char.set_value([])
        else:
            self._command_read_available = True
            truncated = encoded[:512]
            if len(truncated) < total_len:
                LOGGER.warning(
                    "Command notify disabled; truncating response to 512 bytes for read fallback (total=%d)",
                    total_len,
                )
            self.command_char.set_value(truncated)

    def _on_pin_session_update(self, state) -> None:
        if state is None:
            LOGGER.info("PIN session cleared")
            return
        LOGGER.info(
            "PIN session %s status=%s expires=%s attemptsRemaining=%s",
            state.session_id,
            state.status,
            state.expires_at,
            state.attempts_remaining,
        )

    # Runtime ------------------------------------------------------------
    def run(self) -> None:
        LOGGER.info("Advertising digital key service as %s", LOCAL_NAME)
        try:
            self.peripheral.publish()
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        if self._is_shutting_down:
            return
        self._is_shutting_down = True
        try:
            if hasattr(self.peripheral, "ad_manager") and hasattr(self.peripheral, "advert"):
                self.peripheral.ad_manager.unregister_advertisement(self.peripheral.advert)
                LOGGER.info("BLE advertisement unregistered")
        except Exception as exc:  # pylint: disable=broad-except
            if "Does Not Exist" in str(exc):
                LOGGER.debug("Advertisement already cleared: %s", exc)
            else:
                LOGGER.warning("Failed to unregister advertisement: %s", exc)
        try:
            if hasattr(self.peripheral, "srv_mng") and hasattr(self.peripheral, "app"):
                self.peripheral.srv_mng.unregister_application(self.peripheral.app.get_path())
                LOGGER.info("GATT application unregistered")
        except Exception as exc:  # pylint: disable=broad-except
            LOGGER.warning("Failed to unregister GATT application: %s", exc)


def detect_adapter() -> str:
    """Choose a BLE adapter address via env override or first available device."""
    env_addr = os.environ.get("VEHICLE_ADAPTER_MAC")
    if env_addr:
        LOGGER.info("Using adapter from VEHICLE_ADAPTER_MAC: %s", env_addr)
        return env_addr

    adapters = adapter.Adapter.available()
    if not adapters:
        raise RuntimeError(
            "No BLE adapters found. Ensure bluetoothd is running and the adapter is powered."
        )

    powered_adapters = [dev for dev in adapters if getattr(dev, "powered", False)]
    selected = powered_adapters[0] if powered_adapters else adapters[0]
    LOGGER.info("Detected Bluetooth adapter: %s", selected.address)

    if not getattr(selected, "powered", False):
        try:
            selected.powered = True
            LOGGER.info("Powered on Bluetooth adapter: %s", selected.address)
        except Exception as exc:  # pylint: disable=broad-except
            LOGGER.warning(
                "Bluetooth adapter %s is unpowered and automatic power-on failed: %s. "
                "Proceeding but BLE advertising will likely fail.",
                selected.address,
                exc,
            )
        else:
            return selected.address
    return selected.address


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main(adapter_address: str | None = None) -> None:
    _configure_logging()
    adapter_address = adapter_address or detect_adapter()
    server = VehicleBleServer(adapter_address)
    atexit.register(server.shutdown)

    def _handle_signal(signum, _frame):  # pylint: disable=unused-argument
        LOGGER.info("Stopping BLE server (signal=%s)", signum)
        server.shutdown()
        server.peripheral.mainloop.quit()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    server.run()


if __name__ == "__main__":
    if len(sys.argv) > 2:
        print("Usage: python vehicle_ble.py [adapter_mac]")
        sys.exit(1)
    cli_adapter = sys.argv[1] if len(sys.argv) == 2 else None
    try:
        main(cli_adapter)
    except Exception as exc:  # pylint: disable=broad-except
        LOGGER.exception("BLE server failed: %s", exc)
        raise
