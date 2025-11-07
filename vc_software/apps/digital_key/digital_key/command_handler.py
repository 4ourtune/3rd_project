"""Command processing for Digital Key BLE prototype."""
from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

from .certificates import CertificatePayload, CertificateProvider
from .key_store import KeyStore
from .pki import (
    decrypt_payload,
    encrypt_payload,
    finalize_session_state,
    sign_vehicle_response,
    coerce_public_key_pem,
)
try:
    from .ipc_client import send_cmd as ipc_send_cmd  # pragma: no cover - imported for runtime IPC
except ImportError:  # pragma: no cover - IPC optional during tests
    ipc_send_cmd = None

if TYPE_CHECKING:
    from .pairing import PairingManager

LOGGER = logging.getLogger(__name__)

VEHICLE_COMMANDS = {"UNLOCK", "LOCK", "START", "GET_ALL"}

CERT_REQUEST_TYPE = "cert_request"
SECURE_COMMAND_TYPE = "secure_command"
PKI_COMMAND_TYPE = "pki_command"
PKI_HANDSHAKE_TYPE = "handshake"
PKI_CERT_EXCHANGE_TYPE = "cert_exchange"
PKI_SESSION_SEED_TYPE = "session_seed"


class CommandHandler:
    """Validate and dispatch Digital Key commands."""

    def __init__(
        self,
        key_store: KeyStore,
        certificate_provider: Optional[CertificateProvider] = None,
        pairing_manager: Optional["PairingManager"] = None,
    ):
        self.key_store = key_store
        self.certificate_provider = certificate_provider
        self.pairing_manager = pairing_manager

    def process(self, payload: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Handle a command payload from the smartphone."""
        try:
            request_type = str(payload.get("type", "")).lower()
            if request_type:
                return self._handle_typed_request(request_type, payload)

            command = str(payload.get("command", "")).upper()
            if command in VEHICLE_COMMANDS:
                return self._handle_vehicle_command(command, payload)
            raise ValueError(f"Unsupported command: {command or request_type}")
        except Exception as exc:  # pylint: disable=broad-except
            LOGGER.error("Command processing failed: %s", exc)
            return False, {
                "success": False,
                "command": payload.get("command"),
                "type": payload.get("type"),
                "timestamp": int(time.time() * 1000),
                "error": str(exc),
            }

    def _handle_typed_request(self, request_type: str, payload: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        if request_type == CERT_REQUEST_TYPE:
            if self.certificate_provider is None:
                raise ValueError("Certificate provider is unavailable")

            certificate_payload: CertificatePayload = self.certificate_provider.get_certificate_payload()
            response = dict(certificate_payload.payload)
            response["success"] = True
            response.setdefault("type", CERT_REQUEST_TYPE.replace("request", "response"))
            response["timestamp"] = int(time.time() * 1000)
            if "requestId" in payload:
                response["requestId"] = payload["requestId"]
            LOGGER.info(
                "Serving certificate response (version=%s)",
                response.get("certificate", {}).get("version"),
            )
            return True, response

        if request_type == "get_all":
            return self._handle_vehicle_command("GET_ALL", payload)

        if request_type == SECURE_COMMAND_TYPE:
            return self._handle_secure_command(payload)

        if request_type == PKI_COMMAND_TYPE:
            return self._handle_pki_command(payload)

        if request_type == PKI_HANDSHAKE_TYPE:
            return self._handle_pki_handshake(payload)

        if request_type == PKI_CERT_EXCHANGE_TYPE:
            return self._handle_pki_cert_exchange(payload)

        if request_type == PKI_SESSION_SEED_TYPE:
            return self._handle_pki_session_seed(payload)

        raise ValueError(f"Unsupported request type: {request_type}")

    def _handle_vehicle_command(self, command: str, payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        key_id = str(payload.get("keyId", ""))
        command_requires_key = command != "GET_ALL"

        if command_requires_key:
            try:
                timestamp = int(payload.get("timestamp", 0))
            except (TypeError, ValueError) as exc:
                raise ValueError("Invalid timestamp") from exc

            if not key_id:
                raise ValueError("Missing keyId")
            if not self.key_store.get_key(key_id):
                synced = False
                if self.pairing_manager is not None:
                    synced = self.pairing_manager.sync_keys_from_server("lookup_miss")
                if not self.key_store.get_key(key_id):
                    if synced:
                        raise ValueError(f"Unknown keyId after sync: {key_id}")
                    raise ValueError(f"Unknown keyId: {key_id}")
            if not timestamp:
                raise ValueError("Missing timestamp")
        else:
            timestamp = int(time.time() * 1000)

        # TODO: verify HMAC/PKI signature when crypto is defined.

        LOGGER.info("Dispatching %s via IPC for key %s", command, key_id or "n/a")

        action_ok, action_data = self._dispatch_ipc_command(command)
        if not action_ok:
            error_detail = action_data.get("error") or action_data.get("rawResponse") or "ipc_failed"
            return False, {
                "success": False,
                "command": command,
                "timestamp": int(time.time() * 1000),
                "error": error_detail,
            }

        vehicle_state = self._extract_vehicle_state(action_data)
        if command != "GET_ALL" and not vehicle_state:
            status_ok, status_data = self._dispatch_ipc_command("GET_ALL")
            if status_ok:
                vehicle_state = self._extract_vehicle_state(status_data)
            else:
                LOGGER.warning(
                    "Failed to query vehicle state after %s: %s",
                    command,
                    status_data.get("rawResponse"),
                )

        response: Dict[str, Any] = {
            "success": True,
            "command": command,
            "timestamp": int(time.time() * 1000),
            "data": {"commandProcessedAt": timestamp},
        }
        if vehicle_state:
            response["vehicleState"] = vehicle_state
            response["data"]["vehicleState"] = vehicle_state
            LOGGER.info("Vehicle state after %s: %s", command, vehicle_state)
        if action_data.get("rawResponse"):
            response.setdefault("metadata", {})["ipcRaw"] = action_data["rawResponse"]
        return True, response

    @staticmethod
    def decode_payload(raw_bytes: bytes) -> Dict[str, Any]:
        try:
            return json.loads(raw_bytes.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid JSON payload: {exc}") from exc

    @staticmethod
    def encode_payload(data: Dict[str, Any]) -> bytes:
        return json.dumps(data).encode('utf-8')

    def _maybe_store_key_from_certificate(self, certificate_payload: Dict[str, Any]) -> None:
        key_id = (
            certificate_payload.get("keyId")
            or certificate_payload.get("id")
        )
        if not key_id and isinstance(certificate_payload.get("subject"), dict):
            subject = certificate_payload["subject"]
            key_id = subject.get("keyId") or subject.get("id")
        if not key_id:
            return
        key_id = str(key_id)
        if self.key_store.get_key(key_id):
            return

        entry: Dict[str, Any] = {
            "keyId": key_id,
            "certificate": certificate_payload,
            "permissions": certificate_payload.get("permissions"),
            "userId": certificate_payload.get("userId"),
            "vehicleId": certificate_payload.get("vehicleId"),
            "updatedAt": int(time.time() * 1000),
        }
        try:
            self.key_store.upsert_key(key_id, entry)
            LOGGER.info("Cached keyId %s from PKI certificate payload", key_id)
        except Exception as exc:  # pylint: disable=broad-except
            LOGGER.warning("Failed to persist keyId %s from certificate payload: %s", key_id, exc)

    def _dispatch_ipc_command(self, command: str) -> Tuple[bool, Dict[str, Any]]:
        """Send command to realtime process and parse minimal status details."""
        if ipc_send_cmd is None:
            raise RuntimeError("Realtime IPC client unavailable (ipc_client module missing)")

        try:
            ok, resp = ipc_send_cmd(command, "DK")
        except Exception as exc:  # pylint: disable=broad-except
            LOGGER.error("Realtime IPC send failed for %s: %s", command, exc)
            return False, {"error": f"ipc_exception:{exc}"}

        parsed: Dict[str, Any] = {"rawResponse": resp}
        if not ok:
            LOGGER.error("Realtime IPC returned error for %s: %s", command, resp)
            parsed["error"] = resp
            return False, parsed

        tokens = (resp or "").strip().split(';')
        for token in tokens:
            token = token.strip()
            if not token:
                continue
            if '=' in token:
                key, value = token.split('=', 1)
                parsed[key.upper()] = value
            else:
                parsed.setdefault("_flags", []).append(token.upper())
        return True, parsed

    @staticmethod
    def _extract_vehicle_state(parsed: Dict[str, Any]) -> Dict[str, Any]:
        state: Dict[str, Any] = {}
        locked = parsed.get("LOCKED")
        engine = parsed.get("ENGINE")
        if locked is not None:
            state["locked"] = str(locked).strip() in {"1", "true", "TRUE"}
        if engine is not None:
            state["engineOn"] = str(engine).strip() in {"1", "true", "TRUE"}
        return state

    # Secure command helpers -------------------------------------------
    def _handle_secure_command(self, payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        if self.pairing_manager is None:
            raise ValueError("Pairing manager is unavailable for secure commands")

        session_id = str(payload.get("sessionId") or "")
        if not session_id:
            raise ValueError("Missing sessionId for secure command payload")

        encrypted_payload = payload.get("encryptedPayload")
        if not encrypted_payload:
            raise ValueError("Missing encryptedPayload for secure command payload")

        pki_state = self.pairing_manager.get_pki_session_state(session_id)
        if pki_state is None:
            raise ValueError(f"No PKI session material for session {session_id}")
        if not pki_state.signature_verified:
            raise ValueError("PKI session not verified by client signature")

        aad = None
        plaintext = decrypt_payload(
            pki_state.session_key,
            str(encrypted_payload),
            payload.get("nonce"),
            associated_data=aad,
        )
        try:
            inner_payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Failed to decode secure command payload: {exc}") from exc

        ok, command_response = self._handle_inner_secure_command(inner_payload)
        response_bytes = json.dumps(command_response).encode("utf-8")
        secure_response = encrypt_payload(
            pki_state.session_key,
            response_bytes,
            associated_data=aad,
            include_nonce_inline="nonce" not in payload,
        )
        secure_response.update(
            {
                "type": SECURE_COMMAND_TYPE,
                "sessionId": session_id,
                "success": ok,
                "timestamp": int(time.time() * 1000),
            }
        )
        return ok, secure_response

    def _handle_pki_command(self, payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        if self.pairing_manager is None:
            raise ValueError("Pairing manager is unavailable for PKI commands")

        session_id = str(payload.get("sessionId") or payload.get("session_id") or "")
        if not session_id:
            raise ValueError("Missing sessionId for pki_command")

        certificate_info = payload.get("certificate") or {}
        if certificate_info:
            self._maybe_store_key_from_certificate(certificate_info)

        session_state = self.pairing_manager.get_pki_session_state(session_id)

        if session_state is None:
            session_state = self.pairing_manager.recover_pki_session(
                session_id,
                certificate_info,
                mark_verified=False,
            )
        if session_state is None:
            raise ValueError(f"No PKI session material for session {session_id}")

        session_state = self._refresh_certificate_material(session_state, certificate_info)

        nonce_b64 = payload.get("nonce") or payload.get("clientNonce")
        signature_b64 = payload.get("signature")

        try:
            finalize_session_state(session_state, nonce_b64, signature_b64, signed_payload=payload)

            encrypted_payload = payload.get("encryptedPayload") or payload.get("encrypted_payload")
            if not encrypted_payload:
                raise ValueError("pki_command missing encryptedPayload")

            aad = None
            plaintext = decrypt_payload(
                session_state.session_key,
                str(encrypted_payload),
                payload.get("nonce"),
                associated_data=aad,
            )
            try:
                secure_payload = json.loads(plaintext.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"Failed to decode pki_command payload: {exc}") from exc

            ok, response = self._handle_inner_secure_command(secure_payload)
            response_bytes = json.dumps(response).encode("utf-8")
            secure_response = encrypt_payload(
                session_state.session_key,
                response_bytes,
                associated_data=aad,
                include_nonce_inline=True,
            )
            timestamp_ms = int(time.time() * 1000)
            encrypted_payload_b64 = secure_response["encryptedPayload"]
            nonce_b64 = secure_response.get("nonce")
            signature = sign_vehicle_response(
                session_id=session_id,
                encrypted_payload_b64=encrypted_payload_b64,
                timestamp_ms=timestamp_ms,
                nonce_b64=nonce_b64,
            )
            response_envelope = {
                "version": str(payload.get("version") or "2.0-PKI"),
                "type": "pki_response",
                "sessionId": session_id,
                "success": ok,
                "encryptedPayload": encrypted_payload_b64,
                "timestamp": timestamp_ms,
                "signature": signature,
            }
            return ok, response_envelope
        except Exception as exc:  # pylint: disable=broad-except
            LOGGER.error("PKI command handling failed: %s", exc)
            timestamp_ms = int(time.time() * 1000)
            error_response = {
                "version": str(payload.get("version") or "2.0-PKI"),
                "type": "pki_response",
                "sessionId": session_id,
                "success": False,
                "timestamp": timestamp_ms,
                "error": str(exc),
            }
            return False, error_response

    def _refresh_certificate_material(
        self,
        session_state: "PkiSessionState",
        certificate_info: Dict[str, Any],
    ) -> "PkiSessionState":
        if not certificate_info:
            return session_state

        public_key_material = certificate_info.get("publicKey") or certificate_info.get("public_key")
        certificate_pem = certificate_info.get("pem")
        if certificate_pem is None:
            raw_certificate = certificate_info.get("certificate")
            if isinstance(raw_certificate, str):
                certificate_pem = raw_certificate if "BEGIN CERTIFICATE" in raw_certificate else None

        normalized_public_key = None
        if isinstance(public_key_material, str) and public_key_material.strip():
            try:
                normalized_public_key = coerce_public_key_pem(public_key_material.strip())
            except Exception:  # pylint: disable=broad-except
                LOGGER.debug("Failed to normalize certificate public key; retaining existing session key material")

        if normalized_public_key:
            if (
                session_state.user_public_key_pem
                and session_state.user_public_key_pem.strip() != normalized_public_key.strip()
            ):
                session_state.certificate_public_key_pem = normalized_public_key
            else:
                session_state.user_public_key_pem = normalized_public_key
                session_state.handshake_public_key_pem = normalized_public_key
        if certificate_pem:
            session_state.user_certificate_pem = certificate_pem

        return session_state

    def _handle_inner_secure_command(self, payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        inner_type = str(payload.get("type", "")).lower()
        if inner_type and inner_type != SECURE_COMMAND_TYPE:
            return self._handle_typed_request(inner_type, payload)

        command = str(payload.get("command", "")).upper()
        if command in VEHICLE_COMMANDS:
            return self._handle_vehicle_command(command, payload)
        raise ValueError(f"Unsupported secure command payload: {payload}")

    # PKI v2 helpers ----------------------------------------------------
    def _handle_pki_handshake(self, payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        if self.pairing_manager is None:
            raise ValueError("Pairing manager is unavailable for handshake")
        session_id = str(payload.get("sessionId") or payload.get("session_id") or "")
        client_public_key = (
            payload.get("clientPublicKey")
            or payload.get("client_public_key")
            or payload.get("userPublicKey")
            or payload.get("user_public_key")
        )
        pairing_token = payload.get("pairingToken") or payload.get("pairing_token")
        client_nonce = payload.get("clientNonce") or payload.get("client_nonce")
        version = payload.get("version") or payload.get("protocolVersion")
        response = self.pairing_manager.begin_pki_handshake(
            session_id=session_id,
            client_public_key=str(client_public_key or ""),
            pairing_token=pairing_token,
            client_nonce_b64=client_nonce,
            protocol_version=version,
        )
        return True, response

    def _handle_pki_cert_exchange(self, payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        if self.pairing_manager is None:
            raise ValueError("Pairing manager is unavailable for cert exchange")
        session_id = str(payload.get("sessionId") or payload.get("session_id") or "")
        certificate = payload.get("certificate")
        if not isinstance(certificate, dict):
            raise ValueError("cert_exchange payload missing certificate object")
        response = self.pairing_manager.store_pki_certificate(session_id, certificate)
        return True, response

    def _handle_pki_session_seed(self, payload: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        if self.pairing_manager is None:
            raise ValueError("Pairing manager is unavailable for session seed")
        session_info = payload.get("session") or {}
        session_id = (
            session_info.get("sessionId")
            or payload.get("sessionId")
            or payload.get("session_id")
        )
        session_key = (
            session_info.get("sessionKey")
            or payload.get("sessionKey")
            or payload.get("session_key")
        )
        pairing_token = (
            session_info.get("pairingToken")
            or payload.get("pairingToken")
            or payload.get("pairing_token")
        )
        client_nonce = (
            session_info.get("clientNonce")
            or payload.get("clientNonce")
            or payload.get("client_nonce")
        )
        server_nonce = (
            session_info.get("serverNonce")
            or payload.get("serverNonce")
            or payload.get("server_nonce")
        )
        expires_at = (
            session_info.get("expiresAt")
            or payload.get("expiresAt")
            or payload.get("expires_at")
        )
        response = self.pairing_manager.seed_pki_session(
            session_id=str(session_id or ""),
            session_key_b64=str(session_key or ""),
            pairing_token=pairing_token,
            client_nonce_b64=client_nonce,
            expires_at=expires_at,
            server_nonce_b64=server_nonce,
        )
        return True, response
