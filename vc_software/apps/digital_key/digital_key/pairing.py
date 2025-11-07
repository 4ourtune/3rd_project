"""Pairing challenge generation and validation helpers."""
from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .config import CACHE_DIR, LOG_DIR, ensure_runtime_dirs
from .identity import get_identity_value
from .key_store import KeyStore
from .pairing_client import (
    PairingApiClient,
    PairingApiError,
    PairingSession,
    PinStatus,
    build_client,
)
from .pki import (
    PkiSessionState,
    _normalize_session_key,
    coerce_public_key_pem,
    derive_session_key,
    finalize_session_state,
    load_vehicle_keys,
)

LOGGER = logging.getLogger(__name__)

DEFAULT_DEVICE_ID = (
    os.environ.get("VEHICLE_DEVICE_ID")
    or get_identity_value("device_id")
    or "RASPBERRY_PI_001"
)
DEFAULT_HEADER_VEHICLE_ID = (
    os.environ.get("VEHICLE_STATUS_HEADER_ID")
    or os.environ.get("VEHICLE_STATUS_NUMERIC_ID")
    or os.environ.get("VEHICLE_HEADER_ID")
    or get_identity_value("x_vehicle_id")
)
DEFAULT_OWNER_CANDIDATE_ID = os.environ.get("VEHICLE_OWNER_CANDIDATE_ID")
PAIRING_FLAG_FILENAME = "pairing_enabled"

PIN_STATUS_SUCCESS_STATES = {"VERIFIED", "APPROVED", "COMPLETED", "ACTIVE", "SUCCESS"}
PIN_STATUS_TERMINAL_STATES = {"CANCELLED", "EXPIRED", "FAILED", "DENIED", "TIMEOUT"}
PIN_STATUS_POLL_INTERVAL = float(os.environ.get("PAIRING_PIN_STATUS_INTERVAL", "2.0"))
PIN_SESSION_EXPORT_PATH = LOG_DIR / "pin_session_state.json"
PKI_SESSION_EXPORT_PATH = LOG_DIR / "pki_session_state.json"
SKIP_PIN_REQUEST = os.environ.get("SKIP_PAIRING_PIN_REQUEST", "").strip().lower() in {"1", "true", "yes"}
SUPPRESS_SESSION_SEED_ACK = os.environ.get("SUPPRESS_SESSION_SEED_ACK", "").strip().lower() in {"1", "true", "yes"}


@dataclass
class PinSessionState:
    """Track the current PIN session lifecycle for UI/logging purposes."""

    session_id: str
    pin: str
    expires_at: Any
    attempts_remaining: Optional[int] = None
    pairing_token: Optional[str] = None
    owner_candidate_user_id: Optional[Any] = None
    status: str = "PENDING"
    active: bool = True
    updated_at: float = field(default_factory=time.time)
    last_status_payload: Dict[str, Any] = field(default_factory=dict)
    vehicle_nonce_b64: Optional[str] = None

    def export_dict(self) -> Dict[str, Any]:
        return {
            "sessionId": self.session_id,
            "pin": self.pin,
            "expiresAt": self.expires_at,
            "attemptsRemaining": self.attempts_remaining,
            "pairingToken": self.pairing_token,
            "ownerCandidateUserId": self.owner_candidate_user_id,
            "status": self.status,
            "active": self.active,
            "updatedAt": int(self.updated_at * 1000),
            "vehicleNonce": self.vehicle_nonce_b64,
            "lastStatus": self.last_status_payload,
        }

    def update_from_status(self, status: PinStatus) -> None:
        self.status = status.state or self.status
        if status.expires_at:
            self.expires_at = status.expires_at
        self.attempts_remaining = status.attempts_remaining
        if status.pairing_token:
            self.pairing_token = status.pairing_token
        if status.owner_candidate_user_id:
            self.owner_candidate_user_id = status.owner_candidate_user_id
        self.last_status_payload = status.raw
        self.updated_at = time.time()


@dataclass
class PkiHandshakeContext:
    """Temporarily store handshake material before session seed."""

    session_id: str
    pairing_token: Optional[str]
    user_public_key: str
    user_certificate: Optional[str]
    vehicle_public_key: str
    vehicle_nonce: bytes
    client_nonce: Optional[str] = None
    certificate_public_key: Optional[str] = None
    created_at: float = field(default_factory=time.time)


class PairingManager:
    """Manage pairing challenges and responses."""

    def __init__(
        self,
        key_store: KeyStore,
        device_id: str = DEFAULT_DEVICE_ID,
        header_vehicle_id: Optional[str] = DEFAULT_HEADER_VEHICLE_ID,
        owner_candidate_user_id: Optional[Any] = DEFAULT_OWNER_CANDIDATE_ID,
        api_client: Optional[PairingApiClient] = None,
    ):
        self.key_store = key_store
        self.device_id = device_id
        self.header_vehicle_id = header_vehicle_id or DEFAULT_HEADER_VEHICLE_ID
        if not self.header_vehicle_id:
            raise ValueError("Vehicle header ID is required for pairing API requests")
        self.owner_candidate_user_id = owner_candidate_user_id
        if api_client is None:
            self.api_client = build_client(vehicle_header_id=self.header_vehicle_id)
        else:
            self.api_client = api_client
            if getattr(self.api_client, "vehicle_header_id", None) is None:
                self.api_client.vehicle_header_id = self.header_vehicle_id
        self._active_session: Optional[PairingSession] = None
        self._last_challenge: Optional[Dict[str, Any]] = None

        ensure_runtime_dirs()
        key_store_path = getattr(self.key_store, "path", None)
        if isinstance(key_store_path, Path):
            flag_dir = key_store_path.parent
        else:
            flag_dir = CACHE_DIR
        flag_dir.mkdir(parents=True, exist_ok=True)
        self.pairing_flag_path = flag_dir / PAIRING_FLAG_FILENAME
        PIN_SESSION_EXPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

        self._pin_state_lock = threading.RLock()
        self._pin_session_state: Optional[PinSessionState] = None
        self._pki_state: Optional[PkiSessionState] = None
        self._pki_sessions: Dict[str, PkiSessionState] = {}
        self._pin_poll_thread: Optional[threading.Thread] = None
        self._pin_poll_stop = threading.Event()
        self._session_observers: List[Callable[[Optional[PinSessionState]], None]] = []
        self._session_export_path = PIN_SESSION_EXPORT_PATH
        self._skip_pin_request = SKIP_PIN_REQUEST
        self._pki_export_path = PKI_SESSION_EXPORT_PATH
        self._cached_pki_payload: Optional[Dict[str, Any]] = None
        self._handshake_contexts: Dict[str, PkiHandshakeContext] = {}
        self._pending_handshake: Optional[PkiHandshakeContext] = None
        self._last_session_id: Optional[str] = None
        self._load_cached_pki_session()
        self.sync_keys_from_server("startup")

    def sync_keys_from_server(self, reason: str = "manual", *, allow_fail: bool = True) -> bool:
        """Synchronize digital keys with the backend."""
        if self.api_client is None:
            LOGGER.debug("Key sync skipped (%s): API client unavailable", reason)
            return False
        try:
            payload = self.api_client.fetch_keys(header_vehicle_id=self.header_vehicle_id)
        except PairingApiError as exc:
            message = f"Key sync ({reason}) failed: {exc}"
            if allow_fail:
                LOGGER.warning(message)
                return False
            raise PairingApiError(message) from exc

        keys = payload.get("keys", [])
        mapping: Dict[str, Dict[str, Any]] = {}
        for entry in keys:
            if not isinstance(entry, dict):
                continue
            key_id = entry.get("keyId") or entry.get("id")
            if key_id is None:
                continue
            mapping[str(key_id)] = entry

        if not mapping:
            LOGGER.warning(
                "Key sync (%s) skipped: server returned 0 entries (vehicleId=%s)",
                reason,
                self.header_vehicle_id,
            )
            return False

        self.key_store.replace_all(mapping)
        LOGGER.info(
            "Key sync (%s) completed with %d entries (vehicleId=%s)",
            reason,
            len(mapping),
            self.header_vehicle_id,
        )
        return True

    def build_challenge(self) -> Dict[str, Any]:
        """Return a fresh pairing challenge payload."""
        if not self._is_pairing_allowed():
            LOGGER.info("Pairing challenge blocked: pairing not enabled")
            return {
                "status": "DISABLED",
                "message": "Pairing not enabled",
                "deviceId": self.device_id,
                "issuedAt": int(time.time() * 1000),
            }

        nonce = base64.b64encode(os.urandom(16)).decode("ascii")
        issued_at = int(time.time() * 1000)
        if self._skip_pin_request:
            LOGGER.info("Skipping pairing PIN API request; using cached session data if available")
            challenge = self._build_cached_challenge(nonce, issued_at)
            self._last_challenge = challenge
            return challenge
        try:
            payload = self._build_pin_payload()
            session = self.api_client.request_pin(
                header_vehicle_id=self.header_vehicle_id,
                payload=payload if payload else None,
            )
            self._active_session = session
            self._initialize_pin_session(session)
            try:
                vehicle_public_key = load_vehicle_keys().public_key_pem
            except Exception as exc:  # pylint: disable=broad-except
                LOGGER.debug("Vehicle public key unavailable: %s", exc)
                vehicle_public_key = None
            challenge = {
                "deviceId": self.device_id,
                "vehicleId": self.header_vehicle_id,
                "sessionId": session.session_id,
                "nonce": nonce,
                "issuedAt": issued_at,
                "expiresAt": session.expires_at,
            }
            if session.pairing_token:
                challenge["pairingToken"] = session.pairing_token
            if session.attempts_remaining is not None:
                challenge["attemptsRemaining"] = session.attempts_remaining
            if session.owner_candidate_user_id is not None:
                challenge["ownerCandidateUserId"] = session.owner_candidate_user_id
            if vehicle_public_key:
                challenge["vehiclePublicKey"] = vehicle_public_key
            existing_state = self.get_pki_session_state(session.session_id)
            if existing_state:
                challenge["vehicleNonce"] = base64.b64encode(existing_state.vehicle_nonce).decode(
                    "ascii"
                )
                challenge["pairingToken"] = existing_state.pairing_token
            self._last_challenge = challenge

            LOGGER.info(
                "Pairing PIN for %s (session %s): %s (expires %s)",
                self.device_id,
                session.session_id,
                session.pin,
                session.expires_at,
            )
            print(
                f"[PAIRING] Session {session.session_id} PIN: {session.pin} (expires {session.expires_at})"
            )
            LOGGER.debug("Issuing pairing challenge: %s", challenge)
            return challenge
        except PairingApiError as exc:
            if self._pin_request_recoverable(exc):
                LOGGER.info("Pairing PIN request returned recoverable error (%s); attempting cached session", exc)
                challenge = self._build_cached_challenge(nonce, issued_at)
                self._last_challenge = challenge
                return challenge
            LOGGER.error("Failed to obtain pairing PIN: %s", exc)
            return self._build_error_challenge(str(exc), issued_at)
        except Exception as exc:  # pylint: disable=broad-except
            LOGGER.exception("Unexpected failure during pairing challenge: %s", exc)
            return self._build_error_challenge("Unexpected error requesting PIN", issued_at)

    def handle_pairing_result(self, payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Persist backend-provided key material and return notify payload."""
        session_id = str(payload.get("sessionId") or "")
        if not session_id:
            candidate = self._last_session_id or (self._active_session.session_id if self._active_session else "")
            if candidate:
                LOGGER.warning("Pairing result missing sessionId; using last session %s", candidate)
                session_id = candidate
            else:
                return False, {
                    "status": "ERROR",
                    "message": "Missing sessionId in pairing result payload",
                    "timestamp": int(time.time() * 1000),
                }

        if "clientNonce" in payload or "signature" in payload:
            return self._handle_pairing_handshake(session_id, payload)

        if "keyId" in payload:
            return self._handle_pairing_key_storage(session_id, payload)

        return False, {
            "status": "ERROR",
            "message": "Unsupported pairing result payload format",
            "sessionId": session_id,
            "timestamp": int(time.time() * 1000),
        }

    def _handle_pairing_handshake(self, session_id: str, payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        with self._pin_state_lock:
            pki_state = self._pki_sessions.get(session_id)
            pin_state = self._pin_session_state
        if pki_state is None or pki_state.session_id != session_id:
            LOGGER.warning("Handshake received for session %s but PKI state is unavailable", session_id)
            return False, {
                "status": "ERROR",
                "message": "PKI session state unavailable",
                "sessionId": session_id,
                "timestamp": int(time.time() * 1000),
            }

        client_nonce = payload.get("clientNonce")
        signature = payload.get("signature")
        try:
            finalize_session_state(pki_state, client_nonce, signature)
        except ValueError as exc:
            LOGGER.warning("Handshake verification failed for session %s: %s", session_id, exc)
            return False, {
                "status": "ERROR",
                "message": str(exc),
                "sessionId": session_id,
                "timestamp": int(time.time() * 1000),
            }

        with self._pin_state_lock:
            if pin_state and pin_state.session_id == session_id:
                pin_state.active = False
                pin_state.status = "HANDSHAKE_ACK"
                pin_state.vehicle_nonce_b64 = base64.b64encode(pki_state.vehicle_nonce).decode("ascii")
                if pki_state.client_nonce:
                    pin_state.last_status_payload = dict(pin_state.last_status_payload)
                    pin_state.last_status_payload["clientNonce"] = base64.b64encode(
                        pki_state.client_nonce
                    ).decode("ascii")
                publish_state = pin_state
            else:
                publish_state = None
        if publish_state:
            self._publish_pin_session_state(publish_state)
        self._stop_pin_status_poller()
        self._export_pki_session_state()
        self._export_pki_session_state()
        response = {
            "status": "OK",
            "message": "Handshake acknowledged",
            "sessionId": session_id,
            "vehicleNonce": base64.b64encode(pki_state.vehicle_nonce).decode("ascii"),
            "signatureVerified": pki_state.signature_verified,
            "timestamp": int(time.time() * 1000),
        }
        if pki_state.pairing_token:
            response["pairingToken"] = pki_state.pairing_token
        return True, response

    def _handle_pairing_key_storage(
        self,
        session_id: str,
        payload: Dict[str, Any],
    ) -> Tuple[bool, Dict[str, Any]]:
        status = {"status": "ERROR", "sessionId": session_id}
        key_id = str(payload.get("keyId") or "")
        if not key_id:
            status["message"] = "Missing keyId in pairing result payload"
            status["timestamp"] = int(time.time() * 1000)
            return False, status
        try:
            self.key_store.upsert_key(key_id, payload)
        except Exception as exc:  # pylint: disable=broad-except
            status["message"] = f"Failed to store key: {exc}"
            status["timestamp"] = int(time.time() * 1000)
            LOGGER.warning("Pairing result handling failed: %s", exc)
            return False, status

        with self._pin_state_lock:
            if self._pin_session_state and self._pin_session_state.session_id == session_id:
                self._pin_session_state.status = "KEY_STORED"
                self._pin_session_state.active = False
                publish_state = self._pin_session_state
            else:
                publish_state = None
        if publish_state:
            self._publish_pin_session_state(publish_state)
        self._disable_pairing_flag()
        self._stop_pin_status_poller()
        self.sync_keys_from_server("pairing_result")
        response = {
            "status": "OK",
            "message": "Key stored",
            "sessionId": session_id,
            "keyId": key_id,
            "timestamp": int(time.time() * 1000),
        }
        LOGGER.info("Stored digital key %s for session %s", key_id, session_id)
        return True, response

    def _build_error_challenge(self, message: str, issued_at: int) -> Dict[str, Any]:
        error_payload = {
            "deviceId": self.device_id,
            "status": "ERROR",
            "message": message,
            "issuedAt": issued_at,
        }
        if self._last_challenge:
            return self._last_challenge
        return error_payload

    @staticmethod
    def decode_payload(raw_bytes: bytes) -> Dict[str, Any]:
        """Parse BLE write payload into Python dict."""
        try:
            return json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid JSON payload: {exc}") from exc

    @staticmethod
    def encode_payload(data: Dict[str, Any]) -> bytes:
        return json.dumps(data).encode("utf-8")

    def register_session_observer(
        self,
        callback: Callable[[Optional[PinSessionState]], None],
    ) -> None:
        """Attach a callback that receives session state snapshots."""
        with self._pin_state_lock:
            self._session_observers.append(callback)
            current = self._pin_session_state
        if current:
            try:
                callback(current)
            except Exception as exc:  # pylint: disable=broad-except
                LOGGER.debug("Session observer callback failed during registration: %s", exc)

    def get_pin_session_snapshot(self) -> Optional[Dict[str, Any]]:
        """Return the current PIN session state as a dict for diagnostics."""
        with self._pin_state_lock:
            if self._pin_session_state is None:
                return None
            return dict(self._pin_session_state.export_dict())

    def get_pki_session_state(self, session_id: Optional[str] = None) -> Optional[PkiSessionState]:
        """Return the active PKI session state, optionally filtered by sessionId."""
        with self._pin_state_lock:
            if session_id:
                return self._pki_sessions.get(session_id)
            if self._pki_state is not None:
                return self._pki_state
            if self._last_session_id and self._last_session_id in self._pki_sessions:
                return self._pki_sessions[self._last_session_id]
            # fall back to any cached session
            if self._pki_sessions:
                return next(iter(self._pki_sessions.values()))
            return None

    def _build_pin_payload(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        if self.device_id:
            payload["deviceId"] = self.device_id
        if self.owner_candidate_user_id:
            payload["ownerCandidateUserId"] = self.owner_candidate_user_id
        return payload

    def _pin_request_recoverable(self, exc: PairingApiError) -> bool:
        cause = getattr(exc, "__cause__", None)
        response = getattr(cause, "response", None)
        status_code = getattr(response, "status_code", None)
        if status_code == 400:
            return True
        message = str(exc).lower()
        return "400" in message or "already" in message or "duplicate" in message

    def _build_cached_challenge(self, nonce: str, issued_at: int) -> Dict[str, Any]:
        pki_state = self.get_pki_session_state()
        if pki_state is not None:
            try:
                vehicle_public_key = load_vehicle_keys().public_key_pem
            except Exception as exc:  # pylint: disable=broad-except
                LOGGER.debug("Vehicle public key unavailable while building cached challenge: %s", exc)
                vehicle_public_key = None

            challenge: Dict[str, Any] = {
                "deviceId": self.device_id,
                "sessionId": pki_state.session_id,
                "issuedAt": issued_at,
                "nonce": nonce,
            }
            if pki_state.pairing_token:
                challenge["pairingToken"] = pki_state.pairing_token
            if pki_state.vehicle_nonce:
                challenge["vehicleNonce"] = base64.b64encode(pki_state.vehicle_nonce).decode("ascii")
            if vehicle_public_key:
                challenge["vehiclePublicKey"] = vehicle_public_key
            LOGGER.info(
                "Using existing PKI session %s for pairing challenge (PIN request skipped)",
                pki_state.session_id,
            )
            return challenge

        if self._last_challenge:
            LOGGER.info("Reusing last pairing challenge (PIN request skipped)")
            cached = dict(self._last_challenge)
            cached.setdefault("issuedAt", issued_at)
            cached.setdefault("nonce", nonce)
            return cached

        LOGGER.warning(
            "PIN request skipped but no cached session available; pairing challenge will be disabled",
        )
        return {
            "status": "DISABLED",
            "message": "PIN request skipped; use existing registration",
            "deviceId": self.device_id,
            "issuedAt": issued_at,
        }

    # ------------------------------------------------------------------
    # New PKI handshake helpers
    def begin_pki_handshake(
        self,
        session_id: str,
        client_public_key: str,
        *,
        pairing_token: Optional[str] = None,
        client_nonce_b64: Optional[str] = None,
        protocol_version: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if not client_public_key:
            raise ValueError("Missing clientPublicKey for handshake")

        public_key_material = client_public_key
        if isinstance(public_key_material, dict):
            public_key_material = (
                public_key_material.get("pem")
                or public_key_material.get("publicKey")
                or public_key_material.get("public_key")
                or json.dumps(public_key_material)
            )
        normalized_public_key = str(public_key_material or "")
        if normalized_public_key:
            try:
                normalized_public_key = coerce_public_key_pem(normalized_public_key)
            except Exception:  # pylint: disable=broad-except
                LOGGER.debug("Client public key not yet normalised; awaiting certificate exchange")
        else:
            normalized_public_key = ""

        if not session_id:
            if self._pending_handshake:
                session_id = self._pending_handshake.session_id
            elif self._last_session_id:
                session_id = self._last_session_id
            else:
                session_id = str(uuid4())

        try:
            vehicle_public_key = load_vehicle_keys().public_key_pem
        except Exception as exc:  # pylint: disable=broad-except
            raise ValueError(f"Vehicle keys unavailable: {exc}") from exc

        vehicle_nonce = os.urandom(16)
        with self._pin_state_lock:
            context = self._handshake_contexts.get(session_id)
            if context is None:
                context = PkiHandshakeContext(
                    session_id=session_id,
                    pairing_token=pairing_token,
                    user_public_key=normalized_public_key or str(client_public_key),
                    user_certificate=None,
                    vehicle_public_key=vehicle_public_key,
                    vehicle_nonce=vehicle_nonce,
                    client_nonce=client_nonce_b64,
                    certificate_public_key=None,
                )
            else:
                if pairing_token:
                    context.pairing_token = pairing_token
                if normalized_public_key:
                    context.user_public_key = normalized_public_key
                else:
                    context.user_public_key = str(client_public_key)
                context.client_nonce = client_nonce_b64 or context.client_nonce
                if context.vehicle_public_key != vehicle_public_key:
                    context.vehicle_public_key = vehicle_public_key
            self._handshake_contexts[session_id] = context
            self._pending_handshake = context
            self._last_session_id = session_id

        with self._pin_state_lock:
            existing_state = self._pki_sessions.get(session_id)
        if existing_state:
            if context.user_public_key:
                existing_state.user_public_key_pem = context.user_public_key
                existing_state.handshake_public_key_pem = context.user_public_key
            if context.client_nonce:
                try:
                    existing_state.client_nonce = base64.b64decode(context.client_nonce)
                except ValueError:
                    pass
            with self._pin_state_lock:
                self._pki_state = existing_state
                self._pki_sessions[session_id] = existing_state
            self._export_pki_session_state()

        vehicle_nonce = context.vehicle_nonce
        LOGGER.info("PKI handshake processed (session=%s, hasToken=%s)", session_id, bool(pairing_token))

        nonce_b64 = base64.b64encode(vehicle_nonce).decode("ascii")
        response = {
            "type": "handshake_ack",
            "success": True,
            "sessionId": session_id,
            "vehiclePublicKey": vehicle_public_key,
            "vehicleNonce": nonce_b64,
            "serverNonce": nonce_b64,
            "sessionSupported": True,
        }
        if protocol_version:
            response["version"] = protocol_version
        if pairing_token:
            response["pairingToken"] = pairing_token
        if client_nonce_b64:
            response["clientNonce"] = client_nonce_b64
        return response

    @staticmethod
    def _extract_certificate_material(certificate_payload: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """Return (public_key_pem, certificate_pem) from an exchange payload."""
        if not isinstance(certificate_payload, dict):
            raise ValueError("certificate payload must be an object")

        candidates: List[str] = []

        def _append_candidate(value: Any) -> None:
            if isinstance(value, str):
                stripped = value.strip()
                if stripped:
                    candidates.append(stripped)

        _append_candidate(certificate_payload.get("pem"))
        raw_certificate = certificate_payload.get("certificate")
        if isinstance(raw_certificate, str):
            _append_candidate(raw_certificate)
        elif isinstance(raw_certificate, dict):
            for key in ("pem", "data", "value", "body", "certificate"):
                _append_candidate(raw_certificate.get(key))

        if not candidates:
            encoded = certificate_payload.get("der")
            if isinstance(encoded, str):
                _append_candidate(encoded)

        for candidate in candidates:
            try:
                if "BEGIN CERTIFICATE" in candidate:
                    cert = x509.load_pem_x509_certificate(candidate.encode("utf-8"))
                else:
                    der_bytes = base64.b64decode(candidate, validate=True)
                    cert = x509.load_der_x509_certificate(der_bytes)
            except Exception:  # pylint: disable=broad-except
                continue
            certificate_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
            public_key_pem = cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii")
            return public_key_pem, certificate_pem

        public_key_field = certificate_payload.get("publicKey") or certificate_payload.get("public_key")
        if isinstance(public_key_field, str):
            public_key_field = public_key_field.strip()
            if public_key_field:
                try:
                    public_key_pem = coerce_public_key_pem(public_key_field)
                except Exception:  # pylint: disable=broad-except
                    public_key_pem = public_key_field
                return public_key_pem, None

        raise ValueError("certificate payload missing usable certificate or public key data")

    def store_pki_certificate(self, session_id: str, certificate_payload: Dict[str, Any]) -> Dict[str, Any]:
        if not session_id:
            raise ValueError("Missing sessionId for cert_exchange")
        with self._pin_state_lock:
            context = self._handshake_contexts.get(session_id)
        if context is None:
            raise ValueError(f"Handshake context not found for session {session_id}")

        try:
            public_key_pem, certificate_pem = self._extract_certificate_material(certificate_payload)
        except ValueError as exc:
            raise ValueError(f"Invalid certificate payload: {exc}") from exc

        if certificate_pem:
            context.user_certificate = certificate_pem
        if public_key_pem:
            context.certificate_public_key = public_key_pem

        key_id = (
            certificate_payload.get("keyId")
            or certificate_payload.get("id")
        )
        if not key_id and isinstance(certificate_payload.get("subject"), dict):
            subject_block = certificate_payload["subject"]
            key_id = subject_block.get("keyId") or subject_block.get("id")

        key_payload: Dict[str, Any] = {}
        if public_key_pem:
            key_payload["publicKey"] = public_key_pem
        if certificate_pem:
            key_payload["certificate"] = certificate_pem
        for field in ("permissions", "userId", "vehicleId"):
            if field in certificate_payload:
                key_payload[field] = certificate_payload[field]
        key_payload["updatedAt"] = int(time.time() * 1000)

        if key_id and key_payload:
            try:
                self.key_store.upsert_key(key_id, key_payload)
                LOGGER.info("Registered keyId %s in key store", key_id)
            except Exception as exc:  # pylint: disable=broad-except
                LOGGER.warning("Failed to persist keyId %s: %s", key_id, exc)
        else:
            LOGGER.debug("Skipping key store registration; keyId or payload missing")

        updated_state: Optional[PkiSessionState] = None
        with self._pin_state_lock:
            self._handshake_contexts[session_id] = context
            self._pending_handshake = context
            state = self._pki_sessions.get(session_id)
            if state:
                if public_key_pem:
                    if not state.user_public_key_pem:
                        state.user_public_key_pem = public_key_pem
                        state.handshake_public_key_pem = public_key_pem
                    else:
                        state.certificate_public_key_pem = public_key_pem
                if certificate_pem:
                    state.user_certificate_pem = certificate_pem
                updated_state = state
                self._pki_sessions[session_id] = state
                self._pki_state = state
                self._last_session_id = session_id
        if updated_state is not None:
            self._export_pki_session_state()

        return {
            "type": "cert_exchange_ack",
            "success": True,
            "sessionId": session_id,
        }

    def seed_pki_session(
        self,
        session_id: str,
        session_key_b64: str,
        *,
        pairing_token: Optional[str] = None,
        client_nonce_b64: Optional[str] = None,
        server_nonce_b64: Optional[str] = None,
        expires_at: Optional[Any] = None,
    ) -> Dict[str, Any]:
        if not session_id:
            raise ValueError("Missing sessionId for session_seed")
        if not session_key_b64:
            raise ValueError("Missing sessionKey for session_seed")
        try:
            session_key = _normalize_session_key(session_key_b64)
        except Exception as exc:  # pylint: disable=broad-except
            raise ValueError(f"Invalid session key: {exc}") from exc
        if len(session_key) not in (16, 24, 32):
            raise ValueError("Session key must be 16, 24, or 32 bytes after normalization")

        with self._pin_state_lock:
            context = self._handshake_contexts.get(session_id)
        if context is None:
            with self._pin_state_lock:
                context = self._pending_handshake
            if context and context.session_id != session_id:
                context = None
        if context is None:
            LOGGER.info("PKI session_seed received before handshake (session=%s)", session_id)
            context = PkiHandshakeContext(
                session_id=session_id,
                pairing_token=pairing_token,
                user_public_key="",
                user_certificate=None,
                vehicle_public_key=load_vehicle_keys().public_key_pem,
                vehicle_nonce=os.urandom(16),
                client_nonce=client_nonce_b64,
            )
            with self._pin_state_lock:
                self._handshake_contexts[session_id] = context
                self._pending_handshake = context

        pairing_token_candidate = pairing_token or context.pairing_token
        if pairing_token_candidate is None and self._cached_pki_payload:
            pairing_token_candidate = self._cached_pki_payload.get("pairingToken")
        if pairing_token_candidate is None and self._last_session_id == session_id and self._cached_pki_payload:
            pairing_token_candidate = self._cached_pki_payload.get("pairingToken")
        if pairing_token_candidate is None:
            pairing_token_candidate = ""

        try:
            state = PkiSessionState(
                session_id=session_id,
                pairing_token=str(pairing_token_candidate),
                user_public_key_pem=context.user_public_key,
                handshake_public_key_pem=context.user_public_key or None,
                certificate_public_key_pem=context.certificate_public_key,
                user_certificate_pem=context.user_certificate,
                vehicle_public_key_pem=context.vehicle_public_key,
                vehicle_nonce=context.vehicle_nonce,
                session_key=session_key,
            )
        except Exception as exc:  # pylint: disable=broad-except
            raise ValueError(f"Failed to construct PKI session: {exc}") from exc

        if client_nonce_b64 or context.client_nonce:
            nonce_str = client_nonce_b64 or context.client_nonce
            if nonce_str:
                try:
                    state.client_nonce = base64.b64decode(nonce_str)
                except ValueError:
                    LOGGER.debug("Ignoring invalid client nonce for session %s", session_id)
        if server_nonce_b64:
            try:
                state.vehicle_nonce = base64.b64decode(server_nonce_b64)
            except ValueError:
                LOGGER.debug("Invalid server nonce for session %s", session_id)
        state.signature_verified = True
        if expires_at is not None:
            try:
                state.established_at = float(expires_at)
            except (TypeError, ValueError):
                pass

        with self._pin_state_lock:
            self._pki_state = state
            self._pki_sessions[session_id] = state
            if self._pending_handshake and self._pending_handshake.session_id == session_id:
                self._pending_handshake = None
            self._last_session_id = session_id
            self._handshake_contexts.pop(session_id, None)
        self._export_pki_session_state()
        LOGGER.info(
            "Seeded PKI session %s (expiresAt=%s)",
            session_id,
            expires_at,
        )

        if SUPPRESS_SESSION_SEED_ACK:
            LOGGER.debug("Session seed ack suppressed for session %s", session_id)
            return None

        return {
            "type": "session_seed_ack",
            "success": True,
            "sessionId": session_id,
            "serverNonce": base64.b64encode(state.vehicle_nonce).decode("ascii"),
        }

    def recover_pki_session(
        self,
        session_id: str,
        certificate_info: Dict[str, Any],
        *,
        mark_verified: bool = False,
    ) -> Optional[PkiSessionState]:
        """Attempt to derive a PKI session using cached pairing material."""
        try:
            extracted_public_key, certificate_pem = self._extract_certificate_material(certificate_info)
        except ValueError:
            extracted_public_key = None
            certificate_pem = None

        remote_public_key = extracted_public_key or certificate_info.get("publicKey") or certificate_info.get("public_key")
        if isinstance(remote_public_key, dict):
            remote_public_key = remote_public_key.get("pem") or remote_public_key.get("data") or json.dumps(remote_public_key)
        if isinstance(remote_public_key, str):
            candidate_public_key = remote_public_key.strip()
            if candidate_public_key:
                try:
                    remote_public_key = coerce_public_key_pem(candidate_public_key)
                except Exception:  # pylint: disable=broad-except
                    remote_public_key = candidate_public_key
            else:
                remote_public_key = None
        else:
            remote_public_key = None

        if not remote_public_key:
            return None

        with self._pin_state_lock:
            template = self._pki_state
            if session_id in self._pki_sessions:
                template = self._pki_sessions[session_id]
            pin_state = self._pin_session_state

        pairing_token = None
        vehicle_public_key = None
        vehicle_nonce = None
        if template is not None:
            pairing_token = template.pairing_token
            vehicle_public_key = template.vehicle_public_key_pem
            vehicle_nonce = template.vehicle_nonce
        if pairing_token is None and pin_state is not None:
            pairing_token = pin_state.pairing_token
            if pin_state.vehicle_nonce_b64:
                try:
                    vehicle_nonce = base64.b64decode(pin_state.vehicle_nonce_b64)
                except ValueError:
                    vehicle_nonce = None
        if pairing_token is None or vehicle_nonce is None:
            cached = self._cached_pki_payload
            if cached:
                pairing_token = pairing_token or cached.get("pairingToken")
                vehicle_public_key = vehicle_public_key or cached.get("vehiclePublicKey")
                nonce_b64 = cached.get("vehicleNonce")
                if vehicle_nonce is None and nonce_b64:
                    try:
                        vehicle_nonce = base64.b64decode(nonce_b64)
                    except ValueError:
                        vehicle_nonce = None
        if pairing_token is None or vehicle_nonce is None:
            LOGGER.debug(
                "PKI session recovery failed: missing pairing token/vehicle nonce for session %s",
                session_id,
            )
            return None
        if vehicle_public_key is None:
            try:
                vehicle_public_key = load_vehicle_keys().public_key_pem
            except Exception:  # pylint: disable=broad-except
                vehicle_public_key = None
        try:
            new_state = derive_session_key(
                session_id=session_id,
                pairing_token=str(pairing_token),
                vehicle_nonce=vehicle_nonce,
                remote_public_key_pem=str(remote_public_key),
                user_certificate_pem=certificate_pem
                or certificate_info.get("pem")
                or certificate_info.get("certificate"),
            )
        except Exception:  # pylint: disable=broad-except
            return None
        if vehicle_public_key:
            new_state.vehicle_public_key_pem = vehicle_public_key
        if template and template.handshake_public_key_pem:
            new_state.handshake_public_key_pem = template.handshake_public_key_pem
            new_state.user_public_key_pem = template.handshake_public_key_pem
        if template and template.certificate_public_key_pem:
            new_state.certificate_public_key_pem = template.certificate_public_key_pem
        if mark_verified:
            new_state.signature_verified = True
        elif template and template.signature_verified:
            new_state.signature_verified = template.signature_verified
        elif self._cached_pki_payload and self._cached_pki_payload.get("signatureVerified"):
            new_state.signature_verified = True
        else:
            existing_state = self.get_pki_session_state(session_id)
            if existing_state and existing_state.signature_verified:
                new_state.signature_verified = True
        with self._pin_state_lock:
            self._pki_state = new_state
            self._pki_sessions[session_id] = new_state
            self._last_session_id = session_id
        self._export_pki_session_state()
        return new_state

    def _load_cached_pki_session(self) -> None:
        path = self._pki_export_path
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self._cached_pki_payload = data
            session_id = str(data["sessionId"])
            pairing_token = data.get("pairingToken")
            user_public_key = data.get("userPublicKey")
            handshake_public_key = data.get("handshakePublicKey") or user_public_key
            certificate_public_key = data.get("certificatePublicKey")
            vehicle_public_key = data.get("vehiclePublicKey")
            vehicle_nonce_b64 = data.get("vehicleNonce")
            session_key_b64 = data.get("sessionKey")
            if not all([session_id, pairing_token, user_public_key, vehicle_public_key, vehicle_nonce_b64, session_key_b64]):
                raise ValueError("Cached PKI session missing required fields")

            vehicle_nonce = base64.b64decode(vehicle_nonce_b64)
            session_key = base64.b64decode(session_key_b64)
            if len(session_key) != 32:
                raise ValueError("Cached session key must be 32 bytes")

            state = PkiSessionState(
                session_id=session_id,
                pairing_token=str(pairing_token),
                user_public_key_pem=str(user_public_key),
                handshake_public_key_pem=str(handshake_public_key) if handshake_public_key else None,
                certificate_public_key_pem=str(certificate_public_key) if certificate_public_key else None,
                user_certificate_pem=data.get("userCertificate"),
                vehicle_public_key_pem=str(vehicle_public_key),
                vehicle_nonce=vehicle_nonce,
                session_key=session_key,
                established_at=float(data.get("establishedAt", time.time())),
            )
            client_nonce_b64 = data.get("clientNonce")
            if client_nonce_b64:
                state.client_nonce = base64.b64decode(client_nonce_b64)
            state.signature_verified = bool(data.get("signatureVerified", False))

            with self._pin_state_lock:
                self._pki_state = state
                self._pki_sessions[session_id] = state
                self._last_session_id = session_id
            LOGGER.info("Restored cached PKI session %s from %s", session_id, path)
        except Exception as exc:  # pylint: disable=broad-except
            message = str(exc)
            if "Cached PKI session missing required fields" in message:
                LOGGER.info("Discarding stale PKI session cache at %s (%s)", path, message)
                try:
                    path.unlink(missing_ok=True)  # type: ignore[call-arg]
                except TypeError:
                    try:
                        path.unlink()
                    except OSError:
                        pass
            else:
                LOGGER.warning("Failed to restore cached PKI session state: %s", exc)
            self._cached_pki_payload = None

    def _export_pki_session_state(self) -> None:
        path = self._pki_export_path
        with self._pin_state_lock:
            state = self._pki_state
        if state is None:
            self._cached_pki_payload = None
            self._pki_sessions.clear()
            try:
                if path.exists():
                    path.unlink()
            except OSError as exc:
                LOGGER.debug("Failed to remove PKI session cache: %s", exc)
            return

        payload: Dict[str, Any] = {
            "sessionId": state.session_id,
            "pairingToken": state.pairing_token,
            "userPublicKey": state.user_public_key_pem,
            "handshakePublicKey": state.handshake_public_key_pem,
            "certificatePublicKey": state.certificate_public_key_pem,
            "userCertificate": state.user_certificate_pem,
            "vehiclePublicKey": state.vehicle_public_key_pem,
            "vehicleNonce": base64.b64encode(state.vehicle_nonce).decode("ascii"),
            "sessionKey": base64.b64encode(state.session_key).decode("ascii"),
            "signatureVerified": state.signature_verified,
            "establishedAt": state.established_at,
        }
        if state.client_nonce:
            payload["clientNonce"] = base64.b64encode(state.client_nonce).decode("ascii")

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            self._cached_pki_payload = payload
        except OSError as exc:
            LOGGER.debug("Failed to persist PKI session cache: %s", exc)

    def _is_pairing_allowed(self) -> bool:
        has_keys = bool(self.key_store.list_keys())
        if not has_keys:
            return True
        return self.pairing_flag_path.exists()

    def is_pairing_allowed(self) -> bool:
        """Public helper for consumers that need the current pairing state."""
        return self._is_pairing_allowed()

    def _disable_pairing_flag(self) -> None:
        try:
            if self.pairing_flag_path.exists():
                self.pairing_flag_path.unlink()
        except OSError as exc:
            LOGGER.debug("Failed to remove pairing flag: %s", exc)

    def enable_pairing(self) -> None:
        """Allow the next pairing challenge by creating the flag file."""
        self.pairing_flag_path.touch(exist_ok=True)

    # Internal helpers --------------------------------------------------
    def _initialize_pin_session(self, session: PairingSession) -> None:
        self._stop_pin_status_poller()
        state = PinSessionState(
            session_id=session.session_id,
            pin=session.pin,
            expires_at=session.expires_at,
            attempts_remaining=session.attempts_remaining,
            pairing_token=session.pairing_token,
            owner_candidate_user_id=session.owner_candidate_user_id,
        )
        with self._pin_state_lock:
            self._pin_session_state = state
            self._pki_state = None
            self._pki_sessions.pop(session.session_id, None)
        self._publish_pin_session_state(state)
        self._export_pki_session_state()
        self._start_pin_status_poller(session.session_id)

    def _publish_pin_session_state(self, state: Optional[PinSessionState]) -> None:
        snapshot = state.export_dict() if state else None
        try:
            if snapshot is None:
                if self._session_export_path.exists():
                    self._session_export_path.unlink()
            else:
                self._session_export_path.write_text(
                    json.dumps(snapshot, indent=2),
                    encoding="utf-8",
                )
        except OSError as exc:
            LOGGER.debug("Failed to update PIN session export: %s", exc)
        self._notify_session_observers(state)

    def _notify_session_observers(self, state: Optional[PinSessionState]) -> None:
        with self._pin_state_lock:
            callbacks = list(self._session_observers)
        for callback in callbacks:
            try:
                callback(state)
            except Exception as exc:  # pylint: disable=broad-except
                LOGGER.debug("Session observer callback failed: %s", exc)

    def _start_pin_status_poller(self, session_id: str) -> None:
        if PIN_STATUS_POLL_INTERVAL <= 0:
            LOGGER.debug("PIN status poll interval disabled; skipping status thread")
            return
        with self._pin_state_lock:
            existing_thread = self._pin_poll_thread
        if existing_thread and existing_thread.is_alive():
            LOGGER.debug("Stopping previous PIN status poller before starting new one")
            self._stop_pin_status_poller()
        self._pin_poll_stop = threading.Event()
        thread = threading.Thread(
            target=self._pin_status_poll_loop,
            args=(session_id,),
            name=f"PinStatusPoller[{session_id}]",
            daemon=True,
        )
        self._pin_poll_thread = thread
        thread.start()

    def _stop_pin_status_poller(self) -> None:
        thread = self._pin_poll_thread
        if not thread:
            return
        self._pin_poll_stop.set()
        if thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=1.5)
        self._pin_poll_thread = None
        self._pin_poll_stop = threading.Event()

    def _pin_status_poll_loop(self, session_id: str) -> None:
        LOGGER.debug("Starting PIN status poller for session %s", session_id)
        while not self._pin_poll_stop.wait(PIN_STATUS_POLL_INTERVAL):
            with self._pin_state_lock:
                state = self._pin_session_state
            if state is None or state.session_id != session_id or not state.active:
                LOGGER.debug("Stopping poller: state mismatch or inactive")
                break

            # Local expiry detection (best-effort)
            expires_at = state.expires_at
            if expires_at is not None:
                try:
                    if isinstance(expires_at, (int, float)):
                        expiry_ms = float(expires_at)
                    else:
                        expiry_ms = float(str(expires_at))
                except (TypeError, ValueError):
                    expiry_ms = None
                if expiry_ms and time.time() * 1000 >= expiry_ms:
                    LOGGER.info("PIN session %s expired locally", session_id)
                    expired_status = PinStatus(
                        session_id=session_id,
                        state="EXPIRED",
                        expires_at=expires_at,
                        attempts_remaining=state.attempts_remaining,
                        pairing_token=state.pairing_token,
                        owner_candidate_user_id=state.owner_candidate_user_id,
                        user_public_key=None,
                        user_certificate=None,
                        raw={"status": "EXPIRED", "source": "local-expiry"},
                    )
                    self._handle_pin_terminal(expired_status, cancel_remote=True)
                    break

            try:
                status = self.api_client.get_pin_status(
                    session_id=session_id,
                    header_vehicle_id=self.header_vehicle_id,
                )
            except PairingApiError as exc:
                LOGGER.debug("PIN status poll failed for session %s: %s", session_id, exc)
                continue

            self._handle_pin_status_update(status)

            if status.state in PIN_STATUS_SUCCESS_STATES | PIN_STATUS_TERMINAL_STATES:
                LOGGER.debug("Status %s is terminal for session %s", status.state, session_id)
                break
        LOGGER.debug("PIN status poller stopped for session %s", session_id)

    def _handle_pin_status_update(self, status: PinStatus) -> None:
        with self._pin_state_lock:
            state = self._pin_session_state
            if state is None or state.session_id != status.session_id:
                LOGGER.debug("Ignoring status for session %s (stale)", status.session_id)
                return
            state.update_from_status(status)
            publish_state = state

        if status.state in PIN_STATUS_SUCCESS_STATES:
            self._handle_pin_verified(status)
        elif status.state in PIN_STATUS_TERMINAL_STATES:
            self._handle_pin_terminal(status)
        else:
            self._publish_pin_session_state(publish_state)

    def _handle_pin_verified(self, status: PinStatus) -> None:
        if not status.user_public_key:
            LOGGER.warning(
                "PIN status VERIFIED for session %s but user public key is missing",
                status.session_id,
            )
            with self._pin_state_lock:
                state = self._pin_session_state
            if state:
                self._publish_pin_session_state(state)
            return

        with self._pin_state_lock:
            pin_state = self._pin_session_state
        pairing_token = status.pairing_token or (pin_state.pairing_token if pin_state else None)
        if not pairing_token:
            LOGGER.warning(
                "Pairing token unavailable when preparing PKI session for %s",
                status.session_id,
            )
            if pin_state:
                self._publish_pin_session_state(pin_state)
            return

        vehicle_nonce = os.urandom(16)
        try:
            pki_state = derive_session_key(
                session_id=status.session_id,
                pairing_token=str(pairing_token),
                vehicle_nonce=vehicle_nonce,
                remote_public_key_pem=str(status.user_public_key),
                user_certificate_pem=status.user_certificate,
            )
        except Exception as exc:  # pylint: disable=broad-except
            LOGGER.error("Failed to derive PKI session for %s: %s", status.session_id, exc)
            return

        with self._pin_state_lock:
            self._pki_state = pki_state
            self._pki_sessions[pki_state.session_id] = pki_state
            self._last_session_id = pki_state.session_id
            if self._pin_session_state and self._pin_session_state.session_id == status.session_id:
                self._pin_session_state.pairing_token = pki_state.pairing_token
                self._pin_session_state.vehicle_nonce_b64 = base64.b64encode(
                    pki_state.vehicle_nonce
                ).decode("ascii")
                self._pin_session_state.active = False
                self._pin_session_state.status = status.state or "VERIFIED"
                publish_state = self._pin_session_state
            else:
                publish_state = None
        if publish_state:
            self._publish_pin_session_state(publish_state)
        self._stop_pin_status_poller()

    def _handle_pin_terminal(self, status: PinStatus, cancel_remote: bool = False) -> None:
        with self._pin_state_lock:
            state = self._pin_session_state
            if state is None or state.session_id != status.session_id:
                LOGGER.debug("Terminal status for unknown session %s", status.session_id)
                return
            state.active = False
            state.status = status.state
            state.last_status_payload = status.raw
            publish_state = state
        self._publish_pin_session_state(publish_state)
        self._stop_pin_status_poller()

        if cancel_remote:
            self._cancel_remote_session(status.session_id)

    def _cancel_remote_session(self, session_id: str) -> None:
        try:
            self.api_client.cancel_pin_session(
                session_id=session_id,
                header_vehicle_id=self.header_vehicle_id,
            )
            LOGGER.debug("Notified backend of local cancellation for session %s", session_id)
        except PairingApiError as exc:
            LOGGER.debug("Failed to cancel session %s remotely: %s", session_id, exc)
