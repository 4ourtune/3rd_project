"""PKI helpers for mutual-authenticated BLE command flows."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import PROJECT_ROOT, resolve_path

LOGGER = logging.getLogger(__name__)

DEFAULT_KEY_PATH = "/opt/dks/keys/vehicle_private.pem"
ENV_KEY_PATH = "VEHICLE_KEY_PATH"
ENV_KEY_PASSWORD = "VEHICLE_KEY_PASSWORD"

HKDF_INFO_PREFIX = b"digital-key-session"
GCM_IV_SIZE = 12
GCM_TAG_SIZE = 16
SESSION_KEY_BYTES = 32


@dataclass(frozen=True)
class VehicleKeyMaterial:
    """Vehicle-side keypair cached for ECDH derivations."""

    private_key: ec.EllipticCurvePrivateKey
    public_key_pem: str


@dataclass
class PkiSessionState:
    """Runtime PKI session details derived after PIN validation."""

    session_id: str
    pairing_token: str
    user_public_key_pem: str
    vehicle_public_key_pem: str
    vehicle_nonce: bytes
    session_key: bytes
    user_certificate_pem: Optional[str] = None
    handshake_public_key_pem: Optional[str] = None
    certificate_public_key_pem: Optional[str] = None
    established_at: float = field(default_factory=time.time)
    client_nonce: Optional[bytes] = None
    signature_verified: bool = False

    def export_dict(self) -> Dict[str, str]:
        """Expose non-sensitive material for BLE characteristics/logging."""
        return {
            "sessionId": self.session_id,
            "pairingToken": self.pairing_token,
            "vehiclePublicKey": self.vehicle_public_key_pem,
            "vehicleNonce": base64.b64encode(self.vehicle_nonce).decode("ascii"),
            "clientNonce": (
                base64.b64encode(self.client_nonce).decode("ascii") if self.client_nonce else None
            ),
            "signatureVerified": self.signature_verified,
            "handshakePublicKey": self.handshake_public_key_pem,
            "certificatePublicKey": self.certificate_public_key_pem,
        }


_VEHICLE_KEY_CACHE: Optional[VehicleKeyMaterial] = None


def load_vehicle_keys(
    path: Optional[str | Path] = None,
    password: Optional[str] = None,
) -> VehicleKeyMaterial:
    """Load and cache the vehicle's EC private key from disk."""
    global _VEHICLE_KEY_CACHE  # pylint: disable=global-statement
    if _VEHICLE_KEY_CACHE is not None:
        return _VEHICLE_KEY_CACHE

    configured = path or os.environ.get(ENV_KEY_PATH, DEFAULT_KEY_PATH)
    resolved_path = resolve_path(configured, fallback_root=PROJECT_ROOT)
    try:
        key_bytes = resolved_path.read_bytes()
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"Vehicle private key PEM not found at {resolved_path}. "
            "Set VEHICLE_KEY_PATH or provision a keypair."
        ) from exc

    password_bytes = password.encode("utf-8") if password else None
    if password_bytes is None:
        env_password = os.environ.get(ENV_KEY_PASSWORD)
        password_bytes = env_password.encode("utf-8") if env_password else None

    private_key = serialization.load_pem_private_key(key_bytes, password=password_bytes)
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    _VEHICLE_KEY_CACHE = VehicleKeyMaterial(private_key=private_key, public_key_pem=public_pem)
    return _VEHICLE_KEY_CACHE


def _load_remote_public_key(data: str) -> ec.EllipticCurvePublicKey:
    try:
        return serialization.load_pem_public_key(data.encode("utf-8"))
    except ValueError:
        # Attempt DER/base64 fallback.
        try:
            der = base64.b64decode(data, validate=True)
        except (ValueError, TypeError) as exc:
            hex_candidate = data.strip().lower()
            if len(hex_candidate) % 2 == 0:
                try:
                    raw = binascii.unhexlify(hex_candidate)
                except (binascii.Error, ValueError) as exc2:  # hex decode failed
                    raise ValueError("Unable to decode remote public key material") from exc2
                else:
                    if raw and raw[0] != 0x04:
                        raw = b"\x04" + raw
                    try:
                        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
                    except ValueError as exc3:
                        raise ValueError("Failed to parse hex-encoded public key") from exc3
            raise ValueError("Unable to decode remote public key material") from exc
        return serialization.load_der_public_key(der)


def derive_session_key(
    session_id: str,
    pairing_token: str,
    vehicle_nonce: bytes,
    remote_public_key_pem: str,
    user_certificate_pem: Optional[str] = None,
) -> PkiSessionState:
    """Perform ECDH and HKDF to build a PKI session state."""
    vehicle_keys = load_vehicle_keys()
    remote_public_key = _load_remote_public_key(remote_public_key_pem)
    shared_secret = vehicle_keys.private_key.exchange(ec.ECDH(), remote_public_key)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_BYTES,
        salt=pairing_token.encode("utf-8"),
        info=HKDF_INFO_PREFIX + vehicle_nonce,
    )
    session_key = hkdf.derive(shared_secret)
    session_state = PkiSessionState(
        session_id=session_id,
        pairing_token=pairing_token,
        user_public_key_pem=remote_public_key_pem,
        handshake_public_key_pem=remote_public_key_pem,
        user_certificate_pem=user_certificate_pem,
        vehicle_public_key_pem=vehicle_keys.public_key_pem,
        vehicle_nonce=vehicle_nonce,
        session_key=session_key,
    )
    return session_state


def finalize_session_state(
    state: PkiSessionState,
    client_nonce_b64: Optional[str],
    signature_b64: Optional[str],
    *,
    signed_payload: Optional[Dict[str, Any]] = None,
) -> None:
    """Attach handshake metadata and optionally verify the client's signature."""
    if client_nonce_b64:
        state.client_nonce = base64.b64decode(client_nonce_b64)

    if signature_b64:
        candidate_keys = []
        if state.handshake_public_key_pem:
            candidate_keys.append(state.handshake_public_key_pem)
        if state.user_public_key_pem and state.user_public_key_pem not in candidate_keys:
            candidate_keys.append(state.user_public_key_pem)
        if state.certificate_public_key_pem and state.certificate_public_key_pem not in candidate_keys:
            candidate_keys.append(state.certificate_public_key_pem)

        signature = _decode_signature_value(signature_b64)
        if signed_payload is not None:
            message = _serialize_signed_payload(state, signed_payload)
        else:
            message = state.vehicle_nonce + (state.client_nonce or b"")

        for key_material in candidate_keys or [state.user_public_key_pem]:
            try:
                remote_public_key = _load_remote_public_key(key_material)
                remote_public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
                state.signature_verified = True
                if key_material:
                    if not state.handshake_public_key_pem:
                        state.handshake_public_key_pem = key_material
                        state.user_public_key_pem = key_material
                    elif (
                        state.handshake_public_key_pem
                        and state.handshake_public_key_pem.strip() != key_material.strip()
                    ):
                        state.certificate_public_key_pem = key_material
                break
            except InvalidSignature:
                continue
        else:
            raise ValueError("Client signature verification failed")


def decrypt_payload(
    session_key: bytes | str,
    encrypted_payload_b64: str,
    nonce_b64: Optional[str] = None,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Decrypt a payload preferring AES-GCM, with legacy Salted__ fallback."""
    key_bytes = _normalize_session_key(session_key)
    payload_bytes = base64.b64decode(encrypted_payload_b64)
    if payload_bytes.startswith(b"Salted__"):
        return _decrypt_openssl_salted(payload_bytes, key_bytes)

    explicit_nonce = _decode_nonce(nonce_b64) if nonce_b64 else None
    return decrypt_payload_gcm(
        key_bytes,
        payload_bytes,
        nonce=explicit_nonce,
        associated_data=associated_data,
    )


def encrypt_payload(
    session_key: bytes | str,
    plaintext: bytes,
    associated_data: Optional[bytes] = None,
    *,
    include_nonce_inline: bool = False,
) -> Dict[str, str]:
    """Encrypt data with AES-GCM and serialize for BLE responses."""
    key_bytes = _normalize_session_key(session_key)
    return encrypt_payload_gcm(
        key_bytes,
        plaintext,
        associated_data=associated_data,
        emit_legacy_nonce=not include_nonce_inline,
    )


def _normalize_session_key(key: bytes | str) -> bytes:
    if isinstance(key, bytes):
        return key
    key_str = key.strip()
    try:
        if len(key_str) % 2 == 0 and all(ch in "0123456789abcdefABCDEF" for ch in key_str):
            return bytes.fromhex(key_str)
    except ValueError:
        pass
    return hashlib.sha256(key_str.encode("utf-8")).digest()


def _decode_nonce(nonce_value: str | bytes) -> bytes:
    if isinstance(nonce_value, bytes):
        text = nonce_value.decode("utf-8")
    else:
        text = str(nonce_value)
    text = text.strip()
    hex_chars = set("0123456789abcdefABCDEF")
    if len(text) % 2 == 0 and all(ch in hex_chars for ch in text):
        return binascii.unhexlify(text)
    return base64.b64decode(text)


def encrypt_payload_gcm(
    key_bytes: bytes,
    plaintext: bytes,
    *,
    associated_data: Optional[bytes] = None,
    emit_legacy_nonce: bool = False,
    nonce: Optional[bytes] = None,
) -> Dict[str, str]:
    aesgcm = AESGCM(key_bytes)
    nonce_bytes = nonce or os.urandom(GCM_IV_SIZE)
    ciphertext = aesgcm.encrypt(nonce_bytes, plaintext, associated_data)
    payload: Dict[str, str] = {
        "encryptedPayload": base64.b64encode(nonce_bytes + ciphertext).decode("ascii"),
    }
    if emit_legacy_nonce:
        payload["nonce"] = base64.b64encode(nonce_bytes).decode("ascii")
    return payload


def decrypt_payload_gcm(
    key_bytes: bytes,
    payload: bytes,
    *,
    nonce: Optional[bytes] = None,
    associated_data: Optional[bytes] = None,
) -> bytes:
    if len(payload) < GCM_IV_SIZE + GCM_TAG_SIZE:
        raise ValueError("Ciphertext too short for AES-GCM payload")
    iv = payload[:GCM_IV_SIZE]
    ciphertext = payload[GCM_IV_SIZE:]
    if nonce is not None and nonce != iv:
        if len(nonce) == GCM_IV_SIZE:
            LOGGER.debug(
                "Using provided nonce overriding embedded IV (provided=%s embedded=%s)",
                nonce.hex(),
                iv.hex(),
            )
            iv = nonce
        else:
            LOGGER.debug(
                "Ignoring provided nonce with unexpected length (len=%d, expected=%d)",
                len(nonce),
                GCM_IV_SIZE,
            )
    aesgcm = AESGCM(key_bytes)
    return aesgcm.decrypt(iv, ciphertext, associated_data)


def _decode_signature_value(value: str) -> bytes:
    """Decode signature material provided as base64 or hexadecimal."""
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("Client signature is empty")
    hex_chars = "0123456789abcdefABCDEF"
    if all(ch in hex_chars for ch in cleaned) and len(cleaned) % 2 == 0:
        try:
            return binascii.unhexlify(cleaned)
        except (binascii.Error, ValueError):
            pass
    try:
        normalized = cleaned
        remainder = len(normalized) % 4
        if remainder:
            normalized += "=" * (4 - remainder)
        return base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("Client signature is not valid base64 or hex")


def _serialize_signed_payload(state: PkiSessionState, payload: Dict[str, Any]) -> bytes:
    session_id = str(payload.get("sessionId") or payload.get("session_id") or state.session_id)
    encrypted_payload = payload.get("encryptedPayload") or payload.get("encrypted_payload")
    if encrypted_payload is None:
        raise ValueError("Signed payload missing encryptedPayload")
    timestamp = payload.get("timestamp") or payload.get("timestamp_ms")
    if timestamp is None:
        raise ValueError("Signed payload missing timestamp")
    ordered_payload: Dict[str, Any] = {
        "sessionId": session_id,
        "encryptedPayload": str(encrypted_payload),
    }
    nonce = payload.get("nonce")
    if nonce is not None:
        ordered_payload["nonce"] = str(nonce)
    ordered_payload["timestamp"] = timestamp
    return json.dumps(ordered_payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def coerce_public_key_pem(public_key_material: str) -> str:
    """Normalize remote public key material into a PEM string."""
    key = _load_remote_public_key(public_key_material)
    return (
        key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


def sign_vehicle_response(
    session_id: str,
    encrypted_payload_b64: str,
    *,
    timestamp_ms: int,
    nonce_b64: Optional[str] = None,
) -> str:
    """Sign a PKI response envelope with the vehicle's private key."""
    vehicle_keys = load_vehicle_keys()
    message_parts = [
        session_id.encode("utf-8"),
        str(timestamp_ms).encode("ascii"),
        encrypted_payload_b64.encode("ascii"),
    ]
    if nonce_b64:
        message_parts.append(nonce_b64.encode("ascii"))
    message = b"\n".join(message_parts)
    signature = vehicle_keys.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode("ascii")


def _decrypt_openssl_salted(data: bytes, key_bytes: bytes) -> bytes:
    salt = data[8:16]
    ciphertext = data[16:]
    passphrase = base64.b64encode(key_bytes)
    d = b""
    prev = b""
    while len(d) < 48:
        prev = hashlib.md5(prev + passphrase + salt).digest()
        d += prev
    key = d[:32]
    iv = d[32:48]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = plaintext[-1]
    if not 1 <= pad_len <= 16:
        raise ValueError("Invalid padding in salted payload")
    return plaintext[:-pad_len]


__all__ = [
    "PkiSessionState",
    "VehicleKeyMaterial",
    "decrypt_payload",
    "derive_session_key",
    "encrypt_payload",
    "encrypt_payload_gcm",
    "decrypt_payload_gcm",
    "finalize_session_state",
    "coerce_public_key_pem",
    "load_vehicle_keys",
    "sign_vehicle_response",
]
