"""Certificate provider utilities for BLE command responses."""
from __future__ import annotations

import base64
import logging
import os
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from ssl import PEM_cert_to_DER_cert
from threading import Lock
from typing import Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .config import PROJECT_ROOT, resolve_path
from .identity import get_identity_value


LOGGER = logging.getLogger(__name__)

DEFAULT_CERT_PATH = "/opt/dks/certs/device_cert.pem"
ENV_CERT_PATH = "VEHICLE_CERT_PATH"
ENV_CERT_VERSION = "VEHICLE_CERT_VERSION"


@dataclass(frozen=True)
class CertificatePayload:
    """Structured certificate response consumable by BLE clients."""

    payload: Dict[str, str]


class CertificateProvider:
    """Abstract interface for certificate providers."""

    def get_certificate_payload(self) -> CertificatePayload:
        raise NotImplementedError


class StaticPemProvider(CertificateProvider):
    """Load a pre-issued PEM certificate and expose it as base64 DER."""

    def __init__(self, cert_path: Path, version: int) -> None:
        self.cert_path = cert_path
        self.version = version
        self._lock = Lock()
        self._cached_payload: Optional[CertificatePayload] = None

    def get_certificate_payload(self) -> CertificatePayload:
        with self._lock:
            if self._cached_payload is None:
                self._cached_payload = self._load_payload()
            return self._cached_payload

    def _load_payload(self) -> CertificatePayload:
        try:
            pem_text = self.cert_path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"Certificate PEM not found at {self.cert_path}") from exc

        der_bytes = PEM_cert_to_DER_cert(pem_text)
        fingerprint = sha256(der_bytes).hexdigest()
        certificate_b64 = base64.b64encode(der_bytes).decode("ascii")

        cert_obj = x509.load_der_x509_certificate(der_bytes)
        subject = cert_obj.subject.rfc4514_string()
        issuer = cert_obj.issuer.rfc4514_string()
        serial_hex = format(cert_obj.serial_number, "x")
        try:
            not_before = cert_obj.not_valid_before_utc.isoformat()
        except AttributeError:
            not_before = cert_obj.not_valid_before.replace(tzinfo=None).isoformat()
        try:
            not_after = cert_obj.not_valid_after_utc.isoformat()
        except AttributeError:
            not_after = cert_obj.not_valid_after.replace(tzinfo=None).isoformat()
        public_key_pem = cert_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        signature_b64 = base64.b64encode(cert_obj.signature).decode("ascii")

        vehicle_id = get_identity_value("x_vehicle_id") or os.environ.get("VEHICLE_HEADER_ID")
        device_id = get_identity_value("device_id") or os.environ.get("VEHICLE_DEVICE_ID")
        certificate_info = {
            "id": fingerprint,
            "subject": subject,
            "issuer": issuer,
            "serialNumber": serial_hex,
            "notBefore": not_before,
            "notAfter": not_after,
            "publicKey": public_key_pem,
            "signature": signature_b64,
            "certificate": certificate_b64,
            "fingerprint": fingerprint,
            "version": self.version,
            "vehicleId": vehicle_id,
            "deviceId": device_id,
            "capabilities": ["REMOTE_UNLOCK", "REMOTE_LOCK", "REMOTE_START"],
        }

        payload = {
            "type": "cert_response",
            "version": str(self.version),
            "certificate": certificate_info,
        }
        LOGGER.debug(
            "Loaded certificate payload (version=%s, fingerprint=%s, path=%s)",
            self.version,
            fingerprint,
            self.cert_path,
        )
        return CertificatePayload(payload=payload)


def build_static_provider_from_env() -> Optional[StaticPemProvider]:
    """Create a static provider using environment defaults, or None if unavailable."""
    cert_path_str = os.environ.get(ENV_CERT_PATH, DEFAULT_CERT_PATH)
    cert_path = resolve_path(cert_path_str, fallback_root=PROJECT_ROOT)
    version_raw = os.environ.get(ENV_CERT_VERSION, "1")
    try:
        version = int(version_raw)
    except ValueError:
        LOGGER.warning(
            "Invalid VEHICLE_CERT_VERSION=%s; defaulting to 1",
            version_raw,
        )
        version = 1

    if not cert_path.exists():
        LOGGER.warning("Certificate PEM not found at %s; cert_request will be disabled", cert_path)
        return None
    try:
        mode = cert_path.stat().st_mode
    except OSError as exc:
        LOGGER.warning("Unable to stat certificate PEM at %s: %s", cert_path, exc)
        return None
    if mode & 0o077:
        LOGGER.warning(
            "Certificate PEM at %s has permissive permissions; expected 600",
            cert_path,
        )

    try:
        provider = StaticPemProvider(cert_path=cert_path, version=version)
        # Prime the cache to fail fast on startup.
        provider.get_certificate_payload()
        return provider
    except Exception as exc:  # pylint: disable=broad-except
        LOGGER.error("Failed to initialize certificate provider: %s", exc)
        return None


__all__ = [
    "CertificatePayload",
    "CertificateProvider",
    "StaticPemProvider",
    "build_static_provider_from_env",
]
