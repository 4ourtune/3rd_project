"""HTTP client for server-mediated pairing PIN sessions."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import requests
from requests import RequestException

from .identity import get_identity_value, load_env_defaults

load_env_defaults()

LOGGER = logging.getLogger(__name__)

DEFAULT_BASE_URL = os.environ.get("PAIRING_API_BASE_URL", "http://localhost:3000")

_PLACEHOLDER_SECRETS = {"change-me", "change_me", "dev-secret", "dev_secret"}


def _resolve_vehicle_secret() -> Optional[str]:
    for env_var in ("VEHICLE_API_SECRET", "VEHICLE_STATUS_SECRET"):
        candidate = os.environ.get(env_var)
        if candidate and candidate.strip().lower() not in _PLACEHOLDER_SECRETS:
            return candidate.strip()
    identity_secret = get_identity_value("x_vehicle_secret")
    if identity_secret:
        return identity_secret
    return None


def _resolve_header_vehicle_id() -> Optional[str]:
    for env_var in (
        "VEHICLE_STATUS_HEADER_ID",
        "VEHICLE_STATUS_NUMERIC_ID",
        "VEHICLE_HEADER_ID",
        "VEHICLE_ID_NUMERIC",
    ):
        candidate = os.environ.get(env_var)
        if candidate:
            return candidate
    identity_header = get_identity_value("x_vehicle_id")
    if identity_header:
        return identity_header
    return None


DEFAULT_VEHICLE_SECRET = _resolve_vehicle_secret()
DEFAULT_HEADER_VEHICLE_ID = _resolve_header_vehicle_id()
DEFAULT_TIMEOUT = float(os.environ.get("PAIRING_API_TIMEOUT", "5"))


class PairingApiError(RuntimeError):
    """Raised when the pairing API returns an error response."""


@dataclass(slots=True)
class PairingSession:
    session_id: str
    pin: str
    expires_at: Any
    attempts_remaining: Optional[int] = None
    pairing_token: Optional[str] = None
    owner_candidate_user_id: Optional[Any] = None
    payload: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PinStatus:
    session_id: str
    state: str
    expires_at: Any
    attempts_remaining: Optional[int]
    pairing_token: Optional[str]
    owner_candidate_user_id: Optional[Any]
    user_public_key: Optional[str]
    user_certificate: Optional[str]
    raw: Dict[str, Any] = field(default_factory=dict)


def _ensure_scheme(url: str) -> str:
    if url.startswith("http://") or url.startswith("https://"):
        return url
    LOGGER.warning("PAIRING_API_BASE_URL missing scheme; defaulting to http://")
    return f"http://{url}"


class PairingApiClient:
    """Simple wrapper around the pairing REST endpoints used by the vehicle."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        vehicle_secret: Optional[str] = DEFAULT_VEHICLE_SECRET,
        timeout: float = DEFAULT_TIMEOUT,
        vehicle_header_id: Optional[str] = DEFAULT_HEADER_VEHICLE_ID,
    ) -> None:
        normalized_base = _ensure_scheme(base_url)
        self.base_url = normalized_base.rstrip("/")
        self.vehicle_secret = vehicle_secret
        self.timeout = timeout
        self.vehicle_header_id = vehicle_header_id

    # Vehicle endpoints -------------------------------------------------
    def request_pin(
        self,
        header_vehicle_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> PairingSession:
        """POST /api/device/pairing/pin to create a new PIN session."""
        url = f"{self.base_url}/api/device/pairing/pin"
        headers = self._vehicle_headers(header_vehicle_id)
        body = payload or {}
        LOGGER.info("Requesting pairing PIN (vehicle header id=%s)", headers["x-vehicle-id"])
        try:
            response = requests.post(
                url,
                headers=headers,
                json=body,
                timeout=self.timeout,
            )
        except RequestException as exc:
            raise PairingApiError(f"Failed to contact pairing API: {exc}") from exc
        data = self._parse_response(response)
        try:
            session_id = str(data["sessionId"])
            pin = str(data["pin"])
            expires_at = data.get("expiresAt")
            attempts_remaining = data.get("attemptsRemaining")
            pairing_token = data.get("pairingToken")
            owner_candidate_user_id = data.get("ownerCandidateUserId")
        except KeyError as exc:
            raise PairingApiError(f"Missing required field in PIN response: {exc}") from exc
        LOGGER.info("Received pairing PIN %s (session %s)", pin, session_id)
        return PairingSession(
            session_id=session_id,
            pin=pin,
            expires_at=expires_at,
            attempts_remaining=attempts_remaining,
            pairing_token=pairing_token,
            owner_candidate_user_id=owner_candidate_user_id,
            payload=data,
        )

    def get_session(
        self,
        session_id: str,
        header_vehicle_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /api/device/pairing/session/:sessionId to inspect current state."""
        url = f"{self.base_url}/api/device/pairing/session/{session_id}"
        headers = self._vehicle_headers(header_vehicle_id)
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
        except RequestException as exc:
            raise PairingApiError(f"Failed to contact pairing API: {exc}") from exc
        return self._parse_response(response)

    def get_pin_status(
        self,
        session_id: str,
        header_vehicle_id: Optional[str] = None,
    ) -> PinStatus:
        """GET /api/device/pairing/pin/status to poll for PIN lifecycle events."""
        url = f"{self.base_url}/api/device/pairing/pin/status"
        headers = self._vehicle_headers(header_vehicle_id)
        params = {"sessionId": session_id}
        try:
            response = requests.get(url, headers=headers, params=params, timeout=self.timeout)
        except RequestException as exc:
            raise PairingApiError(f"Failed to contact pairing API: {exc}") from exc
        data = self._parse_response(response)
        state = str(data.get("status") or data.get("state") or "UNKNOWN").upper()
        return PinStatus(
            session_id=session_id,
            state=state,
            expires_at=data.get("expiresAt"),
            attempts_remaining=data.get("attemptsRemaining"),
            pairing_token=data.get("pairingToken"),
            owner_candidate_user_id=data.get("ownerCandidateUserId"),
            user_public_key=data.get("userPublicKey"),
            user_certificate=data.get("userCertificate"),
            raw=data,
        )

    def cancel_pin_session(
        self,
        session_id: str,
        header_vehicle_id: Optional[str] = None,
    ) -> None:
        """POST /api/device/pairing/pin/cancel to notify backend of local cancellation."""
        url = f"{self.base_url}/api/device/pairing/pin/cancel"
        headers = self._vehicle_headers(header_vehicle_id)
        payload = {"sessionId": session_id}
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        except RequestException as exc:
            raise PairingApiError(f"Failed to contact pairing API: {exc}") from exc
        self._parse_response(response)

    def fetch_keys(self, header_vehicle_id: Optional[str] = None) -> Dict[str, Any]:
        """GET /api/device/keys to synchronize digital key metadata."""
        url = f"{self.base_url}/api/device/keys"
        headers = self._vehicle_headers(header_vehicle_id)
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
        except RequestException as exc:
            raise PairingApiError(f"Failed to contact pairing API for keys: {exc}") from exc
        data = self._parse_response(response)
        if "keys" not in data or not isinstance(data["keys"], list):
            raise PairingApiError("Key sync response missing 'keys' list")
        return data

    # Helpers -----------------------------------------------------------
    def _vehicle_headers(self, header_vehicle_id: Optional[str] = None) -> Dict[str, str]:
        vehicle_id = header_vehicle_id or self.vehicle_header_id
        if not vehicle_id:
            raise PairingApiError("Vehicle header ID is not configured")
        if not self.vehicle_secret:
            raise PairingApiError("VEHICLE_API_SECRET is not configured")
        return {
            "x-vehicle-secret": self.vehicle_secret,
            "x-vehicle-id": str(vehicle_id),
            "Content-Type": "application/json",
        }

    @staticmethod
    def _parse_response(response: requests.Response) -> Dict[str, Any]:
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise PairingApiError(f"Pairing API error: {exc}") from exc
        try:
            return response.json()
        except ValueError as exc:  # includes JSONDecodeError
            raise PairingApiError(f"Failed to decode pairing API response: {exc}") from exc


def build_client(
    base_url: Optional[str] = None,
    vehicle_secret: Optional[str] = None,
    timeout: Optional[float] = None,
    vehicle_header_id: Optional[str] = None,
) -> PairingApiClient:
    """Factory that allows optional overrides while keeping env defaults."""
    return PairingApiClient(
        base_url=base_url or DEFAULT_BASE_URL,
        vehicle_secret=vehicle_secret or DEFAULT_VEHICLE_SECRET,
        timeout=timeout or DEFAULT_TIMEOUT,
        vehicle_header_id=vehicle_header_id or DEFAULT_HEADER_VEHICLE_ID,
    )
