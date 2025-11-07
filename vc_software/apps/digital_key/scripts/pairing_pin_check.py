#!/usr/bin/env python3
"""CLI helper to request pairing PIN codes from the backend."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import requests

from digital_key.identity import load_env_defaults, refresh_identity

DEFAULT_IDENTITY_PATH = PROJECT_ROOT / "vehicle_identity.txt"
DEFAULT_ENV_PATH = PROJECT_ROOT / ".env"

load_env_defaults(DEFAULT_ENV_PATH)


def _ensure_scheme(url: str) -> str:
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return f"http://{url}"


def _default_base_url() -> str:
    env_url = os.environ.get("PAIRING_API_BASE_URL") or "http://localhost:3000"
    return _ensure_scheme(env_url)


def _sanitize_secret(value: str | None) -> str | None:
    if not value:
        return None
    lowered = value.strip().lower()
    if lowered in {"change-me", "change_me", "dev-secret", "dev_secret"}:
        return None
    return value


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Request a pairing PIN via POST /api/device/pairing/pin",
    )
    parser.add_argument("--base-url", default=None, help="Server base URL")
    parser.add_argument(
        "--identity-file",
        default=str(DEFAULT_IDENTITY_PATH),
        help="Path to the vehicle identity file",
    )
    parser.add_argument(
        "--header-vehicle-id",
        default=None,
        help="Numeric x-vehicle-id header (defaults to identity/environment)",
    )
    parser.add_argument(
        "--device-id",
        default=None,
        help="Logical deviceId to include in payload (defaults to identity/environment)",
    )
    parser.add_argument(
        "--secret",
        default=None,
        help=(
            "Vehicle secret for x-vehicle-secret header. Defaults to VEHICLE_API_SECRET/"
            "VEHICLE_STATUS_SECRET or identity x_vehicle_secret"
        ),
    )
    parser.add_argument(
        "--owner-candidate",
        default=None,
        help="Optional ownerCandidateUserId to include in payload",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("PAIRING_API_TIMEOUT", "5")),
        help="HTTP timeout in seconds",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print request details without sending",
    )
    parser.add_argument(
        "--seed-session",
        action="store_true",
        help="After PIN verification, seed PKI session state so BLE commands can proceed",
    )
    parser.add_argument(
        "--seed-export",
        default=str((Path(__file__).resolve().parents[1] / "logs" / "pki_session_seed.json")),
        help="Where to write seeded session summary (used with --seed-session)",
    )
    parser.add_argument(
        "--skip-pin",
        action="store_true",
        help="Skip PIN request if the server reports the vehicle is already registered",
    )
    return parser.parse_args(argv)


def _choose_header_vehicle_id(identity: Dict[str, str], override: str | None) -> str:
    if override:
        return override
    env_value = (
        os.environ.get("VEHICLE_STATUS_HEADER_ID")
        or os.environ.get("VEHICLE_STATUS_NUMERIC_ID")
        or os.environ.get("VEHICLE_HEADER_ID")
    )
    if env_value:
        return env_value
    identity_value = identity.get("x_vehicle_id")
    if identity_value:
        return identity_value
    raise ValueError("x-vehicle-id header is not configured")


def _choose_device_id(identity: Dict[str, str], override: str | None) -> str | None:
    if override:
        return override
    env_value = os.environ.get("VEHICLE_DEVICE_ID")
    if env_value:
        return env_value
    return identity.get("device_id")


def _choose_secret(identity: Dict[str, str], override: str | None) -> str:
    candidates = [override, os.environ.get("VEHICLE_API_SECRET"), os.environ.get("VEHICLE_STATUS_SECRET"), identity.get("x_vehicle_secret")]
    for candidate in candidates:
        secret = _sanitize_secret(candidate)
        if secret:
            return secret
    raise ValueError("Vehicle secret is not configured")


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    identity_path = Path(args.identity_file)
    identity = refresh_identity(identity_path)
    if not identity:
        print(f"Identity file not found or empty: {identity_path}", file=sys.stderr)
        return 1

    try:
        header_vehicle_id = _choose_header_vehicle_id(identity, args.header_vehicle_id)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    device_id = _choose_device_id(identity, args.device_id)
    try:
        secret = _choose_secret(identity, args.secret)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    base_url_input = args.base_url or _default_base_url()
    base_url = _ensure_scheme(base_url_input.rstrip("/"))

    payload: Dict[str, Any] = {
        "vehicleId": header_vehicle_id,
    }
    if device_id:
        payload["deviceId"] = device_id
    if args.owner_candidate is not None:
        payload["ownerCandidateUserId"] = args.owner_candidate

    url = f"{base_url}/api/device/pairing/pin"
    headers = {
        "x-vehicle-id": str(header_vehicle_id),
        "x-vehicle-secret": secret,
        "Content-Type": "application/json",
    }

    if args.dry_run:
        print("--- Dry run ---")
        print(f"POST {url}")
        print("Headers:")
        print(json.dumps(headers, indent=2))
        print("Payload:")
        print(json.dumps(payload, indent=2))
        return 0

    print("Requesting PIN with:")
    print(f"  vehicleId (header/payload): {header_vehicle_id}")
    if device_id:
        print(f"  deviceId: {device_id}")
    else:
        print("  deviceId: <omitted>")

    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=args.timeout,
        )
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    print(f"Response status: {response.status_code}")
    try:
        data = response.json()
        print(json.dumps(data, indent=2))
    except ValueError:
        print(response.text)
    return 0 if response.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
