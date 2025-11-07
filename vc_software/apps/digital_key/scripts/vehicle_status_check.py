#!/usr/bin/env python3
"""Vehicle status API health check helper for the Raspberry Pi client."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
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
    env_url = (
        os.environ.get("VEHICLE_STATUS_BASE_URL")
        or os.environ.get("PAIRING_API_BASE_URL")
        or "http://localhost:3000"
    )
    return _ensure_scheme(env_url)


def _default_timeout() -> float:
    raw = os.environ.get("VEHICLE_STATUS_TIMEOUT") or "5"
    try:
        return float(raw)
    except ValueError:
        return 5.0


def _env_secret() -> str | None:
    secret = os.environ.get("VEHICLE_STATUS_SECRET") or os.environ.get("VEHICLE_API_SECRET")
    if secret and secret.lower() != "change-me":
        return secret
    return None


def _identity_secret(identity: Dict[str, str]) -> str | None:
    return (
        identity.get("x_vehicle_secret")
        or identity.get("vehicle_secret")
        or identity.get("secret")
    )


def _env_vehicle_id() -> str | None:
    return os.environ.get("VEHICLE_STATUS_ID") or os.environ.get("VEHICLE_DEVICE_ID")


def _choose_vehicle_id(identity: Dict[str, str], override: str | None) -> str | None:
    if override:
        return override
    env_value = _env_vehicle_id()
    if env_value:
        return env_value
    return (
        identity.get("device_id")
        or identity.get("deviceid")
        or identity.get("vehicle_id")
        or identity.get("vehicleid")
    )


def _env_header_vehicle_id() -> str | None:
    return os.environ.get("VEHICLE_STATUS_HEADER_ID") or os.environ.get("VEHICLE_STATUS_NUMERIC_ID")


def _identity_header_vehicle_id(identity: Dict[str, str]) -> str | None:
    return identity.get("x_vehicle_id") or identity.get("vehicle_header_id")


def _choose_header_vehicle_id(identity: Dict[str, str], override: str | None) -> str:
    if override:
        return override
    env_value = _env_header_vehicle_id()
    if env_value:
        return env_value
    header_value = _identity_header_vehicle_id(identity)
    if header_value:
        return header_value
    raise ValueError("Vehicle header ID is not configured")


def _build_payload(status: str, extra: Dict[str, Any]) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "status": status,
        "timestamp": int(time.time() * 1000),
    }
    payload.update(extra)
    return payload


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Call the vehicle-status API to verify headers and connectivity."
        )
    )
    parser.add_argument(
        "--method",
        choices={"post", "get"},
        default="post",
        help="HTTP method to execute (post sends status, get fetches last cached status)",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="Server base URL (defaults to VEHICLE_STATUS_BASE_URL or PAIRING_API_BASE_URL)",
    )
    parser.add_argument(
        "--identity-file",
        default=str(DEFAULT_IDENTITY_PATH),
        help="Path to the immutable vehicle_identity file",
    )
    parser.add_argument(
        "--vehicle-id",
        default=None,
        help="Device identifier to include in payload (defaults to identity/environment)",
    )
    parser.add_argument(
        "--header-vehicle-id",
        default=None,
        help="Numeric vehicle ID for x-vehicle-id header (defaults to identity/environment)",
    )
    parser.add_argument(
        "--secret",
        default=None,
        help=(
            "Vehicle secret for x-vehicle-secret header. Defaults to VEHICLE_STATUS_SECRET/"
            "VEHICLE_API_SECRET or identity file's x_vehicle_secret"
        ),
    )
    parser.add_argument(
        "--status",
        default="ONLINE",
        help="Status string to include in payload",
    )
    parser.add_argument(
        "--battery",
        type=int,
        default=None,
        help="Optional battery percentage to include in payload",
    )
    parser.add_argument(
        "--odometer",
        type=float,
        default=None,
        help="Optional odometer reading to include in payload",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="HTTP timeout in seconds (defaults to VEHICLE_STATUS_TIMEOUT or 5)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the request without sending it",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    identity_path = Path(args.identity_file)
    identity = refresh_identity(identity_path)
    if not identity:
        print(f"Identity file not found or empty: {identity_path}", file=sys.stderr)
        return 1

    device_id = _choose_vehicle_id(identity, args.vehicle_id)
    try:
        header_vehicle_id = _choose_header_vehicle_id(identity, args.header_vehicle_id)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    secret = args.secret or _env_secret() or _identity_secret(identity)
    if not secret:
        print(
            "Vehicle secret is not configured. Provide --secret, set VEHICLE_STATUS_SECRET, "
            "or add x_vehicle_secret to the identity file.",
            file=sys.stderr,
        )
        return 1

    base_url_input = args.base_url or _default_base_url()
    base_url = _ensure_scheme(base_url_input.rstrip("/"))
    timeout = args.timeout if args.timeout is not None else _default_timeout()

    payload_extra: Dict[str, Any] = {}
    if args.battery is not None:
        payload_extra["battery"] = args.battery
    if args.odometer is not None:
        payload_extra["odometer"] = args.odometer

    payload = _build_payload(args.status, payload_extra)
    if device_id:
        payload.setdefault("deviceId", device_id)

    url = f"{base_url}/api/vehicle-status"
    headers = {
        "x-vehicle-id": str(header_vehicle_id),
        "x-vehicle-secret": secret,
    }

    method = args.method.lower()

    if args.dry_run:
        print("--- Dry run ---")
        print(f"{method.upper()} {url}")
        print("Headers:")
        print(json.dumps(headers, indent=2))
        if method == "post":
            print("Payload:")
            print(json.dumps(payload, indent=2))
        else:
            print("Payload: <none>")
        return 0

    try:
        if method == "get":
            response = requests.get(
                url,
                headers=headers,
                timeout=timeout,
            )
        else:
            response = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=timeout,
            )
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    print(f"Response status: {response.status_code}")
    try:
        body = response.json()
        print(json.dumps(body, indent=2))
    except ValueError:
        print(response.text)
    return 0 if response.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
