#!/usr/bin/env python3
"""Manually seed a PKI session on the Raspberry Pi for BLE testing."""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from digital_key.identity import load_env_defaults
from digital_key.key_store import KeyStore
from digital_key.pki import PkiSessionState, load_vehicle_keys
from digital_key.pairing import PairingManager

DEFAULT_ENV_PATH = PROJECT_ROOT / ".env"
DEFAULT_SESSION_EXPORT = PROJECT_ROOT / "logs" / "pki_session_seed.json"

load_env_defaults(DEFAULT_ENV_PATH)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Seed a PKI session for the BLE server without running the full pairing flow.",
    )
    parser.add_argument("session_id", help="Session identifier to seed")
    parser.add_argument("pairing_token", help="Pairing token associated with the session")
    parser.add_argument(
        "--user-public-key",
        required=True,
        help="Base64 or PEM encoded user public key",
    )
    parser.add_argument(
        "--vehicle-nonce",
        required=True,
        help="Base64 encoded vehicle nonce",
    )
    parser.add_argument(
        "--session-key",
        required=True,
        help="Base64 encoded session key (32 bytes)",
    )
    parser.add_argument(
        "--vehicle-public-key",
        default=None,
        help="Vehicle public key PEM (defaults to local key)",
    )
    parser.add_argument(
        "--export",
        default=str(DEFAULT_SESSION_EXPORT),
        help="Path to write session summary (default: logs/pki_session_seed.json)",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    key_store = KeyStore()
    manager = PairingManager(key_store)

    try:
        vehicle_keys = load_vehicle_keys()
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Failed to load vehicle keys: {exc}", file=sys.stderr)
        return 1

    vehicle_public_key = args.vehicle_public_key or vehicle_keys.public_key_pem
    if not vehicle_public_key:
        print("Vehicle public key not available", file=sys.stderr)
        return 1

    try:
        session_key = base64.b64decode(args.session_key)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Invalid session key base64: {exc}", file=sys.stderr)
        return 1

    if len(session_key) != 32:
        print("Session key must be 32 bytes", file=sys.stderr)
        return 1

    try:
        vehicle_nonce = base64.b64decode(args.vehicle_nonce)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Invalid vehicle nonce base64: {exc}", file=sys.stderr)
        return 1

    session_state = PkiSessionState(
        session_id=args.session_id,
        pairing_token=args.pairing_token,
        user_public_key_pem=args.user_public_key,
        handshake_public_key_pem=args.user_public_key,
        certificate_public_key_pem=None,
        user_certificate_pem=None,
        vehicle_public_key_pem=vehicle_public_key,
        vehicle_nonce=vehicle_nonce,
        session_key=session_key,
    )
    session_state.signature_verified = True

    manager._pki_state = session_state  # pylint: disable=protected-access
    manager._publish_pin_session_state(None)
    manager._export_pki_session_state()  # pylint: disable=protected-access

    export_path = Path(args.export)
    try:
        export_path.parent.mkdir(parents=True, exist_ok=True)
        export_path.write_text(
            json.dumps({
                "sessionId": session_state.session_id,
                "pairingToken": session_state.pairing_token,
                "vehicleNonce": args.vehicle_nonce,
                "userPublicKey": args.user_public_key,
            }, indent=2),
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"Failed to write export file: {exc}", file=sys.stderr)

    print("Seeded PKI session", session_state.session_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
