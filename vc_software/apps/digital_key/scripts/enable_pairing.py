#!/usr/bin/env python3
"""Utility to prep environment and enable the next pairing session."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

PROJECT_ROOT = Path(__file__).resolve().parents[1]
KEYS_DIR = PROJECT_ROOT / "keys"
DEFAULT_PRIVATE_KEY = KEYS_DIR / "vehicle_private.pem"
DEFAULT_PUBLIC_KEY = KEYS_DIR / "vehicle_public.pem"
ENV_PATH = PROJECT_ROOT / ".env"
FLAG_PATH = Path.home() / ".cache" / "dks" / "pairing_enabled"


def _ensure_vehicle_keys() -> Tuple[Path, Path]:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    if DEFAULT_PRIVATE_KEY.exists() and DEFAULT_PUBLIC_KEY.exists():
        return DEFAULT_PRIVATE_KEY, DEFAULT_PUBLIC_KEY

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    DEFAULT_PRIVATE_KEY.write_bytes(private_bytes)
    DEFAULT_PUBLIC_KEY.write_bytes(public_bytes)
    os.chmod(DEFAULT_PRIVATE_KEY, 0o600)
    os.chmod(DEFAULT_PUBLIC_KEY, 0o644)
    print(f"[enable-pairing] Generated new vehicle keypair at {KEYS_DIR}")
    return DEFAULT_PRIVATE_KEY, DEFAULT_PUBLIC_KEY


def _normalize_env_line(line: str) -> Tuple[str, str]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return "", line
    if stripped.startswith("export "):
        stripped = stripped[len("export ") :]
    key, value = stripped.split("=", 1)
    return key.strip(), value.strip()


def _ensure_env_entry(key: str, value: str) -> None:
    lines = []
    existing_value = None
    if ENV_PATH.exists():
        for raw_line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            parsed_key, _ = _normalize_env_line(raw_line)
            if parsed_key and parsed_key == key:
                existing_value = raw_line.split("=", 1)[1].strip()
            lines.append(raw_line)

    target_line = f"{key}={value}"
    if existing_value == value:
        return

    updated = False
    for idx, raw_line in enumerate(lines):
        parsed_key, _ = _normalize_env_line(raw_line)
        if parsed_key == key:
            lines[idx] = target_line
            updated = True
            break
    if not updated:
        lines.append(target_line)

    content = "\n".join(line for line in lines if line != "") + "\n"
    ENV_PATH.write_text(content, encoding="utf-8")
    print(f"[enable-pairing] Updated {ENV_PATH} with {key}")


def main() -> int:
    private_key_path, _ = _ensure_vehicle_keys()
    try:
        env_value = str(private_key_path.relative_to(PROJECT_ROOT))
    except ValueError:
        env_value = str(private_key_path)
    _ensure_env_entry("VEHICLE_KEY_PATH", env_value)

    FLAG_PATH.parent.mkdir(parents=True, exist_ok=True)
    FLAG_PATH.touch(exist_ok=True)

    print(
        "[enable-pairing] Pairing flag created. The next pairing challenge read will "
        "request a new PIN from the backend."
    )
    print(f"[enable-pairing] Flag file : {FLAG_PATH}")
    print(f"[enable-pairing] Private key: {private_key_path}")
    print(f"[enable-pairing] Remember to restart the BLE service if it is running.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
