#!/usr/bin/env python3
"""Generate vehicle EC key material for the Digital Key prototype."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[1] / "keys"


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate vehicle EC keypair.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to write PEM files (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--basename",
        default="vehicle",
        help="File basename for key files (default: vehicle -> vehicle_private.pem)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing files if present.",
    )
    return parser.parse_args(argv)


def write_file(path: Path, data: bytes, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} already exists. Pass --overwrite to replace it.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.chmod(path, 0o600)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
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

    private_path = args.output_dir / f"{args.basename}_private.pem"
    public_path = args.output_dir / f"{args.basename}_public.pem"

    write_file(private_path, private_bytes, overwrite=args.overwrite)
    write_file(public_path, public_bytes, overwrite=args.overwrite)

    print(f"Private key written to: {private_path}")
    print(f"Public key written to : {public_path}")
    print("Update VEHICLE_KEY_PATH to point to the private key if needed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
