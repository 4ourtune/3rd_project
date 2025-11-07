#!/usr/bin/env python3
"""Generate a self-signed vehicle certificate PEM for the Digital Key prototype."""
from __future__ import annotations

import argparse
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DEFAULT_KEYS_DIR = Path(__file__).resolve().parents[1] / "keys"
DEFAULT_PRIVATE_KEY = DEFAULT_KEYS_DIR / "vehicle_private.pem"
DEFAULT_CERT_PATH = DEFAULT_KEYS_DIR / "device_cert.pem"


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate self-signed vehicle certificate PEM.")
    parser.add_argument(
        "--key",
        type=Path,
        default=DEFAULT_PRIVATE_KEY,
        help=f"Existing vehicle private key PEM (default: {DEFAULT_PRIVATE_KEY})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_CERT_PATH,
        help=f"Output certificate path (default: {DEFAULT_CERT_PATH})",
    )
    parser.add_argument(
        "--subject-common-name",
        default="Digital Key Vehicle",
        help="Common Name (CN) for the certificate subject (default: Digital Key Vehicle)",
    )
    parser.add_argument(
        "--valid-days",
        type=int,
        default=365,
        help="Certificate validity period in days (default: 365)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing certificate if present.",
    )
    return parser.parse_args(argv)


def load_or_generate_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    if path.exists():
        key_data = path.read_bytes()
        return serialization.load_pem_private_key(key_data, password=None)

    path.parent.mkdir(parents=True, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP256R1())
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(key_bytes)
    os.chmod(path, 0o600)
    print(f"[generate-cert] Generated new private key at {path}")
    return private_key


def write_cert(path: Path, cert: x509.Certificate, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(
            f"{path} already exists. Pass --overwrite to replace it."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(path, 0o644)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    private_key = load_or_generate_private_key(args.key)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, args.subject_common_name),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=args.valid_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    write_cert(args.output, cert, overwrite=args.overwrite)
    print(f"[generate-cert] Certificate written to: {args.output}")
    print("[generate-cert] Update VEHICLE_CERT_PATH to point to this PEM if needed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
