"""Core cryptographic functions for the classroom project.

Uses RSA-PSS with SHA-256 for signatures. Public-key records are a
classroom trust-directory simulation, not X.509 certificate validation.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_key_pair(owner_name: str, key_size: int = 2048):
    """Generate an RSA key pair and a simulated trusted-key record."""
    if not owner_name or not owner_name.strip():
        raise ValueError("Owner name is required.")
    if key_size < 2048:
        raise ValueError("Use at least 2048 bits for this project demonstration.")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = public_key_fingerprint(public_pem)
    record = {
        "schema_version": 1,
        "record_type": "CLASSROOM_TRUSTED_KEY_RECORD",
        "owner": owner_name.strip(),
        "key_id": fingerprint[:16].upper(),
        "fingerprint_sha256": fingerprint,
        "public_key_pem": public_pem.decode("utf-8"),
        "status": "ACTIVE",
        "issued_at_utc": datetime.now(timezone.utc).isoformat(),
        "trust_note": (
            "Educational trust-directory record only. This is not an X.509 certificate "
            "and does not independently prove the owner's real-world identity."
        ),
    }
    record_bytes = json.dumps(record, indent=2).encode("utf-8")
    return private_pem, public_pem, record_bytes, record


def load_private_key(pem_data: bytes):
    return serialization.load_pem_private_key(pem_data, password=None)


def load_public_key(pem_data: bytes):
    return serialization.load_pem_public_key(pem_data)


def public_key_fingerprint(public_key_pem: bytes) -> str:
    public_key = load_public_key(public_key_pem)
    canonical = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(canonical).hexdigest()


def sign_document(document_bytes: bytes, private_key_pem: bytes) -> bytes:
    """Sign the exact bytes of a document using RSA-PSS/SHA-256."""
    private_key = load_private_key(private_key_pem)
    return private_key.sign(
        document_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(document_bytes: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """Return True only if the signature matches the exact document bytes."""
    public_key = load_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            document_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def evaluate_trust(public_key_pem: bytes, record_bytes: bytes | None) -> dict[str, Any]:
    """Check a supplied key against the project's simulated trust record."""
    actual_fp = public_key_fingerprint(public_key_pem)
    if not record_bytes:
        return {
            "trusted": None,
            "message": "No trusted-key record supplied; cryptographic verification can still be checked.",
            "fingerprint": actual_fp,
            "owner": None,
        }

    try:
        record = json.loads(record_bytes.decode("utf-8"))
        recorded_pem = record["public_key_pem"].encode("utf-8")
        recorded_fp = public_key_fingerprint(recorded_pem)
        if recorded_fp != record.get("fingerprint_sha256"):
            return {
                "trusted": False,
                "message": "Trust record integrity check failed: stored fingerprint does not match its public key.",
                "fingerprint": actual_fp,
                "owner": record.get("owner"),
            }
        if recorded_fp != actual_fp:
            return {
                "trusted": False,
                "message": "The verification public key does not match the supplied trusted-key record.",
                "fingerprint": actual_fp,
                "owner": record.get("owner"),
            }
        if record.get("status") != "ACTIVE":
            return {
                "trusted": False,
                "message": f"Key record status is {record.get('status')!r}, not ACTIVE.",
                "fingerprint": actual_fp,
                "owner": record.get("owner"),
            }
        if record.get("record_type") != "CLASSROOM_TRUSTED_KEY_RECORD":
            return {
                "trusted": False,
                "message": "Unsupported trust-record type.",
                "fingerprint": actual_fp,
                "owner": record.get("owner"),
            }
        return {
            "trusted": True,
            "message": "Public key matches an ACTIVE record in the simulated classroom trust directory.",
            "fingerprint": actual_fp,
            "owner": record.get("owner"),
        }
    except (ValueError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return {
            "trusted": False,
            "message": "Trust record is malformed or unreadable.",
            "fingerprint": actual_fp,
            "owner": None,
        }
