"""Hashing, canonical serialisation and Ed25519 signing keys.

REAL IMPLEMENTATION.
- SHA-256 from Python's hashlib.
- Ed25519 signatures from the `cryptography` package (local, no network).

Prototype limitation: the private key is stored as an unencrypted PEM file
in data/generated/keys/. A production deployment should keep it in an
HSM / TPM / OS key store.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding: sorted keys, no whitespace, UTF-8.

    Two parties that hold the same logical data always produce the same
    bytes, which is what makes hashing/signing JSON records meaningful.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(obj: Any) -> str:
    return sha256_bytes(canonical_json(obj))


def sha256_file(path: Path | str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


class SigningKey:
    """Wrapper around an Ed25519 key pair with a short key id."""

    def __init__(self, private: Ed25519PrivateKey, name: str = "aegis-signer"):
        self._private = private
        self.public = private.public_key()
        self.name = name
        raw = self.public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_raw_hex = raw.hex()
        self.key_id = sha256_bytes(raw)[:16]

    # -- construction -----------------------------------------------
    @classmethod
    def generate(cls, name: str = "aegis-signer") -> "SigningKey":
        return cls(Ed25519PrivateKey.generate(), name)

    @classmethod
    def load_or_create(cls, path: Path, name: str = "aegis-signer") -> "SigningKey":
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            priv = serialization.load_pem_private_key(path.read_bytes(), password=None)
            assert isinstance(priv, Ed25519PrivateKey)
            return cls(priv, name)
        key = cls.generate(name)
        path.write_bytes(
            key._private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return key

    # -- operations -------------------------------------------------
    def sign(self, message: bytes) -> str:
        return self._private.sign(message).hex()

    def public_info(self) -> dict:
        return {"key_id": self.key_id, "algorithm": "Ed25519", "public_key_hex": self.public_raw_hex, "name": self.name}


def verify_signature(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False
