"""HTTP helpers for interacting with the trusted key server."""

from __future__ import annotations

from typing import Tuple

import httpx
from cryptography.hazmat.primitives.asymmetric import ed25519

from client.common.utils import b64d, b64e


def publish_public_key(server_url: str, username: str, password: str, public_key: bytes) -> None:
    """Create or update the caller's account and associated public key."""
    payload = {"username": username, "password": password, "public_key": b64e(public_key)}
    response = httpx.post(f"{server_url}/keys", json=payload, timeout=5.0)
    response.raise_for_status()
    data = response.json()
    version = data.get("key_version")
    status = data.get("status", "updated")
    print(f"[key-server] Key {status} (version {version}).")


def fetch_public_key(server_url: str, username: str) -> Tuple[ed25519.Ed25519PublicKey, int]:
    """Return the stored public key and version for the requested user."""
    response = httpx.get(f"{server_url}/keys/{username}", timeout=5.0)
    response.raise_for_status()
    data = response.json()
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(b64d(data["public_key"]))
    return public_key, int(data.get("key_version", 0))

