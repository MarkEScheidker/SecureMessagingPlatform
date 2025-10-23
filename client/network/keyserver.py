"""HTTP helpers for interacting with the trusted key server."""

from __future__ import annotations

from typing import Tuple

import httpx
from cryptography.hazmat.primitives.asymmetric import ed25519

from client.common.utils import b64d, b64e


def create_account(server_url: str, username: str, password: str) -> None:
    """Ensure an account exists for the current user."""
    response = httpx.post(
        f"{server_url}/accounts",
        json={"username": username, "password": password},
        timeout=5.0,
    )
    if response.status_code in (201, 409):
        status = "created" if response.status_code == 201 else "already exists"
        print(f"[key-server] Account {status} for '{username}'.")
        return
    response.raise_for_status()


def publish_public_key(server_url: str, username: str, password: str, public_key: bytes) -> None:
    """Upload the caller's public key to the server."""
    payload = {"username": username, "password": password, "public_key": b64e(public_key)}
    response = httpx.post(f"{server_url}/keys", json=payload, timeout=5.0)
    response.raise_for_status()
    version = response.json().get("key_version")
    print(f"[key-server] Published public key version {version}.")


def fetch_public_key(server_url: str, username: str) -> Tuple[ed25519.Ed25519PublicKey, int]:
    """Return the stored public key and version for the requested user."""
    response = httpx.get(f"{server_url}/keys/{username}", timeout=5.0)
    response.raise_for_status()
    data = response.json()
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(b64d(data["public_key"]))
    return public_key, int(data.get("key_version", 0))

