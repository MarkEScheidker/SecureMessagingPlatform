"""Dataclasses and shared state containers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519


@dataclass
class AppState:
    """Holds all mutable client state for the active CLI session."""

    username: str
    password: str
    server: str
    identity_private: ed25519.Ed25519PrivateKey
    identity_public: bytes
    known_peers: Dict[str, Tuple[str, int]] = field(default_factory=dict)

