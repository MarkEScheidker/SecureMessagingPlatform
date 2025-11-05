"""Handshake helpers for establishing secure sessions via the relay server."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from client.common.state import AppState
from client.common.utils import b64d, b64e
from client.crypto.core import SecureSession, derive_session, handshake_payload
from client.network.keyserver import fetch_public_key


@dataclass
class InitiatorContext:
    """Keeps local state while waiting for a handshake response."""

    peer_username: str
    eph_private: x25519.X25519PrivateKey
    eph_public: bytes
    nonce: bytes
    peer_public: ed25519.Ed25519PublicKey
    peer_version: int


def build_handshake_init(state: AppState, peer_username: str) -> Tuple[InitiatorContext, Dict[str, str]]:
    """Prepare the initiator handshake payload and return context for completion."""

    peer_public, peer_version = fetch_public_key(state.server, peer_username)

    eph_private = x25519.X25519PrivateKey.generate()
    eph_public = eph_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    nonce = os.urandom(16)

    signed_payload = handshake_payload("init", state.username, peer_username, eph_public, nonce)
    signature = state.identity_private.sign(signed_payload)

    context = InitiatorContext(
        peer_username=peer_username,
        eph_private=eph_private,
        eph_public=eph_public,
        nonce=nonce,
        peer_public=peer_public,
        peer_version=peer_version,
    )

    message = {
        "username": state.username,
        "target": peer_username,
        "ephemeral": b64e(eph_public),
        "nonce": b64e(nonce),
        "signature": b64e(signature),
    }
    return context, message


def complete_handshake_initiator(state: AppState, ctx: InitiatorContext, response: Dict[str, str]) -> SecureSession:
    """Validate the responder's reply and derive the secure session."""

    if response.get("expected") != state.username:
        raise RuntimeError("Responder rejected our identity.")
    if response.get("username") != ctx.peer_username:
        raise RuntimeError("Responder identity mismatch.")

    peer_nonce = b64d(response["nonce"])
    peer_eph = b64d(response["ephemeral"])
    peer_sig = b64d(response["signature"])

    peer_payload = handshake_payload("accept", ctx.peer_username, state.username, peer_eph, peer_nonce)
    ctx.peer_public.verify(peer_sig, peer_payload)

    session_key, transcript_hash = derive_session(
        username=state.username,
        peer_username=ctx.peer_username,
        local_nonce=ctx.nonce,
        remote_nonce=peer_nonce,
        local_eph=ctx.eph_public,
        remote_eph=peer_eph,
        private_key=ctx.eph_private,
    )

    return SecureSession(
        role="initiator",
        username=state.username,
        peer=ctx.peer_username,
        session_key=session_key,
        transcript_hash=transcript_hash,
    )


def handle_handshake_init(state: AppState, request: Dict[str, str]) -> Tuple[SecureSession, Dict[str, str], str, int]:
    """Process an incoming handshake initiation and build the acceptance payload."""

    remote_username = request.get("username")
    target = request.get("target")
    if remote_username is None or target is None:
        raise RuntimeError("Malformed handshake request.")
    if target != state.username:
        raise RuntimeError("Handshake target mismatch.")

    remote_public, remote_version = fetch_public_key(state.server, remote_username)
    remote_nonce = b64d(request["nonce"])
    remote_eph = b64d(request["ephemeral"])
    remote_sig = b64d(request["signature"])

    remote_payload = handshake_payload("init", remote_username, state.username, remote_eph, remote_nonce)
    remote_public.verify(remote_sig, remote_payload)

    eph_private = x25519.X25519PrivateKey.generate()
    eph_public = eph_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    nonce = os.urandom(16)

    response_payload = handshake_payload("accept", state.username, remote_username, eph_public, nonce)
    signature = state.identity_private.sign(response_payload)

    session_key, transcript_hash = derive_session(
        username=state.username,
        peer_username=remote_username,
        local_nonce=nonce,
        remote_nonce=remote_nonce,
        local_eph=eph_public,
        remote_eph=remote_eph,
        private_key=eph_private,
    )

    response = {
        "username": state.username,
        "expected": remote_username,
        "ephemeral": b64e(eph_public),
        "nonce": b64e(nonce),
        "signature": b64e(signature),
    }

    session = SecureSession(
        role="responder",
        username=state.username,
        peer=remote_username,
        session_key=session_key,
        transcript_hash=transcript_hash,
    )
    return session, response, remote_username, remote_version
