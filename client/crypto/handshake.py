"""Handshake helpers for establishing secure sessions."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from client.common.state import AppState
from client.common.utils import b64d, b64e
from client.crypto.core import SecureSession, derive_session, handshake_payload
from client.network.keyserver import fetch_public_key
from client.network.transport import read_frame, write_frame


async def perform_handshake_initiator(
    *,
    reader,
    writer,
    state: AppState,
    peer_username: str,
) -> Tuple[SecureSession, int]:
    """Initiate the handshake with a peer and establish a session."""
    peer_public, peer_version = await asyncio.to_thread(fetch_public_key, state.server, peer_username)

    eph_private = x25519.X25519PrivateKey.generate()
    eph_public = eph_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    nonce = os.urandom(16)

    payload = handshake_payload("init", state.username, peer_username, eph_public, nonce)
    signature = state.identity_private.sign(payload)
    message = {
        "type": "handshake_init",
        "username": state.username,
        "target": peer_username,
        "ephemeral": b64e(eph_public),
        "nonce": b64e(nonce),
        "signature": b64e(signature),
    }
    await write_frame(writer, json.dumps(message).encode("utf-8"))

    response_raw = await read_frame(reader)
    response = json.loads(response_raw.decode("utf-8"))
    if response.get("type") != "handshake_accept":
        raise RuntimeError("Unexpected handshake response.")
    if response.get("expected") != state.username:
        raise RuntimeError("Responder rejected our identity.")
    if response.get("username") != peer_username:
        raise RuntimeError("Responder identity mismatch.")

    peer_nonce = b64d(response["nonce"])
    peer_eph = b64d(response["ephemeral"])
    peer_sig = b64d(response["signature"])

    peer_payload = handshake_payload("accept", peer_username, state.username, peer_eph, peer_nonce)
    peer_public.verify(peer_sig, peer_payload)

    session_key, transcript_hash = derive_session(
        username=state.username,
        peer_username=peer_username,
        local_nonce=nonce,
        remote_nonce=peer_nonce,
        local_eph=eph_public,
        remote_eph=peer_eph,
        private_key=eph_private,
    )
    print(f"[session] Handshake confirmed with '{peer_username}' (key v{peer_version}).")
    session = SecureSession(
        role="initiator",
        username=state.username,
        peer=peer_username,
        session_key=session_key,
        transcript_hash=transcript_hash,
    )
    return session, peer_version


async def perform_handshake_responder(
    *,
    reader,
    writer,
    state: AppState,
) -> Tuple[SecureSession, str, int]:
    """Respond to a handshake initiation and establish a session."""
    raw = await read_frame(reader)
    request = json.loads(raw.decode("utf-8"))
    if request.get("type") != "handshake_init":
        raise RuntimeError("Unexpected handshake payload.")

    remote_username = request["username"]
    target = request.get("target")
    if target != state.username:
        raise RuntimeError("Handshake target mismatch.")

    remote_public, remote_version = await asyncio.to_thread(fetch_public_key, state.server, remote_username)
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
    response = {
        "type": "handshake_accept",
        "username": state.username,
        "expected": remote_username,
        "ephemeral": b64e(eph_public),
        "nonce": b64e(nonce),
        "signature": b64e(signature),
    }
    await write_frame(writer, json.dumps(response).encode("utf-8"))

    session_key, transcript_hash = derive_session(
        username=state.username,
        peer_username=remote_username,
        local_nonce=nonce,
        remote_nonce=remote_nonce,
        local_eph=eph_public,
        remote_eph=remote_eph,
        private_key=eph_private,
    )
    print(f"[session] Handshake confirmed with '{remote_username}' (key v{remote_version}).")
    session = SecureSession(
        role="responder",
        username=state.username,
        peer=remote_username,
        session_key=session_key,
        transcript_hash=transcript_hash,
    )
    return session, remote_username, remote_version

