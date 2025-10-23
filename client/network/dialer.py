"""Outbound connection helper for initiating secure chats."""

from __future__ import annotations

import asyncio

from client.chat.runtime import run_chat
from client.common.state import AppState
from client.crypto.handshake import perform_handshake_initiator


async def connect_and_chat(state: AppState, host: str, port: int, peer_username: str) -> None:
    """Connect to a peer, run the handshake, and start the chat session."""
    print(f"[dial] Connecting to {host}:{port} expecting '{peer_username}'...")
    reader, writer = await asyncio.open_connection(host, port)
    try:
        session, version = await perform_handshake_initiator(
            reader=reader,
            writer=writer,
            state=state,
            peer_username=peer_username,
        )
        state.known_peers[peer_username] = (host, version)
        await run_chat(reader, writer, session)
    finally:
        writer.close()
        await writer.wait_closed()
    print(f"[dial] Session with '{peer_username}' ended.")

