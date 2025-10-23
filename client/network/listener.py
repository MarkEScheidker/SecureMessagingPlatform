"""Inbound secure session handling."""

from __future__ import annotations

import asyncio
from typing import Optional

from client.chat.runtime import run_chat
from client.common.state import AppState
from client.crypto.handshake import perform_handshake_responder
from client.network.discovery import DiscoveryResponder


async def listen_once(state: AppState, host: str, port: int) -> None:
    """Wait for a single inbound connection, then run the chat session."""
    loop = asyncio.get_running_loop()
    protocol = DiscoveryResponder(state)
    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol,
        local_addr=(host, port),
        allow_broadcast=True,
    )

    session_ready: asyncio.Future[None] = loop.create_future()
    chat_finished: asyncio.Future[None] = loop.create_future()

    async def handle_client(reader, writer) -> None:
        addr = writer.get_extra_info("peername")
        peer_username: Optional[str] = None
        try:
            if session_ready.done():
                writer.close()
                await writer.wait_closed()
                return
            session, peer, version = await perform_handshake_responder(
                reader=reader,
                writer=writer,
                state=state,
            )
            peer_username = peer
            if isinstance(addr, tuple) and addr:
                state.known_peers[peer] = (addr[0], version)
            print(f"[listen] Connection from {addr} authenticated as '{peer}'.")
            if not session_ready.done():
                session_ready.set_result(None)

            await run_chat(reader, writer, session)
            if not chat_finished.done():
                chat_finished.set_result(None)
        except Exception as exc:  # noqa: BLE001
            print(f"[listen] Handshake failed from {addr}: {exc}")
            if not session_ready.done():
                session_ready.set_exception(exc)
            if not chat_finished.done():
                chat_finished.set_exception(exc)
        finally:
            if not writer.is_closing():
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
            if peer_username:
                print(f"[listen] Session with '{peer_username}' ended.")

    server = await asyncio.start_server(handle_client, host=host, port=port)
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"[listen] Waiting for incoming connection on {sockets}.")

    try:
        await session_ready
    except Exception:
        server.close()
        await server.wait_closed()
        transport.close()
        raise

    server.close()
    await server.wait_closed()
    transport.close()

    await chat_finished

