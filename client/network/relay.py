"""WebSocket relay client that handles signaling and encrypted chat."""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import websockets
from websockets.client import WebSocketClientProtocol

from client.common.state import AppState
from client.common.utils import b64d, b64e
from client.crypto.core import SecureSession
from client.crypto.handshake import (
    InitiatorContext,
    build_handshake_init,
    complete_handshake_initiator,
    handle_handshake_init,
)


def _build_ws_url(base_url: str, username: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https", "ws", "wss"}:
        raise ValueError("Unsupported server URL scheme")
    scheme = "wss" if parsed.scheme in {"https", "wss"} else "ws"
    path = parsed.path.rstrip("/") + "/ws"
    netloc = parsed.netloc
    if not netloc:
        netloc = parsed.path
        path = "/ws"
    query = f"username={username}"
    rebuilt = urlunparse((scheme, netloc, path, "", query, ""))
    return rebuilt


class RelayClient:
    """Maintain a single websocket connection to the routing server."""

    def __init__(self, state: AppState) -> None:
        self.state = state
        self.ws: Optional[WebSocketClientProtocol] = None
        self._receiver: Optional[asyncio.Task] = None
        self._initiator_contexts: Dict[str, InitiatorContext] = {}
        self._initiator_futures: Dict[str, asyncio.Future[Tuple[SecureSession, int]]] = {}
        self._incoming_sessions: asyncio.Queue[Tuple[str, SecureSession, int]] = asyncio.Queue()
        self.session: Optional[SecureSession] = None
        self.session_peer: Optional[str] = None

    async def connect(self) -> None:
        if self.ws is not None:
            return
        ws_url = _build_ws_url(self.state.server, self.state.username)
        self.ws = await websockets.connect(ws_url, ping_interval=30, ping_timeout=20)
        self._receiver = asyncio.create_task(self._recv_loop())

    async def close(self) -> None:
        if self._receiver:
            self._receiver.cancel()
            with contextlib.suppress(Exception):
                await self._receiver
        if self.ws:
            with contextlib.suppress(Exception):
                await self.ws.close()
        self.ws = None

    async def _send(self, to: str, msg_type: str, payload: dict) -> None:
        if self.ws is None:
            raise RuntimeError("WebSocket not connected")
        envelope = {"to": to, "type": msg_type, "payload": payload}
        await self.ws.send(json.dumps(envelope))

    async def start_handshake(self, peer_username: str) -> Tuple[SecureSession, int]:
        await self.connect()
        if peer_username in self._initiator_futures:
            raise RuntimeError("Handshake already in progress with that peer")

        ctx, message = await asyncio.to_thread(build_handshake_init, self.state, peer_username)
        future: asyncio.Future[Tuple[SecureSession, int]] = asyncio.get_running_loop().create_future()
        self._initiator_contexts[peer_username] = ctx
        self._initiator_futures[peer_username] = future
        await self._send(peer_username, "handshake_init", message)
        session, version = await future
        self.session = session
        self.session_peer = peer_username
        return session, version

    async def wait_for_incoming(self) -> Tuple[str, SecureSession, int]:
        await self.connect()
        peer, session, version = await self._incoming_sessions.get()
        self.session = session
        self.session_peer = peer
        return peer, session, version

    async def send_chat(self, plaintext: str) -> None:
        if not self.session or not self.session_peer:
            raise RuntimeError("No active session")
        nonce_counter, ciphertext = self.session.encrypt(plaintext.encode("utf-8"))
        payload = {
            "nonce": nonce_counter,
            "ciphertext": b64e(ciphertext),
        }
        await self._send(self.session_peer, "chat", payload)

    async def _recv_loop(self) -> None:
        assert self.ws is not None
        try:
            async for raw in self.ws:
                try:
                    message = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                msg_type = message.get("type")
                sender = message.get("from")
                payload = message.get("payload", {})

                if msg_type == "handshake_accept" and sender in self._initiator_contexts:
                    ctx = self._initiator_contexts.pop(sender)
                    fut = self._initiator_futures.pop(sender)
                    try:
                        session = complete_handshake_initiator(self.state, ctx, payload)
                        fut.set_result((session, ctx.peer_version))
                        print(f"[session] Handshake confirmed with '{sender}' (key v{ctx.peer_version}).")
                    except Exception as exc:  # noqa: BLE001
                        fut.set_exception(exc)
                elif msg_type == "handshake_init" and isinstance(sender, str):
                    try:
                        session, response, peer, version = await asyncio.to_thread(handle_handshake_init, self.state, payload)
                        await self._send(sender, "handshake_accept", response)
                        await self._incoming_sessions.put((peer, session, version))
                        print(f"[session] Handshake confirmed with '{peer}' (key v{version}).")
                    except Exception as exc:  # noqa: BLE001
                        print(f"[relay] Failed to process handshake from {sender}: {exc}")
                elif msg_type == "chat" and isinstance(sender, str):
                    if not self.session or self.session_peer != sender:
                        continue
                    try:
                        nonce_counter = int(payload.get("nonce"))
                        ciphertext = b64d(payload.get("ciphertext", ""))
                    except Exception:  # noqa: BLE001
                        continue
                    try:
                        plaintext = self.session.decrypt(nonce_counter, ciphertext).decode("utf-8")
                    except Exception as exc:  # noqa: BLE001
                        print(f"[session] Decryption failed: {exc}")
                        continue
                    print(f"{sender}> {plaintext}")
                elif msg_type == "delivery_status":
                    status = payload.get("status") or message.get("status")
                    target = payload.get("to") or message.get("to")
                    if status == "offline" and target:
                        print(f"[relay] '{target}' appears offline.")
                else:
                    continue
        except websockets.ConnectionClosed:
            print("[relay] Connection to server closed.")
        except Exception as exc:  # noqa: BLE001
            print(f"[relay] Receiver loop error: {exc}")
