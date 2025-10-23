"""Peer discovery helpers using UDP broadcast."""

from __future__ import annotations

import asyncio
import base64
import os
import socket
import time
from typing import Optional

from client.common.config import DISCOVERY_REQUEST, DISCOVERY_RESPONSE_HEADER
from client.common.state import AppState
from client.network.keyserver import fetch_public_key


def discover_peers(state: AppState, port: int, timeout: float = 3.0) -> None:
    """Send a broadcast discovery request and log verified responders."""
    deadline = time.time() + timeout
    seen: dict[str, tuple[str, int]] = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(0.5)
        sock.bind(("0.0.0.0", 0))
        sock.sendto(DISCOVERY_REQUEST, ("255.255.255.255", port))
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            parts = data.split(b"|")
            if len(parts) != 5 or tuple(parts[:2]) != DISCOVERY_RESPONSE_HEADER:
                continue
            username = parts[2].decode("utf-8")
            message = b"|".join(parts[:4])
            signature = base64.b64decode(parts[4])
            try:
                public_key, version = fetch_public_key(state.server, username)
                public_key.verify(signature, message)
            except Exception:
                continue
            seen[username] = (addr[0], version)
    if not seen:
        print("No peers responded.")
        return
    state.known_peers.update(seen)
    print("Discovered peers:")
    for user, (ip_addr, version) in seen.items():
        print(f" - {user} at {ip_addr} (key v{version})")


class DiscoveryResponder(asyncio.DatagramProtocol):
    """Responds to discovery broadcasts with a signed presence packet."""

    def __init__(self, state: AppState) -> None:
        self.state = state
        self.transport: Optional[asyncio.transports.DatagramTransport] = None

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        if data.strip() != DISCOVERY_REQUEST:
            return
        nonce = os.urandom(16)
        message_parts = [
            DISCOVERY_RESPONSE_HEADER[0],
            DISCOVERY_RESPONSE_HEADER[1],
            self.state.username.encode("utf-8"),
            base64.b64encode(nonce),
        ]
        message = b"|".join(message_parts)
        signature = self.state.identity_private.sign(message)
        packet = message + b"|" + base64.b64encode(signature)
        if self.transport:
            self.transport.sendto(packet, addr)

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport

    def connection_lost(self, exc) -> None:  # type: ignore[override]
        self.transport = None

