"""Command-line interface for the secure messaging client."""

from __future__ import annotations

import argparse
import asyncio
import sys
from getpass import getpass
from typing import Optional

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from client.common.config import DEFAULT_PORT, DEFAULT_SERVER_URL
from client.common.state import AppState
from client.common.utils import input_trim
from client.network.dialer import connect_and_chat
from client.network.discovery import discover_peers
from client.network.keyserver import create_account, publish_public_key
from client.network.listener import listen_once

HELP_TEXT = """Commands:
  discover [port]           Broadcast for peers advertising over UDP (default port 4040).
  listen [port]             Wait for an incoming secure session (default port 4040).
  connect <peer> [port]     Dial a discovered peer (default port 4040).
  connect <host> <peer> [port]
                            Dial a peer at a specific host.
  help                      Show this help.
  quit                      Exit the program.
"""


async def app_main(server_url: str) -> None:
    print("Secure Messaging CLI")
    print("----------------------------------------")
    username = ""
    while not username:
        username = await asyncio.to_thread(input_trim, "Username: ")
    password = ""
    while not password:
        password = await asyncio.to_thread(getpass, "Password: ")

    identity_private = ed25519.Ed25519PrivateKey.generate()
    identity_public = identity_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    state = AppState(
        username=username,
        password=password,
        server=server_url,
        identity_private=identity_private,
        identity_public=identity_public,
    )

    try:
        await asyncio.to_thread(create_account, state.server, state.username, state.password)
        await asyncio.to_thread(
            publish_public_key,
            state.server,
            state.username,
            state.password,
            state.identity_public,
        )
    except httpx.RequestError as exc:
        print(f"[error] Could not reach key server: {exc}", file=sys.stderr)
        return
    except httpx.HTTPStatusError as exc:
        try:
            detail = exc.response.json().get("detail", exc.response.text)
        except Exception:  # noqa: BLE001
            detail = exc.response.text
        print(f"[error] Key server rejected request: {detail}", file=sys.stderr)
        return

    print("Logged in. Your key will remain in memory until you exit.")
    print(HELP_TEXT)

    while True:
        raw = await asyncio.to_thread(input_trim, "smp> ")
        if not raw:
            continue
        parts = raw.split()
        command = parts[0].lower()

        if command in {"quit", "exit"}:
            break
        if command == "help":
            print(HELP_TEXT)
            continue
        if command == "discover":
            port = int(parts[1]) if len(parts) > 1 else DEFAULT_PORT
            await asyncio.to_thread(discover_peers, state, port)
            continue
        if command == "listen":
            port = int(parts[1]) if len(parts) > 1 else DEFAULT_PORT
            try:
                await listen_once(state, host="0.0.0.0", port=port)
            except Exception as exc:  # noqa: BLE001
                print(f"[listen] Error: {exc}")
            continue
        if command == "connect":
            args = parts[1:]
            if not args:
                print("Usage: connect <peer> [port] or connect <host> <peer> [port]")
                continue

            host: Optional[str] = None
            peer: Optional[str] = None
            port = DEFAULT_PORT

            if len(args) == 1:
                peer = args[0]
                entry = state.known_peers.get(peer)
                if not entry:
                    print("Unknown peer; run 'discover' or specify host explicitly.")
                    continue
                host = entry[0]
            elif len(args) == 2:
                first, second = args
                if first in state.known_peers and second.isdigit():
                    peer = first
                    host = state.known_peers[first][0]
                    port = int(second)
                else:
                    host, peer = first, second
            else:
                if len(args) > 3:
                    print("Usage: connect <peer> [port] or connect <host> <peer> [port]")
                    continue
                host, peer = args[0], args[1]
                port_token = args[2]
                if port_token.startswith("0x"):
                    base = 16
                    port_token_value = port_token[2:]
                else:
                    base = 10
                    port_token_value = port_token
                try:
                    port = int(port_token_value, base)
                except ValueError:
                    print("Port must be an integer value.")
                    continue

            if host is None or peer is None:
                print("Usage: connect <peer> [port] or connect <host> <peer> [port]")
                continue

            try:
                await connect_and_chat(state, host, port, peer)
            except Exception as exc:  # noqa: BLE001
                print(f"[dial] Error: {exc}")
            continue

        print("Unknown command. Type 'help' for options.")

    print("Clearing session secrets and exiting.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Secure messaging CLI using a trusted introducer server.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--server", default=DEFAULT_SERVER_URL, help="Key server base URL.")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(app_main(args.server))
    except KeyboardInterrupt:
        print("\nInterrupted. Goodbye.")

