"""Command-line interface for the secure messaging client using the relay."""

from __future__ import annotations

import argparse
import asyncio
import sys
from getpass import getpass

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from client.common.config import DEFAULT_SERVER_URL
from client.common.state import AppState
from client.common.utils import input_trim
from client.network.keyserver import publish_public_key
from client.network.relay import RelayClient

HELP_TEXT = """Commands:
  connect <peer>       Initiate a session with a peer via the relay.
  wait                 Wait for the next incoming session request.
  help                 Show this help message.
  quit                 Exit the program.
"""


async def chat_loop(relay: RelayClient) -> None:
    print("Type /leave to close the session.")
    while relay.session and relay.session_peer:
        text = await asyncio.to_thread(input_trim, "you> ")
        if not text:
            continue
        if text in {"/leave", "/quit"}:
            print("Ending session.")
            relay.session = None
            relay.session_peer = None
            break
        try:
            await relay.send_chat(text)
        except Exception as exc:  # noqa: BLE001
            print(f"[session] Send failed: {exc}")
            relay.session = None
            relay.session_peer = None
            break


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

    relay = RelayClient(state)
    print("Logged in. Relay connection will open on demand.")
    print(HELP_TEXT)

    try:
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
            if command == "connect":
                if len(parts) != 2:
                    print("Usage: connect <peer>")
                    continue
                peer = parts[1]
                try:
                    session, version = await relay.start_handshake(peer)
                    print(f"[session] Established with '{session.peer}' (key v{version}).")
                    await chat_loop(relay)
                except Exception as exc:  # noqa: BLE001
                    print(f"[connect] Failed: {exc}")
                continue
            if command in {"wait", "listen"}:
                print("Waiting for incoming session...")
                try:
                    peer, session, version = await relay.wait_for_incoming()
                    print(f"[session] Established with '{peer}' (key v{version}).")
                    await chat_loop(relay)
                except Exception as exc:  # noqa: BLE001
                    print(f"[wait] Failed: {exc}")
                continue

            print("Unknown command. Type 'help' for options.")
    finally:
        await relay.close()
        print("Clearing session secrets and exiting.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Secure messaging CLI using the websocket relay server.",
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

