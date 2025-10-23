"""Interactive chat loop helpers."""

from __future__ import annotations

import asyncio

from client.crypto.core import SecureSession
from client.network.transport import read_frame, write_frame


async def send_loop(writer, session: SecureSession) -> None:
    loop = asyncio.get_running_loop()
    try:
        while True:
            text = await loop.run_in_executor(None, lambda: input("you> ").strip())
            if not text:
                continue
            if text in {"/quit", "/leave"}:
                print("Closing session.")
                writer.close()
                await writer.wait_closed()
                break
            ciphertext = session.encrypt(text.encode("utf-8"))
            await write_frame(writer, ciphertext)
    except (asyncio.CancelledError, EOFError):
        pass


async def recv_loop(reader, session: SecureSession) -> None:
    try:
        while True:
            frame = await read_frame(reader)
            try:
                plaintext = session.decrypt(frame).decode("utf-8")
            except Exception as exc:  # noqa: BLE001
                print(f"[!] Decryption failed: {exc}")
                continue
            print(f"{session.peer}> {plaintext}")
    except asyncio.IncompleteReadError:
        print("[session] Peer closed the connection.")
    except asyncio.CancelledError:
        pass


async def run_chat(reader, writer, session: SecureSession) -> None:
    sender = asyncio.create_task(send_loop(writer, session))
    receiver = asyncio.create_task(recv_loop(reader, session))
    done, pending = await asyncio.wait(
        {sender, receiver},
        return_when=asyncio.FIRST_COMPLETED,
    )
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    for task in done:
        _ = task.exception()

