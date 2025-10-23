"""Binary framing helpers for TCP streams."""

from __future__ import annotations

import struct
from asyncio import StreamReader, StreamWriter


async def read_frame(reader: StreamReader) -> bytes:
    """Read a length-prefixed frame from the stream."""
    header = await reader.readexactly(4)
    length = struct.unpack("!I", header)[0]
    return await reader.readexactly(length)


async def write_frame(writer: StreamWriter, payload: bytes) -> None:
    """Write a length-prefixed frame to the stream."""
    writer.write(struct.pack("!I", len(payload)) + payload)
    await writer.drain()

