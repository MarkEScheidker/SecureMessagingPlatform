"""Generic helper utilities used across client modules."""

from __future__ import annotations

import base64


def b64e(data: bytes) -> str:
    """Base64 encode bytes to an ASCII string."""
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    """Decode a Base64-encoded ASCII string into bytes."""
    return base64.b64decode(data.encode("ascii"))


def input_trim(prompt: str) -> str:
    """Read a line from stdin and trim leading/trailing whitespace."""
    return input(prompt).strip()

