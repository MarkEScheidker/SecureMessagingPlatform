"""Shared configuration constants for the secure messaging client."""

from __future__ import annotations

import os

DEFAULT_SERVER_URL = os.getenv("KEY_SERVER_URL", "https://scheidker.com")
DISCOVERY_REQUEST = b"SMDISCOVER|v1"
DISCOVERY_RESPONSE_HEADER = (b"SMHELLO", b"v1")
PROTOCOL_TAG = b"smproto-v1"
DEFAULT_PORT = 4040

