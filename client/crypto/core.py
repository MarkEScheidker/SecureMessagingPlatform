"""Cryptographic helpers and session primitives."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from client.common.config import PROTOCOL_TAG


@dataclass
class SecureSession:
    """Keeps per-session encryption state and monotonic nonces."""

    role: str
    username: str
    peer: str
    session_key: bytes
    transcript_hash: bytes

    def __post_init__(self) -> None:
        self.cipher = ChaCha20Poly1305(self.session_key)
        self.peer_role = "responder" if self.role == "initiator" else "initiator"
        self.send_counter = 0
        self.recv_counter = 0

    def _nonce(self, counter: int, role: str) -> bytes:
        prefix = b"INIT" if role == "initiator" else b"RESP"
        return prefix + struct.pack("!Q", counter)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = self._nonce(self.send_counter, self.role)
        self.send_counter += 1
        return self.cipher.encrypt(nonce, plaintext, self.transcript_hash)

    def decrypt(self, ciphertext: bytes) -> bytes:
        nonce = self._nonce(self.recv_counter, self.peer_role)
        self.recv_counter += 1
        return self.cipher.decrypt(nonce, ciphertext, self.transcript_hash)


def handshake_payload(event: str, sender: str, receiver: str, eph_pub: bytes, nonce: bytes) -> bytes:
    """Build the signed payload shared during the handshake."""
    return b"|".join(
        [
            PROTOCOL_TAG,
            event.encode("utf-8"),
            sender.encode("utf-8"),
            receiver.encode("utf-8"),
            eph_pub,
            nonce,
        ]
    )


def derive_session(
    *,
    username: str,
    peer_username: str,
    local_nonce: bytes,
    remote_nonce: bytes,
    local_eph: bytes,
    remote_eph: bytes,
    private_key: x25519.X25519PrivateKey,
) -> tuple[bytes, bytes]:
    """Derive a symmetric session key and transcript hash for the connection."""
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(remote_eph)
    shared_secret = private_key.exchange(peer_public_key)

    if username <= peer_username:
        ordered_users = (username, peer_username)
        eph_concat = local_eph + remote_eph
        nonce_concat = local_nonce + remote_nonce
    else:
        ordered_users = (peer_username, username)
        eph_concat = remote_eph + local_eph
        nonce_concat = remote_nonce + local_nonce

    transcript = b"|".join(
        [
            PROTOCOL_TAG,
            ordered_users[0].encode("utf-8"),
            ordered_users[1].encode("utf-8"),
            eph_concat,
            nonce_concat,
        ]
    )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=transcript,
    )
    session_key = hkdf.derive(shared_secret)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(transcript)
    transcript_hash = digest.finalize()
    return session_key, transcript_hash

