# SecureMessagingPlatform

Goal: let two users discover each other, authenticate identities through a trusted introducer, agree on a fresh session key, and chat with authenticated encryption—without any pre-shared secrets.

## What lives where

- `server/` – FastAPI registry (in-memory accounts + Ed25519 keys, HTTPS assumed in deployment). Endpoints: `POST /accounts`, `POST /keys`, `GET /keys/{username}`, and a websocket relay at `/ws`.
- `goclient/` – Go CLI (single `client.go`) that publishes keys, controls the websocket, runs the signed X25519 handshake, and hosts the ChaCha20-Poly1305 chat loop.

## Quick start

### Registry (already hosted)

A ready-to-use registry is running at `https://scheidker.com` and is the recommended target for testing.

### Go client

```bash
cd goclient
go run .          # prompts for creds + peer
```

Set `SMSERVER_HOST` (e.g., `http://127.0.0.1:8000`) if you are not using the compiled-in default (`https://scheidker.com`). The default points to a live instance already hosted at scheidker.com so you can test immediately. Each client run generates a new Ed25519 identity, uploads it, and keeps all secrets in memory only.

## Protocol at a glance

1. **Key publication** – user authenticates to the registry with username/password, uploads Ed25519 public key.
2. **Discovery** – both clients hold a websocket to `/ws`; messages are addressed by username.
3. **Handshake** – initiator/responder generate ephemeral X25519 keys, sign payloads with Ed25519, verify signatures using the registry’s copy, and feed the shared secret through HKDF with the transcript as AAD (forward secrecy + MitM resistance).
4. **Messaging** – ChaCha20-Poly1305 with monotonic, role-tagged counters as nonces. Counters are checked on receipt to reject replays.

Model: trusted introducer. If the registry serves the wrong key, the scheme fails; otherwise, every chat inherits identity authentication from that source.

## Notes

- No persistence: restarting the server wipes accounts/keys, keeping demos deterministic.
- Client commands: `/leave` or `/quit` exit a chat; SIGINT during peer wait cancels cleanly.
- Crypto choices: Ed25519 for identity, X25519 for DH, HKDF-SHA256 for key schedule, ChaCha20-Poly1305 for AEAD, separate nonces for send/receive streams.

That’s the whole system—fire up two clients pointed at the same registry, have them request each other, and you can observe every requirement (discovery, authentication, key exchange, encrypted messaging) end to end.
