# SecureMessagingPlatform

A minimal secure-messaging demo that lets two named users discover one
another, verify identity through a trusted introducer, derive a fresh shared
secret, and exchange encrypted messages – all without any pre-shared keys.

The project is intentionally lightweight so the protocol flow is easy to
inspect and reason about.

## Repository layout

- `server/` - a tiny FastAPI registry that holds user accounts and their
  current Ed25519 public keys in memory. It exposes:
  - `POST /accounts` to create usernames with passwords (bcrypt hashes)
  - `POST /keys` to upload or rotate a user's public key
  - `GET /keys/{username}` to retrieve the stored key and version
- `client/` - an in-memory CLI client implemented with asyncio. It handles:
  - credentials + identity key generation on startup
  - account creation and key publication to the registry
  - UDP broadcast discovery with signed responses
  - mutual authentication and X25519 key agreement (handshake)
  - interactive chat using ChaCha20-Poly1305 with transcript binding
- `goclient/` - the Go client prototype (websocket/chat/crypto experiments, now self-contained with its own `go.mod`).

Within `client/`, the code is organised into small packages:

```
client/
├─ app.py              # script entrypoint that bootstraps the CLI
├─ cli/                # command loop and argument parsing
├─ chat/               # interactive send/receive routines
├─ common/             # shared config, state container, and utilities
├─ crypto/             # session wrapper and handshake helpers
└─ network/            # discovery, registry HTTP calls, framing, dial/listen
```

## Requirements

- Python 3.11+
- `pip install -r client/requirements.txt`
- (Optional) Docker if you prefer to run the FastAPI server via
  `docker compose`

The registry keeps all state in memory so restarting the process wipes all
accounts/keys. This is sufficient for demos and local testing.

## Running the server

### With Docker (recommended for quick starts)

```bash
cd server
docker compose up --build
```

This builds the FastAPI service image and exposes the HTTP API on
`http://127.0.0.1:8000`. Caddy is included in the compose file but can be
disabled or reconfigured if you don't need TLS termination.

### Directly with Python

```bash
cd server
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Either approach provides the same API surface; use whichever fits your
environment.

## Running the client

```bash
cd client
pip install -r requirements.txt
python app.py  # CLI prompts for username/password
```

Environment variable `KEY_SERVER_URL` defaults to `http://127.0.0.1:8000`.
Point it at your running registry if you change ports or deploy remotely.

### Go client prototype

```bash
cd goclient
go run .                # or go build .
```

That directory now holds a single-file Go client. Each run asks for credentials,
publishes a fresh Ed25519 key, performs the websocket handshake, and discards
all state on exit.

### CLI commands

Once authenticated the CLI exposes the following commands:

- `discover [port]` – broadcast on the LAN to find peers listening on the
  given UDP/TCP port (default `4040`). Responses are verified using the
  registry’s published keys.
- `listen [port]` – announce presence, accept a single inbound connection,
  run the authenticated handshake, then drop into the encrypted chat loop.
- `connect <peer> [port]` – dial a known peer by username (address learned
  from discovery or previous sessions). You can also specify
  `connect <host> <peer> [port]` to target a specific address manually.
- `help`, `quit` – show help or exit the program.

All secrets (password, Ed25519 identity key, session keys) live only in
memory. Closing the CLI clears them, forcing a fresh keypair next time.

## Protocol summary

1. **Account + key publication** – the CLI registers with the server,
   uploading an Ed25519 public key bound to the username.
2. **Discovery** – listeners broadcast signed announcements using that
   identity key; initiators fetch the expected key from the registry and
   verify the signature.
3. **Handshake** – both sides generate ephemeral X25519 keys, sign them
   with their Ed25519 identity, verify the peer via the registry, and feed
   the Diffie-Helman shared secret into HKDF. The transcript (ids, nonces,
   eph keys) is hashed and used as AEAD associated data.
4. **Messaging** – chat uses ChaCha20-Poly1305 with direction-specific
   nonces derived from incrementing counters, providing confidentiality,
   integrity, and replay protection for the session.

This design implements the “trusted introducer” model: authenticity rests on
the registry’s ability to distribute correct public keys.

## Development tips

- The server intentionally skips persistence so resetting state is as easy
  as restarting the process/container.
- Because the client relies on UDP broadcast for discovery, you’ll need to
  run peers on the same network segment (or specify host/port explicitly).
- `python -m compileall client` is a quick way to sanity-check for syntax
  errors after code changes.

Enjoy experimenting with the protocol! Contributions that extend the
handshake analysis, add persistence, or explore alternative authentication
schemes are welcome.
