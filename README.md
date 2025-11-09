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
- `goclient/` - a self-contained Go CLI client that publishes keys, handles
  websocket signaling, performs the authenticated X25519 handshake, and drops
  into an encrypted chat loop (backed by its own `go.mod`).

Within `goclient/`, most of the logic lives in a single entrypoint for easy auditing:

```
goclient/
|-- client.go      # interactive CLI + crypto helpers
|-- go.mod
`-- go.sum
```


## Requirements

- Python 3.11+ if you prefer to run the FastAPI server directly instead of Docker
- Go 1.25+ for the CLI client in `goclient/` (the module targets Go 1.25.1)
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

## Running the Go client

```bash
cd goclient
go run .    # or go build .
```

On startup the client prompts for a username/password, generates a fresh
Ed25519 identity, publishes it with `POST /keys`, and connects to the registry's
websocket endpoint at `<server>/ws`. You will then be asked which peer username
to contact; once the peer accepts, the Go client performs the authenticated
X25519 handshake, derives chat keys, and drops into an encrypted session. Type
`/leave` or `/quit` to end the chat and return to the peer prompt. Each run
discards its keys and session state when the process exits.

The default server URL lives in `goclient/client.go` as `defaultServer` (it
currently points at `https://scheidker.com`). Change it to
`http://127.0.0.1:8000` before building if you're running the FastAPI registry
locally, or adjust it to match any other deployment.

All secrets (password, Ed25519 identity key, session keys) live only in memory
inside the Go process. Restarting the CLI forces a fresh identity.

## Protocol summary

1. **Account + key publication** – the CLI registers with the server,
   uploading an Ed25519 public key bound to the username.
2. **Signaling** - each client keeps a websocket open to `/ws`. Messages are
   relayed by username so initiators can page a peer, fetch their Ed25519 key,
   and confirm it against the registry before proceeding.
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
- The Go client expects a reachable websocket endpoint at `<server>/ws`; adjust
  `defaultServer` (or refactor it into a flag) when hopping between local and
  remote registries.
- `go fmt ./goclient && go build ./goclient` are quick sanity checks before
  pushing changes.

Enjoy experimenting with the protocol! Contributions that extend the
handshake analysis, add persistence, or explore alternative authentication
schemes are welcome.
