from __future__ import annotations

"""Tiny FastAPI app that keeps users and keys in memory for easy demos."""

import bcrypt
import json
import time
from typing import Dict, Set

from fastapi import FastAPI, HTTPException, status, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

app = FastAPI(title="Public Key Server")


class KeyRegister(BaseModel):
    username: str
    password: str
    public_key: str

# Users live in memory only. Restarting the app gives a clean slate.
users: dict[str, dict[str, str | int]] = {}

# Active websocket connections per username (in-memory only)
connections: Dict[str, Set[WebSocket]] = {}


def hash_password(password: str) -> str:
    """Use bcrypt so each password gets a unique salt and slow hash."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(password: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except ValueError:
        return False


def validate_username(username: str) -> None:
    if not (3 <= len(username) <= 32) or " " in username:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Username must be 3-32 characters with no spaces.",
        )


@app.get("/status")
def status_endpoint() -> dict[str, str]:
    return {"status": "ok", "service": "public-key-server"}


@app.post("/keys")
def register_key(payload: KeyRegister) -> dict[str, int | str]:
    validate_username(payload.username)
    cleaned_key = payload.public_key.strip()
    if not cleaned_key:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Public key cannot be empty.")

    user = users.get(payload.username)
    if user is None:
        users[payload.username] = {
            "password_hash": hash_password(payload.password),
            "public_key": cleaned_key,
            "key_version": 1,
        }
        return {"status": "created", "key_version": 1}

    if not check_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")

    user["public_key"] = cleaned_key
    user["key_version"] = int(user.get("key_version", 0)) + 1
    return {"status": "updated", "key_version": user["key_version"]}


@app.get("/keys/{username}")
def get_key(username: str) -> dict[str, str | int]:
    validate_username(username)
    user = users.get(username)
    if user is None or not user.get("public_key"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No key stored for that user.")

    return {
        "username": username,
        "public_key": user["public_key"],
        "key_version": user.get("key_version", 0),
    }


@app.websocket("/ws")
async def websocket_router(ws: WebSocket) -> None:
    """
    Very small message forwarder:
    - Client connects with ?username=NAME
    - Incoming JSON: {"to": "Other", "type": "signal|data", "payload": {...}}
    - Server stamps {from, ts} and forwards to all sockets registered to "to".
    - If recipient offline, notify sender with {type: "delivery_status", to, status: "offline"}.
    """
    username = (ws.query_params.get("username") or "").strip()
    if not username:
        await ws.close(code=1008)
        return
    # Keep username validation consistent with the REST API
    try:
        validate_username(username)
    except HTTPException:
        await ws.close(code=1008)
        return

    await ws.accept()

    # Register connection
    connections.setdefault(username, set()).add(ws)

    try:
        while True:
            try:
                raw = await ws.receive_text()
            except WebSocketDisconnect:
                break
            except Exception:
                # Protocol error; close politely
                await ws.close(code=1003)
                break

            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                # Ignore invalid JSON
                continue

            to = msg.get("to")
            mtype = msg.get("type") or "data"
            payload = msg.get("payload")

            if not isinstance(to, str) or not to:
                # Minimal feedback on bad input
                try:
                    await ws.send_text(json.dumps({"type": "error", "error": "invalid_to"}))
                except Exception:
                    pass
                continue

            envelope = {
                "from": username,
                "type": mtype,
                "payload": payload,
                "ts": int(time.time() * 1000),
            }

            recipients = list(connections.get(to, set()))
            if not recipients:
                try:
                    await ws.send_text(json.dumps({
                        "type": "delivery_status",
                        "to": to,
                        "status": "offline",
                    }))
                except Exception:
                    pass
                continue

            for rws in recipients:
                try:
                    await rws.send_text(json.dumps(envelope))
                except Exception:
                    # Drop broken sockets
                    try:
                        await rws.close()
                    except Exception:
                        pass
                    target_set = connections.get(to)
                    if target_set is not None:
                        target_set.discard(rws)
                        if not target_set:
                            connections.pop(to, None)
    finally:
        # Remove this ws from the registry
        current = connections.get(username)
        if current is not None:
            current.discard(ws)
            if not current:
                connections.pop(username, None)
