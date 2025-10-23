from __future__ import annotations

"""Tiny FastAPI app that keeps users and keys in memory for easy demos."""

import bcrypt
from dataclasses import dataclass

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="Public Key Server")


@dataclass
class StoredUser:
    password_hash: str
    public_key: str = ""
    key_version: int = 0


class AccountCreate(BaseModel):
    username: str
    password: str


class KeyRegister(BaseModel):
    username: str
    password: str
    public_key: str


class PublicKey(BaseModel):
    username: str
    public_key: str
    key_version: int


# Users live in memory only. Restarting the app gives a clean slate.
users: dict[str, StoredUser] = {}


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


@app.post("/accounts", status_code=status.HTTP_201_CREATED)
def create_account(payload: AccountCreate) -> dict[str, str]:
    validate_username(payload.username)
    if payload.username in users:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists.")

    users[payload.username] = StoredUser(password_hash=hash_password(payload.password))
    return {"status": "created"}


@app.post("/keys")
def register_key(payload: KeyRegister) -> dict[str, int | str]:
    validate_username(payload.username)
    user = users.get(payload.username)
    if user is None or not check_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")

    cleaned_key = payload.public_key.strip()
    if not cleaned_key:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Public key cannot be empty.")

    user.public_key = cleaned_key
    user.key_version += 1
    return {"status": "updated", "key_version": user.key_version}


@app.get("/keys/{username}")
def get_key(username: str) -> PublicKey:
    validate_username(username)
    user = users.get(username)
    if user is None or not user.public_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No key stored for that user.")

    return PublicKey(username=username, public_key=user.public_key, key_version=user.key_version)
