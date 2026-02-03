from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, Any

from jose import jwt, JWTError
from passlib.context import CryptContext

MAX_BCRYPT_BYTES = 72

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


def _password_bytes(password: str) -> bytes:
    if password is None:
        raise ValueError("Password is required")

    raw = password.encode("utf-8")

    if len(raw) > MAX_BCRYPT_BYTES:
        raise ValueError(
            "Password too long for bcrypt (max 72 bytes). "
            "Avoid emojis or shorten the password."
        )

    return raw


def hash_password(password: str) -> str:
    # 🚨 ABSOLUTE GUARD — bcrypt never sees invalid input
    _password_bytes(password)
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        _password_bytes(password)
        return pwd_context.verify(password, hashed)
    except Exception:
        return False


def create_access_token(
    data: Dict[str, Any],
    secret: str,
    algorithm: str,
    expires_minutes: int,
) -> str:
    if not secret:
        raise ValueError("JWT secret missing")

    payload = dict(data)
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    payload["exp"] = expire

    return jwt.encode(payload, secret, algorithm=algorithm)


def decode_token(token: str, secret: str, algorithm: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, secret, algorithms=[algorithm])
    except JWTError as e:
        raise ValueError("Invalid or expired token") from e

def hash_otp(otp: str) -> str:
    return pwd_context.hash(otp)

def verify_otp(otp: str, otp_hash: str) -> bool:
    return pwd_context.verify(otp, otp_hash)