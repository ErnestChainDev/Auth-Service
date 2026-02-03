from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from jose import jwt, JWTError
from passlib.context import CryptContext

MAX_BCRYPT_BYTES = 72

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _assert_bcrypt_len(password: str) -> None:
    """
    bcrypt only uses first 72 bytes of the password.
    We enforce <= 72 bytes to avoid silent truncation / runtime errors.
    """
    if password is None:
        raise ValueError("Password is required.")
    if len(password.encode("utf-8")) > MAX_BCRYPT_BYTES:
        raise ValueError("Password too long (max 72 bytes for bcrypt).")


def hash_password(password: str) -> str:
    _assert_bcrypt_len(password)
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """
    Returns False if:
    - password is too long (bcrypt limit)
    - hashed value is invalid/corrupted/unknown scheme
    - verification fails
    """
    try:
        _assert_bcrypt_len(password)
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
        raise ValueError("JWT secret is missing.")
    if expires_minutes <= 0:
        raise ValueError("expires_minutes must be > 0.")

    to_encode = dict(data)
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret, algorithm=algorithm)


def decode_token(token: str, secret: str, algorithm: str) -> Dict[str, Any]:
    if not token:
        raise ValueError("Token is required.")
    if not secret:
        raise ValueError("JWT secret is missing.")

    try:
        payload = jwt.decode(token, secret, algorithms=[algorithm])
        # Optional: ensure expected fields exist if you rely on them
        # e.g. payload must contain "sub" and "email"
        return payload
    except JWTError as e:
        raise ValueError("Invalid token") from e
