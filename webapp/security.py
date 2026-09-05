from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


class SecretBox:
    def __init__(self, key_path: Path) -> None:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            key = key_path.read_bytes().strip()
        else:
            key = Fernet.generate_key()
            key_path.write_bytes(key)
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
        self.fernet = Fernet(key)

    def encrypt(self, value: str) -> str:
        return self.fernet.encrypt(value.encode()).decode()

    def decrypt(self, value: str | None) -> str | None:
        if not value:
            return None
        try:
            return self.fernet.decrypt(value.encode()).decode()
        except InvalidToken:
            return None


def ensure_secret(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="ascii").strip()
    value = secrets.token_urlsafe(48)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="ascii")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return value


def csrf_token(session: dict) -> str:
    token = session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf"] = token
    return token


def verify_csrf(session: dict, supplied: str) -> bool:
    expected = session.get("csrf", "")
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))
