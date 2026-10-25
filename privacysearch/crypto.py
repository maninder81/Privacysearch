"""Field-level encryption for personal data stored at rest."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

ENV_KEY = "PRIVACYSEARCH_KEY"


def default_home() -> Path:
    return Path(os.environ.get("PRIVACYSEARCH_HOME", Path.home() / ".privacysearch"))


def load_or_create_key(home: Path | None = None) -> bytes:
    """Return the Fernet key from the environment or the key file, creating the file if needed."""
    env = os.environ.get(ENV_KEY)
    if env:
        return env.encode()
    home = home or default_home()
    home.mkdir(parents=True, exist_ok=True)
    path = home / "secret.key"
    if path.exists():
        return path.read_bytes().strip()
    key = Fernet.generate_key()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


class Vault:
    """Encrypts JSON-serialisable values and derives keyed hashes for lookups."""

    def __init__(self, key: bytes):
        self._fernet = Fernet(key)
        # Separate subkey so lookup hashes cannot be reversed with the encryption key alone.
        self._hash_key = hashlib.sha256(b"privacysearch-index:" + key).digest()

    def encrypt(self, value: Any) -> str:
        return self._fernet.encrypt(json.dumps(value).encode()).decode()

    def decrypt(self, token: str | None) -> Any:
        if token is None:
            return None
        try:
            return json.loads(self._fernet.decrypt(token.encode()))
        except InvalidToken as exc:
            raise ValueError("cannot decrypt stored data: wrong PRIVACYSEARCH_KEY?") from exc

    def index(self, value: str) -> str:
        """Deterministic keyed hash of a normalised identifier, safe to store in clear."""
        return hmac.new(self._hash_key, value.strip().lower().encode(), hashlib.sha256).hexdigest()
