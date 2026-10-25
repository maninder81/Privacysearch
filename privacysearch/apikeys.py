"""API keys: shown once, stored as SHA-256 hashes, scoped, expiring, rotatable and revocable."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

from .storage import Store, new_id, now

SCOPES = {
    "account:read": "Verify the key and read account status (GET /v1/hello).",
    "darkweb:scan": "Start breach scans; also read scans created by this key.",
    "darkweb:read": "Read breach scan results by id.",
    "darkweb:reveal": "Read unmasked breach values (?reveal=true). Every reveal is audit-logged.",
    "profiles:read": "Read protected profiles, exposures, removals and Coverage Scores.",
    "profiles:write": "Create protected profiles (bulk onboarding) and trigger scans.",
}


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def create_key(store: Store, name: str, scopes: list[str], subject: str = "org_local",
               expires_days: int | None = None) -> tuple[str, str]:
    unknown = set(scopes) - SCOPES.keys()
    if unknown:
        raise ValueError(f"unknown scopes: {sorted(unknown)}")
    if not scopes:
        raise ValueError("a key needs at least one scope")
    secret = "ak_" + secrets.token_urlsafe(32)
    kid = new_id("key")
    expires = None
    if expires_days:
        expires = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat(timespec="seconds")
    store.execute(
        "INSERT INTO api_keys(id, name, subject, secret_hash, scopes, created_at, expires_at) VALUES (?,?,?,?,?,?,?)",
        (kid, name, subject, _hash(secret), json.dumps(sorted(set(scopes))), now(), expires),
    )
    store.audit("cli", "api_key_created", kid)
    return kid, secret


def verify(store: Store, secret: str) -> dict | None:
    row = store.one("SELECT * FROM api_keys WHERE secret_hash=?", (_hash(secret),))
    if not row or row["revoked_at"] or (row["expires_at"] and row["expires_at"] <= now()):
        return None
    d = dict(row)
    d["scopes"] = json.loads(d["scopes"])
    return d


def list_keys(store: Store) -> list[dict]:
    out = []
    for r in store.query("SELECT id, name, subject, scopes, created_at, expires_at, revoked_at FROM api_keys"):
        d = dict(r)
        d["scopes"] = json.loads(d["scopes"])
        out.append(d)
    return out


def revoke(store: Store, kid: str) -> bool:
    ok = store.execute("UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (now(), kid)).rowcount > 0
    if ok:
        store.audit("cli", "api_key_revoked", kid)
    return ok


def rotate(store: Store, kid: str) -> str:
    """Issue a new secret for an existing key id; the old secret stops working immediately."""
    row = store.one("SELECT * FROM api_keys WHERE id=? AND revoked_at IS NULL", (kid,))
    if not row:
        raise ValueError(f"no active key {kid}")
    secret = "ak_" + secrets.token_urlsafe(32)
    store.execute("UPDATE api_keys SET secret_hash=? WHERE id=?", (_hash(secret), kid))
    store.audit("cli", "api_key_rotated", kid)
    return secret
