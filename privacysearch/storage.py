"""SQLite persistence. Personal data columns are encrypted with the Vault."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .crypto import Vault

SCHEMA = """
CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    data_enc TEXT NOT NULL,
    autopilot INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exposures (
    id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL,
    source_name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    url TEXT,
    data_types TEXT NOT NULL,
    confidence REAL NOT NULL,
    risk INTEGER NOT NULL,
    status TEXT NOT NULL,
    details_enc TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(profile_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS removals (
    id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    exposure_id TEXT NOT NULL REFERENCES exposures(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL,
    method TEXT NOT NULL,
    legal_basis TEXT NOT NULL,
    status TEXT NOT NULL,
    letter_enc TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    submitted_at TEXT,
    next_check_at TEXT,
    closed_at TEXT,
    note TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    profile_id TEXT REFERENCES profiles(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS watches (
    id TEXT PRIMARY KEY,
    profile_id TEXT REFERENCES profiles(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value_enc TEXT NOT NULL,
    state_enc TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    subject TEXT NOT NULL,
    secret_hash TEXT NOT NULL UNIQUE,
    scopes TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    key_id TEXT,
    identifier_type TEXT NOT NULL,
    identifier_index TEXT NOT NULL,
    status TEXT NOT NULL,
    result_enc TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS scans_lookup ON scans(identifier_type, identifier_index, created_at);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


class Store:
    def __init__(self, path: Path | str, vault: Vault):
        self.vault = vault
        self._lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self.db.close()

    # -- generic helpers -------------------------------------------------
    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self.db.execute(sql, tuple(params))
            self.db.commit()
            return cur

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.db.execute(sql, tuple(params)).fetchall()

    def one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def audit(self, actor: str, action: str, target: str | None = None) -> None:
        self.execute(
            "INSERT INTO audit_log(ts, actor, action, target) VALUES (?,?,?,?)",
            (now(), actor, action, target),
        )

    # -- profiles --------------------------------------------------------
    def add_profile(self, label: str, data: dict, autopilot: bool = True) -> str:
        pid = new_id("prof")
        self.execute(
            "INSERT INTO profiles(id, label, data_enc, autopilot, created_at) VALUES (?,?,?,?,?)",
            (pid, label, self.vault.encrypt(data), int(autopilot), now()),
        )
        return pid

    def update_profile(self, pid: str, data: dict) -> None:
        self.execute("UPDATE profiles SET data_enc=? WHERE id=?", (self.vault.encrypt(data), pid))

    def get_profile(self, pid: str) -> dict | None:
        row = self.one("SELECT * FROM profiles WHERE id=?", (pid,))
        if not row:
            return None
        return {
            "id": row["id"],
            "label": row["label"],
            "autopilot": bool(row["autopilot"]),
            "created_at": row["created_at"],
            "data": self.vault.decrypt(row["data_enc"]),
        }

    def list_profiles(self) -> list[dict]:
        return [self.get_profile(r["id"]) for r in self.query("SELECT id FROM profiles ORDER BY created_at")]

    def delete_profile(self, pid: str) -> bool:
        return self.execute("DELETE FROM profiles WHERE id=?", (pid,)).rowcount > 0

    # -- exposures -------------------------------------------------------
    def exposure_by_fingerprint(self, pid: str, fingerprint: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM exposures WHERE profile_id=? AND fingerprint=?", (pid, fingerprint))

    def insert_exposure(self, pid: str, finding: dict, risk: int) -> str:
        eid = new_id("exp")
        ts = now()
        self.execute(
            """INSERT INTO exposures(id, profile_id, source_id, source_name, source_type, fingerprint, url,
               data_types, confidence, risk, status, details_enc, first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                eid, pid, finding["source_id"], finding["source_name"], finding["source_type"],
                finding["fingerprint"], finding.get("url"), json.dumps(sorted(finding["data_types"])),
                finding["confidence"], risk, "active", self.vault.encrypt(finding.get("details", {})), ts, ts,
            ),
        )
        return eid

    def touch_exposure(self, eid: str, status: str | None = None) -> None:
        if status:
            self.execute("UPDATE exposures SET last_seen=?, status=? WHERE id=?", (now(), status, eid))
        else:
            self.execute("UPDATE exposures SET last_seen=? WHERE id=?", (now(), eid))

    def set_exposure_status(self, eid: str, status: str) -> None:
        self.execute("UPDATE exposures SET status=? WHERE id=?", (status, eid))

    def exposures(self, pid: str, status: str | None = None) -> list[dict]:
        sql, params = "SELECT * FROM exposures WHERE profile_id=?", [pid]
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += " ORDER BY risk DESC, first_seen"
        return [self._exposure(r) for r in self.query(sql, params)]

    def get_exposure(self, eid: str) -> dict | None:
        row = self.one("SELECT * FROM exposures WHERE id=?", (eid,))
        return self._exposure(row) if row else None

    def _exposure(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        d["data_types"] = json.loads(d["data_types"])
        d["details"] = self.vault.decrypt(d.pop("details_enc"))
        return d

    # -- removals --------------------------------------------------------
    def insert_removal(self, rec: dict) -> str:
        rid = new_id("rem")
        self.execute(
            """INSERT INTO removals(id, profile_id, exposure_id, source_id, method, legal_basis, status,
               letter_enc, attempts, created_at, next_check_at, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                rid, rec["profile_id"], rec["exposure_id"], rec["source_id"], rec["method"], rec["legal_basis"],
                rec["status"], self.vault.encrypt(rec.get("letter")), 0, now(), rec.get("next_check_at"),
                rec.get("note"),
            ),
        )
        return rid

    def update_removal(self, rid: str, **fields: Any) -> None:
        if "letter" in fields:
            fields["letter_enc"] = self.vault.encrypt(fields.pop("letter"))
        cols = ", ".join(f"{k}=?" for k in fields)
        self.execute(f"UPDATE removals SET {cols} WHERE id=?", (*fields.values(), rid))

    def removals(self, pid: str | None = None, status: str | None = None) -> list[dict]:
        sql, params = "SELECT * FROM removals WHERE 1=1", []
        if pid:
            sql += " AND profile_id=?"
            params.append(pid)
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += " ORDER BY created_at"
        return [self._removal(r) for r in self.query(sql, params)]

    def open_removal_for(self, exposure_id: str) -> dict | None:
        row = self.one(
            "SELECT * FROM removals WHERE exposure_id=? AND closed_at IS NULL ORDER BY created_at DESC",
            (exposure_id,),
        )
        return self._removal(row) if row else None

    def get_removal(self, rid: str) -> dict | None:
        row = self.one("SELECT * FROM removals WHERE id=?", (rid,))
        return self._removal(row) if row else None

    def _removal(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        d["letter"] = self.vault.decrypt(d.pop("letter_enc"))
        return d

    # -- alerts ----------------------------------------------------------
    def add_alert(self, pid: str | None, kind: str, severity: str, message: str) -> str:
        aid = new_id("alert")
        self.execute(
            "INSERT INTO alerts(id, profile_id, kind, severity, message, created_at) VALUES (?,?,?,?,?,?)",
            (aid, pid, kind, severity, message, now()),
        )
        return aid

    def alerts(self, pid: str | None = None, undelivered: bool = False, since: str | None = None) -> list[dict]:
        sql, params = "SELECT * FROM alerts WHERE 1=1", []
        if pid:
            sql += " AND profile_id=?"
            params.append(pid)
        if undelivered:
            sql += " AND delivered=0"
        if since:
            sql += " AND created_at>=?"
            params.append(since)
        sql += " ORDER BY created_at"
        return [dict(r) for r in self.query(sql, params)]

    def mark_delivered(self, ids: Iterable[str]) -> None:
        for aid in ids:
            self.execute("UPDATE alerts SET delivered=1 WHERE id=?", (aid,))

    # -- watches ---------------------------------------------------------
    def add_watch(self, pid: str | None, kind: str, value: str) -> str:
        wid = new_id("watch")
        self.execute(
            "INSERT INTO watches(id, profile_id, kind, value_enc, state_enc, created_at) VALUES (?,?,?,?,?,?)",
            (wid, pid, kind, self.vault.encrypt(value), self.vault.encrypt(None), now()),
        )
        return wid

    def watches(self) -> list[dict]:
        out = []
        for r in self.query("SELECT * FROM watches ORDER BY created_at"):
            d = dict(r)
            d["value"] = self.vault.decrypt(d.pop("value_enc"))
            d["state"] = self.vault.decrypt(d.pop("state_enc"))
            out.append(d)
        return out

    def set_watch_state(self, wid: str, state: Any) -> None:
        self.execute("UPDATE watches SET state_enc=? WHERE id=?", (self.vault.encrypt(state), wid))

    def delete_watch(self, wid: str) -> bool:
        return self.execute("DELETE FROM watches WHERE id=?", (wid,)).rowcount > 0

    # -- export ----------------------------------------------------------
    def export_profile(self, pid: str) -> dict | None:
        profile = self.get_profile(pid)
        if not profile:
            return None
        return {
            "profile": profile,
            "exposures": self.exposures(pid),
            "removals": self.removals(pid),
            "alerts": self.alerts(pid),
            "watches": [w for w in self.watches() if w["profile_id"] == pid],
        }
