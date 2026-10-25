"""Identifier breach scans behind the /v1/darkweb API, with masking."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .profiles import identifiers
from .providers.hibp import HIBPClient, map_data_classes
from .storage import Store, new_id, now

SUPPORTED = ("email", "password", "domain")
ALL_TYPES = ("email", "phone", "username", "domain", "keyword", "origin", "password")
PERSONAL_TYPES = {"email", "phone", "username"}
REUSE_WINDOW = timedelta(hours=24)


class ScanError(Exception):
    def __init__(self, status: int, type_: str, code: str, message: str):
        super().__init__(message)
        self.status, self.type, self.code, self.message = status, type_, code, message


def mask_value(value):
    if not isinstance(value, str) or not value:
        return None if isinstance(value, str) else value
    if "@" in value:
        user, _, domain = value.partition("@")
        return f"{user[:1]}***@{domain[:1]}***"
    return value[:1] + "***" if len(value) > 2 else "***"


def mask_result(result: dict) -> dict:
    breaches = [{**b, "breachedData": {k: None if isinstance(v, str) else v for k, v in b["breachedData"].items()}, "isMasked": True}
                for b in result["breaches"]]
    extracted = {k: [mask_value(v) for v in vals] for k, vals in result["extractedData"].items()}
    return {**result, "breaches": breaches, "extractedData": extracted}


def _authority(b: dict) -> dict:
    return {"name": b.get("Title", b.get("Name")), "domain": b.get("Domain"), "logoPath": b.get("LogoPath"),
            "dataClasses": b.get("DataClasses", []), "breachDate": b.get("BreachDate"),
            "isVerified": b.get("IsVerified", True)}


def execute(hibp: HIBPClient, itype: str, value: str, emit=None) -> dict:
    """Run a scan synchronously. emit(event, data) is called for each finding (used for SSE)."""
    emit = emit or (lambda event, data: None)
    breaches, pastes = [], []
    extracted = {"emails": [], "usernames": [], "phones": [], "names": [], "cryptoAddresses": []}
    if itype == "email":
        extracted["emails"].append(value)
        for b in hibp.breached_account(value):
            item = {"name": b["Name"], "breachedData": {"email": value, **{t: True for t in
                    map_data_classes(b.get("DataClasses", [])) if t != "email"}},
                    "isMasked": False, "breachAuthority": _authority(b)}
            breaches.append(item)
            emit("breach", item)
        for p in hibp.pastes(value):
            item = {"source": p.get("Source"), "id": p.get("Id"), "title": p.get("Title"), "date": p.get("Date"),
                    "emailCount": p.get("EmailCount")}
            pastes.append(item)
            emit("paste", item)
    elif itype == "password":
        count = hibp.password_count(value)
        if count:
            item = {"name": "PwnedPasswords", "breachedData": {"password": value, "occurrences": count},
                    "isMasked": False, "breachAuthority": {"name": "Pwned Passwords", "domain": None,
                                                           "dataClasses": ["Passwords"]}}
            breaches.append(item)
            emit("breach", item)
    elif itype == "domain":
        for b in hibp.site_breaches(value):
            item = {"name": b["Name"], "breachedData": {"domain": value, "pwnCount": b.get("PwnCount")},
                    "isMasked": False, "breachAuthority": _authority(b)}
            breaches.append(item)
            emit("breach", item)
    return {"breaches": breaches, "pastes": pastes, "extractedData": extracted}


class ScanService:
    def __init__(self, store: Store, hibp: HIBPClient, restrict_to_profiles: bool = True):
        self.store, self.hibp, self.restrict = store, hibp, restrict_to_profiles

    def _index(self, itype: str, value: str) -> str:
        return self.store.vault.index(f"{itype}:{value}")

    def validate(self, body: dict) -> tuple[str, str]:
        itype, value = body.get("identifierType"), body.get("identifierValue")
        details = []
        if itype not in ALL_TYPES:
            details.append({"field": "identifierType", "message": f"must be one of {list(ALL_TYPES)}"})
        if not isinstance(value, str) or not value.strip():
            details.append({"field": "identifierValue", "message": "required non-empty string"})
        if details:
            err = ScanError(422, "invalid_request_error", "validation_failed", "Request body validation failed")
            err.details = details
            raise err
        if itype not in SUPPORTED:
            raise ScanError(422, "invalid_request_error", "identifier_type_not_supported",
                            f"identifierType '{itype}' has no configured provider; supported: {list(SUPPORTED)}")
        value = value.strip() if itype == "password" else value.strip().lower()
        if self.restrict and itype in PERSONAL_TYPES and not self._owned(itype, value):
            raise ScanError(403, "feature_not_allowed", "identifier_not_protected",
                            "Only identifiers belonging to a protected profile can be scanned")
        return itype, value

    def _owned(self, itype: str, value: str) -> bool:
        return any((t, v.lower()) == (itype, value) for p in self.store.list_profiles() for t, v in identifiers(p["data"]))

    def recent(self, itype: str, value: str) -> dict | None:
        since = (datetime.now(timezone.utc) - REUSE_WINDOW).isoformat(timespec="seconds")
        row = self.store.one(
            "SELECT id FROM scans WHERE identifier_type=? AND identifier_index=? AND status='success' "
            "AND created_at>=? ORDER BY created_at DESC", (itype, self._index(itype, value), since))
        return self.get(row["id"]) if row else None

    def create(self, key_id: str, itype: str, value: str) -> str:
        sid = new_id("scan")
        self.store.execute(
            "INSERT INTO scans(id, key_id, identifier_type, identifier_index, status, created_at) VALUES (?,?,?,?,?,?)",
            (sid, key_id, itype, self._index(itype, value), "processing", now()))
        return sid

    def run(self, sid: str, itype: str, value: str, emit=None) -> dict | None:
        try:
            result = execute(self.hibp, itype, value, emit)
        except Exception as exc:  # noqa: BLE001 - surfaced to the client as a failed scan
            self.store.execute("UPDATE scans SET status='failed', error=?, finished_at=? WHERE id=?",
                               (str(exc), now(), sid))
            raise
        self.store.execute("UPDATE scans SET status='success', result_enc=?, finished_at=? WHERE id=?",
                           (self.store.vault.encrypt(result), now(), sid))
        return result

    def get(self, sid: str) -> dict | None:
        row = self.store.one("SELECT * FROM scans WHERE id=?", (sid,))
        if not row:
            return None
        return {"id": row["id"], "key_id": row["key_id"], "status": row["status"],
                "identifierType": row["identifier_type"], "createdAt": row["created_at"],
                "finishedAt": row["finished_at"], "error": row["error"],
                "result": self.store.vault.decrypt(row["result_enc"])}
