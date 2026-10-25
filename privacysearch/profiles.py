"""Validation and normalisation of protected-person profiles."""

from __future__ import annotations

import re

JURISDICTIONS = {"EU", "UK", "US", "US-CA", "CA", "AU", "NZ", "OTHER"}
US_PRIVACY_STATES = {
    "CO", "CT", "DE", "IA", "IN", "KY", "MD", "MN", "MT", "NE", "NH", "NJ", "OR", "RI", "TN", "TX", "UT", "VA",
}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LIST_FIELDS = ("full_names", "emails", "phones", "usernames")


def normalise_phone(phone: str) -> str:
    digits = re.sub(r"[^\d+]", "", phone)
    if not re.fullmatch(r"\+?\d{7,15}", digits):
        raise ValueError(f"invalid phone number: {phone!r}")
    return digits


def parse_address(text: str) -> dict:
    """Parse 'street;city;region;postal_code;country' (trailing parts optional)."""
    parts = [p.strip() for p in text.split(";")]
    keys = ["street", "city", "region", "postal_code", "country"]
    addr = {k: (parts[i] if i < len(parts) else "") for i, k in enumerate(keys)}
    if not addr["city"]:
        raise ValueError(f"address needs at least 'street;city': {text!r}")
    return addr


def normalise_profile(data: dict) -> dict:
    out: dict = {k: [] for k in LIST_FIELDS}
    out["addresses"] = []
    for name in data.get("full_names", []):
        name = " ".join(name.split())
        if len(name.split()) < 2:
            raise ValueError(f"full name needs first and last name: {name!r}")
        out["full_names"].append(name)
    for email in data.get("emails", []):
        email = email.strip().lower()
        if not EMAIL_RE.match(email):
            raise ValueError(f"invalid email: {email!r}")
        out["emails"].append(email)
    out["phones"] = [normalise_phone(p) for p in data.get("phones", [])]
    out["usernames"] = [u.strip().lstrip("@") for u in data.get("usernames", []) if u.strip()]
    for addr in data.get("addresses", []):
        out["addresses"].append(parse_address(addr) if isinstance(addr, str) else {**addr})
    if not out["full_names"] and not out["emails"]:
        raise ValueError("a profile needs at least one full name or email")
    by = data.get("birth_year")
    out["birth_year"] = int(by) if by else None
    juris = (data.get("jurisdiction") or "US").upper()
    if juris not in JURISDICTIONS and not (juris.startswith("US-") and len(juris) == 5):
        raise ValueError(f"unknown jurisdiction {juris!r}; use one of {sorted(JURISDICTIONS)} or US-<state>")
    out["jurisdiction"] = juris
    for k in LIST_FIELDS:
        out[k] = list(dict.fromkeys(out[k]))
    return out


def identifiers(profile_data: dict) -> list[tuple[str, str]]:
    """All (type, value) identifiers a profile owns, used to restrict API scans to protected people."""
    ids = [("email", e) for e in profile_data.get("emails", [])]
    ids += [("phone", p) for p in profile_data.get("phones", [])]
    ids += [("username", u) for u in profile_data.get("usernames", [])]
    return ids
