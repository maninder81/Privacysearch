"""Have I Been Pwned: breached accounts, pastes, site breaches and k-anonymity password checks."""

from __future__ import annotations

import hashlib
import json
import time
from urllib.parse import quote

from .base import Fetcher, ScanReport, http_fetch

API = "https://haveibeenpwned.com/api/v3"
PWNED_PASSWORDS = "https://api.pwnedpasswords.com/range/"

DATA_CLASS_MAP = {
    "email addresses": "email", "passwords": "password", "password hints": "password",
    "phone numbers": "phone", "physical addresses": "home_address", "dates of birth": "dob",
    "names": "name", "usernames": "username", "ip addresses": "ip", "geographic locations": "location",
    "employers": "employer", "credit cards": "financial", "partial credit card data": "financial",
    "bank account numbers": "financial", "social security numbers": "government_id",
    "government issued ids": "government_id", "passport numbers": "government_id",
    "security questions and answers": "security_qa", "profile photos": "photo", "family members' names": "relatives",
}


class HIBPError(RuntimeError):
    pass


def map_data_classes(classes: list[str]) -> list[str]:
    return sorted({DATA_CLASS_MAP.get(c.lower(), "other") for c in classes})


def remediation(data_types: list[str]) -> list[str]:
    steps = []
    if "password" in data_types:
        steps.append("Change this password everywhere you reused it and enable multi-factor authentication.")
    if "financial" in data_types:
        steps.append("Watch card and bank statements; ask your bank to reissue affected cards.")
    if "government_id" in data_types:
        steps.append("Consider a credit freeze and identity-theft monitoring.")
    if "security_qa" in data_types:
        steps.append("Change security questions on accounts that use the same answers.")
    if "phone" in data_types:
        steps.append("Expect targeted smishing; ask your carrier for a SIM-swap / port-out PIN.")
    steps.append("Be alert to phishing that references this breach.")
    return steps


class HIBPClient:
    def __init__(self, api_key: str | None, fetch: Fetcher | None = None, max_retries: int = 3):
        self.api_key = api_key
        self.fetch = fetch or (lambda url, headers: http_fetch(url, headers))
        self.max_retries = max_retries

    def _get(self, url: str, auth: bool = True):
        headers = {"hibp-api-key": self.api_key} if auth and self.api_key else {}
        for attempt in range(self.max_retries + 1):
            status, body = self.fetch(url, headers)
            if status == 200:
                return json.loads(body) if body.strip() else []
            if status == 404:
                return []
            if status == 429 and attempt < self.max_retries:
                time.sleep(min(2 ** attempt, 8))
                continue
            if status == 401:
                raise HIBPError("HIBP rejected the API key (set HIBP_API_KEY)")
            raise HIBPError(f"HIBP request failed with status {status}")
        raise HIBPError("HIBP rate limit persisted")

    def breached_account(self, email: str) -> list[dict]:
        if not self.api_key:
            raise HIBPError("HIBP_API_KEY is required for breached-account lookups")
        return self._get(f"{API}/breachedaccount/{quote(email)}?truncateResponse=false")

    def pastes(self, email: str) -> list[dict]:
        if not self.api_key:
            raise HIBPError("HIBP_API_KEY is required for paste lookups")
        return self._get(f"{API}/pasteaccount/{quote(email)}")

    def site_breaches(self, domain: str) -> list[dict]:
        return self._get(f"{API}/breaches?domain={quote(domain)}", auth=False)

    def password_count(self, password: str) -> int:
        """Times a password appears in breaches. Only the first 5 SHA-1 hex chars leave this machine."""
        digest = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        status, body = self.fetch(PWNED_PASSWORDS + prefix, {"Add-Padding": "true"})
        if status != 200:
            raise HIBPError(f"Pwned Passwords request failed with status {status}")
        for line in body.splitlines():
            h, _, count = line.strip().partition(":")
            if h == suffix:
                return int(count)
        return 0


def breach_finding(breach: dict, email: str, index: str) -> dict:
    types = map_data_classes(breach.get("DataClasses", []))
    return {
        "source_id": f"hibp:{breach['Name']}", "source_name": breach.get("Title", breach["Name"]),
        "source_type": "breach", "fingerprint": f"breach:{breach['Name']}:{index}",
        "url": f"https://haveibeenpwned.com/PwnedWebsites#{breach['Name']}",
        "data_types": types, "confidence": 1.0 if breach.get("IsVerified", True) else 0.7,
        "details": {
            "account": email, "breach_date": breach.get("BreachDate"), "domain": breach.get("Domain"),
            "pwn_count": breach.get("PwnCount"), "is_sensitive": breach.get("IsSensitive", False),
            "remediation": remediation(types),
        },
    }


def paste_finding(paste: dict, email: str, index: str) -> dict:
    pid = f"{paste.get('Source')}:{paste.get('Id')}"
    return {
        "source_id": f"paste:{paste.get('Source')}", "source_name": f"Paste on {paste.get('Source')}",
        "source_type": "paste", "fingerprint": f"paste:{pid}:{index}", "url": None,
        "data_types": ["email"], "confidence": 1.0,
        "details": {"account": email, "title": paste.get("Title"), "date": paste.get("Date"),
                    "email_count": paste.get("EmailCount"), "remediation": remediation(["email"])},
    }


class HIBPProvider:
    id = "hibp"

    def __init__(self, client: HIBPClient, index_fn):
        self.client = client
        self.index_fn = index_fn

    def scan(self, profile: dict) -> ScanReport:
        report = ScanReport()
        if not self.client.api_key:
            report.errors.append("breach monitoring disabled: set HIBP_API_KEY")
            return report
        for email in profile.get("emails", []):
            idx = self.index_fn(email)[:16]
            try:
                breaches = self.client.breached_account(email)
                pastes = self.client.pastes(email)
            except HIBPError as exc:
                report.errors.append(f"{email}: {exc}")
                continue
            for b in breaches:
                f = breach_finding(b, email, idx)
                report.findings.append(f)
                report.checked.add(f["fingerprint"])
            for p in pastes:
                f = paste_finding(p, email, idx)
                report.findings.append(f)
                report.checked.add(f["fingerprint"])
        return report
