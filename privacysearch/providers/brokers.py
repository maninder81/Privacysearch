"""Searches people-search sites for a protected person's listing."""

from __future__ import annotations

import html
import re
from datetime import date

from ..brokers import render_search_url
from .base import Fetcher, ScanReport, http_fetch

BLOCK_MARKERS = ("captcha", "are you a robot", "access denied", "cf-chl", "verify you are human")


def page_text(body: str) -> str:
    body = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", body)
    body = re.sub(r"(?s)<[^>]+>", " ", body)
    return " ".join(html.unescape(body).lower().split())


def fingerprint(broker_id: str, full_name: str) -> str:
    return f"broker:{broker_id}:{' '.join(full_name.lower().split())}"


def match_listing(text: str, full_name: str, profile: dict) -> tuple[float, set[str], list[str]] | None:
    """Return (confidence, data_types, evidence) if the page appears to list this person."""
    parts = full_name.lower().split()
    first, last = re.escape(parts[0]), re.escape(parts[-1])
    if not re.search(rf"\b{first}\b(?:\s+[\w.'-]+){{0,2}}\s+\b{last}\b", text):
        return None
    confidence, types, evidence = 0.3, {"name"}, ["name"]
    for addr in profile.get("addresses", []):
        city = addr.get("city", "").lower()
        if city and re.search(rf"\b{re.escape(city)}\b", text):
            confidence = max(confidence, 0.7)
            types.add("home_address")
            evidence.append(f"city:{addr['city']}")
            street = addr.get("street", "").lower()
            if street and street in text:
                confidence = max(confidence, 0.95)
                evidence.append("street")
    digits = re.sub(r"\D", "", text)
    for phone in profile.get("phones", []):
        tail = re.sub(r"\D", "", phone)[-10:]
        if len(tail) >= 7 and tail in digits:
            confidence = max(confidence, 0.9)
            types.add("phone")
            evidence.append("phone")
    by = profile.get("birth_year")
    if by:
        age = date.today().year - by
        if re.search(rf"\b(age|aged)\s*:?\s*({age}|{age - 1})\b", text):
            confidence = min(1.0, confidence + 0.1)
            types.add("age")
            evidence.append("age")
    for email in profile.get("emails", []):
        if email in text:
            confidence = max(confidence, 0.9)
            types.add("email")
            evidence.append("email")
    return confidence, types, evidence


class BrokerSearchProvider:
    """Fetches each broker's public search page and looks for the person.

    Many brokers block automated requests; those are reported as manual checks with the URL to open.
    With assume_listed=True, brokers that cannot be checked are recorded as presumed exposures so
    Autopilot files proactive opt-outs (the approach most removal services take).
    """

    id = "brokers"

    def __init__(self, brokers: dict[str, dict], fetch: Fetcher | None = None, assume_listed: bool = False,
                 min_confidence: float = 0.5):
        self.brokers = brokers
        self.fetch = fetch or (lambda url, headers: http_fetch(url, headers))
        self.assume_listed = assume_listed
        self.min_confidence = min_confidence

    def _regions(self, profile: dict) -> set[str]:
        juris = profile.get("jurisdiction", "US")
        return {"global", "US"} if juris.startswith("US") else {"global", juris}

    def scan(self, profile: dict) -> ScanReport:
        report = ScanReport()
        regions = self._regions(profile)
        locations = [(a.get("city", ""), a.get("region", "")) for a in profile.get("addresses", [])] or [("", "")]
        for broker in self.brokers.values():
            if broker.get("region", "global") not in regions:
                continue
            for full_name in profile.get("full_names", []):
                fp = fingerprint(broker["id"], full_name)
                result = self._check(broker, full_name, profile, locations)
                if result is None:
                    report.manual_checks.append({
                        "source_id": broker["id"], "source_name": broker["name"], "name": full_name,
                        "search_url": self._first_url(broker, full_name, locations),
                        "optout_url": broker.get("optout_url"),
                    })
                    if self.assume_listed:
                        report.findings.append(self._finding(broker, full_name, fp, 0.5, set(broker["data_types"]),
                                                             None, ["presumed"]))
                    continue
                report.checked.add(fp)
                if result == "absent":
                    continue
                conf, types, evidence, url = result
                if conf >= self.min_confidence:
                    report.findings.append(self._finding(broker, full_name, fp, conf, types, url, evidence))
        return report

    def _first_url(self, broker: dict, full_name: str, locations) -> str | None:
        if not broker.get("search_url"):
            return None
        parts = full_name.split()
        for city, state in locations:
            url = render_search_url(broker["search_url"], parts[0], parts[-1], city, state)
            if url:
                return url
        return None

    def _check(self, broker, full_name, profile, locations):
        """Returns None (could not check), 'absent', or (confidence, types, evidence, url)."""
        if not broker.get("search_url"):
            return None
        parts = full_name.split()
        best, any_checked = None, False
        for city, state in locations:
            url = render_search_url(broker["search_url"], parts[0], parts[-1], city, state)
            if not url:
                continue
            status, body = self.fetch(url, {})
            low = body[:20000].lower()
            if status != 200 and status != 404:
                continue
            if status == 200 and any(m in low for m in BLOCK_MARKERS):
                continue
            any_checked = True
            if status == 404:
                continue
            m = match_listing(page_text(body), full_name, profile)
            if m and (best is None or m[0] > best[0]):
                best = (*m, url)
        if best:
            return best
        return "absent" if any_checked else None

    def _finding(self, broker, full_name, fp, confidence, types, url, evidence) -> dict:
        return {
            "source_id": broker["id"], "source_name": broker["name"], "source_type": "broker",
            "fingerprint": fp, "url": url, "data_types": sorted(types), "confidence": round(confidence, 2),
            "details": {"name": full_name, "evidence": evidence, "optout_url": broker.get("optout_url")},
        }
