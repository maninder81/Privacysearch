from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Protocol

USER_AGENT = "PrivacySearch/0.1 (+self-hosted personal privacy monitor)"

# (url, headers) -> (status, body). Injectable so tests and alternative transports can replace it.
Fetcher = Callable[[str, dict], tuple[int, str]]


def http_fetch(url: str, headers: dict | None = None, timeout: float = 20.0) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace") if exc.fp else ""
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, str(exc)


@dataclass
class ScanReport:
    findings: list[dict] = field(default_factory=list)
    # Fingerprints that were actually checked; a checked fingerprint missing from findings means "not listed".
    checked: set[str] = field(default_factory=set)
    # Sources that could not be checked automatically (blocked, captcha, no search URL).
    manual_checks: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def merge(self, other: "ScanReport") -> None:
        self.findings += other.findings
        self.checked |= other.checked
        self.manual_checks += other.manual_checks
        self.errors += other.errors


class Provider(Protocol):
    id: str

    def scan(self, profile: dict) -> ScanReport: ...
