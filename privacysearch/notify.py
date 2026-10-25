"""Alert delivery (console, webhook, email) and digests."""

from __future__ import annotations

import json
import os
import smtplib
import ssl
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from .risk import coverage
from .storage import Store

SEVERITY_ORDER = {"low": 0, "info": 0, "medium": 1, "high": 2, "critical": 3}


class Mailer:
    """SMTP sender configured from PRIVACYSEARCH_SMTP_* environment variables."""

    def __init__(self, host: str, port: int, username: str | None, password: str | None, sender: str,
                 starttls: bool = True):
        self.host, self.port, self.username, self.password = host, port, username, password
        self.sender, self.starttls = sender, starttls

    @classmethod
    def from_env(cls) -> "Mailer | None":
        host = os.environ.get("PRIVACYSEARCH_SMTP_HOST")
        sender = os.environ.get("PRIVACYSEARCH_SMTP_FROM")
        if not host or not sender:
            return None
        return cls(host, int(os.environ.get("PRIVACYSEARCH_SMTP_PORT", "587")),
                   os.environ.get("PRIVACYSEARCH_SMTP_USER"), os.environ.get("PRIVACYSEARCH_SMTP_PASSWORD"),
                   sender, os.environ.get("PRIVACYSEARCH_SMTP_STARTTLS", "1") != "0")

    def send(self, to: str, subject: str, body: str, reply_to: str | None = None) -> None:
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self.sender, to, subject
        if reply_to:
            msg["Reply-To"] = reply_to
        msg.set_content(body)
        with smtplib.SMTP(self.host, self.port, timeout=30) as smtp:
            if self.starttls:
                smtp.starttls(context=ssl.create_default_context())
            if self.username:
                smtp.login(self.username, self.password or "")
            smtp.send_message(msg)


class ConsoleChannel:
    def __init__(self, stream=None):
        self.stream = stream or sys.stdout

    def send(self, alerts: list[dict]) -> None:
        for a in alerts:
            print(f"[{a['severity'].upper():8}] {a['created_at']} {a['kind']}: {a['message']}", file=self.stream)


class WebhookChannel:
    def __init__(self, url: str):
        self.url = url

    def send(self, alerts: list[dict]) -> None:
        payload = json.dumps({"alerts": alerts}).encode()
        req = urllib.request.Request(self.url, data=payload, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=15).close()


class EmailChannel:
    def __init__(self, mailer: Mailer, to: str):
        self.mailer, self.to = mailer, to

    def send(self, alerts: list[dict]) -> None:
        if alerts:
            body = "\n".join(f"[{a['severity']}] {a['kind']}: {a['message']}" for a in alerts)
            self.mailer.send(self.to, f"PrivacySearch: {len(alerts)} new alert(s)", body)


class Notifier:
    def __init__(self, store: Store, channels: list, min_severity: str = "low"):
        self.store, self.channels, self.min_severity = store, channels, min_severity

    def deliver(self) -> int:
        pending = self.store.alerts(undelivered=True)
        wanted = [a for a in pending if SEVERITY_ORDER.get(a["severity"], 0) >= SEVERITY_ORDER[self.min_severity]]
        for ch in self.channels:
            try:
                ch.send(wanted)
            except Exception as exc:  # noqa: BLE001 - leave undelivered so the next cycle retries
                print(f"alert channel {type(ch).__name__} failed: {exc}", file=sys.stderr)
                return 0
        self.store.mark_delivered(a["id"] for a in pending)
        return len(wanted)


def digest(store: Store, hours: int = 24) -> str:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    lines = [f"PrivacySearch digest - last {hours}h", ""]
    for p in store.list_profiles():
        cov = coverage(store.exposures(p["id"]))
        alerts = store.alerts(p["id"], since=since)
        open_removals = [r for r in store.removals(p["id"]) if r["closed_at"] is None]
        lines.append(f"{p['label']} ({p['id']})")
        lines.append(f"  Coverage Score {cov['coverage_score']}/100, exposure level {cov['exposure_level']}, "
                     f"{cov['open_exposures']} open / {cov['resolved_exposures']} resolved exposures")
        lines.append(f"  {len(open_removals)} removal(s) in progress, {len(alerts)} new alert(s)")
        for a in alerts:
            lines.append(f"    - [{a['severity']}] {a['message']}")
        lines.append("")
    return "\n".join(lines)
