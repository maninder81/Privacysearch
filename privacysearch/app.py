"""Wires configuration, storage and providers together."""

from __future__ import annotations

import os
from pathlib import Path

from .brokers import load_brokers
from .crypto import Vault, default_home, load_or_create_key
from .notify import ConsoleChannel, EmailChannel, Mailer, Notifier, WebhookChannel
from .providers.brokers import BrokerSearchProvider
from .providers.hibp import HIBPClient, HIBPProvider
from .storage import Store


class App:
    def __init__(self, home: Path | None = None, fetch=None, assume_listed: bool | None = None):
        self.home = Path(home) if home else default_home()
        self.home.mkdir(parents=True, exist_ok=True)
        self.vault = Vault(load_or_create_key(self.home))
        self.store = Store(self.home / "privacysearch.db", self.vault)
        self.brokers = load_brokers(self.home / "brokers.json")
        self.fetch = fetch
        self.assume_listed = (os.environ.get("PRIVACYSEARCH_ASSUME_LISTED") == "1"
                              if assume_listed is None else assume_listed)
        self.hibp = HIBPClient(os.environ.get("HIBP_API_KEY"), fetch=fetch)
        self.mailer = Mailer.from_env()

    def providers(self) -> list:
        return [
            BrokerSearchProvider(self.brokers, fetch=self.fetch, assume_listed=self.assume_listed),
            HIBPProvider(self.hibp, self.vault.index),
        ]

    def notifier(self) -> Notifier:
        channels = [ConsoleChannel()]
        if url := os.environ.get("PRIVACYSEARCH_WEBHOOK_URL"):
            channels.append(WebhookChannel(url))
        if self.mailer and (to := os.environ.get("PRIVACYSEARCH_ALERT_EMAIL")):
            channels.append(EmailChannel(self.mailer, to))
        return Notifier(self.store, channels, os.environ.get("PRIVACYSEARCH_ALERT_MIN_SEVERITY", "low"))

    def close(self) -> None:
        self.store.close()
        if tmp := getattr(self, "_tmp", None):
            tmp.cleanup()
