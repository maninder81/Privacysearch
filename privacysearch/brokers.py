"""Data broker registry loading and search-URL rendering."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from urllib.parse import quote

REQUIRED = {"id", "name", "domain", "data_types"}


def load_brokers(extra_path: Path | None = None) -> dict[str, dict]:
    """Load the bundled registry, then merge user entries (same id overrides) from extra_path."""
    bundled = json.loads(resources.files("privacysearch").joinpath("data/brokers.json").read_text())
    brokers = {b["id"]: b for b in bundled["brokers"]}
    if extra_path and extra_path.exists():
        for entry in json.loads(extra_path.read_text()).get("brokers", []):
            missing = REQUIRED - entry.keys()
            if missing:
                raise ValueError(f"broker entry {entry.get('id')!r} missing fields: {sorted(missing)}")
            brokers[entry["id"]] = {**brokers.get(entry["id"], {}), **entry}
    for b in brokers.values():
        b.setdefault("search_url", None)
        b.setdefault("optout_url", None)
        b.setdefault("optout_email", None)
        b.setdefault("expected_days", 14)
        b.setdefault("region", "global")
        b.setdefault("category", "people_search")
    return brokers


def render_search_url(template: str, first: str, last: str, city: str = "", state: str = "") -> str | None:
    """Fill a search URL template. Returns None if it needs a location we don't have."""
    if not city and "{city}" in template.lower():
        return None
    if not state and "{state}" in template.lower():
        return None

    def enc(s: str) -> str:
        return quote(s.strip().replace(" ", "-"), safe="-")

    values = {
        "first": enc(first.lower()), "last": enc(last.lower()),
        "city": enc(city.lower()), "state": enc(state.lower()),
        "First": enc(first.title()), "Last": enc(last.title()),
        "City": enc(city.title()), "STATE": enc(state.upper()),
    }
    return template.format(**values)


def removal_channel(broker: dict) -> str:
    if broker.get("optout_email"):
        return "email"
    if broker.get("optout_url"):
        return "web_form"
    return "manual"
