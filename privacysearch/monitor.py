"""Scanning, reconciliation against stored exposures, watches ("deployed agents") and the monitor loop."""

from __future__ import annotations

import time

from . import removal
from .intel import lookalikes, resolves
from .providers import ScanReport
from .providers.brokers import page_text
from .risk import OPEN_STATUSES, exposure_risk, severity
from .storage import Store


def scan_profile(store: Store, profile: dict, providers: list, brokers: dict[str, dict]) -> dict:
    """Run every provider for a profile and reconcile results with what is already stored."""
    report = ScanReport()
    for provider in providers:
        try:
            report.merge(provider.scan(profile["data"]))
        except Exception as exc:  # noqa: BLE001 - one broken provider must not stop the others
            report.errors.append(f"{provider.id}: {exc}")

    pid = profile["id"]
    summary = {"new": 0, "reappeared": 0, "still_listed": 0, "gone": 0, "manual_checks": report.manual_checks,
               "errors": report.errors}
    found = set()
    for f in report.findings:
        found.add(f["fingerprint"])
        existing = store.exposure_by_fingerprint(pid, f["fingerprint"])
        risk = exposure_risk(f["data_types"], f["confidence"], f["source_type"])
        if existing is None:
            eid = store.insert_exposure(pid, f, risk)
            summary["new"] += 1
            sev = severity(risk)
            what = ", ".join(t.replace("_", " ") for t in f["data_types"])
            if "presumed" in f.get("details", {}).get("evidence", []):
                message = (f"{f['source_name']} could not be checked automatically; it typically holds "
                           f"{what}. Filing a proactive opt-out.")
            else:
                message = f"{f['source_name']} exposes your {what}."
            store.add_alert(pid, f"new_{f['source_type']}", sev, message)
            if profile["autopilot"]:
                removal.create_removal(store, profile, store.get_exposure(eid), brokers)
            continue
        status = existing["status"]
        if status == "removed":
            store.touch_exposure(existing["id"], "reappeared")
            summary["reappeared"] += 1
            store.add_alert(pid, "reappeared", "high", f"{f['source_name']} re-listed your data after removal.")
            if profile["autopilot"]:
                removal.create_removal(store, profile, store.get_exposure(existing["id"]), brokers)
            continue
        store.touch_exposure(existing["id"])
        if status in ("dismissed", "mitigated"):
            continue
        summary["still_listed"] += 1
        open_rem = store.open_removal_for(existing["id"])
        if open_rem and open_rem["status"] == "submitted" and removal.is_due(open_rem):
            removal.on_still_listed(store, open_rem, pid, f["source_name"])

    for fp in report.checked - found:
        existing = store.exposure_by_fingerprint(pid, fp)
        if existing and existing["status"] in OPEN_STATUSES:
            removal.on_gone(store, store.open_removal_for(existing["id"]), existing["id"])
            summary["gone"] += 1
            store.add_alert(pid, "removed", "low", f"Your listing on {existing['source_name']} is gone.")
    store.audit("scanner", "scan_profile", pid)
    return summary


def run_watches(store: Store, fetch=None, resolve=resolves) -> int:
    """Check every watch once and raise an alert for anything new. Returns number of alerts raised."""
    raised = 0
    for w in store.watches():
        state = w["state"] or {}
        if w["kind"] == "lookalike_domain":
            seen = set(state.get("registered", []))
            registered = sorted(d for d in lookalikes(w["value"]) if resolve(d))
            for d in sorted(set(registered) - seen):
                store.add_alert(w["profile_id"], "lookalike_domain", "high",
                                f"Lookalike of {w['value']} is live: {d}")
                raised += 1
            store.set_watch_state(w["id"], {"registered": registered})
        elif w["kind"] == "page_keyword":
            url, _, keyword = w["value"].partition(" ")
            status, body = (fetch or _default_fetch)(url, {})
            present = status == 200 and keyword.lower() in page_text(body)
            if present and not state.get("present"):
                store.add_alert(w["profile_id"], "keyword_seen", "medium", f"'{keyword}' now appears on {url}")
                raised += 1
            store.set_watch_state(w["id"], {"present": present, "status": status})
    return raised


def _default_fetch(url, headers):
    from .providers.base import http_fetch
    return http_fetch(url, headers)


def run_cycle(app) -> dict:
    results = {}
    for profile in app.store.list_profiles():
        results[profile["id"]] = scan_profile(app.store, profile, app.providers(), app.brokers)
    results["autopilot"] = removal.process_queue(app.store, app.brokers, app.mailer)
    results["watch_alerts"] = run_watches(app.store)
    results["alerts_delivered"] = app.notifier().deliver()
    return results


def monitor_forever(app, interval: int) -> None:
    while True:
        started = time.monotonic()
        try:
            run_cycle(app)
        except Exception as exc:  # noqa: BLE001 - keep monitoring through transient failures
            print(f"monitor cycle failed: {exc}")
        time.sleep(max(60, interval - (time.monotonic() - started)))
