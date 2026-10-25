"""Removal requests: legal-basis selection, letter generation, Autopilot submission and follow-up."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .brokers import removal_channel
from .profiles import US_PRIVACY_STATES
from .storage import Store, now

MAX_ATTEMPTS = 3

LEGAL_BASES = {
    "EU": ("GDPR Art. 17", "Article 17 of the General Data Protection Regulation (EU) 2016/679 (right to erasure)",
           "one month (Art. 12(3) GDPR)"),
    "UK": ("UK GDPR Art. 17", "Article 17 of the UK GDPR and the Data Protection Act 2018 (right to erasure)",
           "one month (Art. 12(3) UK GDPR)"),
    "US-CA": ("CCPA §1798.105", "the California Consumer Privacy Act as amended by the CPRA, Cal. Civ. Code "
              "§1798.105 (right to delete), and the Delete Act (SB 362) where you are a registered data broker",
              "45 days (Cal. Civ. Code §1798.130)"),
    "US-STATE": ("State privacy law", "the consumer data privacy law of my state of residence (right to delete)",
                 "45 days"),
    "US": ("Opt-out request", "your published opt-out / suppression policy", "a reasonable time"),
    "CA": ("PIPEDA", "the Personal Information Protection and Electronic Documents Act (Principle 4.3.8, "
           "withdrawal of consent) and applicable provincial law", "30 days"),
    "AU": ("Privacy Act 1988 APP 11/13", "the Australian Privacy Principles 11.2 and 13 under the Privacy Act 1988",
           "30 days"),
    "NZ": ("Privacy Act 2020 IPP 7", "Information Privacy Principle 7 of the Privacy Act 2020", "20 working days"),
    "OTHER": ("Erasure request", "applicable data protection law", "30 days"),
}

NOT_REMOVABLE_TYPES = {"breach", "paste"}


def legal_basis_key(jurisdiction: str) -> str:
    if jurisdiction in LEGAL_BASES:
        return jurisdiction
    if jurisdiction.startswith("US-"):
        return "US-STATE" if jurisdiction[3:] in US_PRIVACY_STATES else "US"
    return "OTHER"


def generate_letter(profile: dict, exposure: dict, broker: dict | None) -> dict:
    """Builds a data-minimised erasure request: only identifiers needed to find the record are included."""
    data = profile["data"]
    key = legal_basis_key(data.get("jurisdiction", "US"))
    short, law, deadline = LEGAL_BASES[key]
    name = exposure.get("details", {}).get("name") or (data.get("full_names") or [""])[0]
    reply_to = (data.get("emails") or [""])[0]
    company = broker["name"] if broker else exposure["source_name"]
    lines = [
        f"To the Data Protection / Privacy team at {company},",
        "",
        f"I am writing to request the deletion of all personal data you hold about me, under {law}.",
        "",
        "Please identify my record using the details below:",
        f"  Name: {name}",
    ]
    if exposure.get("url"):
        lines.append(f"  Listing URL: {exposure['url']}")
    for addr in data.get("addresses", [])[:1]:
        loc = ", ".join(p for p in (addr.get("city"), addr.get("region")) if p)
        if loc:
            lines.append(f"  Location shown: {loc}")
    lines += [
        "",
        "I request that you:",
        "  1. Delete my personal data and remove any profile or listing about me;",
        "  2. Stop selling or sharing my personal data and suppress it from future data acquisition;",
        "  3. Instruct any processors or third parties you disclosed it to, to delete it as well;",
        f"  4. Confirm completion in writing within {deadline}.",
        "",
        "Please do not use the details in this request for any purpose other than fulfilling it. "
        "If you need to verify my identity, tell me what you need and I will provide only that.",
        "",
        "Regards,",
        name,
    ]
    if reply_to:
        lines.append(reply_to)
    return {"subject": f"Personal data deletion request ({short}) - {name}", "body": "\n".join(lines),
            "legal_basis": short, "to": broker.get("optout_email") if broker else None, "reply_to": reply_to}


def form_instructions(broker: dict, exposure: dict, removal_id: str) -> str:
    return (f"Open {broker['optout_url']} and submit the opt-out for the listing "
            f"{exposure.get('url') or '(search your name on the site)'}. Use a masked email if the form asks for one. "
            f"Then run: privacysearch removal mark {removal_id} --status submitted")


def create_removal(store: Store, profile: dict, exposure: dict, brokers: dict[str, dict]) -> str | None:
    """Queue a removal for an exposure unless one is already open. Breaches get remediation instead."""
    if exposure["source_type"] in NOT_REMOVABLE_TYPES:
        return None
    if store.open_removal_for(exposure["id"]):
        return None
    broker = brokers.get(exposure["source_id"])
    letter = generate_letter(profile, exposure, broker)
    channel = removal_channel(broker) if broker else "manual"
    status = "queued" if channel == "email" else "action_required"
    rid = store.insert_removal({
        "profile_id": profile["id"], "exposure_id": exposure["id"], "source_id": exposure["source_id"],
        "method": channel, "legal_basis": letter["legal_basis"], "status": status, "letter": letter,
    })
    note = form_instructions(broker, exposure, rid) if channel == "web_form" else None
    if note:
        store.update_removal(rid, note=note)
    store.set_exposure_status(exposure["id"], "removal_requested" if status == "queued" else "action_required")
    if status == "action_required":
        store.add_alert(profile["id"], "removal_action_required", "medium",
                        f"{exposure['source_name']}: opt-out needs a web form. {note or ''}".strip())
    return rid


def _due(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds")


def mark_submitted(store: Store, removal: dict, brokers: dict[str, dict]) -> None:
    broker = brokers.get(removal["source_id"], {})
    store.update_removal(removal["id"], status="submitted", submitted_at=now(),
                         attempts=removal["attempts"] + 1, next_check_at=_due(int(broker.get("expected_days", 14))))
    store.set_exposure_status(removal["exposure_id"], "removal_requested")


def process_queue(store: Store, brokers: dict[str, dict], mailer=None, profile_id: str | None = None) -> dict:
    """Autopilot: send queued email removals. Returns counts by outcome."""
    counts = {"sent": 0, "skipped_no_mailer": 0, "failed": 0}
    for rem in store.removals(profile_id, status="queued"):
        letter = rem["letter"]
        if not mailer or not letter.get("to"):
            counts["skipped_no_mailer"] += 1
            continue
        try:
            mailer.send(letter["to"], letter["subject"], letter["body"], reply_to=letter.get("reply_to"))
        except Exception as exc:  # noqa: BLE001 - any transport error leaves the request queued for retry
            counts["failed"] += 1
            store.update_removal(rem["id"], note=f"send failed: {exc}")
            continue
        mark_submitted(store, rem, brokers)
        store.audit("autopilot", "removal_sent", rem["id"])
        counts["sent"] += 1
    return counts


def is_due(removal: dict) -> bool:
    return bool(removal.get("next_check_at")) and removal["next_check_at"] <= now()


def on_still_listed(store: Store, removal: dict, profile_id: str, source_name: str) -> None:
    """A submitted removal reached its check date but the listing is still there: re-file or give up."""
    if removal["attempts"] >= MAX_ATTEMPTS:
        store.update_removal(removal["id"], status="failed", closed_at=now(),
                             note=f"still listed after {removal['attempts']} attempts")
        store.set_exposure_status(removal["exposure_id"], "active")
        store.add_alert(profile_id, "removal_failed", "high",
                        f"{source_name} has not removed your listing after {removal['attempts']} requests. "
                        "Consider a regulator complaint.")
        return
    next_status = "queued" if removal["method"] == "email" else "action_required"
    store.update_removal(removal["id"], status=next_status, next_check_at=None,
                         note=f"re-filing (attempt {removal['attempts'] + 1})")
    if next_status == "action_required":
        store.add_alert(profile_id, "removal_action_required", "medium",
                        f"{source_name} still lists you; please re-submit the opt-out form.")


def on_gone(store: Store, removal: dict | None, exposure_id: str) -> None:
    if removal:
        store.update_removal(removal["id"], status="confirmed", closed_at=now())
    store.set_exposure_status(exposure_id, "removed")
