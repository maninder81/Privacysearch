"""Command-line interface: `privacysearch --help`."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from . import apikeys, removal
from .app import App
from .intel import check_sender, lookalikes, resolves
from .monitor import monitor_forever, run_cycle, run_watches, scan_profile
from .notify import digest
from .profiles import normalise_profile
from .risk import coverage, severity
from .storage import now


def _print_json(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _profile(app: App, pid: str) -> dict:
    p = app.store.get_profile(pid)
    if not p:
        sys.exit(f"no profile {pid}")
    return p


def cmd_init(app, args):
    print(f"PrivacySearch home: {app.home}")
    print("Encryption key: " + ("PRIVACYSEARCH_KEY env" if "PRIVACYSEARCH_KEY" in os.environ
                                 else str(app.home / "secret.key")) + "  (back it up; data is unreadable without it)")
    print(f"Brokers loaded: {len(app.brokers)}")
    print("Breach monitoring: " + ("enabled" if app.hibp.api_key else "disabled (set HIBP_API_KEY)"))
    print("Autopilot email: " + ("enabled" if app.mailer else "disabled (set PRIVACYSEARCH_SMTP_HOST/FROM)"))


def cmd_profile_add(app, args):
    data = normalise_profile({
        "full_names": args.name or [], "emails": args.email or [], "phones": args.phone or [],
        "addresses": args.address or [], "usernames": args.username or [], "birth_year": args.birth_year,
        "jurisdiction": args.jurisdiction,
    })
    pid = app.store.add_profile(args.label, data, autopilot=not args.no_autopilot)
    app.store.audit("cli", "profile_created", pid)
    print(pid)


def cmd_profile_import(app, args):
    items = json.loads(Path(args.file).read_text())
    items = items.get("profiles", items) if isinstance(items, dict) else items
    normalised = []
    for i, item in enumerate(items):
        try:
            normalised.append((item["label"], normalise_profile(item), item.get("autopilot", True)))
        except (KeyError, ValueError) as exc:
            sys.exit(f"profile #{i}: {exc}")
    for label, data, auto in normalised:
        pid = app.store.add_profile(label, data, bool(auto))
        print(f"{pid}\t{label}")


def cmd_profile_list(app, args):
    for p in app.store.list_profiles():
        cov = coverage(app.store.exposures(p["id"]))
        print(f"{p['id']}\t{p['label']}\tcoverage {cov['coverage_score']}/100\t{cov['exposure_level']}"
              f"\tautopilot {'on' if p['autopilot'] else 'off'}")


def cmd_profile_show(app, args):
    _print_json(_profile(app, args.id))


def cmd_profile_export(app, args):
    data = app.store.export_profile(args.id) or sys.exit(f"no profile {args.id}")
    app.store.audit("cli", "profile_exported", args.id)
    text = json.dumps(data, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(text)
        print(f"wrote {args.output}")
    else:
        print(text)


def cmd_profile_delete(app, args):
    if not args.yes:
        sys.exit("refusing to delete without --yes (this erases the profile, exposures, removals and alerts)")
    if not app.store.delete_profile(args.id):
        sys.exit(f"no profile {args.id}")
    app.store.audit("cli", "profile_deleted", args.id)
    print(f"deleted {args.id}")


def cmd_scan(app, args):
    profile = _profile(app, args.id)
    if args.assume_listed:
        app.assume_listed = True
    summary = scan_profile(app.store, profile, app.providers(), app.brokers)
    cov = coverage(app.store.exposures(profile["id"]))
    print(f"new {summary['new']}, reappeared {summary['reappeared']}, still listed {summary['still_listed']}, "
          f"gone {summary['gone']}")
    print(f"Coverage Score {cov['coverage_score']}/100, exposure level {cov['exposure_level']}")
    for err in summary["errors"]:
        print(f"warning: {err}", file=sys.stderr)
    if summary["manual_checks"] and args.show_manual:
        print("\nCould not check automatically (open these yourself):")
        for m in summary["manual_checks"]:
            print(f"  {m['source_name']}: {m['search_url'] or 'search on site'}  opt-out: {m['optout_url']}")
    elif summary["manual_checks"]:
        print(f"{len(summary['manual_checks'])} source(s) need a manual check; rerun with --show-manual "
              "or --assume-listed to file proactive opt-outs")
    if profile["autopilot"]:
        counts = removal.process_queue(app.store, app.brokers, app.mailer, profile["id"])
        if counts["sent"]:
            print(f"Autopilot sent {counts['sent']} removal request(s)")
    app.notifier().deliver()


def cmd_exposures(app, args):
    _profile(app, args.id)
    rows = app.store.exposures(args.id, args.status)
    if args.json:
        return _print_json(rows)
    for e in rows:
        print(f"{e['id']}\t{severity(e['risk']):8}\trisk {e['risk']:3}\t{e['status']:17}\t{e['source_name']}"
              f"\t{','.join(e['data_types'])}")
        for step in (e["details"] or {}).get("remediation", []) if args.verbose else []:
            print(f"\t  - {step}")


def cmd_score(app, args):
    _profile(app, args.id)
    _print_json(coverage(app.store.exposures(args.id)))


def cmd_exposure_set(app, args, status):
    e = app.store.get_exposure(args.id) or sys.exit(f"no exposure {args.id}")
    app.store.set_exposure_status(e["id"], status)
    open_rem = app.store.open_removal_for(e["id"])
    if open_rem and status == "dismissed":
        app.store.update_removal(open_rem["id"], status="cancelled", closed_at=now())
    print(f"{e['id']} -> {status}")


def cmd_remove(app, args):
    e = app.store.get_exposure(args.id) or sys.exit(f"no exposure {args.id}")
    rid = removal.create_removal(app.store, _profile(app, e["profile_id"]), e, app.brokers)
    print(rid or "nothing to file (breach exposures need remediation, or a removal is already open)")


def cmd_removals(app, args):
    for r in app.store.removals(args.profile, args.status):
        print(f"{r['id']}\t{r['status']:16}\t{r['method']:9}\t{r['legal_basis']:18}\tattempts {r['attempts']}"
              f"\t{r['source_id']}\tnext check {r['next_check_at'] or '-'}")
        if r["note"] and args.verbose:
            print(f"\t  {r['note']}")


def cmd_removal_letter(app, args):
    r = app.store.get_removal(args.id) or sys.exit(f"no removal {args.id}")
    letter = r["letter"]
    if letter.get("to"):
        print(f"To: {letter['to']}")
    print(f"Subject: {letter['subject']}\n\n{letter['body']}")


def cmd_removal_mark(app, args):
    r = app.store.get_removal(args.id) or sys.exit(f"no removal {args.id}")
    if args.status == "submitted":
        removal.mark_submitted(app.store, r, app.brokers)
    elif args.status == "confirmed":
        removal.on_gone(app.store, r, r["exposure_id"])
    else:
        app.store.update_removal(r["id"], status="failed", closed_at=now())
        app.store.set_exposure_status(r["exposure_id"], "active")
    app.store.audit("cli", f"removal_{args.status}", r["id"])
    print(f"{r['id']} -> {args.status}")


def cmd_autopilot(app, args):
    _print_json(removal.process_queue(app.store, app.brokers, app.mailer, args.profile))


def cmd_monitor(app, args):
    if args.once:
        _print_json(run_cycle(app))
    else:
        print(f"monitoring every {args.interval}s; Ctrl-C to stop")
        monitor_forever(app, args.interval)


def cmd_alerts(app, args):
    for a in app.store.alerts(args.profile):
        print(f"{a['created_at']}\t{a['severity']:8}\t{a['kind']}\t{a['message']}")


def cmd_digest(app, args):
    print(digest(app.store, args.hours))


def cmd_password_check(app, args):
    pw = getpass.getpass("Password (not echoed; only a 5-character hash prefix is sent): ")
    count = app.hibp.password_count(pw)
    if count:
        print(f"This password appears {count:,} times in known breaches. Do not use it.")
        sys.exit(2)
    print("Not found in known breaches.")


def cmd_lookalikes(app, args):
    for domain, technique in sorted(lookalikes(args.domain).items()):
        if args.resolve:
            if resolves(domain):
                print(f"{domain}\t{technique}\tREGISTERED")
        else:
            print(f"{domain}\t{technique}")


def cmd_check_sender(app, args):
    result = check_sender(args.address, args.trusted)
    _print_json(result)
    if result["verdict"] == "suspicious":
        sys.exit(2)


def cmd_watch_add(app, args):
    if args.kind == "page_keyword" and " " not in args.value:
        sys.exit("page_keyword value must be '<url> <keyword>'")
    print(app.store.add_watch(args.profile, args.kind, args.value))


def cmd_watch_list(app, args):
    for w in app.store.watches():
        print(f"{w['id']}\t{w['kind']}\t{w['value']}\t{w['profile_id'] or '-'}")


def cmd_watch_remove(app, args):
    print("removed" if app.store.delete_watch(args.id) else f"no watch {args.id}")


def cmd_watch_run(app, args):
    print(f"{run_watches(app.store)} new alert(s)")
    app.notifier().deliver()


def cmd_key_create(app, args):
    kid, secret = apikeys.create_key(app.store, args.name, args.scopes, args.subject, args.expires_days)
    print(f"id:     {kid}\nsecret: {secret}\nThe secret is shown only once. Store it securely.")


def cmd_key_list(app, args):
    for k in apikeys.list_keys(app.store):
        state = "revoked" if k["revoked_at"] else f"expires {k['expires_at'] or 'never'}"
        print(f"{k['id']}\t{k['name']}\t{k['subject']}\t{','.join(k['scopes'])}\t{state}")


def cmd_key_revoke(app, args):
    print("revoked" if apikeys.revoke(app.store, args.id) else f"no active key {args.id}")


def cmd_key_rotate(app, args):
    print(f"new secret: {apikeys.rotate(app.store, args.id)}\nThe old secret no longer works.")


def cmd_brokers(app, args):
    for b in sorted(app.brokers.values(), key=lambda b: b["name"]):
        auto = "auto-check" if b.get("search_url") else "manual"
        print(f"{b['id']:26}\t{b['region']:6}\t{auto:10}\t{b.get('optout_email') or b.get('optout_url') or '-'}")


def cmd_serve(app, args):
    from .api import serve
    server = serve(app, args.host, args.port, restrict_to_profiles=not args.allow_any_identifier)
    print(f"PrivacySearch API on http://{args.host}:{args.port}  (dashboard at /)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="privacysearch", description="Find, remove and monitor your exposed personal data.")
    p.add_argument("--home", help="data directory (default ~/.privacysearch or $PRIVACYSEARCH_HOME)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the data directory and show configuration").set_defaults(fn=cmd_init)

    prof = sub.add_parser("profile", help="manage protected people").add_subparsers(dest="sub", required=True)
    a = prof.add_parser("add", help="add a protected person")
    a.add_argument("--label", required=True)
    a.add_argument("--name", action="append", help="full name (repeatable, include aliases/maiden names)")
    a.add_argument("--email", action="append")
    a.add_argument("--phone", action="append")
    a.add_argument("--address", action="append", help="'street;city;region;postal_code;country'")
    a.add_argument("--username", action="append")
    a.add_argument("--birth-year", type=int)
    a.add_argument("--jurisdiction", default="US", help="EU, UK, US, US-<state>, CA, AU, NZ, OTHER")
    a.add_argument("--no-autopilot", action="store_true")
    a.set_defaults(fn=cmd_profile_add)
    i = prof.add_parser("import", help="bulk-add profiles from a JSON list (team onboarding)")
    i.add_argument("file")
    i.set_defaults(fn=cmd_profile_import)
    prof.add_parser("list").set_defaults(fn=cmd_profile_list)
    for name, fn in (("show", cmd_profile_show), ("export", cmd_profile_export), ("delete", cmd_profile_delete)):
        s = prof.add_parser(name)
        s.add_argument("id")
        if name == "export":
            s.add_argument("-o", "--output")
        if name == "delete":
            s.add_argument("--yes", action="store_true")
        s.set_defaults(fn=fn)

    s = sub.add_parser("scan", help="scan brokers and breaches for a profile")
    s.add_argument("id")
    s.add_argument("--assume-listed", action="store_true", help="file proactive opt-outs where a check is blocked")
    s.add_argument("--show-manual", action="store_true")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("exposures", help="list exposures ranked by risk")
    s.add_argument("id")
    s.add_argument("--status")
    s.add_argument("--json", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true", help="show remediation steps")
    s.set_defaults(fn=cmd_exposures)

    s = sub.add_parser("score", help="Coverage Score and exposure level")
    s.add_argument("id")
    s.set_defaults(fn=cmd_score)

    for name, status, help_ in (("dismiss", "dismissed", "mark an exposure as not you / not a concern"),
                                ("mitigate", "mitigated", "mark a breach exposure as remediated")):
        s = sub.add_parser(name, help=help_)
        s.add_argument("id")
        s.set_defaults(fn=lambda app, args, st=status: cmd_exposure_set(app, args, st))

    s = sub.add_parser("remove", help="file a removal request for an exposure")
    s.add_argument("id")
    s.set_defaults(fn=cmd_remove)

    s = sub.add_parser("removals", help="removal pipeline")
    s.add_argument("--profile")
    s.add_argument("--status")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_removals)

    rem = sub.add_parser("removal", help="act on one removal").add_subparsers(dest="sub", required=True)
    s = rem.add_parser("letter", help="print the request letter")
    s.add_argument("id")
    s.set_defaults(fn=cmd_removal_letter)
    s = rem.add_parser("mark", help="record progress on a web-form removal")
    s.add_argument("id")
    s.add_argument("--status", required=True, choices=["submitted", "confirmed", "failed"])
    s.set_defaults(fn=cmd_removal_mark)

    s = sub.add_parser("autopilot", help="send queued email removals now")
    s.add_argument("--profile")
    s.set_defaults(fn=cmd_autopilot)

    s = sub.add_parser("monitor", help="continuous scanning, re-filing and alerting")
    s.add_argument("--once", action="store_true")
    s.add_argument("--interval", type=int, default=6 * 3600)
    s.set_defaults(fn=cmd_monitor)

    s = sub.add_parser("alerts")
    s.add_argument("--profile")
    s.set_defaults(fn=cmd_alerts)

    s = sub.add_parser("digest", help="summary of the last N hours")
    s.add_argument("--hours", type=int, default=24)
    s.set_defaults(fn=cmd_digest)

    sub.add_parser("password-check", help="k-anonymity breached-password check").set_defaults(fn=cmd_password_check)

    s = sub.add_parser("lookalikes", help="typosquat / lookalike domains for a domain you own")
    s.add_argument("domain")
    s.add_argument("--resolve", action="store_true", help="only show candidates that resolve in DNS")
    s.set_defaults(fn=cmd_lookalikes)

    s = sub.add_parser("check-sender", help="is this sender imitating a domain you trust?")
    s.add_argument("address")
    s.add_argument("--trusted", action="append", required=True)
    s.set_defaults(fn=cmd_check_sender)

    w = sub.add_parser("watch", help="deployed agents watching domains and pages").add_subparsers(dest="sub", required=True)
    s = w.add_parser("add")
    s.add_argument("--kind", required=True, choices=["lookalike_domain", "page_keyword"])
    s.add_argument("--value", required=True, help="a domain, or '<url> <keyword>'")
    s.add_argument("--profile")
    s.set_defaults(fn=cmd_watch_add)
    w.add_parser("list").set_defaults(fn=cmd_watch_list)
    s = w.add_parser("remove")
    s.add_argument("id")
    s.set_defaults(fn=cmd_watch_remove)
    w.add_parser("run").set_defaults(fn=cmd_watch_run)

    k = sub.add_parser("apikey", help="developer API keys").add_subparsers(dest="sub", required=True)
    s = k.add_parser("create")
    s.add_argument("--name", required=True)
    s.add_argument("--scope", dest="scopes", action="append", required=True, choices=sorted(apikeys.SCOPES))
    s.add_argument("--subject", default="org_local")
    s.add_argument("--expires-days", type=int)
    s.set_defaults(fn=cmd_key_create)
    k.add_parser("list").set_defaults(fn=cmd_key_list)
    for name, fn in (("revoke", cmd_key_revoke), ("rotate", cmd_key_rotate)):
        s = k.add_parser(name)
        s.add_argument("id")
        s.set_defaults(fn=fn)

    sub.add_parser("brokers", help="list the broker registry").set_defaults(fn=cmd_brokers)

    s = sub.add_parser("serve", help="run the HTTP API and dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.add_argument("--allow-any-identifier", action="store_true",
                   help="allow API breach scans of emails/phones that are not in a protected profile")
    s.set_defaults(fn=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    app = App(Path(args.home) if args.home else None)
    try:
        args.fn(app, args)
    except ValueError as exc:
        sys.exit(f"error: {exc}")


if __name__ == "__main__":
    main()
