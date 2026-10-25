import unittest

from privacysearch import apikeys, removal
from privacysearch.intel import check_sender, lookalikes
from privacysearch.monitor import run_watches, scan_profile
from privacysearch.profiles import normalise_profile
from privacysearch.risk import coverage, exposure_risk

from helpers import PROFILE, FakeMailer, FakeNet, make_app


def setup(test, net=None, **kw):
    net = net or FakeNet()
    app = make_app(net, **kw)
    test.addCleanup(app.close)
    pid = app.store.add_profile("Jane", normalise_profile(PROFILE))
    return app, net, pid


def by_source(app, pid):
    return {e["source_id"]: e for e in app.store.exposures(pid)}


class ProfileTests(unittest.TestCase):
    def test_normalises_and_validates(self):
        data = normalise_profile(PROFILE)
        self.assertEqual(data["phones"], ["+15125550142"])
        self.assertEqual(data["addresses"][0]["city"], "Austin")
        with self.assertRaises(ValueError):
            normalise_profile({"full_names": ["Prince"]})
        with self.assertRaises(ValueError):
            normalise_profile({"emails": ["not-an-email"]})
        with self.assertRaises(ValueError):
            normalise_profile({**PROFILE, "jurisdiction": "MARS"})

    def test_personal_data_encrypted_at_rest(self):
        app, _, pid = setup(self)
        scan_profile(app.store, app.store.get_profile(pid), app.providers(), app.brokers)
        raw = b"".join(bytes(str(tuple(r)), "utf8") for t in ("profiles", "exposures", "removals")
                       for r in app.store.query(f"SELECT * FROM {t}"))
        self.assertNotIn(b"jane@example.com", raw)
        self.assertNotIn(b"Elm Street", raw)
        self.assertEqual(app.store.get_profile(pid)["data"]["emails"], ["jane@example.com"])


class ScanTests(unittest.TestCase):
    def test_finds_broker_listings_and_breaches(self):
        app, _, pid = setup(self)
        summary = scan_profile(app.store, app.store.get_profile(pid), app.providers(), app.brokers)
        found = by_source(app, pid)
        self.assertIn("truepeoplesearch", found)
        self.assertIn("radaris", found)
        self.assertIn("hibp:Adobe", found)
        self.assertNotIn("fastpeoplesearch", found)  # page said no results
        tps = found["truepeoplesearch"]
        self.assertGreaterEqual(tps["confidence"], 0.9)
        self.assertTrue({"name", "home_address", "phone", "age"} <= set(tps["data_types"]))
        self.assertIn("password", found["hibp:Adobe"]["data_types"])
        self.assertIn("spokeo", {m["source_id"] for m in summary["manual_checks"]})
        self.assertTrue(any("password" in s.lower() for s in found["hibp:Adobe"]["details"]["remediation"]))
        # Web-form brokers need the user; breaches never get a removal.
        self.assertEqual(tps["status"], "action_required")
        self.assertIsNone(app.store.open_removal_for(found["hibp:Adobe"]["id"]))
        self.assertTrue(any(a["kind"] == "new_breach" for a in app.store.alerts(pid)))

    def test_rescan_is_idempotent(self):
        app, _, pid = setup(self)
        profile = app.store.get_profile(pid)
        scan_profile(app.store, profile, app.providers(), app.brokers)
        n, r = len(app.store.exposures(pid)), len(app.store.removals(pid))
        summary = scan_profile(app.store, profile, app.providers(), app.brokers)
        self.assertEqual(summary["new"], 0)
        self.assertEqual(len(app.store.exposures(pid)), n)
        self.assertEqual(len(app.store.removals(pid)), r)

    def test_removal_lifecycle_confirm_then_reappear(self):
        app, net, pid = setup(self)
        profile = app.store.get_profile(pid)
        scan_profile(app.store, profile, app.providers(), app.brokers)
        rad = by_source(app, pid)["radaris"]
        rem = app.store.open_removal_for(rad["id"])
        removal.mark_submitted(app.store, rem, app.brokers)

        net.listed.discard("radaris.com")
        summary = scan_profile(app.store, profile, app.providers(), app.brokers)
        self.assertEqual(summary["gone"], 1)
        self.assertEqual(app.store.get_exposure(rad["id"])["status"], "removed")
        self.assertEqual(app.store.get_removal(rem["id"])["status"], "confirmed")

        net.listed.add("radaris.com")
        summary = scan_profile(app.store, profile, app.providers(), app.brokers)
        self.assertEqual(summary["reappeared"], 1)
        self.assertIn(app.store.get_exposure(rad["id"])["status"], ("action_required", "removal_requested"))
        new_rem = app.store.open_removal_for(rad["id"])
        self.assertNotEqual(new_rem["id"], rem["id"])
        self.assertTrue(any(a["kind"] == "reappeared" for a in app.store.alerts(pid)))

    def test_still_listed_refiles_then_fails(self):
        app, net, pid = setup(self)
        profile = app.store.get_profile(pid)
        scan_profile(app.store, profile, app.providers(), app.brokers)
        eid = by_source(app, pid)["radaris"]["id"]
        for attempt in range(1, removal.MAX_ATTEMPTS + 1):
            rem = app.store.open_removal_for(eid)
            removal.mark_submitted(app.store, rem, app.brokers)
            app.store.update_removal(rem["id"], next_check_at="2000-01-01T00:00:00+00:00")
            scan_profile(app.store, profile, app.providers(), app.brokers)
        rem = app.store.get_removal(rem["id"])
        self.assertEqual(rem["status"], "failed")
        self.assertEqual(rem["attempts"], removal.MAX_ATTEMPTS)
        self.assertTrue(any(a["kind"] == "removal_failed" for a in app.store.alerts(pid)))

    def test_assume_listed_autopilot_emails_marketing_brokers(self):
        app, _, pid = setup(self, assume_listed=True)
        scan_profile(app.store, app.store.get_profile(pid), app.providers(), app.brokers)
        acx = by_source(app, pid)["acxiom"]
        rem = app.store.open_removal_for(acx["id"])
        self.assertEqual((rem["method"], rem["status"]), ("email", "queued"))

        failing = FakeMailer(fail=True)
        self.assertGreaterEqual(removal.process_queue(app.store, app.brokers, failing)["failed"], 1)
        self.assertEqual(app.store.get_removal(rem["id"])["status"], "queued")

        mailer = FakeMailer()
        counts = removal.process_queue(app.store, app.brokers, mailer)
        self.assertGreaterEqual(counts["sent"], 1)
        sent = next(m for m in mailer.sent if m["to"] == "consumeradvo@acxiom.com")
        self.assertIn("1798.105", sent["body"])
        self.assertEqual(sent["reply_to"], "jane@example.com")
        self.assertNotIn("555", sent["body"])  # data minimisation: phone not disclosed
        rem = app.store.get_removal(rem["id"])
        self.assertEqual((rem["status"], rem["attempts"]), ("submitted", 1))
        self.assertIsNotNone(rem["next_check_at"])

    def test_breach_provider_reports_bad_key(self):
        net = FakeNet()
        net.hibp_key_ok = False
        app, _, pid = setup(self, net)
        summary = scan_profile(app.store, app.store.get_profile(pid), app.providers(), app.brokers)
        self.assertTrue(any("API key" in e for e in summary["errors"]))
        self.assertIn("truepeoplesearch", by_source(app, pid))  # other providers still ran


class RiskTests(unittest.TestCase):
    def test_weights_and_coverage(self):
        self.assertGreater(exposure_risk(["home_address", "phone"], 1, "broker"),
                           exposure_risk(["name", "employer"], 1, "broker"))
        self.assertEqual(coverage([])["coverage_score"], 100)
        exps = [{"risk": 30, "status": "removed", "data_types": ["phone"]},
                {"risk": 10, "status": "active", "data_types": ["email"]}]
        cov = coverage(exps)
        self.assertEqual(cov["coverage_score"], 75)
        self.assertEqual(cov["exposure_level"], "low")
        self.assertEqual(cov["open_by_data_type"], {"email": 1})

    def test_legal_basis(self):
        self.assertEqual(removal.legal_basis_key("EU"), "EU")
        self.assertEqual(removal.legal_basis_key("US-VA"), "US-STATE")
        self.assertEqual(removal.legal_basis_key("US-FL"), "US")
        self.assertEqual(removal.legal_basis_key("US-CA"), "US-CA")


class PasswordTests(unittest.TestCase):
    def test_k_anonymity(self):
        net = FakeNet()
        app = make_app(net)
        self.addCleanup(app.close)
        self.assertEqual(app.hibp.password_count("password"), 9545824)
        self.assertEqual(app.hibp.password_count("correct horse battery staple x"), 0)
        url = net.calls[0][0]
        self.assertTrue(url.endswith("/range/5BAA6"))  # only the 5-char hash prefix is sent


class IntelTests(unittest.TestCase):
    def test_lookalikes(self):
        cands = lookalikes("example.com")
        self.assertEqual(cands["exmaple.com"], "transposition")
        self.assertEqual(cands["examp1e.com"], "homoglyph")
        self.assertEqual(cands["example.net"], "tld_swap")
        self.assertNotIn("example.com", cands)

    def test_check_sender(self):
        trusted = ["example.com"]
        self.assertEqual(check_sender("billing@examp1e.com", trusted)["verdict"], "suspicious")
        self.assertEqual(check_sender("billing@example.co", trusted)["verdict"], "suspicious")
        self.assertEqual(check_sender("ap@example-invoices.com", trusted)["verdict"], "suspicious")
        self.assertEqual(check_sender("a@mail.example.com", trusted)["verdict"], "trusted")
        self.assertEqual(check_sender("a@unrelated.org", trusted)["verdict"], "unknown")

    def test_lookalike_watch_alerts_once(self):
        app, _, pid = setup(self)
        app.store.add_watch(pid, "lookalike_domain", "example.com")
        live = {"exmaple.com"}
        self.assertEqual(run_watches(app.store, resolve=lambda d: d in live), 1)
        self.assertEqual(run_watches(app.store, resolve=lambda d: d in live), 0)
        live.add("examp1e.com")
        self.assertEqual(run_watches(app.store, resolve=lambda d: d in live), 1)

    def test_page_keyword_watch(self):
        app, _, pid = setup(self)
        app.store.add_watch(pid, "page_keyword", "https://forum.test/thread Jane")
        pages = {"body": "<p>nothing</p>"}
        fetch = lambda url, h: (200, pages["body"])
        self.assertEqual(run_watches(app.store, fetch=fetch), 0)
        pages["body"] = "<p>jane lives at ...</p>"
        self.assertEqual(run_watches(app.store, fetch=fetch), 1)
        self.assertEqual(run_watches(app.store, fetch=fetch), 0)


class DataRightsTests(unittest.TestCase):
    def test_export_and_delete_cascade(self):
        app, _, pid = setup(self)
        scan_profile(app.store, app.store.get_profile(pid), app.providers(), app.brokers)
        export = app.store.export_profile(pid)
        self.assertEqual(export["profile"]["data"]["emails"], ["jane@example.com"])
        self.assertTrue(export["exposures"] and export["removals"] and export["alerts"])
        self.assertTrue(app.store.delete_profile(pid))
        for table in ("exposures", "removals", "alerts"):
            self.assertEqual(app.store.query(f"SELECT COUNT(*) c FROM {table}")[0]["c"], 0)


class ApiKeyTests(unittest.TestCase):
    def test_lifecycle(self):
        app = make_app()
        self.addCleanup(app.close)
        kid, secret = apikeys.create_key(app.store, "ci", ["account:read"])
        self.assertTrue(secret.startswith("ak_"))
        self.assertEqual(apikeys.verify(app.store, secret)["id"], kid)
        self.assertIsNone(apikeys.verify(app.store, secret + "x"))
        new = apikeys.rotate(app.store, kid)
        self.assertIsNone(apikeys.verify(app.store, secret))
        self.assertEqual(apikeys.verify(app.store, new)["id"], kid)
        self.assertTrue(apikeys.revoke(app.store, kid))
        self.assertIsNone(apikeys.verify(app.store, new))
        with self.assertRaises(ValueError):
            apikeys.create_key(app.store, "bad", ["root"])
        stored = app.store.query("SELECT secret_hash FROM api_keys")[0]["secret_hash"]
        self.assertNotIn("ak_", stored)


if __name__ == "__main__":
    unittest.main()
