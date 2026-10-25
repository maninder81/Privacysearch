import json
import threading
import time
import unittest
import urllib.error
import urllib.request

from privacysearch import apikeys
from privacysearch.api import RateLimiter, serve
from privacysearch.profiles import normalise_profile

from helpers import PROFILE, make_app

ALL = ["account:read", "darkweb:scan", "darkweb:read", "darkweb:reveal", "profiles:read", "profiles:write"]


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.app = make_app()
        self.pid = self.app.store.add_profile("Jane", normalise_profile(PROFILE))
        self.server = serve(self.app, "127.0.0.1", 0, rate_limits={"read": 1000, "write": 1000})
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.app.close)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        _, self.admin = apikeys.create_key(self.app.store, "admin", ALL)
        _, self.scanner = apikeys.create_key(self.app.store, "scanner", ["darkweb:scan"])

    def call(self, method, path, key=None, body=None, content_type="application/json"):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if key:
            req.add_header("Authorization", f"Bearer {key}")
        if data is not None:
            req.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                raw = r.read().decode()
                return r.status, dict(r.headers), raw if "event-stream" in r.headers["Content-Type"] else json.loads(raw)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), json.loads(e.read())

    def wait_scan(self, sid, key):
        for _ in range(100):
            status, _, body = self.call("GET", f"/v1/darkweb/scans/{sid}", key)
            if body.get("status") in ("success", "failed"):
                return body
            time.sleep(0.02)
        self.fail("scan did not finish")

    def test_hello_and_auth_errors(self):
        status, headers, body = self.call("GET", "/v1/hello", self.admin)
        self.assertEqual(status, 200)
        self.assertEqual(body["subject"], "org_local")
        self.assertIn("darkweb:reveal", body["scopes"])
        self.assertIn("X-RateLimit-Remaining", headers)
        status, _, body = self.call("GET", "/v1/hello")
        self.assertEqual((status, body["error"]["type"]), (401, "authentication_error"))
        self.assertIn("request_id", body["error"])
        status, _, body = self.call("GET", "/v1/hello", "ak_bogus")
        self.assertEqual(body["error"]["code"], "invalid_api_key")
        status, _, body = self.call("GET", "/v1/hello", self.scanner)
        self.assertEqual((status, body["error"]["code"]), (403, "scope_not_granted"))
        status, _, body = self.call("GET", "/v1/nope", self.admin)
        self.assertEqual(status, 404)

    def test_scan_mask_reveal_and_reuse(self):
        status, _, body = self.call("POST", "/v1/darkweb/scans", self.scanner,
                                    {"identifierType": "email", "identifierValue": "Jane@Example.com"})
        self.assertEqual((status, body["status"]), (202, "processing"))
        result = self.wait_scan(body["id"], self.scanner)
        self.assertEqual(result["status"], "success")
        breach = result["breaches"][0]
        self.assertTrue(breach["isMasked"])
        self.assertIsNone(breach["breachedData"]["email"])
        self.assertEqual(breach["breachAuthority"]["name"], "Adobe")
        self.assertEqual(result["extractedData"]["emails"], ["j***@e***"])

        status, _, err = self.call("GET", f"/v1/darkweb/scans/{body['id']}?reveal=true", self.scanner)
        self.assertEqual(status, 403)
        status, _, revealed = self.call("GET", f"/v1/darkweb/scans/{body['id']}?reveal=true", self.admin)
        self.assertEqual(revealed["breaches"][0]["breachedData"]["email"], "jane@example.com")
        actions = [r["action"] for r in self.app.store.query("SELECT action FROM audit_log")]
        self.assertIn("darkweb_reveal", actions)

        status, _, again = self.call("POST", "/v1/darkweb/scans", self.scanner,
                                     {"identifierType": "email", "identifierValue": "jane@example.com"})
        self.assertEqual((status, again["id"], again.get("reused")), (200, body["id"], True))

    def test_scan_validation_and_protection(self):
        status, _, body = self.call("POST", "/v1/darkweb/scans", self.scanner,
                                    {"identifierType": "email", "identifierValue": "someone@else.com"})
        self.assertEqual((status, body["error"]["code"]), (403, "identifier_not_protected"))
        status, _, body = self.call("POST", "/v1/darkweb/scans", self.scanner,
                                    {"identifierType": "phone", "identifierValue": "+15125550142"})
        self.assertEqual((status, body["error"]["code"]), (422, "identifier_type_not_supported"))
        status, _, body = self.call("POST", "/v1/darkweb/scans", self.scanner, {"identifierType": "ssn"})
        self.assertEqual(status, 422)
        self.assertEqual(len(body["error"]["details"]), 2)
        status, _, body = self.call("POST", "/v1/darkweb/scans", self.scanner, {}, content_type="text/plain")
        self.assertEqual(status, 415)

    def test_password_and_domain_scans(self):
        _, _, body = self.call("POST", "/v1/darkweb/scans", self.scanner,
                               {"identifierType": "password", "identifierValue": "password"})
        result = self.wait_scan(body["id"], self.scanner)
        self.assertEqual(result["breaches"][0]["breachedData"]["occurrences"], 9545824)
        self.assertIsNone(result["breaches"][0]["breachedData"]["password"])
        _, _, body = self.call("POST", "/v1/darkweb/scans", self.scanner,
                               {"identifierType": "domain", "identifierValue": "adobe.com"})
        self.assertEqual(self.wait_scan(body["id"], self.scanner)["breaches"][0]["name"], "Adobe")

    def test_other_keys_cannot_read_scans_without_read_scope(self):
        _, other = apikeys.create_key(self.app.store, "other", ["darkweb:scan"])
        _, _, body = self.call("POST", "/v1/darkweb/scans", self.scanner,
                               {"identifierType": "domain", "identifierValue": "adobe.com"})
        self.wait_scan(body["id"], self.scanner)
        status, _, _ = self.call("GET", f"/v1/darkweb/scans/{body['id']}", other)
        self.assertEqual(status, 404)

    def test_stream(self):
        status, headers, raw = self.call("POST", "/v1/darkweb/scans/stream", self.scanner,
                                         {"identifierType": "email", "identifierValue": "jane@example.com"})
        self.assertEqual(status, 200)
        events = [block.split("\n") for block in raw.strip().split("\n\n")]
        names = [lines[0].removeprefix("event: ") for lines in events if lines[0].startswith("event:")]
        self.assertEqual(names, ["breach", "done"])
        breach = json.loads(events[0][1].removeprefix("data: "))
        self.assertIsNone(breach["breachedData"]["email"])
        done = json.loads(events[-1][1].removeprefix("data: "))
        self.assertEqual((done["status"], done["totalBreaches"]), ("completed", 1))

    def test_profiles_bulk_scan_and_exposures(self):
        status, _, body = self.call("POST", "/v1/profiles", self.admin, {"profiles": [
            {"label": "CFO", "full_names": ["Sam Roe"], "emails": ["sam@corp.test"]}, {"label": "bad"}]})
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["details"][0]["index"], 1)
        status, _, body = self.call("POST", "/v1/profiles", self.admin, {"profiles": [
            {"label": "CFO", "full_names": ["Sam Roe"], "emails": ["sam@corp.test"]}]})
        self.assertEqual(status, 201)

        status, _, body = self.call("POST", f"/v1/profiles/{self.pid}/scan", self.admin, {})
        self.assertEqual(status, 200)
        self.assertGreater(body["new"], 0)
        _, _, listing = self.call("GET", "/v1/profiles", self.admin)
        self.assertEqual(len(listing["data"]), 2)
        self.assertNotIn("data", listing["data"][0])  # no raw PII in summaries
        _, _, exps = self.call("GET", f"/v1/profiles/{self.pid}/exposures", self.admin)
        risks = [e["risk"] for e in exps["data"]]
        self.assertEqual(risks, sorted(risks, reverse=True))  # ranked by risk
        self.assertEqual(exps["data"][0]["severity"], "high")
        _, _, rems = self.call("GET", f"/v1/profiles/{self.pid}/removals", self.admin)
        self.assertNotIn("letter", rems["data"][0])

    def test_dashboard_served(self):
        with urllib.request.urlopen(self.base + "/", timeout=5) as r:
            self.assertIn("PrivacySearch", r.read().decode())
            self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])


class RateLimiterTests(unittest.TestCase):
    def test_window(self):
        rl = RateLimiter({"write": 2})
        results = [rl.check("org", "write")[0] for _ in range(3)]
        if results != [True, True, False]:  # crossed a second boundary mid-test; retry once
            results = [rl.check("org2", "write")[0] for _ in range(3)]
        self.assertEqual(results, [True, True, False])
        self.assertTrue(rl.check("other-org", "write")[0])


if __name__ == "__main__":
    unittest.main()
