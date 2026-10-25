import json
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

from privacysearch.app import App

PROFILE = {
    "full_names": ["Jane Q Doe"],
    "emails": ["jane@example.com"],
    "phones": ["+1 (512) 555-0142"],
    "addresses": ["42 Elm Street;Austin;TX;78701;US"],
    "birth_year": 1985,
    "jurisdiction": "US-CA",
}

BREACHES = [{
    "Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04", "PwnCount": 152445165,
    "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"], "IsVerified": True,
}]


class FakeNet:
    """Routes URLs to canned responses. Pages listing Jane can be toggled per broker."""

    def __init__(self):
        self.listed = {"truepeoplesearch.com", "radaris.com"}
        self.blocked = {"spokeo.com"}
        self.hibp_key_ok = True
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, headers))
        if "api.pwnedpasswords.com/range/" in url:
            # SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
            return 200, "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\nABCDEF0000000000000000000000000000:1"
        if "haveibeenpwned.com/api/v3/breachedaccount/" in url:
            if not self.hibp_key_ok:
                return 401, ""
            return (200, json.dumps(BREACHES)) if "jane%40example.com" in url else (404, "")
        if "haveibeenpwned.com/api/v3/pasteaccount/" in url:
            return 404, ""
        if "haveibeenpwned.com/api/v3/breaches?domain=" in url:
            return 200, json.dumps(BREACHES)
        for domain in self.blocked:
            if domain in url:
                return 403, "Access denied"
        for domain in self.listed:
            if domain in url:
                return 200, ("<html><body><div class='card'>Jane Q. Doe, Age 40</div><p>Lives in Austin, TX</p>"
                             "<p>(512) 555-0142</p><script>var x='noise'</script></body></html>")
        return 200, "<html><body>No results found</body></html>"


def make_app(net=None, **kw):
    tmp = tempfile.TemporaryDirectory()
    import os
    os.environ["PRIVACYSEARCH_KEY"] = Fernet.generate_key().decode()
    os.environ["HIBP_API_KEY"] = "test-key"
    for var in ("PRIVACYSEARCH_SMTP_HOST", "PRIVACYSEARCH_WEBHOOK_URL"):
        os.environ.pop(var, None)
    app = App(Path(tmp.name), fetch=net or FakeNet(), **kw)
    app._tmp = tmp  # keep directory alive for the app's lifetime
    return app


class FakeMailer:
    def __init__(self, fail=False):
        self.sent, self.fail = [], fail

    def send(self, to, subject, body, reply_to=None):
        if self.fail:
            raise OSError("smtp down")
        self.sent.append({"to": to, "subject": subject, "body": body, "reply_to": reply_to})
