"""HTTP API compatible with the shape of the Serus v1 API, plus profile endpoints and a dashboard."""

from __future__ import annotations

import json
import queue
import re
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlparse

from . import apikeys
from .monitor import scan_profile
from .profiles import normalise_profile
from .risk import coverage, severity
from .scans import ScanError, ScanService, mask_result

TIERS = {"default": 60, "read": 7, "write": 3}
STREAM_MAX_SECONDS = 300
HEARTBEAT_SECONDS = 15


class RateLimiter:
    """Fixed one-second windows per (subject, tier); all keys of one subject share the allowance."""

    def __init__(self, limits: dict[str, int]):
        self.limits = limits
        self._lock = threading.Lock()
        self._windows: dict[tuple[str, str], tuple[int, int]] = {}

    def check(self, subject: str, tier: str) -> tuple[bool, int, int, int]:
        limit = self.limits[tier]
        window = int(time.time())
        with self._lock:
            start, count = self._windows.get((subject, tier), (window, 0))
            if start != window:
                start, count = window, 0
            allowed = count < limit
            if allowed:
                count += 1
            self._windows[(subject, tier)] = (start, count)
        return allowed, limit, max(0, limit - count), window + 1


class ApiError(Exception):
    def __init__(self, status: int, type_: str, code: str, message: str, details=None, headers=None):
        super().__init__(message)
        self.status, self.type, self.code, self.message = status, type_, code, message
        self.details, self.headers = details, headers or {}


def make_handler(app, restrict_to_profiles: bool = True, rate_limits: dict[str, int] | None = None):
    limiter = RateLimiter({**TIERS, **(rate_limits or {})})
    scans = ScanService(app.store, app.hibp, restrict_to_profiles)
    routes = []

    def route(method: str, pattern: str, tier: str, scopes: tuple[str, ...] | None):
        """scopes=None means public; otherwise the key needs at least one of the listed scopes."""
        def deco(fn):
            routes.append((method, re.compile(f"^{pattern}$"), tier, scopes, fn))
            return fn
        return deco

    class Handler(BaseHTTPRequestHandler):
        server_version = "PrivacySearch"
        sys_version = ""

        def log_message(self, fmt, *args):  # quieter default logging without client IPs
            pass

        # -- plumbing ----------------------------------------------------
        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def _dispatch(self, method: str):
            self.request_id = str(uuid.uuid4())
            self.extra_headers = {}
            parsed = urlparse(self.path)
            self.query = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
            try:
                for m, rx, tier, scopes, fn in routes:
                    match = rx.match(parsed.path)
                    if m == method and match:
                        key = None
                        if scopes is not None:
                            key = self._auth()
                            self._rate(key, tier)
                            if not set(scopes) & set(key["scopes"]):
                                raise ApiError(403, "feature_not_allowed", "scope_not_granted",
                                               f"API key lacks a required permission: one of {list(scopes)}")
                        return fn(self, key, **match.groupdict())
                raise ApiError(404, "invalid_request_error", "not_found", "Endpoint not found")
            except ApiError as e:
                self._error(e)
            except ScanError as e:
                self._error(ApiError(e.status, e.type, e.code, e.message, getattr(e, "details", None)))
            except Exception:  # noqa: BLE001 - never leak internals to the client; log them server-side
                traceback.print_exc()
                self._error(ApiError(500, "internal_error", "internal_error", "Server-side failure"))

        def _auth(self) -> dict:
            header = self.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                raise ApiError(401, "authentication_error", "missing_api_key", "Missing Bearer API key")
            key = apikeys.verify(app.store, header[7:].strip())
            if not key:
                raise ApiError(401, "authentication_error", "invalid_api_key", "API key is invalid, revoked, or expired")
            return key

        def _rate(self, key: dict, tier: str):
            ok, limit, remaining, reset = limiter.check(key["subject"], tier)
            self.extra_headers = {"X-RateLimit-Limit": str(limit), "X-RateLimit-Remaining": str(remaining),
                                  "X-RateLimit-Reset": str(reset)}
            if not ok:
                raise ApiError(429, "rate_limit_error", "rate_limited", "Rate limit exceeded",
                               headers={"Retry-After": "1"})

        def body(self) -> dict:
            if "application/json" not in self.headers.get("Content-Type", ""):
                raise ApiError(415, "invalid_request_error", "unsupported_media_type",
                               "Content-Type must be application/json")
            length = int(self.headers.get("Content-Length") or 0)
            if length > 1_000_000:
                raise ApiError(422, "invalid_request_error", "body_too_large", "Request body too large")
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                raise ApiError(422, "invalid_request_error", "invalid_json", "Request body is not valid JSON")
            if not isinstance(data, dict):
                raise ApiError(422, "invalid_request_error", "invalid_json", "Request body must be a JSON object")
            return data

        def send_json(self, status: int, payload, headers=None):
            raw = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("X-Request-Id", self.request_id)
            for k, v in {**self.extra_headers, **(headers or {})}.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def _error(self, e: ApiError):
            err = {"type": e.type, "code": e.code, "message": e.message, "request_id": self.request_id}
            if e.details:
                err["details"] = e.details
            self.send_json(e.status, {"error": err}, e.headers)

        def sse(self, event: str | None, data=None):
            chunk = f": {data}\n\n" if event is None else f"event: {event}\ndata: {json.dumps(data)}\n\n"
            self.wfile.write(chunk.encode())
            self.wfile.flush()

    # -- account -----------------------------------------------------------
    @route("GET", "/v1/hello", "default", ("account:read",))
    def hello(h, key):
        h.send_json(200, {"subject": key["subject"], "scopes": key["scopes"], "credits_remaining": None})

    # -- darkweb -----------------------------------------------------------
    def _scan_view(scan: dict, reveal: bool) -> dict:
        out = {k: scan[k] for k in ("id", "status", "identifierType", "createdAt", "finishedAt")}
        if scan["status"] == "failed":
            out["error"] = scan["error"]
        if scan["result"] is not None:
            result = scan["result"] if reveal else mask_result(scan["result"])
            out.update(result)
        return out

    @route("POST", "/v1/darkweb/scans", "write", ("darkweb:scan",))
    def create_scan(h, key):
        itype, value = scans.validate(h.body())
        existing = scans.recent(itype, value)
        if existing:
            return h.send_json(200, {"id": existing["id"], "status": existing["status"], "identifierType": itype,
                                     "reused": True})
        sid = scans.create(key["id"], itype, value)

        def work():
            try:
                scans.run(sid, itype, value)
            except Exception:  # noqa: BLE001 - recorded on the scan row
                pass
        threading.Thread(target=work, daemon=True).start()
        h.send_json(202, {"id": sid, "status": "processing", "identifierType": itype})

    @route("GET", r"/v1/darkweb/scans/(?P<scan_id>scan_[0-9a-f]+)", "read",
           ("darkweb:read", "darkweb:scan", "darkweb:reveal"))
    def get_scan(h, key, scan_id):
        scan = scans.get(scan_id)
        if not scan:
            raise ApiError(404, "invalid_request_error", "scan_not_found", "Scan not found")
        if not ({"darkweb:read", "darkweb:reveal"} & set(key["scopes"])) and scan["key_id"] != key["id"]:
            raise ApiError(404, "invalid_request_error", "scan_not_found", "Scan not found")
        reveal = h.query.get("reveal") == "true"
        if reveal:
            if "darkweb:reveal" not in key["scopes"]:
                raise ApiError(403, "feature_not_allowed", "scope_not_granted", "Reveal requires darkweb:reveal")
            app.store.audit(key["id"], "darkweb_reveal", scan_id)
        h.send_json(200, _scan_view(scan, reveal))

    @route("POST", "/v1/darkweb/scans/stream", "write", ("darkweb:scan",))
    def stream_scan(h, key):
        itype, value = scans.validate(h.body())
        reveal = h.query.get("reveal") == "true" and "darkweb:reveal" in key["scopes"]
        if reveal:
            app.store.audit(key["id"], "darkweb_reveal_stream", itype)

        def shape(event, data):
            if event == "breach" and not reveal:
                return mask_result({"breaches": [data], "extractedData": {}})["breaches"][0]
            return data

        h.send_response(200)
        h.send_header("Content-Type", "text/event-stream")
        h.send_header("Cache-Control", "no-cache")
        h.send_header("Connection", "close")
        h.send_header("X-Request-Id", h.request_id)
        for k, v in h.extra_headers.items():
            h.send_header(k, v)
        h.end_headers()

        existing = scans.recent(itype, value)
        if existing:
            for b in existing["result"]["breaches"]:
                h.sse("breach", shape("breach", b))
            for p in existing["result"]["pastes"]:
                h.sse("paste", p)
            return h.sse("done", {"id": existing["id"], "status": "completed",
                                  "totalBreaches": len(existing["result"]["breaches"]),
                                  "totalPastes": len(existing["result"]["pastes"])})

        sid = scans.create(key["id"], itype, value)
        events: queue.Queue = queue.Queue()

        def work():
            try:
                result = scans.run(sid, itype, value, emit=lambda e, d: events.put((e, d)))
                events.put(("done", {"id": sid, "status": "completed", "totalBreaches": len(result["breaches"]),
                                     "totalPastes": len(result["pastes"])}))
            except Exception as exc:  # noqa: BLE001 - reported as the terminal error event
                events.put(("error", {"id": sid, "message": str(exc)}))
        threading.Thread(target=work, daemon=True).start()

        deadline = time.monotonic() + STREAM_MAX_SECONDS
        while time.monotonic() < deadline:
            try:
                event, data = events.get(timeout=HEARTBEAT_SECONDS)
            except queue.Empty:
                h.sse(None, "heartbeat")
                continue
            h.sse(event, shape(event, data))
            if event in ("done", "error"):
                return
        h.sse("error", {"id": sid, "message": "stream exceeded maximum duration"})

    # -- profiles ----------------------------------------------------------
    def _profile_or_404(pid):
        p = app.store.get_profile(pid)
        if not p:
            raise ApiError(404, "invalid_request_error", "profile_not_found", "Profile not found")
        return p

    def _summary(p):
        return {"id": p["id"], "label": p["label"], "autopilot": p["autopilot"], "created_at": p["created_at"],
                **coverage(app.store.exposures(p["id"]))}

    @route("GET", "/v1/profiles", "read", ("profiles:read",))
    def list_profiles(h, key):
        h.send_json(200, {"data": [_summary(p) for p in app.store.list_profiles()]})

    @route("POST", "/v1/profiles", "write", ("profiles:write",))
    def create_profiles(h, key):
        items = h.body().get("profiles")
        if not isinstance(items, list) or not items or len(items) > 500:
            raise ApiError(422, "invalid_request_error", "validation_failed", "'profiles' must be a list of 1-500 items")
        errors, normalised = [], []
        for i, item in enumerate(items):
            try:
                if not isinstance(item, dict) or not item.get("label"):
                    raise ValueError("each profile needs a 'label'")
                normalised.append((item["label"], normalise_profile(item), item.get("autopilot", True)))
            except ValueError as exc:
                errors.append({"index": i, "message": str(exc)})
        if errors:
            raise ApiError(422, "invalid_request_error", "validation_failed", "Profile validation failed", errors)
        ids = [app.store.add_profile(label, data, bool(auto)) for label, data, auto in normalised]
        app.store.audit(key["id"], "profiles_created", ",".join(ids))
        h.send_json(201, {"data": [{"id": i} for i in ids]})

    @route("GET", r"/v1/profiles/(?P<pid>prof_[0-9a-f]+)", "read", ("profiles:read",))
    def get_profile(h, key, pid):
        h.send_json(200, _summary(_profile_or_404(pid)))

    @route("GET", r"/v1/profiles/(?P<pid>prof_[0-9a-f]+)/exposures", "read", ("profiles:read",))
    def exposures(h, key, pid):
        _profile_or_404(pid)
        fields = ("id", "source_id", "source_name", "source_type", "url", "data_types", "confidence", "risk",
                  "status", "first_seen", "last_seen")
        data = [{**{f: e[f] for f in fields}, "severity": severity(e["risk"]),
                 "remediation": (e["details"] or {}).get("remediation")} for e in app.store.exposures(pid)]
        h.send_json(200, {"data": data})

    @route("GET", r"/v1/profiles/(?P<pid>prof_[0-9a-f]+)/removals", "read", ("profiles:read",))
    def removals(h, key, pid):
        _profile_or_404(pid)
        fields = ("id", "exposure_id", "source_id", "method", "legal_basis", "status", "attempts", "created_at",
                  "submitted_at", "next_check_at", "closed_at", "note")
        h.send_json(200, {"data": [{f: r[f] for f in fields} for r in app.store.removals(pid)]})

    @route("POST", r"/v1/profiles/(?P<pid>prof_[0-9a-f]+)/scan", "write", ("profiles:write",))
    def scan(h, key, pid):
        profile = _profile_or_404(pid)
        summary = scan_profile(app.store, profile, app.providers(), app.brokers)
        h.send_json(200, {"profile_id": pid, **summary, **coverage(app.store.exposures(pid))})

    # -- dashboard ---------------------------------------------------------
    @route("GET", "/", "default", None)
    def dashboard(h, key):
        raw = resources.files("privacysearch").joinpath("data/dashboard.html").read_bytes()
        h.send_response(200)
        h.send_header("Content-Type", "text/html; charset=utf-8")
        h.send_header("Content-Length", str(len(raw)))
        h.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; "
                      "script-src 'unsafe-inline'; connect-src 'self'")
        h.end_headers()
        h.wfile.write(raw)

    return Handler


def serve(app, host: str = "127.0.0.1", port: int = 8787, restrict_to_profiles: bool = True,
          rate_limits: dict[str, int] | None = None) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(app, restrict_to_profiles, rate_limits))
    server.daemon_threads = True
    return server
