import base64
import http.server
import json
import socketserver
import threading
import unittest

import _bootstrap  # noqa: F401
from fixtures import Site
from npc_fingerprint.fetch.snapshot import PageSnapshot, ScriptRef
from npc_fingerprint.fetch.static import FetchResult, StaticFetcher
from npc_fingerprint.modules import active, jsrecon

active.DELAY = 0


def b64(o):
    return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")


AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
GKEY = "AIza" + "SyA-1234567890abcdefghijklmnopqrstu"
PASSWORD = "Zx9Qp4Lm7Rt2Vw8Yb3Nc6Hd1Kf5Js0Ga"
JWT = f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'iss': 'https://auth.shop.test', 'role': 'admin', 'exp': 1000, 'email': 'a@b.c'})}.c2lnbmF0dXJlLXNpZ25hdHVyZQ"
JS = f"""
const API = "/api/v2/users/{{id}}"; fetch("/graphql"); fetch('/admin/export?format=csv'); const a="/static/js/x.js"; const b="/logo.png"; fetch("/health");
const s = new WebSocket("wss://rt.shop.test/socket"); const u = "https://shop.test/rest/orders/list";
const ext = "https://api.stripe.com/v1/charges"; const w3 = "http://www.w3.org/2000/svg";
const stg = "https://staging.shop.test/api/health"; const lan = "http://192.168.1.20:8080/debug"; const dbh = "https://shop-dev.internal/x";
const bucket = "https://acme-prod-assets.s3.amazonaws.com/img/a.png"; const gcs = "https://storage.googleapis.com/acme-backups/db.sql"; const old = "https://s3.amazonaws.com/legacy-bucket/f";
const awsKey = "{AWS}"; const stripe = "{STRIPE}"; const gk = "{GKEY}";
const cfg = {{ apiKey: "{PASSWORD}", password: "changeme", client_secret: "your-client-secret", secret: "aaaaaaaaaaaaaaaaaaaa" }};
const tok = "{JWT}";
/* -----BEGIN RSA PRIVATE KEY----- */
"""
HTML = "<html><!-- TODO remove admin password before launch --><!-- build 1234 --><!--[if IE]><p>ie</p><![endif]--></html>"


def recon_snapshot():
    return PageSnapshot(mode="browser", url="https://shop.test/", final_url="https://shop.test/", html_raw=HTML,
                        scripts=[ScriptRef(url="https://shop.test/static/main.js", recon_text=JS),
                                 ScriptRef(url="https://cdn.other.test/lib.js", recon_text="const k='" + STRIPE + "'; fetch('/api/third')")])


class JsRecon(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = jsrecon.analyze(recon_snapshot(), None)
        cls.kinds = {k: [e["value"] for e in v] for k, v in cls.r["endpoints"]["by_kind"].items()}

    def test_endpoints_are_classified_and_noise_is_dropped(self):
        k = self.kinds
        self.assertIn("/api/v2/users/{id}", k["api"])
        self.assertIn("/admin/export?format=csv", k["admin"])
        self.assertIn("/health", k["ops"])
        self.assertIn("https://staging.shop.test/api/health", k["api"])
        self.assertNotIn("/static/js/x.js", str(k))
        self.assertNotIn("/logo.png", str(k))
        self.assertEqual(self.r["endpoints"]["graphql"], ["/graphql"])
        self.assertTrue(self.r["endpoints"]["websockets"])

    def test_third_party_scripts_are_not_mined(self):
        self.assertNotIn("/api/third", str(self.kinds))
        self.assertEqual(sum(1 for s in self.r["secrets"]["items"] if s["type"] == "Stripe secret key"), 1)

    def test_secret_types_and_false_positive_filters(self):
        have = {s["type"] for s in self.r["secrets"]["items"]}
        self.assertTrue({"AWS access key ID", "Stripe secret key", "Private key", "Hard-coded credential", "Google API key", "JSON Web Token"} <= have)
        red = " ".join(s["redacted"] for s in self.r["secrets"]["items"])
        self.assertNotIn("changeme", red)                       # placeholder
        self.assertNotIn("aaaa", red)                           # low entropy

    def test_secrets_are_never_emitted_in_full(self):
        blob = json.dumps(self.r)
        for secret in (AWS, STRIPE, GKEY, PASSWORD, "a@b.c"):
            self.assertNotIn(secret, blob)

    def test_jwt_description_leaks_no_claim_values(self):
        jwt = next(s for s in self.r["secrets"]["items"] if s["type"] == "JSON Web Token")
        self.assertIn("alg HS256", jwt["note"])
        self.assertIn("expired", jwt["note"])
        self.assertIn("role", jwt["note"])
        self.assertNotIn("admin", jwt["note"])

    def test_hosts_buckets_and_comments(self):
        h = self.r["hosts"]
        self.assertIn("192.168.1.20", h["internal"])
        self.assertIn("shop-dev.internal", h["internal"])
        self.assertEqual(h["staging"], ["staging.shop.test"])
        self.assertEqual({b["name"] for b in h["buckets"]}, {"acme-prod-assets", "acme-backups", "legacy-bucket"})
        self.assertNotIn("www.w3.org", h["third_party"])
        self.assertEqual(len(self.r["comments"]), 1)
        self.assertIn("password", self.r["comments"][0])

    def test_static_mode_downloads_bodies_with_a_budget(self):
        class F:
            def __init__(self): self.calls = 0
            def get(self, url, **kw):
                self.calls += 1
                return FetchResult(url, 200, [], b"fetch('/api/v1/x')")
        snap = PageSnapshot(mode="static", url="https://shop.test/", final_url="https://shop.test/",
                            scripts=[ScriptRef(url=f"https://shop.test/s{i}.js") for i in range(20)])
        f = F()
        res = jsrecon.analyze(snap, f)
        self.assertEqual(f.calls, jsrecon.STATIC_FETCH_LIMIT)
        self.assertTrue(any("only the first" in n for n in res["notes"]))
        self.assertEqual(snap.extra_requests.count("script-body"), jsrecon.STATIC_FETCH_LIMIT)


def serve(handler):
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class ActiveChecks(unittest.TestCase):
    def run_checks(self, handler, recon=None, headers=None):
        srv = serve(handler)
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}/"
            snap = PageSnapshot(mode="static", url=url, final_url=url, status=200, headers=headers or [("Server", "nginx/1.18.0")])
            f = StaticFetcher("t/1", timeout=5)
            return active.analyze(snap, f, recon), snap
        finally:
            srv.shutdown(); srv.server_close()

    def test_vulnerable_server_findings_and_request_budget(self):
        class H(http.server.BaseHTTPRequestHandler):
            server_version = "nginx/1.18.0"
            def version_string(self): return self.server_version
            def log_message(self, *a): pass
            def _r(self, code, body=b"", extra=()):
                self.send_response(code)
                for k, v in extra: self.send_header(k, v)
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            def do_OPTIONS(self): self._r(204, extra=[("Allow", "GET, HEAD, OPTIONS, TRACE, PUT")])
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self._r(200, b'{"data":{"__schema":{"queryType":{"name":"Query"}}}}', [("Content-Type", "application/json")])
            def do_GET(self):
                o = self.headers.get("Origin")
                extra = [("Access-Control-Allow-Origin", o), ("Access-Control-Allow-Credentials", "true")] if o else []
                if self.path == "/":
                    return self._r(200, b"<html>ok</html>", extra)
                self._r(404, b"<center>nginx/1.18.0</center>Traceback (most recent call last):\n")
        res, snap = self.run_checks(H, {"endpoints": {"graphql": ["/graphql"]}})
        c = {x["id"]: x for x in res["checks"]}
        self.assertEqual(c["http-methods"]["status"], "weak")
        self.assertIn("TRACE", c["http-methods"]["reason"])
        self.assertEqual((c["cors"]["status"], c["cors"]["severity"]), ("weak", "high"))
        self.assertEqual(c["error-page"]["data"]["signatures"], ["Stack trace (Python)"])
        self.assertEqual(c["graphql-introspection"]["status"], "weak")
        self.assertEqual(res["disclosures"][0]["version"], "1.18.0")
        self.assertNotIn("https-redirect", c)                                    # plain-HTTP target: does not apply
        self.assertEqual(res["requests"], 5)                                      # OPTIONS, CORS x2, error page, GraphQL
        self.assertEqual(len([x for x in snap.extra_requests if x.startswith("active:")]), 5)

    def test_well_configured_server_passes(self):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_OPTIONS(self): self.send_response(204); self.send_header("Allow", "GET, HEAD, OPTIONS"); self.end_headers()
            def do_GET(self):
                code = 200 if self.path == "/" else 404
                self.send_response(code); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
        res, _ = self.run_checks(H, None, headers=[])
        c = {x["id"]: x for x in res["checks"]}
        self.assertEqual((c["http-methods"]["status"], c["cors"]["status"], c["error-page"]["status"]), ("pass", "pass", "pass"))
        self.assertNotIn("graphql-introspection", c)                             # nothing named GraphQL, so no query is ever sent

    def test_https_redirect_logic_with_a_stub_fetcher(self):
        class F:
            def __init__(self, r): self.r = r
            def get(self, url, **kw): return self.r
        def run(result):
            snap = PageSnapshot(mode="static", url="https://example.test/", final_url="https://example.test/", status=200)
            return active.check_https_redirect(active._Ctx(snap, F(result)), snap)
        self.assertEqual(run(FetchResult("u", 301, [("Location", "https://example.test/")]))["status"], "pass")
        self.assertEqual(run(FetchResult("u", 200, []))["status"], "weak")
        self.assertEqual(run(FetchResult("u", 302, [("Location", "http://other/")]))["status"], "weak")
        self.assertEqual(run(FetchResult("u", error="refused"))["status"], "info")

    def test_internal_addresses_are_never_probed_for_public_targets(self):
        class F:
            def __init__(self): self.calls = []
            def get(self, url, **kw): self.calls.append(url); return FetchResult(url, 200, [], b"")
        snap = PageSnapshot(mode="static", url="https://public.example/", final_url="https://public.example/", status=200)
        c = active._Ctx(snap, F())
        self.assertIsNone(c.get("x", "http://169.254.169.254/latest"))
        self.assertEqual(c.f.calls, [])

    def test_tls_version_probing_against_a_local_server(self):
        with Site(http.server.SimpleHTTPRequestHandler, tls=True) as s:
            r12 = active._try_version("localhost", s.port, "TLSv1.2")
            r13 = active._try_version("localhost", s.port, "TLSv1.3")
            r10 = active._try_version("localhost", s.port, "TLSv1.0")
        self.assertEqual((r12, r13), ("accepted", "accepted"))
        self.assertIn(r10, ("rejected", "untestable"))                           # modern server refuses it, or this OpenSSL cannot even try

    def test_legacy_tls_acceptance_is_reported_and_untestable_is_not_called_a_pass(self):
        snap = PageSnapshot(mode="static", url="https://x.test/", final_url="https://x.test:8443/", status=200)
        c = active._Ctx(snap, None)
        orig = active._try_version
        try:
            active._try_version = lambda h, p, n, timeout=4.0: {"TLSv1.0": "accepted", "TLSv1.1": "rejected", "TLSv1.2": "accepted", "TLSv1.3": "accepted"}[n]
            self.assertEqual((lambda r: (r["status"], r["severity"]))(active.check_tls_protocols(c, snap)), ("weak", "high"))
            active._try_version = lambda h, p, n, timeout=4.0: "untestable" if n in ("TLSv1.0", "TLSv1.1") else "accepted"
            r = active.check_tls_protocols(c, snap)
            self.assertEqual(r["status"], "pass")
            self.assertIn("could not be tested", r["reason"])
        finally:
            active._try_version = orig


if __name__ == "__main__":
    unittest.main()
