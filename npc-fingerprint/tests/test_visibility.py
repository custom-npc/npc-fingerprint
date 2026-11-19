"""Round-3 visibility features: Next.js route/chunk mining, generic lazy-chunk following, source-map mining,
env-var/GraphQL/tRPC/npm-scope extraction, DOM/postMessage sinks, and the npm dependency-confusion check."""
import http.server
import json
import socketserver
import threading
import unittest

import _bootstrap  # noqa: F401
from npc_fingerprint.fetch.snapshot import PageSnapshot, ScriptRef
from npc_fingerprint.fetch.static import FetchResult, StaticFetcher
from npc_fingerprint.modules import jsrecon

MAIN_JS = b"""
fetch("/api/secret-route");
import(/* webpackChunkName: "billing" */ "/static/js/billing-settings.abcd.js");
const u = process.env.NEXT_PUBLIC_API_URL;
graphqlClient.query(`query GetUser($id: ID!) { user(id: $id) { id name } }`);
fetch("/api/trpc/user.getProfile");
const pkg = "@acme-internal/ui-kit";
const dsn = "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@o123456.ingest.sentry.io/789";
const pool = "us-east-1:a1b2c3d4-e5f6-7890-abcd-ef1234567890";
window.addEventListener("message", function(e) { document.getElementById("x").innerHTML = e.data; });
"""
BILLING_JS = b'fetch("/api/v3/billing");'
NEXT_DATA = b'<script id="__NEXT_DATA__" type="application/json">{"buildId":"abc123","props":{}}</script>'
BUILD_MANIFEST = b"""self.__BUILD_MANIFEST = {
"/":["static/chunks/pages/index-h1.js"],
"/about":["static/chunks/pages/about-h2.js"],
"sortedPages":["/","/about"]
};self.__BUILD_MANIFEST_CB && self.__BUILD_MANIFEST_CB()"""
SSG_MANIFEST = b'self.__SSG_MANIFEST=new Set(["/","/about"]);self.__SSG_MANIFEST_CB&&self.__SSG_MANIFEST_CB()'
ABOUT_CHUNK = b'fetch("/api/about-data");'


class Server(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _r(self, body, ctype="application/javascript"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        routes = {
            "/_next/static/chunks/main-xyz.js": MAIN_JS,
            "/_next/static/abc123/_buildManifest.js": BUILD_MANIFEST,
            "/_next/static/abc123/_ssgManifest.js": SSG_MANIFEST,
            "/_next/static/chunks/pages/about-h2.js": ABOUT_CHUNK,
            "/static/js/billing-settings.abcd.js": BILLING_JS,
        }
        if self.path in routes:
            return self._r(routes[self.path])
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


class NextjsAndLazyChunks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Server)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        html = NEXT_DATA.decode() + f'<script src="{base}/_next/static/chunks/main-xyz.js"></script>'
        cls.snap = PageSnapshot(mode="static", url=base + "/", final_url=base + "/", status=200, html_raw=html,
                                scripts=[ScriptRef(url=f"{base}/_next/static/chunks/main-xyz.js")])
        cls.fetcher = StaticFetcher("t/1", timeout=5)
        cls.res = jsrecon.analyze(cls.snap, cls.fetcher)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_nextjs_build_id_and_routes_are_recovered(self):
        self.assertEqual(self.res["framework"]["name"], "Next.js")
        self.assertEqual(self.res["framework"]["build_id"], "abc123")
        self.assertEqual(self.res["framework"]["routes_found"], 2)
        routes = {e["value"] for e in self.res["endpoints"]["by_kind"]["route"]}
        self.assertEqual(routes, {"/", "/about"})

    def test_chunks_named_by_the_manifest_are_fetched_and_mined(self):
        # about-h2.js is only known via the buildManifest's route->chunk map, never referenced in the HTML.
        self.assertIn("/api/about-data", [e["value"] for e in self.res["endpoints"]["by_kind"]["api"]])
        self.assertGreaterEqual(self.res["framework"]["chunks_fetched"], 1)

    def test_generic_lazy_chunk_is_followed_and_mined(self):
        # billing-settings.abcd.js is a plain literal import() string in main.js, not a <script src>.
        self.assertIn("/api/v3/billing", [e["value"] for e in self.res["endpoints"]["by_kind"]["api"]])

    def test_main_endpoint_is_found_too(self):
        self.assertIn("/api/secret-route", [e["value"] for e in self.res["endpoints"]["by_kind"]["api"]])

    def test_graphql_operation_name_and_trpc_procedure(self):
        self.assertIn("GetUser", self.res["graphql_operations"])
        self.assertIn("user.getProfile", self.res["trpc_procedures"])

    def test_env_var_name_is_harvested(self):
        self.assertIn("NEXT_PUBLIC_API_URL", self.res["env_vars"])

    def test_npm_scope_candidate_is_collected_common_scopes_are_not(self):
        self.assertIn("@acme-internal/ui-kit", self.res["npm_candidates"])

    def test_sentry_dsn_and_cognito_pool_are_found_as_info_level(self):
        types = {s["type"]: s for s in self.res["secrets"]["items"]}
        self.assertIn("Sentry DSN", types)
        self.assertEqual(types["Sentry DSN"]["severity"], "info")
        self.assertIn("AWS Cognito identity pool ID", types)

    def test_secrets_never_appear_in_full(self):
        blob = json.dumps(self.res)
        self.assertNotIn("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@o123456", blob)
        self.assertNotIn("a1b2c3d4-e5f6-7890-abcd-ef1234567890", blob)

    def test_dom_sinks_and_unchecked_message_listener(self):
        d = self.res["dom_sinks"]
        self.assertGreaterEqual(d["risky_listener_count"], 1)
        self.assertFalse(d["message_listeners"][0]["has_origin_check"])
        self.assertIn("innerHTML", d["sinks"])

    def test_extra_requests_stayed_first_party_and_bounded(self):
        extra = self.snap.extra_requests
        self.assertLessEqual(sum(1 for x in extra if x.startswith(("nextjs:", "lazy-chunk"))), jsrecon.MAX_EXTRA_SCRIPTS + 2)


class UrlUserinfoHandling(unittest.TestCase):
    def test_credential_in_a_url_is_never_mistaken_for_a_hostname(self):
        # A regression for a real bug this suite caught: the URL matcher used to stop right before the "@" in
        # "https://<secret>@host/path", so the secret itself was misread as a hostname and leaked into the
        # third-party hosts list. The real host must be recovered and the secret must never appear as a host.
        dsn = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        text = f'const dsn = "https://{dsn}@o123456.ingest.sentry.io/789";'
        res = jsrecon.mine([("a.js", text)], "x.test", "x.test")
        self.assertNotIn(dsn, res["hosts"]["third_party"])
        self.assertIn("o123456.ingest.sentry.io", res["hosts"]["third_party"])


class OriginCheckedListener(unittest.TestCase):
    def test_a_listener_with_an_origin_check_is_not_flagged_risky(self):
        texts = [("app.js", 'addEventListener("message", e => { if (e.origin !== "https://x.test") return; doThing(e.data); });')]
        d = jsrecon.find_dom_sinks(texts)
        self.assertEqual(d["risky_listener_count"], 0)
        self.assertTrue(d["message_listeners"][0]["has_origin_check"])


class JwtAlgorithmMix(unittest.TestCase):
    def test_two_different_algorithms_on_one_page_are_flagged(self):
        import base64

        def b64(o):
            return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
        hs = f"{b64({'alg': 'HS256'})}.{b64({'sub': '1'})}.sig_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        rs = f"{b64({'alg': 'RS256'})}.{b64({'sub': '2'})}.sig_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        res = jsrecon.mine([("a.js", f'const t1="{hs}"; const t2="{rs}";')], "x.test", "x.test")
        mix = next((s for s in res["secrets"]["items"] if s["type"] == "JWT algorithm mix"), None)
        self.assertIsNotNone(mix)
        self.assertIn("HS256", mix["redacted"])
        self.assertIn("RS256", mix["redacted"])


class SourceMapMining(unittest.TestCase):
    def test_exposed_map_is_fetched_and_original_source_is_mined(self):
        class F:
            def get(self, url, **kw):
                doc = {"sources": ["webpack:///src/api/client.ts"],
                       "sourcesContent": ["export const BASE = '/api/v9/internal'; // TODO remove debug flag"]}
                return FetchResult(url, 200, [("Content-Type", "application/json")], json.dumps(doc).encode())
        snap = PageSnapshot(mode="static", url="https://x.test/", final_url="https://x.test/")
        bundle = {"source_maps": [{"script": "main.js", "map_url": "https://x.test/main.js.map", "status": "exposed"}]}
        sm = jsrecon.mine_source_maps(bundle, snap, F())
        self.assertEqual(sm["maps_fetched"], 1)
        self.assertIn("src/api/client.ts", sm["sources"][0])
        texts = sm["extra_texts"]
        self.assertTrue(any("/api/v9/internal" in t for _, t in texts))

    def test_no_exposed_maps_means_no_fetch(self):
        snap = PageSnapshot(mode="static", url="https://x.test/", final_url="https://x.test/")
        sm = jsrecon.mine_source_maps({"source_maps": [{"status": "not-exposed"}]}, snap, object())
        self.assertEqual(sm, {"maps_fetched": 0, "sources": [], "extra_texts": []})


class NpmConfusionCheck(unittest.TestCase):
    def test_404_is_confirmed_200_is_noise_error_is_unverified(self):
        class F:
            def get(self, url, **kw):
                if "unpublished" in url:
                    return FetchResult(url, 404, [], b"")
                if "taken" in url:
                    return FetchResult(url, 200, [], b"{}")
                raise OSError("dns failure")
        res = jsrecon.check_npm_confusion(["@acme/unpublished-pkg", "@acme/taken-pkg", "@acme/broken-pkg"], F())
        by = {c["name"]: c["state"] for c in res["checked"]}
        self.assertEqual(by["@acme/unpublished-pkg"], "confirmed")
        self.assertEqual(by["@acme/taken-pkg"], "noise")
        self.assertEqual(by["@acme/broken-pkg"], "unverified")

    def test_a_confirmed_exposure_becomes_a_priority_action(self):
        from npc_fingerprint import merge
        rep = {"recon": {"npm_confusion": {"checked": [{"name": "@acme/internal-pkg", "state": "confirmed", "note": "x"},
                                                        {"name": "@acme/taken", "state": "noise", "note": "y"}]}, "secrets": {"items": []}},
              "vulnerabilities": {"items": []}, "tls_findings": [], "active": {"checks": []}, "security_headers": [],
              "bundle": {}, "hygiene": {}, "anomalies": [], "target": {"status": 200, "scheme": "https"}}
        acts = merge.build_actions(rep)
        self.assertTrue(any("acme/internal-pkg" in a["text"] and a["severity"] == "high" for a in acts))
        self.assertFalse(any("taken" in a["text"] for a in acts))

    def test_check_is_bounded_and_never_touches_the_target(self):
        calls = []

        class F:
            def get(self, url, **kw):
                calls.append(url)
                return FetchResult(url, 404, [], b"")
        jsrecon.check_npm_confusion([f"@x/{i}" for i in range(30)], F(), max_checks=5)
        self.assertEqual(len(calls), 5)
        self.assertTrue(all(u.startswith("https://registry.npmjs.org/") for u in calls))


if __name__ == "__main__":
    unittest.main()
