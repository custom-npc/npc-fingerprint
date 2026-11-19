import http.server
import socketserver
import threading
import unittest

import _bootstrap  # noqa: F401
from npc_fingerprint.fetch.snapshot import PageSnapshot
from npc_fingerprint.fetch.static import StaticFetcher
from npc_fingerprint.modules import verify


class Fixture(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _r(self, code, body=b"", ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        if self.path == "/robots.txt":
            return self._r(200, b"User-agent: *\nDisallow: /admin/\nDisallow: /private/\n")
        if self.path == "/sitemap.xml":
            return self._r(200, b"<urlset><url><loc>https://x/a</loc></url><url><loc>https://x/b</loc></url></urlset>", "application/xml")
        if self.path == "/openapi.json":
            return self._r(200, b'{"openapi":"3.0.0","info":{"title":"Shop API"},"paths":{"/a":{},"/b":{}}}', "application/json")
        if self.path == "/api/v2/orders":
            return self._r(401, b"")
        if self.path == "/api/v1/orders":
            return self._r(404, b"")
        if self.path == "/admin/export":
            return self._r(200, b"ok")
        return self._r(404, b"<html>not found</html>", "text/html")


def serve():
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class SchemaDiscovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = serve()
        url = f"http://127.0.0.1:{cls.srv.server_address[1]}/"
        cls.snap = PageSnapshot(mode="static", url=url, final_url=url, status=200)
        cls.f = StaticFetcher("t/1", timeout=5)
        cls.result = verify.schema_discovery(cls.snap, cls.f)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def get(self, path):
        return next((x for x in self.result["found"] if x["path"] == path), None)

    def test_robots_and_sitemap_are_summarised(self):
        self.assertIn("2 Disallow", self.get("/robots.txt")["summary"])
        self.assertIn("2 URL", self.get("/sitemap.xml")["summary"])

    def test_a_real_openapi_document_is_parsed(self):
        self.assertIn("Shop API", self.get("/openapi.json")["summary"])
        self.assertIn("3.0.0", self.get("/openapi.json")["summary"])

    def test_soft_404_html_pages_are_rejected_not_reported_as_found(self):
        for path in ("/swagger.json", "/api-docs", "/v3/api-docs", "/.well-known/openid-configuration"):
            self.assertIsNone(self.get(path), path)

    def test_only_the_fixed_convention_list_is_probed(self):
        self.assertEqual(self.result["checked"], len(verify.SCHEMA_PATHS))


class Reachability(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = serve()
        url = f"http://127.0.0.1:{cls.srv.server_address[1]}/"
        cls.snap = PageSnapshot(mode="static", url=url, final_url=url, status=200)
        cls.f = StaticFetcher("t/1", timeout=5)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_status_codes_map_to_honest_states(self):
        recon = {"by_kind": {"api": [{"value": "/api/v2/orders"}], "admin": [{"value": "/admin/export"}]}}
        res = verify.reachability(self.snap, self.f, recon, "127.0.0.1")
        by = {i["value"]: i for i in res["items"]}
        self.assertEqual((by["/api/v2/orders"]["state"], by["/api/v2/orders"]["status_code"]), ("confirmed", 401))
        self.assertEqual((by["/admin/export"]["state"], by["/admin/export"]["status_code"]), ("confirmed", 200))

    def test_shadow_versions_are_derived_from_the_apps_own_convention_not_guessed(self):
        recon = {"by_kind": {"api": [{"value": "/api/v2/orders"}]}}
        res = verify.reachability(self.snap, self.f, recon, "127.0.0.1")
        shadow = next(i for i in res["items"] if i["kind"] == "shadow")
        self.assertEqual((shadow["value"], shadow["derived_from"], shadow["state"], shadow["status_code"]),
                         ("/api/v1/orders", "/api/v2/orders", "noise", 404))

    def test_404_is_noise_not_a_finding(self):
        res = verify.reachability(self.snap, self.f, {"by_kind": {"api": [{"value": "/api/v1/orders"}]}}, "127.0.0.1")
        self.assertEqual(res["items"][0]["state"], "noise")

    def test_out_of_scope_endpoints_are_never_requested(self):
        res = verify.reachability(self.snap, self.f, {"by_kind": {"api": [{"value": "https://evil.com/steal"}]}}, "127.0.0.1")
        self.assertEqual((res["items"][0]["state"], res["requests"]), ("suppressed", 0))

    def test_explicit_scope_allows_a_declared_extra_domain(self):
        res = verify.reachability(self.snap, self.f, {"by_kind": {"api": [{"value": "https://evil.com/steal"}]}}, "127.0.0.1", ["evil.com"])
        self.assertNotEqual(res["items"][0]["state"], "suppressed")

    def test_candidate_count_is_bounded(self):
        many = {"by_kind": {"api": [{"value": f"/api/x{i}"} for i in range(50)]}}
        self.assertLessEqual(len(verify.pick_candidates(many)), verify.MAX_CHECKS)

    def test_shadow_version_count_is_bounded(self):
        paths = [f"/api/v{i}/thing" for i in range(2, 30)]
        self.assertLessEqual(len(verify.shadow_versions(paths)), verify.MAX_SHADOW)


if __name__ == "__main__":
    unittest.main()
