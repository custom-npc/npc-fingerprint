"""The whole product in one pass against local fixtures: fingerprint + posture + CVEs + recon + active + Nuclei + report."""
import http.server
import io
import json
import unittest
from unittest import mock

import _bootstrap  # noqa: F401
from fixtures import Site, StaticHandler, STATIC_HTML
from vuln_fixtures import make_vuln_db, osv_jquery_vulns
from npc_fingerprint.db import store
from npc_fingerprint.modules import drift
from npc_fingerprint.render import emit
from npc_fingerprint.scanner import Options, Scanner
from npc_fingerprint.vulns.osv import OsvClient

STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
LEAK_JS = (f"const k='{STRIPE}'; fetch('/api/v1/orders'); fetch('/graphql'); const e = '/admin/export';\n").encode()
DBDIR = str(make_vuln_db())


def fake_post(self, body):
    return {"vulns": osv_jquery_vulns()} if body["package"]["name"] == "jquery" else {}


class Recording(StaticHandler):
    seen: list = []

    def do_OPTIONS(self):
        Recording.seen.append("OPTIONS /")
        self.send_response(204); self.send_header("Allow", "GET, HEAD, OPTIONS"); self.end_headers()

    def do_GET(self):
        Recording.seen.append(f"GET {self.path} origin={self.headers.get('Origin')}")
        if self.path == "/leak.js":
            self.send_response(200); self.send_header("Content-Type", "application/javascript"); self.send_header("Content-Length", str(len(LEAK_JS)))
            self.end_headers(); self.wfile.write(LEAK_JS); return
        if self.path == "/":
            body = STATIC_HTML.replace(b"</head>", b'<script src="/leak.js"></script></head>')
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("X-Powered-By", "PHP/7.4.3")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        return super().do_GET()


def scan(url, **kw):
    kw.setdefault("no_dns", True)
    kw.setdefault("no_cache", True)
    kw.setdefault("no_browser", True)
    kw.setdefault("db_dir", DBDIR)
    sc = Scanner(Options(**kw), store.load())
    try:
        with mock.patch.object(OsvClient, "_post", fake_post):
            return sc.scan(url)
    finally:
        sc.close()


class FullScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Recording.seen = []
        cls.site = Site(Recording).__enter__()
        cls.rep = scan(cls.site.url)
        cls.hits = list(Recording.seen)

    @classmethod
    def tearDownClass(cls):
        cls.site.__exit__()

    def cve(self, cid):
        return next((i for i in self.rep["vulnerabilities"]["items"] if i["cve"] == cid), None)

    def test_cve_matching_uses_both_sources_and_ranks_by_exploitation(self):
        a, j = self.cve("CVE-2020-1927"), self.cve("CVE-2020-11022")
        self.assertEqual((a["priority"], a["sources"]), ("exploited", ["nvd"]))
        self.assertEqual((j["priority"], j["sources"], j["fixed"]), ("likely", ["osv"], "3.5.0"))
        self.assertEqual(self.rep["vulnerabilities"]["items"][0]["cve"], "CVE-2020-1927")
        self.assertTrue(any("distribution" in c for c in a["caveats"]))                 # Server: Apache/2.4.41 (Ubuntu)

    def test_priority_actions_lead_with_the_exploited_cve_and_the_leaked_secret(self):
        acts = self.rep["actions"]
        self.assertEqual(acts[0]["severity"], "critical")
        self.assertIn("Apache HTTP Server 2.4.41", acts[0]["text"])
        self.assertTrue(any("Rotate the exposed Stripe secret key" in a["text"] for a in acts))
        self.assertTrue(any("Content-Security-Policy" in a["text"] for a in acts))

    def test_recon_finds_endpoints_and_redacts_the_secret_everywhere(self):
        rc = self.rep["recon"]
        self.assertIn("/api/v1/orders", [e["value"] for e in rc["endpoints"]["by_kind"]["api"]])
        self.assertEqual(rc["endpoints"]["graphql"], ["/graphql"])
        self.assertEqual(rc["secrets"]["items"][0]["type"], "Stripe secret key")
        for text in (json.dumps(self.rep), "\n".join(emit.to_plain(emit.render_report(self.rep, emit.make_console(width=80, file=io.StringIO()), width=80, verbose=True)))):
            self.assertNotIn(STRIPE, text)
        self.assertIn("sk_l…dc", json.dumps(self.rep, ensure_ascii=False))

    def test_nuclei_suggestions_connect_cves_to_templates_and_never_run(self):
        nz = self.rep["nuclei"]
        self.assertFalse(nz["executed"])
        self.assertIn("CVE-2020-1927", [t["template"] for t in nz["by_cve"]])
        self.assertIn("-id CVE-2020-1927", nz["commands"]["cve_templates"])
        self.assertIn("apache", [t["tag"] for t in nz["tags"]])

    def test_active_checks_ran_and_stayed_read_only(self):
        ids = {c["id"] for c in self.rep["active"]["checks"]}
        self.assertTrue({"http-methods", "cors", "error-page", "graphql-introspection"} <= ids)
        self.assertTrue(any(h.startswith("OPTIONS") for h in self.hits))
        self.assertTrue(any("origin=https://npc-fingerprint.invalid" in h for h in self.hits))
        self.assertTrue(all(h.startswith(("OPTIONS", "GET")) for h in self.hits))             # nothing but read-only methods

    def test_report_is_json_serialisable_and_additive(self):
        json.dumps(self.rep)
        for k in ("technologies", "weak", "anomalies", "favicon", "security_headers", "csp", "tls", "http", "bundle", "libraries", "edge", "third_party", "hygiene", "drift"):
            self.assertIn(k, self.rep)                                                  # every pre-existing key is still there
        for k in ("vulnerabilities", "recon", "active", "nuclei", "actions"):
            self.assertIn(k, self.rep)


class Modes(unittest.TestCase):
    def test_passive_sends_no_active_requests(self):
        Recording.seen = []
        with Site(Recording) as s:
            rep = scan(s.url, passive=True)
        self.assertFalse(rep["active"]["enabled"])
        self.assertEqual(rep["active"]["checks"], [])
        self.assertFalse(any(h.startswith("OPTIONS") or "npc-fingerprint-" in h or "origin=https://npc" in h for h in Recording.seen))
        self.assertEqual(sum(1 for x in rep["requests"]["extra"] if x.startswith("active:")), 0)

    def test_offline_never_calls_osv_and_says_so(self):
        with Site(Recording) as s, mock.patch.object(OsvClient, "_post", side_effect=AssertionError("network used in offline mode")):
            sc = Scanner(Options(no_dns=True, no_cache=True, no_browser=True, db_dir=DBDIR, offline=True), store.load())
            rep = sc.scan(s.url)
            sc.close()
        v = rep["vulnerabilities"]
        self.assertEqual(v["status"], "partial")
        self.assertGreaterEqual(v["sources"]["osv"]["skipped"], 1)
        self.assertEqual(v["sources"]["osv"]["errors"], [])
        self.assertTrue(any(i["cve"] == "CVE-2020-1927" for i in v["items"]))           # local data still answers
        self.assertTrue(any(i["sources"] == ["retire.js"] for i in v["items"]))         # and the retire.js fallback covers jQuery

    def test_skip_stages(self):
        with Site(Recording) as s:
            rep = scan(s.url, skip={"vulns", "recon", "active", "nuclei"})
        self.assertIsNone(rep["vulnerabilities"])
        self.assertIsNone(rep["nuclei"])
        self.assertTrue(rep["recon"].get("skipped"))
        self.assertEqual(rep["active"]["checks"], [])

    def test_missing_cve_database_degrades_loudly_not_silently(self):
        with Site(Recording) as s:
            rep = scan(s.url, db_dir="/nonexistent/dir")
        v = rep["vulnerabilities"]
        self.assertEqual(v["status"], "partial")
        self.assertTrue(any("not installed" in w for w in rep["warnings"]))
        self.assertTrue(any(i["cve"] == "CVE-2020-11022" for i in v["items"]))           # OSV works without the local database

    def test_baseline_drift_covers_cves_and_secrets(self):
        with Site(Recording) as s:
            first = scan(s.url)
            old = json.loads(json.dumps(first))
            old["vulnerabilities"]["items"] = [i for i in old["vulnerabilities"]["items"] if i["cve"] != "CVE-2020-11022"]
            old["recon"]["secrets"]["items"] = []
            path = __import__("tempfile").mktemp(suffix=".json")
            with open(path, "w") as fh:
                json.dump({"reports": [old]}, fh)
            sc = Scanner(Options(no_dns=True, no_cache=True, no_browser=True, db_dir=DBDIR, baseline=drift.load_baseline(path)), store.load())
            with mock.patch.object(OsvClient, "_post", fake_post):
                again = sc.scan(s.url)
            sc.close()
        kinds = {(c["area"], c["kind"]) for c in again["drift"]["changes"]}
        self.assertIn(("vulnerability", "added"), kinds)
        self.assertIn(("secret", "added"), kinds)


if __name__ == "__main__":
    unittest.main()
