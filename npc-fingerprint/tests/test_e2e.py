import contextlib
import http.server
import io
import json
import tempfile
import threading
import time
import unittest

import _bootstrap  # noqa: F401
from fixtures import Site, SpaHandler, StaticHandler
from npc_fingerprint import cli
from npc_fingerprint.db import store
from npc_fingerprint.fetch.browser import BrowserSession, BrowserUnavailable
from npc_fingerprint.render import emit
from npc_fingerprint.render.theme import asciify
from npc_fingerprint.scanner import Options, Scanner


def browser_available() -> bool:
    try:
        b = BrowserSession("t/1", 10)
        b.start()
        b.close()
        return True
    except BrowserUnavailable:
        return False


HAVE_BROWSER = browser_available()
DB = store.load()


def scan(url, **opts):
    sc = Scanner(Options(no_dns=True, no_cache=True, timeout=opts.pop("timeout", 20), **opts), DB)
    try:
        return sc.scan(url)
    finally:
        sc.close()


def by_name(rep, name):
    return next((d for d in rep["technologies"] if d["name"] == name), None)


def render_lines(rep, width=80, ascii_only=False, verbose=False):
    con = emit.make_console(width=width, file=io.StringIO())
    return emit.to_plain(emit.render_report(rep, con, width=width, ascii_only=ascii_only, verbose=verbose))


class StaticSite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site = Site(StaticHandler).__enter__()
        cls.rep = scan(cls.site.url, no_browser=True)

    @classmethod
    def tearDownClass(cls):
        cls.site.__exit__()

    def test_detections_with_versions_and_evidence(self):
        r = self.rep
        self.assertEqual(by_name(r, "Apache HTTP Server")["version"], "2.4.41")
        self.assertEqual(by_name(r, "PHP")["version"], "7.4.3")
        self.assertEqual(by_name(r, "WordPress")["version"], "6.4.2")
        jq = by_name(r, "jQuery")
        self.assertEqual(jq["version"], "1.12.4")
        self.assertTrue({"script-src", "banner"} <= {e["signal"] for e in jq["evidence"]})
        for d in r["technologies"]:
            self.assertTrue(d["evidence"], d["name"])

    def test_security_findings(self):
        r = self.rep
        st = {f["id"]: f["status"] for f in r["security_headers"]}
        self.assertEqual(st["hsts"], "n/a")
        self.assertTrue(all(st[k] == "missing" for k in ("csp", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy")))
        self.assertEqual(r["summary"]["tls"]["state"], "bad")
        self.assertEqual(r["libraries"]["advisory_counts"]["medium"], 3)
        self.assertEqual(r["hygiene"]["cookies"]["session_cookies_at_risk"], 1)
        self.assertEqual(r["third_party"]["scripts_without_sri"], 1)
        self.assertEqual(r["hygiene"]["security_txt"]["status"], "missing")

    def test_request_budget_and_json(self):
        self.assertLessEqual(self.rep["requests"]["extra_count"], 8)
        json.dumps(self.rep)
        self.assertEqual(self.rep["target"]["mode"], "static")


class SpaSite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site = Site(SpaHandler, tls=True).__enter__()
        cls.static = scan(cls.site.url, no_browser=True)
        cls.browser = scan(cls.site.url) if HAVE_BROWSER else None

    @classmethod
    def tearDownClass(cls):
        cls.site.__exit__()

    @unittest.skipUnless(HAVE_BROWSER, "Chromium not available")
    def test_js_aware_detection_finds_what_static_misses(self):
        react = by_name(self.browser, "React")
        self.assertEqual((react["status"], react["version"]), ("confirmed", "18.2.0"))
        self.assertIn("js-global", {e["signal"] for e in react["evidence"]})
        self.assertNotEqual(by_name(self.static, "React")["status"], "confirmed")     # static HTML only implies it

    @unittest.skipUnless(HAVE_BROWSER, "Chromium not available")
    def test_browser_mode_posture_and_request_budget(self):
        r = self.browser
        self.assertEqual(r["target"]["mode"], "browser")
        self.assertIs(r["tls"]["verified"], False)
        self.assertEqual(r["http"]["observed"], "http/1.1")
        self.assertEqual(r["csp"]["grade"], "D")
        self.assertEqual({f["id"]: f["status"] for f in r["security_headers"]}["hsts"], "pass")
        self.assertTrue(any(m["status"] == "exposed" for m in r["bundle"]["source_maps"]))
        self.assertEqual(r["hygiene"]["security_txt"]["status"], "pass")
        self.assertNotIn("script-head", r["requests"]["extra"])            # bundle bytes reused from the page load
        self.assertLessEqual(r["requests"]["extra_count"], 5)

    def test_static_mode_tls_and_h3_honesty(self):
        r = self.static
        self.assertIs(r["tls"]["verified"], False)
        self.assertTrue(r["tls"]["cert"]["self_signed"])
        self.assertEqual(r["http"]["h3"], "not-seen")


class BareServer(unittest.TestCase):
    def test_python_http_server_missing_headers(self):
        with Site(http.server.SimpleHTTPRequestHandler, directory=tempfile.mkdtemp()) as s:
            r = scan(s.url, no_browser=True)
        st = {f["id"]: f["status"] for f in r["security_headers"]}
        self.assertEqual(st["hsts"], "n/a")
        self.assertEqual(sum(1 for v in st.values() if v == "missing"), 5)
        self.assertEqual(by_name(r, "Python")["version"], "3.12.3")
        self.assertEqual(r["summary"]["tls"]["label"], "none")


class Rendering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with Site(StaticHandler) as a, Site(SpaHandler, tls=True) as b:
            cls.reps = [scan(a.url, no_browser=True), scan(b.url, no_browser=True)]

    def test_fits_80x24_unicode_and_ascii(self):
        for rep in self.reps:
            for asc in (False, True):
                lines = render_lines(rep, 80, asc)
                self.assertLessEqual(len(lines), 24)
                self.assertLessEqual(max(len(x) for x in lines), 80)
                if asc:
                    self.assertTrue(all(ord(c) < 128 for x in lines for c in x))

    def test_narrow_terminal_still_renders(self):
        lines = render_lines(self.reps[0], 60)
        self.assertLessEqual(max(len(x) for x in lines), 60)

    def test_no_escape_codes_when_not_a_tty(self):
        buf = io.StringIO()
        emit.render_report(self.reps[0], emit.make_console(width=80, file=buf), width=80)
        self.assertNotIn("\x1b", buf.getvalue())

    def test_verbose_trace_lists_evidence(self):
        txt = "\n".join(render_lines(self.reps[0], 80, verbose=True))
        self.assertIn("TRACE", txt)
        self.assertIn("script-src", txt)
        self.assertIn("header x-powered-by", txt)

    def test_hostile_page_text_cannot_inject_terminal_escapes(self):
        rep = json.loads(json.dumps(self.reps[0]))
        rep["technologies"][0]["name"] = "Evil\x1b[31mName\x07\x1b]0;pwned\x07"
        rep["technologies"][0]["evidence"][0]["matched"] = "\x1b[2J" + "x" * 10
        rep["target"]["final_url"] = "http://x/\x1b[31m"
        out = "\n".join(render_lines(rep, 80, verbose=True))
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)


class CliBehaviour(unittest.TestCase):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_json_stdout_is_pure_json(self):
        with Site(StaticHandler) as s:
            code, out, err = self.run_cli(["-u", s.url, "--json", "--no-browser", "--no-dns", "--no-cache"])
        doc = json.loads(out)
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", out)
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(len(doc["reports"]), 1)
        self.assertIn("scanning", err)

    def test_no_targets_is_a_usage_error(self):
        code, out, err = self.run_cli([])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")

    def test_unreachable_target_degrades_and_exits_nonzero(self):
        code, out, err = self.run_cli(["-u", "http://127.0.0.1:1/", "--no-browser", "--no-dns", "--width", "80", "-q"])
        self.assertEqual(code, 1)
        self.assertIn("ERROR", out)

    def test_bare_host_falls_back_from_https_to_http(self):
        with Site(StaticHandler) as s:
            rep = scan(f"127.0.0.1:{s.port}", no_browser=True)
        self.assertTrue(rep["target"]["final_url"].startswith("http://"))
        self.assertEqual(rep["target"]["status"], 200)

    def test_slow_target_times_out_gracefully(self):
        class Slow(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                time.sleep(6)
        with Site(Slow) as s:
            t = time.monotonic()
            rep = scan(s.url, no_browser=True, timeout=2)
            dt = time.monotonic() - t
        self.assertLess(dt, 8)
        self.assertIsNone(rep["target"]["status"])
        self.assertTrue(rep["target"]["error"])

    def test_baseline_drift_workflow(self):
        with Site(StaticHandler) as s:
            code, out, _ = self.run_cli(["-u", s.url, "--json", "--no-browser", "--no-dns", "--no-cache", "-q"])
            doc = json.loads(out)
            for d in doc["reports"][0]["technologies"]:
                if d["name"] == "jQuery":
                    d["version"] = "3.7.1"                       # pretend last scan saw a newer jQuery
            doc["reports"][0]["technologies"] = [d for d in doc["reports"][0]["technologies"] if d["name"] != "PHP"]
            path = tempfile.mktemp(suffix=".json")
            with open(path, "w") as f:
                json.dump(doc, f)
            code, out, _ = self.run_cli(["-u", s.url, "--json", "--no-browser", "--no-dns", "--no-cache", "-q", "--baseline", path])
        drift = json.loads(out)["reports"][0]["drift"]
        kinds = {(c["kind"], c["subject"]) for c in drift["changes"]}
        self.assertIn(("changed", "jQuery"), kinds)
        self.assertIn(("added", "PHP"), kinds)
        rep = json.loads(out)["reports"][0]
        txt = "\n".join(render_lines(rep, 80))
        self.assertIn("DRIFT", txt)
        self.assertLessEqual(len(txt.splitlines()), 24)

    def test_db_status_command(self):
        code, out, err = self.run_cli(["db", "status", "--db-dir", tempfile.mkdtemp()])
        self.assertEqual(code, 0)
        self.assertIn("missing (bundled seed is used)", out)


if __name__ == "__main__":
    unittest.main()
