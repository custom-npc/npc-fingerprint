import gzip
import http.server
import io
import json
import pathlib
import socketserver
import tempfile
import threading
import unittest

import _bootstrap  # noqa: F401
from vuln_fixtures import NVD_ITEMS, make_vuln_db, osv_jquery_vulns
from npc_fingerprint.db import store
from npc_fingerprint.vulns import cvss, db, engine, enrich, nvd, platform as platform_mod
from npc_fingerprint.vulns.osv import OsvClient, OsvError, cve_ids, fixed_and_range


class Cvss(unittest.TestCase):
    def test_known_reference_scores(self):
        cases = {"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1, "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N": 0.0,
                 "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 8.8}
        for v, score in cases.items():
            self.assertEqual(cvss.score_v3(v), score, v)

    def test_v4_and_garbage_are_not_guessed(self):
        self.assertIsNone(cvss.score_v3("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))
        self.assertIsNone(cvss.score_v3("nonsense"))
        self.assertEqual((cvss.severity(9.8), cvss.severity(6.1), cvss.label_to_severity("MODERATE")), ("critical", "medium", "medium"))


class FakeOsv:
    """OSV stand-in: pages jQuery results over two requests; counts hits; can be switched off."""

    def __init__(self):
        self.hits, self.down = 0, False
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                outer.hits += 1
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if outer.down:
                    self.send_response(503); self.send_header("Content-Length", "0"); self.end_headers(); return
                v = osv_jquery_vulns()
                if body["package"]["name"] != "jquery":
                    out = {}
                elif "page_token" not in body:
                    out = {"vulns": [v[0]], "next_page_token": "p2"}
                else:
                    out = {"vulns": [v[1], {"id": "GHSA-old", "withdrawn": "2021-01-01T00:00:00Z"}]}
                b = json.dumps(out).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        self.srv = socketserver.TCPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def close(self):
        self.srv.shutdown(); self.srv.server_close()


class Osv(unittest.TestCase):
    def setUp(self):
        self.fake = FakeOsv()
        self.dir = pathlib.Path(tempfile.mkdtemp())

    def tearDown(self):
        self.fake.close()

    def test_paging_and_cache(self):
        c = OsvClient(self.fake.base, directory=self.dir)
        r = c.query("npm", "jquery", "1.12.4")
        self.assertEqual({cve_ids(v)[0] for v in r if cve_ids(v)}, {"CVE-2020-11022", "CVE-2020-11023"})
        self.assertEqual(self.fake.hits, 2)                       # two pages
        c.query("npm", "jquery", "1.12.4")
        self.assertEqual(self.fake.hits, 2)                       # second call served from the cache
        self.assertEqual(c.stats["cached"], 1)

    def test_stale_cache_survives_an_outage_and_offline_uses_only_the_cache(self):
        c = OsvClient(self.fake.base, directory=self.dir)
        c.query("npm", "jquery", "1.12.4")
        self.fake.down = True
        off = OsvClient(self.fake.base, directory=self.dir, offline=True)
        self.assertTrue(off.query("npm", "jquery", "1.12.4"))
        with self.assertRaises(OsvError):
            off.query("npm", "jquery", "9.9.9")                    # offline and never seen
        broken = OsvClient(self.fake.base, directory=self.dir, use_cache=False)
        with self.assertRaises(OsvError):
            broken.query("npm", "jquery", "1.12.4")                # real outage without a cache is an error, not a crash

    def test_fixed_version_for_the_interval_containing_the_version(self):
        v = osv_jquery_vulns()[0]
        self.assertEqual(fixed_and_range(v, "jquery", "npm", "1.12.4"), ("3.5.0", ">=1.2.0, <3.5.0"))
        self.assertEqual(fixed_and_range(v, "jquery", "npm", "3.5.0")[0], None)
        self.assertEqual(fixed_and_range(v, "jquery", "npm", "1.0.0")[0], None)           # before the introduced event


class Nvd(unittest.TestCase):
    DOC = json.dumps({"format": "NVD_CVE", "vulnerabilities": NVD_ITEMS}, indent=2).encode()

    def test_streaming_parser_at_awkward_chunk_sizes(self):
        for chunk in (7, 64, 4096, 1 << 20):
            self.assertEqual(len(list(nvd.iter_vulnerabilities(io.BytesIO(self.DOC), chunk=chunk))), len(NVD_ITEMS), chunk)

    def test_ingest_keeps_relevant_rows_and_counts_the_rest(self):
        d = make_vuln_db()
        v = db.VulnDB.open(d)
        self.assertEqual(len(v.candidates(["apache"], "http_server")), 3)
        self.assertEqual([u["id"] for u in v.unanalyzed("nginx")], ["CVE-2025-1111"])

    def test_row_matching(self):
        v = db.VulnDB.open(make_vuln_db())
        rows = {r["id"]: r for r in v.candidates(["apache"], "http_server")}
        self.assertTrue(nvd.row_matches(rows["CVE-2020-1927"], "2.4.41")[0])
        self.assertFalse(nvd.row_matches(rows["CVE-2020-1927"], "2.4.42")[0])
        self.assertTrue(nvd.row_matches(rows["CVE-2021-41773"], "2.4.49")[0])
        self.assertFalse(nvd.row_matches(rows["CVE-2021-41773"], "2.4.50")[0])
        self.assertEqual(nvd.row_matches(next(r for r in v.candidates(["php"], "php") if r["vee"] == "7.3.11"), "7.3.10")[1], "7.3.11")

    def test_unbounded_and_prerelease_cpes_are_not_matched(self):
        con = db.connect(pathlib.Path(tempfile.mkdtemp()), create=True)
        items = [{"cve": {"id": "CVE-2024-9999", "published": "2024-05-01T00:00:00", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "x"}],
                          "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"}]}]}]}},
                 {"cve": {"id": "CVE-2019-5555", "published": "2019-01-01T00:00:00", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "x"}],
                          "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:openssl:openssl:1.0.2:beta1:*:*:*:*:*:*"}]}]}]}}]
        st = nvd.ingest(con, io.BytesIO(json.dumps({"vulnerabilities": items}).encode()), nvd.wanted_products({}))
        self.assertEqual((st["kept"], st["unbounded_skipped"]), (0, 1))

    def test_year_update_skips_unchanged_years(self):
        import datetime
        gz = gzip.compress(self.DOC)
        calls = []

        class R(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): pass

        def opener(url, timeout=0):
            calls.append(url)
            return R(b"lastModifiedDate:2026-10-29\nsha256:ABC\n") if url.endswith(".meta") else R(gz)
        con = db.connect(pathlib.Path(tempfile.mkdtemp()), create=True)
        y = datetime.date.today().year
        t1 = nvd.update_feeds(con, nvd.wanted_products({}), y - 1, opener)
        t2 = nvd.update_feeds(con, nvd.wanted_products({}), y - 1, opener)
        self.assertEqual((t1["years"], t2["years"], t2["skipped"]), (2, 0, 2))
        self.assertEqual(sum(1 for c in calls if c.endswith(".json.gz")), 2)


class Enrichment(unittest.TestCase):
    def test_loaders_and_lookups(self):
        v = db.VulnDB.open(make_vuln_db())
        self.assertEqual(v.kev("CVE-2021-41773")["ransomware"], 1)
        self.assertAlmostEqual(v.epss("CVE-2019-11043")["score"], 0.97)
        self.assertEqual(v.exploits("CVE-2019-0211")[0]["ref"], "47688")
        self.assertEqual(v.nuclei("CVE-2021-41773")["severity"], "high")
        self.assertEqual(v.nuclei_tag_counts()["apache"], 143)

    def test_suspiciously_small_feeds_are_refused(self):
        con = db.connect(pathlib.Path(tempfile.mkdtemp()), create=True)
        with self.assertRaises(ValueError):
            enrich.load_kev(con, json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-1"}]}).encode())
        with self.assertRaises(ValueError):
            enrich.load_epss(con, b"cve,epss,percentile\nCVE-2020-1,0.1,0.1\n")

    def test_missing_database_degrades_to_empty_answers(self):
        v = db.VulnDB(None)
        self.assertFalse(v.available)
        self.assertEqual((v.kev("CVE-1"), v.epss("CVE-1"), v.exploits("CVE-1"), v.nuclei_tag_counts(), v.unanalyzed("x")), (None, None, [], {}, []))


TECHS = [
    {"name": "Apache HTTP Server", "version": "2.4.41", "status": "confirmed", "basis": "claimed", "evidence": [{"signal": "header", "location": "server"}]},
    {"name": "jQuery", "version": "1.12.4", "status": "confirmed", "basis": "observed", "evidence": [{"signal": "js-global", "location": "jQuery.fn.jquery"}]},
    {"name": "PHP", "version": "7.3.10", "status": "confirmed", "basis": "claimed", "evidence": [{"signal": "header", "location": "x-powered-by"}]},
    {"name": "nginx", "version": "1.26.0", "status": "probable", "basis": "claimed", "evidence": [{"signal": "header", "location": "x-served-by"}]},
    {"name": "Cloudflare", "version": None, "status": "confirmed", "basis": "observed", "evidence": []},
    {"name": "Weird CMS", "version": "3.1.4", "status": "confirmed", "basis": "observed", "evidence": []},
    {"name": "Disputed Thing", "version": "9.9.9", "status": "disputed", "basis": "claimed", "evidence": []},
    {"name": "Nginx2", "version": "1", "status": "confirmed", "basis": "observed", "evidence": []},
]


class Engine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake = FakeOsv()
        cls.vdb = db.VulnDB.open(make_vuln_db())
        cls.defs = store.load().techs
        cls.osv = OsvClient(cls.fake.base, directory=pathlib.Path(tempfile.mkdtemp()))
        cls.res = engine.run(TECHS, cls.defs, cls.vdb, cls.osv, None, {"server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.3.10"})

    @classmethod
    def tearDownClass(cls):
        cls.fake.close()

    def by_cve(self, cve):
        return next((i for i in self.res["items"] if i["cve"] == cve), None)

    def test_priority_tiers_and_ordering(self):
        r = self.res
        self.assertEqual(r["items"][0]["cve"], "CVE-2020-1927")                       # KEV-listed first
        self.assertEqual(self.by_cve("CVE-2020-1927")["priority"], "exploited")
        self.assertEqual(self.by_cve("CVE-2019-11043")["priority"], "likely")         # EPSS 0.97
        self.assertEqual(self.by_cve("CVE-2020-11022")["priority"], "likely")         # EPSS 0.31
        self.assertEqual(self.by_cve("CVE-2020-11023")["priority"], "minor")          # medium CVSS, EPSS 0.04
        order = [engine.TIERS.index(i["priority"]) for i in r["items"]]
        self.assertEqual(order, sorted(order))

    def test_version_ranges_are_respected(self):
        self.assertIsNone(self.by_cve("CVE-2021-41773"))                              # 2.4.41 is not 2.4.49
        self.assertIsNone(self.by_cve("CVE-2019-0211"))                               # outside 2.4.17..2.4.38
        self.assertEqual(self.by_cve("CVE-2019-11043")["fixed"], "7.3.11")

    def test_framework_versions_come_from_osv_with_fixed_release(self):
        j = self.by_cve("CVE-2020-11022")
        self.assertEqual((j["sources"], j["fixed"], j["cvss"]), (["osv"], "3.5.0", 6.1))
        self.assertEqual(self.res["sources"]["osv"]["queries"], 2)                    # paged, withdrawn record dropped

    def test_enrichment_attached(self):
        a = self.by_cve("CVE-2020-1927")
        self.assertEqual((a["kev"]["added"], a["nuclei"]["template"]), ("2022-05-01", "CVE-2020-1927"))
        self.assertIn("exploited in the wild", a["why"])

    def test_honest_caveats_and_confidence(self):
        a = self.by_cve("CVE-2020-1927")
        self.assertTrue(any("distribution" in c for c in a["caveats"]))               # Ubuntu banner: backports possible
        self.assertEqual(a["confidence"], "medium")
        self.assertEqual(self.by_cve("CVE-2020-11022")["confidence"], "high")         # observed at runtime, no caveats

    def test_coverage_report(self):
        r = self.res
        self.assertIn("Cloudflare", r["no_version"])
        self.assertIn("Weird CMS", r["no_source"])
        self.assertFalse(any(i["technology"] == "Disputed Thing" for i in r["items"]))
        self.assertEqual(r["nvd_gaps"][0]["technology"], "nginx")
        self.assertEqual(r["status"], "ok")

    def test_imprecise_version_is_flagged_low_confidence_or_skipped(self):
        res = engine.run([{"name": "Apache HTTP Server", "version": "2.4", "status": "confirmed", "basis": "observed", "evidence": []}], self.defs, self.vdb, self.osv, None, {})
        self.assertTrue(all(i["confidence"] == "low" for i in res["items"]))

    def test_retire_fallback_and_missing_database(self):
        libs = {"libraries": [{"library": "jquery", "version": "1.12.4", "advisories": [{"severity": "medium", "ids": ["CVE-2020-11022"], "summary": "XSS", "range": ">=1.2.0 <3.5.0", "info": []}]}]}
        res = engine.run([], self.defs, db.VulnDB(None), None, libs, {})
        it = res["items"][0]
        self.assertEqual((it["cve"], it["sources"], it["fixed"], res["status"]), ("CVE-2020-11022", ["retire.js"], "3.5.0", "partial"))
        self.assertIn("not installed", it["why"])


class Platform(unittest.TestCase):
    """The direct fix for the reported zapvi.in contradiction: a Windows-only CVE matched by version on a
    Linux-hosted target must not be reported as exploitable, and the report must say exactly why."""

    @classmethod
    def setUpClass(cls):
        import io
        con = db.connect(pathlib.Path(tempfile.mkdtemp()), create=True)
        windows_only = {"cve": {"id": "CVE-2020-9999", "published": "2020-01-01T00:00:00", "vulnStatus": "Analyzed",
                                "descriptions": [{"lang": "en", "value": "RCE in nginx on Windows"}],
                                "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
                                "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
                                    {"vulnerable": True, "criteria": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:windows:*:*"}]}]}]}}
        cross_platform = {"cve": {"id": "CVE-2021-8888", "published": "2021-01-01T00:00:00", "vulnStatus": "Analyzed",
                                  "descriptions": [{"lang": "en", "value": "XSS in nginx"}],
                                  "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 6.1, "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}}]},
                                  "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
                                      {"vulnerable": True, "criteria": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"}]}]}]}}
        no_template = {"cve": {"id": "CVE-2022-7777", "published": "2022-01-01T00:00:00", "vulnStatus": "Analyzed",
                               "descriptions": [{"lang": "en", "value": "info leak in nginx"}],
                               "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 5.3, "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}}]},
                               "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
                                   {"vulnerable": True, "criteria": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"}]}]}]}}
        nvd.ingest(con, io.BytesIO(json.dumps({"vulnerabilities": [windows_only, cross_platform, no_template]}).encode()),
                  {("nginx", "nginx")})
        enrich.load_nuclei(con, '{"ID":"CVE-2021-8888","Info":{"Name":"nginx XSS","Severity":"medium"},"file_path":"p"}\n'
                                '{"ID":"CVE-2020-9999","Info":{"Name":"nginx Windows RCE","Severity":"critical"},"file_path":"p2"}\n', None)
        con.execute("INSERT OR REPLACE INTO meta VALUES ('updated_at','2026-10-30T00:00:00Z')")
        con.commit()
        cls.vdb = db.VulnDB(con)
        cls.defs = {}
        cls.TECHS = [{"name": "Nginx", "version": "1.24.0", "status": "confirmed", "basis": "observed", "evidence": []}]

    def run_with_platform(self, platform_info):
        return engine.run(self.TECHS, self.defs, self.vdb, None, None, {}, platform_info)

    def by(self, res, cve):
        return next(i for i in res["items"] if i["cve"] == cve)

    def test_windows_only_cve_is_suppressed_on_a_detected_linux_target(self):
        res = self.run_with_platform({"os": "linux", "confidence": "high", "evidence": "Server banner names a Linux distribution (Ubuntu)"})
        w = self.by(res, "CVE-2020-9999")
        self.assertEqual((w["priority"], w["coverage"], w["state"]), ("suppressed", "env_mismatch", "suppressed"))
        self.assertIn("windows", w["why"])
        self.assertIn("linux", w["why"])
        self.assertTrue(any("platform mismatch" in s for s in w["confidence_signals"]))
        self.assertEqual(res["by_priority"]["suppressed"], 1)
        self.assertEqual(res["by_coverage"]["env_mismatch"], 1)

    def test_the_same_cve_is_not_suppressed_when_the_platform_actually_matches(self):
        res = self.run_with_platform({"os": "windows", "confidence": "high", "evidence": "Server banner names Windows"})
        w = self.by(res, "CVE-2020-9999")
        self.assertNotEqual(w["priority"], "suppressed")
        self.assertEqual(w["coverage"], "testable")                   # now the platform matches AND a template exists

    def test_unknown_platform_never_suppresses_only_adds_a_caveat(self):
        res = self.run_with_platform({"os": "unknown", "confidence": None, "evidence": "no signal"})
        w = self.by(res, "CVE-2020-9999")
        self.assertNotEqual(w["priority"], "suppressed")
        self.assertTrue(any("could not be determined" in s for s in w["confidence_signals"]))

    def test_unconstrained_cve_is_testable_when_a_template_exists(self):
        res = self.run_with_platform({"os": "linux", "confidence": "high", "evidence": "x"})
        x = self.by(res, "CVE-2021-8888")
        self.assertEqual((x["coverage"], x["platform_required"]), ("testable", None))
        self.assertIn(x["state"], ("confirmed", "lead"))

    def test_matched_cve_with_no_nuclei_template_is_labelled_so_not_silently_dropped(self):
        res = self.run_with_platform({"os": "linux", "confidence": "high", "evidence": "x"})
        n = self.by(res, "CVE-2022-7777")
        self.assertEqual(n["coverage"], "no_template")
        self.assertNotEqual(n["priority"], "suppressed")               # a real finding, just nothing to auto-verify with

    def test_nuclei_suggestions_only_come_from_the_testable_bucket(self):
        # This is the exact shape of the reported bug: CVE-2020-9999 has a real Nuclei template AND is a critical
        # version match, but on a Linux target it is a platform mismatch and must still never be suggested.
        from npc_fingerprint.modules import nuclei as nuclei_mod
        res = self.run_with_platform({"os": "linux", "confidence": "high", "evidence": "Server banner names a Linux distribution"})
        self.assertEqual(self.by(res, "CVE-2020-9999")["coverage"], "env_mismatch")
        rep = {"technologies": [], "vulnerabilities": res, "recon": {}, "active": {"checks": []}, "tls_findings": []}
        sug = nuclei_mod.suggest(rep, self.vdb, self.defs, "https://x.test/")
        templates = {t["cve"] for t in sug["by_cve"]}
        self.assertEqual(templates, {"CVE-2021-8888"})
        self.assertNotIn("CVE-2020-9999", templates)                   # a template exists, but it is suppressed: never suggested
        self.assertNotIn("CVE-2022-7777", templates)                   # no template exists: nothing to suggest
        self.assertEqual(sug["skipped"], {"no_template": 1, "env_mismatch": 1})
        self.assertTrue(any("CVE-2022-7777" in n for n in sug["notes"]))
        self.assertTrue(any("CVE-2020-9999" in n and "platform mismatch" in n for n in sug["notes"]))


class PlatformDetect(unittest.TestCase):
    def test_iis_and_windows_banners(self):
        self.assertEqual(platform_mod.detect("Microsoft-IIS/10.0", None, [], set())["os"], "windows")
        self.assertEqual(platform_mod.detect("nginx/1.24.0 Win64", None, [], set())["os"], "windows")

    def test_linux_distro_banner_is_high_confidence(self):
        d = platform_mod.detect("Apache/2.4.41 (Ubuntu)", None, [], set())
        self.assertEqual((d["os"], d["confidence"]), ("linux", "high"))

    def test_linux_hosting_edge_is_medium_confidence(self):
        d = platform_mod.detect(None, None, ["Vercel Edge"], set())
        self.assertEqual((d["os"], d["confidence"]), ("linux", "medium"))

    def test_no_signal_is_unknown_and_never_guessed(self):
        d = platform_mod.detect(None, None, [], set())
        self.assertEqual((d["os"], d["confidence"]), ("unknown", None))

    def test_mismatch_requires_both_a_constraint_and_confidence(self):
        self.assertTrue(platform_mod.mismatch("windows", {"os": "linux", "confidence": "high", "evidence": ""}))
        self.assertFalse(platform_mod.mismatch(None, {"os": "linux", "confidence": "high", "evidence": ""}))
        self.assertFalse(platform_mod.mismatch("windows", {"os": "unknown", "confidence": None, "evidence": ""}))


if __name__ == "__main__":
    unittest.main()
