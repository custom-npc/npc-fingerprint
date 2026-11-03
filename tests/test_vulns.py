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
from npc_fingerprint.vulns import cvss, db, engine, enrich, nvd
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


if __name__ == "__main__":
    unittest.main()
