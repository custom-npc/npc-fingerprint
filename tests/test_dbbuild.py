import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401
from npc_fingerprint.db import store, update as upd

NUCLEI = """
id: favicon-detection
info:
  name: Favicon Detection
http:
  - method: GET
    path:
      - "{{BaseURL}}/favicon.ico"
    matchers:
      - type: dsl
        name: qnap-turbo-nas
        dsl:
          - "status_code==200 && (\\"1038982136\\" == mmh3(base64_py(body)))"
      - type: dsl
        name: example-md5-product
        dsl:
          - "status_code==200 && (\\"0123456789abcdef0123456789abcdef\\" == md5(body))"
"""

OWASP = """
- algorithm: MD5
  hash: dcea02a5797ce9e36f19b7590752563e
  name: Parallels Plesk
  source: owasp_wiki
- algorithm: MD5
  hash: d41d8cd98f00b204e9800998ecf8427e
  name: Zero byte favicon
  source: owasp_wiki
"""


def make_tarball() -> tuple[bytes, str]:
    """A webappanalyzer-shaped repo, archived with `git archive` exactly like GitHub does."""
    tmp = tempfile.mkdtemp()
    git = lambda *a: subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a], cwd=tmp, check=True, capture_output=True, text=True).stdout.strip()  # noqa: E731
    git("init", "-q")
    tech = Path(tmp, "src", "technologies")
    tech.mkdir(parents=True)
    for letter, n in (("a", 300), ("b", 300), ("_", 5)):
        tech.joinpath(f"{letter}.json").write_text(json.dumps({f"{letter.upper()}Tech{i}": {"cats": [1], "icon": "x.svg", "description": "d", "headers": {"X-A": f"v{i}"}} for i in range(n)}))
    Path(tmp, "src", "categories.json").write_text(json.dumps({"1": {"name": "CMS", "groups": [1], "priority": 1}}))
    git("add", "-A")
    git("commit", "-q", "-m", "x")
    sha = git("rev-parse", "HEAD")
    out = os.path.join(tmp, "out.tar.gz")
    git("archive", "--format=tar.gz", "--prefix=webappanalyzer-main/", "-o", out, "HEAD")
    return Path(out).read_bytes(), sha


class Build(unittest.TestCase):
    def test_enthec_tarball_parsing_and_commit_pin(self):
        raw, sha = make_tarball()
        techs, cats, commit = upd.parse_enthec_tar(raw)
        self.assertEqual(len(techs), 605)
        self.assertNotIn("icon", techs["ATech0"])             # compacted
        self.assertEqual(cats["1"]["name"], "CMS")
        self.assertEqual(commit, sha)                          # GitHub-style archives carry the commit in a pax header

    def test_tiny_archive_is_rejected(self):
        import io, tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = b"{}"
            ti = tarfile.TarInfo("x/src/technologies/a.json")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        with self.assertRaises(upd.DBBuildError):
            upd.parse_enthec_tar(buf.getvalue())

    def test_favicon_sources(self):
        n = upd.parse_nuclei_favicons(NUCLEI)
        self.assertEqual(n["mmh3"]["1038982136"], [["qnap-turbo-nas", "nuclei"]])
        self.assertIn("0123456789abcdef0123456789abcdef", n["md5"])
        md5, ignore = upd.parse_owasp_favicons(OWASP)
        self.assertEqual(md5["dcea02a5797ce9e36f19b7590752563e"][0][0], "Parallels Plesk")
        self.assertEqual(ignore, ["d41d8cd98f00b204e9800998ecf8427e"])      # sentinel entries never become detections

    def test_full_update_with_fake_network_then_load(self):
        raw, sha = make_tarball()
        retire = json.dumps({"jquery": {"vulnerabilities": [], "extractors": {}}}).encode()
        urls = {upd.SOURCES["enthec"]: raw, upd.SOURCES["nuclei"]: NUCLEI.encode(), upd.SOURCES["owasp"]: OWASP.encode(), upd.SOURCES["retire"]: retire}
        logs = []
        d = tempfile.mkdtemp()
        rc = upd.update(d, only={"enthec", "favicons", "retire"}, log=logs.append, fetcher=lambda u, t: urls[u])
        self.assertEqual(rc, 0, logs)
        db = store.load(d)
        self.assertFalse(db.seed)
        self.assertEqual(len(db.techs), 605)
        self.assertEqual(db.meta["technologies"]["commit"], sha)
        self.assertIn("1038982136", db.favicons["mmh3"])
        self.assertIn("d41d8cd98f00b204e9800998ecf8427e", db.favicons["ignore"]["md5"])
        self.assertIn("jquery", db.retire)
        self.assertIn("technologies.json", upd.status(d))

    def test_partial_failure_keeps_other_sources_and_reports_nonzero(self):
        raw, _ = make_tarball()

        def fetcher(u, t):
            if u == upd.SOURCES["retire"]:
                raise OSError("offline")
            return {upd.SOURCES["enthec"]: raw, upd.SOURCES["nuclei"]: NUCLEI.encode(), upd.SOURCES["owasp"]: OWASP.encode()}[u]
        d = tempfile.mkdtemp()
        self.assertEqual(upd.update(d, only={"enthec", "favicons", "retire"}, log=lambda m: None, fetcher=fetcher), 1)
        self.assertTrue(Path(d, "technologies.json").exists())
        self.assertFalse(Path(d, "retire.json").exists())

    def test_from_tar_for_air_gapped_use(self):
        raw, _ = make_tarball()
        tarfile_path = os.path.join(tempfile.mkdtemp(), "w.tar.gz")
        Path(tarfile_path).write_bytes(raw)
        d = tempfile.mkdtemp()
        rc = upd.update(d, only={"enthec"}, from_tar=tarfile_path, log=lambda m: None, fetcher=lambda u, t: (_ for _ in ()).throw(AssertionError("no network expected")))
        self.assertEqual(rc, 0)


class VulnData(unittest.TestCase):
    def test_nvd_and_enrichment_update_end_to_end_with_a_fake_network(self):
        import datetime
        import gzip
        import io
        from vuln_fixtures import NVD_ITEMS
        from npc_fingerprint.render.live import Progress
        from npc_fingerprint.vulns import db as vdb_mod, enrich as enr
        doc = gzip.compress(json.dumps({"vulnerabilities": NVD_ITEMS}).encode())

        class R(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): pass

        def opener(url, timeout=0):
            return R(b"lastModifiedDate:2026-10-29\nsha256:ABC\n") if url.endswith(".meta") else R(doc)
        kev = {"vulnerabilities": [{"cveID": f"CVE-2021-{i:05d}", "dateAdded": "2021-11-03", "dueDate": "2021-11-17", "knownRansomwareCampaignUse": "Unknown",
                                    "vulnerabilityName": "x", "requiredAction": "y"} for i in range(150)]}
        epss = "cve,epss,percentile\n" + "\n".join(f"CVE-2020-{i:05d},0.01,0.1" for i in range(1500))
        edb = "id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes\n1,x,y,2020,a,webapps,php,,,,0,CVE-2020-1927\n"
        files = {enr.SOURCES["kev"]: json.dumps(kev).encode(), enr.SOURCES["epss"]: gzip.compress(epss.encode()), enr.SOURCES["exploitdb"]: edb.encode(),
                 enr.SOURCES["nuclei_cves"]: b'{"ID":"CVE-2020-1927","Info":{"Name":"n","Severity":"medium"},"file_path":"p"}\n',
                 enr.SOURCES["nuclei_stats"]: json.dumps({"tags": [{"name": "apache", "count": 5}]}).encode()}
        d = tempfile.mkdtemp()
        events = []
        pr = Progress([("nvd", "NVD"), ("enrich", "Enrich")], "t", on_done=lambda k, st, det, el: events.append((k, st)))
        rc = upd.update(d, only={"nvd", "enrich"}, log=lambda m: None, fetcher=lambda u, t: files[u], since=datetime.date.today().year - 1, progress=pr, nvd_opener=opener)
        self.assertEqual(rc, 0)
        self.assertEqual(events, [("nvd", "ok"), ("enrich", "ok")])
        v = vdb_mod.VulnDB.open(d)
        self.assertEqual(v.meta()["kev_count"], "150")
        self.assertEqual(len(v.candidates(["apache"], "http_server")), 3)
        self.assertEqual(v.nuclei("CVE-2020-1927")["severity"], "medium")
        self.assertEqual(v.exploits("CVE-2020-1927")[0]["source"], "exploit-db")
        self.assertIn("vulns.sqlite", upd.status(d))

    def test_a_failing_enrichment_source_does_not_lose_the_others(self):
        import gzip
        from npc_fingerprint.vulns import db as vdb_mod, enrich as enr
        kev = {"vulnerabilities": [{"cveID": f"CVE-2021-{i:05d}", "dateAdded": "a", "dueDate": "b", "knownRansomwareCampaignUse": "Unknown", "vulnerabilityName": "x", "requiredAction": "y"} for i in range(150)]}

        def fetcher(url, timeout):
            if url == enr.SOURCES["kev"]:
                return json.dumps(kev).encode()
            raise OSError("offline")
        d = tempfile.mkdtemp()
        rc = upd.update(d, only={"enrich"}, log=lambda m: None, fetcher=fetcher)
        self.assertEqual(rc, 1)
        self.assertEqual(vdb_mod.VulnDB.open(d).meta()["kev_count"], "150")


if __name__ == "__main__":
    unittest.main()
