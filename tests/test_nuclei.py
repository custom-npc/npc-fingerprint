import pathlib
import subprocess
import unittest
from unittest import mock

import _bootstrap  # noqa: F401
from vuln_fixtures import make_vuln_db
from npc_fingerprint.db import store
from npc_fingerprint.modules import nuclei
from npc_fingerprint.vulns import db

REP = {
    "technologies": [
        {"name": "Apache HTTP Server", "version": "2.4.49", "status": "confirmed", "categories": ["Web servers"]},
        {"name": "WordPress", "version": "6.4", "status": "probable", "categories": ["CMS"]},
        {"name": "Google Analytics", "version": None, "status": "confirmed", "categories": ["Analytics"]},
        {"name": "PHP", "version": None, "status": "implied", "categories": ["Programming languages"]},
        {"name": "Nginx", "version": "1.2", "status": "disputed", "categories": ["Web servers"]},
    ],
    "vulnerabilities": {"items": [
        {"cve": "CVE-2021-41773", "technology": "Apache HTTP Server", "version": "2.4.49", "priority": "exploited", "severity": "high", "nuclei": {"template": "CVE-2021-41773", "severity": "high"}},
        {"cve": "CVE-2020-0001", "technology": "jQuery", "version": "1.1", "priority": "minor", "severity": "low", "nuclei": None}]},
    "recon": {"endpoints": {"graphql": ["/graphql"], "by_kind": {"admin": [{"value": "/swagger/index.html"}]}}},
    "active": {"checks": [{"id": "cors", "status": "weak"}]}, "tls_findings": [],
}


class Suggestions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vdb = db.VulnDB.open(make_vuln_db())
        cls.defs = store.load().techs

    def test_exact_templates_and_validated_tags(self):
        r = nuclei.suggest(REP, self.vdb, self.defs, "https://shop.example.com/")
        self.assertEqual([t["template"] for t in r["by_cve"]], ["CVE-2021-41773"])
        tags = [t["tag"] for t in r["tags"]]
        self.assertIn("apache", tags)
        self.assertIn("graphql", tags)
        self.assertNotIn("nginx", tags)                       # disputed technology is not a basis for a suggestion
        self.assertNotIn("analytics", " ".join(tags))        # analytics/tag managers are not worth scanning
        self.assertNotIn("cors", tags)                        # no such tag in the (fixture) vocabulary: never suggest a tag that matches nothing
        self.assertTrue(r["commands"]["cve_templates"].startswith("nuclei -u https://shop.example.com/ -id CVE-2021-41773"))
        self.assertIn("-rl 20", r["commands"]["technology_tags"])

    def test_without_the_template_index_tags_are_labelled_unverified(self):
        r = nuclei.suggest(REP, db.VulnDB(None), self.defs, "https://x.test/")
        self.assertFalse(r["template_index"])
        self.assertTrue(any("unverified" in n for n in r["notes"]))

    def test_it_never_executes_anything(self):
        src = pathlib.Path(nuclei.__file__).read_text()
        for banned in ("subprocess", "os.system", "Popen", "exec(", "eval("):
            self.assertNotIn(banned, src)
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("executed!")), mock.patch.object(subprocess, "Popen", side_effect=AssertionError("executed!")):
            r = nuclei.suggest(REP, self.vdb, self.defs, "https://x.test/")
        self.assertFalse(r["executed"])
        self.assertIn("never runs Nuclei", r["note"])

    def test_target_is_shell_quoted(self):
        r = nuclei.suggest(REP, self.vdb, self.defs, "https://x.test/?a=1&b=$(id)")
        self.assertIn("'https://x.test/?a=1&b=$(id)'", r["commands"]["cve_templates"])


if __name__ == "__main__":
    unittest.main()
