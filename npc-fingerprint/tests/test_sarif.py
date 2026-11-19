import unittest

import _bootstrap  # noqa: F401
from npc_fingerprint.render import sarif

REP = {
    "target": {"final_url": "https://shop.example.com/"},
    "vulnerabilities": {"items": [
        {"cve": "CVE-2020-1927", "technology": "Nginx", "version": "1.24.0", "priority": "exploited", "coverage": "testable",
         "why": "exploited in the wild", "fixed": "1.25.3", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-1927"},
        {"cve": "CVE-2020-9999", "technology": "Nginx", "version": "1.24.0", "priority": "suppressed", "coverage": "env_mismatch",
         "why": "platform mismatch", "url": ""}]},
    "security_headers": [{"id": "csp", "title": "CSP", "status": "missing", "severity": "medium", "reason": "absent: no XSS backstop"},
                         {"id": "hsts", "title": "HSTS", "status": "pass", "severity": "info", "reason": "ok"}],
    "tls_findings": [{"id": "cert-expiring", "severity": "low", "reason": "certificate expires in 10 days"}],
    "active": {"checks": [{"id": "cors", "title": "CORS", "status": "weak", "severity": "high", "reason": "reflects any Origin"},
                          {"id": "methods", "title": "HTTP methods", "status": "pass", "severity": "info", "reason": "fine"}]},
    "recon": {"secrets": {"items": [{"type": "Stripe secret key", "severity": "critical", "where": "main.js:12",
                                     "redacted": "sk_l…dc (107)", "note": "full account access"}]}},
}


class Sarif(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = sarif.build(REP)
        cls.results = cls.doc["runs"][0]["results"]
        cls.ids = [r["ruleId"] for r in cls.results]

    def test_valid_minimal_shape(self):
        self.assertEqual(self.doc["version"], "2.1.0")
        self.assertTrue(self.doc["$schema"].endswith("sarif-schema-2.1.0.json"))
        self.assertIn("driver", self.doc["runs"][0]["tool"])

    def test_every_result_rule_is_declared(self):
        declared = {r["id"] for r in self.doc["runs"][0]["tool"]["driver"]["rules"]}
        self.assertTrue(all(rid in declared for rid in self.ids))

    def test_suppressed_cve_never_becomes_a_sarif_alert(self):
        self.assertIn("CVE-2020-1927", self.ids)
        self.assertNotIn("CVE-2020-9999", self.ids)

    def test_passing_checks_are_not_findings(self):
        self.assertNotIn("header-hsts", self.ids)
        self.assertNotIn("active-methods", self.ids)

    def test_severity_maps_to_sarif_level(self):
        levels = {r["ruleId"]: r["level"] for r in self.results}
        self.assertEqual(levels["CVE-2020-1927"], "error")
        self.assertEqual(levels["header-csp"], "warning")
        self.assertEqual(levels["tls-cert-expiring"], "note")
        self.assertEqual(levels["secret-exposed"], "error")

    def test_secret_value_never_appears_in_full(self):
        import json
        blob = json.dumps(self.doc, ensure_ascii=False)
        self.assertNotIn("sk_live", blob)
        self.assertIn("sk_l…dc", blob)

    def test_locations_use_a_url_not_a_local_path(self):
        for r in self.results:
            uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertTrue(uri.startswith(("http://", "https://", "about:")))


if __name__ == "__main__":
    unittest.main()
