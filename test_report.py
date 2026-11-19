"""The human-readable output: headed sections, one-line explanations, safe text, fits the terminal."""
import io
import unittest
from unittest import mock

import _bootstrap  # noqa: F401
from test_pipeline import DBDIR, Recording, fake_post
from fixtures import Site
from npc_fingerprint.db import store
from npc_fingerprint.render import emit
from npc_fingerprint.scanner import Options, Scanner
from npc_fingerprint.vulns.osv import OsvClient

TITLES = ["Priority actions", "Vulnerabilities (CVE)", "Technology stack", "Security headers", "TLS and protocol", "Active checks", "JavaScript recon",
          "JavaScript libraries and bundles", "Edge and header consistency", "Third parties, cookies and disclosure", "Nuclei: suggested next step"]


def render(rep, width=80, **kw):
    return emit.to_plain(emit.render_report(rep, emit.make_console(width=width, file=io.StringIO()), width=width, **kw))


class Sections(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Recording.seen = []
        with Site(Recording) as s, mock.patch.object(OsvClient, "_post", fake_post):
            sc = Scanner(Options(no_dns=True, no_cache=True, no_browser=True, db_dir=DBDIR), store.load())
            cls.rep = sc.scan(s.url)
            sc.close()
        cls.lines = render(cls.rep)

    def headings(self, lines):
        return [(i, ln[3:].split("  ")[0]) for i, ln in enumerate(lines) if ln.startswith("── ")]

    def test_every_section_has_a_short_heading_and_a_one_line_explanation(self):
        found = self.headings(self.lines)
        self.assertEqual([t for _, t in found], TITLES)
        for i, title in found:
            blurb = self.lines[i + 1].strip()
            self.assertTrue(blurb, title)
            self.assertLessEqual(len(blurb), 76, f"{title}: explanation must stay on one line")
            self.assertTrue(self.lines[i + 2].strip(), f"{title}: a section must contain findings")

    def test_nothing_overflows_the_terminal(self):
        for width in (80, 100, 60):
            self.assertLessEqual(max(len(x) for x in render(self.rep, width=width)), width, width)

    def test_cve_section_is_grouped_by_real_world_risk_with_plain_meanings(self):
        txt = "\n".join(self.lines)
        self.assertLess(txt.index("Exploited in the wild (1)"), txt.index("Likely to be exploited"))
        self.assertIn("Attackers are using these right now", txt)
        self.assertIn("CVE-2020-1927", txt)
        self.assertIn("KEV", txt)
        self.assertIn("nuclei", txt)
        self.assertIn("Apache HTTP Server 2.4.41", txt)

    def test_brief_keeps_only_what_you_act_on(self):
        titles = [t for _, t in self.headings(render(self.rep, brief=True))]
        self.assertEqual(titles, ["Priority actions", "Vulnerabilities (CVE)", "Nuclei: suggested next step"])

    def test_summary_is_just_the_card(self):
        lines = render(self.rep, summary_only=True)
        self.assertEqual(self.headings(lines), [])
        self.assertLessEqual(len(lines), 24)

    def test_ascii_mode_is_pure_ascii_including_the_sections(self):
        lines = render(self.rep, ascii_only=True)
        self.assertTrue(all(ord(c) < 128 for ln in lines for c in ln))
        self.assertIn("-- Priority actions", "\n".join(lines))

    def test_verbose_adds_the_evidence_trace_and_more_findings(self):
        v = render(self.rep, verbose=True)
        self.assertGreater(len(v), len(self.lines))
        self.assertIn("TRACE", "\n".join(v))

    def test_hostile_page_text_cannot_inject_terminal_escapes(self):
        import json
        rep = json.loads(json.dumps(self.rep))
        rep["actions"].insert(0, {"severity": "high", "area": "x", "text": "Evil\x1b[31mtext\x07\x1b]0;pwned\x07"})
        rep["recon"]["comments"] = ["\x1b[2J<script>"]
        rep["vulnerabilities"]["items"][0]["summary"] = "\x1b[31mred"
        rep["nuclei"]["notes"] = ["\x1b]52;c;ZXZpbA==\x07"]
        out = "\n".join(render(rep, verbose=True))
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)

    def test_no_colour_codes_unless_a_terminal(self):
        buf = io.StringIO()
        emit.render_report(self.rep, emit.make_console(width=80, file=buf), width=80, verbose=True)
        self.assertNotIn("\x1b[", buf.getvalue())


class CveTrustFix(unittest.TestCase):
    """The human-readable report is where the reported bug actually showed up (JSON correctness alone doesn't
    help someone reading the terminal output), so this exercises the exact rendering, not just the engine."""

    @classmethod
    def setUpClass(cls):
        import io
        import pathlib
        import tempfile

        from npc_fingerprint import merge
        from npc_fingerprint.vulns import db as vdb_mod, enrich, engine, nvd

        con = vdb_mod.connect(pathlib.Path(tempfile.mkdtemp()), create=True)
        windows_cve = {"cve": {"id": "CVE-2020-9999", "published": "2020-01-01T00:00:00", "vulnStatus": "Analyzed",
                               "descriptions": [{"lang": "en", "value": "RCE in nginx on Windows"}],
                               "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
                               "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
                                   {"vulnerable": True, "criteria": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:windows:*:*"}]}]}]}}
        nvd.ingest(con, io.BytesIO(__import__("json").dumps({"vulnerabilities": [windows_cve]}).encode()), {("nginx", "nginx")})
        enrich.load_nuclei(con, '{"ID":"CVE-2020-9999","Info":{"Name":"nginx Windows RCE","Severity":"critical"},"file_path":"p"}\n', None)
        con.commit()
        vdb = vdb_mod.VulnDB(con)
        techs = [{"name": "Nginx", "version": "1.24.0", "status": "confirmed", "basis": "observed", "evidence": []}]
        res = engine.run(techs, {}, vdb, None, None, {}, {"os": "linux", "confidence": "high", "evidence": "Server banner names a Linux distribution (Ubuntu)"})

        Recording.seen = []
        with Site(Recording) as site:
            sc = Scanner(Options(no_dns=True, no_cache=True, no_browser=True, offline=True), store.load())
            rep = sc.scan(site.url)
            sc.close()
        rep["vulnerabilities"] = res                   # override with our controlled scenario
        rep["actions"] = merge.build_actions(rep)
        rep["summary"] = merge.build_surface(rep)
        cls.lines = render(rep, verbose=True)
        cls.text = "\n".join(cls.lines)

    def test_suppressed_cve_is_shown_with_its_own_heading_and_reason(self):
        self.assertIn("Suppressed: platform mismatch", self.text)
        self.assertIn("CVE-2020-9999", self.text)
        self.assertIn("requires windows", self.text)
        self.assertIn("looks like linux", self.text)

    def test_coverage_breakdown_line_explains_the_nuclei_gap(self):
        self.assertIn("1 CVE(s) matched by version", self.text)
        self.assertIn("suppressed as a platform mismatch", self.text)

    def test_nothing_overflows_at_80_columns(self):
        self.assertLessEqual(max(len(x) for x in self.lines), 80)


if __name__ == "__main__":
    unittest.main()
