"""One clean command: flags, setup (no root), installer, packaging metadata, live output wiring."""
import contextlib
import io
import json
import pathlib
import subprocess
import tempfile
import tomllib
import unittest
from unittest import mock

import _bootstrap  # noqa: F401
from test_pipeline import DBDIR, Recording, fake_post
from fixtures import Site
from rich.console import Console
from npc_fingerprint import __version__, cli
from npc_fingerprint.db import update as upd
from npc_fingerprint.fetch import browser as browser_mod
from npc_fingerprint.render import live
from npc_fingerprint.vulns.osv import OsvClient

ROOT = pathlib.Path(__file__).resolve().parent.parent


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class Scanning(unittest.TestCase):
    def test_json_is_pure_and_carries_every_feature(self):
        Recording.seen = []
        with Site(Recording) as s, mock.patch.object(OsvClient, "_post", fake_post):
            code, out, err = run(["-u", s.url, "--json", "--no-browser", "--no-dns", "--no-cache", "--db-dir", DBDIR])
        doc = json.loads(out)
        self.assertEqual((code, doc["schema_version"], doc["schema_minor"]), (0, 1, 1))
        self.assertNotIn("\x1b", out + err)
        rep = doc["reports"][0]
        self.assertGreater(rep["vulnerabilities"]["total"], 0)
        self.assertTrue(rep["actions"])
        self.assertIn("scanning", err)

    def test_one_command_covers_the_whole_workflow_in_the_terminal(self):
        Recording.seen = []
        with Site(Recording) as s, mock.patch.object(OsvClient, "_post", fake_post):
            code, out, err = run(["-u", s.url, "--no-browser", "--no-dns", "--no-cache", "--db-dir", DBDIR, "--width", "80"])
        for needle in ("Priority actions", "Vulnerabilities (CVE)", "Active checks", "JavaScript recon", "Nuclei: suggested next step", "nuclei -u "):
            self.assertIn(needle, out)
        self.assertEqual(code, 0)

    def test_bad_skip_and_only_values_are_usage_errors(self):
        self.assertEqual(run(["-u", "x.test", "--skip", "bogus"])[0], 2)
        self.assertEqual(run(["db", "update", "--only", "bogus"])[0], 2)
        self.assertEqual(run([])[0], 2)

    def test_skip_flag_is_honoured(self):
        with Site(Recording) as s:
            code, out, err = run(["-u", s.url, "--json", "--no-browser", "--no-dns", "--no-cache", "--db-dir", DBDIR, "--skip", "vulns,recon,active,nuclei"])
        rep = json.loads(out)["reports"][0]
        self.assertIsNone(rep["vulnerabilities"])
        self.assertTrue(rep["recon"]["skipped"])

    def test_live_view_goes_to_stderr_only_and_report_to_stdout(self):
        err_buf = io.StringIO()
        fake_err = Console(file=err_buf, force_terminal=True, width=80, color_system="truecolor")
        Recording.seen = []
        with Site(Recording) as s, mock.patch.object(OsvClient, "_post", fake_post), mock.patch.object(live, "make_err_console", return_value=fake_err):
            code, out, err = run(["-u", s.url, "--no-browser", "--no-dns", "--no-cache", "--db-dir", DBDIR, "--width", "80"])
        self.assertEqual(code, 0)
        self.assertIn("\x1b[", err_buf.getvalue())                       # animation frames were drawn on the (pseudo-)terminal
        self.assertNotIn("\x1b[", out)                                   # the report on stdout stays clean
        self.assertIn("Priority actions", out)

    def test_quiet_and_no_live_print_plain_lines_not_animation(self):
        with Site(Recording) as s:
            code, out, err = run(["-u", s.url, "--no-browser", "--no-dns", "--no-cache", "--db-dir", DBDIR, "--no-live", "--width", "80"])
            code_q, _, err_q = run(["-u", s.url, "--no-browser", "--no-dns", "--no-cache", "--db-dir", DBDIR, "-q", "--width", "80"])
        self.assertIn("tls", err)
        self.assertNotIn("\x1b", err)
        self.assertEqual(err_q, "")


class LiveWithBrowser(unittest.TestCase):
    @unittest.skipUnless(browser_mod.HAVE_PLAYWRIGHT and __import__("test_e2e").HAVE_BROWSER, "Chromium not available")
    def test_animation_and_the_browser_coexist(self):
        from fixtures import SpaHandler
        err_buf = io.StringIO()
        fake_err = Console(file=err_buf, force_terminal=True, width=80, color_system="truecolor")
        with Site(SpaHandler, tls=True) as s, mock.patch.object(live, "make_err_console", return_value=fake_err):
            code, out, err = run(["-u", s.url, "--no-dns", "--no-cache", "--db-dir", DBDIR, "--offline", "--width", "80", "--brief"])
        self.assertEqual(code, 0)
        self.assertIn("\x1b[", err_buf.getvalue())
        self.assertNotIn("\x1b[", out)
        self.assertIn("Priority actions", out)


class Setup(unittest.TestCase):
    def test_check_reports_without_changing_anything(self):
        code, out, err = run(["setup", "--check", "--db-dir", tempfile.mkdtemp()])
        self.assertEqual(code, 0)
        for label in ("Python", "Chromium", "Fingerprints", "CVE + exploit data", "Nuclei"):
            self.assertIn(label, out)

    def test_setup_runs_browser_then_data_at_user_level(self):
        calls = {}
        with mock.patch.object(cli, "ensure_browser", return_value=(True, "fake-chromium")) as eb, \
                mock.patch.object(upd, "update", side_effect=lambda *a, **k: calls.update(args=a, kw=k) or 0):
            code, _, err = run(["setup", "--no-live", "--db-dir", "/tmp/x"])
        self.assertEqual(code, 0)
        eb.assert_called_once()
        self.assertIsNotNone(calls["kw"]["progress"])
        self.assertEqual(calls["kw"]["since"], 2010)
        self.assertIn("Setup complete", err)

    def test_setup_flags_skip_steps(self):
        with mock.patch.object(cli, "ensure_browser") as eb, mock.patch.object(upd, "update", return_value=0) as u:
            run(["setup", "--no-live", "--no-browser", "--no-data"])
        eb.assert_not_called()
        u.assert_not_called()

    def test_browser_install_is_user_level_and_never_escalates(self):
        seq = {"n": 0}
        calls = []

        def fake_start(self):
            seq["n"] += 1
            if seq["n"] == 1:
                raise browser_mod.BrowserUnavailable("no chromium")
            self.browser_path = "playwright-chromium"

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        with mock.patch.object(browser_mod.BrowserSession, "start", fake_start), mock.patch.object(browser_mod.BrowserSession, "close", lambda self: None), \
                mock.patch.object(subprocess, "run", fake_run):
            ok, detail = cli.ensure_browser()
        self.assertTrue(ok)
        self.assertEqual(calls[0][1:], ["-m", "playwright", "install", "chromium"])
        self.assertFalse(any("sudo" in " ".join(c) or "install-deps" in " ".join(c) for c in calls))

    def test_missing_system_libraries_degrade_to_static_with_an_honest_hint(self):
        def always_fail(self):
            raise browser_mod.BrowserUnavailable("missing libnss3")
        with mock.patch.object(browser_mod.BrowserSession, "start", always_fail), mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "boom")) as sp:
            ok, detail = cli.ensure_browser()
        self.assertFalse(ok)
        self.assertIn("--no-browser", detail)
        self.assertNotIn("sudo", " ".join(" ".join(c.args[0]) for c in sp.call_args_list))      # never runs anything privileged

    def test_system_chromium_is_used_without_any_download(self):
        with mock.patch.dict("os.environ", {"NPC_CHROMIUM": "/opt/custom/chromium"}):
            self.assertEqual(browser_mod.BrowserSession.system_browsers()[0], "/opt/custom/chromium")


class Packaging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.py = tomllib.loads((ROOT / "pyproject.toml").read_text())

    def test_version_commands_and_python(self):
        p = self.py["project"]
        self.assertEqual(p["version"], __version__)
        self.assertEqual(set(p["scripts"]), {"npc-fingerprint", "npcf"})
        self.assertTrue(p["requires-python"].startswith(">=3.11"))
        self.assertIn("GPL-3.0-or-later", p["license"]["text"])

    def test_dependencies_float_to_the_latest_and_are_all_free(self):
        for dep in self.py["project"]["dependencies"]:
            spec = dep.split("#")[0]
            self.assertIn(">=", spec, dep)
            self.assertNotIn("<", spec)                      # no upper bounds: new installs resolve the newest releases
            self.assertNotIn("==", spec)
        names = {d.split(">=")[0] for d in self.py["project"]["dependencies"]}
        self.assertEqual(names, {"playwright", "niquests", "regex", "mmh3", "cryptography", "rich", "dnspython", "pyyaml"})

    def test_installer_is_user_level(self):
        script = (ROOT / "install.sh").read_text()
        code = [ln for ln in script.splitlines() if not ln.lstrip().startswith("#")]
        self.assertFalse(any("sudo " in ln for ln in code))
        self.assertEqual(subprocess.run(["sh", "-n", str(ROOT / "install.sh")]).returncode, 0)
        r = subprocess.run(["sh", str(ROOT / "install.sh"), "--dry-run", "--no-setup"], capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "HOME": tempfile.mkdtemp()})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(any(k in r.stdout for k in ("pipx install", "uv tool install", "-m venv")))

    def test_repo_hygiene_files_exist(self):
        for f in ("README.md", "LICENSE", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "install.sh", "Makefile", ".editorconfig", ".gitignore",
                  ".github/workflows/ci.yml", ".github/dependabot.yml", "docs/RESEARCH.md"):
            self.assertTrue((ROOT / f).exists(), f)


if __name__ == "__main__":
    unittest.main()
