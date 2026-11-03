import io
import os
import time
import unittest

import _bootstrap  # noqa: F401
from fixtures import Site, SpaHandler
from rich.console import Console
from npc_fingerprint.db import store
from npc_fingerprint.render import live
from npc_fingerprint.render.theme import asciify
from npc_fingerprint.scanner import Options, Scanner


def sample_progress():
    p = live.Progress(title="https://shop.example.com/")
    p.done("load", "200 · 41 requests")
    p.done("tls", "1.3 · h2 · Let's Encrypt R11")
    p.done("headers", "2/6 present", "warn")
    p.skip("active", "passive mode")
    p.start("tech", "Matching 7,641 technology signatures…")
    return p


class LiveView(unittest.TestCase):
    def test_every_frame_fits_80_columns_and_a_24_row_terminal(self):
        v = live.LiveView(sample_progress())
        for ascii_only in (False, True):
            v.ascii = ascii_only
            for now in (100.0, 100.2, 100.9, 101.7):
                lines = v.lines(80, now)
                self.assertLessEqual(len(lines), 16)
                self.assertTrue(all(sum(len(t) for t, _ in ln) <= 80 for ln in lines))
            if ascii_only:
                self.assertTrue(all(ord(c) < 128 for ln in v.lines(80, 100.0) for t, _ in ln for c in asciify(t)))

    def test_the_animation_actually_moves(self):
        v = live.LiveView(sample_progress())
        self.assertNotEqual(v.lines(80, 100.0)[1], v.lines(80, 100.4)[1])                      # comet position/colours
        spin = lambda now: v.lines(80, now)[[i for i, ln in enumerate(v.lines(80, now)) if "Fingerprint" in "".join(t for t, _ in ln)][0]][1]  # noqa: E731
        self.assertNotEqual(spin(100.0), spin(100.08))                                            # spinner frame

    def test_states_are_shown_with_glyphs_and_text(self):
        txt = "\n".join("".join(t for t, _ in ln) for ln in live.LiveView(sample_progress()).lines(80, 100.0))
        for expect in ("Load and render the page", "200 · 41 requests", "2/6 present", "passive mode", "Matching 7,641"):
            self.assertIn(expect, txt)

    def test_cost_is_a_small_fraction_of_one_core(self):
        buf = io.StringIO()
        con = Console(file=buf, force_terminal=True, width=80, color_system="truecolor")
        c0, w0 = time.process_time(), time.monotonic()
        with live.live_display(sample_progress(), con):
            time.sleep(1.5)
        cpu, wall = time.process_time() - c0, time.monotonic() - w0
        print(f"\n   [perf] live view: {cpu * 1000:.0f} ms CPU over {wall:.1f}s = {cpu / wall * 100:.1f}% of one core")
        self.assertLess(cpu / wall, 0.10)
        self.assertGreater(len(buf.getvalue()), 500)                                            # it really drew frames

    def test_live_is_only_used_on_a_real_terminal_and_never_for_json(self):
        term = Console(file=io.StringIO(), force_terminal=True, width=80)
        pipe = Console(file=io.StringIO(), width=80)
        self.assertTrue(live.live_allowed(term, False, False, False))
        self.assertFalse(live.live_allowed(pipe, False, False, False))
        self.assertFalse(live.live_allowed(term, True, False, False))     # --no-live
        self.assertFalse(live.live_allowed(term, False, True, False))     # --quiet
        self.assertFalse(live.live_allowed(term, False, False, True))     # --json
        os.environ["NPC_NO_ANIM"] = "1"
        try:
            self.assertFalse(live.live_allowed(term, False, False, False))   # reduced motion
        finally:
            del os.environ["NPC_NO_ANIM"]

    def test_plain_reporter_writes_one_line_per_step(self):
        out = io.StringIO()
        pr = live.PlainReporter(out)
        p = live.Progress(on_done=pr.on_done)
        p.start("tls")
        p.done("tls", "1.3 h2")
        self.assertEqual(out.getvalue().count("\n"), 1)
        self.assertIn("tls", out.getvalue())
        q = io.StringIO()
        live.PlainReporter(q, quiet=True).on_done("tls", "ok", "x", 0.1)
        self.assertEqual(q.getvalue(), "")


class ScannerReporting(unittest.TestCase):
    def test_every_stage_reports_exactly_once_in_order(self):
        events = []
        with Site(SpaHandler, tls=True) as s:
            sc = Scanner(Options(no_dns=True, no_cache=True, no_browser=True, offline=True), store.load())
            p = live.Progress(title=s.url, on_done=lambda k, st, d, e: events.append((k, st)))
            sc.scan(s.url, p)
            sc.close()
        keys = [k for k, _ in events]
        self.assertEqual(sorted(keys), sorted(k for k, _ in live.SCAN_STEPS))
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(keys[0], "load")
        self.assertEqual(keys[-1], "report")

    def test_unreachable_target_skips_the_rest_cleanly(self):
        events = {}
        sc = Scanner(Options(no_dns=True, no_cache=True, no_browser=True, offline=True), store.load())
        p = live.Progress(on_done=lambda k, st, d, e: events.__setitem__(k, st))
        rep = sc.scan("http://127.0.0.1:1/", p)
        sc.close()
        self.assertEqual(events["load"], "bad")
        self.assertEqual({events[k] for k in ("tls", "tech", "recon", "active", "vulns", "nuclei")}, {"skip"})
        self.assertIsNone(rep["target"]["status"])


if __name__ == "__main__":
    unittest.main()
