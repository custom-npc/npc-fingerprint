"""Live run view: what the tool is doing right now, with a light animation.

Design constraints: terminal-only, no GPU or full-screen takeover, ~12 frames/s of a few lines of text (a fraction of one percent
of a core), degrades to plain one-line-per-step logs when output is not a terminal, with --no-live, NO_COLOR-agnostic, or when the
user asked for reduced motion (NPC_NO_ANIM=1). Everything goes to stderr, so stdout (report / --json) stays clean.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from contextlib import contextmanager

from ..util import fit, safe
from .layout import Line, fit_spans
from .theme import ASCII, UNI, asciify, style_of

try:
    from rich.console import Console
    from rich.live import Live
    from rich.text import Text
    HAVE_RICH = True
except ImportError:  # pragma: no cover
    HAVE_RICH = False

SPIN_UNI = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SPIN_ASCII = "|/-\\"
SCAN_STEPS = [
    ("load", "Load and render the page"), ("tls", "TLS and HTTP protocol"), ("headers", "Security headers"),
    ("tech", "Fingerprint technologies"), ("favicon", "Favicon hashes"), ("bundle", "JavaScript bundles"),
    ("recon", "Mine JavaScript for endpoints, secrets"), ("active", "Non-destructive active checks"),
    ("vulns", "Match CVEs and exploit data"), ("nuclei", "Suggest Nuclei templates"), ("report", "Assemble the report"),
]


class Progress:
    """Thread-safe run model. The scanner reports into it; a view (live or plain) reads from it."""

    def __init__(self, steps=SCAN_STEPS, title: str = "", on_done=None):
        self.steps = [k for k, _ in steps]
        self.labels = dict(steps)
        self.state = {k: "pending" for k in self.steps}
        self.detail = {k: "" for k in self.steps}
        self.t_start: dict[str, float] = {}
        self.t_end: dict[str, float] = {}
        self.title = title
        self.current = ""
        self.t0 = time.monotonic()
        self._lock = threading.Lock()
        self._on_done = on_done

    # reporting API -----------------------------------------------------------------------------------
    def start(self, key: str, action: str = "") -> None:
        with self._lock:
            if key in self.state:
                self.state[key] = "running"
                self.t_start[key] = time.monotonic()
            self.current = action or self.labels.get(key, key)

    def say(self, action: str) -> None:
        with self._lock:
            self.current = action

    def done(self, key: str, detail: str = "", state: str = "ok") -> None:
        with self._lock:
            if key in self.state:
                self.state[key] = state
                self.detail[key] = detail
                self.t_end[key] = time.monotonic()
                self.t_start.setdefault(key, self.t_end[key])
        if self._on_done:
            self._on_done(key, state, detail, self.elapsed(key))

    def skip(self, key: str, why: str = "") -> None:
        self.done(key, why, "skip")

    def elapsed(self, key: str) -> float:
        with self._lock:
            s, e = self.t_start.get(key), self.t_end.get(key)
        return 0.0 if s is None else (e or time.monotonic()) - s

    def total(self) -> float:
        return time.monotonic() - self.t0

    def snapshot(self):
        with self._lock:
            return dict(self.state), dict(self.detail), self.current


class NullProgress(Progress):
    def __init__(self):
        super().__init__([], "")

    def start(self, *a, **k): pass
    def say(self, *a, **k): pass
    def done(self, *a, **k): pass
    def skip(self, *a, **k): pass


def new_target(progress: Progress, title: str) -> Progress:
    p = Progress(SCAN_STEPS, title, progress._on_done if progress else None)
    return p


# ----------------------------------------------------------------------------------------------------
class LiveView:
    """Rich renderable: header, sweeping scan bar, one line per step, current action. Pure function of (progress, clock)."""

    def __init__(self, progress: Progress, ascii_only: bool = False, clock=time.monotonic):
        self.p, self.ascii, self.clock = progress, ascii_only, clock

    def lines(self, width: int, now: float | None = None) -> list[Line]:
        g = ASCII if self.ascii else UNI
        t = self.clock() if now is None else now
        spin = (SPIN_ASCII if self.ascii else SPIN_UNI)[int(t * 12.5) % (len(SPIN_ASCII) if self.ascii else len(SPIN_UNI))]
        st, det, cur = self.p.snapshot()
        W = max(30, min(width, 100))
        out: list[Line] = []
        el = int(self.p.total())
        head: Line = [(" npc-fingerprint ", "title"), (f"{g['arrow']} ", "frame"), (fit(self.p.title, W - 30, g["ell"]), "url")]
        clock_txt = f"{el // 60:02d}:{el % 60:02d} "
        pad = W - sum(len(x) for x, _ in head) - len(clock_txt)
        out.append(fit_spans(head + [(" " * max(1, pad), ""), (clock_txt, "dim")], W))
        out.append([(" ", "")] + self._sweep(W - 2, t, g))
        lw = min(40, max((len(x) for x in self.p.labels.values()), default=10)) + 2
        for k in self.p.steps:
            s = st[k]
            if s == "running":
                icon: tuple[str, str] = (spin, "accent")
                label_style = "emph"
                tail = f"{self.p.elapsed(k):.1f}s"
            elif s == "pending":
                icon, label_style, tail = (g["na"], "dim"), "dim", ""
            else:
                icon = {"ok": (g["pass"], "ok"), "warn": (g["warn"], "warn"), "bad": (g["bad"], "bad"), "skip": ("-", "dim")}[s]
                label_style = "value" if s != "skip" else "dim"
                tail = det[k]
            line: Line = [(" ", ""), icon, (" ", ""), (self.p.labels[k].ljust(lw), label_style), (tail, "dim" if s in ("pending", "skip") else "value")]
            out.append(fit_spans(line, W))
        if cur:
            out.append(fit_spans([(" ", ""), (g["arrow"] + " ", "accent"), (cur, "dim")], W))
        return out

    def _sweep(self, w: int, t: float, g: dict) -> Line:
        """A bright comet bouncing along a dim track: one cheap string per frame."""
        w = max(10, min(w, 64))
        seg = 8
        span = w - seg
        pos = int(t * 26) % (2 * span)
        pos = pos if pos <= span else 2 * span - pos
        cells: Line = []
        if self.ascii:
            return [("[" + "-" * pos + "=" * seg + "-" * (span - pos) + "]", "accent")]
        track = "━"
        cells.append((track * pos, "dim"))
        for i in range(seg):
            cells.append((track, f"heat:{35 + int(65 * (i + 1) / seg)}"))
        cells.append((track * (span - pos), "dim"))
        return cells

    def __rich_console__(self, console, options):
        for ln in self.lines(options.max_width):
            tx = Text(no_wrap=True, overflow="crop")
            for s, st in ln:
                tx.append(asciify(s) if self.ascii else s, style=style_of(st) or None)
            yield tx


class PlainReporter:
    """No animation: one line per finished step on stderr (non-TTY, CI logs, screen readers, --no-live)."""

    def __init__(self, stream=None, ascii_only: bool = False, quiet: bool = False):
        self.stream, self.ascii, self.quiet = stream or sys.stderr, ascii_only, quiet
        self._g = ASCII if ascii_only else UNI

    def on_done(self, key: str, state: str, detail: str, elapsed: float) -> None:
        if self.quiet:
            return
        icon = {"ok": self._g["pass"], "warn": self._g["warn"], "bad": self._g["bad"], "skip": "-"}.get(state, "?")
        print(safe(f"  {icon} {key:<8} {detail} ({elapsed:.1f}s)").rstrip(), file=self.stream, flush=True)


def live_allowed(console, no_live: bool, quiet: bool, as_json: bool) -> bool:
    if not HAVE_RICH or no_live or quiet or as_json or os.environ.get("NPC_NO_ANIM") or os.environ.get("TERM") == "dumb":
        return False
    return bool(getattr(console, "is_terminal", False))


@contextmanager
def live_display(progress: Progress, console, ascii_only: bool = False, fps: int = 12):
    """Show the live view on `console` (stderr) for the duration of the block; it vanishes afterwards (transient)."""
    view = LiveView(progress, ascii_only)
    with Live(view, console=console, refresh_per_second=fps, transient=True, vertical_overflow="crop"):
        yield


def make_err_console(no_color: bool = False, file=None):
    if not HAVE_RICH:
        return None
    return Console(file=file or sys.stderr, no_color=no_color, highlight=False, soft_wrap=False, emoji=False, markup=False)
