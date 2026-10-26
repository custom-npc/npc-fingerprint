"""Terminal output. Rich handles colour-depth negotiation, NO_COLOR and non-TTY output; we only supply spans."""
from __future__ import annotations

import sys

from .layout import Line, build_card, fit_spans, hint_line
from .theme import ASCII, UNI, asciify, style_of, use_ascii
from .trace import build_trace

try:
    from rich.console import Console
    from rich.text import Text
    HAVE_RICH = True
except ImportError:  # pragma: no cover
    HAVE_RICH = False


def make_console(no_color: bool = False, width: int | None = None, file=None):
    if not HAVE_RICH:
        return None
    return Console(file=file or sys.stdout, no_color=no_color, width=width, highlight=False, soft_wrap=False,
                   legacy_windows=False, emoji=False, markup=False)


def to_plain(lines: list[Line]) -> list[str]:
    return ["".join(t for t, _ in ln) for ln in lines]


def emit(lines: list[Line], console, ascii_only: bool = False) -> None:
    if ascii_only:
        lines = [[(asciify(t), st) for t, st in ln] for ln in lines]
    if console is None:
        for ln in to_plain(lines):
            print(ln)
        return
    for ln in lines:
        text = Text(no_wrap=True, overflow="crop")
        for t, st in ln:
            text.append(t, style=style_of(st) or None)
        console.print(text, crop=True, overflow="crop", no_wrap=True)


def render_report(rep: dict, console, *, verbose: bool = False, ascii_only: bool = False, width: int | None = None,
                  stream=None) -> list[Line]:
    g = ASCII if use_ascii(ascii_only, stream) else UNI
    w = width or (console.width if console is not None else 80)
    W = min(w, 100)
    lines = build_card(rep, W, g)
    lines.append(hint_line(g, verbose, W))
    if verbose:
        lines.append([("", "")])
        lines += [fit_spans(ln, w if w >= 40 else 80) for ln in build_trace(rep, g)]
    emit(lines, console, ascii_only=g is ASCII)
    return lines
