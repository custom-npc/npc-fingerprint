"""Glyph sets and styles. Meaning is always carried by a glyph AND a word/number, never by colour alone."""
from __future__ import annotations

import os
import sys

UNI = {
    "ok": "●", "warn": "▲", "bad": "✖", "na": "○", "pass": "✔", "weak": "▲", "missing": "✖", "n/a": "○", "info": "●",
    "tl": "╭", "tr": "╮", "bl": "╰", "br": "╯", "h": "─", "v": "│", "lt": "├", "rt": "┤", "tt": "┬", "bt": "┴",
    "full": "█", "half": "▌", "empty": "░", "arrow": "▸", "dot": "·", "ell": "…", "minus": "−", "implied": "↳",
    "tree_mid": "├─", "tree_end": "└─", "tree_bar": "│ ",
}
ASCII = {
    "ok": "o", "warn": "!", "bad": "x", "na": "-", "pass": "+", "weak": "!", "missing": "x", "n/a": "-", "info": "o",
    "tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|", "lt": "+", "rt": "+", "tt": "+", "bt": "+",
    "full": "#", "half": "=", "empty": ".", "arrow": ">", "dot": "-", "ell": "~", "minus": "-", "implied": "->",
    "tree_mid": "|-", "tree_end": "`-", "tree_bar": "| ",
}

STYLES = {
    "frame": "dim", "title": "bold", "label": "dim", "ok": "green", "warn": "yellow", "bad": "bold red", "na": "dim",
    "value": "", "emph": "bold", "url": "cyan", "dim": "dim", "implied": "dim italic", "accent": "bold cyan",
    "disputed": "bold yellow", "added": "bold green", "removed": "bold red", "changed": "bold yellow",
}


def heat(conf: int) -> str:
    """One hue, brightness = confidence (colour-blind safe; the number is always printed beside it)."""
    t = max(0, min(100, conf)) / 100.0
    lo, hi = (70, 82, 105), (0, 230, 118)
    r, g, b = (round(lo[i] + (hi[i] - lo[i]) * t) for i in range(3))
    return f"rgb({r},{g},{b})"


def style_of(name: str) -> str:
    if name.startswith("heat:"):
        return heat(int(name[5:]))
    return STYLES.get(name, "")


def use_ascii(force: bool = False, stream=None) -> bool:
    if force or os.environ.get("NPC_ASCII"):
        return True
    enc = getattr(stream or sys.stdout, "encoding", None) or "ascii"
    try:
        "╭█✔▲●○✖─│▸·…".encode(enc)
        return False
    except (UnicodeEncodeError, LookupError):
        return True


STATE_GLYPH_STYLE = {"ok": "ok", "warn": "warn", "bad": "bad", "na": "na"}


_ASCII_MAP = str.maketrans({"·": "-", "…": "~", "→": ">", "▸": ">", "−": "-", "—": "-", "–": "-", "↳": ">", "×": "x", "•": "*"})


def asciify(text: str) -> str:
    """Last-resort net for ASCII mode: known glyphs map 1:1, anything else becomes '?' (widths preserved)."""
    return text.translate(_ASCII_MAP).encode("ascii", "replace").decode("ascii")
