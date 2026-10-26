"""Pattern handling for the community fingerprint database.

Wappalyzer-style patterns are JavaScript regexes with ``\\;key:value`` tags appended. We need:
  * the `regex` module when available (per-match timeouts: the patterns are community-written and the
    inputs are untrusted pages, so catastrophic backtracking is a real risk), falling back to `re`;
  * JS -> Python syntax translation;
  * a literal "hint" per pattern so most patterns are rejected by a plain substring test before any
    regex runs (this is what keeps ~7.6k technologies fast in pure Python);
  * the version-template mini language (``\\1``, ``\\1?a:b``).
"""
from __future__ import annotations

import re
from typing import Any

try:  # preferred engine
    import regex as _engine  # type: ignore

    HAVE_REGEX = True
except ImportError:  # pragma: no cover - exercised in minimal environments
    _engine = re
    HAVE_REGEX = False

STATS = {"compiled": 0, "skipped": 0, "timeouts": 0}
_CACHE: dict[str, Any] = {}

# `re` has no timeout; without `regex` we refuse patterns with nested quantifiers (classic ReDoS shape).
_NESTED_QUANT = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")


def translate(body: str) -> str:
    """JavaScript regex syntax -> syntax both `re` and `regex` accept."""
    body = body.replace("[^]", r"[\s\S]")
    body = re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", body)
    body = re.sub(r"\\k<([A-Za-z_]\w*)>", r"(?P=\1)", body)
    return body


def compile_body(body: str):
    """Compile (case-insensitive) or return None. Failures are counted, never raised."""
    if body in _CACHE:
        return _CACHE[body]
    rx = None
    try:
        t = translate(body)
        if not HAVE_REGEX and _NESTED_QUANT.search(t):
            raise ValueError("nested quantifier without regex engine")
        rx = _engine.compile(t, _engine.IGNORECASE)
        STATS["compiled"] += 1
    except Exception:  # noqa: BLE001 - patterns we cannot port are skipped and counted
        STATS["skipped"] += 1
        rx = None
    _CACHE[body] = rx
    return rx


def run(rx, text: str, timeout: float = 0.5):
    try:
        if HAVE_REGEX:
            return rx.search(text, timeout=timeout)
        return rx.search(text)
    except TimeoutError:
        STATS["timeouts"] += 1
        return None


# ----------------------------------------------------------------------------
# Literal hints
# ----------------------------------------------------------------------------

_QUANT = re.compile(r"\{(\d*)(?:,(\d*))?\}")


def _skip_class(b: str, i: int) -> int:
    """b[i] == '['. Return index just past the closing ']' (JS semantics: '[]' is empty, '[^]' is any)."""
    n = len(b)
    j = i + 1
    if j < n and b[j] == "^":
        j += 1
    if j < n and b[j] == "]":
        return j + 1
    while j < n:
        if b[j] == "\\":
            j += 2
            continue
        if b[j] == "]":
            return j + 1
        j += 1
    return n


def _skip_group(b: str, i: int) -> int:
    """b[i] == '('. Return index just past the matching ')'."""
    n, depth, j = len(b), 0, i
    while j < n:
        c = b[j]
        if c == "\\":
            j += 2
            continue
        if c == "[":
            j = _skip_class(b, j)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return n


def literal_hint(body: str, min_len: int = 3) -> str | None:
    """Longest run of characters that *must* appear (case-insensitively) in any text the pattern matches.

    Sound by construction: anything optional, alternated, grouped or class-based is excluded. When in
    doubt a character is dropped, which only makes the hint shorter (never wrongly strict).
    """
    b, n, i = body, len(body), 0
    runs: list[str] = []
    cur: list[str] = []

    def flush() -> None:
        if cur:
            runs.append("".join(cur))
            cur.clear()

    while i < n:
        c = b[i]
        lit: str | None = None
        if c == "\\":
            if i + 1 >= n:
                flush()
                break
            d = b[i + 1]
            i += 2
            if d.isalnum():  # \d \w \s \b \1 \xHH \uHHHH \cX \p{..} \k<..>
                flush()
                if d == "x":
                    i += 2
                elif d == "u":
                    if i < n and b[i] == "{":
                        k = b.find("}", i)
                        i = n if k < 0 else k + 1
                    else:
                        i += 4
                elif d == "c":
                    i += 1
                elif d in "pPk" and i < n and b[i] in "{<":
                    k = b.find("}" if b[i] == "{" else ">", i)
                    i = n if k < 0 else k + 1
                continue
            lit = d
        elif c == "[":
            flush()
            i = _skip_class(b, i)
            continue
        elif c == "(":
            flush()
            i = _skip_group(b, i)
            continue
        elif c == ")":
            return None  # unbalanced; give up
        elif c == "|":
            return None  # top-level alternation: nothing is guaranteed
        elif c in "^$.":
            flush()
            i += 1
            continue
        elif c in "*+?":
            if c in "*?" and cur:
                cur.pop()  # previous literal is optional
            flush()
            i += 1
            if i < n and b[i] in "?+":
                i += 1
            continue
        elif c == "{":
            m = _QUANT.match(b, i)
            if m:
                lo = m.group(1)
                if cur and (lo == "" or int(lo) == 0):
                    cur.pop()
                flush()
                i = m.end()
                if i < n and b[i] in "?+":
                    i += 1
                continue
            lit = "{"
            i += 1
        else:
            lit = c
            i += 1
        if lit is not None:
            cur.append(lit)
    flush()
    if not runs:
        return None
    best = max(runs, key=len)
    if len(best) < min_len or not best.isascii():
        return None
    return best.lower()


# ----------------------------------------------------------------------------
# Pattern objects: body + tags (confidence, version template) + hint
# ----------------------------------------------------------------------------

class Hit:
    __slots__ = ("matched", "groups")

    def __init__(self, matched: str, groups: tuple):
        self.matched = matched
        self.groups = groups  # groups[0] is the whole match, like JS exec()


def resolve_version(template: str | None, groups: tuple) -> str | None:
    """Wappalyzer version syntax: ``\\1`` back-references and ``\\1?yes:no`` ternaries."""
    if not template:
        return None
    version = template
    for i, g in enumerate(groups):
        m = re.search(rf"\\{i}\?([^:]+):(.*)$", version)
        if m:
            version = version.replace(m.group(0), m.group(1) if g else m.group(2))
        version = version.strip().replace(f"\\{i}", g or "")
    version = version.strip()
    if not version or "\\" in version:
        return None
    return version[:32]


class Pat:
    """One parsed pattern: ``body\\;confidence:50\\;version:\\1``."""

    __slots__ = ("raw", "body", "confidence", "version", "hint", "_rx", "_ready")

    def __init__(self, raw: str):
        self.raw = raw
        parts = raw.split("\\;")
        self.body = parts[0]
        self.confidence = 100
        self.version: str | None = None
        for tag in parts[1:]:
            k, _, v = tag.partition(":")
            if k == "confidence":
                try:
                    self.confidence = max(0, min(100, int(v)))
                except ValueError:
                    pass
            elif k == "version":
                self.version = v
        self.hint = literal_hint(self.body) if self.body else None
        self._rx = None
        self._ready = False

    def match(self, text: str, low: str | None = None) -> Hit | None:
        """Return a Hit or None. An empty body means "present" and matches any value."""
        if not self.body:
            return Hit("", ("",))
        if self.hint is not None:
            if (low if low is not None else text.lower()).find(self.hint) < 0:
                return None
        if not self._ready:
            self._rx = compile_body(self.body)
            self._ready = True
        if self._rx is None:
            return None
        m = run(self._rx, text)
        if m is None:
            return None
        groups = (m.group(0),) + tuple(m.groups())
        return Hit(m.group(0), groups)


def to_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]
