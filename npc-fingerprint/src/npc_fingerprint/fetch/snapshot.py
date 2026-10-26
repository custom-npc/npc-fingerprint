"""PageSnapshot: everything the analysis modules need, produced by either the browser or static fetcher."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from ..util import clean

HEAD_BYTES = 500          # banner scan window (spec: first 500 bytes)
TAIL_BYTES = 1024         # for sourceMappingURL / end-of-file legal comments
SCRIPT_TEXT_CAP = 262144  # per-script text kept for `scripts` rule matching


@dataclass
class ScriptRef:
    url: str | None                  # None for inline scripts
    integrity: str | None = None
    crossorigin: str | None = None
    type: str | None = None
    size: int | None = None          # decoded size when known
    head: bytes | None = None
    tail: bytes | None = None
    text: str | None = None          # decoded head of the script (inline: whole text, capped)
    observed: bool = False           # True when the browser really downloaded it


@dataclass
class NetRequest:
    url: str
    resource_type: str
    method: str = "GET"
    status: int | None = None
    protocol: str | None = None
    observed: bool = True            # False when merely declared in static HTML


@dataclass
class PageSnapshot:
    mode: str                                   # browser | static
    url: str
    final_url: str
    status: int | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)   # main document, wire order, duplicates kept
    html_raw: str = ""
    html_rendered: str | None = None
    title: str = ""
    meta: list[tuple[str, str]] = field(default_factory=list)      # (lower-cased name, content)
    scripts: list[ScriptRef] = field(default_factory=list)
    links: list[dict] = field(default_factory=list)                # rel, href, integrity, crossorigin
    cookies_jar: list[dict] = field(default_factory=list)          # browser cookie jar (names + flags; values kept in memory only)
    js_values: dict[str, str] = field(default_factory=dict)        # chain -> '' (present) | string value
    dom_hits: dict[str, list[dict]] = field(default_factory=dict)  # selector -> element records
    text: str = ""
    css: str = ""
    icons: list[str] = field(default_factory=list)                 # <link rel~=icon> hrefs (absolute)
    requests: list[NetRequest] = field(default_factory=list)
    xhr_hosts: list[str] = field(default_factory=list)
    protocol: str | None = None                 # observed protocol of the main document: h2 | http/1.1 | h3
    protocols_seen: dict[str, int] = field(default_factory=dict)
    server_ip: str | None = None
    elapsed_ms: int = 0
    extra_requests: list[str] = field(default_factory=list)   # explicit requests we made beyond the page load
    warnings: list[str] = field(default_factory=list)
    partial: bool = False
    error: str | None = None

    # -- header helpers ------------------------------------------------------
    def header_values(self, name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]

    def header(self, name: str) -> str | None:
        vals = self.header_values(name)
        if not vals:
            return None
        return ", ".join(vals)

    @property
    def scheme(self) -> str:
        return urlsplit(self.final_url).scheme.lower()

    @property
    def host(self) -> str:
        return urlsplit(self.final_url).hostname or ""

    def set_cookie_headers(self) -> list[str]:
        return self.header_values("set-cookie")


# ----------------------------------------------------------------------------
# Set-Cookie parsing
# ----------------------------------------------------------------------------

def parse_set_cookie(raw: str) -> dict:
    parts = [p.strip() for p in raw.split(";")]
    name, _, value = parts[0].partition("=")
    attrs: dict[str, str] = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return {
        "name": name.strip(),
        "value": value,                       # in memory for rule matching; never printed or serialised
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": (attrs.get("samesite") or None),
        "domain": attrs.get("domain") or None,
        "path": attrs.get("path") or None,
        "partitioned": "partitioned" in attrs,
        "persistent": "max-age" in attrs or "expires" in attrs,
    }


_COOKIE_SPLIT = re.compile(r",\s*(?=[^;,=\s]+=)")


def split_joined_set_cookie(joined: str) -> list[str]:
    """Fallback when a client merged several Set-Cookie headers into one comma-joined string."""
    return [p for p in _COOKIE_SPLIT.split(joined) if p.strip()]


# ----------------------------------------------------------------------------
# Static HTML parsing
# ----------------------------------------------------------------------------

class PageParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self._base_set = False
        self.meta: list[tuple[str, str]] = []
        self.scripts: list[ScriptRef] = []
        self.links: list[dict] = []
        self.title = ""
        self._mode: str | None = None
        self._buf: list[str] = []
        self._cur: dict | None = None
        self.text_parts: list[str] = []
        self.css_parts: list[str] = []
        self._text_len = 0

    def _abs(self, u: str | None) -> str | None:
        if not u:
            return None
        u = u.strip()
        if u.lower().startswith(("data:", "javascript:", "about:", "blob:")):
            return None
        try:
            return urljoin(self.base, u)
        except ValueError:
            return None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else "") for k, v in attrs}
        if tag == "base" and a.get("href") and not self._base_set:
            self._base_set = True
            self.base = self._abs(a["href"]) or self.base
        elif tag == "meta":
            name = a.get("name") or a.get("property") or a.get("http-equiv")
            if name:
                self.meta.append((name.lower(), a.get("content", "")))
        elif tag == "link" and a.get("href"):
            self.links.append({
                "rel": a.get("rel", "").lower(), "href": self._abs(a["href"]),
                "integrity": a.get("integrity") or None, "crossorigin": a.get("crossorigin"),
            })
        elif tag == "script":
            self._mode = "script"
            self._buf = []
            self._cur = a
        elif tag == "style":
            self._mode, self._buf = "style", []
        elif tag == "title":
            self._mode, self._buf = "title", []

    def handle_endtag(self, tag):
        if tag == "script" and self._mode == "script" and self._cur is not None:
            a = self._cur
            src = self._abs(a.get("src")) if a.get("src") else None
            text = "".join(self._buf)[:SCRIPT_TEXT_CAP]
            if a.get("src") and src is None:
                pass  # data:/javascript: src, ignore
            else:
                self.scripts.append(ScriptRef(
                    url=src, integrity=a.get("integrity") or None, crossorigin=a.get("crossorigin"),
                    type=a.get("type"), text=None if src else text))
            self._mode = self._cur = None
        elif tag == "style" and self._mode == "style":
            self.css_parts.append("".join(self._buf)[:100000])
            self._mode = None
        elif tag == "title" and self._mode == "title":
            self.title = clean("".join(self._buf))[:200]
            self._mode = None

    def handle_data(self, data):
        if self._mode in ("script", "style", "title"):
            self._buf.append(data)
        elif self._text_len < 100000:
            d = data.strip()
            if d:
                self.text_parts.append(d)
                self._text_len += len(d)


def parse_html(html: str, base_url: str) -> PageParser:
    p = PageParser(base_url)
    try:
        p.feed(html)
        p.close()
    except Exception:  # noqa: BLE001 - malformed markup must never kill a scan
        pass
    return p
