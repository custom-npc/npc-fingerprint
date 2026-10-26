"""Static (no-JavaScript) fetching.

Backend: `niquests` (HTTP/1.1, HTTP/2 and HTTP/3 aware, requests-compatible API) with a plain `requests`
fallback. Anything only niquests exposes (http_version, conn_info) is read defensively with getattr, so the
same code path works on both.
"""
from __future__ import annotations

import time
import warnings
from dataclasses import dataclass, field

try:
    import niquests as _http  # type: ignore

    BACKEND = "niquests"
except ImportError:  # pragma: no cover - fallback for environments where niquests wheels are unavailable
    import requests as _http  # type: ignore

    BACKEND = "requests"

from .snapshot import NetRequest, PageSnapshot, parse_html, split_joined_set_cookie


@dataclass
class FetchResult:
    url: str
    status: int | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    http_version: str | None = None
    error: str | None = None
    truncated: bool = False
    total_size: int | None = None   # from Content-Range / Content-Length when known

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None

    def header(self, name: str) -> str | None:
        vals = [v for k, v in self.headers if k.lower() == name.lower()]
        return ", ".join(vals) if vals else None


_VERSION_NAMES = {9: "http/0.9", 10: "http/1.0", 11: "http/1.1", 20: "h2", 30: "h3"}


def _http_version(r) -> str | None:
    v = getattr(r, "http_version", None)          # niquests: 10 / 11 / 20 / 30
    if isinstance(v, int) and v in _VERSION_NAMES:
        return _VERSION_NAMES[v]
    raw = getattr(r, "raw", None)
    v = getattr(raw, "version", None)             # urllib3: 10 / 11
    if isinstance(v, int) and v in _VERSION_NAMES:
        return _VERSION_NAMES[v]
    return None


def _wire_headers(r) -> list[tuple[str, str]]:
    """Headers with duplicates preserved (matters for Set-Cookie)."""
    try:
        items = list(r.raw.headers.items())       # urllib3 HTTPHeaderDict yields repeated names separately
        if items:
            return [(str(k), str(v)) for k, v in items]
    except Exception:  # noqa: BLE001
        pass
    out: list[tuple[str, str]] = []
    for k, v in r.headers.items():        # clients that merge repeated headers join Set-Cookie with ", "
        if str(k).lower() == "set-cookie":
            out.extend((str(k), part) for part in split_joined_set_cookie(str(v)))
        else:
            out.append((str(k), str(v)))
    return out


class StaticFetcher:
    """Connection-reusing fetcher (one Session per run)."""

    def __init__(self, user_agent: str, timeout: float = 15.0, verify: bool = False):
        self.timeout = timeout
        self.verify = verify
        self.session = _http.Session()
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        try:
            self.session.max_redirects = 8
        except Exception:  # noqa: BLE001
            pass

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:  # noqa: BLE001
            pass

    def get(self, url: str, *, headers: dict | None = None, max_bytes: int = 2_000_000,
            range_bytes: int | None = None, method: str = "GET") -> FetchResult:
        h = dict(headers or {})
        if range_bytes:
            h["Range"] = f"bytes=0-{range_bytes - 1}"
        deadline = time.monotonic() + self.timeout * 1.5
        res = FetchResult(url=url)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")      # unverified-HTTPS warnings are expected: we report TLS separately
                r = self.session.request(method, url, headers=h, timeout=(min(self.timeout, 8.0), self.timeout),
                                         allow_redirects=True, stream=True, verify=self.verify)
                res.url = str(r.url)
                res.status = r.status_code
                res.headers = _wire_headers(r)
                res.http_version = _http_version(r)
                body = bytearray()
                if method != "HEAD":
                    for chunk in r.iter_content(chunk_size=65536):
                        body.extend(chunk)
                        if len(body) >= max_bytes or (range_bytes and len(body) >= range_bytes) \
                                or time.monotonic() > deadline:
                            res.truncated = True
                            break
                r.close()
            res.body = bytes(body[:max_bytes])
            cr = res.header("content-range")
            if cr and "/" in cr and cr.rsplit("/", 1)[1].strip().isdigit():
                res.total_size = int(cr.rsplit("/", 1)[1])
            elif res.header("content-length") and res.header("content-length").strip().isdigit() \
                    and not res.header("content-encoding"):
                res.total_size = int(res.header("content-length"))
            elif not res.truncated:
                res.total_size = len(res.body)
        except Exception as e:  # noqa: BLE001 - network failures degrade, they never crash a scan
            res.error = f"{type(e).__name__}: {e}"[:200]
        return res


def snapshot_from_static(url: str, fetcher: StaticFetcher) -> PageSnapshot:
    """Fetch the page once and parse it with the stdlib HTML parser. No JS globals, no DOM-rule evaluation."""
    t0 = time.monotonic()
    res = fetcher.get(url, max_bytes=3_000_000)
    snap = PageSnapshot(mode="static", url=url, final_url=res.url or url, status=res.status)
    if not res.ok:
        snap.error = res.error or "request failed"
        snap.partial = True
        snap.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return snap
    snap.headers = res.headers
    snap.protocol = res.http_version
    if snap.protocol:
        snap.protocols_seen = {snap.protocol: 1}
    ctype = (res.header("content-type") or "").lower()
    html = res.body.decode("utf-8", "replace") if (not ctype or "html" in ctype or "xml" in ctype or "text" in ctype) else ""
    snap.html_raw = html
    p = parse_html(html, snap.final_url)
    snap.title = p.title
    snap.meta = p.meta
    snap.scripts = p.scripts
    snap.links = p.links
    snap.text = " ".join(p.text_parts)[:100000]
    snap.css = "\n".join(p.css_parts)[:200000]
    for s in p.scripts:
        if s.url:
            snap.requests.append(NetRequest(s.url, "script", observed=False))
    for l in p.links:
        if l.get("href") and "stylesheet" in l["rel"]:
            snap.requests.append(NetRequest(l["href"], "stylesheet", observed=False))
    if res.truncated:
        snap.warnings.append("page body truncated at 3 MB")
    snap.elapsed_ms = int((time.monotonic() - t0) * 1000)
    return snap
