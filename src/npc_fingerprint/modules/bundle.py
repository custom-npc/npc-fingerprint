"""Module 6: JS bundle copyright / banner scan.

Browser mode: the scripts were already downloaded by the page load, so scanning them costs zero extra
requests. Static mode: ranged GETs (first 500 bytes; the response's Content-Range also gives the size) for at
most `top_k` candidates. Banners in the first 500 bytes catch webpack/rollup style `/*! ... */` headers and
`For license information please see X.LICENSE.txt` pointers; bundlers that move legal comments elsewhere are
a documented limitation (the tail window is scanned too, for the source-map pointer and end-of-file comments).
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from ..fetch.snapshot import HEAD_BYTES, PageSnapshot, ScriptRef
from ..util import extra_request_allowed, registrable_domain, trunc

_COMMENT = re.compile(rb"/\*!?(.{0,700}?)\*/", re.S)
_LINE_BANNER = re.compile(rb"^//[!#]?\s*(.{3,200})$", re.M)
_LIBVER = re.compile(r"([A-Za-z][A-Za-z0-9_.\-]{1,40}(?:\.js)?)\s*(?:JavaScript Library\s*)?v?(\d+\.\d+(?:\.\d+)?(?:[-.][0-9A-Za-z.]+)?)")
_LICENSE = re.compile(r"\b(MIT|Apache(?:-|\s)?(?:License)?(?:,?\s*Version)?\s*2(?:\.0)?|BSD(?:-\d-Clause)?|GPL(?:v?\d)?|LGPL|ISC|MPL(?:-?2\.0)?|Unlicense)\b", re.I)
_COPY = re.compile(r"(?:\(c\)|©|copyright)\s*(?:\d{4}(?:\s*[-,]\s*\d{4})?\s*)?([^\n|*]{3,70})", re.I)
_LICFILE = re.compile(r"please see (\S+?\.LICENSE\.txt)", re.I)
_SOURCEMAP = re.compile(rb"[/*]#\s*sourceMappingURL=([^\s*]+)")
_NAMEISH = re.compile(r"(main|app|bundle|vendor|chunk|index|runtime|polyfill|framework|common)", re.I)


def parse_banners(head: bytes | None, tail: bytes | None = None) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for label, blob in (("head", (head or b"")[:HEAD_BYTES]), ("tail", (tail or b"")[-600:])):
        if not blob:
            continue
        chunks = [m.group(1) for m in _COMMENT.finditer(blob)]
        if label == "head":
            chunks += [m.group(1) for m in _LINE_BANNER.finditer(blob[:300])]
        for raw in chunks:
            text = re.sub(r"\s+", " ", raw.decode("utf-8", "replace")).strip()
            if not text or text in seen or len(text) < 4:
                continue
            seen.add(text)
            lib = _LIBVER.search(text)
            lic = _LICENSE.search(text)
            cp = _COPY.search(text)
            lf = _LICFILE.search(text)
            if not (lib or lic or cp or lf or "license" in text.lower()):
                continue
            out.append({"where": label, "text": trunc(text, 200),
                        "library": re.sub(r"(?:\.min)?(?:\.js)?$", "", lib.group(1), flags=re.I) if lib else None,
                        "version": lib.group(2) if lib else None,
                        "license": lic.group(1) if lic else None,
                        "copyright": trunc(cp.group(1).strip(" .,;"), 70) if cp else None,
                        "license_file": lf.group(1) if lf else None})
    return out


def _first_party(snap: PageSnapshot, url: str) -> bool:
    return registrable_domain(urlsplit(url).hostname or "") == registrable_domain(snap.host)


def _rank(snap: PageSnapshot, s: ScriptRef) -> tuple:
    u = s.url or ""
    path = urlsplit(u).path
    return (0 if _first_party(snap, u) else 1, 0 if _NAMEISH.search(path) else 1, 0 if ".min." in path else 1, -len(path))


def _head_probe(snap: PageSnapshot, fetcher, s: ScriptRef) -> None:
    if not extra_request_allowed(snap.host, s.url):
        return
    r = fetcher.get(s.url, range_bytes=HEAD_BYTES, max_bytes=HEAD_BYTES * 2)
    snap.extra_requests.append("script-head")
    if r.ok and r.status in (200, 206) and r.body:
        s.head = r.body[:HEAD_BYTES]
        s.size = r.total_size
        s.observed = False


def analyze(snap: PageSnapshot, fetcher, top_k: int = 4) -> dict:
    ext = [s for s in snap.scripts if s.url]
    res: dict = {"scripts_seen": len(ext), "scanned": 0, "bundle": None, "banners": [], "source_maps": [], "notes": []}
    if not ext:
        res["notes"].append("no external <script src> found")
        return res
    if snap.mode == "static" or not any(s.head for s in ext):
        if fetcher is None:
            res["notes"].append("no fetcher available; bundle scan skipped")
            return res
        for s in sorted([s for s in ext if s.head is None], key=lambda s: _rank(snap, s))[:top_k]:
            _head_probe(snap, fetcher, s)
        res["notes"].append(f"static mode: ranged probes for the top {top_k} candidates only")
    scanned = [s for s in ext if s.head]
    res["scanned"] = len(scanned)
    sized = [s for s in ext if s.size]
    biggest = max(sized, key=lambda s: s.size) if sized else (scanned[0] if scanned else None)
    if biggest is not None:
        b = parse_banners(biggest.head, biggest.tail)
        res["bundle"] = {"url": trunc(biggest.url, 160), "size": biggest.size, "first_party": _first_party(snap, biggest.url),
                         "banners": b, "bytes_scanned": len(biggest.head or b"")}
    seen: set[tuple] = set()
    for s in scanned:
        for bn in parse_banners(s.head, s.tail):
            key = (bn["library"], bn["version"], bn["license"], bn["text"][:40])
            if key not in seen:
                seen.add(key)
                res["banners"].append({**bn, "script": trunc(s.url, 160)})

    # source maps: only first-party scripts, at most two checks, HEAD only
    checked = 0
    for s in sorted(scanned, key=lambda s: -(s.size or 0)):
        if checked >= 2 or not _first_party(snap, s.url):
            continue
        tail = s.tail
        if tail is None and snap.mode == "static" and fetcher is not None and s is biggest:
            r = fetcher.get(s.url, headers={"Range": "bytes=-1024"}, max_bytes=2048)
            snap.extra_requests.append("script-tail")
            tail = r.body[-1024:] if r.ok and r.status in (200, 206) else None
            s.tail = tail
        m = _SOURCEMAP.search(tail or b"")
        if not m:
            continue
        ref = m.group(1).decode("utf-8", "replace")
        if ref.startswith("data:"):
            res["source_maps"].append({"script": trunc(s.url, 120), "map_url": "(inline data: URI)", "status": "inline"})
            continue
        murl = urljoin(s.url, ref)
        if not _first_party(snap, murl) or fetcher is None or not extra_request_allowed(snap.host, murl):
            continue
        r = fetcher.get(murl, method="HEAD")
        snap.extra_requests.append("source-map")
        checked += 1
        status = "exposed" if r.ok and r.status == 200 else "not-exposed" if r.ok and r.status in (401, 403, 404, 410) else "unknown"
        res["source_maps"].append({"script": trunc(s.url, 120), "map_url": trunc(murl, 160), "status": status, "http_status": r.status})
    return res
