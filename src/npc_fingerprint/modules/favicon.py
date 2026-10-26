"""Module 3: favicon hash fingerprinting (Shodan-compatible mmh3 + MD5) against a local database.

Honest limits: a favicon hash only says "this image is the same bytes as one we have seen on product X".
Defaults pages, reused icons and honeypots all produce collisions, so a hash match alone is capped at
"possible" confidence; it only raises a technology's confidence when another signal agrees (see merge.py).
"""
from __future__ import annotations

import base64
import codecs
import hashlib
import json
import re
import time
from pathlib import Path

try:
    import mmh3 as _mmh3  # type: ignore
except ImportError:  # pragma: no cover - fallback keeps the tool usable where wheels are unavailable
    _mmh3 = None

from ..fetch.snapshot import PageSnapshot
from ..util import cache_dir, extra_request_allowed, origin_of, trunc

EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
MAX_FAVICON_BYTES = 1_048_576
CACHE_TTL = 24 * 3600
POSSIBLE_CONFIDENCE = 40


def _murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, signed result (what mmh3.hash() returns). Pure-Python fallback."""
    M = 0xFFFFFFFF
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = seed & M
    n = len(data)
    rounded = n & ~3
    for i in range(0, rounded, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & M
        k = ((k << 15) | (k >> 17)) & M
        k = (k * c2) & M
        h ^= k
        h = ((h << 13) | (h >> 19)) & M
        h = (h * 5 + 0xE6546B64) & M
    tail = data[rounded:]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & M
        k = ((k << 15) | (k >> 17)) & M
        k = (k * c2) & M
        h ^= k
    h ^= n
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & M
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & M
    h ^= h >> 16
    return h - (1 << 32) if h & 0x80000000 else h


def mmh3_hash(data: bytes) -> int:
    return _mmh3.hash(data) if _mmh3 is not None else _murmur3_32(data)


def favicon_hashes(raw: bytes) -> dict:
    # Shodan hashes the base64 TEXT *with* a newline every 76 characters. base64.b64encode() emits none and
    # would produce a different (useless) hash, so use the "base64" codec exactly like Shodan's reference code.
    return {"mmh3": mmh3_hash(codecs.encode(raw, "base64")), "md5": hashlib.md5(raw).hexdigest()}


# ----------------------------------------------------------------------------
# discovery + fetch (+ tiny on-disk cache)
# ----------------------------------------------------------------------------

def candidate_urls(snap: PageSnapshot) -> list[str]:
    icons = list(snap.icons)
    if not icons:
        for l in snap.links:
            rel = (l.get("rel") or "").split()
            if "icon" in rel and l.get("href"):
                icons.append(l["href"])
    out: list[str] = []
    for u in icons:
        if u not in out:
            out.append(u)
    default = origin_of(snap.final_url) + "/favicon.ico"
    if default not in out:
        out.append(default)
    out = [u for u in out if u.startswith("data:") or extra_request_allowed(snap.host, u)]
    return out[:2]  # at most two attempts: the declared icon, then /favicon.ico


def _looks_like_image(body: bytes, ctype: str) -> bool:
    if ctype.startswith("image/") or "icon" in ctype:
        return True
    if "html" in ctype or "json" in ctype or ctype.startswith("text/") and "svg" not in ctype:
        return False
    magic = (b"\x00\x00\x01\x00", b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"<svg", b"<?xml", b"BM")
    return body.startswith(magic)


def _cache_path(url: str) -> Path:
    return cache_dir() / "favicons" / (hashlib.sha1(url.encode()).hexdigest() + ".json")


def _cache_get(url: str):
    p = _cache_path(url)
    try:
        d = json.loads(p.read_text())
        if time.time() - d["t"] < CACHE_TTL:
            return base64.b64decode(d["b64"]) if d.get("b64") is not None else None, d.get("ok", True)
    except (OSError, ValueError, KeyError):
        pass
    return None


def _cache_put(url: str, body: bytes | None) -> None:
    try:
        p = _cache_path(url)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"t": time.time(), "ok": body is not None,
                                 "b64": base64.b64encode(body).decode() if body is not None else None}))
    except OSError:
        pass


def fetch_favicon(snap: PageSnapshot, fetcher, use_cache: bool = True) -> tuple[bytes | None, str | None, list[str]]:
    """Return (bytes, url, notes). Makes at most two requests (zero on a cache hit or data: URI)."""
    notes: list[str] = []
    for url in candidate_urls(snap):
        if url.startswith("data:"):
            m = re.match(r"data:([^;,]*)(;base64)?,(.*)", url, re.S)
            if m:
                try:
                    body = base64.b64decode(m.group(3)) if m.group(2) else m.group(3).encode()
                    return body, "data: URI (inline)", notes
                except (ValueError, TypeError):
                    continue
        if use_cache:
            hit = _cache_get(url)
            if hit is not None:
                body, ok = hit
                if ok and body:
                    return body, url, notes + ["favicon served from local cache"]
                continue
        if fetcher is None:
            continue
        r = fetcher.get(url, max_bytes=MAX_FAVICON_BYTES)
        snap.extra_requests.append("favicon")
        ctype = (r.header("content-type") or "").split(";")[0].strip().lower() if r.ok else ""
        if r.ok and r.status == 200 and r.body and len(r.body) <= MAX_FAVICON_BYTES and _looks_like_image(r.body, ctype):
            if use_cache:
                _cache_put(url, r.body)
            return r.body, url, notes
        if use_cache:
            _cache_put(url, None)
    return None, None, notes + ["no usable favicon found"]


# ----------------------------------------------------------------------------
# matching
# ----------------------------------------------------------------------------

def analyze(snap: PageSnapshot, fetcher, favicons_db: dict, use_cache: bool = True) -> dict:
    body, url, notes = fetch_favicon(snap, fetcher, use_cache)
    if body is None:
        return {"status": "none", "url": None, "notes": notes, "matches": []}
    h = favicon_hashes(body)
    ign = favicons_db.get("ignore", {})
    sentinel = (h["md5"] == EMPTY_MD5 or h["md5"] in ign.get("md5", []) or str(h["mmh3"]) in map(str, ign.get("mmh3", [])))
    res = {"url": trunc(url, 200), "bytes": len(body), "mmh3": h["mmh3"], "md5": h["md5"], "notes": notes, "matches": []}
    if sentinel:
        res["status"] = "sentinel"
        res["notes"] = notes + ["hash belongs to an empty/invalid placeholder icon and carries no information"]
        return res
    names: dict[str, dict] = {}
    for algo, key in (("mmh3", str(h["mmh3"])), ("md5", h["md5"])):
        for entry in favicons_db.get(algo, {}).get(key, []):
            name, src = (entry if isinstance(entry, (list, tuple)) else (entry, ""))
            e = names.setdefault(name, {"name": name, "via": [], "sources": []})
            if algo not in e["via"]:
                e["via"].append(algo)
            if src and src not in e["sources"]:
                e["sources"].append(src)
    res["matches"] = sorted(names.values(), key=lambda e: e["name"].lower())
    if res["matches"]:
        res["status"] = "matched"
        res["confidence"] = POSSIBLE_CONFIDENCE if len(res["matches"]) <= 3 else 25
        if len(res["matches"]) > 3:
            res["notes"] = notes + [f"{len(res['matches'])} products share this icon: ambiguous"]
    else:
        res["status"] = "no-match"
        res["confidence"] = 0
    return res
