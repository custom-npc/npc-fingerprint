""""Verify" stage: turns what jsrecon found into checked facts, and reads the small set of standard,
self-declared discovery files every well-behaved site already publishes. Nothing here is guessed or
brute-forced: every request either follows a literal reference the site's own code contains, or reads one of
a fixed, documented list of convention paths (the same category as /.well-known/security.txt, which the tool
already reads). `--passive` or `--skip verify` disables this whole stage.
"""
from __future__ import annotations

import json
import re
import time
from urllib.parse import urljoin

from ..fetch.snapshot import PageSnapshot
from ..util import origin_of, trunc
from .scope import in_scope

RANK = {"admin": 0, "auth": 1, "api": 2, "file": 3, "route": 4, "ops": 5, "other": 6}
MAX_CHECKS = 15
MAX_SHADOW = 6
DELAY = 0.12
SHADOW_RX = re.compile(r"^(.*/)v(\d+)(/.*)?$", re.I)

# Standard, published convention paths — the same category as /.well-known/security.txt. Never guessed beyond
# this fixed list, and robots.txt/sitemap.xml are read by every web crawler as a matter of course.
SCHEMA_PATHS = ("/robots.txt", "/sitemap.xml", "/.well-known/openid-configuration",
               "/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs")


def pick_candidates(recon_endpoints: dict) -> list[dict]:
    items = []
    for kind, lst in (recon_endpoints or {}).get("by_kind", {}).items():
        for e in lst:
            if e["value"].startswith(("http://", "https://", "/")):
                items.append({"value": e["value"], "kind": kind})
    items.sort(key=lambda e: RANK.get(e["kind"], 8))
    return items[:MAX_CHECKS]


def shadow_versions(paths: list[str]) -> list[dict]:
    """For a path the app's own code names .../v3/..., also propose v1 and v2 of that SAME path: a convention
    the app itself declared by using versioned paths at all, not a guess at an unrelated path."""
    out, seen = [], set()
    for p in paths:
        m = SHADOW_RX.match(p)
        if not m:
            continue
        n = int(m.group(2))
        for v in range(1, min(n, 9)):
            cand = f"{m.group(1)}v{v}{m.group(3) or ''}"
            if cand in seen or cand == p:
                continue
            seen.add(cand)
            out.append({"value": cand, "kind": "shadow", "derived_from": trunc(p, 100)})
            if len(out) >= MAX_SHADOW:
                return out
    return out


def _classify(status: int) -> tuple[str, str]:
    if status in (401, 403):
        return "confirmed", f"HTTP {status}: exists, requires authentication"
    if 200 <= status < 300:
        return "confirmed", f"HTTP {status}: live"
    if status in (301, 302, 303, 307, 308):
        return "confirmed", f"HTTP {status}: redirects"
    if status in (404, 410):
        return "noise", f"HTTP {status}: not found (a stale reference in the site's own code)"
    if status == 429:
        return "lead", "HTTP 429: rate-limited by the server"
    return "lead", f"HTTP {status}"


def reachability(snap: PageSnapshot, fetcher, recon_endpoints: dict, target_host: str, allowed_scope: list[str] | None = None) -> dict:
    """A single read-only GET per candidate, status-coded and scope-checked. Backs off if the server asks to
    via Retry-After, and never requests anything outside scope — those are reported as suppressed, not fetched."""
    cands = pick_candidates(recon_endpoints)
    shadows = shadow_versions([c["value"] for c in cands if c["value"].startswith("/")])
    results, requests, delay = [], 0, DELAY
    for item in cands + shadows:
        val = item["value"]
        url = val if val.startswith(("http://", "https://")) else urljoin(snap.final_url, val)
        if not in_scope(url, target_host, allowed_scope):
            results.append({**item, "url": trunc(url, 160), "state": "suppressed", "status_code": None, "note": "outside scope: not requested"})
            continue
        if fetcher is None:
            results.append({**item, "url": trunc(url, 160), "state": "unverified", "status_code": None, "note": "no fetcher available"})
            continue
        if requests:
            time.sleep(delay)
        requests += 1
        snap.extra_requests.append("verify:reachability")
        r = fetcher.get(url, max_bytes=256, follow=False)
        if r is None or r.error:
            results.append({**item, "url": trunc(url, 160), "state": "unverified", "status_code": None, "note": (r.error if r else "request blocked")[:80] if r else "request blocked"})
            continue
        ra = r.header("retry-after")
        if ra and ra.strip().isdigit():
            delay = max(delay, min(5.0, int(ra.strip())))
        state, note = _classify(r.status)
        results.append({**item, "url": trunc(url, 160), "state": state, "status_code": r.status, "note": note})
    return {"checked": len(results), "requests": requests, "items": results,
            "note": "One read-only GET per item; nothing guessed beyond the site's own JavaScript and the versioned-path convention it already uses."}


def schema_discovery(snap: PageSnapshot, fetcher) -> dict:
    found = []
    if fetcher is None:
        return {"found": found, "checked": 0}
    for path in SCHEMA_PATHS:
        url = origin_of(snap.final_url) + path
        r = fetcher.get(url, max_bytes=50_000)
        snap.extra_requests.append(f"verify:{path}")
        if r is None or r.error or r.status != 200 or not r.body:
            continue
        ctype = (r.header("content-type") or "").lower()
        body = r.body
        if path != "/robots.txt" and "html" in ctype and not body.lstrip().startswith((b"{", b"<?xml", b"User-agent", b"Sitemap")):
            continue  # a soft-404 HTML page, not the real resource
        info = {"path": path, "status": r.status, "content_type": ctype, "summary": "present"}
        text = body.decode("utf-8", "replace")
        if path == "/robots.txt":
            disallow = [ln.split(":", 1)[1].strip() for ln in text.splitlines() if ln.lower().startswith("disallow:") and ln.split(":", 1)[1].strip()]
            info["summary"] = f"{len(disallow)} Disallow rule(s)" if disallow else "present, no Disallow rules"
        elif path == "/sitemap.xml":
            n = text.lower().count("<loc>")
            info["summary"] = f"{n} URL(s) listed" if n else "present"
        elif path.endswith("openid-configuration"):
            try:
                doc = json.loads(text)
                info["summary"] = f"issuer {trunc(doc.get('issuer', '?'), 60)}"
            except ValueError:
                continue
        elif path.endswith((".json",)) or "api-docs" in path:
            try:
                doc = json.loads(text)
                ver = doc.get("openapi") or doc.get("swagger")
                if not ver:
                    continue
                title = (doc.get("info") or {}).get("title", "API")
                info["summary"] = f"{trunc(title, 40)} (OpenAPI {ver}, {len(doc.get('paths') or {})} paths)"
            except ValueError:
                continue
        found.append(info)
    return {"found": found, "checked": len(SCHEMA_PATHS)}
