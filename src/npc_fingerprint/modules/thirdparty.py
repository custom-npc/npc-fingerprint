"""Extra 4: third-party origin and Subresource Integrity (SRI) inventory.

Browser mode uses the real network log (observed requests); static mode can only report what the HTML
declares. No extra requests are made in either mode.
"""
from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlsplit

from ..fetch.snapshot import PageSnapshot
from ..util import registrable_domain, trunc


def _site(url: str) -> tuple[str, str]:
    host = urlsplit(url).hostname or ""
    return registrable_domain(host), host


def analyze(snap: PageSnapshot) -> dict:
    first = registrable_domain(snap.host)
    origins: dict[str, dict] = defaultdict(lambda: {"requests": 0, "types": defaultdict(int), "hosts": set()})
    insecure: list[str] = []
    for r in snap.requests:
        if not r.url.startswith(("http://", "https://")):
            continue
        site, host = _site(r.url)
        if r.url.startswith("http://") and snap.scheme == "https" and r.observed:
            insecure.append(trunc(r.url, 100))
        if not site or site == first:
            continue
        o = origins[site]
        o["requests"] += 1
        o["types"][r.resource_type] += 1
        o["hosts"].add(host)
    tp_scripts = [s for s in snap.scripts if s.url and _site(s.url)[0] not in ("", first)]
    tp_styles = [l for l in snap.links if "stylesheet" in (l.get("rel") or "") and l.get("href") and _site(l["href"])[0] not in ("", first)]
    no_sri_scripts = [s.url for s in tp_scripts if not s.integrity]
    no_sri_styles = [l["href"] for l in tp_styles if not l.get("integrity")]
    ranked = sorted(origins.items(), key=lambda kv: -kv[1]["requests"])
    top = [{"origin": k, "requests": v["requests"], "types": dict(v["types"]), "hosts": sorted(v["hosts"])[:4]} for k, v in ranked[:12]]
    return {
        "first_party": first,
        "observed": snap.mode == "browser",
        "origins": len(origins), "requests": sum(v["requests"] for v in origins.values()),
        "scripts_third_party": len(tp_scripts), "scripts_without_sri": len(no_sri_scripts),
        "styles_third_party": len(tp_styles), "styles_without_sri": len(no_sri_styles),
        "insecure_requests": len(insecure), "insecure_examples": insecure[:5],
        "without_sri_examples": [trunc(u, 100) for u in (no_sri_scripts + no_sri_styles)[:6]],
        "top": top,
        "note": None if snap.mode == "browser" else "static HTML: these resources are declared, not observed loading",
    }


def label_origins(result: dict, detections: list) -> None:
    """Attach technology names to third-party origins using script-src evidence already collected."""
    for o in result.get("top", []):
        names = []
        for d in detections:
            for e in d.evidence:
                if e.signal == "script-src" and o["origin"] in e.location and d.name not in names:
                    names.append(d.name)
        if names:
            o["technologies"] = names[:3]
