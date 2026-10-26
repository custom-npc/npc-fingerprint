"""Step 9: report merger.

Combines every module's output into one report: deduplicates, assigns confidence bands, attributes layers
(edge/origin/app), marks technologies disputed when the anomaly layer finds a contradiction, lets weak
independent signals (favicon, bundle banners) corroborate detections, and builds the surface summary.
"""
from __future__ import annotations

import re

from . import SCHEMA_VERSION, TOOL_NAME, __version__
from .model import Detection, Evidence, band
from .modules.tech import TechDB
from .util import trunc, utcnow_iso

APP_SIGNALS = {"js-global", "dom", "script-src", "script", "css", "text", "xhr", "html", "url", "banner"}
VISIBLE = ("confirmed", "probable", "disputed", "implied")


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _names_match(a: str, b: str) -> bool:
    na, nb = _norm(a), _norm(b)
    if not na or not nb:
        return False
    return na == nb or (min(len(na), len(nb)) >= 4 and (na in nb or nb in na))


def _recompute(d: Detection) -> None:
    d.confidence = min(100, sum(e.confidence for e in d.evidence))
    if d.status not in ("implied", "disputed"):
        d.status = band(d.confidence)
    TechDB._pick_version(d)


def attribute_layers(dets: list[Detection], edge: dict, leak_headers: set[str]) -> None:
    edge_keys = [_norm(e["name"]) for e in edge.get("edges", [])] + [_norm(e["id"]) for e in edge.get("edges", [])]
    proxied = bool(edge.get("edges"))
    for d in dets:
        if _norm(d.name) in edge_keys or any(k and (k in _norm(d.name) or _norm(d.name) in k) and len(_norm(d.name)) >= 5 for k in edge_keys):
            d.layer = "edge"
        elif d.status == "implied":
            d.layer = "unknown"
        elif d.evidence and all(e.signal in ("header", "cookie", "meta") for e in d.evidence):
            hdrs = {e.location.lower() for e in d.evidence if e.signal == "header"}
            d.layer = "origin"
            if proxied and hdrs and not (hdrs & leak_headers or "server" in hdrs):
                d.layer = "edge"
        elif any(e.signal in APP_SIGNALS for e in d.evidence):
            d.layer = "app"


def mark_disputed(dets: list[Detection], anomalies: list[dict]) -> None:
    for a in anomalies:
        if a["tier"] != "contradiction":
            continue
        involved = {x.lower() for x in a.get("involves", [])}
        for d in dets:
            if d.status == "implied":
                continue
            sig = [e for e in d.evidence if e.signal in ("header", "cookie")]
            if sig and len(sig) == len(d.evidence) and any(e.location.lower() in involved for e in sig):
                d.status = "disputed"
                d.confidence = min(d.confidence, 40)
                d.notes.append(f"disputed: {a['title']} ({a['why'][:90]})")


def corroborate_favicon(dets: list[Detection], fav: dict) -> list[str]:
    hit: list[str] = []
    for m in fav.get("matches", []):
        for d in dets:
            if d.status in ("implied", "disputed") or not _names_match(d.name, m["name"]):
                continue
            if any(e.signal.startswith("favicon") for e in d.evidence):
                continue
            d.evidence.append(Evidence("favicon", "favicon-mmh3", trunc(fav.get("url", "favicon"), 90),
                                       trunc(f"mmh3 {fav.get('mmh3')} = {m['name']}", 100), "database match", 20, None, "n/a",
                                       "+".join(m.get("sources", [])) or "favicon-db"))
            _recompute(d)
            hit.append(d.name)
    return hit


def corroborate_banners(dets: list[Detection], banners: list[dict], tdb: TechDB | None = None) -> None:
    for b in banners:
        if not b.get("library") or not b.get("version"):
            continue
        ev = Evidence("bundle", "banner", trunc(b.get("script", "bundle"), 90), trunc(b["text"], 100),
                      "copyright/version comment", 80, b["version"], "raw", "bundle-scan")
        if tdb is not None and not any(_names_match(d.name, b["library"]) for d in dets):
            exact = next((n for n in tdb.techs if _norm(n) == _norm(b["library"])), None)
            if exact:      # the library announces itself in the served bundle: a first-hand signal
                dets.append(tdb.new_detection(exact, [ev]))
                continue
        for d in dets:
            if d.status == "implied" or not _names_match(d.name, b["library"]):
                continue
            if any(e.signal == "banner" and e.location == b.get("script") for e in d.evidence):
                continue
            d.evidence.append(Evidence("bundle", "banner", trunc(b.get("script", "bundle"), 90), trunc(b["text"], 100),
                                       "copyright/version comment", 40, b["version"], "raw", "bundle-scan"))
            _recompute(d)


def build_surface(rep: dict) -> dict:
    sh = rep["security_headers"]
    passed = sum(1 for f in sh if f["status"] == "pass")
    visible = [d for d in rep["technologies"] if d["status"] in ("confirmed", "probable", "disputed")]
    tls = rep.get("tls") or {}
    http = rep.get("http") or {}
    if rep["target"].get("scheme") != "https":
        tls_state, tls_label = "bad", "none"
    elif tls.get("error"):
        tls_state, tls_label = "warn", "error"
    else:
        v = (tls.get("tls_version") or "?").replace("TLSv", "")
        tls_label = f"{v} {http.get('summary') or '?'}"
        tls_state = "warn" if (tls.get("verified") is False or any(f["severity"] in ("high", "medium") for f in rep.get("tls_findings", []))) else "ok"
    libs = rep.get("libraries") or {}
    risks = libs.get("total_advisories", 0)
    edge = rep.get("edge") or {}
    tp = rep.get("third_party") or {}
    hyg = rep.get("hygiene") or {}
    cookies = hyg.get("cookies") or {}
    stx = hyg.get("security_txt") or {}
    anoms = rep.get("anomalies", [])
    disputed = [d for d in rep["technologies"] if d["status"] == "disputed"]
    return {
        "tech": {"count": len(visible), "state": "ok" if visible else "na"},
        "headers": {"passed": passed, "total": len(sh), "state": "ok" if passed == len(sh) else "warn" if passed >= 3 else "bad"},
        "csp": {"grade": (rep.get("csp") or {}).get("grade"), "enforced": (rep.get("csp") or {}).get("enforced", False)},
        "tls": {"label": tls_label, "state": tls_state},
        "js": {"libraries": len(libs.get("libraries", [])), "advisories": risks,
               "maps_exposed": sum(1 for m in (rep.get("bundle") or {}).get("source_maps", []) if m.get("status") in ("exposed", "inline")),
               "state": "warn" if (risks or any(m.get("status") in ("exposed", "inline") for m in (rep.get("bundle") or {}).get("source_maps", []))) else "ok"},
        "edge": {"names": [e["name"] for e in edge.get("edges", [])], "leaks": len(edge.get("origin_leaks", [])),
                 "state": "warn" if edge.get("origin_leaks") else "ok"},
        "third_party": {"origins": tp.get("origins", 0), "without_sri": tp.get("scripts_without_sri", 0) + tp.get("styles_without_sri", 0),
                        "state": "warn" if (tp.get("scripts_without_sri", 0) + tp.get("styles_without_sri", 0) + tp.get("insecure_requests", 0)) else "ok"},
        "hygiene": {"cookies": cookies.get("total", 0), "at_risk": cookies.get("session_cookies_at_risk", 0),
                    "security_txt": stx.get("status"),
                    "state": "warn" if (cookies.get("session_cookies_at_risk", 0) or stx.get("status") in ("missing", "weak")) else "ok"},
        "anomalies": {"layered": sum(1 for a in anoms if a["tier"] == "layered"),
                      "contradictions": sum(1 for a in anoms if a["tier"] == "contradiction"), "disputed": len(disputed)},
    }


def build_report(*, target: str, snap, dets: list[Detection], tech_stats: dict, anomalies: list[dict], favicon: dict,
                 sec: list, csp: dict, tls: dict | None, tls_findings: list, http: dict, bundle: dict, libs: dict,
                 edge: dict, third_party: dict, cookies: dict, security_txt, dns: dict | None, db, tdb, duration_ms: int,
                 warnings: list[str], backend: str, regex_stats: dict, engine: str, leak_headers: set[str]) -> dict:
    fav_hits = corroborate_favicon(dets, favicon)
    corroborate_banners(dets, bundle.get("banners", []), tdb)
    mark_disputed(dets, anomalies)
    attribute_layers(dets, edge, leak_headers)
    dets.sort(key=lambda d: (-d.confidence, d.name.lower()))
    visible = [d.to_dict() for d in dets if d.status in VISIBLE]
    weak = [d.to_dict() for d in dets if d.status == "weak"]
    favicon = dict(favicon)
    favicon["corroborates"] = fav_hits

    stx = security_txt.to_dict()
    stx["status"] = security_txt.status
    meta = db.meta.get("technologies", {}) if db.meta else {}
    rep: dict = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "generated_at": utcnow_iso(),
        "duration_ms": duration_ms,
        "target": {"input": target, "url": snap.url, "final_url": snap.final_url, "status": snap.status,
                   "scheme": snap.scheme, "title": snap.title, "mode": snap.mode, "partial": snap.partial,
                   "error": snap.error, "server_ip": snap.server_ip},
        "db": {"technologies": {"count": len(db.techs), "commit": meta.get("commit"), "built_at": meta.get("built_at"),
                                "seed": db.seed},
               "patterns": regex_stats, "regex_engine": engine, "http_backend": backend,
               "signals_evaluated": tech_stats.get("signals", {}),
               "script_rules_complete": tech_stats.get("script_rules_complete", True)},
        "technologies": visible,
        "weak": weak,
        "anomalies": anomalies,
        "favicon": favicon,
        "security_headers": [f.to_dict() for f in sec],
        "csp": csp,
        "tls": tls,
        "tls_findings": [f.to_dict() for f in tls_findings],
        "http": http,
        "bundle": bundle,
        "libraries": libs,
        "edge": edge,
        "third_party": third_party,
        "hygiene": {"cookies": cookies, "security_txt": stx},
        "dns": dns or {},
        "drift": None,
        "requests": {"page_load": "browser (Chromium)" if snap.mode == "browser" else "single static GET",
                     "extra": list(snap.extra_requests), "extra_count": len(snap.extra_requests),
                     "network_requests_observed": len([r for r in snap.requests if r.observed])},
        "warnings": warnings + snap.warnings + db.notes,
    }
    rep["summary"] = build_surface(rep)
    return rep
