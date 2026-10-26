"""Extra 3: edge-versus-origin attribution.

Separates what the CDN/WAF/proxy says about itself from what the origin leaks through it, so
`Server: cloudflare` is not misreported as "the web server" and origin banners seen through an edge are
flagged as leaks.
"""
from __future__ import annotations

import re

from ..fetch.snapshot import PageSnapshot, parse_set_cookie
from .anomaly import edge_rules

WEIGHTS = {"header": 90, "header-value": 90, "cookie": 60, "cname": 60, "ns": 40}


def _suffix(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def analyze(snap: PageSnapshot, dns: dict | None) -> dict:
    R = edge_rules()
    names = {k.lower() for k, _ in snap.headers}
    cookies = {parse_set_cookie(c)["name"].lower() for c in snap.set_cookie_headers()}
    cookies |= {str(c.get("name", "")).lower() for c in snap.cookies_jar}
    cnames = (dns or {}).get("CNAME", [])
    nss = (dns or {}).get("NS", [])
    edges = []
    for e in R.get("edge", []):
        ev: list[tuple[str, str]] = []
        for h in e.get("headers", []):
            if h in names:
                ev.append(("header", f"header {h} present"))
        for hv in e.get("header_values", []):
            name, _, rx = hv.partition(":")
            for v in snap.header_values(name):
                if re.search(rx, v, re.I):
                    ev.append(("header-value", f"{name}: {v[:50]}"))
                    break
        for c in e.get("cookies", []):
            pre = c.endswith("*")
            for ck in cookies:
                if (ck.startswith(c[:-1]) if pre else ck == c):
                    ev.append(("cookie", f"cookie {ck}"))
                    break
        for suf in e.get("cname", []):
            hit = next((c for c in cnames if _suffix(c, suf)), None)
            if hit:
                ev.append(("cname", f"CNAME -> {hit}"))
                break
        for suf in e.get("ns", []):
            hit = next((n for n in nss if _suffix(n, suf)), None)
            if hit:
                ev.append(("ns", f"NS {hit}"))
                break
        if not ev:
            continue
        conf = min(100, sum(WEIGHTS[k] for k, _ in ev))
        if conf >= 50:
            edges.append({"id": e["id"], "name": e["name"], "kind": e["kind"], "confidence": conf, "evidence": [t for _, t in ev]})
    edges.sort(key=lambda x: -x["confidence"])

    leaks = []
    if edges:
        edge_server = any(re.search(hv.partition(":")[2], v, re.I) for e in R.get("edge", []) if e["id"] in {x["id"] for x in edges}
                          for hv in e.get("header_values", []) if hv.startswith("server:") for v in snap.header_values("server"))
        for h in R.get("origin_leaks", {}).get("headers", []):
            for v in snap.header_values(h):
                leaks.append({"header": h, "value": v[:80], "why": "origin application detail visible through the edge"})
        if not edge_server:
            for v in snap.header_values("server"):
                leaks.append({"header": "server", "value": v[:80], "why": "origin server banner passes through the edge"})
    proxied = bool(edges) or any(h in names for h in R.get("proxy_evidence", {}).get("headers", []))
    chain = ["client"] + [e["name"] for e in edges[:2]] + ["origin"] if edges else (["client", "proxy/cache (unidentified)", "origin"] if proxied else ["client", "origin"])
    return {"edges": edges, "origin_leaks": leaks, "proxied": proxied, "layers": " → ".join(chain),
            "dns_used": bool(dns)}
