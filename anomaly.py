"""Module 2: conflicting identity headers -> possible spoofing. The anti-false-positive layer.

Two tiers (see data/anomaly_rules.toml): `layered` is plausible behind reverse proxies and multi-backend
setups; `contradiction` is something one honest stack cannot produce. Only contradictions cause a
technology to be marked "disputed".
"""
from __future__ import annotations

import re
import tomllib
from importlib import resources

from ..fetch.snapshot import PageSnapshot, parse_set_cookie
from ..util import cmp_version, trunc

_RULES: dict | None = None
_EDGE: dict | None = None


def rules() -> dict:
    global _RULES
    if _RULES is None:
        _RULES = tomllib.loads(resources.files("npc_fingerprint").joinpath("data", "anomaly_rules.toml").read_text("utf-8"))
    return _RULES


def edge_rules() -> dict:
    global _EDGE
    if _EDGE is None:
        _EDGE = tomllib.loads(resources.files("npc_fingerprint").joinpath("data", "edge_rules.toml").read_text("utf-8"))
    return _EDGE


def _claims(snap: PageSnapshot) -> dict[str, list[str]]:
    """runtime id -> evidence strings, from identity headers and cookie names."""
    claims: dict[str, list[str]] = {}
    cookie_names = {parse_set_cookie(c)["name"].lower() for c in snap.set_cookie_headers()}
    cookie_names |= {str(c.get("name", "")).lower() for c in snap.cookies_jar}
    for rt in rules().get("runtime", []):
        for sig in rt["signals"]:
            kind, _, rest = sig.partition(":")
            if kind == "header":
                name, _, rx = rest.partition(":")
                for v in snap.header_values(name):
                    if re.search(rx, v, re.I):
                        claims.setdefault(rt["id"], []).append(f"header {name}: {trunc(v, 50)}")
            elif kind == "cookie" and rest in cookie_names:
                claims.setdefault(rt["id"], []).append(f"cookie {rest}")
    return claims


def _has_proxy_evidence(snap: PageSnapshot, edge: dict | None) -> bool:
    if edge and edge.get("edges"):
        return True
    names = {k.lower() for k, _ in snap.headers}
    return any(h in names for h in edge_rules().get("proxy_evidence", {}).get("headers", []))


def analyze(snap: PageSnapshot, edge: dict | None, observed_protocol: str | None) -> list[dict]:
    out: list[dict] = []
    R = rules()
    proxied = _has_proxy_evidence(snap, edge)

    # 1. singleton headers repeated with different values -------------------------------------------
    for name in R.get("singletons", {}).get("headers", []):
        vals = snap.header_values(name)
        if len(vals) > 1 and len({v.strip().lower() for v in vals}) > 1:
            out.append({"id": f"duplicate-{name}", "tier": "layered", "title": f"two different {name} headers",
                        "why": "usually two proxy layers each adding their own value; the first/last may not be the origin's",
                        "evidence": [f"{name}: {trunc(v, 60)}" for v in vals], "involves": [name]})

    # 2. more than one application runtime claimed ---------------------------------------------------------
    claims = _claims(snap)
    if len(claims) > 1:
        labels = {rt["id"]: rt["label"] for rt in R.get("runtime", [])}
        ev = [f"{labels[k]}: {e}" for k, v in claims.items() for e in v]
        out.append({"id": "multiple-runtimes", "tier": "layered",
                    "title": "claims " + " + ".join(labels[k] for k in claims),
                    "why": "one app server rarely runs several runtimes; expect a reverse proxy in front of different backends, or spoofed headers",
                    "evidence": ev, "involves": ["x-powered-by", "server", "cookie"]})

    # 3. server version cannot speak the protocol we observed ---------------------------------------------
    server_hdr = snap.header("server") or ""
    ident = None
    for s in R.get("server", []):
        m = re.search(s["pattern"], server_hdr, re.I)
        if m:
            ident = (s["id"], m.group(1) if m.groups() else None)
            break
    if ident and ident[1] and observed_protocol:
        for cap in R.get("capability", []):
            if cap["server"] == ident[0] and cap["protocol"] == observed_protocol:
                c = cmp_version(ident[1], cap["min_version"])
                if c is not None and c < 0:
                    tier = "layered" if proxied else "contradiction"
                    out.append({"id": f"capability-{cap['server']}-{cap['protocol']}", "tier": tier,
                                "title": f"Server claims {ident[0]} {ident[1]} but {cap['protocol']} was negotiated",
                                "why": cap["why"] + (". A proxy/CDN may be terminating the connection and relaying the origin's Server header."
                                                     if proxied else ". No proxy evidence was found, so this claim is implausible."),
                                "evidence": [f"server: {trunc(server_hdr, 60)}", f"observed protocol: {observed_protocol}"],
                                "involves": ["server"]})

    # 4. edge always rewrites a header it did not rewrite ----------------------------------------------------
    names = {k.lower() for k, _ in snap.headers}
    for ow in R.get("overwrite", []):
        if ow["when_header"] in names:
            vals = snap.header_values(ow["header"])
            if vals and not any(re.search(ow["expected"], v, re.I) for v in vals):
                out.append({"id": f"overwrite-{ow['header']}", "tier": "contradiction",
                            "title": f"{ow['when_header']} present but {ow['header']} is {trunc(vals[0], 30)}",
                            "why": ow["why"],
                            "evidence": [f"{ow['when_header']}: present", f"{ow['header']}: {trunc(vals[0], 60)}"],
                            "involves": [ow["header"]]})
    return out
