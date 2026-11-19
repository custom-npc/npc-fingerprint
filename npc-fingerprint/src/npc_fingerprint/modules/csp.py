"""Extra 2: Content-Security-Policy quality grading (beyond present/missing)."""
from __future__ import annotations

import re

from ..fetch.snapshot import PageSnapshot
from ..util import trunc

# Hosts commonly cited as allow-list bypasses (JSONP / user-controllable content). Matched as suffixes.
BYPASS_HOSTS = ("googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "cloudfront.net",
                "amazonaws.com", "raw.githubusercontent.com", "herokuapp.com", "appspot.com", "firebaseapp.com",
                "accounts.google.com", "ajax.aspnetcdn.com")
KEYWORDS = {"'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", "'unsafe-hashes'",
            "'wasm-unsafe-eval'", "'report-sample'"}


def parse(value: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in value.split(";"):
        toks = part.strip().split()
        if not toks:
            continue
        name = toks[0].lower()
        if name not in out:               # first occurrence wins, per the CSP spec
            out[name] = toks[1:]
    return out


def _hosts(sources: list[str]) -> list[str]:
    hosts = []
    for s in sources:
        sl = s.lower()
        if sl in KEYWORDS or sl.startswith(("'nonce-", "'sha")) or sl.endswith(":") or sl == "*":
            continue
        h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", sl).split("/")[0].split(":")[0]
        if h and "." in h or h.startswith("*."):
            hosts.append(h)
    return hosts


def _grade_one(d: dict[str, list[str]]) -> dict:
    score, issues = 100, []

    def hit(sev: str, directive: str, msg: str, pts: int) -> None:
        nonlocal score
        issues.append({"severity": sev, "directive": directive, "issue": msg})
        score -= pts

    script = d.get("script-src") or d.get("default-src")
    sname = "script-src" if "script-src" in d else "default-src"
    if script is None:
        hit("high", "script-src", "no script-src or default-src: scripts are not restricted", 40)
    else:
        low = [t.lower() for t in script]
        nonce_hash = any(t.startswith(("'nonce-", "'sha")) for t in low)
        strict = "'strict-dynamic'" in low
        guarded = nonce_hash or strict
        if "'unsafe-inline'" in low and not guarded:
            hit("high", sname, "'unsafe-inline' lets injected inline scripts run", 35)
        if "'unsafe-eval'" in low:
            hit("medium", sname, "'unsafe-eval' allows eval()-style code execution", 20)
        if "*" in low:
            hit("high", sname, "wildcard source allows scripts from anywhere", 40)
        if "http:" in low:
            hit("high", sname, "http: scheme allows scripts over plain HTTP", 30)
        if "https:" in low and not strict:
            hit("medium", sname, "https: scheme allows scripts from any HTTPS host", 20)
        if "data:" in low:
            hit("high", sname, "data: URIs can carry executable script", 30)
        if any(t.startswith("http://") for t in low):
            hit("medium", sname, "an allowed script source uses plain HTTP", 10)
        if not guarded:
            wild = [h for h in _hosts(low) if h.startswith("*.")]
            if wild:
                hit("low", sname, f"broad wildcard host {wild[0]}", min(10, 5 * len(wild)))
            bad = [h for h in _hosts(low) if any(h == b or h.endswith("." + b) or h.lstrip("*.") == b for b in BYPASS_HOSTS)]
            if bad:
                hit("medium", sname, f"allowed host {bad[0]} serves user-controllable/JSONP content", min(30, 15 * len(bad)))
    obj = d.get("object-src") or d.get("default-src")
    if obj is None:
        hit("medium", "object-src", "object-src not restricted (plugin content)", 10)
    if "base-uri" not in d:
        hit("low", "base-uri", "base-uri missing: an injected <base> can redirect relative script URLs", 5)
    if "frame-ancestors" not in d:
        hit("low", "frame-ancestors", "frame-ancestors missing: clickjacking relies on X-Frame-Options", 5)
    score = max(0, score)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
    return {"score": score, "grade": grade, "issues": issues}


def analyze(snap: PageSnapshot) -> dict:
    enforced = [v for v in snap.header_values("content-security-policy") if v.strip()]
    report_only = [v for v in snap.header_values("content-security-policy-report-only") if v.strip()]
    meta_csp = [c for n, c in snap.meta if n == "content-security-policy" and c.strip()]
    res: dict = {"present": False, "enforced": False, "report_only": bool(report_only), "grade": None, "score": None,
                 "issues": [], "directives": [], "hosts": [], "policies": 0, "via_meta": False}
    pols = enforced or meta_csp
    if not pols:
        if report_only:
            g = _grade_one(parse(report_only[0]))
            res["report_only_grade"] = g["grade"]
        return res
    res.update(present=True, enforced=True, policies=len(pols), via_meta=not enforced)
    graded = [(_grade_one(parse(p)), parse(p)) for p in pols]
    best, d = max(graded, key=lambda x: x[0]["score"])   # every policy must be bypassed, so the strongest governs
    res.update(grade=best["grade"], score=best["score"], issues=best["issues"], directives=sorted(d.keys()))
    hosts: list[str] = []
    for name in ("default-src", "script-src", "script-src-elem", "connect-src", "frame-src", "img-src"):
        for h in _hosts(d.get(name, [])):
            if h not in hosts:
                hosts.append(h)
    res["hosts"] = hosts[:40]
    if "frame-ancestors" in d:
        res["frame_ancestors"] = trunc(" ".join(d["frame-ancestors"]), 100)
    if res["via_meta"]:
        res["issues"].append({"severity": "low", "directive": "meta", "issue": "delivered via <meta>: frame-ancestors and report-uri are ignored there"})
    return res
