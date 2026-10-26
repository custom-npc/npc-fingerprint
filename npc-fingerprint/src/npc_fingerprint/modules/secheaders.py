"""Module 4: security-header analysis. Present/weak/missing/n-a with a one-line reason for each."""
from __future__ import annotations

import re

from ..fetch.snapshot import PageSnapshot
from ..model import Finding
from ..util import trunc

HSTS_MIN_AGE = 15_552_000   # ~180 days; a policy threshold, not a standard
SAFE_REFERRER = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
LEAKY_REFERRER = {"unsafe-url": "sends the full URL (path and query) to every site",
                  "no-referrer-when-downgrade": "sends the full URL to any HTTPS destination",
                  "origin": "sends the origin on every request, including cross-site",
                  "origin-when-cross-origin": "sends the full URL same-origin and the origin cross-site"}


def _f(id_: str, title: str, status: str, severity: str, reason: str, short: str | None = None, **data) -> Finding:
    """`reason` is the full one-liner (JSON, trace); `short` (<= 28 chars) is what fits the 80-column card."""
    data["short"] = trunc(short or reason, 28)
    return Finding("headers", id_, title, status, severity, trunc(reason, 110), data)


def hsts(snap: PageSnapshot) -> Finding:
    if snap.scheme != "https":
        return _f("hsts", "HSTS", "n/a", "info", "ignored over plain HTTP (the site is not served over TLS)", "n/a: plain HTTP")
    v = snap.header("strict-transport-security")
    if not v:
        return _f("hsts", "HSTS", "missing", "medium", "no HSTS: first visit and downgrade attacks stay possible", "absent: downgrade possible")
    m = re.search(r"max-age\s*=\s*\"?(\d+)", v, re.I)
    age = int(m.group(1)) if m else 0
    flags = [f for f in ("includeSubDomains", "preload") if re.search(f, v, re.I)]
    if age == 0:
        return _f("hsts", "HSTS", "weak", "medium", "max-age=0 switches HSTS off", "max-age=0 (off)", value=v)
    days = age // 86400
    if age < HSTS_MIN_AGE:
        return _f("hsts", "HSTS", "weak", "low", f"max-age {days}d is short (under 180d)", f"max-age {days}d (short)", value=v)
    return _f("hsts", "HSTS", "pass", "info", f"max-age {days}d" + (f", {', '.join(flags)}" if flags else ""), f"max-age {days}d" + (" +sub" if "includeSubDomains" in flags else "") + (" +preload" if "preload" in flags else ""), value=v)


def csp_finding(snap: PageSnapshot, csp: dict) -> Finding:
    if csp.get("enforced"):
        g, score = csp["grade"], csp["score"]
        top = csp["issues"][0]["issue"] if csp["issues"] else "no weaknesses found"
        if g in ("A", "B"):
            return _f("csp", "CSP", "pass", "info", f"grade {g} ({score}/100)" + ("" if g == "A" else f": {top}"), f"grade {g}" + ("" if g == "A" else f": {csp['issues'][0]['directive']}"), grade=g)
        sev = "high" if g in ("D", "F") else "medium"
        return _f("csp", "CSP", "weak", sev, f"grade {g}: {top}", f"grade {g}: {csp['issues'][0]['directive'] if csp['issues'] else 'weak'}", grade=g)
    if csp.get("report_only"):
        return _f("csp", "CSP", "weak", "medium", "report-only: violations are logged, nothing is blocked", "report-only: not enforced")
    return _f("csp", "CSP", "missing", "medium", "absent: no browser-enforced backstop against XSS", "absent: no XSS backstop")


def xfo(snap: PageSnapshot, csp: dict) -> Finding:
    v = snap.header("x-frame-options")
    covered = bool(csp.get("enforced") and "frame_ancestors" in csp)
    if v:
        val = v.strip().upper()
        if val in ("DENY", "SAMEORIGIN"):
            return _f("x-frame-options", "X-Frame-Options", "pass", "info", f"{val}: framing blocked", val, value=v)
        if val.startswith("ALLOW-FROM"):
            return _f("x-frame-options", "X-Frame-Options", "weak", "low", "ALLOW-FROM is obsolete; use CSP frame-ancestors", "ALLOW-FROM obsolete", value=v)
        return _f("x-frame-options", "X-Frame-Options", "weak", "low", f"unrecognised value '{trunc(v, 30)}'", value=v)
    if covered:
        return _f("x-frame-options", "X-Frame-Options", "pass", "info", "covered by CSP frame-ancestors", "via CSP frame-ancestors")
    return _f("x-frame-options", "X-Frame-Options", "missing", "medium", "page can be framed by any site (clickjacking)", "framing allowed")


def xcto(snap: PageSnapshot) -> Finding:
    v = snap.header("x-content-type-options")
    if v and v.strip().lower() == "nosniff":
        return _f("x-content-type-options", "X-Content-Type-Options", "pass", "info", "nosniff: MIME sniffing disabled", "nosniff", value=v)
    if v:
        return _f("x-content-type-options", "X-Content-Type-Options", "weak", "low", f"value '{trunc(v, 30)}' is not 'nosniff'", "not nosniff", value=v)
    return _f("x-content-type-options", "X-Content-Type-Options", "missing", "low", "browsers may MIME-sniff responses into executable types", "MIME sniffing allowed")


def referrer(snap: PageSnapshot) -> Finding:
    v = snap.header("referrer-policy")
    if not v:
        return _f("referrer-policy", "Referrer-Policy", "missing", "low", "unset: relies on the browser default (strict-origin-when-cross-origin)", "unset (browser default)")
    # the last recognised token wins (fallback syntax)
    toks = [t.strip().lower() for t in v.split(",") if t.strip()]
    eff = toks[-1] if toks else ""
    if eff in SAFE_REFERRER:
        return _f("referrer-policy", "Referrer-Policy", "pass", "info", eff, value=v)
    if eff in LEAKY_REFERRER:
        return _f("referrer-policy", "Referrer-Policy", "weak", "medium" if eff == "unsafe-url" else "low",
                  f"{eff} {LEAKY_REFERRER[eff]}", f"{eff}: leaks URL", value=v)
    return _f("referrer-policy", "Referrer-Policy", "weak", "low", f"unrecognised value '{trunc(v, 30)}'", value=v)


def permissions(snap: PageSnapshot) -> Finding:
    v = snap.header("permissions-policy")
    if v:
        n = len([p for p in v.split(",") if p.strip()])
        return _f("permissions-policy", "Permissions-Policy", "pass", "info", f"{n} feature rule(s) set", f"{n} feature rule(s)", value=trunc(v, 200))
    if snap.header("feature-policy"):
        return _f("permissions-policy", "Permissions-Policy", "weak", "low", "only the deprecated Feature-Policy header is set", "deprecated Feature-Policy")
    return _f("permissions-policy", "Permissions-Policy", "missing", "low", "no restrictions on camera, microphone, geolocation...", "no feature restrictions")


def analyze(snap: PageSnapshot, csp: dict) -> list[Finding]:
    return [hsts(snap), csp_finding(snap, csp), xfo(snap, csp), xcto(snap), referrer(snap), permissions(snap)]
