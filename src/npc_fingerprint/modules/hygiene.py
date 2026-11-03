"""Extra 5: cookie hygiene + security.txt (RFC 9116).

Cookie *values* are never stored or printed; only names and attributes.
"""
from __future__ import annotations

import datetime as dt
import re

from ..fetch.snapshot import PageSnapshot, parse_set_cookie
from ..model import Finding
from ..util import origin_of, trunc

SESSION_LIKE = re.compile(r"(sess|sid\b|auth|token|jwt|login|remember|csrf|xsrf)", re.I)


def audit_cookies(snap: PageSnapshot) -> dict:
    https = snap.scheme == "https"
    cookies: dict[str, dict] = {}
    for raw in snap.set_cookie_headers():
        c = parse_set_cookie(raw)
        if c["name"]:
            c["js_set"] = False
            cookies.setdefault(c["name"], c)
    for j in snap.cookies_jar:           # JS-set cookies (and ones the jar normalised) that no header announced
        name = str(j.get("name", ""))
        if name and name not in cookies:
            cookies[name] = {"name": name, "secure": bool(j.get("secure")), "httponly": bool(j.get("httpOnly")),
                             "samesite": j.get("sameSite") if j.get("sameSite") not in (None, "") else None,
                             "domain": j.get("domain"), "path": j.get("path"), "js_set": True}
    out = []
    counts = {"missing_secure": 0, "missing_httponly": 0, "missing_samesite": 0, "prefix_violations": 0}
    for name, c in sorted(cookies.items()):
        issues: list[str] = []
        sess = bool(SESSION_LIKE.search(name))
        sev = "medium" if sess else "low"
        if https and not c["secure"]:
            issues.append("no Secure flag")
            counts["missing_secure"] += 1
        if not c["httponly"] and not c.get("js_set"):
            issues.append("no HttpOnly flag (readable by page scripts)")
            counts["missing_httponly"] += 1
        ss = (c.get("samesite") or "").lower()
        if not ss and not c.get("js_set"):
            issues.append("no SameSite (browser default applies)")
            counts["missing_samesite"] += 1
        if ss == "none" and not c["secure"]:
            issues.append("SameSite=None without Secure")
        low = name.lower()
        if low.startswith("__host-") and (not c["secure"] or (c.get("path") or "/") != "/" or c.get("domain")):
            issues.append("__Host- prefix rules violated (needs Secure, Path=/, no Domain)")
            counts["prefix_violations"] += 1
        elif low.startswith("__secure-") and not c["secure"]:
            issues.append("__Secure- prefix without Secure")
            counts["prefix_violations"] += 1
        out.append({"name": trunc(name, 60), "session_like": sess, "secure": c["secure"], "httponly": c["httponly"],
                    "samesite": c.get("samesite"), "js_set": c.get("js_set", False), "issues": issues,
                    "severity": sev if issues else "info"})
    risky = [c for c in out if c["issues"] and c["session_like"]]
    return {"total": len(out), "cookies": out[:40], "counts": counts, "session_cookies_at_risk": len(risky),
            "note": "Secure is not applicable over plain HTTP" if not https and out else None}


# ----------------------------------------------------------------------------
# security.txt
# ----------------------------------------------------------------------------

def parse_security_txt(text: str) -> dict:
    signed = text.lstrip().startswith("-----BEGIN PGP SIGNED MESSAGE-----")
    if signed:
        lines, body, in_body = text.splitlines(), [], False
        for ln in lines:
            if not in_body:
                if ln.strip() == "":
                    in_body = True
                continue
            if ln.startswith("-----BEGIN PGP SIGNATURE-----"):
                break
            body.append(ln)
        text = "\n".join(body)
    fields: dict[str, list[str]] = {}
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z][A-Za-z-]*):\s*(.+)$", ln)
        if m:
            fields.setdefault(m.group(1).lower(), []).append(m.group(2).strip())
    return {"fields": fields, "signed": signed}


def check_security_txt(snap: PageSnapshot, fetcher) -> Finding:
    title = "security.txt"
    if fetcher is None:
        return Finding("hygiene", "security-txt", title, "n/a", "info", "not checked (no fetcher)")
    url = origin_of(snap.final_url) + "/.well-known/security.txt"
    r = fetcher.get(url, max_bytes=65536)
    snap.extra_requests.append("security.txt")
    if not r.ok:
        return Finding("hygiene", "security-txt", title, "n/a", "info", trunc(f"could not be fetched: {r.error}", 100))
    ctype = (r.header("content-type") or "").lower()
    body = r.body.decode("utf-8", "replace")
    if r.status != 200 or "html" in ctype or body.lstrip()[:1] == "<":
        return Finding("hygiene", "security-txt", title, "missing", "low",
                       "no /.well-known/security.txt: researchers have no declared disclosure contact", {"http_status": r.status})
    p = parse_security_txt(body)
    f = p["fields"]
    if "contact" not in f or "expires" not in f:
        miss = [k for k in ("Contact", "Expires") if k.lower() not in f]
        return Finding("hygiene", "security-txt", title, "weak", "low", f"present but invalid: missing {' and '.join(miss)} (RFC 9116)")
    try:
        exp = dt.datetime.fromisoformat(f["expires"][0].replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=dt.timezone.utc)
        days = (exp - dt.datetime.now(dt.timezone.utc)).days
    except ValueError:
        return Finding("hygiene", "security-txt", title, "weak", "low", "present but Expires is not a valid ISO 8601 date")
    data = {"contact": [trunc(c, 80) for c in f["contact"][:3]], "expires_in_days": days, "signed": p["signed"],
            "https": r.url.startswith("https://")}
    if days < 0:
        return Finding("hygiene", "security-txt", title, "weak", "low", f"expired {-days} day(s) ago: contact details may be stale", data)
    notes = [] if data["https"] else ["served over HTTP (RFC 9116 requires HTTPS)"]
    return Finding("hygiene", "security-txt", title, "pass" if data["https"] else "weak", "info" if data["https"] else "low",
                   f"present, expires in {days}d" + (", signed" if p["signed"] else "") + (f"; {notes[0]}" if notes else ""), data)
