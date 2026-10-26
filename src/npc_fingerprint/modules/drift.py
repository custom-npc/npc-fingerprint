"""Extra 6: baseline drift. Compare a fresh report against a previous --json report."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

VISIBLE = ("confirmed", "probable", "disputed")


def _key(url: str) -> str:
    p = urlsplit(url or "")
    return f"{p.scheme.lower()}://{(p.hostname or '').lower()}{(p.path or '/').rstrip('/') or '/'}"


def _host_key(url: str) -> str:
    return (urlsplit(url or "").hostname or "").lower()


def load_baseline(path: str) -> dict:
    """Return {"meta": {...}, "reports": {key: report}} from a single report, a list, or the wrapped format."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "reports" in data:
        reports, meta = data["reports"], {k: data.get(k) for k in ("generated_at", "version", "db")}
    elif isinstance(data, list):
        reports, meta = data, {}
    else:
        reports, meta = [data], {}
    return {"meta": meta, "reports": reports}


def pick(baseline: dict, target_url: str, final_url: str) -> dict | None:
    for r in baseline["reports"]:
        t = r.get("target", {})
        if _key(t.get("final_url", "")) in (_key(final_url), _key(target_url)) or _key(t.get("url", "")) in (_key(final_url), _key(target_url)):
            return r
    for r in baseline["reports"]:   # fall back to host match
        t = r.get("target", {})
        if _host_key(t.get("final_url") or t.get("url")) == _host_key(final_url):
            return r
    return None


def _techs(rep: dict) -> tuple[dict, dict]:
    vis = {d["name"]: d for d in rep.get("technologies", []) if d.get("status") in VISIBLE}
    weak = {d["name"]: d for d in rep.get("weak", [])}
    return vis, weak


def diff(cur: dict, old: dict, meta: dict | None = None) -> dict:
    changes: list[dict] = []

    def add(area: str, kind: str, subject: str, frm=None, to=None) -> None:
        changes.append({"area": area, "kind": kind, "subject": subject, "from": frm, "to": to})

    cv, cw = _techs(cur)
    ov, ow = _techs(old)
    for n in sorted(cv.keys() - ov.keys()):
        add("technology", "noise" if n in ow else "added", n, None, cv[n].get("version"))
    for n in sorted(ov.keys() - cv.keys()):
        add("technology", "noise" if n in cw else "removed", n, ov[n].get("version"), None)
    for n in sorted(cv.keys() & ov.keys()):
        if (cv[n].get("version") or None) != (ov[n].get("version") or None):
            add("technology", "changed", n, ov[n].get("version"), cv[n].get("version"))
        if cv[n].get("status") == "disputed" and ov[n].get("status") != "disputed":
            add("technology", "changed", f"{n} (status)", ov[n].get("status"), "disputed")

    oh = {f["id"]: f for f in old.get("security_headers", [])}
    for f in cur.get("security_headers", []):
        o = oh.get(f["id"])
        if o and o["status"] != f["status"]:
            add("headers", "changed", f["title"], o["status"], f["status"])
    oc, cc = (old.get("csp") or {}).get("grade"), (cur.get("csp") or {}).get("grade")
    if oc != cc:
        add("csp", "changed", "CSP grade", oc, cc)

    ot, ct = old.get("tls") or {}, cur.get("tls") or {}
    ocert, ccert = ot.get("cert") or {}, ct.get("cert") or {}
    if ocert.get("sha256") and ccert.get("sha256") and ocert["sha256"] != ccert["sha256"]:
        add("tls", "changed", "certificate rotated", ocert["sha256"][:12], ccert["sha256"][:12])
    if ocert.get("issuer") != ccert.get("issuer") and ocert.get("issuer") and ccert.get("issuer"):
        add("tls", "changed", "certificate issuer", ocert.get("issuer"), ccert.get("issuer"))
    if ot.get("tls_version") != ct.get("tls_version") and ot.get("tls_version") and ct.get("tls_version"):
        add("tls", "changed", "TLS version", ot.get("tls_version"), ct.get("tls_version"))
    oht, cht = (old.get("http") or {}).get("summary"), (cur.get("http") or {}).get("summary")
    if oht != cht and oht and cht:
        add("http", "changed", "HTTP protocol", oht, cht)

    of, cf = old.get("favicon") or {}, cur.get("favicon") or {}
    if of.get("mmh3") is not None and cf.get("mmh3") is not None and of["mmh3"] != cf["mmh3"]:
        add("favicon", "changed", "favicon hash", of["mmh3"], cf["mmh3"])

    ol = {l["library"]: l for l in (old.get("libraries") or {}).get("libraries", [])}
    cl = {l["library"]: l for l in (cur.get("libraries") or {}).get("libraries", [])}
    for n in sorted(cl.keys() - ol.keys()):
        add("libraries", "added", n, None, cl[n]["version"])
    for n in sorted(ol.keys() - cl.keys()):
        add("libraries", "removed", n, ol[n]["version"], None)
    for n in sorted(cl.keys() & ol.keys()):
        if cl[n]["version"] != ol[n]["version"]:
            add("libraries", "changed", n, ol[n]["version"], cl[n]["version"])

    oe = {e["name"] for e in (old.get("edge") or {}).get("edges", [])}
    ce = {e["name"] for e in (cur.get("edge") or {}).get("edges", [])}
    for n in sorted(ce - oe):
        add("edge", "added", n)
    for n in sorted(oe - ce):
        add("edge", "removed", n)

    oo = {o["origin"] for o in (old.get("third_party") or {}).get("top", [])}
    co = {o["origin"] for o in (cur.get("third_party") or {}).get("top", [])}
    for n in sorted(co - oo):
        add("third-party", "added", n)
    for n in sorted(oo - co):
        add("third-party", "removed", n)

    summary = {k: sum(1 for c in changes if c["kind"] == k) for k in ("added", "removed", "changed", "noise")}
    return {"baseline": {"generated_at": old.get("generated_at") or (meta or {}).get("generated_at"),
                         "tool_version": (meta or {}).get("version"),
                         "db_commit": ((old.get("db") or {}).get("technologies") or {}).get("commit")},
            "summary": summary, "changes": changes}
