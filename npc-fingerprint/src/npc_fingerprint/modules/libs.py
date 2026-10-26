"""Extra 1: client-side library risk (offline retire.js data) - version-based, evidence-backed.

Versions come from four independent places: the running page (JS globals), script URLs, file names and
banner comments. A library is only reported when a version was actually evidenced; implied libraries never
produce advisories. The result is "this version is in a known-vulnerable range", not "this site is exploitable".
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..fetch.snapshot import PageSnapshot
from ..regexcompat import compile_body, run
from ..util import cmp_version, trunc

VERSION_RX = r"[0-9][0-9.a-z_\\-]+"
_CHAIN = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$")
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
PRIORITY = {"js-global": 4, "banner": 3, "script-url": 2, "filename": 2}


def clean_version(v: str) -> str:
    """The retire.js version token is greedy ([0-9][0-9.a-z_-]+), so file names like jquery-1.12.4.min.js yield
    '1.12.4.min'. Strip file-name residue so versions compare and conflict-check correctly."""
    v = re.sub(r"(?:\.min)?(?:\.(?:js|css))?$", "", v, flags=re.I)
    return v.rstrip(".-_")


class RetireDB:
    def __init__(self, raw: dict):
        self.raw = {k: v for k, v in raw.items() if isinstance(v, dict)}

    def func_chains(self) -> list[str]:
        """Only plain property chains are ever evaluated in the page; DB strings are never executed as code."""
        out: list[str] = []
        for lib in self.raw.values():
            for f in (lib.get("extractors") or {}).get("func", []) or []:
                if isinstance(f, str) and _CHAIN.match(f) and f not in out:
                    out.append(f)
        return out

    def _rx(self, pattern: str):
        return compile_body(pattern.replace("§§version§§", VERSION_RX))

    def extract(self, snap: PageSnapshot) -> list[dict]:
        found: list[dict] = []
        urls = [s.url for s in snap.scripts if s.url]
        texts = []
        for s in snap.scripts:
            blob = b"".join(x for x in (s.head, s.tail) if x)
            if blob:
                texts.append((s.url or "script", blob.decode("utf-8", "replace")))
            elif s.text and not s.url:
                texts.append(("inline script", s.text[:600]))
        for lib, d in self.raw.items():
            ex = d.get("extractors") or {}
            for chain in ex.get("func", []) or []:
                v = snap.js_values.get(chain)
                if v and re.match(VERSION_RX, v):
                    found.append({"library": lib, "version": clean_version(v), "basis": "js-global", "location": chain, "matched": v})
            for pat in ex.get("uri", []) or []:
                rx = self._rx(pat)
                for u in urls:
                    m = rx and run(rx, u)
                    if m and m.groups():
                        found.append({"library": lib, "version": clean_version(m.group(1)), "basis": "script-url", "location": trunc(u, 120), "matched": trunc(m.group(0), 80)})
            for pat in ex.get("filename", []) or []:
                rx = self._rx(pat)
                for u in urls:
                    name = urlsplit(u).path.rsplit("/", 1)[-1]
                    m = rx and run(rx, name)
                    if m and m.groups():
                        found.append({"library": lib, "version": clean_version(m.group(1)), "basis": "filename", "location": trunc(u, 120), "matched": trunc(name, 80)})
            for pat in ex.get("filecontent", []) or []:
                rx = self._rx(pat)
                for label, t in texts:
                    m = rx and run(rx, t)
                    if m and m.groups():
                        found.append({"library": lib, "version": clean_version(m.group(1)), "basis": "banner", "location": trunc(label, 120), "matched": trunc(m.group(0), 80)})
        return found

    def advisories(self, lib: str, version: str) -> list[dict]:
        out = []
        for v in self.raw.get(lib, {}).get("vulnerabilities", []) or []:
            lo, hi = v.get("atOrAbove"), v.get("below")
            if hi is None and lo is None:
                continue
            ok = True
            if lo is not None:
                c = cmp_version(version, lo)
                ok = ok and c is not None and c >= 0
            if hi is not None:
                c = cmp_version(version, hi)
                ok = ok and c is not None and c < 0
            if ok:
                ids = v.get("identifiers") or {}
                out.append({"severity": v.get("severity", "medium"),
                            "ids": [i for k in ("CVE", "githubID", "issue", "bug") for i in (ids.get(k) if isinstance(ids.get(k), list) else [ids.get(k)] if ids.get(k) else [])][:6],
                            "summary": trunc(ids.get("summary", ""), 100),
                            "range": (f">={lo} " if lo else "") + (f"<{hi}" if hi else ""),
                            "info": (v.get("info") or [])[:2]})
        return out


def analyze(snap: PageSnapshot, db: RetireDB) -> dict:
    ev = db.extract(snap)
    by_lib: dict[str, list[dict]] = {}
    for e in ev:
        by_lib.setdefault(e["library"], []).append(e)
    libs = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for lib, items in sorted(by_lib.items()):
        items.sort(key=lambda e: -PRIORITY.get(e["basis"], 1))
        chosen = items[0]["version"]
        versions = sorted({e["version"] for e in items})
        adv = db.advisories(lib, chosen)
        for a in adv:
            counts[a["severity"] if a["severity"] in counts else "medium"] += 1
        libs.append({"library": lib, "version": chosen, "versions_seen": versions,
                     "conflict": len(versions) > 1, "evidence": items[:6],
                     "advisories": sorted(adv, key=lambda a: -SEVERITY_ORDER.get(a["severity"], 0)),
                     "confidence": 100 if any(e["basis"] == "js-global" for e in items) or len(items) > 1 else 85})
    total = sum(counts.values())
    return {"libraries": libs, "advisory_counts": counts, "total_advisories": total,
            "note": "version-based match against known-vulnerable ranges; exploitability is not verified"}
