"""Module 1: baseline technology detection.

A thin, auditable matcher over the community Wappalyzer-format database (enthec/webappanalyzer). It
evaluates every signal class the format defines against what the (JS-rendered) page actually exposes and
records *which* header / cookie / selector / URL / pattern produced each match.
"""
from __future__ import annotations

import time
from collections import defaultdict

from ..fetch.snapshot import PageSnapshot, parse_set_cookie
from ..model import Detection, Evidence, band
from ..regexcompat import Hit, Pat, resolve_version, to_list
from ..util import trunc

SELF_DECLARED_HEADERS = {"server", "x-powered-by", "x-generator", "x-aspnet-version", "x-aspnetmvc-version",
                         "powered-by", "x-runtime", "x-drupal-cache"}
SCRIPT_RULE_BYTE_BUDGET = 1_500_000
SCRIPT_RULE_TIME_BUDGET = 4.0


def _ev(signal: str, location: str, hit: Hit, pat: Pat, view: str = "rendered", matched: str | None = None,
        conf: int | None = None) -> Evidence:
    return Evidence(module="tech", signal=signal, location=trunc(location, 90),
                    matched=trunc(hit.matched if matched is None else matched, 100) or "(present)",
                    pattern=trunc(pat.raw, 100) or "(presence)", confidence=pat.confidence if conf is None else conf,
                    version=resolve_version(pat.version, hit.groups), view=view)


class TechDB:
    def __init__(self, techs: dict, cats: dict):
        self.techs = techs
        self.cats = cats
        self._dict_idx: dict[str, dict[str, list[tuple[str, Pat]]]] = {}
        self._list_idx: dict[str, list[tuple[str, Pat]]] = {}
        self._dom_idx: list[tuple[str, str, dict]] | None = None

    # -- lazy indexes ---------------------------------------------------------------------------
    def _dict(self, kind: str) -> dict[str, list[tuple[str, Pat]]]:
        if kind not in self._dict_idx:
            idx: dict[str, list[tuple[str, Pat]]] = defaultdict(list)
            for name, t in self.techs.items():
                for key, v in (t.get(kind) or {}).items():
                    for raw in to_list(v):
                        idx[key.lower()].append((name, Pat(str(raw))))
            self._dict_idx[kind] = idx
        return self._dict_idx[kind]

    def _list(self, kind: str) -> list[tuple[str, Pat]]:
        if kind not in self._list_idx:
            out = []
            for name, t in self.techs.items():
                for raw in to_list(t.get(kind)):
                    out.append((name, Pat(str(raw))))
            self._list_idx[kind] = out
        return self._list_idx[kind]

    def _dom(self) -> list[tuple[str, str, dict]]:
        """[(tech, selector, spec)] with spec = {'exists': Pat|None, 'attributes': {n: Pat}, 'properties': {n: Pat}, 'text': Pat|None}"""
        if self._dom_idx is None:
            out = []
            for name, t in self.techs.items():
                d = t.get("dom")
                if not d:
                    continue
                items: list[tuple[str, dict]] = []
                if isinstance(d, str):
                    items = [(d, {"exists": ""})]
                elif isinstance(d, list):
                    items = [(s, {"exists": ""}) for s in d if isinstance(s, str)]
                elif isinstance(d, dict):
                    items = [(s, spec if isinstance(spec, dict) else {"exists": ""}) for s, spec in d.items()]
                for sel, spec in items:
                    if not spec or not any(k in spec for k in ("exists", "attributes", "properties", "text")):
                        spec = {"exists": ""}
                    norm = {
                        "exists": Pat(str(spec["exists"])) if "exists" in spec else None,
                        "attributes": {k: [Pat(str(x)) for x in to_list(v)] for k, v in (spec.get("attributes") or {}).items()},
                        "properties": {k: [Pat(str(x)) for x in to_list(v)] for k, v in (spec.get("properties") or {}).items()},
                        "text": [Pat(str(x)) for x in to_list(spec.get("text"))] or None,
                    }
                    out.append((name, sel, norm))
            self._dom_idx = out
        return self._dom_idx

    # -- what to ask the live page ----------------------------------------------------------------
    def _js(self) -> dict[str, list[tuple[str, str]]]:
        """chain -> [(tech, raw pattern)]. Chains are case-sensitive in JavaScript, so keys keep their case."""
        if not hasattr(self, "_js_idx"):
            idx: dict[str, list[tuple[str, str]]] = defaultdict(list)
            for name, t in self.techs.items():
                for chain, raws in (t.get("js") or {}).items():
                    for raw in to_list(raws):
                        idx[chain].append((name, str(raw)))
            self._js_idx = idx
        return self._js_idx

    def js_chains(self) -> list[str]:
        return list(self._js().keys())

    def dom_plan(self) -> list[dict]:
        plan: dict[str, dict] = {}
        for _, sel, spec in self._dom():
            q = plan.setdefault(sel, {"s": sel, "a": set(), "p": set(), "t": False})
            q["a"].update(spec["attributes"].keys())
            q["p"].update(spec["properties"].keys())
            q["t"] = q["t"] or bool(spec["text"])
        return [{"s": q["s"], "a": sorted(q["a"]) or None, "p": sorted(q["p"]) or None, "t": q["t"]} for q in plan.values()]

    # -- analysis ----------------------------------------------------------------------------------
    def analyze(self, snap: PageSnapshot, *, cert_issuer: str | None = None, dns: dict | None = None,
                csp_hosts: list[str] | None = None) -> tuple[list[Detection], dict]:
        hits: dict[str, list[Evidence]] = defaultdict(list)
        stats = {"signals": defaultdict(int), "script_rules_complete": True}

        def add(tech: str, ev: Evidence) -> None:
            hits[tech].append(ev)

        # headers (Set-Cookie handled with cookies) -------------------------------------------------
        hmap: dict[str, list[str]] = defaultdict(list)
        for k, v in snap.headers:
            if k.lower() != "set-cookie":
                hmap[k.lower()].append(v)
        hidx = self._dict("headers")
        for name, vals in hmap.items():
            rules = hidx.get(name)
            if not rules:
                continue
            value = ", ".join(vals)
            low = value.lower()
            stats["signals"]["header"] += 1
            for tech, pat in rules:
                h = pat.match(value, low)
                if h:
                    add(tech, _ev("header", name, h, pat, "raw", matched=f"{name}: {value}" if not h.matched else None))

        # cookies --------------------------------------------------------------------------------
        cookies: dict[str, str] = {}
        for raw in snap.set_cookie_headers():
            c = parse_set_cookie(raw)
            if c["name"]:
                cookies.setdefault(c["name"].lower(), c["value"])
        for c in snap.cookies_jar:
            if c.get("name"):
                cookies.setdefault(str(c["name"]).lower(), str(c.get("value", "")))
        cidx = self._dict("cookies")
        for name, value in cookies.items():
            for tech, pat in cidx.get(name, []):
                h = pat.match(value)
                if h:
                    add(tech, _ev("cookie", name, h, pat, "n/a", matched=f"{name}=<{len(value)} chars>"))
        stats["signals"]["cookie"] = len(cookies)

        # meta ---------------------------------------------------------------------------------------
        midx = self._dict("meta")
        for name, content in snap.meta:
            for tech, pat in midx.get(name, []):
                h = pat.match(content)
                if h:
                    add(tech, _ev("meta", f"meta[{name}]", h, pat, "both" if snap.mode == "browser" else "raw"))
        stats["signals"]["meta"] = len(snap.meta)

        # script URLs, page URL, xhr hosts --------------------------------------------------------
        urls = [s.url for s in snap.scripts if s.url]
        for tech, pat in self._list("scriptSrc"):
            for u in urls:
                h = pat.match(u)
                if h:
                    add(tech, _ev("script-src", u, h, pat))
        stats["signals"]["script-src"] = len(urls)
        low_url = snap.final_url.lower()
        for tech, pat in self._list("url"):
            h = pat.match(snap.final_url, low_url)
            if h:
                add(tech, _ev("url", snap.final_url, h, pat, "n/a"))
        for tech, pat in self._list("xhr"):
            for host in snap.xhr_hosts:
                h = pat.match(host)
                if h:
                    add(tech, _ev("xhr", host, h, pat, "rendered"))

        # html: raw and rendered views ------------------------------------------------------------
        raw_hits: set[tuple[str, str]] = set()
        raw_low = snap.html_raw.lower() if snap.html_raw else ""
        html_rules = self._list("html")
        if snap.html_raw:
            for tech, pat in html_rules:
                h = pat.match(snap.html_raw, raw_low)
                if h:
                    raw_hits.add((tech, pat.raw))
                    add(tech, _ev("html", "response body", h, pat, "raw"))
        if snap.html_rendered and snap.html_rendered != snap.html_raw:
            ren_low = snap.html_rendered.lower()
            for tech, pat in html_rules:
                if (tech, pat.raw) in raw_hits:
                    continue
                h = pat.match(snap.html_rendered, ren_low)
                if h:
                    add(tech, _ev("html", "rendered DOM", h, pat, "rendered"))
        elif snap.html_rendered:
            for ev_list in hits.values():
                for ev in ev_list:
                    if ev.signal == "html":
                        ev.view = "both"
        stats["signals"]["html"] = 1 if snap.html_raw or snap.html_rendered else 0

        # text / css -------------------------------------------------------------------------------
        for kind, text in (("text", snap.text), ("css", snap.css)):
            if not text:
                continue
            low = text.lower()
            for tech, pat in self._list(kind):
                h = pat.match(text, low)
                if h:
                    add(tech, _ev(kind, "page text" if kind == "text" else "stylesheets", h, pat))

        # script bodies (bounded) --------------------------------------------------------------------
        t0, scanned = time.monotonic(), 0
        script_rules = self._list("scripts")
        if script_rules:
            for idx, s in enumerate(snap.scripts):
                if not s.text:
                    continue
                if scanned > SCRIPT_RULE_BYTE_BUDGET or time.monotonic() - t0 > SCRIPT_RULE_TIME_BUDGET:
                    stats["script_rules_complete"] = False
                    break
                scanned += len(s.text)
                low = s.text.lower()
                loc = s.url or f"inline script #{idx + 1}"
                for tech, pat in script_rules:
                    h = pat.match(s.text, low)
                    if h:
                        add(tech, _ev("script", loc, h, pat, "rendered" if snap.mode == "browser" else "raw"))
        stats["signals"]["script"] = scanned

        # JS globals (browser only) ---------------------------------------------------------------
        jidx = self._js()
        for chain, value in snap.js_values.items():
            for t_name, raw in jidx.get(chain, []):
                pat = self._js_pat(raw)
                h = pat.match(value)
                if h:
                    add(t_name, _ev("js-global", chain, h, pat, "rendered", matched=value or "(present)"))
        stats["signals"]["js-global"] = len(snap.js_values)

        # DOM rules (browser only) ------------------------------------------------------------------
        if snap.dom_hits:
            for tech, sel, spec in self._dom():
                recs = snap.dom_hits.get(sel)
                if not recs:
                    continue
                if spec["exists"] is not None:
                    h = spec["exists"].match("")
                    if h:
                        add(tech, _ev("dom", sel, h, spec["exists"], matched=f"{len(recs)} element(s)"))
                for attr, pats in spec["attributes"].items():
                    for rec in recs:
                        v = (rec.get("a") or {}).get(attr)
                        if v is None:
                            continue
                        for pat in pats:
                            h = pat.match(v)
                            if h:
                                add(tech, _ev("dom", f"{sel}@{attr}", h, pat, matched=v))
                for prop, pats in spec["properties"].items():
                    for rec in recs:
                        v = (rec.get("p") or {}).get(prop)
                        if v is None:
                            continue
                        for pat in pats:
                            h = pat.match(v)
                            if h:
                                add(tech, _ev("dom", f"{sel}.{prop}", h, pat, matched=v))
                if spec["text"]:
                    for rec in recs:
                        t = rec.get("t")
                        if t is None:
                            continue
                        for pat in spec["text"]:
                            h = pat.match(t)
                            if h:
                                add(tech, _ev("dom", f"{sel} (text)", h, pat))
        stats["signals"]["dom"] = len(snap.dom_hits)

        # certificate issuer ---------------------------------------------------------------------
        if cert_issuer:
            li = cert_issuer.lower()
            for name, t in self.techs.items():
                ci = t.get("certIssuer")
                if ci and str(ci).lower() in li:
                    add(name, Evidence("tech", "cert-issuer", "TLS certificate", trunc(cert_issuer, 100),
                                       trunc(str(ci), 100), 100, None, "n/a"))

        # DNS records ------------------------------------------------------------------------------
        if dns:
            for name, t in self.techs.items():
                rules = t.get("dns")
                if not isinstance(rules, dict):
                    continue
                for rtype, raws in rules.items():
                    for val in dns.get(rtype.upper(), []):
                        for raw in to_list(raws):
                            pat = self._js_pat(raw)
                            h = pat.match(val)
                            if h:
                                add(name, _ev("dns", rtype.upper(), h, pat, "n/a", matched=val))

        # CSP allow-list hints (weak by construction: "allowed", not "used") --------------------------
        if csp_hosts:
            sr = self._list("scriptSrc")
            for host in csp_hosts:
                probe = f"//{host.lstrip('*.')}/"
                for tech, pat in sr:
                    h = pat.match(probe)
                    if h:
                        add(tech, _ev("csp-allowlist", host, h, pat, "raw", matched=f"allowed: {host}",
                                      conf=min(pat.confidence, 25)))

        return self._resolve(hits), {"signals": dict(stats["signals"]),
                                     "script_rules_complete": stats["script_rules_complete"]}

    _js_cache: dict = {}

    def _js_pat(self, raw) -> Pat:
        raw = str(raw)
        p = self._js_cache.get(raw)
        if p is None:
            p = self._js_cache[raw] = Pat(raw)
        return p

    # -- resolution: dedupe, sum, requires/excludes/implies, versions, status -------------------------
    def _cat_names(self, ids) -> list[str]:
        out = []
        for i in to_list(ids):
            c = self.cats.get(str(i))
            if c:
                out.append(c["name"] if isinstance(c, dict) else str(c))
        return out

    def _resolve(self, hits: dict[str, list[Evidence]]) -> list[Detection]:
        dets: dict[str, Detection] = {}
        for name, evs in hits.items():
            seen: set[tuple] = set()
            uniq: list[Evidence] = []
            for e in evs:
                k = (e.signal, e.location, e.pattern, e.view)
                if k not in seen:
                    seen.add(k)
                    uniq.append(e)
            t = self.techs.get(name, {})
            conf = min(100, sum(e.confidence for e in uniq))
            det = Detection(name=name, categories=self._cat_names(t.get("cats")), confidence=conf, evidence=uniq,
                            website=t.get("website"), cpe=t.get("cpe"))
            self._pick_version(det)
            dets[name] = det

        # requires / requiresCategory: drop techs whose prerequisites are absent (to a fixpoint)
        changed = True
        while changed:
            changed = False
            present_cats = {c for d in dets.values() for c in d.categories}
            for name in list(dets):
                t = self.techs.get(name, {})
                req = to_list(t.get("requires"))
                reqc = self._cat_names(t.get("requiresCategory"))
                if (req and not all(r in dets for r in req)) or (reqc and not any(c in present_cats for c in reqc)):
                    del dets[name]
                    changed = True

        # excludes: higher confidence excluder wins
        for name in sorted(dets, key=lambda n: -dets[n].confidence):
            if name not in dets:
                continue
            for ex in to_list(self.techs.get(name, {}).get("excludes")):
                if ex in dets and ex != name:
                    del dets[ex]

        # implies (transitive, depth-capped); implied techs are labelled, never "confirmed"
        for _ in range(4):
            added = False
            for name, d in list(dets.items()):
                for raw in to_list(self.techs.get(name, {}).get("implies")):
                    p = Pat(str(raw))
                    target = p.body
                    if not target or target in dets or target not in self.techs:
                        continue
                    t = self.techs[target]
                    imp = Detection(name=target, categories=self._cat_names(t.get("cats")),
                                    confidence=min(d.confidence, p.confidence), status="implied", basis="inferred",
                                    implied_by=[name], website=t.get("website"), cpe=t.get("cpe"),
                                    evidence=[Evidence("tech", "implies", name, f"{name} implies {target}", "",
                                                       min(d.confidence, p.confidence), None, "n/a")])
                    dets[target] = imp
                    added = True
            if not added:
                break

        out = []
        for d in dets.values():
            if d.status != "implied":
                d.status = band(d.confidence)
                sigs = {(e.signal, e.location.lower()) for e in d.evidence}
                if all((s == "meta") or (s == "header" and loc in SELF_DECLARED_HEADERS) for s, loc in sigs):
                    d.basis = "claimed"
                    d.notes.append("only self-declared by the server; nothing corroborates it")
            out.append(d)
        out.sort(key=lambda d: (-d.confidence, d.name.lower()))
        return out

    def new_detection(self, name: str, evidence: list[Evidence]) -> Detection:
        """Build a detection for a technology from externally gathered evidence (e.g. a bundle banner)."""
        t = self.techs.get(name, {})
        det = Detection(name=name, categories=self._cat_names(t.get("cats")), confidence=min(100, sum(e.confidence for e in evidence)),
                        evidence=list(evidence), website=t.get("website"), cpe=t.get("cpe"))
        det.status = band(det.confidence)
        self._pick_version(det)
        return det

    @staticmethod
    def _pick_version(det: Detection) -> None:
        cands = [(e.confidence, len(e.version), e.version) for e in det.evidence if e.version]
        if not cands:
            return
        cands.sort(reverse=True)
        det.version = cands[0][2]
        distinct = {c[2] for c in cands}
        if len(distinct) > 1:
            det.notes.append("conflicting version evidence: " + ", ".join(sorted(distinct)))
