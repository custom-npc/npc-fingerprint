"""`-v` trace mode: the exact evidence chain behind every claim, as an indented tree."""
from __future__ import annotations

from ..util import human_bytes, trunc
from .layout import Line

LAYER_NOTE = {"edge": "edge", "origin": "origin", "app": "app", "unknown": ""}


def _tree(g: dict, last: bool, depth_bars: list[bool]) -> str:
    stem = "".join(g["tree_bar"] if b else "  " for b in depth_bars)
    return stem + (g["tree_end"] if last else g["tree_mid"]) + " "


def build_trace(rep: dict, g: dict) -> list[Line]:
    L: list[Line] = [[("TRACE ", "accent"), ("evidence behind every claim (nothing is reported without one)", "dim")]]

    def section(title: str, items: list[list[Line]] | None = None) -> None:
        L.append([(title, "title")])

    def leaf(prefix: str, spans: Line) -> None:
        L.append([(prefix, "frame")] + spans)

    # technologies --------------------------------------------------------------------------------
    section(f"TECHNOLOGIES  ({len(rep['technologies'])} reported, {len(rep['weak'])} weak)")
    for i, d in enumerate(rep["technologies"] + rep["weak"]):
        last_d = i == len(rep["technologies"]) + len(rep["weak"]) - 1
        weak = d["status"] == "weak"
        head = f"{d['name']}" + (f" {d['version']}" if d.get("version") else "")
        meta = f"{d['confidence']}% {d['status']}" + (f" · {d['layer']}" if d.get("layer") not in (None, "unknown") else "") \
            + (f" · basis: {d['basis']}" if d.get("basis") in ("claimed", "inferred") else "")
        st = {"disputed": "disputed", "implied": "implied", "weak": "dim"}.get(d["status"], f"heat:{d['confidence']}")
        leaf(_tree(g, last_d, []), [(head, st), (f"  {meta}", "dim")])
        bars = [not last_d]
        for note in d.get("notes", []):
            leaf(_tree(g, False, bars), [(trunc(note, 110), "warn")])
        if d.get("implied_by"):
            leaf(_tree(g, True, bars), [(f"implied by {', '.join(d['implied_by'])} (no direct evidence)", "implied")])
        evs = d.get("evidence", [])
        if not d.get("implied_by"):
            for j, e in enumerate(evs):
                v = f" v{e['version']}" if e.get("version") else ""
                leaf(_tree(g, j == len(evs) - 1, bars),
                     [(f"{e['signal']} ", "accent"), (f"{e['location']}", "value"), (f" = {e['matched']}", "dim"),
                      (f"  +{e['confidence']}{v} [{e['view']}]", "dim")])
        _ = weak

    # anomalies ------------------------------------------------------------------------------------
    section(f"HEADER ANOMALIES  ({len(rep['anomalies'])})")
    for i, a in enumerate(rep["anomalies"]):
        st = "disputed" if a["tier"] == "contradiction" else "warn"
        leaf(_tree(g, i == len(rep["anomalies"]) - 1, []), [(f"[{a['tier']}] ", st), (a["title"], "value")])
        leaf("   " + g["tree_end"] + " ", [(trunc(a["why"], 120), "dim")])
    if not rep["anomalies"]:
        leaf("   ", [("none: identity headers are mutually consistent", "dim")])

    # security headers + CSP ---------------------------------------------------------------------
    section("SECURITY HEADERS")
    for i, f in enumerate(rep["security_headers"]):
        stl = {"pass": "ok", "weak": "warn", "missing": "bad"}.get(f["status"], "na")
        leaf(_tree(g, i == len(rep["security_headers"]) - 1, []), [(f"{g.get(f['status'], g['na'])} {f['title']}: ", stl), (f["reason"], "value")])
    csp = rep.get("csp") or {}
    for iss in csp.get("issues", []):
        leaf("   " + g["tree_mid"] + " ", [(f"csp {iss['severity']} ", "warn"), (f"{iss['directive']}: {iss['issue']}", "dim")])

    # TLS / HTTP -----------------------------------------------------------------------------------
    tls, http = rep.get("tls") or {}, rep.get("http") or {}
    section("TLS & HTTP")
    if tls.get("error"):
        leaf("   ", [(f"TLS probe: {tls['error']}", "warn")])
    elif tls:
        c = tls.get("cert") or {}
        leaf(_tree(g, False, []), [(f"{tls.get('tls_version')} · {tls.get('cipher', '?')} · alpn {tls.get('alpn')}", "value")])
        if c:
            leaf(_tree(g, False, []), [(f"issuer {c.get('issuer')} · subject {c.get('subject_cn')} · {c.get('key')} · sig {c.get('sig_alg')}", "value")])
            leaf(_tree(g, False, []), [(f"valid {c.get('not_before', '')[:10]} → {c.get('not_after', '')[:10]} ({c.get('days_left')}d) · {c.get('san_count', 0)} SANs", "dim")])
            leaf(_tree(g, False, []), [(f"sha256 {c.get('sha256')}", "dim")])
        if tls.get("verified") is False:
            leaf(_tree(g, False, []), [(f"validation failed: {tls.get('verify_error')}", "warn")])
    leaf(_tree(g, True, []), [(f"http: observed {http.get('observed') or 'n/a'} · alpn {http.get('alpn') or 'n/a'} · h3 {http.get('h3')}"
                              + (f" · alt-svc {', '.join(a['protocol'] for a in http.get('alt_svc', []))}" if http.get("alt_svc") else ""), "value")])

    # favicon ---------------------------------------------------------------------------------------
    f = rep.get("favicon") or {}
    section("FAVICON")
    if f.get("url"):
        leaf(_tree(g, not f.get("matches"), []), [(f"{f['url']} ({f.get('bytes')} B) mmh3 {f.get('mmh3')} md5 {f.get('md5')} → {f.get('status')}", "value")])
        for j, m in enumerate(f.get("matches", [])):
            leaf(_tree(g, j == len(f["matches"]) - 1, [False]), [(f"{m['name']} via {'+'.join(m['via'])}", "value"),
                                                                  ("  (capped at 'possible' unless another signal agrees)", "dim")])
    else:
        leaf("   ", [("; ".join(f.get("notes", ["none"])), "dim")])

    # bundle + libraries --------------------------------------------------------------------------
    b = rep.get("bundle") or {}
    section(f"JS BUNDLES  ({b.get('scripts_seen', 0)} external scripts, {b.get('scanned', 0)} scanned)")
    if b.get("bundle"):
        bb = b["bundle"]
        leaf(_tree(g, not b.get("banners"), []), [(f"largest: {bb['url']} {human_bytes(bb.get('size'))} {'first-party' if bb.get('first_party') else 'third-party'}", "value")])
    for j, bn in enumerate(b.get("banners", [])[:8]):
        leaf(_tree(g, j == min(len(b["banners"]), 8) - 1, []), [(f"{bn.get('library') or 'comment'} {bn.get('version') or ''} ", "accent"),
                                                                (f"{bn.get('license') or ''} {bn.get('copyright') or ''} ", "value"), (f"[{bn['where']}] {bn['text'][:60]}", "dim")])
    for m in b.get("source_maps", []):
        leaf("   ", [(f"source map {m['status']}: {m['map_url']}", "warn" if m["status"] != "not-exposed" else "dim")])
    libs = rep.get("libraries") or {}
    section(f"LIBRARY RISK  ({libs.get('total_advisories', 0)} advisories)")
    for i, l in enumerate(libs.get("libraries", [])):
        leaf(_tree(g, i == len(libs["libraries"]) - 1, []), [(f"{l['library']} {l['version']}", "value"), (f"  evidence: {', '.join(sorted({e['basis'] for e in l['evidence']}))}", "dim")
                                                           , (f"  CONFLICT {l['versions_seen']}" if l["conflict"] else "", "warn")])
        for a in l["advisories"]:
            leaf("   " + g["tree_bar"] + g["tree_mid"] + " ", [(f"{a['severity']} ", "warn"), (f"{', '.join(a['ids'])} ", "value"), (f"{a['range']} {a['summary']}", "dim")])
    if libs.get("note"):
        leaf("   ", [(libs["note"], "dim")])

    # edge / third party / hygiene ----------------------------------------------------------------
    e = rep.get("edge") or {}
    section(f"EDGE vs ORIGIN  ({e.get('layers', '')})")
    for x in e.get("edges", []):
        leaf("   " + g["tree_mid"] + " ", [(f"{x['name']} [{x['kind']}] {x['confidence']}% ", "value"), ("; ".join(x["evidence"][:4]), "dim")])
    for lk in e.get("origin_leaks", []):
        leaf("   " + g["tree_mid"] + " ", [("leak ", "warn"), (f"{lk['header']}: {lk['value']}", "value"), (f"  {lk['why']}", "dim")])
    tp = rep.get("third_party") or {}
    section(f"THIRD PARTIES  ({tp.get('origins', 0)} origins, {tp.get('requests', 0)} requests)")
    for o in tp.get("top", [])[:8]:
        leaf("   " + g["tree_mid"] + " ", [(f"{o['origin']} ", "value"), (f"{o['requests']}x {','.join(o['types'])} ", "dim"), (", ".join(o.get("technologies", [])), "accent")])
    for u in tp.get("without_sri_examples", []):
        leaf("   " + g["tree_mid"] + " ", [("no SRI ", "warn"), (u, "dim")])
    hyg = rep.get("hygiene") or {}
    ck = hyg.get("cookies") or {}
    section(f"COOKIES & security.txt  ({ck.get('total', 0)} cookies)")
    for c in ck.get("cookies", []):
        if c["issues"]:
            leaf("   " + g["tree_mid"] + " ", [(f"{c['name']}{' (session-like)' if c['session_like'] else ''}: ", "value"), ("; ".join(c["issues"]), "warn")])
    stx = hyg.get("security_txt") or {}
    leaf(_tree(g, True, []), [(f"security.txt: {stx.get('reason', 'n/a')}", "value")])

    # drift -------------------------------------------------------------------------------------------
    d = rep.get("drift")
    if d:
        section(f"DRIFT vs {(d['baseline'].get('generated_at') or 'baseline')[:19]}  (+{d['summary']['added']} -{d['summary']['removed']} ~{d['summary']['changed']})")
        for c in d["changes"]:
            st = {"added": "added", "removed": "removed", "changed": "changed", "noise": "dim"}[c["kind"]]
            leaf("   " + g["tree_mid"] + " ", [(f"{c['kind']:7} ", st), (f"{c['area']}: {c['subject']}", "value"),
                                                 (f"  {c['from']} → {c['to']}" if c["from"] is not None or c["to"] is not None else "", "dim")])

    # run facts ----------------------------------------------------------------------------------------
    r, db = rep["requests"], rep["db"]
    section("RUN")
    leaf(_tree(g, False, []), [(f"page load: {r['page_load']} · observed {r['network_requests_observed']} requests · extra requests by us: {r['extra_count']} {r['extra']}", "value")])
    t = db["technologies"]
    leaf(_tree(g, False, []), [(f"database: {t['count']} technologies · commit {t.get('commit') or 'n/a'} · built {t.get('built_at') or 'n/a'}{' · SEED' if t.get('seed') else ''}", "value")])
    p = db["patterns"]
    leaf(_tree(g, False, []), [(f"patterns: {p['compiled']} compiled, {p['skipped']} not portable (skipped), {p['timeouts']} timeouts · regex engine {db['regex_engine']} · http {db['http_backend']}", "dim")])
    leaf(_tree(g, True, []), [(f"signals evaluated: {db['signals_evaluated']}" + ("" if db.get("script_rules_complete", True) else " · script rules hit their time budget"), "dim")])
    if rep["warnings"]:
        section("WARNINGS")
        for i, w in enumerate(rep["warnings"]):
            leaf(_tree(g, i == len(rep["warnings"]) - 1, []), [(trunc(w, 130), "warn")])
    return L
