"""The "scan card": a threat-surface strip on top, stack (confidence heat-bars) on the left, posture on the
right, then one line per deeper check. Built as plain (text, style) spans so it is fully testable and
independent of the terminal library. Guaranteed to fit 80 columns; the default card is at most 24 rows.
"""
from __future__ import annotations

from ..util import cell_width, fit, safe, str_width

Span = tuple[str, str]
Line = list[Span]

POSTURE_LABELS = {"hsts": "HSTS", "csp": "CSP", "x-frame-options": "X-Frame-Opt", "x-content-type-options": "X-Content-T",
                  "referrer-policy": "Referrer-Pol", "permissions-policy": "Permissions"}
MAX_STACK_ROWS = 7


# ---------------------------------------------------------------------------- span helpers
def spans_width(spans: Line) -> int:
    return sum(str_width(t) for t, _ in spans)


ELL = ["…"]   # set per render by build_card (ASCII mode swaps in a 1-cell stand-in)


def fit_spans(spans: Line, width: int, ell: str | None = None) -> Line:
    """Truncate a span list to `width` terminal cells, keeping styles; an ellipsis marks the cut."""
    ell = ell or ELL[0]
    if spans_width(spans) <= width:
        return [(safe(t), st) for t, st in spans]
    room = width - str_width(ell)
    out: Line = []
    used = 0
    for text, style in spans:
        text = safe(text)
        w = str_width(text)
        if used + w <= room:
            out.append((text, style))
            used += w
            continue
        cut, cw = [], 0
        for ch in text:
            c = cell_width(ch)
            if used + cw + c > room:
                break
            cut.append(ch)
            cw += c
        if cut:
            out.append(("".join(cut), style))
        break
    out.append((ell, "dim"))
    return out


def pad_spans(spans: Line, width: int) -> Line:
    s = fit_spans(spans, width)
    return s + [(" " * max(0, width - spans_width(s)), "")]


def bar(conf: int, g: dict) -> Line:
    full, half = conf // 10, 1 if conf % 10 >= 5 else 0
    empty = 10 - full - half
    return [(g["full"] * full + g["half"] * half, f"heat:{conf}"), (g["empty"] * empty, "dim")]


# ---------------------------------------------------------------------------- sections
def _icon(state: str, g: dict) -> Span:
    return (g[state], {"ok": "ok", "warn": "warn", "bad": "bad", "na": "na"}[state])


def surface_items(rep: dict, g: dict) -> list[Line]:
    s = rep["summary"]
    items: list[Line] = []

    def add(label: str, state: str, value: str) -> None:
        items.append([(label + " ", "label"), _icon(state, g), (" " + value, "value")])

    add("TECH", s["tech"]["state"], str(s["tech"]["count"]))
    add("HEADERS", s["headers"]["state"], f"{s['headers']['passed']}/{s['headers']['total']}")
    csp = s["csp"]
    add("CSP", "ok" if csp["grade"] in ("A", "B") else "warn" if csp["grade"] else "bad", csp["grade"] or "none")
    add("TLS", s["tls"]["state"], s["tls"]["label"])
    js = s["js"]
    add("JS", js["state"], f"{js['advisories']} adv" if js["advisories"] else "map!" if js.get("maps_exposed") else f"{js['libraries']} libs")
    e = s["edge"]
    add("EDGE", "warn" if e["leaks"] else "ok" if e["names"] else "na", (e["names"][0] if e["names"] else "none")[:12])
    tp = s["third_party"]
    add("3P", tp["state"], f"{tp['origins']}" + (f" {tp['without_sri']}!sri" if tp["without_sri"] else ""))
    h = s["hygiene"]
    add("HYG", h["state"], f"{h['cookies']}ck" + (f" {h['at_risk']}!" if h["at_risk"] else ""))
    return items


def wrap_items(items: list[Line], width: int, lead: str = "SURFACE ") -> list[Line]:
    lines: list[Line] = []
    cur: Line = [(lead, "accent")]
    for it in items:
        need = spans_width(it) + 2
        if spans_width(cur) + need > width and len(cur) > 1:
            lines.append(cur)
            cur = [(" " * len(lead), "")]
        cur += [("  ", "")] + it if len(cur) > 1 else it
    lines.append(cur)
    return lines


def stack_rows(rep: dict, name_w: int, g: dict) -> list[Line]:
    """One row per technology: [drift mark][name version, padded] [heat bar] [conf]."""
    dets = rep["technologies"]
    main = [d for d in dets if d["status"] in ("confirmed", "probable", "disputed")]
    implied = [d for d in dets if d["status"] == "implied"]
    removed = [c for c in (rep.get("drift") or {}).get("changes", []) if c["area"] == "technology" and c["kind"] == "removed"]
    ordered = main + implied
    limit = MAX_STACK_ROWS if len(ordered) <= MAX_STACK_ROWS else MAX_STACK_ROWS - 1
    rows: list[Line] = []

    def name_cell(spans: Line) -> Line:
        f = fit_spans(spans, name_w - 1)
        return f + [(" " * max(0, name_w - spans_width(f)), "")]

    for d in ordered[:limit]:
        mark = {"added": ("+", "added"), "changed": ("~", "changed")}.get(d.get("drift"), (" ", ""))
        label = d["name"] + (f" {d['version']}" if d.get("version") else "")
        if d["status"] == "implied":
            rows.append(name_cell([mark, (f"{g['implied']} {label}", "implied")]) + [("implied", "implied")])
        elif d["status"] == "disputed":
            rows.append(name_cell([mark, (label, "disputed"), (f" {g['warn']}", "warn")]) + bar(d["confidence"], g)
                        + [(f" {d['confidence']:>3}", "warn")])
        else:
            rows.append(name_cell([mark, (label, "value")]) + bar(d["confidence"], g)
                        + [(f" {d['confidence']:>3}", f"heat:{d['confidence']}")])
    if len(ordered) > limit:
        rows.append([(f" {g['ell']} +{len(ordered) - limit} more (-v)", "dim")])
    if removed and len(rows) < MAX_STACK_ROWS:
        rows.append([(f" {g['minus']} gone: " + ", ".join(c["subject"] for c in removed[:3]), "removed")])
    return rows


def posture_rows(rep: dict, w: int, g: dict) -> list[Line]:
    rows: list[Line] = []
    for f in rep["security_headers"]:
        st = f["status"]
        style = {"pass": "ok", "weak": "warn", "missing": "bad", "n/a": "na"}.get(st, "na")
        label = POSTURE_LABELS.get(f["id"], f["title"])[:12]
        rows.append([(g[st if st in g else "na"], style), (" " + label.ljust(13), "emph"),
                     ((f.get("data") or {}).get("short") or f["reason"], "dim" if st == "pass" else "value")])
    csp = rep.get("csp") or {}
    layered = [a for a in rep.get("anomalies", []) if a["tier"] == "layered"]
    if layered:
        rows.append([(g["warn"], "warn"), (" " + "layered".ljust(13), "emph"), (layered[0]["title"], "value")])
    elif csp.get("issues"):
        rows.append([(g["warn"], "warn"), (" " + "csp issues".ljust(13), "emph"), (str(len(csp["issues"])) + " (" + csp["issues"][0]["directive"] + " ...)", "value")])
    return rows


def lower_lines(rep: dict, g: dict) -> list[Line]:
    L: list[Line] = []
    s = rep["summary"]
    tls, http = rep.get("tls") or {}, rep.get("http") or {}

    def line(tag: str, state: str, parts: list[Span]) -> None:
        L.append([(tag.ljust(6), "label"), _icon(state, g), (" ", "")] + parts)

    # TLS
    if rep["target"]["scheme"] != "https":
        line("TLS", "bad", [("none: served over plain HTTP", "bad")])
    elif tls.get("error"):
        line("TLS", "warn", [(f"probe failed: {tls['error']}", "value")])
    else:
        c = tls.get("cert") or {}
        h3 = http.get("h3")
        proto = http.get("summary") or "?"
        proto_txt = proto + (f" (h3 {h3})" if h3 in ("advertised", "observed") else "")
        parts: list[Span] = []
        if tls.get("verified") is False:
            why = tls.get("verify_error") or ""
            why = "self-signed" if "self" in why.lower() and "sign" in why.lower() else why[:24]
            parts.append((f"UNTRUSTED ({why}) {g['dot']} ", "warn"))
        parts += [(str(tls.get("tls_version", "?")).replace("TLSv", ""), "value"), (f" {g['dot']} {proto_txt}", "value")]
        if isinstance(c.get("days_left"), int):
            parts.append((f" {g['dot']} exp {c['days_left']}d", "warn" if c["days_left"] < 30 else "dim"))
        parts.append((f" {g['dot']} {c.get('issuer', '?')}", "value"))
        if c.get("sha256"):
            parts.append((f" {g['dot']} sha256 {c['sha256'][:8]}{g['ell']}{c['sha256'][-4:]}", "dim"))
        line("TLS", s["tls"]["state"], parts)
    # EDGE
    e = rep.get("edge") or {}
    if e.get("edges"):
        parts = [(e["layers"], "value")]
        if e.get("origin_leaks"):
            lk = e["origin_leaks"][0]
            parts.append((f" {g['dot']} leaks {lk['header']}: {lk['value']}", "warn"))
        line("EDGE", s["edge"]["state"], parts)
    else:
        line("EDGE", "na", [("no CDN/WAF identified" + (" (proxy/cache headers present)" if e.get("proxied") else ""), "dim")])
    # FAVICON
    f = rep.get("favicon") or {}
    if f.get("status") == "matched":
        names = ", ".join(m["name"] for m in f["matches"][:2])
        tag = "corroborated" if f.get("corroborates") else "possible"
        line("FAV", "ok" if f.get("corroborates") else "warn", [(f"mmh3 {f['mmh3']} → {names} ({tag})", "value")])
    elif f.get("status") in ("no-match", "sentinel"):
        line("FAV", "na", [(f"mmh3 {f.get('mmh3')} {g['dot']} " + ("placeholder icon" if f["status"] == "sentinel" else "no database match"), "dim")])
    else:
        line("FAV", "na", [("no favicon found", "dim")])
    # JS
    b = (rep.get("bundle") or {}).get("bundle")
    libs = rep.get("libraries") or {}
    parts = []
    if b:
        from ..util import human_bytes
        nm = b["url"].rsplit("/", 1)[-1].split("?")[0] or b["url"]
        parts.append((f"{nm} {human_bytes(b.get('size'))}", "value"))
        bn = next((x for x in b.get("banners", []) if x.get("library")), None)
        if bn:
            parts.append((f" {g['dot']} {bn['library']} {bn.get('version', '')}", "value"))
    if libs.get("total_advisories"):
        sev = ", ".join(f"{n} {k}" for k, n in libs["advisory_counts"].items() if n)
        parts.append((f" {g['dot']} {libs['total_advisories']} advisories ({sev})", "warn"))
    sm = [m for m in (rep.get("bundle") or {}).get("source_maps", []) if m["status"] in ("exposed", "inline")]
    if sm:
        parts.append((f" {g['dot']} source map {sm[0]['status']}", "warn"))
    if not parts:
        parts = [("no external scripts" if not (rep.get("bundle") or {}).get("scripts_seen") else "no banners found", "dim")]
    line("JS", s["js"]["state"] if (b or libs.get("libraries")) else "na", parts)
    # 3P
    tp = rep.get("third_party") or {}
    n_o = tp.get("origins", 0)
    p3 = [(f"{n_o} third-party origin{'' if n_o == 1 else 's'}", "value")]
    if tp.get("scripts_without_sri") or tp.get("styles_without_sri"):
        n_s = tp.get("scripts_without_sri", 0) + tp.get("styles_without_sri", 0)
        p3.append((f" {g['dot']} {n_s} resource{'' if n_s == 1 else 's'} without SRI", "warn"))
    if tp.get("insecure_requests"):
        p3.append((f" {g['dot']} {tp['insecure_requests']} insecure request{'' if tp['insecure_requests'] == 1 else 's'}", "warn"))
    if tp.get("note"):
        p3.append((f" {g['dot']} declared only", "dim"))
    line("3P", s["third_party"]["state"], p3)
    # HYGIENE
    hyg = rep.get("hygiene") or {}
    ck, stx = hyg.get("cookies") or {}, hyg.get("security_txt") or {}
    hp: list[Span] = [(f"{ck.get('total', 0)} cookies", "value")]
    if ck.get("session_cookies_at_risk"):
        hp.append((f" ({ck['session_cookies_at_risk']} session-like at risk)", "warn"))
    hp.append((f" {g['dot']} security.txt {stx.get('status', 'n/a')}", "warn" if stx.get("status") in ("missing", "weak") else "dim"))
    line("HYG", s["hygiene"]["state"], hp)
    # DRIFT
    d = rep.get("drift")
    if d:
        sm_ = d["summary"]
        when = (d["baseline"].get("generated_at") or "baseline")[:10]
        L.append([("DRIFT".ljust(6), "label"), (f"+{sm_['added']} ", "added"), (f"{g['minus']}{sm_['removed']} ", "removed"),
                  (f"~{sm_['changed']} ", "changed"), (f"vs {when}" + (f" ({sm_['noise']} low-confidence flips ignored)" if sm_["noise"] else ""), "dim")])
    return L


def note_line(rep: dict, g: dict) -> Line | None:
    anoms = [a for a in rep.get("anomalies", []) if a["tier"] == "contradiction"]
    if anoms:
        extra = f" (+{len(anoms) - 1} more)" if len(anoms) > 1 else ""
        return [("DISPUTED ", "disputed"), (g["warn"] + " ", "warn"), (anoms[0]["title"] + extra, "value")]
    if rep["target"].get("error"):
        return [("ERROR ", "bad"), (g["bad"] + " ", "bad"), (str(rep["target"]["error"]), "value")]
    t = rep["db"]["technologies"]
    if t.get("seed"):
        return [("NOTE ", "label"), (g["warn"] + " ", "warn"),
                (f"seed fingerprints ({t['count']}): run `npc-fingerprint db update`", "dim")]
    ws = [w for w in rep.get("warnings", []) if "seed" in w or "partial" in w or "unavailable" in w or "timed" in w or "did not finish" in w]
    if ws:
        return [("NOTE ", "label"), (g["warn"] + " ", "warn"), (ws[0][:90] + (f" (+{len(rep['warnings']) - 1} more, -v)" if len(rep["warnings"]) > 1 else ""), "dim")]
    return None


# ---------------------------------------------------------------------------- card assembly
def build_card(rep: dict, width: int, g: dict) -> list[Line]:
    ELL[0] = g["ell"]
    W = max(40, width)
    inner = W - 2
    wide = W >= 78
    lines: list[Line] = []
    t = rep["target"]
    commit = (rep["db"]["technologies"].get("commit") or ("seed" if rep["db"]["technologies"].get("seed") else "?"))[:7]
    right = f" {rep['duration_ms'] / 1000:.1f}s {g['dot']} db {commit} "
    left_lead = [(g["h"] + " ", "frame"), ("npc-fingerprint", "title"), (f" {g['arrow']} ", "frame")]
    url_room = inner - spans_width(left_lead) - str_width(right) - 3
    url_txt = fit(t["final_url"], max(8, url_room), g["ell"])
    mid = inner - spans_width(left_lead) - str_width(url_txt) - str_width(right)
    top: Line = [(g["tl"], "frame")] + left_lead + [(url_txt, "url"), (" " + g["h"] * max(1, mid - 1), "frame"), (right, "dim"), (g["tr"], "frame")]
    lines.append(fit_spans(top, W))

    def boxed(spans: Line) -> Line:
        return [(g["v"], "frame")] + pad_spans(spans, inner) + [(g["v"], "frame")]

    for sl in wrap_items(surface_items(rep, g), inner - 1):
        lines.append(boxed([(" ", "")] + sl))
    note = note_line(rep, g)
    if note:
        lines.append(boxed([(" ", "")] + note))

    if wide:
        Lw = round((W - 3) * 0.44)
        Rw = W - 3 - Lw
        lines.append([(g["lt"] + g["h"] * Lw + g["tt"] + g["h"] * Rw + g["rt"], "frame")])
        name_w = Lw - 16
        lines.append([(g["v"], "frame")] + pad_spans([(" STACK", "accent"), (" " * (Lw - 11), ""), ("conf", "label")], Lw)
                     + [(g["v"], "frame")] + pad_spans([(" POSTURE", "accent")], Rw) + [(g["v"], "frame")])
        srows, prows = stack_rows(rep, name_w, g), posture_rows(rep, Rw - 2, g)
        n = max(len(srows), len(prows), 1)
        for i in range(n):
            ls = [(" ", "")] + (srows[i] if i < len(srows) else [])
            rs = [(" ", "")] + (prows[i] if i < len(prows) else [])
            lines.append([(g["v"], "frame")] + pad_spans(ls, Lw) + [(g["v"], "frame")] + pad_spans(rs, Rw) + [(g["v"], "frame")])
        lines.append([(g["lt"] + g["h"] * Lw + g["bt"] + g["h"] * Rw + g["rt"], "frame")])
    else:
        lines.append([(g["lt"] + g["h"] * inner + g["rt"], "frame")])
        lines.append(boxed([(" STACK", "accent")]))
        for r in stack_rows(rep, min(24, max(10, inner - 18)), g):
            lines.append(boxed([(" ", "")] + r))
        lines.append(boxed([(" POSTURE", "accent")]))
        for r in posture_rows(rep, inner - 2, g):
            lines.append(boxed([(" ", "")] + r))
        lines.append([(g["lt"] + g["h"] * inner + g["rt"], "frame")])

    for ll in lower_lines(rep, g):
        lines.append(boxed([(" ", "")] + ll))
    lines.append([(g["bl"] + g["h"] * inner + g["br"], "frame")])
    return lines


def hint_line(g: dict, verbose: bool, width: int = 80) -> Line:
    h = f" {'-v evidence trace' if not verbose else '-v trace on'} {g['dot']} --json {g['dot']} --no-browser {g['dot']} --baseline FILE"
    return fit_spans([(h, "dim")], width)
