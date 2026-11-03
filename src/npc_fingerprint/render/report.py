"""Headed, human-readable report: short sub-headings, one-line explanations, one line per finding.

The scan card (layout.py) is the at-a-glance dashboard. This module is the part you read: each section says in one line what it
is, then lists findings with an icon, a label and a plain-language reason. `brief=True` keeps only the sections you act on.
"""
from __future__ import annotations

from ..util import human_bytes, trunc
from .layout import Line, bar, fit_spans

SEV_STYLE = {"critical": "bad", "high": "bad", "medium": "warn", "low": "dim", "info": "dim"}
STATE_ICON = {"pass": ("pass", "ok"), "weak": ("warn", "warn"), "missing": ("bad", "bad"), "n/a": ("na", "na"), "info": ("na", "dim")}
TIER_STYLE = {"exploited": "bad", "weaponized": "bad", "likely": "warn", "severe": "warn", "minor": "dim"}
TIER_TITLE = {"exploited": "Exploited in the wild", "weaponized": "Public exploit available", "likely": "Likely to be exploited",
              "severe": "Severe, no known exploitation", "minor": "Lower priority"}


class Section:
    """Collects the lines of one section; renders nothing if it stayed empty."""

    def __init__(self, title: str, blurb: str, g: dict, width: int):
        self.title, self.blurb, self.g, self.w = title, blurb, g, width
        self.body: list[Line] = []

    def line(self, spans: Line, indent: int = 3) -> None:
        self.body.append(fit_spans([(" " * indent, "")] + spans, self.w))

    def item(self, icon: str, style: str, label: str, text: str, indent: int = 3) -> None:
        self.line([(self.g.get(icon, icon), style), (" ", ""), (label, "emph"), ((": " + text) if text else "", "value")], indent)

    def note(self, text: str, indent: int = 5, style: str = "dim", max_lines: int = 2) -> None:
        import textwrap
        parts = textwrap.wrap(text, max(20, self.w - indent), break_long_words=True) or [""]
        if len(parts) > max_lines:
            parts = parts[:max_lines]
            parts[-1] = parts[-1][: max(0, self.w - indent - 1)].rstrip() + self.g["ell"]
        for p in parts:
            self.line([(p, style)], indent)

    def lines(self) -> list[Line]:
        if not self.body:
            return []
        g = self.g
        head: Line = [(g["h"] * 2 + " ", "frame"), (self.title, "accent"), ("  " + g["h"] * max(2, min(self.w, 100) - len(self.title) - 6), "frame")]
        return [fit_spans(head, self.w), fit_spans([(" " * 3, ""), (self.blurb, "dim")], self.w)] + self.body + [[("", "")]]


def _cve_line(sec: Section, it: dict, g: dict, detail: bool) -> None:
    badges: Line = []
    if it.get("kev"):
        badges.append(("KEV ", "bad"))
    if it.get("exploits"):
        badges.append(("PoC ", "bad"))
    ep = it.get("epss")
    if ep and ep["score"] >= 0.10:
        badges.append((f"EPSS {ep['score']:.0%} ", "warn"))
    if it.get("nuclei"):
        badges.append(("nuclei ", "accent"))
    sev = (it.get("severity") or "?").upper()
    score = f" {it['cvss']:.1f}" if it.get("cvss") is not None else ""
    tail = f"{it['technology']} {it['version']}" + (f" {g['arrow']} {it['fixed']}" if it.get("fixed") else "")
    sec.line([(f"{it['cve']:<16}", "emph"), (f"{sev}{score}".ljust(11), SEV_STYLE.get(it.get("severity") or "", "dim"))] + badges + [(tail, "value")], 5)
    if detail:
        why = it.get("summary") or ""
        cav = it["caveats"][0] if it.get("caveats") else ""
        sec.line([(trunc(why, 70), "dim")] + ([(f" {g['dot']} {trunc(cav, 60)}", "warn")] if cav else []), 7)


def build_sections(rep: dict, g: dict, width: int, verbose: bool = False, brief: bool = False) -> list[Line]:
    W = max(40, min(width, 100))
    out: list[Line] = []

    def add(sec: Section) -> None:
        out.extend(sec.lines())

    # 1. priority actions ------------------------------------------------------------------------------------------
    s = Section("Priority actions", "Do these first. Most urgent at the top.", g, W)
    for a in rep.get("actions", []):
        icon = "bad" if a["severity"] in ("critical", "high") else "warn" if a["severity"] == "medium" else "na"
        s.line([(g[icon], SEV_STYLE[a["severity"]]), (" ", ""), (a["severity"].upper().ljust(9), SEV_STYLE[a["severity"]]), (a["text"], "value")])
    if not rep.get("actions") and rep["target"].get("status") is not None:
        s.line([(g["pass"], "ok"), (" Nothing urgent found.", "value")])
    add(s)

    # 2. vulnerabilities -----------------------------------------------------------------------------------------------
    v = rep.get("vulnerabilities")
    s = Section("Vulnerabilities (CVE)", "Known CVEs for the versions found, ranked by real-world exploitation.", g, W)
    if v is not None:
        per_tier = 3 if not verbose else 50
        shown_any = False
        for tier in ("exploited", "weaponized", "likely", "severe", "minor"):
            items = [i for i in v["items"] if i["priority"] == tier]
            if not items or (brief and tier == "minor"):
                continue
            shown_any = True
            s.line([(f"{TIER_TITLE[tier]} ({len(items)})", TIER_STYLE[tier])])
            s.note(v["tier_meaning"][tier], 5, max_lines=1)
            for it in items[:per_tier]:
                _cve_line(s, it, g, detail=True)
            if len(items) > per_tier:
                s.note(f"+{len(items) - per_tier} more (use -v)")
        if not shown_any:
            msg = "No CVEs match the versions detected." if v["checked"] else "No technology with a usable version was detected, so nothing could be matched."
            s.line([(g["pass"] if v["checked"] else g["na"], "ok" if v["checked"] else "dim"), (" " + msg, "value")])
        if v["checked"]:
            s.note("checked: " + ", ".join(f"{c['technology']} {c['version']}" for c in v["checked"][:8]), 3)
        if v["no_version"]:
            s.note("not checked (no version visible): " + ", ".join(v["no_version"][:8]), 3)
        for gp in v.get("nvd_gaps", [])[:3]:
            s.note(f"NVD gap: {gp['count']} CVEs since {gp['since']} mention {gp['technology']} but NVD has not analysed which versions they affect", 3)
        if v["status"] != "ok":
            src = v["sources"]
            why = []
            if not src["nvd"]["available"]:
                why.append("local CVE database missing (run `npc-fingerprint setup`)")
            if src["osv"]["errors"]:
                why.append("OSV unreachable")
            if src["osv"].get("skipped"):
                why.append(f"OSV skipped for {src['osv']['skipped']} package(s) (--offline, not cached)")
            s.note("partial data: " + "; ".join(why or ["some sources unavailable"]), 3)
        s.note(v["note"], 3)
    add(s)

    # 3. technology stack ----------------------------------------------------------------------------------------------
    s = Section("Technology stack", "What the site is built with. Confidence = independent signals agreeing.", g, W)
    techs = [t for t in rep["technologies"] if t["status"] in ("confirmed", "probable", "disputed")]
    for t in techs[: (40 if verbose else 12)]:
        label = t["name"] + (f" {t['version']}" if t.get("version") else "")
        st = "warn" if t["status"] == "disputed" else f"heat:{t['confidence']}"
        tag = {"disputed": "disputed: headers contradict each other", "claimed": "claimed by a header only"}.get(t["status"] if t["status"] == "disputed" else t.get("basis"), "")
        s.line([(label.ljust(28), "emph")] + bar(t["confidence"], g) + [(f" {t['confidence']:>3}%  ", st), (t["layer"] if t.get("layer") not in (None, "unknown") else "", "dim"),
                                                                       ((f"  {tag}" if tag else ""), "warn" if tag else "dim")])
    if len(techs) > (40 if verbose else 12):
        s.note(f"+{len(techs) - (40 if verbose else 12)} more (use -v)")
    imp = [t["name"] for t in rep["technologies"] if t["status"] == "implied"]
    if imp:
        s.note("implied (not seen directly): " + ", ".join(imp[:8]), 3)
    if not brief:
        add(s)

    # 4. security headers --------------------------------------------------------------------------------------------------
    s = Section("Security headers", "Protections a browser applies only if the server asks for them.", g, W)
    for f in rep["security_headers"]:
        icon, st = STATE_ICON.get(f["status"], ("na", "dim"))
        s.item(icon, st, f["title"], f["reason"])
    if not brief:
        add(s)

    # 5. TLS / protocol -----------------------------------------------------------------------------------------------------
    s = Section("TLS and protocol", "How the connection is secured and which HTTP version is spoken.", g, W)
    tls, http = rep.get("tls") or {}, rep.get("http") or {}
    if rep["target"]["scheme"] != "https":
        s.item("bad", "bad", "Transport", "plain HTTP: traffic can be read and changed in transit")
    elif tls.get("error"):
        s.item("warn", "warn", "TLS probe", tls["error"])
    elif tls:
        c = tls.get("cert") or {}
        s.item("warn" if tls.get("verified") is False else "pass", "warn" if tls.get("verified") is False else "ok", "Certificate",
               (f"NOT TRUSTED ({trunc(tls.get('verify_error'), 40)}) " if tls.get("verified") is False else "") + f"{c.get('issuer', '?')}, {c.get('key', '?')}, "
               f"{c.get('days_left', '?')} days left")
        s.item("pass", "ok", "Protocol", f"{str(tls.get('tls_version', '?')).replace('TLSv', 'TLS ')}, {http.get('summary') or '?'}"
               + (f", HTTP/3 {http['h3']}" if http.get("h3") in ("advertised", "observed") else ""))
        s.note("sha256 " + str(c.get("sha256", "")), 5)
    for f in rep.get("tls_findings", []):
        if f["id"] not in ("cert-invalid", "no-tls"):
            s.item("warn", "warn", f["title"], f["reason"])
    for c in (rep.get("active") or {}).get("checks", []):
        if c["id"] in ("tls-protocols", "https-redirect"):
            icon, st = STATE_ICON.get(c["status"], ("na", "dim"))
            s.item(icon, st, c["title"] + " [active]", c["reason"])
    if not brief:
        add(s)

    # 6. active checks ----------------------------------------------------------------------------------------------------------
    ac = rep.get("active") or {}
    s = Section("Active checks", "Read-only requests that test behaviour. Turn off with --passive.", g, W)
    for c in ac.get("checks", []):
        if c["id"] in ("tls-protocols", "https-redirect") or c["id"] == "error":
            continue
        icon, st = STATE_ICON.get(c["status"], ("na", "dim"))
        s.item(icon, st, c["title"], c["reason"])
    if ac.get("enabled") is False:
        s.line([(g["na"], "dim"), (" skipped (passive mode)", "dim")])
    if not brief:
        add(s)

    # 7. JavaScript recon ---------------------------------------------------------------------------------------------------------
    rc = rep.get("recon") or {}
    s = Section("JavaScript recon", "What the site's own code reveals. Nothing is tested; secrets redacted.", g, W)
    if rc and not rc.get("skipped"):
        sec = rc["secrets"]["items"]
        for x in sec[: (25 if verbose else 5)]:
            icon = "bad" if x["severity"] in ("critical", "high") else "warn" if x["severity"] == "medium" else "na"
            s.line([(g[icon], SEV_STYLE[x["severity"]]), (" ", ""), (x["type"], "emph"), (f"  {x['redacted']}", "value"), (f"  {x['where']}", "dim")])
            s.note(f"{x['severity']}: {x['note']}", 5)
        if not sec:
            s.item("pass", "ok", "Secrets", f"none found in {rc['scanned']['scripts']} scripts and the page")
        elif len(sec) > 5 and not verbose:
            s.note(f"+{len(sec) - 5} more (use -v)")
        ep = rc["endpoints"]
        kinds = [(k, ep["by_kind"][k]) for k in ("admin", "auth", "api", "file", "ops", "websocket") if ep["by_kind"].get(k)]
        s.item("na" if not kinds else "info", "dim", "Endpoints", f"{ep['total']} referenced" + (": " + ", ".join(f"{len(v)} {k}" for k, v in kinds) if kinds else ""))
        for k, items in kinds[:4]:
            for e in items[: (6 if verbose else 2)]:
                s.note(f"{k:<9}{e['value']}", 5)
        h = rc["hosts"]
        for label, vals in (("Internal hosts", h["internal"]), ("Staging hosts", h["staging"])):
            if vals:
                s.item("warn", "warn", label, ", ".join(vals[:4]))
        for b in h["buckets"][:4]:
            s.item("warn", "warn", "Cloud storage", f"{b['provider']} bucket '{b['name']}' referenced: check its access policy")
        for c in rc.get("comments", [])[:3]:
            s.item("warn", "warn", "HTML comment", c)
        for n in rc.get("notes", []):
            s.note(n, 3)
    elif rc.get("skipped"):
        s.line([(g["na"], "dim"), (" skipped", "dim")])
    if not brief:
        add(s)

    # 8. JS libraries ---------------------------------------------------------------------------------------------------------------
    lib, bun = rep.get("libraries") or {}, rep.get("bundle") or {}
    s = Section("JavaScript libraries and bundles", "Client-side library versions and what bundles say about themselves.", g, W)
    for l in lib.get("libraries", []):
        n = len(l["advisories"])
        s.item("warn" if n else "pass", "warn" if n else "ok", f"{l['library']} {l['version']}", f"{n} known advisories" if n else "no known advisories")
    b = bun.get("bundle")
    if b:
        s.item("info", "dim", "Largest bundle", f"{b['url'].rsplit('/', 1)[-1]} ({human_bytes(b.get('size'))}, {'first' if b.get('first_party') else 'third'}-party)")
    for bn in bun.get("banners", [])[:4]:
        if bn.get("library"):
            s.item("info", "dim", "Banner", f"{bn['library']} {bn.get('version', '')} {('· ' + bn['license']) if bn.get('license') else ''}".strip())
    for m in bun.get("source_maps", []):
        if m["status"] in ("exposed", "inline"):
            s.item("warn", "warn", "Source map", f"{m['status']}: original source is publicly readable ({trunc(m['map_url'], 50)})")
    if not brief:
        add(s)

    # 9. edge / network ---------------------------------------------------------------------------------------------------------------
    e = rep.get("edge") or {}
    s = Section("Edge and header consistency", "Who fronts the origin, what leaks through, do header claims agree.", g, W)
    s.item("info" if e.get("edges") else "na", "dim", "Path", e.get("layers", ""))
    for lk in e.get("origin_leaks", [])[:4]:
        s.item("warn", "warn", "Origin leak", f"{lk['header']}: {lk['value']} ({lk['why']})")
    for a in rep.get("anomalies", [])[:5]:
        s.item("warn", "warn" if a["tier"] == "contradiction" else "dim", a["tier"].capitalize(), f"{a['title']} {g['dot']} {trunc(a['why'], 70)}")
    if not brief:
        add(s)

    # 10. third parties, cookies, disclosure --------------------------------------------------------------------------------------------
    tp, hyg = rep.get("third_party") or {}, rep.get("hygiene") or {}
    s = Section("Third parties, cookies and disclosure", "Code you load from others, cookie protection, researcher contact.", g, W)
    n_s = tp.get("scripts_without_sri", 0) + tp.get("styles_without_sri", 0)
    s.item("warn" if n_s or tp.get("insecure_requests") else "pass", "warn" if n_s or tp.get("insecure_requests") else "ok", "Third parties",
           f"{tp.get('origins', 0)} origins" + (f", {n_s} resources without SRI" if n_s else "") + (f", {tp['insecure_requests']} insecure requests" if tp.get("insecure_requests") else ""))
    ck = hyg.get("cookies") or {}
    risky = [c for c in ck.get("cookies", []) if c["issues"]]
    s.item("warn" if risky else "pass", "warn" if risky else "ok", "Cookies", f"{ck.get('total', 0)} set" + (f", {len(risky)} with weaknesses" if risky else ""))
    for c in risky[:3]:
        s.note(f"{c['name']}: {'; '.join(c['issues'][:2])}", 5)
    stx = hyg.get("security_txt") or {}
    icon, st = STATE_ICON.get(stx.get("status", "n/a"), ("na", "dim"))
    s.item(icon, st, "security.txt", stx.get("reason", "n/a"))
    for o in tp.get("top", [])[:5 if verbose else 3]:
        s.note(f"{o['origin']} ({o['requests']} requests)" + (f" {g['dot']} {', '.join(o['technologies'])}" if o.get("technologies") else ""), 5)
    if not brief:
        add(s)

    # 11. nuclei -----------------------------------------------------------------------------------------------------------------------------
    nz = rep.get("nuclei")
    s = Section("Nuclei: suggested next step", "Templates worth running next. Suggestions only; nothing was executed.", g, W)
    if nz:
        for t in nz["by_cve"][: (12 if verbose else 4)]:
            s.line([(t["template"].ljust(18), "emph"), (str(t.get("severity") or "").ljust(9), SEV_STYLE.get(t.get("severity") or "", "dim")), (t["why"], "dim")], 5)
        if len(nz["by_cve"]) > (12 if verbose else 4):
            s.note(f"+{len(nz['by_cve']) - (12 if verbose else 4)} more (use -v)")
        if nz["tags"]:
            s.line([("tags: ", "dim"), (", ".join(f"{t['tag']}" + (f" ({t['templates']})" if t.get("templates") else "") for t in nz["tags"][:8]), "value")], 5)
        for label, cmd in nz["commands"].items():
            s.line([(g["arrow"] + " ", "accent"), (cmd, "url")], 3)
        for n in nz["notes"][:2]:
            s.note(n, 3)
        if not nz["commands"]:
            s.line([(g["na"], "dim"), (" nothing specific to suggest for this target", "dim")])
    add(s)

    return out[:-1] if out and out[-1] == [("", "")] else out
