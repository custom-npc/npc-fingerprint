"""Orchestration: one `Scanner` per run (one browser, one HTTP session, shared caches), one `scan()` per URL.

Everything a scan does happens here, in one pass, in this order:
  load -> tls -> headers -> tech -> favicon -> bundle -> recon -> active -> vulns -> nuclei -> report
Each stage reports into a Progress object (live view) and degrades to a warning instead of failing the scan.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import UA_TOKEN, regexcompat
from .db.store import DBBundle
from .fetch import static as static_mod
from .fetch.browser import BrowserSession, BrowserUnavailable, FetchPlan
from .fetch.snapshot import PageSnapshot
from .merge import build_actions, build_report, build_surface
from .model import Finding
from .modules import (active as active_mod, anomaly, bundle, csp as csp_mod, dnsprobe, drift, edge as edge_mod, favicon, hygiene, jsrecon,
                      libs, nuclei as nuclei_mod, secheaders, thirdparty, tls)
from .modules.tech import TechDB
from .render.live import NullProgress, Progress
from .util import normalize_url, split_url
from .vulns import engine as vuln_engine
from .vulns.db import VulnDB
from .vulns.osv import OsvClient

SKIPPABLE = {"favicon", "bundle", "recon", "active", "vulns", "nuclei", "dns"}


@dataclass
class Options:
    no_browser: bool = False
    timeout: float = 20.0
    no_dns: bool = False
    no_cache: bool = False
    baseline: dict | None = None
    top_k: int = 4
    passive: bool = False          # no active checks (the page load itself is always made)
    offline: bool = False          # no network except the target (CVE data from local files and caches only)
    skip: set = field(default_factory=set)
    db_dir: str | None = None


class Scanner:
    def __init__(self, opts: Options, db: DBBundle, log=lambda msg: None):
        self.opts, self.db, self.log = opts, db, log
        if opts.no_dns:
            opts.skip.add("dns")
        self.tdb = TechDB(db.techs, db.cats)
        self.retire = libs.RetireDB(db.retire)
        self.vdb = VulnDB.open(opts.db_dir)
        self.osv = OsvClient(offline=opts.offline, use_cache=not opts.no_cache)
        self.warnings: list[str] = []
        self.browser: BrowserSession | None = None
        self.static: static_mod.StaticFetcher | None = None
        self._leak = set(edge_mod.edge_rules().get("origin_leaks", {}).get("headers", []))
        chains = list(dict.fromkeys(self.tdb.js_chains() + self.retire.func_chains()))
        self.plan = FetchPlan(js_chains=chains, dom=self.tdb.dom_plan())
        if not opts.no_browser:
            try:
                self.browser = BrowserSession(UA_TOKEN, opts.timeout)
                self.browser.start()
            except BrowserUnavailable as e:
                self.browser = None
                self.warnings.append(f"JavaScript rendering unavailable, using static fetching: {e}")
        ua = (self.browser.user_agent if self.browser else f"Mozilla/5.0 (compatible; {UA_TOKEN})")
        self.static = static_mod.StaticFetcher(ua, timeout=min(opts.timeout, 15.0))
        if not self.vdb.available:
            self.warnings.append("CVE/exploit database not installed: run `npc-fingerprint setup` (OSV lookups still work online)")

    def close(self) -> None:
        if self.browser:
            self.browser.close()
        if self.static:
            self.static.close()

    # ------------------------------------------------------------------
    def _open(self, url: str):
        if self.browser is not None:
            v = self.browser.open(url, self.plan)
            return v.snapshot, v.fetcher, v.close
        snap = static_mod.snapshot_from_static(url, self.static)
        return snap, self.static, (lambda: None)

    def scan(self, raw: str, progress: Progress | None = None) -> dict:
        t0 = time.monotonic()
        pr = progress or NullProgress()
        url, had_scheme = normalize_url(raw)
        candidates = [url] if had_scheme else [url, "http://" + url.split("://", 1)[1]]
        snap = fetcher = closer = None
        warns = list(self.warnings)
        pr.start("load", f"Opening {url}")
        for i, cand in enumerate(candidates):
            snap, fetcher, closer = self._open(cand)
            if snap.status is not None:
                break
            if i + 1 < len(candidates):
                closer()
                warns.append(f"{cand} unreachable ({snap.error}); retrying over http://")
                pr.say(f"{cand} unreachable, trying http://")
        assert snap is not None
        pr.done("load", (f"HTTP {snap.status} · {len(snap.requests)} requests · {snap.mode}" if snap.status is not None else f"unreachable: {snap.error}"),
                "ok" if snap.status is not None else "bad")
        try:
            return self._analyze(raw, snap, fetcher, warns, t0, pr)
        finally:
            closer()

    # ------------------------------------------------------------------
    def _safe(self, name: str, fn, default, warns: list[str]):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - one broken module must never sink the report
            warns.append(f"module '{name}' failed: {type(e).__name__}: {str(e)[:100]}")
            return default

    def _analyze(self, raw: str, snap: PageSnapshot, fetcher, warns: list[str], t0: float, pr: Progress) -> dict:
        scheme, host, port = split_url(snap.final_url)
        reachable = snap.status is not None
        skip = self.opts.skip
        dns_future = None
        pool = ThreadPoolExecutor(max_workers=1)
        if "dns" not in skip and host and reachable:
            dns_future = pool.submit(dnsprobe.resolve, host)

        # -- TLS / HTTP --------------------------------------------------------------------------------
        pr.start("tls", "TLS handshake and certificate")
        tls_res = None
        if reachable and scheme == "https":
            tls_res = self._safe("tls", lambda: tls.probe(host, port), {"error": "probe crashed"}, warns)
            snap.extra_requests.append("tls-handshake")
        dns = None
        if dns_future is not None:
            pr.say("Looking up DNS records (CNAME, NS, MX, TXT)")
            dns = self._safe("dns", lambda: dns_future.result(timeout=8), None, warns)
        pool.shutdown(wait=False)
        http = tls.http_info(snap, tls_res)
        tls_findings = self._safe("tls-findings", lambda: tls.findings(tls_res, snap), [], warns) if reachable else []
        if not reachable:
            pr.skip("tls", "target unreachable")
        elif scheme != "https":
            pr.done("tls", "plain HTTP: no TLS", "bad")
        elif (tls_res or {}).get("error"):
            pr.done("tls", "probe failed", "warn")
        else:
            c = (tls_res or {}).get("cert") or {}
            pr.done("tls", f"{str(tls_res.get('tls_version', '')).replace('TLSv', '')} · {http.get('summary') or '?'} · {c.get('issuer', '?')}",
                    "warn" if (tls_res.get("verified") is False or tls_findings) else "ok")

        # -- headers + anomalies --------------------------------------------------------------------------
        pr.start("headers", "Checking security headers and header consistency")
        empty_csp = {"present": False, "enforced": False, "report_only": False, "grade": None, "score": None, "issues": [], "directives": [],
                     "hosts": [], "policies": 0, "via_meta": False}
        csp_res = self._safe("csp", lambda: csp_mod.analyze(snap), empty_csp, warns)
        sec = self._safe("security-headers", lambda: secheaders.analyze(snap, csp_res), [], warns)
        edge_res = self._safe("edge", lambda: edge_mod.analyze(snap, dns), {"edges": [], "origin_leaks": [], "proxied": False,
                                                                         "layers": "client → origin", "dns_used": False}, warns)
        observed = snap.protocol or (tls_res or {}).get("alpn")
        anomalies = self._safe("anomaly", lambda: anomaly.analyze(snap, edge_res, observed), [], warns)
        passed = sum(1 for f in sec if f.status == "pass")
        pr.done("headers", f"{passed}/{len(sec)} present · CSP {csp_res.get('grade') or 'none'}" + (f" · {len(anomalies)} anomalies" if anomalies else ""),
                "ok" if passed == len(sec) and not anomalies else "warn") if reachable else pr.skip("headers", "target unreachable")

        # -- technologies ---------------------------------------------------------------------------------
        pr.start("tech", f"Matching {len(self.db.techs):,} technology signatures")
        cert = (tls_res or {}).get("cert") or {}
        issuer = f"{cert.get('issuer_o') or ''} {cert.get('issuer_cn') or ''}".strip() or None
        dets, tstats = self._safe("tech", lambda: self.tdb.analyze(snap, cert_issuer=issuer, dns=dns, csp_hosts=csp_res.get("hosts")), ([], {}), warns)
        pr.done("tech", f"{sum(1 for d in dets if d.status in ('confirmed', 'probable'))} technologies") if reachable else pr.skip("tech", "target unreachable")

        fav = {"status": "none", "matches": [], "notes": ["page unreachable"]}
        bun = {"scripts_seen": 0, "scanned": 0, "bundle": None, "banners": [], "source_maps": [], "notes": []}
        lib = {"libraries": [], "advisory_counts": {}, "total_advisories": 0, "note": ""}
        tp = {"origins": 0, "requests": 0, "top": [], "scripts_without_sri": 0, "styles_without_sri": 0, "insecure_requests": 0}
        cookies = {"total": 0, "cookies": [], "counts": {}, "session_cookies_at_risk": 0}
        stx = Finding("hygiene", "security-txt", "security.txt", "n/a", "info", "not checked")
        recon = {"skipped": True}
        active = {"enabled": False, "checks": [], "note": "skipped"}
        if reachable:
            pr.start("favicon", "Hashing the favicon")
            if "favicon" in skip:
                pr.skip("favicon", "skipped")
            else:
                fav = self._safe("favicon", lambda: favicon.analyze(snap, fetcher, self.db.favicons, not self.opts.no_cache), fav, warns)
                pr.done("favicon", (f"matches {fav['matches'][0]['name']} (possible)" if fav.get("matches") else "no database match" if fav.get("status") == "no-match" else "no favicon"))
            pr.start("bundle", "Scanning JavaScript bundles for banners and source maps")
            if "bundle" in skip:
                pr.skip("bundle", "skipped")
            else:
                bun = self._safe("bundle", lambda: bundle.analyze(snap, fetcher, self.opts.top_k), bun, warns)
                lib = self._safe("libraries", lambda: libs.analyze(snap, self.retire), lib, warns)
                maps = sum(1 for m in bun.get("source_maps", []) if m["status"] in ("exposed", "inline"))
                pr.done("bundle", f"{bun.get('scanned', 0)} scripts · {len(bun.get('banners', []))} banners" + (f" · {maps} source map exposed" if maps else ""),
                        "warn" if maps or lib.get("total_advisories") else "ok")
            tp = self._safe("third-party", lambda: thirdparty.analyze(snap), tp, warns)
            thirdparty.label_origins(tp, dets)
            cookies = self._safe("cookies", lambda: hygiene.audit_cookies(snap), cookies, warns)
            pr.start("recon", "Mining first-party JavaScript for endpoints and secrets")
            if "recon" in skip:
                pr.skip("recon", "skipped")
            else:
                recon = self._safe("recon", lambda: jsrecon.analyze(snap, fetcher), {"skipped": True, "error": True}, warns)
                n_sec = (recon.get("secrets") or {}).get("count", 0)
                pr.done("recon", f"{(recon.get('endpoints') or {}).get('total', 0)} endpoints · {n_sec} secrets",
                        "bad" if any(s["severity"] in ("critical", "high") for s in (recon.get("secrets") or {}).get("items", [])) else "warn" if n_sec else "ok")
            pr.start("active", "Running read-only active checks (CORS, methods, error page, TLS versions)")
            if self.opts.passive or "active" in skip:
                pr.skip("active", "passive mode" if self.opts.passive else "skipped")
            else:
                active = self._safe("active", lambda: active_mod.analyze(snap, fetcher, recon), active, warns)
                weak = sum(1 for c in active.get("checks", []) if c["status"] == "weak")
                pr.done("active", f"{len(active.get('checks', []))} checks · {weak} findings", "warn" if weak else "ok")
            stx = self._safe("security.txt", lambda: hygiene.check_security_txt(snap, fetcher), stx, warns)
        else:
            for k in ("favicon", "bundle", "recon", "active"):
                pr.skip(k, "target unreachable")

        pr.start("report", "Merging evidence into the report")
        rep = build_report(
            target=raw, snap=snap, dets=dets, tech_stats=tstats, anomalies=anomalies, favicon=fav, sec=sec, csp=csp_res,
            tls=tls_res, tls_findings=tls_findings, http=http, bundle=bun, libs=lib, edge=edge_res, third_party=tp,
            cookies=cookies, security_txt=stx, dns=dns, db=self.db, tdb=self.tdb, duration_ms=0,
            warnings=warns, backend=static_mod.BACKEND, regex_stats=dict(regexcompat.STATS),
            engine="regex" if regexcompat.HAVE_REGEX else "re", leak_headers=self._leak, recon=recon, active=active)

        # -- vulnerabilities (needs the final, merged technology list) ------------------------------------------
        pr.start("vulns", "Matching detected versions against CVE data")
        if "vulns" in skip or not reachable:
            pr.skip("vulns", "skipped" if reachable else "target unreachable")
        else:
            rep["vulnerabilities"] = self._safe("vulnerabilities", lambda: vuln_engine.run(
                rep["technologies"], self.db.techs, self.vdb, self.osv, rep["libraries"], rep["target"].get("banners", {})), None, rep["warnings"])
            v = rep["vulnerabilities"]
            if v is None:
                pr.done("vulns", "failed", "warn")
            else:
                bp = v["by_priority"]
                pr.done("vulns", f"{v['total']} CVEs · {bp['exploited']} exploited · {bp['weaponized']} with public exploit · {len(v['checked'])} versions checked",
                        "bad" if (bp["exploited"] or bp["weaponized"]) else "warn" if v["total"] or v["status"] != "ok" else "ok")
                for e in v["sources"]["osv"]["errors"][:2]:
                    rep["warnings"].append(f"OSV: {e}")

        pr.start("nuclei", "Choosing Nuclei templates for what was found")
        if "nuclei" in skip or not reachable:
            pr.skip("nuclei", "skipped" if reachable else "target unreachable")
        else:
            rep["nuclei"] = self._safe("nuclei", lambda: nuclei_mod.suggest(rep, self.vdb, self.db.techs, rep["target"]["final_url"]), None, rep["warnings"])
            nz = rep["nuclei"]
            pr.done("nuclei", f"{len(nz['by_cve'])} CVE templates · {len(nz['tags'])} tags" if nz else "failed", "ok" if nz else "warn")

        if self.opts.baseline is not None:
            old = drift.pick(self.opts.baseline, raw, snap.final_url)
            if old is None:
                rep["warnings"].append("baseline has no report for this target; drift not computed")
            else:
                rep["drift"] = drift.diff(rep, old, self.opts.baseline.get("meta"))
                self._annotate_drift(rep)
        rep["actions"] = build_actions(rep)
        rep["summary"] = build_surface(rep)
        rep["duration_ms"] = int((time.monotonic() - t0) * 1000)
        pr.done("report", f"{len(rep['actions'])} priority actions")
        return rep

    @staticmethod
    def _annotate_drift(rep: dict) -> None:
        by = {c["subject"]: c["kind"] for c in rep["drift"]["changes"] if c["area"] == "technology"}
        for d in rep["technologies"]:
            if d["name"] in by:
                d["drift"] = by[d["name"]]
