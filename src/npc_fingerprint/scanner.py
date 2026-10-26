"""Orchestration: one `Scanner` per run (one browser, one HTTP session, shared caches), one `scan()` per URL."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from . import UA_TOKEN
from . import regexcompat
from .db.store import DBBundle
from .fetch import static as static_mod
from .fetch.browser import BrowserSession, BrowserUnavailable, FetchPlan
from .fetch.snapshot import PageSnapshot
from .modules import (anomaly, bundle, csp as csp_mod, dnsprobe, drift, edge as edge_mod, favicon, hygiene, libs,
                      secheaders, thirdparty, tls)
from .merge import build_report
from .modules.tech import TechDB
from .util import normalize_url, split_url


@dataclass
class Options:
    no_browser: bool = False
    timeout: float = 20.0
    no_dns: bool = False
    no_cache: bool = False
    baseline: dict | None = None
    top_k: int = 4


class Scanner:
    def __init__(self, opts: Options, db: DBBundle, log=lambda msg: None):
        self.opts, self.db, self.log = opts, db, log
        self.tdb = TechDB(db.techs, db.cats)
        self.retire = libs.RetireDB(db.retire)
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

    def close(self) -> None:
        if self.browser:
            self.browser.close()
        if self.static:
            self.static.close()

    # ------------------------------------------------------------------
    def _open(self, url: str):
        """Return (snapshot, fetcher, closer)."""
        if self.browser is not None:
            v = self.browser.open(url, self.plan)
            return v.snapshot, v.fetcher, v.close
        snap = static_mod.snapshot_from_static(url, self.static)
        return snap, self.static, (lambda: None)

    def scan(self, raw: str) -> dict:
        t0 = time.monotonic()
        url, had_scheme = normalize_url(raw)
        candidates = [url] if had_scheme else [url, "http://" + url.split("://", 1)[1]]
        snap = fetcher = closer = None
        warns = list(self.warnings)
        for i, cand in enumerate(candidates):
            snap, fetcher, closer = self._open(cand)
            if snap.status is not None:
                break
            if i + 1 < len(candidates):
                closer()
                warns.append(f"{cand} unreachable ({snap.error}); retrying over http://")
        assert snap is not None
        try:
            return self._analyze(raw, snap, fetcher, warns, t0)
        finally:
            closer()

    # ------------------------------------------------------------------
    def _safe(self, name: str, fn, default, warns: list[str]):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - one broken module must never sink the report
            warns.append(f"module '{name}' failed: {type(e).__name__}: {str(e)[:100]}")
            return default

    def _analyze(self, raw: str, snap: PageSnapshot, fetcher, warns: list[str], t0: float) -> dict:
        scheme, host, port = split_url(snap.final_url)
        dns_future = None
        pool = ThreadPoolExecutor(max_workers=1)
        if not self.opts.no_dns and host:
            dns_future = pool.submit(dnsprobe.resolve, host)

        tls_res = None
        if snap.status is not None and scheme == "https":
            tls_res = self._safe("tls", lambda: tls.probe(host, port), {"error": "probe crashed"}, warns)
            snap.extra_requests.append("tls-handshake")
        dns = None
        if dns_future is not None:
            dns = self._safe("dns", lambda: dns_future.result(timeout=8), None, warns)
        pool.shutdown(wait=False)

        empty_csp = {"present": False, "enforced": False, "report_only": False, "grade": None, "score": None,
                     "issues": [], "directives": [], "hosts": [], "policies": 0, "via_meta": False}
        csp_res = self._safe("csp", lambda: csp_mod.analyze(snap), empty_csp, warns)
        sec = self._safe("security-headers", lambda: secheaders.analyze(snap, csp_res), [], warns)
        http = tls.http_info(snap, tls_res)
        tls_findings = self._safe("tls-findings", lambda: tls.findings(tls_res, snap), [], warns) if snap.status is not None else []
        edge_res = self._safe("edge", lambda: edge_mod.analyze(snap, dns), {"edges": [], "origin_leaks": [], "proxied": False,
                                                                         "layers": "client → origin", "dns_used": False}, warns)
        observed = snap.protocol or (tls_res or {}).get("alpn")
        anomalies = self._safe("anomaly", lambda: anomaly.analyze(snap, edge_res, observed), [], warns)

        cert = (tls_res or {}).get("cert") or {}
        issuer = f"{cert.get('issuer_o') or ''} {cert.get('issuer_cn') or ''}".strip() or None
        dets, tstats = self._safe("tech", lambda: self.tdb.analyze(snap, cert_issuer=issuer, dns=dns, csp_hosts=csp_res.get("hosts")),
                                  ([], {}), warns)

        fav = {"status": "none", "matches": [], "notes": ["page unreachable"]}
        bun = {"scripts_seen": 0, "scanned": 0, "bundle": None, "banners": [], "source_maps": [], "notes": []}
        lib = {"libraries": [], "advisory_counts": {}, "total_advisories": 0, "note": ""}
        tp = {"origins": 0, "requests": 0, "top": [], "scripts_without_sri": 0, "styles_without_sri": 0, "insecure_requests": 0}
        cookies = {"total": 0, "cookies": [], "counts": {}, "session_cookies_at_risk": 0}
        from .model import Finding
        stx = Finding("hygiene", "security-txt", "security.txt", "n/a", "info", "not checked")
        if snap.status is not None:
            fav = self._safe("favicon", lambda: favicon.analyze(snap, fetcher, self.db.favicons, not self.opts.no_cache), fav, warns)
            bun = self._safe("bundle", lambda: bundle.analyze(snap, fetcher, self.opts.top_k), bun, warns)
            lib = self._safe("libraries", lambda: libs.analyze(snap, self.retire), lib, warns)
            tp = self._safe("third-party", lambda: thirdparty.analyze(snap), tp, warns)
            thirdparty.label_origins(tp, dets)
            cookies = self._safe("cookies", lambda: hygiene.audit_cookies(snap), cookies, warns)
            stx = self._safe("security.txt", lambda: hygiene.check_security_txt(snap, fetcher), stx, warns)

        rep = build_report(
            target=raw, snap=snap, dets=dets, tech_stats=tstats, anomalies=anomalies, favicon=fav, sec=sec, csp=csp_res,
            tls=tls_res, tls_findings=tls_findings, http=http, bundle=bun, libs=lib, edge=edge_res, third_party=tp,
            cookies=cookies, security_txt=stx, dns=dns, db=self.db, tdb=self.tdb, duration_ms=int((time.monotonic() - t0) * 1000),
            warnings=warns, backend=static_mod.BACKEND, regex_stats=dict(regexcompat.STATS),
            engine="regex" if regexcompat.HAVE_REGEX else "re", leak_headers=self._leak)
        if self.opts.baseline is not None:
            old = drift.pick(self.opts.baseline, raw, snap.final_url)
            if old is None:
                rep["warnings"].append("baseline has no report for this target; drift not computed")
            else:
                rep["drift"] = drift.diff(rep, old, self.opts.baseline.get("meta"))
                self._annotate_drift(rep)
        return rep

    @staticmethod
    def _annotate_drift(rep: dict) -> None:
        by = {c["subject"]: c["kind"] for c in rep["drift"]["changes"] if c["area"] == "technology"}
        for d in rep["technologies"]:
            if d["name"] in by:
                d["drift"] = by[d["name"]]
