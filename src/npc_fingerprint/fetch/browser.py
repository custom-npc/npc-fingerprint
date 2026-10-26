"""JavaScript-aware collection with Playwright + Chromium.

One browser per run, one isolated context per URL. Everything the analysis needs is collected from the
single page load the browser performs anyway: rendered DOM, JS globals, DOM-rule hits, script bodies (for
the bundle scan and `scripts` rules), the network log, per-request HTTP protocol (via the DevTools
protocol) and cookie flags. Extra requests (favicon, security.txt...) go through the context's request
API, which reuses cookies and connections.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from .snapshot import (HEAD_BYTES, SCRIPT_TEXT_CAP, TAIL_BYTES, NetRequest, PageSnapshot, ScriptRef)
from .static import FetchResult

try:
    from playwright.sync_api import sync_playwright
    HAVE_PLAYWRIGHT = True
except ImportError:  # pragma: no cover
    HAVE_PLAYWRIGHT = False

MAX_SCRIPT_BODIES = 40
MAX_SCRIPT_BYTES = 6_000_000
MAX_REQUESTS_RECORDED = 600


class BrowserUnavailable(RuntimeError):
    pass


@dataclass
class FetchPlan:
    """What to ask the live page, derived from the fingerprint database (+ retire.js function extractors)."""
    js_chains: list[str] = field(default_factory=list)
    dom: list[dict] = field(default_factory=list)   # {"s": selector, "a": [attrs]|None, "p": [props]|None, "t": bool}


_JS_PROBE = """chains => chains.map(c => { try {
  const v = c.split('.').reduce((o, k) => o[k], window);
  return v === undefined || v === null ? null
       : (typeof v === 'object' || typeof v === 'function') ? '' : String(v).slice(0, 200);
} catch (e) { return null } })"""

_DOM_PROBE = """plan => { const out = {};
  for (const q of plan) {
    let els; try { els = document.querySelectorAll(q.s) } catch (e) { continue }
    if (!els.length) continue;
    const recs = [];
    for (const el of Array.from(els).slice(0, 5)) {
      const r = {};
      if (q.a) { r.a = {}; for (const n of q.a) r.a[n] = el.getAttribute(n) }
      if (q.p) { r.p = {}; for (const n of q.p) { try { const v = el[n]; r.p[n] = v == null ? null : (typeof v === 'object' ? '' : String(v).slice(0, 200)) } catch (e) { r.p[n] = null } } }
      if (q.t) r.t = (el.textContent || '').slice(0, 2000);
      recs.push(r);
    }
    out[q.s] = recs;
  }
  return out }"""

_PAGE_FACTS = """() => {
  const abs = (u) => { try { return new URL(u, document.baseURI).href } catch (e) { return null } };
  const metas = Array.from(document.querySelectorAll('meta')).map(m => [
    (m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv') || '').toLowerCase(),
    m.getAttribute('content') || '']).filter(x => x[0]);
  const scripts = Array.from(document.scripts).map(s => ({
    src: s.getAttribute('src') ? abs(s.getAttribute('src')) : null,
    integrity: s.getAttribute('integrity'), crossorigin: s.getAttribute('crossorigin'), type: s.getAttribute('type'),
    text: s.getAttribute('src') ? null : (s.textContent || '').slice(0, %d)}));
  const links = Array.from(document.querySelectorAll('link[href]')).map(l => ({
    rel: (l.getAttribute('rel') || '').toLowerCase(), href: abs(l.getAttribute('href')),
    integrity: l.getAttribute('integrity'), crossorigin: l.getAttribute('crossorigin')}));
  const text = (document.body ? document.body.innerText : '').slice(0, 100000);
  let css = '';
  try { for (const ss of Array.from(document.styleSheets)) {
    try { for (const r of Array.from(ss.cssRules)) { css += r.cssText + '\\n'; if (css.length > 200000) break } } catch (e) {}
    if (css.length > 200000) break } } catch (e) {}
  const icons = Array.from(document.querySelectorAll('link[rel~="icon" i]')).map(l => abs(l.getAttribute('href'))).filter(Boolean);
  return {metas, scripts, links, text, css, title: document.title, icons};
}""" % SCRIPT_TEXT_CAP


class BrowserFetcher:
    """Fetcher interface backed by the context's APIRequestContext (shares cookies + connections)."""

    def __init__(self, context, timeout: float):
        self._ctx = context
        self.timeout = timeout

    def get(self, url: str, *, headers: dict | None = None, max_bytes: int = 2_000_000,
            range_bytes: int | None = None, method: str = "GET") -> FetchResult:
        res = FetchResult(url=url)
        try:
            fn = self._ctx.request.head if method == "HEAD" else self._ctx.request.get
            r = fn(url, headers=headers or None, timeout=self.timeout * 1000, max_redirects=5,
                   fail_on_status_code=False, ignore_https_errors=True)
            res.url, res.status = r.url, r.status
            ha = r.headers_array                      # property on APIResponse (method on Response)
            ha = ha() if callable(ha) else ha
            res.headers = [(h["name"], h["value"]) for h in ha]
            if method != "HEAD":
                body = r.body()
                res.truncated = len(body) > max_bytes
                res.body = body[:max_bytes]
                res.total_size = len(body)
        except Exception as e:  # noqa: BLE001
            res.error = f"{type(e).__name__}: {e}"[:200]
        return res

    def close(self) -> None:  # lifecycle is owned by Visit
        pass


class Visit:
    """An open page visit: snapshot + a fetcher that stays valid until `close()`."""

    def __init__(self, snapshot: PageSnapshot, fetcher: BrowserFetcher | None, context):
        self.snapshot = snapshot
        self.fetcher = fetcher
        self._ctx = context

    def close(self) -> None:
        try:
            if self._ctx is not None:
                self._ctx.close()
        except Exception:  # noqa: BLE001
            pass


class BrowserSession:
    def __init__(self, user_agent_suffix: str, timeout: float = 20.0):
        if not HAVE_PLAYWRIGHT:
            raise BrowserUnavailable("playwright is not installed (pip install playwright)")
        self.timeout = timeout
        self._suffix = user_agent_suffix
        self._pw = None
        self.browser = None
        self.user_agent: str | None = None

    def __enter__(self) -> "BrowserSession":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def start(self) -> None:
        try:
            self._pw = sync_playwright().start()
            args = []
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                args.append("--no-sandbox")   # required when running as root (containers/CI)
            self.browser = self._pw.chromium.launch(headless=True, args=args)
        except Exception as e:  # noqa: BLE001
            self.close()
            hint = "run: python -m playwright install chromium"
            raise BrowserUnavailable(f"could not launch Chromium ({str(e).splitlines()[0][:120]}); {hint}") from e
        # Honest identification: the real Chromium UA plus our token.
        probe = self.browser.new_context()
        try:
            page = probe.new_page()
            base_ua = page.evaluate("navigator.userAgent")
        finally:
            probe.close()
        self.user_agent = f"{base_ua} {self._suffix}"

    def close(self) -> None:
        try:
            if self.browser is not None:
                self.browser.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            if self._pw is not None:
                self._pw.stop()
        except Exception:  # noqa: BLE001
            pass
        self.browser = self._pw = None

    # ------------------------------------------------------------------
    def open(self, url: str, plan: FetchPlan) -> Visit:
        assert self.browser is not None
        t0 = time.monotonic()
        ctx = self.browser.new_context(
            user_agent=self.user_agent, ignore_https_errors=True, java_script_enabled=True,
            service_workers="block", viewport={"width": 1280, "height": 800}, locale="en-US")
        snap = PageSnapshot(mode="browser", url=url, final_url=url)
        page = ctx.new_page()
        page.set_default_timeout(self.timeout * 1000)
        responses: list = []
        reqs: list[tuple[str, str, str]] = []
        protos: dict[str, dict] = {}
        page.on("response", lambda r: responses.append(r) if len(responses) < 2000 else None)
        page.on("request", lambda r: reqs.append((r.url, r.resource_type, r.method)) if len(reqs) < 2000 else None)
        try:
            cdp = ctx.new_cdp_session(page)
            cdp.send("Network.enable")

            def _on_resp(params):
                r = params.get("response", {})
                protos[r.get("url", "")] = {"protocol": r.get("protocol"), "ip": r.get("remoteIPAddress"),
                                           "type": params.get("type")}
            cdp.on("Network.responseReceived", _on_resp)
        except Exception:  # noqa: BLE001 - protocol visibility is a bonus, not a requirement
            snap.warnings.append("per-request HTTP protocol unavailable (CDP session failed)")

        main = None
        try:
            main = page.goto(url, wait_until="domcontentloaded", timeout=self.timeout * 1000)
        except Exception as e:  # noqa: BLE001
            snap.error = f"navigation failed: {str(e).splitlines()[0][:160]}"
            snap.partial = True
        # Let SPAs hydrate, but never wait unboundedly.
        for state, ms in (("load", 6000), ("networkidle", 3000)):
            try:
                page.wait_for_load_state(state, timeout=ms)
            except Exception:  # noqa: BLE001
                if state == "load":
                    snap.warnings.append("page did not finish loading in time; analysing what rendered")
                    snap.partial = True
        try:
            page.wait_for_timeout(250)
        except Exception:  # noqa: BLE001
            pass

        if main is None:
            snap.elapsed_ms = int((time.monotonic() - t0) * 1000)
            if snap.error is None:
                snap.error = "no main response"
            # Navigation failed outright (DNS, refused, TLS...). Nothing to analyse.
            try:
                if page.url and not page.url.startswith("chrome-error"):
                    snap.final_url = page.url
            except Exception:  # noqa: BLE001
                pass
            return Visit(snap, None, ctx)

        snap.final_url = main.url
        snap.status = main.status
        snap.headers = [(h["name"], h["value"]) for h in main.headers_array()]
        try:
            snap.html_raw = main.text()[:3_000_000]
        except Exception:  # noqa: BLE001
            snap.html_raw = ""
        try:
            sd = main.server_addr()
            snap.server_ip = sd.get("ipAddress") if sd else None
        except Exception:  # noqa: BLE001
            pass
        main_proto = protos.get(main.url) or next((v for v in protos.values() if v.get("type") == "Document"), None)
        if main_proto:
            snap.protocol = main_proto.get("protocol")
            snap.server_ip = snap.server_ip or main_proto.get("ip")
        counts: dict[str, int] = {}
        for v in protos.values():
            if v.get("protocol"):
                counts[v["protocol"]] = counts.get(v["protocol"], 0) + 1
        snap.protocols_seen = counts

        # -- rendered DOM facts -------------------------------------------------
        try:
            snap.html_rendered = page.content()[:3_000_000]
            facts = page.evaluate(_PAGE_FACTS)
            snap.title = (facts.get("title") or "")[:200]
            snap.meta = [(k, v) for k, v in facts.get("metas", [])]
            snap.links = facts.get("links", [])
            snap.text = facts.get("text", "")
            snap.css = facts.get("css", "")
            dom_scripts = facts.get("scripts", [])
            snap.icons = facts.get("icons", [])
        except Exception as e:  # noqa: BLE001
            dom_scripts = []
            snap.warnings.append(f"rendered DOM unavailable: {str(e).splitlines()[0][:100]}")
            snap.partial = True

        # -- JS globals + DOM rule hits -------------------------------------------
        snap.js_values = self._eval_chains(page, plan.js_chains)
        snap.dom_hits = self._eval_dom(page, plan.dom, snap)

        # -- cookies (jar includes JS-set cookies) --------------------------------
        try:
            snap.cookies_jar = ctx.cookies()
        except Exception:  # noqa: BLE001
            snap.cookies_jar = []

        # -- script bodies the browser already downloaded (zero extra requests) ---
        by_url: dict[str, ScriptRef] = {}
        n_bodies = 0
        for r in responses:
            try:
                if r.request.resource_type != "script" or not (200 <= r.status < 300) or n_bodies >= MAX_SCRIPT_BODIES:
                    continue
                clen = r.headers.get("content-length")
                if clen and clen.isdigit() and int(clen) > MAX_SCRIPT_BYTES:
                    by_url[r.url] = ScriptRef(url=r.url, size=int(clen), observed=True)
                    continue
                body = r.body()
                n_bodies += 1
                by_url[r.url] = ScriptRef(
                    url=r.url, size=len(body), head=body[:HEAD_BYTES], tail=body[-TAIL_BYTES:],
                    text=body[:SCRIPT_TEXT_CAP].decode("utf-8", "replace"), observed=True)
            except Exception:  # noqa: BLE001 - body can be evicted; keep going
                continue
        merged: list[ScriptRef] = []
        seen: set[str] = set()
        for d in dom_scripts:
            src = d.get("src")
            if src:
                ref = by_url.get(src) or ScriptRef(url=src)
                ref.integrity, ref.crossorigin, ref.type = d.get("integrity"), d.get("crossorigin"), d.get("type")
                seen.add(src)
                merged.append(ref)
            else:
                merged.append(ScriptRef(url=None, type=d.get("type"), text=d.get("text") or ""))
        for u, ref in by_url.items():          # scripts injected dynamically and already removed from the DOM
            if u not in seen:
                merged.append(ref)
        snap.scripts = merged

        # -- network log -----------------------------------------------------------
        status_by_url = {r.url: r.status for r in responses}
        xhr_hosts: list[str] = []
        for (u, rtype, method) in reqs[:MAX_REQUESTS_RECORDED]:
            snap.requests.append(NetRequest(u, rtype, method, status_by_url.get(u),
                                            (protos.get(u) or {}).get("protocol")))
            if rtype in ("xhr", "fetch"):
                from urllib.parse import urlsplit
                h = urlsplit(u).hostname
                if h and h not in xhr_hosts:
                    xhr_hosts.append(h)
        snap.xhr_hosts = xhr_hosts

        snap.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return Visit(snap, BrowserFetcher(ctx, self.timeout), ctx)

    # ------------------------------------------------------------------
    @staticmethod
    def _eval_chains(page, chains: list[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for i in range(0, len(chains), 1500):
            part = chains[i:i + 1500]
            try:
                vals = page.evaluate(_JS_PROBE, part)
            except Exception:  # noqa: BLE001
                break
            for c, v in zip(part, vals):
                if v is not None:
                    out[c] = v
        return out

    @staticmethod
    def _eval_dom(page, plan: list[dict], snap: PageSnapshot) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        deadline = time.monotonic() + 4.0
        for i in range(0, len(plan), 400):
            if time.monotonic() > deadline:
                snap.warnings.append("DOM rule evaluation stopped at its time budget")
                break
            try:
                out.update(page.evaluate(_DOM_PROBE, plan[i:i + 400]))
            except Exception:  # noqa: BLE001
                break
        return out
