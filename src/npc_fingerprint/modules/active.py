"""Non-destructive active checks: a handful of single, read-only requests that answer questions passive analysis cannot.

Not path discovery, not brute forcing, nothing that changes server state. Every request is a normal GET/OPTIONS/HEAD (plus one
read-only GraphQL query, only if the site's own JavaScript names a GraphQL endpoint). Total budget: about 8 requests and 4 TLS
handshakes per target, spaced out. Disable everything here with --passive.
"""
from __future__ import annotations

import re
import secrets
import socket
import ssl
import time
from urllib.parse import urlsplit

from ..fetch.snapshot import PageSnapshot
from ..model import Finding
from ..util import extra_request_allowed, is_ip, origin_of, trunc

DELAY = 0.15
PROBE_ORIGIN = "https://npc-fingerprint.invalid"
RISKY_METHODS = {"TRACE": "medium", "TRACK": "medium", "CONNECT": "medium", "PUT": "low", "DELETE": "low", "PROPFIND": "low",
                 "PROPPATCH": "low", "MKCOL": "low", "COPY": "low", "MOVE": "low"}
SERVER_NAMES = {"apache": "Apache HTTP Server", "nginx": "Nginx", "openresty": "OpenResty", "lighttpd": "lighttpd", "litespeed": "LiteSpeed",
                "microsoft-iis": "Microsoft IIS", "tomcat": "Apache Tomcat", "jetty": "Jetty"}
VERSION_DISCLOSURE = re.compile(r"(?i)\b(apache|nginx|openresty|lighttpd|litespeed|microsoft-iis|tomcat|jetty)/(\d+(?:\.\d+){1,3})")
DEBUG_SIGNATURES = [
    ("Werkzeug interactive debugger", re.compile(r"Werkzeug Debugger|The debugger caught an exception", re.I), "high", "an interactive Python console may be reachable"),
    ("Django DEBUG=True", re.compile(r"You're seeing this error because you have <code>DEBUG = True|Using the URLconf defined in"), "high", "settings, paths and SQL are shown on errors"),
    ("Laravel/Ignition debug page", re.compile(r"Whoops, looks like something went wrong|facade/ignition|Illuminate\\\\"), "high", "debug mode exposes source and environment"),
    ("Symfony debug page", re.compile(r"Symfony\\Component|<title>.*Symfony Exception", re.I), "high", "debug mode exposes source and configuration"),
    ("ASP.NET detailed error", re.compile(r"Server Error in '/' Application|Version Information:\s*Microsoft \.NET Framework", re.I), "medium", "stack trace and framework version are shown"),
    ("Stack trace (Java)", re.compile(r"\bat (?:java|javax|org|com)\.[\w.$]+\([\w.]+\.java:\d+\)"), "medium", "internal class names and line numbers leak"),
    ("Stack trace (Python)", re.compile(r"Traceback \(most recent call last\)"), "medium", "internal paths and code leak"),
    ("Stack trace (Node.js)", re.compile(r"\n\s+at .+\(.*(?:node_modules|\.js:\d+:\d+).*\)"), "medium", "internal paths and code leak"),
    ("PHP error message", re.compile(r"(?:Fatal error|Warning|Notice|Parse error): .{0,200} on line \d+"), "medium", "file paths and code context leak"),
    ("Rails routing error page", re.compile(r"Routing Error|ActionController::RoutingError"), "medium", "development-mode error page"),
    ("Spring Whitelabel page", re.compile(r"Whitelabel Error Page"), "low", "confirms Spring Boot defaults"),
]


class _Ctx:
    def __init__(self, snap: PageSnapshot, fetcher):
        self.snap, self.f, self.n = snap, fetcher, 0

    def get(self, name: str, url: str, **kw):
        if not extra_request_allowed(self.snap.host, url):
            return None
        if self.n:
            time.sleep(DELAY)
        self.n += 1
        self.snap.extra_requests.append(f"active:{name}")
        return self.f.get(url, max_bytes=kw.pop("max_bytes", 300_000), **kw)


def _f(id_: str, title: str, status: str, severity: str, reason: str, **data) -> dict:
    return Finding("active", id_, title, status, severity, trunc(reason, 120), data).to_dict()


def check_methods(c: _Ctx, origin: str) -> dict:
    r = c.get("methods", origin + "/", method="OPTIONS")
    if r is None or not r.ok:
        return _f("http-methods", "HTTP methods", "n/a", "info", "OPTIONS request failed")
    raw = (r.header("allow") or "") + "," + (r.header("access-control-allow-methods") or "")
    methods = sorted({m.strip().upper() for m in raw.split(",") if m.strip()})
    if not methods:
        return _f("http-methods", "HTTP methods", "info", "info", f"server did not advertise methods (HTTP {r.status})", status_code=r.status)
    risky = {m: RISKY_METHODS[m] for m in methods if m in RISKY_METHODS}
    if "TRACE" in risky or "TRACK" in risky:
        return _f("http-methods", "HTTP methods", "weak", "medium", "TRACE is enabled: request headers can be reflected (cross-site tracing)", methods=methods)
    if risky:
        return _f("http-methods", "HTTP methods", "weak", "low", f"write/WebDAV methods advertised ({', '.join(risky)}): confirm they require authentication", methods=methods)
    return _f("http-methods", "HTTP methods", "pass", "info", f"only {', '.join(methods)} advertised", methods=methods)


def check_cors(c: _Ctx, origin: str) -> dict:
    results = {}
    for label, o in (("arbitrary", PROBE_ORIGIN), ("null", "null")):
        r = c.get("cors", origin + "/", headers={"Origin": o})
        if r is None or not r.ok:
            continue
        results[label] = ((r.header("access-control-allow-origin") or "").strip(), (r.header("access-control-allow-credentials") or "").strip().lower() == "true")
    if not results:
        return _f("cors", "CORS", "n/a", "info", "request failed")
    acao, cred = results.get("arbitrary", ("", False))
    nacao, ncred = results.get("null", ("", False))
    if acao == PROBE_ORIGIN and cred:
        return _f("cors", "CORS", "weak", "high", "reflects any Origin and allows credentials: any website can read logged-in responses", acao=acao, credentials=True)
    if nacao == "null" and ncred:
        return _f("cors", "CORS", "weak", "high", "trusts Origin: null with credentials (reachable from sandboxed iframes)", acao=nacao, credentials=True)
    if acao == PROBE_ORIGIN:
        return _f("cors", "CORS", "weak", "low", "reflects arbitrary Origins (no credentials): safe only for public data", acao=acao)
    if acao == "*" and cred:
        return _f("cors", "CORS", "weak", "low", "wildcard origin with credentials header (browsers reject it, but it is a misconfiguration)", acao=acao)
    if acao == "*":
        return _f("cors", "CORS", "info", "info", "public wildcard CORS: fine for public data, wrong for private data", acao=acao)
    return _f("cors", "CORS", "pass", "info", "no cross-origin access granted to unknown origins" if not acao else f"restricted to {trunc(acao, 40)}", acao=acao)


def check_https_redirect(c: _Ctx, snap: PageSnapshot) -> dict | None:
    u = urlsplit(snap.final_url)
    if u.scheme != "https" or (u.port not in (None, 443)):
        return None
    r = c.get("http-redirect", f"http://{u.hostname}/", follow=False)
    if r is None:
        return None
    if not r.ok:
        return _f("https-redirect", "HTTP → HTTPS", "info", "info", "port 80 is not reachable (HTTPS-only)")
    loc = r.header("location") or ""
    if r.status in (301, 302, 303, 307, 308) and loc.lower().startswith("https://"):
        return _f("https-redirect", "HTTP → HTTPS", "pass", "info", f"plain HTTP redirects to HTTPS ({r.status})", status_code=r.status)
    if r.status in (301, 302, 303, 307, 308):
        return _f("https-redirect", "HTTP → HTTPS", "weak", "medium", f"plain HTTP redirects to {trunc(loc, 50)}, not to HTTPS", status_code=r.status)
    return _f("https-redirect", "HTTP → HTTPS", "weak", "medium", f"plain HTTP answers {r.status} instead of redirecting to HTTPS", status_code=r.status)


def check_error_page(c: _Ctx, snap: PageSnapshot, origin: str) -> tuple[dict, list[dict]]:
    path = "/npc-fingerprint-" + secrets.token_hex(4)
    r = c.get("error-page", origin + path)
    if r is None or not r.ok:
        return _f("error-page", "Error page", "n/a", "info", "request failed"), []
    body = r.body.decode("utf-8", "replace")
    found = [(n, sev, why) for n, rx, sev, why in DEBUG_SIGNATURES if rx.search(body)]
    disclosures, seen = [], set()
    for src in ((r.header("server") or ""), (r.header("x-powered-by") or ""), body[:60000]):
        for m in VERSION_DISCLOSURE.finditer(src):
            key = (m.group(1).lower(), m.group(2))
            if key not in seen:
                seen.add(key)
                disclosures.append({"technology": SERVER_NAMES.get(key[0], key[0]), "version": key[1], "source": "error page" if src is body[:60000] else "error response header"})
    data = {"status_code": r.status, "signatures": [n for n, _, _ in found], "disclosed": [f"{d['technology']} {d['version']}" for d in disclosures]}
    main_server = (snap.header("server") or "").lower()
    err_server = (r.header("server") or "").lower()
    if err_server and main_server and err_server.split("/")[0] != main_server.split("/")[0]:
        data["different_server_layer"] = err_server
    if found:
        worst = max(found, key=lambda x: {"high": 2, "medium": 1, "low": 0}[x[1]])
        return _f("error-page", "Error page", "weak", worst[1], f"{worst[0]}: {worst[2]}", **data), disclosures
    if disclosures:
        d = disclosures[0]
        return _f("error-page", "Error page", "weak", "low", f"default error page names {d['technology']} {d['version']}", **data), disclosures
    note = "unknown paths return 200 (soft 404)" if r.status == 200 else f"unknown paths return {r.status} with no debug detail"
    return _f("error-page", "Error page", "info" if r.status == 200 else "pass", "info", note, **data), disclosures


_LEGACY = {"TLSv1.0": "TLSv1", "TLSv1.1": "TLSv1_1"}


def _try_version(host: str, port: int, name: str, timeout: float = 4.0) -> str:
    v = getattr(ssl.TLSVersion, {"TLSv1.0": "TLSv1", "TLSv1.1": "TLSv1_1", "TLSv1.2": "TLSv1_2", "TLSv1.3": "TLSv1_3"}[name])
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        ctx.minimum_version = ctx.maximum_version = v
        if name in _LEGACY:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return "untestable"
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=None if is_ip(host) else host):
                return "accepted"
    except ssl.SSLError as e:
        return "untestable" if "NO_PROTOCOLS_AVAILABLE" in str(e) else "rejected"
    except (OSError, socket.timeout):
        return "error"


def check_tls_protocols(c: _Ctx, snap: PageSnapshot) -> dict | None:
    u = urlsplit(snap.final_url)
    if u.scheme != "https" or not u.hostname:
        return None
    host, port = u.hostname, u.port or 443
    res = {}
    for name in ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
        if c.n:
            time.sleep(DELAY)
        snap.extra_requests.append(f"active:tls-{name}")
        res[name] = _try_version(host, port, name)
    acc = [k for k, v in res.items() if v == "accepted"]
    legacy = [k for k in acc if k in _LEGACY]
    untestable = [k for k, v in res.items() if v == "untestable"]
    if legacy:
        return _f("tls-protocols", "TLS versions", "weak", "high" if "TLSv1.0" in legacy else "medium",
                  f"{' and '.join(legacy)} still accepted (deprecated since 2021)", versions=res)
    if "TLSv1.2" not in acc and "TLSv1.3" not in acc and not untestable:
        return _f("tls-protocols", "TLS versions", "info", "info", "could not complete a TLS 1.2/1.3 handshake in this check", versions=res)
    note = f"accepts {', '.join(acc) or 'none'}" + (f"; {', '.join(untestable)} could not be tested with this OpenSSL" if untestable else "")
    if "TLSv1.3" not in acc and "TLSv1.3" not in untestable:
        return _f("tls-protocols", "TLS versions", "weak", "low", note + "; TLS 1.3 not offered", versions=res)
    return _f("tls-protocols", "TLS versions", "pass", "info", note, versions=res)


def check_graphql(c: _Ctx, snap: PageSnapshot, recon: dict | None) -> dict | None:
    eps = ((recon or {}).get("endpoints") or {}).get("graphql") or []
    path = next((e for e in eps if e.startswith("/")), None)
    if not path:
        return None
    url = origin_of(snap.final_url) + path.split("?")[0]
    r = c.get("graphql", url, method="POST", headers={"Content-Type": "application/json", "Accept": "application/json"},
              data=b'{"query":"{__schema{queryType{name}}}"}')
    if r is None or not r.ok:
        return _f("graphql-introspection", "GraphQL introspection", "n/a", "info", "request failed", endpoint=path)
    body = r.body.decode("utf-8", "replace")
    if r.status == 200 and '"__schema"' in body and '"data"' in body:
        return _f("graphql-introspection", "GraphQL introspection", "weak", "medium", f"introspection is enabled on {path}: the full API schema is readable", endpoint=path)
    if "introspection" in body.lower():
        return _f("graphql-introspection", "GraphQL introspection", "pass", "info", f"introspection is disabled on {path}", endpoint=path)
    return _f("graphql-introspection", "GraphQL introspection", "info", "info", f"{path} answered HTTP {r.status} without exposing the schema", endpoint=path)


def analyze(snap: PageSnapshot, fetcher, recon: dict | None) -> dict:
    if snap.status is None or fetcher is None:
        return {"enabled": True, "checks": [], "requests": 0, "disclosures": [], "note": "target unreachable"}
    c = _Ctx(snap, fetcher)
    origin = origin_of(snap.final_url)
    checks: list[dict] = []
    disclosures: list[dict] = []
    for fn in (lambda: check_methods(c, origin), lambda: check_cors(c, origin), lambda: check_https_redirect(c, snap)):
        try:
            r = fn()
            if r:
                checks.append(r)
        except Exception as e:  # noqa: BLE001 - one broken check must not cancel the others
            checks.append(_f("error", "Check failed", "n/a", "info", f"{type(e).__name__}: {e}"))
    try:
        ep, disc = check_error_page(c, snap, origin)
        checks.append(ep)
        disclosures += disc
    except Exception as e:  # noqa: BLE001
        checks.append(_f("error-page", "Error page", "n/a", "info", f"{type(e).__name__}: {e}"))
    for fn in (lambda: check_graphql(c, snap, recon), lambda: check_tls_protocols(c, snap)):
        try:
            r = fn()
            if r:
                checks.append(r)
        except Exception as e:  # noqa: BLE001
            checks.append(_f("error", "Check failed", "n/a", "info", f"{type(e).__name__}: {e}"))
    return {"enabled": True, "checks": checks, "requests": c.n, "disclosures": disclosures,
            "note": "Read-only requests only; nothing was modified, guessed or brute-forced."}
