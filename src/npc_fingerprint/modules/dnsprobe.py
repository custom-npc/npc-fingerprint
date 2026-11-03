"""Public DNS lookups (CNAME chain, NS, MX, TXT, SOA). Queries go to the user's resolver, never to the target."""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from ..util import is_ip, registrable_domain

try:
    import dns.exception
    import dns.resolver
    HAVE_DNSPYTHON = True
except ImportError:  # pragma: no cover
    HAVE_DNSPYTHON = False


def _clean(name: str) -> str:
    return name.rstrip(".").lower()


def _dnspython_query(name: str, rtype: str, lifetime: float) -> list[str]:
    r = dns.resolver.Resolver()
    r.lifetime = lifetime
    try:
        ans = r.resolve(name, rtype)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException):
        return []
    out = []
    for rd in ans:
        if rtype == "CNAME":
            out.append(_clean(str(rd.target)))
        elif rtype == "NS":
            out.append(_clean(str(rd.target)))
        elif rtype == "MX":
            out.append(_clean(str(rd.exchange)))
        elif rtype == "SOA":
            out.append(_clean(str(rd.mname)))
        elif rtype == "TXT":
            out.append(b"".join(rd.strings).decode("utf-8", "replace")[:300])
    return out


def resolve(host: str, lifetime: float = 2.0, query=None) -> dict[str, list[str]]:
    """Return {"CNAME": [chain...], "NS": [...], "MX": [...], "TXT": [...], "SOA": [...]} (empty lists dropped)."""
    if not host or is_ip(host) or host == "localhost" or "." not in host:
        return {}
    q = query or (_dnspython_query if HAVE_DNSPYTHON else None)
    if q is None:   # stdlib fallback: the canonical name is the end of the CNAME chain
        try:
            canon = socket.getaddrinfo(host, None, flags=socket.AI_CANONNAME)[0][3]
            return {"CNAME": [_clean(canon)]} if canon and _clean(canon) != _clean(host) else {}
        except OSError:
            return {}

    def cname_chain() -> list[str]:
        chain, name = [], host
        for _ in range(8):
            t = q(name, "CNAME", lifetime) if q is _dnspython_query else q(name, "CNAME")
            if not t:
                break
            chain.append(t[0])
            name = t[0]
        return chain

    apex = registrable_domain(host)
    jobs = {"CNAME": cname_chain}
    for rt in ("NS", "MX", "TXT", "SOA"):
        jobs[rt] = (lambda rt=rt: q(apex, rt, lifetime) if q is _dnspython_query else q(apex, rt))
    out: dict[str, list[str]] = {}
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {k: ex.submit(fn) for k, fn in jobs.items()}
        for k, f in futs.items():
            try:
                v = f.result(timeout=lifetime * 4)
            except Exception:  # noqa: BLE001
                v = []
            if v:
                out[k] = v
    return out
