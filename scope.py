"""Scope guard: before anything new this round touches a URL that wasn't the page the user asked to scan
(an endpoint mined from JavaScript, a lazy chunk, a shadow API version), check it's actually in scope.

Default scope is the scanned target's own registrable domain. `--scope` lets the user declare extra domains
(an API host, a CDN that also hosts first-party code) as explicitly allowed. Anything outside scope is still
reported (it came from the site's own code, so it's worth knowing about) but never requested.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from ..util import registrable_domain


def in_scope(url: str, target_host: str, allowed: list[str] | None = None) -> bool:
    """True if `url` may be fetched: same registrable domain as the target, or explicitly allowed."""
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return False
    if registrable_domain(host) == registrable_domain(target_host):
        return True
    return bool(allowed) and any(registrable_domain(host) == registrable_domain(a) for a in allowed)


def filter_in_scope(urls: list[str], target_host: str, allowed: list[str] | None = None) -> tuple[list[str], list[str]]:
    """(in_scope_urls, out_of_scope_urls), order preserved, de-duplicated."""
    seen_in: set[str] = set()
    seen_out: set[str] = set()
    ins, outs = [], []
    for u in urls:
        if in_scope(u, target_host, allowed):
            if u not in seen_in:
                seen_in.add(u)
                ins.append(u)
        elif u not in seen_out:
            seen_out.add(u)
            outs.append(u)
    return ins, outs
