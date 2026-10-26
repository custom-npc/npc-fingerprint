"""Data shapes shared across modules. Everything serialises to plain JSON via `to_dict`."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Evidence:
    """One concrete reason a detection exists. Nothing is reported without at least one."""

    module: str            # tech | favicon | bundle | headers | tls | edge | csp ...
    signal: str            # header, cookie, meta, script-src, js-global, dom, url, html, text, css, script, xhr,
                           # cert-issuer, dns, favicon-mmh3, favicon-md5, banner, csp-allowlist, implies
    location: str          # which header / cookie / selector / URL the signal came from
    matched: str           # the (truncated, sanitised) text that matched
    pattern: str = ""      # the rule that matched (truncated)
    confidence: int = 100  # this evidence's contribution, 0..100
    version: str | None = None
    view: str = "rendered"  # raw | rendered | both | n/a
    source: str = "webappanalyzer"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Detection:
    name: str
    categories: list[str]
    confidence: int
    version: str | None = None
    status: str = "confirmed"      # confirmed | probable | weak | disputed | implied
    basis: str = "observed"        # observed | claimed (only self-declared headers/meta) | inferred
    layer: str = "unknown"         # edge | origin | app | client | unknown
    evidence: list[Evidence] = field(default_factory=list)
    implied_by: list[str] = field(default_factory=list)
    website: str | None = None
    cpe: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["evidence"] = [e.to_dict() for e in self.evidence]
        return d


@dataclass
class Finding:
    """A pass/weak/missing style result with a one-line reason (headers, cookies, security.txt...)."""

    module: str
    id: str
    title: str
    status: str            # pass | weak | missing | n/a | info
    severity: str          # info | low | medium | high
    reason: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def band(conf: int) -> str:
    """Confidence band used everywhere: >=90 confirmed, 50-89 probable, <50 weak."""
    return "confirmed" if conf >= 90 else "probable" if conf >= 50 else "weak"
