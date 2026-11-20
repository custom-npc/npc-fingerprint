"""Detect which OS family the target is actually running on, so a CVE's platform precondition (vulns/nvd.py)
can be checked instead of ignored. This is the direct fix for reporting a Windows-only IIS CVE as "critical"
against a Linux-hosted Next.js app: the CVE still *matches by version*, but the platform check moves it out of
the exploitable list and into a clearly explained, separate bucket.

Evidence we trust, in order: an explicit OS-revealing Server/X-Powered-By banner (high confidence) beats a
hosting-edge inference (medium confidence: "fronted by Vercel" means "almost certainly Linux containers", but
that is a convention, not a certificate). Anything else stays "unknown" rather than defaulting to "linux" just
because that is the common case — a wrong default here could wrongly suppress a real finding, which is worse
than not suppressing an unlikely one.
"""
from __future__ import annotations

import re

from .nvd import canon_platform

IIS_RX = re.compile(r"\b(?:microsoft-)?iis\b", re.I)
WINDOWS_RX = re.compile(r"\bwin(?:dows|32|64)\b", re.I)
LINUX_DISTRO_RX = re.compile(r"\b(?:ubuntu|debian|red ?hat|rhel|centos|fedora|alpine|amzn|amazon ?linux|suse|opensuse|el[5-9](?:_\d+)?)\b", re.I)
UNIXY_SERVER_RX = re.compile(r"\b(?:apache|nginx|openresty|lighttpd|litespeed|caddy|gunicorn|uvicorn|puma|unicorn)\b", re.I)
# Hosting/edge products that run their compute on Linux containers as a matter of how the product works, not a guess.
LINUX_EDGE_NAMES = {"vercel edge", "netlify edge", "amazon cloudfront", "fastly", "akamai", "google cloud front end",
                    "azure front door / azure cdn", "azure front door / cdn"}


def detect(target_banner: str | None, powered_by: str | None, edge_names: list[str], tech_names: set[str]) -> dict:
    """-> {"os": "windows"|"linux"|"macos"|"unknown", "confidence": "high"|"medium"|None, "evidence": str}"""
    banner = target_banner or ""
    pb = powered_by or ""
    if IIS_RX.search(banner) or IIS_RX.search(pb) or "microsoft iis" in {n.lower() for n in tech_names}:
        return {"os": "windows", "confidence": "high", "evidence": f"Server/X-Powered-By names IIS ({banner or pb})"}
    if WINDOWS_RX.search(banner):
        return {"os": "windows", "confidence": "high", "evidence": f"Server banner names Windows ({banner})"}
    if LINUX_DISTRO_RX.search(banner):
        m = LINUX_DISTRO_RX.search(banner)
        return {"os": "linux", "confidence": "high", "evidence": f"Server banner names a Linux distribution ({m.group(0)}: {banner})"}
    for name in edge_names:
        if name.lower() in LINUX_EDGE_NAMES:
            return {"os": "linux", "confidence": "medium", "evidence": f"fronted by {name} (runs on Linux containers by convention, not confirmed on the origin itself)"}
    if UNIXY_SERVER_RX.search(banner) and not WINDOWS_RX.search(banner):
        # Apache/nginx/etc. *can* run on Windows, so this is weaker than a distro string, but still a useful lead.
        return {"os": "linux", "confidence": "medium", "evidence": f"Server banner ({banner}) is a Unix-family web server (also available on Windows, so this is a lead, not a certainty)"}
    return {"os": "unknown", "confidence": None, "evidence": "no platform-revealing signal found"}


def mismatch(required: str | None, detected: dict) -> bool:
    """True only when we are reasonably sure the target's OS is NOT the one the CVE requires."""
    req = canon_platform(required)
    if not req or detected["confidence"] is None:
        return False
    return req != detected["os"]
