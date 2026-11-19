"""Small shared helpers: paths, text fitting, URL and version handling."""
from __future__ import annotations

import datetime as _dt
import os
import re
import sys
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit

# ----------------------------------------------------------------------------
# Paths
# ----------------------------------------------------------------------------

def home_dir() -> Path:
    """Root for downloaded databases and caches. Override with NPC_FINGERPRINT_HOME."""
    env = os.environ.get("NPC_FINGERPRINT_HOME")
    if env:
        return Path(env).expanduser()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "npc-fingerprint"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "npc-fingerprint"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "npc-fingerprint"


def data_dir() -> Path:
    return home_dir() / "data"


def cache_dir() -> Path:
    return home_dir() / "cache"


def utcnow_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ----------------------------------------------------------------------------
# Text fitting (cell widths matter for terminal alignment)
# ----------------------------------------------------------------------------

_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]+")


def clean(s: object) -> str:
    """Collapse control characters / whitespace so untrusted text can never inject terminal escapes."""
    return _CTRL.sub(" ", str(s)).strip()


def safe(s: object) -> str:
    """Neutralise control characters (terminal-escape injection) without trimming intentional spacing."""
    return _CTRL.sub(" ", str(s))


def trunc(s: object, n: int) -> str:
    s = clean(s)
    return s if len(s) <= n else s[: max(0, n - 1)] + "…"


def cell_width(ch: str) -> int:
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def str_width(s: str) -> int:
    return sum(cell_width(c) for c in s)


def fit(s: str, width: int, ellipsis: str = "…") -> str:
    """Truncate to `width` terminal cells (not characters)."""
    s = clean(s)
    if str_width(s) <= width:
        return s
    out, used = [], 0
    limit = max(0, width - str_width(ellipsis))
    for ch in s:
        w = cell_width(ch)
        if used + w > limit:
            break
        out.append(ch)
        used += w
    return "".join(out) + ellipsis


def pad(s: str, width: int) -> str:
    return s + " " * max(0, width - str_width(s))


def human_bytes(n: int | None) -> str:
    if n is None:
        return "?"
    x = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if x < 1024 or unit == "GB":
            return f"{int(x)} {unit}" if unit == "B" else f"{x:.0f} {unit}" if x >= 100 else f"{x:.1f} {unit}"
        x /= 1024
    return f"{n} B"


# ----------------------------------------------------------------------------
# URLs and domains
# ----------------------------------------------------------------------------

# Approximation of the public-suffix list for the multi-label suffixes people actually meet.
# Install the optional `publicsuffixlist` package for exact behaviour.
_MULTI_SUFFIXES = frozenset("""
co.uk org.uk me.uk ltd.uk plc.uk ac.uk gov.uk net.uk sch.uk
com.au net.au org.au edu.au gov.au id.au co.nz org.nz net.nz govt.nz ac.nz
co.jp ne.jp or.jp ac.jp go.jp co.kr or.kr ne.kr go.kr
com.cn net.cn org.cn gov.cn edu.cn com.hk org.hk com.tw org.tw com.sg com.my com.ph com.vn
co.id co.th in.th com.br net.br org.br com.ar com.mx com.co com.pe com.ve com.uy com.tr org.tr
co.il org.il co.za org.za co.ke co.in net.in org.in firm.in gen.in ind.in
com.ng com.eg com.sa com.pk com.bd com.ua com.pl net.pl org.pl com.ru
github.io gitlab.io herokuapp.com vercel.app netlify.app pages.dev workers.dev web.app
firebaseapp.com appspot.com azurewebsites.net cloudfront.net s3.amazonaws.com blogspot.com
""".split())

_psl = None
try:  # pragma: no cover - optional dependency
    from publicsuffixlist import PublicSuffixList  # type: ignore

    _psl = PublicSuffixList()
except Exception:  # noqa: BLE001
    _psl = None

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def is_ip(host: str) -> bool:
    return bool(_IPV4.match(host)) or ":" in host


def registrable_domain(host: str) -> str:
    host = (host or "").lower().strip(".")
    if not host or is_ip(host) or "." not in host:
        return host
    if _psl is not None:  # pragma: no cover
        try:
            r = _psl.privatesuffix(host)
            if r:
                return r
        except Exception:  # noqa: BLE001
            pass
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last2 = ".".join(labels[-2:])
    if last2 in _MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last2


def normalize_url(raw: str) -> tuple[str, bool]:
    """Return (url, had_scheme). A bare host gets https:// (the scanner falls back to http://)."""
    raw = raw.strip()
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        return raw, True
    return "https://" + raw, False


def split_url(url: str) -> tuple[str, str, int]:
    p = urlsplit(url)
    scheme = (p.scheme or "https").lower()
    host = p.hostname or ""
    port = p.port or (443 if scheme == "https" else 80)
    return scheme, host, port


def origin_of(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


# ----------------------------------------------------------------------------
# Versions
# ----------------------------------------------------------------------------

_VER = re.compile(r"^v?(\d+(?:\.\d+)*)(?:[-_.]?([A-Za-z]+)[-_.]?(\d*))?")


def version_key(v: str):
    """Comparable key; pre-releases (beta, rc, ...) sort before the release. None if unparseable."""
    m = _VER.match((v or "").strip())
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(".")]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    if m.group(2):
        return (tuple(nums), 0, m.group(2).lower(), int(m.group(3) or 0))
    return (tuple(nums), 1, "", 0)


def cmp_version(a: str, b: str):
    ka, kb = version_key(a), version_key(b)
    if ka is None or kb is None:
        return None
    return (ka > kb) - (ka < kb)


def is_internal_literal(host: str) -> bool:
    """True for localhost and literal private/loopback/link-local/reserved IPs (hostnames are not resolved)."""
    import ipaddress
    h = (host or "").strip("[]").lower()
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified


def extra_request_allowed(target_host: str, url: str) -> bool:
    """Our own follow-up requests (favicon, script heads, source maps) never reach into internal address space
    on behalf of a public page. If the scan target itself is internal, internal follow-ups are fine."""
    host = urlsplit(url).hostname or ""
    return (not is_internal_literal(host)) or is_internal_literal(target_host)
