"""Deeper recon from code the site already serves: endpoints, hosts, cloud buckets, exposed secrets, HTML comments.

Passive by construction. Nothing found here is requested, probed or validated (a discovered secret is never "tried"; a
discovered endpoint is never fetched, except the single opt-in GraphQL introspection check in active.py). This is *not*
hidden-path discovery: every item was literally written into the page or its scripts.

Secrets are ALWAYS redacted in output (first 4 + last 2 characters and the length) so reports and baselines are safe to share.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
from urllib.parse import urlsplit

from ..fetch.snapshot import PageSnapshot
from ..util import registrable_domain, trunc

MAX_TOTAL_BYTES = 12_000_000
TIME_BUDGET = 6.0
STATIC_FETCH_LIMIT = 8

URL_RX = re.compile(r"""(?:https?|wss?)://[A-Za-z0-9_.\-]+(?::\d{2,5})?(?:/[^\s"'`<>\\)\]},;]*)?""")
PATH_RX = re.compile(r"""["'`](/(?!/)[A-Za-z0-9_\-.~%@:+=?&/{}$]{2,200})["'`]""")
STATIC_EXT = re.compile(r"\.(?:png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|otf|map|mp4|webm|webp|avif|mp3|ogg|wasm)(?:\?|$)", re.I)
STATIC_PREFIX = ("/static/", "/assets/", "/images/", "/img/", "/fonts/", "/css/", "/js/", "/_next/", "/_nuxt/", "/node_modules/", "/dist/", "/build/", "/webpack", "/locales/", "/i18n/")
KINDS = (
    ("admin", re.compile(r"(?:^|/)(?:admin\w*|manage\w*|internal|private|debug|console|actuator\w*|swagger\w*|openapi\w*|api-docs|graphiql|phpinfo|backoffice|staff|cms)(?:/|\.|$|\?)", re.I)),
    ("auth", re.compile(r"(?:^|/)(?:login|logout|signin|signup|sign-in|register|oauth2?|openid|sso|saml\d*|token|auth\w*|session\w*|password|reset\w*|2fa|mfa|verify\w*)(?:/|\.|$|\?)", re.I)),
    ("api", re.compile(r"(?:^|/)(?:api|rest|graphql|gql|rpc|odata|ajax|xhr|services?|v\d+(?:\.\d+)?)(?:/|\.|$|\?)", re.I)),
    ("file", re.compile(r"(?:^|/)(?:upload\w*|download\w*|export\w*|import\w*|files?|attachments?|backups?)(?:/|\.|$|\?)", re.I)),
    ("ops", re.compile(r"(?:^|/)(?:metrics|health\w*|status|ping|version|info)(?:/|\.|$|\?)", re.I)),
)
NOISE_HOSTS = ("w3.org", "schema.org", "purl.org", "ogp.me", "reactjs.org", "react.dev", "fb.me", "github.com", "npmjs.com", "mozilla.org",
               "stackoverflow.com", "wikipedia.org", "creativecommons.org", "apache.org", "gnu.org", "example.com", "example.org", "localhost.localdomain",
               "xmlsoap.org", "microsoft.com/fwlink", "json-schema.org", "tc39.es", "whatwg.org", "ecma-international.org")
INTERNAL_HOST = re.compile(r"^(?:localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)$|\.(?:internal|local|corp|lan|intranet|home)$", re.I)
STAGING_HOST = re.compile(r"(?:^|[.\-])(?:dev|staging|stage|stg|uat|qa|preprod|sandbox|test)(?:[.\-]|$)", re.I)
BUCKETS = (
    ("AWS S3", re.compile(r"\b([a-z0-9][a-z0-9.\-]{2,62})\.s3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com\b", re.I)),
    ("AWS S3", re.compile(r"(?<![A-Za-z0-9.\-])s3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com/([a-z0-9][a-z0-9.\-]{2,62})", re.I)),
    ("Google Cloud Storage", re.compile(r"\bstorage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{2,62})", re.I)),
    ("Azure Blob", re.compile(r"\b([a-z0-9]{3,24})\.blob\.core\.windows\.net\b", re.I)),
    ("DigitalOcean Spaces", re.compile(r"\b([a-z0-9\-]{3,63})\.[a-z0-9]{3,5}\.digitaloceanspaces\.com\b", re.I)),
    ("Firebase RTDB", re.compile(r"\b([a-z0-9\-]{3,40})\.firebaseio\.com\b", re.I)),
)
COMMENT_RX = re.compile(r"<!--(?!\[if|<!\[)(.{4,400}?)-->", re.S)
COMMENT_KEYWORDS = re.compile(r"password|passwd|secret|token|api[_\- ]?key|todo|fixme|hack|credential|username|staging|internal|debug|admin|10\.\d+\.\d+\.\d+|192\.168\.", re.I)

# (type, regex, severity, confidence, note, required substrings (cheap prefilter, matched case-insensitively against a lowered copy))
SECRET_PATTERNS = [
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"), "medium", "high", "pairs with a secret key; rotate if the secret leaked too", ("akia", "asia", "agpa", "aida", "aroa", "anpa")),
    ("AWS secret access key", re.compile(r"(?i)aws.{0,30}(?:secret|private).{0,30}[\"']([A-Za-z0-9/+=]{40})[\"']"), "critical", "high", "full AWS credential material", ("aws",)),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "low", "high", "browser key by design: confirm referrer/API restrictions", ("aiza",)),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"), "critical", "high", "grants repository access", ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"), "high", "high", "workspace access", ("xox",)),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"), "high", "high", "anyone can post to your Slack", ("hooks.slack.com",)),
    ("Discord webhook", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,}"), "high", "high", "anyone can post to your Discord", ("webhooks",)),
    ("Stripe secret key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{24,}\b"), "critical", "high", "full Stripe account access", ("k_live_",)),
    ("Stripe publishable key", re.compile(r"\bpk_live_[0-9A-Za-z]{24,}\b"), "info", "high", "public by design", ("pk_live_",)),
    ("Twilio API key", re.compile(r"\bSK[0-9a-f]{32}\b"), "high", "medium", "Twilio API access", ("sk",)),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "high", "high", "send mail as you", ("sg.",)),
    ("Mailgun API key", re.compile(r"\bkey-[0-9a-f]{32}\b"), "high", "medium", "send mail as you", ("key-",)),
    ("Telegram bot token", re.compile(r"(?i)(?:bot|telegram[^\"'\n]{0,30})\d{8,10}:[A-Za-z0-9_\-]{35}\b"), "high", "medium", "control of a Telegram bot", ("bot", "telegram")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"), "critical", "high", "private key material published in a page", ("private key",)),
    ("Google service account", re.compile(r"\"type\"\s*:\s*\"service_account\""), "critical", "high", "service-account credentials file", ("service_account",)),
    ("Azure storage key", re.compile(r"AccountKey=[A-Za-z0-9+/=]{60,}"), "critical", "high", "full storage account access", ("accountkey=",)),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "critical", "high", "publish rights to npm packages", ("npm_",)),
    ("Mapbox secret token", re.compile(r"\bsk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b"), "high", "high", "Mapbox secret scope token", ("sk.eyj",)),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "medium", "high", "a signed token shipped in client code", ("eyj",)),
]
GENERIC = re.compile(r"""(?i)\b([a-z0-9_.\-]{0,24}(?:secret|passwd|password|api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|private[_\-]?key))["']?\s*[:=]\s*["']([^"'\s]{12,100})["']""")
GENERIC_HINTS = ("secret", "passwd", "password", "api_key", "api-key", "apikey", "access_token", "access-token", "auth_token", "auth-token", "client_secret", "private_key")
PLACEHOLDER = re.compile(r"your|example|change.?me|x{4,}|\*{3,}|placeholder|sample|dummy|todo|insert|<|\{\{|\$\{|process\.env|undefined|null|true|false|lorem|password|secret|token", re.I)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def redact(value: str, kind: str = "") -> str:
    if "PRIVATE KEY" in value:
        return value[:40]
    if value.startswith("http"):
        u = urlsplit(value)
        return f"{u.scheme}://{u.netloc}/…{value[-4:]} ({len(value)})"
    if len(value) < 12:
        return f"…({len(value)})"
    return f"{value[:4]}…{value[-2:]} ({len(value)})"


def _b64json(part: str):
    try:
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (ValueError, TypeError):
        return None


def describe_jwt(tok: str) -> tuple[str, str]:
    """(note, severity): header/claims facts only; never the payload values."""
    h, p, _ = tok.split(".", 2) if tok.count(".") >= 2 else (tok, "", "")
    hd, pl = _b64json(h) or {}, _b64json(p) or {}
    bits = [f"alg {hd.get('alg', '?')}"]
    sev = "medium"
    if str(hd.get("alg", "")).lower() == "none":
        bits.append("UNSIGNED (alg none)")
        sev = "high"
    if isinstance(pl, dict):
        if "iss" in pl:
            bits.append(f"iss {trunc(pl['iss'], 40)}")
        exp = pl.get("exp")
        if isinstance(exp, (int, float)):
            bits.append("expired" if exp < time.time() else "still valid")
            if exp < time.time() and sev == "medium":
                sev = "low"
        keys = [k for k in ("role", "roles", "admin", "scope", "permissions", "is_admin") if k in pl]
        if keys:
            bits.append("claims: " + ",".join(keys))
    return ", ".join(bits), sev


def _kind(path: str) -> str:
    for name, rx in KINDS:
        if rx.search(path):
            return name
    return "other"


def _plausible_path(p: str) -> bool:
    base = p.split("?", 1)[0]
    if len(base) < 3 or STATIC_EXT.search(base) or base.startswith(STATIC_PREFIX) or not re.search(r"[A-Za-z]", base):
        return False
    if "${" in base and base.count("/") < 2:
        return False
    if base.count("/") >= 2 or "?" in p:
        return True
    return _kind(base) != "other"


def _label(url: str | None, n: int) -> str:
    if not url:
        return f"inline#{n}"
    return urlsplit(url).path.rsplit("/", 1)[-1] or urlsplit(url).netloc


def collect_texts(snap: PageSnapshot, fetcher) -> tuple[list[tuple[str, str]], list[str]]:
    """(label, text) for first-party external scripts, inline scripts and the page HTML. Static mode fetches the bodies."""
    first = registrable_domain(snap.host)
    texts: list[tuple[str, str]] = []
    notes: list[str] = []
    ext = [s for s in snap.scripts if s.url and registrable_domain(urlsplit(s.url).hostname or "") == first]
    if snap.mode == "static" and fetcher is not None:
        todo = [s for s in ext if not s.recon_text][:STATIC_FETCH_LIMIT]
        for s in todo:
            r = fetcher.get(s.url, max_bytes=2_000_000)
            snap.extra_requests.append("script-body")
            if r.ok and r.status == 200 and r.body:
                s.recon_text = r.body.decode("utf-8", "replace")
        if len(ext) > STATIC_FETCH_LIMIT:
            notes.append(f"static mode: only the first {STATIC_FETCH_LIMIT} first-party scripts were downloaded for mining")
    for s in ext:
        if s.recon_text:
            texts.append((_label(s.url, 0), s.recon_text))
    n = 0
    for s in snap.scripts:
        if not s.url and s.text and len(s.text) > 40:
            n += 1
            texts.append((_label(None, n), s.text))
    html = snap.html_rendered or snap.html_raw
    if html:
        texts.append(("page HTML", html))
    return texts, notes


def mine(texts: list[tuple[str, str]], first_party: str, snap_host: str) -> dict:
    t0, total = time.monotonic(), 0
    endpoints: dict[str, dict] = {}
    hosts: dict[str, str] = {}
    buckets: dict[tuple, dict] = {}
    secrets: dict[tuple, dict] = {}
    complete = True
    for label, text in texts:
        if total > MAX_TOTAL_BYTES or time.monotonic() - t0 > TIME_BUDGET:
            complete = False
            break
        total += len(text)
        is_html = label == "page HTML"
        low = text.lower()
        # --- endpoints (code only: HTML anchors are navigation, not API surface) -------------------
        if not is_html:
            for m in PATH_RX.finditer(text):
                p = m.group(1)
                if _plausible_path(p) and p not in endpoints and len(endpoints) < 400:
                    endpoints[p] = {"value": trunc(p, 120), "kind": _kind(p.split("?", 1)[0]), "where": label, "host": None}
        for m in URL_RX.finditer(text):
            url = m.group(0).rstrip(".:")
            u = urlsplit(url)
            host = (u.hostname or "").lower()
            if not host or any(host == n or host.endswith("." + n) for n in NOISE_HOSTS):
                continue
            hosts.setdefault(host, label)
            if u.scheme in ("ws", "wss"):
                endpoints.setdefault(url, {"value": trunc(url, 120), "kind": "websocket", "where": label, "host": host})
            elif registrable_domain(host) == first_party and not is_html and _plausible_path(u.path or "/x/y") and url not in endpoints:
                endpoints[url] = {"value": trunc(url, 120), "kind": _kind(u.path), "where": label, "host": host}
        for provider, rx in BUCKETS:
            for m in rx.finditer(text):
                buckets.setdefault((provider, m.group(1).lower()), {"provider": provider, "name": m.group(1).lower(), "where": label})
        # --- secrets ---------------------------------------------------------------------------------
        for typ, rx, sev, conf, note, hints in SECRET_PATTERNS:
            if not any(h in low for h in hints):
                continue
            for m in rx.finditer(text):
                val = m.group(1) if rx.groups and m.group(1) else m.group(0)
                key = (typ, hashlib.sha256(val.encode()).hexdigest()[:12])
                if key in secrets:
                    continue
                n = note
                s = sev
                if typ == "JSON Web Token":
                    n, s = describe_jwt(m.group(0))
                secrets[key] = {"type": typ, "severity": s, "confidence": conf, "where": f"{label}:{text.count(chr(10), 0, m.start()) + 1}",
                                "redacted": redact(m.group(0) if typ != "AWS secret access key" else val), "note": n,
                                "id": key[1]}
        if any(h in low for h in GENERIC_HINTS):
            for m in GENERIC.finditer(text):
                k, v = m.group(1), m.group(2)
                if PLACEHOLDER.search(v) or v.startswith(("http", "/", ".")) or entropy(v) < 3.4 or not (re.search(r"\d", v) and re.search(r"[A-Za-z]", v)):
                    continue
                if any(s["id"] == hashlib.sha256(v.encode()).hexdigest()[:12] for s in secrets.values()):
                    continue
                key = ("Hard-coded credential", hashlib.sha256(v.encode()).hexdigest()[:12])
                secrets.setdefault(key, {"type": "Hard-coded credential", "severity": "medium", "confidence": "medium",
                                         "where": f"{label}:{text.count(chr(10), 0, m.start()) + 1}", "redacted": redact(v),
                                         "note": f"assigned to '{trunc(k, 30)}'; high-entropy literal", "id": key[1]})
    by_kind: dict[str, list[dict]] = {}
    for e in endpoints.values():
        by_kind.setdefault(e["kind"], []).append(e)
    graphql = [e["value"] for e in endpoints.values() if "graphql" in e["value"].lower() and not e["value"].startswith(("ws", "http")) or
               ("graphql" in e["value"].lower() and e.get("host") and registrable_domain(e["host"]) == first_party)]
    internal = sorted(h for h in hosts if INTERNAL_HOST.search(h))
    staging = sorted(h for h in hosts if STAGING_HOST.search(h.rsplit(".", 1)[0]) and h not in internal and registrable_domain(h) == first_party)
    third = sorted(h for h in hosts if registrable_domain(h) != first_party and not INTERNAL_HOST.search(h))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    items = sorted(secrets.values(), key=lambda s: (order.get(s["severity"], 9), s["type"]))
    return {"endpoints": {"total": len(endpoints), "by_kind": by_kind, "graphql": graphql[:5],
                          "websockets": [e["value"] for e in by_kind.get("websocket", [])][:5]},
            "hosts": {"internal": internal[:10], "staging": staging[:10], "third_party": third[:30], "third_party_count": len(third),
                      "buckets": list(buckets.values())[:10]},
            "secrets": {"count": len(items), "items": items[:25]}, "bytes_scanned": total, "complete": complete}


def comments_of_interest(html: str | None) -> list[str]:
    out = []
    for m in COMMENT_RX.finditer(html or ""):
        c = re.sub(r"\s+", " ", m.group(1)).strip()
        if COMMENT_KEYWORDS.search(c) and c not in out:
            out.append(trunc(c, 120))
        if len(out) >= 5:
            break
    return out


def analyze(snap: PageSnapshot, fetcher) -> dict:
    texts, notes = collect_texts(snap, fetcher)
    res = mine(texts, registrable_domain(snap.host), snap.host)
    res["comments"] = comments_of_interest(snap.html_raw)
    res["scanned"] = {"scripts": sum(1 for l, _ in texts if l not in ("page HTML",) and not l.startswith("inline#")),
                      "inline": sum(1 for l, _ in texts if l.startswith("inline#")), "bytes": res.pop("bytes_scanned")}
    res["notes"] = notes + ([] if res.pop("complete") else ["recon hit its size/time budget; results are partial"])
    res["note"] = "Everything listed was written into the page or its scripts. Nothing was requested or tested; secrets are redacted."
    return res
