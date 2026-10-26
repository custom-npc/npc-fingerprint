"""Module 5: TLS certificate + HTTP protocol analysis.

One extra TCP+TLS handshake (no HTTP request) gives ALPN, protocol version, cipher and the leaf certificate.
HTTP/3 cannot be seen through TCP ALPN (QUIC negotiates it), so it is reported as `observed` (a client really
used it) or `advertised` (Alt-Svc) - never guessed.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
import socket
import ssl

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, dsa
    from cryptography.x509.oid import NameOID
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False

from ..fetch.snapshot import PageSnapshot
from ..model import Finding
from ..util import is_ip, trunc

ALPN = ["h2", "http/1.1"]


def _handshake(host: str, port: int, timeout: float, verify: bool):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(ALPN)
    sni = None if is_ip(host) else host          # SNI matters on shared hosts; IP literals have none
    with socket.create_connection((host, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=sni) as t:
            return {"der": t.getpeercert(binary_form=True), "tls_version": t.version(), "cipher": t.cipher(),
                    "alpn": t.selected_alpn_protocol()}


def _name_attr(name, oid) -> str | None:
    try:
        a = name.get_attributes_for_oid(oid)
        return a[0].value if a else None
    except Exception:  # noqa: BLE001
        return None


def _key_desc(pk) -> str:
    if isinstance(pk, rsa.RSAPublicKey):
        return f"RSA {pk.key_size}"
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return f"EC {pk.curve.name}"
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pk, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(pk, dsa.DSAPublicKey):
        return f"DSA {pk.key_size}"
    return type(pk).__name__


def parse_cert(der: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der)
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
    now = dt.datetime.now(dt.timezone.utc)
    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(v) for v in ext.value.get_values_for_type(x509.DNSName)]
    except Exception:  # noqa: BLE001
        pass
    i_o, i_cn = _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME), _name_attr(cert.issuer, NameOID.COMMON_NAME)
    s_cn, s_o = _name_attr(cert.subject, NameOID.COMMON_NAME), _name_attr(cert.subject, NameOID.ORGANIZATION_NAME)
    try:
        sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:  # noqa: BLE001
        sig = None
    issuer_display = (f"{i_o} ({i_cn})" if i_o and i_cn and i_cn != i_o else (i_o or i_cn or cert.issuer.rfc4514_string()))
    return {
        "subject_cn": s_cn, "subject_o": s_o, "issuer_o": i_o, "issuer_cn": i_cn, "issuer": trunc(issuer_display, 100),
        "not_before": nb.replace(microsecond=0).isoformat(), "not_after": na.replace(microsecond=0).isoformat(),
        "days_left": (na - now).days, "san": sans[:12], "san_count": len(sans),
        "sha256": hashlib.sha256(der).hexdigest(), "key": _key_desc(cert.public_key()), "sig_alg": sig,
        "self_signed": cert.issuer == cert.subject, "serial": format(cert.serial_number, "x"),
    }


def probe(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    res: dict = {"applicable": True, "host": host, "port": port, "verified": None, "verify_error": None}
    got = None
    try:
        got = _handshake(host, port, timeout, verify=True)
        res["verified"] = True
    except ssl.SSLCertVerificationError as e:           # subclass of SSLError: must be caught first
        res["verified"] = False
        res["verify_error"] = trunc(getattr(e, "verify_message", None) or str(e), 140)
    except (ssl.SSLError, OSError, socket.timeout) as e:
        res["error"] = trunc(f"{type(e).__name__}: {e}", 160)
        return res
    if got is None:                                     # validation failed: look again without validation
        try:
            got = _handshake(host, port, timeout, verify=False)
        except (ssl.SSLError, OSError, socket.timeout) as e:
            res["error"] = trunc(f"{type(e).__name__}: {e}", 160)
            return res
    res.update(tls_version=got["tls_version"], alpn=got["alpn"])
    if got["cipher"]:
        res["cipher"] = got["cipher"][0]
    if got["der"] and HAVE_CRYPTO:
        try:
            res["cert"] = parse_cert(got["der"])
        except Exception as e:  # noqa: BLE001
            res["cert"] = {"sha256": hashlib.sha256(got["der"]).hexdigest(), "parse_error": trunc(str(e), 80)}
    elif got["der"]:
        res["cert"] = {"sha256": hashlib.sha256(got["der"]).hexdigest()}
    return res


# ----------------------------------------------------------------------------
# HTTP protocol summary
# ----------------------------------------------------------------------------

_ALT = re.compile(r'([\w.\-]+)="([^"]*)"(?:\s*;\s*ma=(\d+))?')


def parse_alt_svc(value: str | None) -> list[dict]:
    if not value or value.strip().lower() == "clear":
        return []
    return [{"protocol": m.group(1), "authority": m.group(2), "max_age": int(m.group(3)) if m.group(3) else None}
            for m in _ALT.finditer(value)]


def http_info(snap: PageSnapshot, tls: dict | None) -> dict:
    alt = parse_alt_svc(snap.header("alt-svc"))
    seen = snap.protocols_seen or {}
    observed = snap.protocol
    h3_observed = observed == "h3" or "h3" in seen
    h3_adv = any(a["protocol"].lower().startswith("h3") for a in alt)
    alpn = (tls or {}).get("alpn")
    summary = observed or alpn or ("http/1.x" if snap.scheme == "http" else None)
    return {"observed": observed, "alpn": alpn, "alt_svc": alt, "protocols_seen": seen,
            "h3": "observed" if h3_observed else "advertised" if h3_adv else "not-seen", "summary": summary}


def findings(tls: dict | None, snap: PageSnapshot) -> list[Finding]:
    out: list[Finding] = []
    if snap.scheme != "https":
        out.append(Finding("tls", "no-tls", "TLS", "missing", "high", "served over plain HTTP: traffic is readable and modifiable in transit"))
        return out
    if not tls or tls.get("error"):
        out.append(Finding("tls", "tls-error", "TLS", "info", "info", trunc(f"TLS probe failed: {(tls or {}).get('error', 'unknown')}", 110)))
        return out
    if tls.get("verified") is False:
        out.append(Finding("tls", "cert-invalid", "Certificate", "weak", "high", trunc(f"certificate does not validate: {tls.get('verify_error')}", 110)))
    v = tls.get("tls_version") or ""
    if v in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append(Finding("tls", "tls-old", "TLS version", "weak", "high", f"{v} negotiated: deprecated protocol"))
    cert = tls.get("cert") or {}
    d = cert.get("days_left")
    if isinstance(d, int):
        if d < 0:
            out.append(Finding("tls", "cert-expired", "Certificate", "weak", "high", f"certificate expired {-d} day(s) ago"))
        elif d < 14:
            out.append(Finding("tls", "cert-expiring", "Certificate", "weak", "medium", f"certificate expires in {d} day(s)"))
        elif d < 30:
            out.append(Finding("tls", "cert-expiring", "Certificate", "weak", "low", f"certificate expires in {d} day(s)"))
    if cert.get("sig_alg") in ("md5", "sha1"):
        out.append(Finding("tls", "cert-weak-sig", "Certificate", "weak", "medium", f"{cert['sig_alg'].upper()} signature is no longer trusted"))
    if str(cert.get("key", "")).startswith("RSA ") and int(cert["key"].split()[1]) < 2048:
        out.append(Finding("tls", "cert-weak-key", "Certificate", "weak", "medium", f"{cert['key']} is below the 2048-bit minimum"))
    if cert.get("self_signed") and tls.get("verified") is not False:
        out.append(Finding("tls", "cert-self-signed", "Certificate", "info", "low", "self-signed certificate"))
    return out
