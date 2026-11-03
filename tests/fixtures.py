"""Local test sites: a static site, a JavaScript-rendered SPA over HTTPS, and a bare python http.server."""
from __future__ import annotations

import datetime as dt
import http.server
import os
import socketserver
import ssl
import tempfile
import threading
from functools import partial

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

STATIC_HTML = b"""<!doctype html><html><head><title>Acme Blog</title>
<meta name="generator" content="WordPress 6.4.2">
<link rel="stylesheet" href="/wp-content/themes/x/style.css">
<link rel="icon" href="/favicon.ico">
<script src="/wp-includes/js/jquery/jquery-1.12.4.min.js"></script>
<script src="https://cdn.thirdparty.example/lib.js"></script>
</head><body><h1>Hello</h1></body></html>"""

JQUERY_JS = b"/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n!function(a,b){window.jQuery=function(){};}();\n" + b"x" * 5000
FAVICON = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x08\x00" + bytes(range(200))

SPA_HTML = b"""<!doctype html><html><head><title>Shop SPA</title></head>
<body><div id="root"></div><script src="/static/app.js"></script></body></html>"""
SPA_JS = b"""/*! For license information please see app.js.LICENSE.txt */
window.React = {version: '18.2.0'};
window.__NEXT_DATA__ = {};
document.getElementById('root').innerHTML = '<div data-reactroot=""><h1>Shop</h1></div>';
fetch('/api/items').catch(function(){});
//# sourceMappingURL=app.js.map
"""


class StaticHandler(http.server.BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41 (Ubuntu)"

    def version_string(self):          # one clean Server header (the stdlib default would append a Python banner)
        return self.server_version

    def log_message(self, *a):
        pass

    def _send(self, body, ctype, extra=()):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/wp-includes/js/jquery/jquery-1.12.4.min.js":
            return self._send(JQUERY_JS, "application/javascript")
        if p == "/favicon.ico":
            return self._send(FAVICON, "image/x-icon")
        if p == "/.well-known/security.txt":
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
        return self._send(STATIC_HTML, "text/html; charset=utf-8",
                          [("X-Powered-By", "PHP/7.4.3"),
                           ("Set-Cookie", "PHPSESSID=abc123; path=/"), ("Set-Cookie", "theme=dark; Secure; HttpOnly; SameSite=Lax")])


class SpaHandler(StaticHandler):
    server_version = "nginx/1.24.0"

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/static/app.js":
            return self._send(SPA_JS, "application/javascript")
        if p == "/static/app.js.map":
            return self._send(b'{"version":3}', "application/json")
        if p == "/api/items":
            return self._send(b"[]", "application/json")
        if p == "/favicon.ico":
            return self._send(FAVICON, "image/x-icon")
        if p == "/.well-known/security.txt":
            exp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
            return self._send(f"Contact: mailto:security@example.test\nExpires: {exp}\n".encode(), "text/plain")
        return self._send(SPA_HTML, "text/html; charset=utf-8", [
            ("X-Powered-By", "Next.js"),
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'"),
            ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "strict-origin-when-cross-origin")])


def make_cert(directory: str) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"), x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False).sign(key, hashes.SHA256()))
    cp, kp = os.path.join(directory, "c.pem"), os.path.join(directory, "k.pem")
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cp, kp


class Site:
    """A throwaway server. tls=True serves HTTPS with a self-signed certificate (ALPN http/1.1)."""

    def __init__(self, handler, tls: bool = False, directory: str | None = None):
        self.tls = tls
        self._tmp = tempfile.mkdtemp()
        h = partial(handler, directory=directory) if directory else handler
        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), h)
        self.httpd.daemon_threads = True
        if tls:
            cp, kp = make_cert(self._tmp)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cp, kp)
            ctx.set_alpn_protocols(["http/1.1"])
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"{'https' if self.tls else 'http'}://{'localhost' if self.tls else '127.0.0.1'}:{self.port}/"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()
