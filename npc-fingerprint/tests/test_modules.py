import base64
import codecs
import datetime as dt
import hashlib
import os
import socket
import ssl
import threading
import unittest

import _bootstrap  # noqa: F401
from npc_fingerprint import merge
from npc_fingerprint.db import store
from npc_fingerprint.fetch.snapshot import NetRequest, PageSnapshot, ScriptRef
from npc_fingerprint.fetch.static import FetchResult
from npc_fingerprint.model import Detection, Evidence
from npc_fingerprint.modules import (anomaly, bundle, csp, dnsprobe, drift, edge, favicon, hygiene, libs, secheaders,
                                     thirdparty, tls)
from npc_fingerprint.modules.tech import TechDB


def snap(**kw):
    base = dict(mode="static", url="https://x.test/", final_url="https://x.test/", status=200)
    base.update(kw)
    return PageSnapshot(**base)


class FakeFetcher:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def get(self, url, **kw):
        self.calls.append((url, kw))
        return self.result(url) if callable(self.result) else self.result


class Favicon(unittest.TestCase):
    def test_murmur3_matches_reference_vectors(self):
        self.assertEqual(favicon._murmur3_32(b"foo"), -156908512)
        self.assertEqual(favicon._murmur3_32(b"foo", 42), -1322301282)
        self.assertEqual(favicon._murmur3_32(b""), 0)

    def test_murmur3_all_tail_lengths_against_independent_reference(self):
        import struct

        def ref(data, seed=0):
            c1, c2 = 0xcc9e2d51, 0x1b873593
            h = seed
            for i in range(len(data) // 4):
                k = struct.unpack_from("<I", data, i * 4)[0]
                k = (k * c1) & 0xffffffff; k = ((k << 15) | (k >> 17)) & 0xffffffff; k = (k * c2) & 0xffffffff
                h ^= k; h = ((h << 13) | (h >> 19)) & 0xffffffff; h = (h * 5 + 0xe6546b64) & 0xffffffff
            tail = data[(len(data) // 4) * 4:]
            k = 0
            for j in range(len(tail) - 1, -1, -1):
                k = (k << 8) | tail[j]
            if tail:
                k = (k * c1) & 0xffffffff; k = ((k << 15) | (k >> 17)) & 0xffffffff; k = (k * c2) & 0xffffffff; h ^= k
            h ^= len(data); h ^= h >> 16; h = (h * 0x85ebca6b) & 0xffffffff; h ^= h >> 13; h = (h * 0xc2b2ae35) & 0xffffffff; h ^= h >> 16
            return h - (1 << 32) if h & 0x80000000 else h
        for n in range(0, 64):
            d = os.urandom(n)
            self.assertEqual(favicon._murmur3_32(d), ref(d), n)

    def test_shodan_hash_uses_newline_base64(self):
        raw = os.urandom(300)
        self.assertIn(b"\n", codecs.encode(raw, "base64"))
        self.assertNotIn(b"\n", base64.b64encode(raw))
        self.assertEqual(favicon.favicon_hashes(raw)["mmh3"], favicon.mmh3_hash(codecs.encode(raw, "base64")))

    def test_match_sentinel_and_cap(self):
        raw = b"\x00\x00\x01\x00" + os.urandom(64)
        h = favicon.favicon_hashes(raw)
        s = snap(links=[{"rel": "icon", "href": "https://x.test/f.ico"}])
        f = FakeFetcher(FetchResult("https://x.test/f.ico", 200, [("Content-Type", "image/x-icon")], raw))
        db = {"mmh3": {str(h["mmh3"]): [["Acme CMS", "nuclei"]]}, "md5": {}, "ignore": {"md5": [], "mmh3": []}}
        r = favicon.analyze(s, f, db, use_cache=False)
        self.assertEqual(r["status"], "matched")
        self.assertLessEqual(r["confidence"], 40)                    # never above "possible" on its own
        db["ignore"]["md5"].append(h["md5"])
        self.assertEqual(favicon.analyze(s, f, db, use_cache=False)["status"], "sentinel")

    def test_soft_404_html_is_not_a_favicon(self):
        s = snap()
        f = FakeFetcher(FetchResult("u", 200, [("Content-Type", "text/html")], b"<html>not found</html>"))
        self.assertEqual(favicon.analyze(s, f, {"mmh3": {}, "md5": {}}, use_cache=False)["status"], "none")
        self.assertLessEqual(len(f.calls), 2)                        # request budget: at most two attempts

    def test_data_uri_needs_no_request(self):
        raw = b"\x89PNG\r\n" + os.urandom(20)
        uri = "data:image/png;base64," + base64.b64encode(raw).decode()
        s = snap(icons=[uri])
        f = FakeFetcher(FetchResult("u", 404, [], b""))
        r = favicon.analyze(s, f, {"mmh3": {}, "md5": {}}, use_cache=False)
        self.assertEqual(r["md5"], hashlib.md5(raw).hexdigest())
        self.assertEqual(f.calls, [])

    def test_corroboration_raises_confidence_only_with_another_signal(self):
        d = Detection("WordPress", ["CMS"], 60, evidence=[Evidence("tech", "script-src", "u", "m", "p", 60)], status="probable")
        hit = merge.corroborate_favicon([d], {"url": "u", "mmh3": 1, "matches": [{"name": "wordpress", "via": ["mmh3"], "sources": ["nuclei"]}]})
        self.assertEqual(hit, ["WordPress"])
        self.assertEqual(d.confidence, 80)
        self.assertEqual(merge.corroborate_favicon([], {"matches": [{"name": "x"}]}), [])


class Csp(unittest.TestCase):
    def test_grades(self):
        s = snap(headers=[("Content-Security-Policy", "default-src 'self'; script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")])
        self.assertEqual(csp.analyze(s)["grade"], "A")
        s = snap(headers=[("Content-Security-Policy", "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com *.example.com data:")])
        r = csp.analyze(s)
        self.assertEqual(r["grade"], "F")
        self.assertIn("cdnjs.cloudflare.com", r["hosts"])
        s = snap(headers=[("Content-Security-Policy-Report-Only", "default-src 'self'")])
        r = csp.analyze(s)
        self.assertFalse(r["enforced"])
        self.assertTrue(r["report_only"])

    def test_unsafe_inline_ignored_when_nonce_present(self):
        s = snap(headers=[("Content-Security-Policy", "script-src 'nonce-x' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")])
        self.assertEqual(csp.analyze(s)["grade"], "A")


class SecHeaders(unittest.TestCase):
    def by_id(self, s):
        return {f.id: f for f in secheaders.analyze(s, csp.analyze(s))}

    def test_plain_http_hsts_not_applicable(self):
        r = self.by_id(snap(url="http://x/", final_url="http://x/"))
        self.assertEqual(r["hsts"].status, "n/a")
        self.assertEqual(r["x-frame-options"].status, "missing")

    def test_good_configuration_passes(self):
        s = snap(headers=[("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
                          ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"),
                          ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"), ("Permissions-Policy", "camera=(), microphone=()")])
        r = self.by_id(s)
        self.assertEqual({k: v.status for k, v in r.items()}, {k: "pass" for k in r})
        self.assertEqual(r["x-frame-options"].reason, "covered by CSP frame-ancestors")

    def test_weak_values(self):
        s = snap(headers=[("Strict-Transport-Security", "max-age=300"), ("Referrer-Policy", "unsafe-url"), ("X-Frame-Options", "ALLOW-FROM https://a")])
        r = self.by_id(s)
        self.assertEqual(r["hsts"].status, "weak")
        self.assertEqual(r["referrer-policy"].status, "weak")
        self.assertEqual(r["x-frame-options"].status, "weak")

    def test_every_finding_has_a_one_line_reason_and_short_form(self):
        for f in secheaders.analyze(snap(), csp.analyze(snap())):
            self.assertTrue(f.reason and "\n" not in f.reason)
            self.assertLessEqual(len(f.data["short"]), 28)


class Anomaly(unittest.TestCase):
    def test_tiering_depends_on_proxy_evidence(self):
        s = snap(protocol="h2", headers=[("Server", "Apache/2.2.22"), ("X-Powered-By", "PHP/5.3")])
        a = {x["id"]: x for x in anomaly.analyze(s, None, "h2")}
        self.assertEqual(a["capability-apache-h2"]["tier"], "contradiction")
        s.headers.append(("Via", "1.1 varnish"))
        a = {x["id"]: x for x in anomaly.analyze(s, None, "h2")}
        self.assertEqual(a["capability-apache-h2"]["tier"], "layered")

    def test_cloudflare_overwrite_and_runtimes(self):
        s = snap(headers=[("Server", "Apache/2.4.41"), ("CF-RAY", "1-AMS"), ("X-Powered-By", "ASP.NET"), ("Set-Cookie", "PHPSESSID=x")])
        ids = {x["id"]: x["tier"] for x in anomaly.analyze(s, None, None)}
        self.assertEqual(ids["overwrite-server"], "contradiction")
        self.assertEqual(ids["multiple-runtimes"], "layered")

    def test_nginx_in_front_of_iis_is_only_layered_or_nothing(self):
        s = snap(headers=[("Server", "nginx/1.24.0"), ("X-Powered-By", "ASP.NET")])
        self.assertFalse([x for x in anomaly.analyze(s, None, "http/1.1") if x["tier"] == "contradiction"])

    def test_duplicate_server_headers(self):
        s = snap(headers=[("Server", "nginx"), ("Server", "Apache")])
        self.assertEqual(anomaly.analyze(s, None, None)[0]["id"], "duplicate-server")

    def test_only_contradictions_dispute_a_technology(self):
        d = Detection("Apache HTTP Server", ["Web servers"], 100, evidence=[Evidence("tech", "header", "server", "Apache/2.2.22", "p", 100)])
        corroborated = Detection("PHP", ["Languages"], 100, evidence=[Evidence("tech", "header", "x-powered-by", "PHP", "p", 100), Evidence("tech", "js-global", "x", "y", "p", 100)])
        merge.mark_disputed([d, corroborated], [{"tier": "layered", "involves": ["server"], "title": "t", "why": "w"}])
        self.assertEqual(d.status, "confirmed" if d.status != "disputed" else "x")
        merge.mark_disputed([d, corroborated], [{"tier": "contradiction", "involves": ["server", "x-powered-by"], "title": "t", "why": "w"}])
        self.assertEqual(d.status, "disputed")
        self.assertLessEqual(d.confidence, 40)
        self.assertNotEqual(corroborated.status, "disputed")        # independent evidence keeps it alive


class Tls(unittest.TestCase):
    def test_probe_against_self_signed_server(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from fixtures import make_cert
        import tempfile
        cp, kp = make_cert(tempfile.mkdtemp())
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cp, kp)
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                try:
                    with ctx.wrap_socket(c, server_side=True) as t:
                        t.recv(1)
                except Exception:  # noqa: BLE001
                    pass
        threading.Thread(target=serve, daemon=True).start()
        r = tls.probe("localhost", port)
        srv.close()
        with open(cp, "rb") as fh:
            der = x509.load_pem_x509_certificate(fh.read()).public_bytes(serialization.Encoding.DER)
        self.assertIs(r["verified"], False)
        self.assertEqual(r["alpn"], "h2")
        self.assertEqual(r["cert"]["sha256"], hashlib.sha256(der).hexdigest())
        self.assertTrue(r["cert"]["self_signed"])
        self.assertEqual(r["cert"]["issuer_o"], "Test Org")
        ids = {f.id for f in tls.findings(r, snap(final_url="https://localhost/"))}
        self.assertIn("cert-invalid", ids)

    def test_refused_connection_degrades(self):
        self.assertIn("error", tls.probe("127.0.0.1", 1, timeout=1))

    def test_alt_svc_and_h3_states(self):
        self.assertEqual([a["protocol"] for a in tls.parse_alt_svc('h3=":443"; ma=86400, h3-29=":443"; ma=86400')], ["h3", "h3-29"])
        self.assertEqual(tls.parse_alt_svc("clear"), [])
        self.assertEqual(tls.http_info(snap(headers=[("Alt-Svc", 'h3=":443"')], protocol="h2"), None)["h3"], "advertised")
        self.assertEqual(tls.http_info(snap(protocol="h3"), None)["h3"], "observed")
        self.assertEqual(tls.http_info(snap(protocol="h2"), None)["h3"], "not-seen")


class BundleLibsEdge(unittest.TestCase):
    def test_banners(self):
        b = bundle.parse_banners(b"/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */!function(a,b){")
        self.assertEqual((b[0]["library"], b[0]["version"]), ("jQuery", "1.12.4"))
        self.assertIn("jQuery Foundation", b[0]["copyright"])
        self.assertEqual(bundle.parse_banners(b"/*! For license information please see main.js.LICENSE.txt */(()=>{")[0]["license_file"], "main.js.LICENSE.txt")
        self.assertEqual(bundle.parse_banners(b"/*! lodash.min.js v4.17.21 | MIT License */")[0]["library"], "lodash")
        self.assertEqual(bundle.parse_banners(b"var a=1;function b(){}"), [])

    def test_only_first_500_bytes_are_scanned(self):
        blob = b"x" * 600 + b"/*! jQuery v1.12.4 */"
        self.assertEqual(bundle.parse_banners(blob), [])

    def test_static_mode_probes_at_most_top_k(self):
        scripts = [ScriptRef(url=f"https://x.test/s{i}.js") for i in range(10)]
        s = snap(scripts=scripts)
        f = FakeFetcher(FetchResult("u", 206, [("Content-Range", "bytes 0-499/9000")], b"/*! jQuery v1.12.4 */" + b"x" * 400, total_size=9000))
        r = bundle.analyze(s, f, top_k=4)
        heads = [c for c in f.calls if c[1].get("range_bytes")]
        self.assertEqual(len(heads), 4)                      # head probes are capped at top_k
        self.assertLessEqual(len(f.calls), 5)                # + at most one tail probe (largest bundle, for the source-map pointer)
        self.assertEqual(r["bundle"]["size"], 9000)

    def test_libs_advisories_use_evidenced_versions_only(self):
        rdb = libs.RetireDB(store.load().retire)
        s = snap(mode="browser", js_values={"jQuery.fn.jquery": "1.12.4"},
                 scripts=[ScriptRef(url="https://x.test/jquery-1.12.4.min.js", head=b"/*! jQuery v1.12.4 */")])
        r = libs.analyze(s, rdb)
        self.assertEqual(r["advisory_counts"]["medium"], 3)
        s.js_values = {"jQuery.fn.jquery": "3.7.1"}
        s.scripts = []
        self.assertEqual(libs.analyze(s, rdb)["total_advisories"], 0)
        self.assertEqual(libs.analyze(snap(), rdb)["libraries"], [])        # nothing evidenced -> nothing reported

    def test_db_strings_are_never_evaluated_as_code(self):
        rdb = libs.RetireDB({"evil": {"extractors": {"func": ["alert(1)", "a.b.c", "x;y"]}, "vulnerabilities": []}})
        self.assertEqual(rdb.func_chains(), ["a.b.c"])

    def test_edge_attribution_and_leaks(self):
        s = snap(headers=[("Server", "cloudflare"), ("CF-RAY", "1-AMS"), ("X-Powered-By", "PHP/7.4.3")])
        e = edge.analyze(s, {"CNAME": ["x.cdn.cloudflare.net"], "NS": ["a.ns.cloudflare.com"]})
        self.assertEqual(e["edges"][0]["name"], "Cloudflare")
        self.assertEqual(e["layers"], "client → Cloudflare → origin")
        self.assertEqual([l["header"] for l in e["origin_leaks"]], ["x-powered-by"])
        self.assertEqual(edge.analyze(snap(headers=[("Server", "nginx")]), None)["edges"], [])

    def test_dns_chain_with_injected_resolver(self):
        def fake(name, rtype):
            return {("www.example.com", "CNAME"): ["d1.cloudfront.net"], ("example.com", "MX"): ["mail.protection.outlook.com"]}.get((name, rtype), [])
        d = dnsprobe.resolve("www.example.com", query=fake)
        self.assertEqual(d["CNAME"], ["d1.cloudfront.net"])
        self.assertEqual(dnsprobe.resolve("127.0.0.1"), {})


class ThirdPartyHygiene(unittest.TestCase):
    def test_third_party_and_sri(self):
        s = snap(mode="browser", url="https://www.shop.co.uk/", final_url="https://www.shop.co.uk/",
                 scripts=[ScriptRef(url="https://www.shop.co.uk/a.js"), ScriptRef(url="https://cdn.jsdelivr.net/x.js"),
                          ScriptRef(url="https://www.google-analytics.com/a.js", integrity="sha384-abc")],
                 links=[{"rel": "stylesheet", "href": "https://fonts.googleapis.com/css", "integrity": None}],
                 requests=[NetRequest("https://img.shop.co.uk/i.png", "image"), NetRequest("http://t.example.net/p.gif", "image"),
                           NetRequest("https://cdn.jsdelivr.net/x.js", "script")])
        r = thirdparty.analyze(s)
        self.assertEqual(r["first_party"], "shop.co.uk")
        self.assertEqual((r["scripts_third_party"], r["scripts_without_sri"], r["styles_without_sri"], r["insecure_requests"]), (2, 1, 1, 1))

    def test_cookie_audit(self):
        s = snap(headers=[("Set-Cookie", "sessionid=abc; Path=/"), ("Set-Cookie", "__Host-id=1; Secure; Path=/; Domain=x.com; HttpOnly; SameSite=Lax"),
                          ("Set-Cookie", "theme=dark; Secure; HttpOnly; SameSite=Lax")])
        c = hygiene.audit_cookies(s)
        self.assertEqual(c["counts"]["prefix_violations"], 1)
        self.assertEqual(c["session_cookies_at_risk"], 1)
        self.assertTrue(all("value" not in x for x in c["cookies"]))

    def test_security_txt(self):
        s = snap()
        exp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        signed = f"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nContact: mailto:s@x.com\nExpires: {exp}\n-----BEGIN PGP SIGNATURE-----\nabc\n".encode()
        ok = hygiene.check_security_txt(s, FakeFetcher(FetchResult("https://x.test/.well-known/security.txt", 200, [("Content-Type", "text/plain")], signed)))
        self.assertEqual(ok.status, "pass")
        self.assertTrue(ok.data["signed"])
        soft404 = hygiene.check_security_txt(s, FakeFetcher(FetchResult("u", 200, [("Content-Type", "text/html")], b"<html>")))
        self.assertEqual(soft404.status, "missing")
        expired = hygiene.check_security_txt(s, FakeFetcher(FetchResult("u", 200, [("Content-Type", "text/plain")], b"Contact: mailto:a@b.c\nExpires: 2020-01-01T00:00:00Z\n")))
        self.assertTrue(expired.reason.startswith("expired"))
        self.assertEqual(hygiene.check_security_txt(s, FakeFetcher(FetchResult("u", 200, [("Content-Type", "text/plain")], b"Contact: x\n"))).status, "weak")


class Guards(unittest.TestCase):
    def test_retire_versions_have_no_filename_residue_or_false_conflicts(self):
        rdb = libs.RetireDB(store.load().retire)
        s = snap(mode="browser", js_values={"jQuery.fn.jquery": "1.12.4"},
                 scripts=[ScriptRef(url="https://x.test/js/jquery-1.12.4.min.js"), ScriptRef(url="https://x.test/bootstrap-3.3.7.min.js?ver=1")])
        self.assertEqual({(e["library"], e["version"]) for e in rdb.extract(s)}, {("jquery", "1.12.4"), ("bootstrap", "3.3.7")})
        jq = next(l for l in libs.analyze(s, rdb)["libraries"] if l["library"] == "jquery")
        self.assertFalse(jq["conflict"])

    def test_follow_up_requests_never_reach_internal_addresses_for_public_pages(self):
        from npc_fingerprint.util import extra_request_allowed
        self.assertFalse(extra_request_allowed("example.com", "http://169.254.169.254/latest/meta-data"))
        self.assertFalse(extra_request_allowed("example.com", "http://10.0.0.5/f.ico"))
        self.assertFalse(extra_request_allowed("example.com", "http://localhost:8080/f.ico"))
        self.assertTrue(extra_request_allowed("example.com", "https://cdn.example.net/f.ico"))
        self.assertTrue(extra_request_allowed("localhost", "http://127.0.0.1:8000/f.ico"))   # scanning your own dev server is fine
        s = snap(icons=["http://169.254.169.254/icon.ico"])
        self.assertTrue(all("169.254" not in u for u in favicon.candidate_urls(s)))

    def test_merged_set_cookie_headers_are_split_without_breaking_expires(self):
        from npc_fingerprint.fetch.snapshot import split_joined_set_cookie
        parts = split_joined_set_cookie("a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/, b=2; Secure")
        self.assertEqual(len(parts), 2)
        self.assertTrue(parts[0].startswith("a=1") and parts[1].startswith("b=2"))


class Drift(unittest.TestCase):
    def test_diff_buckets(self):
        old = {"target": {"url": "https://x/", "final_url": "https://x/"},
               "technologies": [{"name": "jQuery", "version": "1.12.4", "status": "confirmed"}, {"name": "Nginx", "version": "1.24.0", "status": "confirmed"}],
               "weak": [{"name": "Vue.js"}], "security_headers": [{"id": "hsts", "title": "HSTS", "status": "missing"}], "csp": {"grade": None},
               "tls": {"cert": {"sha256": "a" * 64, "issuer": "LE"}, "tls_version": "TLSv1.2"}}
        new = {"target": {"url": "https://x/", "final_url": "https://x/"},
               "technologies": [{"name": "jQuery", "version": "3.7.1", "status": "confirmed"}, {"name": "Vue.js", "version": None, "status": "probable"},
                                {"name": "React", "version": "18", "status": "confirmed"}], "weak": [],
               "security_headers": [{"id": "hsts", "title": "HSTS", "status": "pass"}], "csp": {"grade": "B"},
               "tls": {"cert": {"sha256": "b" * 64, "issuer": "LE"}, "tls_version": "TLSv1.3"}}
        d = drift.diff(new, old)
        self.assertEqual(d["summary"], {"added": 1, "removed": 1, "changed": 5, "noise": 1})   # Vue.js: weak -> probable is noise, not a change


if __name__ == "__main__":
    unittest.main()
