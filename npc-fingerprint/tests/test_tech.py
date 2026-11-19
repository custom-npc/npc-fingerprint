import time
import unittest

import _bootstrap  # noqa: F401
from npc_fingerprint.db import store
from npc_fingerprint.fetch.snapshot import PageSnapshot, ScriptRef
from npc_fingerprint.modules.tech import TechDB


def snap(**kw):
    base = dict(mode="browser", url="https://x.test/", final_url="https://x.test/", status=200)
    base.update(kw)
    return PageSnapshot(**base)


class Detection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db = store.load()
        cls.tdb = TechDB(db.techs, db.cats)

    def get(self, dets, name):
        return next((d for d in dets if d.name == name), None)

    def test_every_detection_has_evidence(self):
        s = snap(headers=[("Server", "nginx/1.24.0"), ("X-Powered-By", "Next.js")], meta=[("generator", "WordPress 6.4.2")],
                 js_values={"React.version": "18.2.0"})
        dets, _ = self.tdb.analyze(s)
        self.assertTrue(dets)
        for d in dets:
            self.assertTrue(d.evidence, d.name)

    def test_versions_from_headers_meta_and_js(self):
        s = snap(headers=[("Server", "nginx/1.24.0")], meta=[("generator", "WordPress 6.4.2")], js_values={"React.version": "18.2.0"})
        dets, _ = self.tdb.analyze(s)
        self.assertEqual(self.get(dets, "Nginx").version, "1.24.0")
        self.assertEqual(self.get(dets, "WordPress").version, "6.4.2")
        self.assertEqual(self.get(dets, "React").version, "18.2.0")

    def test_implied_is_labelled_never_confirmed(self):
        s = snap(meta=[("generator", "WordPress 6.4.2")])
        dets, _ = self.tdb.analyze(s)
        php = self.get(dets, "PHP")
        self.assertEqual(php.status, "implied")
        self.assertEqual(php.implied_by, ["WordPress"])

    def test_apache_coyote_is_not_apache(self):
        dets, _ = self.tdb.analyze(snap(headers=[("Server", "Apache-Coyote/1.1")]))
        self.assertIsNone(self.get(dets, "Apache HTTP Server"))

    def test_self_declared_only_is_marked_claimed(self):
        dets, _ = self.tdb.analyze(snap(headers=[("Server", "nginx/1.24.0")]))
        d = self.get(dets, "Nginx")
        self.assertEqual(d.basis, "claimed")
        self.assertTrue(any("self-declared" in n for n in d.notes))

    def test_conflicting_versions_are_reported(self):
        s = snap(js_values={"jQuery.fn.jquery": "3.7.1"},
                 scripts=[ScriptRef(url="https://x.test/js/jquery-1.12.4.min.js")])
        d = self.get(self.tdb.analyze(s)[0], "jQuery")
        self.assertTrue(any("conflicting" in n for n in d.notes), d.notes)

    def test_cookie_values_never_appear_in_evidence(self):
        s = snap(headers=[("Set-Cookie", "PHPSESSID=SECRETVALUE123; Secure")])
        d = self.get(self.tdb.analyze(s)[0], "PHP")
        blob = repr([e.to_dict() for e in d.evidence])
        self.assertNotIn("SECRETVALUE123", blob)
        self.assertEqual(d.confidence, 75)       # cookie rule carries confidence:75

    def test_cert_issuer_and_dom_rules(self):
        s = snap(dom_hits={"[ng-version]": [{"a": {"ng-version": "17.3.1"}}]})
        dets, _ = self.tdb.analyze(s, cert_issuer="Let's Encrypt R11")
        self.assertEqual(self.get(dets, "Angular").version, "17.3.1")
        self.assertIsNotNone(self.get(dets, "Let's Encrypt"))

    def test_csp_allowlist_hints_are_weak(self):
        # only host-level rules can match an allow-list entry (path-level rules need a real URL)
        dets, _ = self.tdb.analyze(snap(), csp_hosts=["cdn.shopify.com"])
        d = self.get(dets, "Shopify")
        self.assertIsNotNone(d)
        self.assertEqual(d.status, "weak")
        self.assertLess(d.confidence, 50)

    def test_static_and_browser_differ_on_js_only_signals(self):
        static = self.tdb.analyze(snap(mode="static"))[0]
        browser = self.tdb.analyze(snap(js_values={"React.version": "18.2.0"}))[0]
        self.assertIsNone(self.get(static, "React"))
        self.assertEqual(self.get(browser, "React").status, "confirmed")


class Scale(unittest.TestCase):
    def test_eight_thousand_technologies_stay_fast(self):
        techs = {}
        for i in range(8000):
            techs[f"Tech{i}"] = {"cats": [1], "html": [f"<div class=\"zz{i}-widget[^>]*>", f"unique-marker-{i}-end\\;confidence:50"],
                                 "scriptSrc": [f"/assets/lib{i}(?:\\.min)?\\.js"], "headers": {f"X-Tech-{i % 50}": f"v{i}"},
                                 "scripts": [f"function tech{i}Init\\("], "text": [f"powered by tech{i}"]}
        techs["Needle"] = {"cats": [1], "html": [r"id=\"needle-(\d+)\"\;version:\1"]}
        tdb = TechDB(techs, {"1": {"name": "x"}})
        html = ("<p>filler text</p>" * 6000) + '<div id="needle-42"></div>'
        s = snap(html_raw=html, html_rendered=html, scripts=[ScriptRef(url="https://x.test/assets/other.js", text="var a=1;" * 4000)])
        t = time.perf_counter()
        dets, _ = tdb.analyze(s)
        dt = time.perf_counter() - t
        self.assertEqual([d.name for d in dets], ["Needle"])
        self.assertEqual(dets[0].version, "42")
        print(f"\n   [perf] 8000 technologies x ~120 KB page: {dt * 1000:.0f} ms")
        self.assertLess(dt, 6.0)


if __name__ == "__main__":
    unittest.main()
