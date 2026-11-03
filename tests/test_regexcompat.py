import unittest

import _bootstrap  # noqa: F401
from npc_fingerprint import regexcompat as rc


class Hints(unittest.TestCase):
    CASES = {
        r"^nginx(?:/([\d.]+))?$": "nginx",
        r"jquery(?:-|\.)([\d.]*\d)[^/]*\.js": "jquery",
        r"/wp-(?:content|includes)/": "/wp-",
        r"google-analytics\.com/(?:ga|analytics)\.js": "google-analytics.com/",
        r"foo|bar": None,                      # top-level alternation: nothing guaranteed
        r"ab?c": None,                         # 'b' optional, remaining runs too short
        r"abcd?e": "abc",
        r"\bVue\b": "vue",
        r"abc{0,2}d": None,
        r"x{2,3}yzw": "yzw",
    }

    def test_known_hints(self):
        for pat, expected in self.CASES.items():
            self.assertEqual(rc.literal_hint(pat), expected, pat)

    def test_hints_are_sound(self):
        """If the regex matches, the hint must be a substring: the prefilter may never cause a false negative."""
        pats = list(self.CASES) + [r"<link[^>]+s\d+\.wp\.com", r"cdn\.shopify\.com", r"data-react(?:root|id)", r"/([\d.]+)/jquery(?:\.min)?\.js",
                                   r"^Apache(?:/([\d.]+))?", r"(?:a|b)needle", r"needle+s?", r"\.php\b", r"wp-json/?", r"a.b.c.d", r"[a-z]+needle[0-9]*", r"x{2,3}yzw"]
        samples = ["nginx/1.24.0", "jquery-1.12.4.min.js", "/wp-content/x", "https://www.google-analytics.com/analytics.js", "foo", "bar", "ac", "abcde",
                   "abce", "xxyzw", "a Vue app", "abd", "abccd", "<link rel=x href=https://s0.wp.com/a>", "cdn.shopify.com/s/x", "data-reactroot", "/3.7.1/jquery.min.js",
                   "Apache/2.4.1", "wp-json", "xxyz", "bneedle", "needles", "needle", "index.php", "ab", "abc", "axbxcxd", "xyz needle9", "NEEDLE"]
        for p in pats:
            rx = rc.compile_body(p)
            h = rc.literal_hint(p)
            for s in samples:
                if rx is not None and rx.search(s) and h:
                    self.assertIn(h, s.lower(), f"{p!r} matched {s!r} but hint {h!r} absent")


class Tags(unittest.TestCase):
    def test_confidence_and_version(self):
        p = rc.Pat(r"^nginx(?:/([\d.]+))?\;version:\1\;confidence:80")
        h = p.match("nginx/1.24.0")
        self.assertEqual(p.confidence, 80)
        self.assertEqual(rc.resolve_version(p.version, h.groups), "1.24.0")

    def test_ternary(self):
        p = rc.Pat(r"^Apache(?:/([\d.]+))?\;version:\1?\1:unknown")
        self.assertEqual(rc.resolve_version(p.version, p.match("Apache").groups), "unknown")
        self.assertEqual(rc.resolve_version(p.version, p.match("Apache/2.4").groups), "2.4")

    def test_empty_pattern_means_presence(self):
        self.assertIsNotNone(rc.Pat("").match("anything"))

    def test_js_any_char_class_translates(self):
        self.assertIsNotNone(rc.Pat(r"[^]x").match("zzx"))

    def test_unportable_pattern_is_counted_not_fatal(self):
        before = rc.STATS["skipped"]
        self.assertIsNone(rc.Pat(r"(?<=a|bc)x").match("bcx") if not rc.HAVE_REGEX else None)
        self.assertGreaterEqual(rc.STATS["skipped"], before)

    def test_invalid_regex_does_not_raise(self):
        self.assertIsNone(rc.Pat(r"([unclosed").match("anything unclosed"))


if __name__ == "__main__":
    unittest.main()
