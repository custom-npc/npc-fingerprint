import unittest

import _bootstrap  # noqa: F401
from npc_fingerprint.modules import scope


class ScopeGuard(unittest.TestCase):
    def test_same_registrable_domain_is_in_scope(self):
        self.assertTrue(scope.in_scope("https://api.shop.test/x", "shop.test"))
        self.assertTrue(scope.in_scope("https://shop.test/x", "www.shop.test"))

    def test_other_domains_are_out_of_scope_by_default(self):
        self.assertFalse(scope.in_scope("https://evil.com/x", "shop.test"))

    def test_relative_url_has_no_host_and_is_rejected(self):
        self.assertFalse(scope.in_scope("/api/x", "shop.test"))

    def test_explicit_scope_extends_allowed_domains(self):
        self.assertFalse(scope.in_scope("https://partner-api.example.net/x", "shop.test"))
        self.assertTrue(scope.in_scope("https://partner-api.example.net/x", "shop.test", ["example.net"]))

    def test_filter_in_scope_splits_and_dedupes(self):
        ins, outs = scope.filter_in_scope(
            ["https://shop.test/a", "https://evil.com/b", "https://shop.test/a", "https://evil.com/b"], "shop.test")
        self.assertEqual((ins, outs), (["https://shop.test/a"], ["https://evil.com/b"]))


if __name__ == "__main__":
    unittest.main()
