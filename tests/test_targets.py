import unittest

from triageflow import hostname_of, is_ip


class TargetParsingTests(unittest.TestCase):
    def test_bare_ipv6_is_not_truncated_at_first_colon(self):
        host = hostname_of("2001:db8::1")
        self.assertEqual(host, "2001:db8::1")
        self.assertTrue(is_ip(host))

    def test_bracketed_ipv6_with_port_preserves_full_address(self):
        host = hostname_of("[2001:db8::1]:8443")
        self.assertEqual(host, "2001:db8::1")
        self.assertTrue(is_ip(host))

    def test_ipv6_url_extracts_hostname(self):
        host = hostname_of("https://[2001:db8::1]:8443/admin")
        self.assertEqual(host, "2001:db8::1")
        self.assertTrue(is_ip(host))

    def test_hostname_with_port_drops_port_for_scope_checks(self):
        self.assertEqual(hostname_of("app.example.test:8443"), "app.example.test")


if __name__ == "__main__":
    unittest.main()
