import unittest

from triageflow import (
    base_url_for_root,
    build_wordlist_candidates,
    hostname_of,
    is_ip,
    parse_dns_resolvers,
)


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


    def test_wordlist_candidates_are_valid_and_stay_in_scope(self):
        candidates = build_wordlist_candidates(
            ["example.test"],
            ["admin", "api.example.test", "other.example.org", "bad_name", "-bad", "admin"],
        )
        self.assertEqual(candidates, ["admin.example.test", "api.example.test"])

    def test_base_url_matches_normalized_www_root(self):
        self.assertEqual(
            base_url_for_root("example.test", ["https://www.example.test/path"]),
            "https://www.example.test/",
        )

    def test_dns_resolvers_skip_link_local_scoped_ipv6(self):
        resolvers = parse_dns_resolvers(
            "nameserver 172.20.10.1\n"
            "nameserver fe80::8820:dff:fe52:5d64%eth1\n"
            "nameserver fe80::1\n"
            "nameserver 2001:4860:4860::8888\n"
            "nameserver 172.20.10.1\n"
        )
        self.assertEqual(resolvers, ["172.20.10.1", "2001:4860:4860::8888"])


if __name__ == "__main__":
    unittest.main()
