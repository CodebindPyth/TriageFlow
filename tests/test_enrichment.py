import unittest

from triageflow_enrichment import (
    _classify_cve_match,
    collect_fingerprints,
    httpx_url,
)


class FingerprintTests(unittest.TestCase):
    def test_httpx_url_fallback(self):
        self.assertEqual(httpx_url({"input": "https://example.test"}), "https://example.test")
        self.assertEqual(httpx_url({"input": "not-a-url"}), "")

    def test_extracts_product_versions_and_source_urls(self):
        records = [{
            "url": "https://example.test",
            "tech": ["WordPress:6.4.3", "PHP:8.2.1"],
            "webserver": "nginx/1.24.0",
            "status_code": 200,
            "title": "Example",
        }]
        fingerprints = collect_fingerprints(records)
        observed = {(item["product"], item["version"], item["source"]) for item in fingerprints}
        self.assertIn(("WordPress", "6.4.3", "tech"), observed)
        self.assertIn(("PHP", "8.2.1", "tech"), observed)
        self.assertIn(("nginx", "1.24.0", "webserver"), observed)

    def test_duplicate_fingerprints_are_removed(self):
        record = {"url": "https://example.test", "tech": ["PHP:8.2.1", "PHP:8.2.1"]}
        fingerprints = collect_fingerprints([record])
        php_rows = [row for row in fingerprints if row["product"] == "PHP"]
        self.assertEqual(len(php_rows), 1)

    def test_same_product_from_tech_and_webserver_is_merged(self):
        record = {
            "url": "https://example.test",
            "tech": ["OpenResty", "jQuery:3.6.4"],
            "webserver": "openresty",
            "server": "OpenResty",
        }
        fingerprints = collect_fingerprints([record])
        openresty_rows = [
            row for row in fingerprints if row["product"].casefold() == "openresty"
        ]
        self.assertEqual(len(openresty_rows), 1)
        self.assertEqual(openresty_rows[0]["source"], "tech; webserver; server")
        self.assertEqual(openresty_rows[0]["raw_fingerprint"], "OpenResty | openresty")

    def test_cpe_exact_version_is_prioritized(self):
        cve = {"configurations": [{"nodes": [{"cpeMatch": [{
            "criteria": "cpe:2.3:a:wordpress:wordpress:6.4.3:*:*:*:*:*:*:*",
            "vulnerable": True,
        }]}]}]}
        confidence, criteria = _classify_cve_match(cve, "WordPress", "6.4.3")
        self.assertTrue(confidence.startswith("CPE applicability supports"))
        self.assertEqual(len(criteria), 1)

    def test_cpe_mismatch_does_not_claim_version_support(self):
        cve = {"configurations": [{"nodes": [{"cpeMatch": [{
            "criteria": "cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*",
            "vulnerable": True,
        }]}]}]}
        confidence, _ = _classify_cve_match(cve, "WordPress", "6.4.3")
        self.assertTrue(confidence.startswith("CPE product found"))

    def test_cpe_version_range_is_checked(self):
        cve = {"configurations": [{"nodes": [{"cpeMatch": [{
            "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "6.0.0",
            "versionEndExcluding": "6.5.0",
            "vulnerable": True,
        }]}]}]}
        confidence, criteria = _classify_cve_match(cve, "WordPress", "6.4.3")
        self.assertTrue(confidence.startswith("CPE applicability supports"))
        self.assertEqual(len(criteria), 1)

    def test_keyword_only_candidate_is_labelled_as_such(self):
        confidence, criteria = _classify_cve_match({"configurations": []}, "WordPress", "6.4.3")
        self.assertTrue(confidence.startswith("Keyword-only"))
        self.assertEqual(criteria, [])


if __name__ == "__main__":
    unittest.main()
