import unittest

from triageflow_enrichment import collect_fingerprints, httpx_url


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


if __name__ == "__main__":
    unittest.main()
