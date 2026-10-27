import unittest

from triageflow_dirs import directory_fuzz_url


class DirectoryFuzzTests(unittest.TestCase):
    def test_uses_origin_root_and_appends_fuzz_marker(self):
        self.assertEqual(
            directory_fuzz_url("https://app.example.test/admin?next=1"),
            "https://app.example.test/FUZZ",
        )

    def test_preserves_port(self):
        self.assertEqual(
            directory_fuzz_url("http://app.example.test:8080/path"),
            "http://app.example.test:8080/FUZZ",
        )

    def test_rejects_non_http_urls(self):
        with self.assertRaises(ValueError):
            directory_fuzz_url("ftp://app.example.test/")


if __name__ == "__main__":
    unittest.main()
