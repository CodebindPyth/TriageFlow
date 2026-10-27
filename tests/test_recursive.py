import unittest

from pathlib import Path
import tempfile

from triageflow_recursive import is_in_scope, read_lines, write_lines


class RecursiveSubdomainTests(unittest.TestCase):
    def test_accepts_root_and_nested_hosts(self):
        self.assertTrue(is_in_scope("example.test", ["example.test"]))
        self.assertTrue(is_in_scope("api.example.test", ["example.test"]))
        self.assertTrue(is_in_scope("v2.dev.api.example.test", ["example.test"]))

    def test_rejects_suffix_lookalikes_and_unrelated_domains(self):
        self.assertFalse(is_in_scope("notexample.test", ["example.test"]))
        self.assertFalse(is_in_scope("example.test.evil.test", ["example.test"]))
        self.assertFalse(is_in_scope("example.org", ["example.test"]))
        self.assertFalse(is_in_scope("sub.example.test.evil.test", ["example.test"]))

    def test_case_and_trailing_dot_are_normalized(self):
        self.assertTrue(is_in_scope("API.Example.Test.", ["example.test"]))

    def test_line_helpers_write_one_host_per_line(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "hosts.txt"
            write_lines(path, ["api.example.test", "api.example.test", "dev.example.test"])
            self.assertEqual(read_lines(path), ["api.example.test", "dev.example.test"])

    def test_recursive_validation_rejects_invalid_depth_and_host_cap(self):
        from pathlib import Path
        from triageflow_recursive import recursive_subfinder

        with self.assertRaises(ValueError):
            recursive_subfinder(["api.example.test"], ["example.test"], Path("."), max_depth=0)
        with self.assertRaises(ValueError):
            recursive_subfinder(["api.example.test"], ["example.test"], Path("."), max_hosts=0)


if __name__ == "__main__":
    unittest.main()
