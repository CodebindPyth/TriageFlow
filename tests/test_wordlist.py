import unittest

from triageflow import (
    build_wordlist_candidates,
    bundled_wordlist_path,
    combine_targets,
)


class WordlistCandidateTests(unittest.TestCase):
    def test_labels_are_combined_with_root_domain(self):
        self.assertEqual(
            build_wordlist_candidates(["inlanefreight.local"], ["www", "api"]),
            ["www.inlanefreight.local", "api.inlanefreight.local"],
        )

    def test_full_hostnames_inside_scope_are_kept(self):
        self.assertEqual(
            build_wordlist_candidates(
                ["example.test"], ["dev.example.test", "api", "dev.example.test"]
            ),
            ["dev.example.test", "api.example.test"],
        )

    def test_full_hostnames_outside_scope_are_ignored(self):
        self.assertEqual(
            build_wordlist_candidates(["example.test"], ["other.test", "portal"]),
            ["portal.example.test"],
        )

    def test_invalid_words_and_duplicate_candidates_are_ignored(self):
        self.assertEqual(
            build_wordlist_candidates(
                ["example.test"],
                ["", "# comment", "bad label", "https://bad.test", "-bad", "ok", "ok"],
            ),
            ["ok.example.test"],
        )

    def test_bundled_wordlist_is_available_for_default_cli_use(self):
        path = bundled_wordlist_path()
        self.assertTrue(path.is_file())
        words = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertIn("www", words)
        self.assertIn("api", words)

    def test_wordlist_targets_are_prioritized_before_passive_results(self):
        self.assertEqual(
            combine_targets(
                direct=["https://example.test/"],
                roots=["example.test"],
                wordlist_names=["api.example.test", "dev.example.test"],
                passive_names=["dev.example.test", "mail.example.test"],
            ),
            [
                "https://example.test/",
                "example.test",
                "api.example.test",
                "dev.example.test",
                "mail.example.test",
            ],
        )


if __name__ == "__main__":
    unittest.main()
