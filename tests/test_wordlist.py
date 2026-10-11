import unittest

from triageflow import build_wordlist_candidates


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


if __name__ == "__main__":
    unittest.main()
