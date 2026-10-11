import argparse
import unittest
from pathlib import Path
from unittest.mock import patch

from triageflow import interactive_setup, prompt_choice


def make_args():
    return argparse.Namespace(
        single_target=None,
        list=None,
        wordlist=None,
        no_subdomains=False,
        no_nuclei=False,
        no_screenshots=False,
    )


class WizardTests(unittest.TestCase):
    def test_prompt_choice_uses_default(self):
        with patch("builtins.input", return_value=""):
            self.assertEqual(prompt_choice("Profile", {"1": "Standard", "2": "Quick"}, "1"), "1")

    def test_standard_wizard_uses_bundled_wordlist(self):
        args = make_args()
        with patch("builtins.input", side_effect=["1", "example.com", "1", "1"]):
            with patch("builtins.print"):
                self.assertTrue(interactive_setup(args))
        self.assertEqual(args.single_target, "example.com")
        self.assertIsNone(args.list)
        self.assertTrue(args.wordlist.endswith(str(Path("wordlists") / "subdomains-small.txt")))
        self.assertFalse(args.no_subdomains)
        self.assertFalse(args.no_nuclei)
        self.assertFalse(args.no_screenshots)

    def test_quick_wizard_disables_heavy_stages(self):
        args = make_args()
        with patch("builtins.input", side_effect=["1", "example.com", "3", "2"]):
            with patch("builtins.print"):
                self.assertTrue(interactive_setup(args))
        self.assertEqual(args.single_target, "example.com")
        self.assertIsNone(args.wordlist)
        self.assertTrue(args.no_subdomains)
        self.assertTrue(args.no_nuclei)
        self.assertTrue(args.no_screenshots)

    def test_quit_cancels_wizard(self):
        args = make_args()
        with patch("builtins.input", return_value="q"):
            with patch("builtins.print"):
                self.assertFalse(interactive_setup(args))


if __name__ == "__main__":
    unittest.main()
