import tempfile
import unittest
from pathlib import Path

from vhost_direct import load_labels


class DirectVHostWordlistTests(unittest.TestCase):
    def test_load_labels_filters_invalid_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as temp:
            wordlist = Path(temp) / "labels.txt"
            wordlist.write_text(
                "# comment\nadmin\nAdmin\ndev-1\nnot.a.label\n-bad\n\n",
                encoding="utf-8",
            )
            self.assertEqual(load_labels(wordlist, "inlanefreight.local"), ["admin", "dev-1"])

    def test_missing_wordlist_raises_clear_error(self):
        with tempfile.TemporaryDirectory() as temp:
            missing = Path(temp) / "missing.txt"
            with self.assertRaisesRegex(FileNotFoundError, "Wordlist not found"):
                load_labels(missing, "inlanefreight.local")


if __name__ == "__main__":
    unittest.main()
