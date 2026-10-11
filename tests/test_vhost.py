import csv
import json
import tempfile
import unittest
from pathlib import Path

from triageflow import base_url_for_root, build_wordlist_candidates, write_vhost_outputs


class VirtualHostTests(unittest.TestCase):
    def test_base_url_uses_supplied_scheme_and_host(self):
        self.assertEqual(
            base_url_for_root("inlanefreight.local", ["http://inlanefreight.local/login"]),
            "http://inlanefreight.local/",
        )
        self.assertEqual(
            base_url_for_root("app.example.test", ["https://app.example.test:8443/path"]),
            "https://app.example.test:8443/",
        )

    def test_wordlist_candidates_stay_under_selected_root(self):
        self.assertEqual(
            build_wordlist_candidates(
                ["inlanefreight.local"], ["admin", "dev", "not-in-scope.example"]
            ),
            ["admin.inlanefreight.local", "dev.inlanefreight.local"],
        )

    def test_vhost_outputs_are_written_in_csv_json_and_text(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            rows = [{
                "virtual_host": "portal.inlanefreight.local",
                "root_domain": "inlanefreight.local",
                "base_url": "http://inlanefreight.local/",
                "status_code": 200,
                "content_length": 1234,
                "words": 200,
                "lines": 30,
                "content_type": "text/html",
                "redirect_location": "",
            }]
            write_vhost_outputs(rows, out)
            with (out / "vhost-findings.csv").open(encoding="utf-8", newline="") as stream:
                saved = list(csv.DictReader(stream))
            self.assertEqual(saved[0]["virtual_host"], "portal.inlanefreight.local")
            self.assertEqual(
                (out / "vhost-subdomains.txt").read_text(encoding="utf-8").strip(),
                "portal.inlanefreight.local",
            )
            raw = json.loads((out / "vhost-findings.json").read_text(encoding="utf-8"))
            self.assertEqual(raw["count"], 1)
            self.assertEqual(raw["results"][0]["status_code"], 200)


if __name__ == "__main__":
    unittest.main()
