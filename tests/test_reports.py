import csv
import tempfile
import unittest
from pathlib import Path

from triageflow_reports import (
    generate_html_report,
    write_asset_inventory,
    write_default_credentials_review,
)


class V2ReportTests(unittest.TestCase):
    def test_asset_inventory_is_csv_friendly(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "asset-inventory.csv"
            rows = write_asset_inventory([{
                "url": "https://app.example.test",
                "host": "app.example.test",
                "a": ["192.0.2.10"],
                "status_code": 200,
                "title": "Admin",
                "webserver": "nginx/1.24",
                "tech": ["WordPress:6.4.3"],
            }], path)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["hostname"], "app.example.test")
            with path.open(encoding="utf-8", newline="") as stream:
                saved = list(csv.DictReader(stream))
            self.assertEqual(saved[0]["ip_addresses"], "192.0.2.10")

    def test_default_credential_report_is_manual_only(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            rows = write_default_credentials_review([{
                "origin": "https://wp.example.test",
                "login_url": "https://wp.example.test/wp-login.php",
                "title": "WordPress Log In",
                "evidence": "password input field",
            }], [{
                "url": "https://wp.example.test",
                "product": "WordPress",
                "version": "6.4.3",
            }], out)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["credentials_submitted"], "No")
            self.assertIn("MANUAL REVIEW REQUIRED", rows[0]["review_status"])
            self.assertTrue((out / "default-credentials-review.md").is_file())

    def test_html_report_is_generated_and_escapes_untrusted_titles(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            write_asset_inventory([{
                "url": "https://app.example.test",
                "title": "<script>alert('xss')</script>",
                "status_code": 200,
            }], out / "asset-inventory.csv")
            write_default_credentials_review([], [], out)
            with (out / "vhost-findings.csv").open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=[
                    "virtual_host", "root_domain", "base_url", "status_code",
                    "content_length", "words", "lines", "content_type", "redirect_location",
                ])
                writer.writeheader()
                writer.writerow({
                    "virtual_host": "portal.example.test",
                    "root_domain": "example.test",
                    "base_url": "http://example.test/",
                    "status_code": "200",
                    "content_length": "1234",
                    "words": "200",
                    "lines": "30",
                    "content_type": "text/html",
                    "redirect_location": "",
                })
            report = generate_html_report(out, {
                "version": "9.8.7",
                "finished_utc": "2026-10-11T00:00:00Z",
                "target_count": 1,
                "live_url_count": 1,
                "subdomain_count": 0,
                "software_fingerprint_count": 0,
                "login_panel_count": 0,
                "cve_candidate_count": 0,
                "stages": {},
            })
            text = report.read_text(encoding="utf-8")
            self.assertIn("TriageFlow v9.8.7 — Recon Report", text)
            self.assertIn("<title>TriageFlow v9.8.7 Security Recon Report</title>", text)
            self.assertNotIn("TriageFlow v2.0.1", text)
            self.assertIn("HTTP virtual hosts", text)
            self.assertIn("portal.example.test", text)
            self.assertNotIn("<script>alert", text)
            self.assertIn("&lt;script&gt;", text)

    def test_html_report_displays_gowitness_screenshots_from_local_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            shot_dir = out / "gowitness"
            shot_dir.mkdir()
            (shot_dir / "https_example_test.png").write_bytes(b"fake image bytes")
            report = generate_html_report(out, {
                "version": "2.0.8",
                "finished_utc": "2026-10-11T00:00:00Z",
                "target_count": 1,
                "live_url_count": 1,
                "subdomain_count": 0,
                "software_fingerprint_count": 0,
                "login_panel_count": 0,
                "cve_candidate_count": 0,
                "stages": {"gowitness": 0},
            })
            text = report.read_text(encoding="utf-8")
            self.assertIn("<h2>Screenshots</h2>", text)
            self.assertIn('src="gowitness/https_example_test.png"', text)
            self.assertIn("1 screenshot image(s) found", text)
            self.assertIn("\n.screenshots{", text)
            self.assertNotIn("\\n.screenshots{", text)


if __name__ == "__main__":
    unittest.main()
