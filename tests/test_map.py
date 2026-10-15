import csv
import json
import tempfile
import unittest
from pathlib import Path

from triageflow_map import build_attack_surface_graph, generate_attack_surface_map
from triageflow_reports import generate_html_report, write_asset_inventory, write_default_credentials_review


class AttackSurfaceMapTests(unittest.TestCase):
    def test_map_connects_hosts_urls_endpoints_and_security_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            (out / "root-domains.txt").write_text("example.test\n", encoding="utf-8")
            write_asset_inventory([{
                "url": "https://app.example.test",
                "hostname": "app.example.test",
                "status_code": 200,
                "title": "<img src=x onerror=alert(1)>",
                "webserver": "Apache/2.4.57",
                "tech": ["Apache HTTP Server:2.4.57"],
            }], out / "asset-inventory.csv")

            with (out / "software-inventory.csv").open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=[
                    "url", "product", "version", "source", "raw_fingerprint",
                ])
                writer.writeheader()
                writer.writerow({
                    "url": "https://app.example.test",
                    "product": "Apache HTTP Server",
                    "version": "2.4.57",
                    "source": "tech",
                    "raw_fingerprint": "Apache HTTP Server:2.4.57",
                })

            with (out / "login-panels.csv").open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=["login_url", "title", "evidence"])
                writer.writeheader()
                writer.writerow({
                    "login_url": "https://app.example.test/login",
                    "title": "Sign in",
                    "evidence": "password input field",
                })

            (out / "katana-findings.jsonl").write_text(
                json.dumps({"request": {"endpoint": "https://app.example.test/api/profile"}}) + "\n",
                encoding="utf-8",
            )
            (out / "nuclei-findings.jsonl").write_text(
                json.dumps({
                    "template-id": "test-template",
                    "matched-at": "https://app.example.test",
                    "info": {"name": "Example finding", "severity": "high"},
                }) + "\n",
                encoding="utf-8",
            )
            (out / "cve-candidates.json").write_text(json.dumps({
                "results": [{
                    "product": "Apache HTTP Server",
                    "observed_version": "2.4.57",
                    "cves": [{
                        "id": "CVE-2024-12345",
                        "severity": "HIGH",
                        "cvss_score": 8.0,
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
                        "description": "Example candidate for map testing",
                    }],
                }],
            }), encoding="utf-8")

            graph = build_attack_surface_graph(out)
            kinds = {node["type"] for node in graph["nodes"]}
            labels = {node["label"] for node in graph["nodes"]}
            self.assertTrue({"root", "host", "url", "technology", "login", "endpoint", "finding", "cve"}.issubset(kinds))
            self.assertIn("CVE-2024-12345 (HIGH)", labels)
            self.assertGreater(graph["edge_count"], 5)

            result = generate_attack_surface_map(out)
            self.assertTrue(Path(result["html_path"]).is_file())
            self.assertTrue(Path(result["json_path"]).is_file())
            page = Path(result["html_path"]).read_text(encoding="utf-8")
            self.assertIn("Interactive attack surface relationship map", page)
            self.assertIn("attack surface", page.lower())
            self.assertNotIn("<img src=x", page)
            self.assertIn("\\u003cimg", page)

            write_default_credentials_review([], [], out)
            report = generate_html_report(out, {
                "version": "2.1.0",
                "finished_utc": "2026-10-15T00:00:00Z",
                "target_count": 1,
                "live_url_count": 1,
                "subdomain_count": 0,
                "software_fingerprint_count": 1,
                "login_panel_count": 0,
                "cve_candidate_count": 1,
                "attack_map_enabled": True,
                "stages": {},
            })
            report_text = report.read_text(encoding="utf-8")
            self.assertIn('href="attack-surface-map.html"', report_text)
            self.assertIn('href="attack-surface-map.json"', report_text)


if __name__ == "__main__":
    unittest.main()
