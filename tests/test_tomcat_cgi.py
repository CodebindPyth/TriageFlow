import tempfile
import unittest
from pathlib import Path

from triageflow_cgi import find_tomcat_origins, run_tomcat_cgi_check


class TomcatCgiDiscoveryTests(unittest.TestCase):
    def test_detects_tomcat_from_httpx_technology(self):
        records = [{"url": "http://example.test:8080", "tech": ["Apache Tomcat:9.0.31"]}]
        self.assertEqual(find_tomcat_origins(records, []), ["http://example.test:8080"])

    def test_detects_coyote_header_as_tomcat_hint(self):
        records = [{"url": "http://example.test:8080/", "webserver": "Apache-Coyote/1.1"}]
        self.assertEqual(find_tomcat_origins(records, []), ["http://example.test:8080"])

    def test_ignores_non_tomcat_observations(self):
        records = [{"url": "https://example.test", "webserver": "nginx/1.24.0"}]
        self.assertEqual(find_tomcat_origins(records, []), [])

    def test_no_tomcat_writes_empty_reports_without_network_requests(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_tomcat_cgi_check(
                [{"url": "https://example.test", "server": "nginx"}],
                [],
                Path(temp_dir),
            )
            self.assertEqual(result["status"], "skipped")
            self.assertEqual(result["probes_sent"], 0)
            self.assertTrue((Path(temp_dir) / "tomcat-cgi-findings.csv").exists())
            self.assertTrue((Path(temp_dir) / "tomcat-cgi-findings.json").exists())


if __name__ == "__main__":
    unittest.main()
