import json
import tempfile
import unittest
from pathlib import Path

from triageflow_quality import correlate_evidence, evaluate_labeled_fixtures


ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures" / "triage_quality_cases.json"


class EvidenceCorrelationTests(unittest.TestCase):
    def test_labeled_regression_fixture_is_fully_correct(self):
        report = evaluate_labeled_fixtures(FIXTURE)
        self.assertTrue(report["passed"], report["details"])
        self.assertEqual(report["cases"], 5)
        self.assertEqual(report["overall_classification_accuracy"], 1.0)
        self.assertEqual(report["cve_classification_accuracy"], 1.0)
        self.assertEqual(report["nuclei_classification_accuracy"], 1.0)
        self.assertIn("not a measure of real-world", report["note"])

    def test_finding_duplicates_are_counted_but_not_called_confirmed(self):
        evidence = {
            "assets": [{"url": "https://app.example.test/", "hostname": "app.example.test"}],
            "software_fingerprints": [{"url": "https://app.example.test/", "product": "PHP", "version": "8.2.1"}],
            "nuclei_findings": [
                {"template_id": "same-check", "matched_at": "https://app.example.test/a", "severity_as_reported": "high"},
                {"template_id": "same-check", "matched_at": "https://app.example.test/b", "severity_as_reported": "high"},
            ],
            "cve_candidates": [],
            "login_panels": [],
        }
        report = correlate_evidence(evidence)
        self.assertEqual(len(report["nuclei_findings"]), 2)
        self.assertTrue(all(x["duplicate_count_for_host_and_template"] == 2 for x in report["nuclei_findings"]))
        self.assertTrue(all(x["validation_state"] == "scanner_reported_unverified" for x in report["nuclei_findings"]))

    def test_conflicting_versions_are_reported_without_choosing_one(self):
        evidence = {
            "assets": [],
            "software_fingerprints": [
                {"url": "https://app.example.test/", "product": "nginx", "version": "1.24.0"},
                {"url": "https://APP.example.test/", "product": "Nginx", "version": "1.26.0"},
            ],
            "nuclei_findings": [],
            "cve_candidates": [],
            "login_panels": [],
        }
        report = correlate_evidence(evidence)
        self.assertEqual(len(report["software_version_conflicts"]), 1)
        self.assertEqual(report["software_version_conflicts"][0]["observed_versions"], ["1.24.0", "1.26.0"])

    def test_evaluator_penalizes_unexpected_predictions(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Path(temp) / "fixture.json"
            fixture.write_text(json.dumps({
                "name": "unexpected prediction",
                "cases": [{
                    "id": "unexpected-cve",
                    "evidence": {
                        "assets": [],
                        "software_fingerprints": [],
                        "cve_candidates": [{
                            "candidate_id": "CVE-TEST-9999",
                            "product": "WordPress",
                            "observed_version": "6.4.3",
                            "match_confidence": "Keyword-only candidate; no matching product CPE criteria found",
                            "source_urls": ["https://example.test/"],
                        }],
                        "nuclei_findings": [],
                        "login_panels": [],
                    },
                    "expected": {"cve_classifications": [], "nuclei_classifications": []},
                }],
            }), encoding="utf-8")
            report = evaluate_labeled_fixtures(fixture)
            self.assertFalse(report["passed"])
            self.assertEqual(report["overall_classification_accuracy"], 0.0)

    def test_evaluation_output_is_json_serializable(self):
        report = evaluate_labeled_fixtures(FIXTURE)
        self.assertEqual(json.loads(json.dumps(report))["overall_classification_accuracy"], 1.0)


if __name__ == "__main__":
    unittest.main()
