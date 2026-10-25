import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from triageflow_ai import DEFAULT_MODEL, _extract_response_text, analyze_saved_results, build_evidence, render_markdown, write_markdown_report

class TriageFlowAITests(unittest.TestCase):
    def test_default_model_is_configurable(self):
        self.assertEqual(DEFAULT_MODEL, "gpt-6-astra")

    def test_missing_or_malformed_artifacts_are_tolerated(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            (out / "nuclei-findings.jsonl").write_text("{bad json}\n", encoding="utf-8")
            evidence = build_evidence(out)
            self.assertEqual(evidence["nuclei_findings"], [])
            self.assertEqual(evidence["assets"], [])
            self.assertIn("evidence_limits", evidence)

    def test_build_evidence_normalizes_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            (out / "nuclei-findings.jsonl").write_text(json.dumps({
                "template-id": "sample", "info": {"name": "test finding", "severity": "high"},
                "matched-at": "https://app.example.test/"}) + "\n", encoding="utf-8")
            (out / "asset-inventory.csv").write_text(
                "url,hostname,status_code,title,webserver,technologies\nhttps://app.example.test/,app.example.test,200,Example,nginx,Python\n",
                encoding="utf-8")
            evidence = build_evidence(out)
            self.assertEqual(evidence["nuclei_findings"][0]["severity_as_reported"], "high")
            self.assertEqual(evidence["assets"][0]["hostname"], "app.example.test")

    def test_build_evidence_includes_quality_assessment(self):
        with tempfile.TemporaryDirectory() as temp:
            evidence = build_evidence(Path(temp))
            quality = evidence["quality_assessment"]
            self.assertEqual(quality["schema_version"], 1)
            self.assertEqual(quality["summary"]["asset_records"], 0)
            self.assertIn("not prove exploitability", quality["summary"]["interpretation"])

    def test_extract_response_text(self):
        self.assertEqual(_extract_response_text({"output": [{"content": [
            {"type": "output_text", "text": "{\"hello\":\"world\"}"}
        ]}]}), "{\"hello\":\"world\"}")

    def test_requires_api_key(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.dict("os.environ", {"OPENAI_API_KEY": ""}, clear=False):
                with self.assertRaisesRegex(ValueError, "OPENAI_API_KEY"):
                    analyze_saved_results(Path(temp), api_key="")
            self.assertFalse((Path(temp) / "ai-triage.json").exists())

    def test_markdown_renderer_handles_empty_result(self):
        rendered = render_markdown({"model": "test-model", "executive_summary": "Insufficient evidence.",
            "limitations": ["No scanner output."], "prioritized_findings": [],
            "recommended_next_steps": ["Review authorized scope."]})
        self.assertIn("Advisory only", rendered)
        self.assertIn("No actionable findings", rendered)

    def test_write_markdown_report(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            path = write_markdown_report(out, {"model": "test-model", "executive_summary": "Summary",
                "limitations": [], "prioritized_findings": [], "recommended_next_steps": []})
            self.assertTrue(path.is_file())
            self.assertIn("test-model", path.read_text(encoding="utf-8"))

if __name__ == "__main__":
    unittest.main()
