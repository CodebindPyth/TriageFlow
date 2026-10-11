import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

from triageflow import run_step


class RunStepProgressTests(unittest.TestCase):
    def test_long_step_prints_heartbeat_and_counts_new_jsonl_records(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            output_file = directory / "httpx-details.jsonl"
            log_file = directory / "tool.log"
            script = (
                "import sys, time; "
                "from pathlib import Path; "
                "p = Path(sys.argv[1]); "
                "p.write_text('first\\n', encoding='utf-8'); "
                "time.sleep(0.12); "
                "p.open('a', encoding='utf-8').write('second\\n'); "
                "time.sleep(0.12)"
            )

            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                return_code = run_step(
                    "test tool",
                    [sys.executable, "-c", script, str(output_file)],
                    log_file,
                    progress_file=output_file,
                    heartbeat_interval=0.04,
                )

            self.assertEqual(return_code, 0)
            output = captured.getvalue()
            self.assertIn("still running", output)
            self.assertIn("HTTP result record(s) saved", output)
            self.assertIn("completed in", output)


if __name__ == "__main__":
    unittest.main()
