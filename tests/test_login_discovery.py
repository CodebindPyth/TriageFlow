import csv
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from triageflow_enrichment import detect_login_panels


class LoginDiscoveryTests(unittest.TestCase):
    def test_discovers_login_page_linked_from_homepage_at_custom_path(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/":
                    body = (
                        '<html><head><title>University home</title></head><body>'
                        '<a href="/identity/sign-in">Sign in to student portal</a>'
                        '</body></html>'
                    ).encode()
                    status = 200
                elif self.path == "/identity/sign-in":
                    body = (
                        '<html><head><title>Campus Access</title></head><body>'
                        '<form action="/session"><input name="username">'
                        '<input name="password" type="password"></form></body></html>'
                    ).encode()
                    status = 200
                else:
                    body = b"not found"
                    status = 404
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        try:
            with tempfile.TemporaryDirectory() as temp:
                output = Path(temp) / "login-panels.csv"
                panels = detect_login_panels([origin + "/"], output, max_hosts=5, timeout=0.5)
                self.assertEqual(len(panels), 1)
                self.assertEqual(panels[0]["login_url"], origin + "/identity/sign-in")
                self.assertIn("password input field", panels[0]["evidence"])
                self.assertIs(panels[0]["credentials_submitted"], False)
                with output.open(encoding="utf-8", newline="") as stream:
                    saved = list(csv.DictReader(stream))
                self.assertEqual(saved[0]["login_url"], origin + "/identity/sign-in")
                summary = json.loads((Path(temp) / "login-discovery-summary.json").read_text())
                self.assertEqual(summary["panels_found"], 1)
                self.assertGreaterEqual(summary["requests_sent"], 2)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
