"""Bounded GET-only discovery of likely CGI script endpoints on Tomcat services.

No command arguments, query strings, credentials, or exploit payloads are submitted.
Responses are candidates for manual verification only.
"""
from __future__ import annotations

import csv
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

MAX_TOMCAT_ORIGINS = 10
CGI_DIRECTORIES = ("/cgi/", "/cgibin/", "/cgi-bin/")
CGI_FILENAMES = ("cmd.bat", "cmd.cmd", "index.bat", "index.cmd")
FIELDS = [
    "origin", "path", "url", "kind", "http_status", "content_type",
    "content_length", "server", "location", "classification", "note",
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects outside the original URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _origin(url: str) -> str:
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in ("http", "https") or not parts.netloc or not parts.hostname:
            return ""
        return urlunsplit((parts.scheme.lower(), parts.netloc, "", "", ""))
    except ValueError:
        return ""


def _record_text(record: dict) -> str:
    values = []
    for key in ("tech", "technologies", "webserver", "server"):
        value = record.get(key)
        if isinstance(value, list):
            values.extend(str(item) for item in value)
        elif value:
            values.append(str(value))
    return " ".join(values)


def find_tomcat_origins(httpx_records: list[dict], fingerprints: list[dict]) -> list[str]:
    """Return unique origins whose observed fingerprints suggest Tomcat."""
    origins = []
    seen = set()

    def add(url: str) -> None:
        origin = _origin(url)
        if origin and origin.casefold() not in seen and len(origins) < MAX_TOMCAT_ORIGINS:
            seen.add(origin.casefold())
            origins.append(origin)

    for record in httpx_records:
        if re.search(r"(?:apache[- ]?)?tomcat|apache-coyote", _record_text(record), re.I):
            add(str(record.get("url") or record.get("input") or record.get("final_url") or ""))
    for record in fingerprints:
        text = " ".join(str(record.get(key) or "") for key in ("product", "raw_fingerprint"))
        if re.search(r"(?:apache[- ]?)?tomcat|apache-coyote", text, re.I):
            add(str(record.get("url") or ""))
    return origins


def _probe(opener, origin: str, path: str, timeout: float) -> dict:
    url = origin + path
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": "TriageFlow/2.3 (authorized, non-exploit CGI discovery)",
            "Accept": "*/*",
            "Connection": "close",
        },
    )
    status = ""
    headers = None
    try:
        response = opener.open(request, timeout=timeout)
        status = getattr(response, "status", 200)
        headers = response.headers
        response.close()
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = exc.headers
        exc.close()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "origin": origin, "path": path, "url": url,
            "kind": "directory" if path.endswith("/") else "script",
            "http_status": "", "content_type": "", "content_length": "",
            "server": "", "location": "",
            "classification": "unconfirmed",
            "note": f"request error: {type(exc).__name__}",
        }

    status_number = int(status) if str(status).isdigit() else 0
    possible = status_number not in (404, 410, 0)
    return {
        "origin": origin,
        "path": path,
        "url": url,
        "kind": "directory" if path.endswith("/") else "script",
        "http_status": status,
        "content_type": headers.get("Content-Type", "") if headers else "",
        "content_length": headers.get("Content-Length", "") if headers else "",
        "server": headers.get("Server", "") if headers else "",
        "location": headers.get("Location", "") if headers else "",
        "classification": "possible endpoint" if possible else "not found",
        "note": (
            "HTTP response alone does not prove a CGI script exists; custom 404 pages and catch-all routes can create false positives."
            if possible else "HTTP 404/410 response."
        ),
    }


def run_tomcat_cgi_check(
    httpx_records: list[dict],
    fingerprints: list[dict],
    output_dir: Path,
    timeout: float = 2.5,
) -> dict:
    """Check a small fixed set of CGI directories and .bat/.cmd paths using GET only."""
    output_dir.mkdir(parents=True, exist_ok=True)
    origins = find_tomcat_origins(httpx_records, fingerprints)
    rows: list[dict] = []
    probes_sent = 0

    if origins:
        opener = urllib.request.build_opener(_NoRedirect)
        for origin in origins:
            for directory in CGI_DIRECTORIES:
                time.sleep(0.1)
                directory_row = _probe(opener, origin, directory, timeout)
                rows.append(directory_row)
                probes_sent += 1
                directory_status = str(directory_row["http_status"])
                if directory_status in ("404", "410") or directory_status == "":
                    continue
                for filename in CGI_FILENAMES:
                    path = directory + filename
                    time.sleep(0.1)
                    rows.append(_probe(opener, origin, path, timeout))
                    probes_sent += 1

    csv_path = output_dir / "tomcat-cgi-findings.csv"
    json_path = output_dir / "tomcat-cgi-findings.json"
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    possible = [row for row in rows if row["classification"] == "possible endpoint"]
    result = {
        "status": "completed" if origins else "skipped",
        "reason": "" if origins else "No Tomcat/Apache-Coyote fingerprint observed",
        "tomcat_origins_checked": len(origins),
        "probes_sent": probes_sent,
        "candidate_count": len(possible),
        "csv": str(csv_path),
        "json": str(json_path),
        "method": "bounded same-origin GET-only requests; no query strings, credentials, command arguments, or exploit payloads",
        "candidates": possible,
    }
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result
