"""Bounded ffuf directory discovery for explicitly authorized live URLs."""
from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def directory_fuzz_url(raw_url: str) -> str:
    """Use the origin root for discovery and add ffuf's FUZZ marker."""
    parsed = urlsplit(raw_url.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Not a live HTTP(S) URL: {raw_url}")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, "/", "", "")) + "FUZZ"


def run_directory_ffuf(
    live_urls: list[str],
    wordlist: Path,
    out_dir: Path,
    *,
    rate: int = 10,
    threads: int = 10,
    max_time: int = 60,
    timeout: int = 10,
) -> dict:
    """Run ffuf once per unique HTTP(S) origin with explicit rate and time limits."""
    if not wordlist.is_file():
        raise FileNotFoundError(f"Directory wordlist does not exist: {wordlist}")
    if not 1 <= rate <= 100:
        raise ValueError("directory rate must be between 1 and 100 requests/second")
    if not 1 <= threads <= 50:
        raise ValueError("directory threads must be between 1 and 50")
    if not 5 <= max_time <= 600:
        raise ValueError("directory max time must be between 5 and 600 seconds")
    if not 1 <= timeout <= 30:
        raise ValueError("directory request timeout must be between 1 and 30 seconds")

    results_dir = out_dir / "ffuf-directory"
    results_dir.mkdir(parents=True, exist_ok=True)
    origins: list[str] = []
    for raw in live_urls:
        parsed = urlsplit(raw.strip())
        if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
            origin = urlunsplit((parsed.scheme.lower(), parsed.netloc, "", "", ""))
            if origin not in origins:
                origins.append(origin)

    findings: list[dict] = []
    hosts: list[dict] = []
    errors: list[str] = []
    for index, origin in enumerate(origins, 1):
        parsed = urlsplit(origin)
        host_key = f"{parsed.hostname or 'host'}-{parsed.port or 0}"
        safe_host = "".join(ch if ch.isalnum() or ch in ".-" else "_" for ch in host_key)
        suffix = hashlib.sha256(origin.encode("utf-8")).hexdigest()[:8]
        result_path = results_dir / f"{safe_host}-{suffix}.json"
        log_path = results_dir / f"{safe_host}-{suffix}.log"
        result_path.unlink(missing_ok=True)
        command = [
            "ffuf", "-w", str(wordlist), "-u", directory_fuzz_url(origin),
            "-ac", "-noninteractive", "-rate", str(rate), "-t", str(threads),
            "-maxtime", str(max_time), "-timeout", str(timeout),
            "-of", "json", "-o", str(result_path),
        ]
        print(f"[+] ffuf directory discovery {index}/{len(origins)}: {origin}")
        try:
            with log_path.open("w", encoding="utf-8", errors="replace") as log:
                log.write("COMMAND: " + " ".join(command) + "\n")
                try:
                    proc = subprocess.run(
                        command, stdout=log, stderr=subprocess.STDOUT,
                        check=False, timeout=max_time + 15,
                    )
                except subprocess.TimeoutExpired:
                    message = f"ffuf exceeded the per-origin time limit for {origin}"
                    errors.append(message)
                    hosts.append({"origin": origin, "status": "timeout", "log": str(log_path)})
                    continue
            if proc.returncode != 0:
                message = f"ffuf exited with code {proc.returncode} for {origin}"
                errors.append(message)
                hosts.append({"origin": origin, "status": "failed", "exit_code": proc.returncode, "log": str(log_path)})
                continue

            document = {}
            if result_path.is_file():
                try:
                    parsed_json = json.loads(result_path.read_text(encoding="utf-8", errors="replace"))
                    document = parsed_json if isinstance(parsed_json, dict) else {}
                except json.JSONDecodeError:
                    message = f"Invalid ffuf JSON for {origin}"
                    errors.append(message)
                    hosts.append({"origin": origin, "status": "invalid_json", "log": str(log_path)})
                    continue
            host_findings = []
            for item in document.get("results", []):
                if not isinstance(item, dict):
                    continue
                row = {
                    "origin": origin,
                    "url": item.get("url", ""),
                    "status_code": item.get("status", ""),
                    "content_length": item.get("length", ""),
                    "words": item.get("words", ""),
                    "lines": item.get("lines", ""),
                    "content_type": item.get("content-type", ""),
                    "redirect_location": item.get("redirectlocation", ""),
                }
                host_findings.append(row)
            findings.extend(host_findings)
            hosts.append({"origin": origin, "status": "completed", "findings": len(host_findings),
                          "result_file": str(result_path), "log": str(log_path)})
        except OSError as exc:
            message = f"Could not execute ffuf for {origin}: {exc}"
            errors.append(message)
            hosts.append({"origin": origin, "status": "failed", "reason": str(exc)})

    csv_path = out_dir / "ffuf-directory-findings.csv"
    fields = ["origin", "url", "status_code", "content_length", "words", "lines", "content_type", "redirect_location"]
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(findings)

    summary = {
        "status": "completed_with_errors" if errors else "completed",
        "wordlist": str(wordlist),
        "origins_total": len(origins),
        "origins_completed": sum(host.get("status") == "completed" for host in hosts),
        "findings": len(findings),
        "rate_per_second": rate,
        "threads": threads,
        "max_seconds_per_origin": max_time,
        "request_timeout_seconds": timeout,
        "csv": str(csv_path),
        "hosts": hosts,
        "errors": errors,
    }
    (out_dir / "ffuf-directory-findings.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"[+] ffuf directory discovery: {len(findings)} paths; results: {csv_path}")
    return summary
