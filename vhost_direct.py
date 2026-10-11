#!/usr/bin/env python3
"""Direct HTTP virtual-host discovery for authorized labs.

This entry point sends requests to the supplied base URL with a changing Host
header. It does not resolve each candidate through dnsx first.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


def load_labels(path: Path, root_domain: str) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    labels: list[str] = []
    seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        value = raw.strip().lower().rstrip(".")
        if not value or value.startswith("#"):
            continue
        # This utility expects labels, not full hostnames, to avoid leaving scope.
        if not LABEL_RE.fullmatch(value) or value == root_domain.lower():
            continue
        if value not in seen:
            labels.append(value)
            seen.add(value)
    return labels


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Direct HTTP Host-header virtual-host discovery for authorized targets."
    )
    parser.add_argument("-u", "--url", required=True, help="Base URL reachable from this machine, e.g. http://inlanefreight.local/")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist containing one hostname label per line")
    parser.add_argument("-o", "--output", default="triageflow-results", help="Output base directory")
    parser.add_argument("--rate", type=int, default=100, help="Maximum requests per second")
    parser.add_argument("--max-time", type=int, default=120, help="Maximum run time in seconds")
    parser.add_argument("--timeout", type=int, default=3, help="Per-request timeout in seconds")
    args = parser.parse_args()

    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or not parsed.netloc:
        parser.error("--url must be a valid http:// or https:// URL")
    if args.rate < 1 or args.max_time < 1 or args.timeout < 1:
        parser.error("--rate, --max-time, and --timeout must be positive integers")
    if shutil.which("ffuf") is None:
        print("[ERROR] ffuf was not found on PATH. Install ffuf and retry.", file=sys.stderr)
        return 2

    root = parsed.hostname.lower().rstrip(".")
    try:
        labels = load_labels(Path(args.wordlist).expanduser(), root)
    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    if not labels:
        print("[ERROR] No valid single-label entries found in the wordlist.", file=sys.stderr)
        return 2

    print("Direct VHost mode: candidates go straight to ffuf as HTTP Host headers; dnsx is not used.")
    print(f"Target URL: {args.url}")
    print(f"Root domain: {root}")
    print(f"Wordlist labels: {len(labels)}")
    if input("Confirm this target is yours or explicitly in scope (type YES): ").strip() != "YES":
        print("Cancelled; no requests sent.")
        return 1

    out_dir = Path(args.output).expanduser().resolve() / datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=False)
    label_file = out_dir / "vhost-wordlist.txt"
    raw_file = out_dir / "vhost-raw.json"
    log_file = out_dir / "ffuf-vhost.log"
    write_text(label_file, "".join(f"{label}\n" for label in labels))

    base_url = f"{parsed.scheme}://{parsed.netloc}/"
    cmd = [
        "ffuf", "-w", str(label_file), "-u", base_url,
        "-H", f"Host: FUZZ.{root}",
        "-ac", "-noninteractive", "-of", "json", "-o", str(raw_file),
        "-t", "50", "-rate", str(args.rate), "-timeout", str(args.timeout),
        "-maxtime", str(args.max_time),
    ]
    with log_file.open("w", encoding="utf-8", errors="replace") as log:
        log.write("COMMAND: " + " ".join(cmd) + "\n\n")
        try:
            result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, check=False)
        except OSError as exc:
            print(f"[ERROR] Could not run ffuf: {exc}", file=sys.stderr)
            return 2
    if result.returncode != 0:
        print(f"[ERROR] ffuf exited with code {result.returncode}; see {log_file}", file=sys.stderr)
        return result.returncode

    try:
        document = json.loads(raw_file.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[ERROR] Could not parse ffuf results: {exc}", file=sys.stderr)
        return 2

    fields = ["virtual_host", "base_url", "status_code", "content_length", "words", "lines", "content_type", "redirect_location"]
    rows = []
    valid_labels = set(labels)
    for item in document.get("results", []):
        value = str((item.get("input") or {}).get("FUZZ", "")).strip().lower()
        if value not in valid_labels:
            continue
        rows.append({
            "virtual_host": f"{value}.{root}",
            "base_url": base_url,
            "status_code": item.get("status", ""),
            "content_length": item.get("length", ""),
            "words": item.get("words", ""),
            "lines": item.get("lines", ""),
            "content_type": item.get("content-type", ""),
            "redirect_location": item.get("redirectlocation", ""),
        })

    with (out_dir / "vhost-findings.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    write_text(out_dir / "vhost-subdomains.txt", "".join(f"{row['virtual_host']}\n" for row in rows))
    (out_dir / "vhost-findings.json").write_text(
        json.dumps({"count": len(rows), "results": rows}, indent=2), encoding="utf-8"
    )
    print(f"[+] Candidate results: {len(rows)}")
    print(f"[+] Results directory: {out_dir}")
    print(f"[+] CSV: {out_dir / 'vhost-findings.csv'}")
    print(f"[+] Hostnames: {out_dir / 'vhost-subdomains.txt'}")
    print(f"[+] ffuf log: {log_file}")
    return 0


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Partial ffuf output, if present, is retained.")
        raise SystemExit(130)
