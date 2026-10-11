#!/usr/bin/env python3
"""TriageFlow: orchestrate authorized subdomain discovery and web triage."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from triageflow_enrichment import (
    detect_login_panels,
    httpx_url,
    query_nvd_cves,
    read_httpx_jsonl,
    write_software_inventory,
)

GO_BIN = Path.home() / "go" / "bin"
GO_INSTALLS = {
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "gowitness": "github.com/sensepost/gowitness@latest",
}


def ensure_tools(required: list[str]) -> list[str]:
    """Locate required binaries and try installing missing Go tools."""
    GO_BIN.mkdir(parents=True, exist_ok=True)
    os.environ["PATH"] = str(GO_BIN) + os.pathsep + os.environ.get("PATH", "")
    missing = [name for name in required if shutil.which(name) is None]
    if not missing:
        return []

    go = shutil.which("go")
    if not go:
        print("[ERROR] Missing tools: " + ", ".join(missing))
        print("[ERROR] Go is unavailable; install Go and retry.")
        return missing

    for name in missing:
        install_path = GO_INSTALLS.get(name)
        if not install_path:
            continue
        print(f"[+] Attempting to install {name} with Go...")
        result = subprocess.run([go, "install", install_path], check=False)
        if result.returncode:
            print(f"[ERROR] Installation failed for {name}; try: go install {install_path}")

    return [name for name in required if shutil.which(name) is None]


def read_lines(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(path)
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def write_lines(path: Path, values: list[str]) -> None:
    path.write_text("".join(f"{item}\n" for item in dict.fromkeys(values)), encoding="utf-8")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def normalize_target(raw: str) -> str:
    value = raw.strip()
    if "://" in value:
        parsed = urlparse(value)
        if not parsed.hostname:
            raise ValueError(f"Invalid URL: {raw}")
        return value.rstrip("/")
    return value.rstrip("/")


def hostname_of(target: str) -> str:
    if "://" in target:
        return (urlparse(target).hostname or "").lower().rstrip(".")
    return target.split(":", 1)[0].strip("[]").lower().rstrip(".")


def discover_wordlist(root_domains: list[str], wordlist: Path, out_dir: Path) -> list[str]:
    """Create subdomain candidates and retain names that resolve with system DNS."""
    words = read_lines(wordlist)
    candidates: list[str] = []
    for root in root_domains:
        for word in words:
            name = word.lower().rstrip(".")
            if "://" in name or "/" in name or " " in name:
                continue
            if name == root or name.endswith("." + root):
                candidate = name
            else:
                candidate = f"{name}.{root}"
            if candidate not in candidates:
                candidates.append(candidate)

    resolved: list[str] = []
    for name in candidates:
        try:
            socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
            resolved.append(name)
        except OSError:
            pass

    write_lines(out_dir / "wordlist-candidates.txt", candidates)
    write_lines(out_dir / "wordlist-resolved.txt", resolved)
    print(f"[+] Wordlist candidates: {len(candidates)}; DNS-resolving: {len(resolved)}")
    return resolved


def run_step(name: str, command: list[str], log_path: Path) -> int:
    """Run one external tool and preserve stdout/stderr in a log."""
    print(f"\n[+] {name}\n    $ {' '.join(command)}")
    try:
        with log_path.open("w", encoding="utf-8", errors="replace") as log:
            log.write("COMMAND: " + " ".join(command) + "\n\n")
            result = subprocess.run(
                command, stdout=log, stderr=subprocess.STDOUT, text=True, check=False
            )
    except OSError as exc:
        log_path.write_text(f"Could not execute command: {exc}\n", encoding="utf-8")
        print(f"[ERROR] Could not execute {command[0]}: {exc}")
        return 127

    if result.returncode == 0:
        print(f"[OK] {name} completed; log: {log_path}")
    else:
        print(f"[!] {name} returned {result.returncode}; inspect {log_path}")
    return result.returncode


def save_report(out_dir: Path, status: dict) -> None:
    status["finished_utc"] = datetime.now(timezone.utc).isoformat()
    (out_dir / "summary.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
    summary = [
        "# TriageFlow run summary", "",
        f"- Started (UTC): {status.get('started_utc', 'unknown')}",
        f"- Root domains: {status.get('root_domain_count', 0)}",
        f"- Discovered subdomains: {status.get('subdomain_count', 0)}",
        f"- Combined targets: {status.get('target_count', 0)}",
        f"- Live URLs: {status.get('live_url_count', 0)}",
        f"- Nuclei exit code: {status.get('nuclei_exit_code', 'not run')}",
        f"- GoWitness exit code: {status.get('gowitness_exit_code', 'not run')}", "",
        "## Output files", "",
        "- root-domains.txt: supplied root domains",
        "- subdomains.txt: Subfinder results, if enabled",
        "- wordlist-candidates.txt and wordlist-resolved.txt: custom wordlist results, if used",
        "- all-targets.txt: deduplicated target list",
        "- live.txt: live URLs from httpx; shared by Nuclei and GoWitness",
        "- nuclei-findings.jsonl: Nuclei findings, if enabled",
        "- gowitness/: screenshot artifacts, if enabled",
        "- *.log: command output and troubleshooting details", "",
        "Only assess targets within your written authorization and scope.", ""
    ]
    (out_dir / "README.md").write_text("\n".join(summary), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Authorized workflow: Subfinder + wordlist -> httpx -> Nuclei + GoWitness"
    )
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("-l", "--list", help="Input file: one domain, host, IP, or URL per line")
    inputs.add_argument("-u", "--url", dest="single_target", help="One domain, host, IP, or URL")
    parser.add_argument("-w", "--wordlist", help="Custom subdomain wordlist, one entry per line")
    parser.add_argument("-o", "--output", default="triageflow-results", help="Output base directory")
    parser.add_argument("--severity", default="medium,high,critical", help="Nuclei severities")
    parser.add_argument("--no-subdomains", action="store_true", help="Skip Subfinder")
    parser.add_argument("--subfinder-all", action="store_true", help="Use all configured Subfinder sources")
    parser.add_argument("--timeout", type=int, default=10, help="httpx timeout in seconds")
    parser.add_argument("--no-nuclei", action="store_true", help="Skip Nuclei")
    parser.add_argument("--no-screenshots", action="store_true", help="Skip GoWitness")
    parser.add_argument("--no-login-check", action="store_true",
                        help="Skip bounded GET-only login-panel discovery")
    parser.add_argument("--max-login-hosts", type=int, default=50,
                        help="Maximum distinct live origins checked for login panels (default: 50)")
    parser.add_argument("--no-cve-lookup", action="store_true",
                        help="Skip NVD lookups for observed product/version candidates")
    parser.add_argument("--max-cve-products", type=int, default=5,
                        help="Maximum distinct product/version pairs queried in NVD (default: 5)")
    args = parser.parse_args()

    if args.timeout < 1:
        parser.error("--timeout must be at least 1")
    if args.max_login_hosts < 1:
        parser.error("--max-login-hosts must be at least 1")
    if args.max_cve_products < 1:
        parser.error("--max-cve-products must be at least 1")

    try:
        input_path = Path(args.list).expanduser().resolve() if args.list else None
        raw = read_lines(input_path) if input_path else [args.single_target]
        targets = list(dict.fromkeys(normalize_target(x) for x in raw))
    except (OSError, ValueError) as exc:
        print(f"[ERROR] Invalid or unreadable input: {exc}", file=sys.stderr)
        return 2
    if not targets:
        print("[ERROR] No targets supplied.", file=sys.stderr)
        return 2

    roots, direct = [], []
    for target in targets:
        host = hostname_of(target)
        if host and not is_ip(host) and "." in host:
            roots.append(host)
        if "://" in target or is_ip(host) or "." not in host:
            direct.append(target)
    roots = list(dict.fromkeys(roots))

    wordlist = Path(args.wordlist).expanduser().resolve() if args.wordlist else None
    if wordlist and not wordlist.is_file():
        print(f"[ERROR] Wordlist does not exist: {wordlist}", file=sys.stderr)
        return 2

    required = ["httpx"]
    if not args.no_nuclei:
        required.append("nuclei")
    if not args.no_screenshots:
        required.append("gowitness")
    if not args.no_subdomains and roots:
        required.append("subfinder")
    missing = ensure_tools(required)
    if missing:
        print("[ERROR] Required tools unavailable; no scan started: " + ", ".join(missing))
        return 2

    print("TriageFlow — authorized testing only")
    print(f"Input targets: {len(targets)}; root domains: {len(roots)}")
    print("All live URLs reported by httpx will be passed to enabled downstream stages.")
    if input("Confirm targets are yours or explicitly in scope (type YES): ").strip() != "YES":
        print("Cancelled; no scans started.")
        return 1

    out_dir = Path(args.output).expanduser().resolve() / datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=False)
    status = {
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_path) if input_path else None,
        "single_target": args.single_target if args.single_target else None,
        "root_domain_count": len(roots), "subdomain_count": 0,
        "target_count": 0, "live_url_count": 0, "software_fingerprint_count": 0,
        "login_panel_count": 0, "cve_candidate_count": 0, "stages": {}
    }

    discovered: list[str] = []
    if not args.no_subdomains and roots:
        roots_file, sub_file = out_dir / "root-domains.txt", out_dir / "subdomains.txt"
        write_lines(roots_file, roots)
        cmd = ["subfinder", "-dL", str(roots_file), "-silent", "-o", str(sub_file)]
        if args.subfinder_all:
            cmd.insert(1, "-all")
        rc = run_step("Subfinder: passive subdomain discovery", cmd, out_dir / "subfinder.log")
        status["stages"]["subfinder"] = rc
        if rc:
            save_report(out_dir, status)
            return rc
        if sub_file.exists():
            discovered = read_lines(sub_file)

    wordlist_names: list[str] = []
    if wordlist and roots:
        try:
            wordlist_names = discover_wordlist(roots, wordlist, out_dir)
        except OSError as exc:
            print(f"[ERROR] Cannot read wordlist: {exc}", file=sys.stderr)
            save_report(out_dir, status)
            return 2

    combined = list(dict.fromkeys(direct + roots + discovered + wordlist_names))
    combined_file, live_file = out_dir / "all-targets.txt", out_dir / "live.txt"
    write_lines(combined_file, combined)
    status["subdomain_count"] = len(set(discovered + wordlist_names))
    status["target_count"] = len(combined)

    details_file = out_dir / "httpx-details.jsonl"
    rc = run_step("httpx: identify live services and fingerprint technologies",
                  ["httpx", "-l", str(combined_file), "-silent", "-no-color",
                   "-timeout", str(args.timeout), "-td", "-server", "-title",
                   "-status-code", "-json", "-o", str(details_file)], out_dir / "httpx.log")
    status["stages"]["httpx"] = rc
    if rc:
        save_report(out_dir, status)
        return rc

    httpx_records = read_httpx_jsonl(details_file)
    live = list(dict.fromkeys(
        httpx_url(record) for record in httpx_records if httpx_url(record)
    ))
    write_lines(live_file, live)
    fingerprints = write_software_inventory(httpx_records, out_dir / "software-inventory.csv")
    status["live_url_count"] = len(live)
    status["software_fingerprint_count"] = len(fingerprints)
    if not live:
        print("[!] No live web URLs found or httpx JSON output could not be parsed; downstream stages skipped.")
        status["stages"]["login_panels"] = "skipped: no live URLs"
        status["stages"]["cve_lookup"] = "skipped: no live URLs"
        save_report(out_dir, status)
        return 0

    failures = []
    if args.no_login_check:
        status["stages"]["login_panels"] = "skipped"
    else:
        try:
            panels = detect_login_panels(
                live, out_dir / "login-panels.csv",
                max_hosts=args.max_login_hosts, timeout=min(float(args.timeout), 5.0),
            )
            status["login_panel_count"] = len(panels)
            status["stages"]["login_panels"] = {"status": "completed", "found": len(panels)}
        except Exception as exc:
            status["stages"]["login_panels"] = {"status": "failed", "error": str(exc)}
            print(f"[!] Login-panel discovery failed: {exc}")
            failures.append("login-panel discovery")

    if args.no_cve_lookup:
        status["stages"]["cve_lookup"] = "skipped"
    else:
        try:
            cve_summary = query_nvd_cves(
                fingerprints, out_dir / "cve-candidates.json",
                max_products=args.max_cve_products,
            )
            status["cve_candidate_count"] = cve_summary.get("cve_candidates", 0)
            status["stages"]["cve_lookup"] = {"status": "completed", **cve_summary}
        except Exception as exc:
            status["stages"]["cve_lookup"] = {"status": "failed", "error": str(exc)}
            print(f"[!] NVD CVE lookup failed: {exc}")
            failures.append("CVE lookup")
    if args.no_nuclei:
        status["stages"]["nuclei"] = "skipped"
    else:
        findings = out_dir / "nuclei-findings.jsonl"
        rc = run_step("Nuclei: template-based security checks",
                      ["nuclei", "-l", str(live_file), "-severity", args.severity,
                       "-jsonl", "-no-color", "-o", str(findings)], out_dir / "nuclei.log")
        status["stages"]["nuclei"] = rc
        status["nuclei_exit_code"] = rc
        if rc:
            failures.append("nuclei")

    if args.no_screenshots:
        status["stages"]["gowitness"] = "skipped"
    else:
        shot_dir = out_dir / "gowitness"
        shot_dir.mkdir()
        rc = run_step("GoWitness: screenshot live web services",
                      ["gowitness", "scan", "file", "-f", str(live_file),
                       "--write-db", "--screenshot-path", str(shot_dir)],
                      out_dir / "gowitness.log")
        status["stages"]["gowitness"] = rc
        status["gowitness_exit_code"] = rc
        if rc:
            failures.append("gowitness")

    save_report(out_dir, status)
    print("\n[+] Pipeline finished")
    print(f"    Results directory: {out_dir}")
    print(f"    Combined targets: {combined_file}")
    print(f"    Live URLs: {live_file}")
    print(f"    Summary: {out_dir / 'README.md'}")
    print(f"    JSON report: {out_dir / 'summary.json'}")
    if failures:
        print("[!] Failed stage(s): " + ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
