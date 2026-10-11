#!/usr/bin/env python3
"""TriageFlow: orchestrate authorized subdomain discovery and web triage."""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import os
import shutil
import subprocess
import sys
import time
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
from triageflow_reports import (
    generate_html_report,
    read_csv_rows,
    write_asset_inventory,
    write_default_credentials_review,
)

VERSION = "2.0.0"
GO_BIN = Path.home() / "go" / "bin"
GO_INSTALLS = {
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "ffuf": "github.com/ffuf/ffuf/v2@latest",
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


def system_dns_resolvers() -> list[str]:
    """Read configured unicast DNS servers so private lab zones can be queried."""
    resolver_file = Path("/etc/resolv.conf")
    resolvers = []
    try:
        for line in resolver_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0].lower() == "nameserver":
                server = parts[1].strip()
                try:
                    ipaddress.ip_address(server)
                except ValueError:
                    continue
                if server not in resolvers:
                    resolvers.append(server)
    except OSError:
        pass
    return resolvers


def build_wordlist_candidates(root_domains: list[str], words: list[str]) -> list[str]:
    """Build valid in-scope host candidates; ignore malformed and out-of-scope full hostnames."""
    candidates: list[str] = []
    seen = set()
    for root_value in root_domains:
        root = root_value.lower().strip().rstrip(".")
        if not root:
            continue
        for word in words:
            name = word.strip().lower().rstrip(".")
            if not name or "://" in name or "/" in name or " " in name or "@" in name:
                continue
            if name == root or name.endswith("." + root):
                candidate = name
            elif "." in name:
                # A full hostname for a different domain must not escape the selected scope.
                continue
            else:
                candidate = f"{name}.{root}"
            labels = candidate.split(".")
            if any(
                not label
                or len(label) > 63
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                for label in labels
            ):
                continue
            if len(candidate) > 253 or candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
    return candidates


def discover_wordlist(
    root_domains: list[str],
    wordlist: Path,
    out_dir: Path,
    dns_resolvers: list[str] | None = None,
    dns_threads: int = 100,
    dns_timeout: int = 2,
) -> list[str]:
    """Build candidates, then resolve them in parallel with ProjectDiscovery dnsx.

    Unlike repeated socket.getaddrinfo calls, dnsx bounds DNS wait time and resolves
    many candidates concurrently. The system's resolvers are preferred for private labs.
    """
    words = read_lines(wordlist)
    candidates = build_wordlist_candidates(root_domains, words)
    candidates_path = out_dir / "wordlist-candidates.txt"
    resolved_path = out_dir / "wordlist-resolved.txt"
    log_path = out_dir / "dnsx.log"
    write_lines(candidates_path, candidates)
    write_lines(resolved_path, [])

    print(f"[+] Wordlist candidates: {len(candidates)}")
    if not candidates:
        print("[!] No valid candidates were generated; check the target and wordlist format.")
        return []

    if not dns_resolvers:
        dns_resolvers = system_dns_resolvers()
    cmd = [
        "dnsx", "-l", str(candidates_path), "-silent", "-no-color",
        "-auto-wildcard", "-timeout", str(dns_timeout), "-retry", "1",
        "-t", str(dns_threads), "-hostsfile", "-o", str(resolved_path),
    ]
    if dns_resolvers:
        cmd.extend(["-r", ",".join(dns_resolvers)])
        print("[+] DNS resolvers: " + ", ".join(dns_resolvers))
    else:
        print(
            "[WARN] No nameserver was read from /etc/resolv.conf. "
            "dnsx will use its default resolvers; for a private lab, set --dns-resolvers."
        )
    print(
        f"[+] Resolving {len(candidates)} candidates with dnsx "
        f"(threads={dns_threads}, timeout={dns_timeout}s, retries=1)."
    )
    write_lines(log_path, ["COMMAND: " + " ".join(cmd)])
    try:
        with log_path.open("a", encoding="utf-8", errors="replace") as log:
            process = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, text=True)
            started = time.monotonic()
            try:
                while True:
                    try:
                        rc = process.wait(timeout=10)
                        break
                    except subprocess.TimeoutExpired:
                        elapsed = int(time.monotonic() - started)
                        print(
                            f"[+] dnsx is still resolving candidates ({elapsed}s elapsed); "
                            f"diagnostics: {log_path}"
                        )
            except KeyboardInterrupt:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                raise
    except OSError as exc:
        raise RuntimeError(
            f"Could not start dnsx: {exc}. Check that dnsx is installed and on PATH."
        ) from exc

    if rc != 0:
        raise RuntimeError(
            f"dnsx exited with code {rc}; inspect {log_path}. "
            "Try dnsx -h to verify flags for your installed version."
        )
    resolved = read_lines(resolved_path) if resolved_path.is_file() else []
    print(f"[+] DNS-resolving candidates: {len(resolved)} / {len(candidates)}")
    print(f"[+] Candidate lists: {candidates_path} and {resolved_path}")
    return resolved




def base_url_for_root(root: str, targets: list[str]) -> str:
    """Pick the supplied HTTP URL for a root, or use plain HTTP as a fallback."""
    for target in targets:
        if hostname_of(target) != root:
            continue
        if "://" in target:
            parsed = urlparse(target)
            if parsed.scheme in ("http", "https") and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}/"
    return f"http://{root}/"


def discover_vhosts(
    base_url: str,
    root_domain: str,
    wordlist: Path,
    out_dir: Path,
    rate: int = 100,
    threads: int = 50,
    timeout: int = 3,
    max_time: int = 120,
) -> list[dict]:
    """Use ffuf Host-header discovery for virtual hosts that do not have DNS records."""
    labels = []
    seen = set()
    for hostname in build_wordlist_candidates([root_domain], read_lines(wordlist)):
        if hostname == root_domain:
            continue
        label = hostname[: -(len(root_domain) + 1)]
        if label and label not in seen:
            seen.add(label)
            labels.append(label)

    safe_root = re.sub(r"[^A-Za-z0-9.-]", "_", root_domain)
    input_path = out_dir / f"vhost-wordlist-{safe_root}.txt"
    raw_path = out_dir / f"vhost-raw-{safe_root}.json"
    log_path = out_dir / f"ffuf-vhost-{safe_root}.log"
    write_lines(input_path, labels)
    if not labels:
        return []

    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Unsupported base URL for virtual-host discovery: {base_url}")
    root_url = f"{parsed.scheme}://{parsed.netloc}/"
    cmd = [
        "ffuf", "-w", str(input_path), "-u", root_url,
        "-H", f"Host: FUZZ.{root_domain}",
        "-ac", "-noninteractive", "-of", "json", "-o", str(raw_path),
        "-t", str(threads), "-rate", str(rate), "-timeout", str(timeout),
        "-maxtime", str(max_time),
    ]
    print(
        f"[+] Virtual-host discovery: {root_domain} "
        f"({len(labels)} labels, {rate} requests/s cap, maximum {max_time}s)."
    )
    write_lines(log_path, ["COMMAND: " + " ".join(cmd)])
    try:
        with log_path.open("a", encoding="utf-8", errors="replace") as log:
            process = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, text=True)
            started = time.monotonic()
            try:
                while True:
                    try:
                        rc = process.wait(timeout=10)
                        break
                    except subprocess.TimeoutExpired:
                        elapsed = int(time.monotonic() - started)
                        print(
                            f"[+] ffuf is still checking virtual hosts ({elapsed}s elapsed); "
                            f"diagnostics: {log_path}"
                        )
            except KeyboardInterrupt:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                raise
    except OSError as exc:
        raise RuntimeError(f"Could not start ffuf: {exc}") from exc

    if rc != 0:
        raise RuntimeError(f"ffuf exited with code {rc}; inspect {log_path}")
    if not raw_path.is_file():
        return []
    try:
        document = json.loads(raw_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"ffuf output is not valid JSON; inspect {raw_path}") from exc

    valid_labels = set(labels)
    rows = []
    for item in document.get("results", []):
        input_value = item.get("input") or {}
        label = str(input_value.get("FUZZ", "")).strip().lower()
        if label not in valid_labels:
            continue
        rows.append({
            "virtual_host": f"{label}.{root_domain}",
            "root_domain": root_domain,
            "base_url": root_url,
            "status_code": item.get("status", ""),
            "content_length": item.get("length", ""),
            "words": item.get("words", ""),
            "lines": item.get("lines", ""),
            "content_type": item.get("content-type", ""),
            "redirect_location": item.get("redirectlocation", ""),
        })
    print(f"[+] Virtual-host candidates reported by ffuf: {len(rows)}")
    return rows


def write_vhost_outputs(rows: list[dict], out_dir: Path) -> None:
    fields = [
        "virtual_host", "root_domain", "base_url", "status_code",
        "content_length", "words", "lines", "content_type", "redirect_location",
    ]
    with (out_dir / "vhost-findings.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    write_lines(out_dir / "vhost-subdomains.txt", [row["virtual_host"] for row in rows])
    (out_dir / "vhost-findings.json").write_text(
        json.dumps({"count": len(rows), "results": rows}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


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
    # Always generate the manual-only default-credential checklist; this never submits credentials.
    panels = read_csv_rows(out_dir / "login-panels.csv")
    fingerprints = read_csv_rows(out_dir / "software-inventory.csv")
    reviews = write_default_credentials_review(panels, fingerprints, out_dir)
    status["default_credential_review_count"] = len(reviews)
    status["finished_utc"] = datetime.now(timezone.utc).isoformat()
    (out_dir / "summary.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
    summary = [
        "# TriageFlow run summary", "",
        f"- Started (UTC): {status.get('started_utc', 'unknown')}",
        f"- Root domains: {status.get('root_domain_count', 0)}",
        f"- Discovered subdomains: {status.get('subdomain_count', 0)}",
        f"- Combined targets: {status.get('target_count', 0)}",
        f"- Live URLs: {status.get('live_url_count', 0)}",
        f"- Asset inventory rows: {status.get('asset_count', 0)}",
        f"- Software fingerprint rows: {status.get('software_fingerprint_count', 0)}",
        f"- Default-credential review entries (manual only): {status.get('default_credential_review_count', 0)}",
        f"- Login panels found: {status.get('login_panel_count', 0)}",
        f"- Virtual hosts found: {status.get('vhost_count', 0)}",
        f"- CVE keyword candidates: {status.get('cve_candidate_count', 0)}",
        f"- Nuclei exit code: {status.get('nuclei_exit_code', 'not run')}",
        f"- GoWitness exit code: {status.get('gowitness_exit_code', 'not run')}", "",
        "## Output files", "",
        "- root-domains.txt: supplied root domains",
        "- subdomains.txt: Subfinder results, if enabled",
        "- wordlist-candidates.txt and wordlist-resolved.txt: custom wordlist results, if used",
        "- dnsx.log: bounded parallel DNS resolution for custom wordlist candidates",
        "- vhost-subdomains.txt and vhost-findings.csv/.json: virtual hosts discovered using Host headers, if enabled",
        "- all-targets.txt: deduplicated target list",
        "- live.txt: live URLs from httpx; shared by Nuclei and GoWitness",
        "- httpx-details.jsonl: JSONL response and technology fingerprints",
        "- asset-inventory.csv: deduplicated web asset inventory",
        "- software-inventory.csv: observed products and available versions",
        "- login-panels.csv: likely login endpoints found with GET-only checks",
        "- default-credentials-review.md/.csv: manual hardening checklist; no login attempts",
        "- cve-candidates.json and cve-candidates.md: NVD keyword search candidates",
        "- nuclei-findings.jsonl: Nuclei findings, if enabled",
        *(["- report.html: self-contained HTML report"] if status.get("html_report_enabled", True) else []),
        "- gowitness/: screenshots of live URLs including discovered live subdomains, if enabled",
        "- *.log: command output and troubleshooting details", "",
        "Only assess targets within your written authorization and scope.", ""
    ]
    (out_dir / "README.md").write_text("\n".join(summary), encoding="utf-8")
    if status.get("html_report_enabled", True):
        try:
            report_path = generate_html_report(out_dir, status)
            print(f"[+] HTML report: {report_path}")
        except OSError as exc:
            status["html_report_error"] = str(exc)
            (out_dir / "summary.json").write_text(
                json.dumps(status, indent=2), encoding="utf-8"
            )
            print(f"[!] Could not create HTML report: {exc}")


def prompt_choice(prompt: str, choices: dict[str, str], default: str) -> str:
    """Ask a validated menu question; return the default when the user presses Enter."""
    options = " / ".join(f"{key}={label}" for key, label in choices.items())
    while True:
        answer = input(f"{prompt} ({options}) [default {default}]: ").strip().lower()
        answer = answer or default
        if answer in choices:
            return answer
        print("Please choose one of: " + ", ".join(choices))


def interactive_setup(args: argparse.Namespace) -> bool:
    """Collect the minimum needed to run TriageFlow without memorizing CLI flags."""
    print("\n" + "=" * 58)
    print(" TriageFlow | Guided setup")
    print("=" * 58)
    print("Use this only for systems you own or are explicitly authorized to test.")
    print("Press Ctrl+C at any prompt to cancel.\n")

    target_mode = prompt_choice(
        "What do you want to scan?",
        {"1": "one domain/URL/IP", "2": "a file of targets", "q": "quit"},
        "1",
    )
    if target_mode == "q":
        print("Cancelled.")
        return False

    if target_mode == "1":
        value = input("Target domain, URL, or IP (example: example.com): ").strip()
        if not value:
            print("No target entered; cancelled.")
            return False
        args.single_target = value
        args.list = None
    else:
        value = input("Path to target file (one target per line): ").strip()
        if not value:
            print("No file path entered; cancelled.")
            return False
        args.list = value
        args.single_target = None

    if not args.wordlist:
        bundled_wordlist = Path(__file__).resolve().parent / "wordlists" / "subdomains-small.txt"
        wordlist_mode = prompt_choice(
            "Subdomain wordlist?",
            {"1": "use included small wordlist", "2": "use my own wordlist", "3": "none"},
            "1",
        )
        if wordlist_mode == "1":
            if bundled_wordlist.is_file():
                args.wordlist = str(bundled_wordlist)
                print(f"Using included wordlist: {bundled_wordlist}")
            else:
                print("Included wordlist not found; wordlist discovery will be skipped.")
        elif wordlist_mode == "2":
            custom_path = input("Path to your wordlist (one label per line): ").strip()
            if custom_path:
                args.wordlist = custom_path
            else:
                print("No path entered; wordlist discovery will be skipped.")

    profile = prompt_choice(
        "Choose a scan profile",
        {
            "1": "standard (recommended: all enabled stages)",
            "2": "quick (skip Subfinder, Nuclei, screenshots)",
        },
        "1",
    )
    if profile == "2":
        args.no_subdomains = True
        args.no_nuclei = True
        args.no_screenshots = True
        print("Quick profile selected. httpx, software inventory, CVE lookup, and login discovery stay enabled.")

    screenshot_default = "1" if profile == "1" else "2"
    screenshot_choice = prompt_choice(
        "Capture screenshots of responding subdomains and web pages?",
        {"1": "yes, use GoWitness screenshots", "2": "no, skip screenshots"},
        screenshot_default,
    )
    args.no_screenshots = screenshot_choice == "2"

    html_choice = prompt_choice(
        "Generate a single-page HTML report?",
        {"1": "yes, recommended", "2": "no, only CSV/JSON/Markdown"},
        "1",
    )
    args.no_html_report = html_choice == "2"

    print("\nSetup complete. TriageFlow will check its tools next.")
    print("Before any scan starts, you must still confirm authorization by typing YES.\n")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Beginner-friendly authorized web reconnaissance. Run without arguments for a guided setup.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=(
            "Easy start: python3 triageflow.py\n"
            "Direct start: python3 triageflow.py -u example.com -w wordlists/subdomains-small.txt\n"
            "Read the Greek guide: QUICKSTART_EL.md"
        ),
    )
    inputs = parser.add_mutually_exclusive_group(required=False)
    inputs.add_argument("-l", "--list", help="Input file: one domain, host, IP, or URL per line")
    inputs.add_argument("-u", "--url", dest="single_target", help="One domain, host, IP, or URL")
    parser.add_argument("-w", "--wordlist", help="Custom subdomain wordlist, one entry per line")
    parser.add_argument("-o", "--output", default="triageflow-results", help="Output base directory")
    parser.add_argument("--severity", default="medium,high,critical", help="Nuclei severities")
    parser.add_argument("--no-subdomains", action="store_true", help="Skip Subfinder")
    parser.add_argument("--subfinder-all", action="store_true", help="Use all configured Subfinder sources")
    parser.add_argument("--timeout", type=int, default=10, help="httpx timeout in seconds")
    parser.add_argument("--dns-threads", type=int, default=100,
                        help="Parallel dnsx threads for the custom wordlist (default: 100)")
    parser.add_argument("--dns-timeout", type=int, default=2,
                        help="Per-query dnsx timeout in seconds (default: 2)")
    parser.add_argument("--dns-resolvers",
                        help="Comma-separated DNS resolver IPs; default reads /etc/resolv.conf")
    parser.add_argument("--vhost-fuzz", action="store_true",
                        help="Also enumerate HTTP virtual hosts using the wordlist and Host header")
    parser.add_argument("--vhost-rate", type=int, default=100,
                        help="Maximum ffuf virtual-host requests per second (default: 100)")
    parser.add_argument("--vhost-max-time", type=int, default=120,
                        help="Maximum seconds per root domain for virtual-host discovery (default: 120)")
    parser.add_argument("--no-nuclei", action="store_true", help="Skip Nuclei")
    parser.add_argument("--no-screenshots", action="store_true", help="Skip GoWitness")
    parser.add_argument("--no-login-check", action="store_true",
                        help="Skip bounded GET-only login-panel discovery")
    parser.add_argument("--max-login-hosts", type=int, default=25,
                        help="Maximum distinct live origins checked for login panels")
    parser.add_argument("--no-cve-lookup", action="store_true",
                        help="Skip NVD lookups for observed product/version candidates")
    parser.add_argument("--max-cve-products", type=int, default=5,
                        help="Maximum distinct product/version pairs queried in NVD")
    parser.add_argument("--wizard", action="store_true",
                        help="Open the guided setup wizard")
    parser.add_argument("--no-html-report", action="store_true",
                        help="Skip the self-contained HTML report")
    parser.add_argument("--version", action="version", version=f"TriageFlow {VERSION}")
    args = parser.parse_args()

    if args.wizard and (args.list or args.single_target):
        parser.error("--wizard cannot be combined with --url or --list")
    if args.wizard or (not args.list and not args.single_target):
        try:
            if not interactive_setup(args):
                return 1
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            return 1

    if args.timeout < 1:
        parser.error("--timeout must be at least 1")
    if args.dns_threads < 1:
        parser.error("--dns-threads must be at least 1")
    if args.dns_timeout < 1:
        parser.error("--dns-timeout must be at least 1")
    if args.vhost_rate < 1:
        parser.error("--vhost-rate must be at least 1")
    if args.vhost_max_time < 1:
        parser.error("--vhost-max-time must be at least 1")
    if args.vhost_fuzz and not args.wordlist:
        parser.error("--vhost-fuzz requires --wordlist")
    if args.dns_resolvers:
        resolver_values = [value.strip() for value in args.dns_resolvers.split(",") if value.strip()]
        if not resolver_values:
            parser.error("--dns-resolvers must contain at least one IP address")
        for resolver in resolver_values:
            try:
                ipaddress.ip_address(resolver)
            except ValueError:
                parser.error(f"Invalid DNS resolver IP: {resolver}")

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
    if wordlist and roots:
        required.append("dnsx")
    if args.vhost_fuzz:
        required.append("ffuf")
    missing = ensure_tools(required)
    if missing:
        print("[ERROR] Required tools unavailable; no scan started: " + ", ".join(missing))
        return 2

    if not args.no_screenshots and not any(
        shutil.which(browser) for browser in (
            "chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"
        )
    ):
        print(
            "[WARN] Screenshots are enabled, but Chrome/Chromium was not found in PATH. "
            "GoWitness may fail; install a supported browser or rerun with --no-screenshots."
        )

    print(f"TriageFlow v{VERSION} — authorized testing only")
    print(f"Input targets: {len(targets)}; root domains: {len(roots)}")
    print("All live URLs reported by httpx will be passed to enabled downstream stages.")
    if input("Confirm targets are yours or explicitly in scope (type YES): ").strip() != "YES":
        print("Cancelled; no scans started.")
        return 1

    out_dir = Path(args.output).expanduser().resolve() / datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=False)
    status = {
        "version": VERSION,
        "html_report_enabled": not args.no_html_report,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_path) if input_path else None,
        "single_target": args.single_target if args.single_target else None,
        "root_domain_count": len(roots), "subdomain_count": 0,
        "target_count": 0, "live_url_count": 0, "asset_count": 0,
        "software_fingerprint_count": 0, "login_panel_count": 0,
        "default_credential_review_count": 0, "cve_candidate_count": 0, "stages": {}
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
        if args.dns_resolvers:
            resolvers = [value.strip() for value in args.dns_resolvers.split(",") if value.strip()]
        else:
            resolvers = system_dns_resolvers()
        try:
            wordlist_names = discover_wordlist(
                roots, wordlist, out_dir,
                dns_resolvers=resolvers,
                dns_threads=args.dns_threads,
                dns_timeout=args.dns_timeout,
            )
            status["stages"]["wordlist_dns"] = {
                "status": "completed",
                "candidates": len(read_lines(out_dir / "wordlist-candidates.txt")),
                "resolved": len(wordlist_names),
                "threads": args.dns_threads,
                "timeout_seconds": args.dns_timeout,
                "resolvers": resolvers or "dnsx defaults",
            }
        except KeyboardInterrupt:
            status["stages"]["wordlist_dns"] = "interrupted by user"
            print("\n[!] Wordlist DNS check interrupted. Saving partial results...")
            save_report(out_dir, status)
            return 130
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"[ERROR] Wordlist DNS resolution failed: {exc}", file=sys.stderr)
            status["stages"]["wordlist_dns"] = {"status": "failed", "error": str(exc)}
            save_report(out_dir, status)
            return 2

    vhost_rows: list[dict] = []
    vhost_hosts: list[str] = []
    should_run_vhost = bool(args.vhost_fuzz)
    if wordlist and roots and not args.vhost_fuzz and not wordlist_names and not discovered:
        print(
            "\n[!] No subdomains from the wordlist resolved through DNS. "
            "For lab domains, the web server may use virtual hosts that have no DNS records."
        )
        print("    Virtual-host discovery sends HTTP requests with different Host headers.")
        try:
            answer = input("Try virtual-host discovery with ffuf? Type YES to run it: ").strip()
        except EOFError:
            answer = ""
        should_run_vhost = answer == "YES"

    if should_run_vhost:
        missing_ffuf = [] if shutil.which("ffuf") else ensure_tools(["ffuf"])
        if missing_ffuf:
            message = "ffuf is unavailable; virtual-host discovery was skipped."
            print("[WARN] " + message)
            status["stages"]["vhost_fuzz"] = {"status": "skipped", "reason": message}
        else:
            try:
                for root in roots:
                    base_url = base_url_for_root(root, targets)
                    vhost_rows.extend(
                        discover_vhosts(
                            base_url, root, wordlist, out_dir,
                            rate=args.vhost_rate,
                            timeout=min(max(args.timeout, 1), 5),
                            max_time=args.vhost_max_time,
                        )
                    )
                write_vhost_outputs(vhost_rows, out_dir)
                vhost_hosts = [row["virtual_host"] for row in vhost_rows]
                status["vhost_count"] = len(vhost_rows)
                status["stages"]["vhost_fuzz"] = {
                    "status": "completed",
                    "found": len(vhost_rows),
                    "rate_limit": args.vhost_rate,
                    "max_time_per_root_seconds": args.vhost_max_time,
                }
            except KeyboardInterrupt:
                status["stages"]["vhost_fuzz"] = "interrupted by user"
                if vhost_rows:
                    write_vhost_outputs(vhost_rows, out_dir)
                    status["vhost_count"] = len(vhost_rows)
                    vhost_hosts = [row["virtual_host"] for row in vhost_rows]
                print("\n[!] Virtual-host discovery interrupted. Saving partial results...")
                save_report(out_dir, status)
                return 130
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
                print(f"[WARN] Virtual-host discovery failed: {exc}", file=sys.stderr)
                status["stages"]["vhost_fuzz"] = {"status": "failed", "error": str(exc)}
                if vhost_rows:
                    write_vhost_outputs(vhost_rows, out_dir)
                    status["vhost_count"] = len(vhost_rows)
                    vhost_hosts = [row["virtual_host"] for row in vhost_rows]
    elif wordlist and roots:
        status["stages"]["vhost_fuzz"] = "not run (DNS or Subfinder already found subdomains)"

    combined = list(dict.fromkeys(direct + roots + discovered + wordlist_names))
    combined_file, live_file = out_dir / "all-targets.txt", out_dir / "live.txt"
    write_lines(combined_file, combined)
    status["subdomain_count"] = len(set(discovered + wordlist_names + vhost_hosts))
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
    assets = write_asset_inventory(httpx_records, out_dir / "asset-inventory.csv")
    fingerprints = write_software_inventory(httpx_records, out_dir / "software-inventory.csv")
    status["live_url_count"] = len(live)
    status["asset_count"] = len(assets)
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
                max_hosts=args.max_login_hosts, timeout=min(float(args.timeout), 2.5),
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
    if wordlist:
        print(f"    Wordlist DNS results: {out_dir / 'wordlist-resolved.txt'}")
        print(f"    DNS log: {out_dir / 'dnsx.log'}")
    if status.get("vhost_count", 0) or status.get("stages", {}).get("vhost_fuzz"):
        print(f"    VHost findings: {out_dir / 'vhost-findings.csv'}")
    print(f"    Summary: {out_dir / 'README.md'}")
    print(f"    JSON report: {out_dir / 'summary.json'}")
    if status.get("html_report_enabled", True):
        print(f"    HTML report: {out_dir / 'report.html'}")
    print(f"    Asset inventory: {out_dir / 'asset-inventory.csv'}")
    print(f"    Default-credential review: {out_dir / 'default-credentials-review.md'}")
    if failures:
        print("[!] Failed stage(s): " + ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user (Ctrl+C). Partial output files, if already written, have been retained.")
        raise SystemExit(130)
