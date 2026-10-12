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

VERSION = "2.0.9"
GO_BIN = Path.home() / "go" / "bin"
GO_INSTALLS = {
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "ffuf": "github.com/ffuf/ffuf/v2@latest",
    "gowitness": "github.com/sensepost/gowitness@latest",
}


def add_go_bin_paths(go: str) -> None:
    """Expose the Go tool binary directories, including custom GOBIN/GOPATH values."""
    candidates = [GO_BIN]
    try:
        result = subprocess.run(
            [go, "env", "GOBIN", "GOPATH"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if result.returncode == 0:
            values = result.stdout.splitlines()
            gobin = values[0].strip() if values else ""
            gopath = values[1].strip() if len(values) > 1 else ""
            if gobin:
                candidates.append(Path(gobin).expanduser())
            for entry in gopath.split(os.pathsep):
                if entry.strip():
                    candidates.append(Path(entry.strip()).expanduser() / "bin")
    except (OSError, subprocess.SubprocessError):
        # The default ~/go/bin path remains available even if "go env" fails.
        pass

    existing_path = os.environ.get("PATH", "").split(os.pathsep)
    entries = [str(path) for path in candidates if str(path)]
    os.environ["PATH"] = os.pathsep.join(dict.fromkeys(entries + existing_path))


def ensure_tools(required: list[str]) -> list[str]:
    """Find required binaries first; install only tools that are genuinely missing."""
    GO_BIN.mkdir(parents=True, exist_ok=True)
    os.environ["PATH"] = str(GO_BIN) + os.pathsep + os.environ.get("PATH", "")
    missing = [name for name in required if shutil.which(name) is None]
    if not missing:
        print("[OK] Required tools are already available; skipping downloads.")
        return []

    go = shutil.which("go")
    if not go:
        print("[ERROR] Missing tools: " + ", ".join(missing))
        print("[ERROR] Go is unavailable; install Go and retry.")
        return missing

    # Go can install binaries outside ~/go/bin when GOBIN or GOPATH is customized.
    # Search those locations before deciding that a download/install is necessary.
    add_go_bin_paths(go)
    missing = [name for name in required if shutil.which(name) is None]
    if not missing:
        print("[OK] Required tools were found in configured Go bin directories; skipping downloads.")
        return []

    for name in missing:
        install_path = GO_INSTALLS.get(name)
        if not install_path:
            continue
        print(f"[+] Installing missing tool {name} with Go...")
        result = subprocess.run([go, "install", install_path], check=False)
        if result.returncode:
            print(f"[ERROR] Installation failed for {name}; try: go install {install_path}")

    return [name for name in required if shutil.which(name) is None]


def bundled_wordlist_path() -> Path:
    """Return the repository's built-in starter wordlist."""
    return Path(__file__).resolve().parent / "wordlists" / "subdomains-small.txt"


def discover_default_wordlist(candidates: list[Path] | None = None) -> Path | None:
    """Prefer an existing local SecLists DNS wordlist, then fall back to the bundled list."""
    if candidates is None:
        home = Path.home()
        seclists_name = Path("Discovery") / "DNS" / "subdomains-top1million-5000.txt"
        candidates = [
            Path("/usr/share/seclists") / seclists_name,
            home / "SecLists" / seclists_name,
            home / "seclists" / seclists_name,
            Path("/usr/share/SecLists") / seclists_name,
            bundled_wordlist_path(),
        ]
    return next((path.expanduser() for path in candidates if path.is_file()), None)


def combine_targets(
    direct: list[str],
    roots: list[str],
    wordlist_names: list[str],
    passive_names: list[str],
) -> list[str]:
    """Deduplicate targets while prioritizing wordlist discoveries before passive results."""
    return list(dict.fromkeys([*direct, *roots, *wordlist_names, *passive_names]))


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


def create_run_output_dir(output_base: str | Path, now: datetime | None = None) -> Path:
    """Create a unique timestamped run directory, even for runs started in one second."""
    base = Path(output_base).expanduser().resolve()
    timestamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S-%f")
    candidate = base / timestamp
    suffix = 1
    while True:
        try:
            candidate.mkdir(parents=True, exist_ok=False)
            return candidate
        except FileExistsError:
            candidate = base / f"{timestamp}-{suffix:02d}"
            suffix += 1


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

    value = target.strip()
    # Preserve bare/bracketed IPv6 literals rather than mistaking the first
    # colon-delimited segment for a hostname.
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")].lower().rstrip(".")
    try:
        ipaddress.ip_address(value)
        return value.lower()
    except ValueError:
        pass
    return value.split(":", 1)[0].strip("[]").lower().rstrip(".")


def parse_dns_resolvers(contents: str) -> list[str]:
    """Parse resolv.conf nameservers and skip scoped/link-local IPv6 addresses."""
    resolvers = []
    for line in contents.splitlines():
        parts = line.strip().split()
        if len(parts) < 2 or parts[0].lower() != "nameserver":
            continue
        server = parts[1].strip()
        # dnsx's comma-separated resolver list is not a reliable place to pass
        # interface-scoped link-local addresses such as fe80::1%eth1.
        if "%" in server:
            continue
        try:
            address = ipaddress.ip_address(server)
        except ValueError:
            continue
        if address.is_link_local or address.is_multicast or address.is_unspecified:
            continue
        if server not in resolvers:
            resolvers.append(server)
    return resolvers


def system_dns_resolvers() -> list[str]:
    """Read usable DNS nameservers; ignore scoped/link-local IPv6 from VPN interfaces."""
    try:
        contents = Path("/etc/resolv.conf").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return []
    return parse_dns_resolvers(contents)


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
    print(f"[+] Wordlist file: {wordlist}")
    print(f"[+] Wordlist entries: {len(words)} non-empty, non-comment lines")
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
        target_host = hostname_of(target)
        normalized_host = target_host[4:] if target_host.startswith("www.") else target_host
        if normalized_host != root:
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


def run_step(
    name: str,
    command: list[str],
    log_path: Path,
    progress_file: Path | None = None,
    heartbeat_interval: float = 10.0,
) -> int:
    """Run an external tool, log its output, and print a heartbeat while it works.

    When progress_file is provided, report how many newline-delimited records
    have been appended since the previous heartbeat. This is useful for quiet
    tools such as httpx that otherwise appear to hang when output is redirected.
    """
    print(f"\n[+] {name}\n    $ {' '.join(command)}", flush=True)
    started = time.monotonic()
    progress_offset = 0
    progress_records = 0
    try:
        with log_path.open("w", encoding="utf-8", errors="replace") as log:
            log.write("COMMAND: " + " ".join(command) + "\n\n")
            process = subprocess.Popen(
                command, stdout=log, stderr=subprocess.STDOUT, text=True
            )
            try:
                while True:
                    try:
                        return_code = process.wait(timeout=heartbeat_interval)
                        break
                    except subprocess.TimeoutExpired:
                        elapsed = int(time.monotonic() - started)
                        progress_note = ""
                        if progress_file is not None:
                            try:
                                with progress_file.open("rb") as stream:
                                    stream.seek(progress_offset)
                                    chunk = stream.read()
                                progress_offset += len(chunk)
                                progress_records += chunk.count(b"\n")
                            except OSError:
                                # httpx may not create its output file until its first result.
                                pass
                            progress_note = (
                                f"; {progress_records} HTTP result record(s) saved"
                            )
                        print(
                            f"[+] {name} still running ({elapsed}s elapsed"
                            f"{progress_note}); log: {log_path}",
                            flush=True,
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
        log_path.write_text(f"Could not execute command: {exc}\n", encoding="utf-8")
        print(f"[ERROR] Could not execute {command[0]}: {exc}")
        return 127

    elapsed = int(time.monotonic() - started)
    if return_code == 0:
        print(f"[OK] {name} completed in {elapsed}s; log: {log_path}")
    else:
        print(f"[!] {name} returned {return_code}; inspect {log_path}")
    return return_code


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

    if not args.wordlist and not getattr(args, "no_wordlist", False):
        default_wordlist = discover_default_wordlist()
        wordlist_mode = prompt_choice(
            "Subdomain wordlist?",
            {
                "1": "use detected local list (SecLists if installed; otherwise bundled list)",
                "2": "use my own wordlist",
                "3": "none",
            },
            "1",
        )
        if wordlist_mode == "1":
            if default_wordlist is not None:
                args.wordlist = str(default_wordlist)
                print(f"Using detected wordlist: {default_wordlist}")
            else:
                print("No default wordlist was found; wordlist discovery will be skipped.")
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
    parser.add_argument(
        "--bruteforce-direct", action="store_true",
        help="Send wordlist hostnames straight to httpx, bypassing dnsx pre-resolution; Subfinder still runs unless --no-subdomains is set",
    )
    parser.add_argument(
        "--bruteforce-rate", type=int, default=50,
        help="httpx request rate limit in direct wordlist mode (default: 50 requests/s)",
    )
    parser.add_argument(
        "--no-wordlist",
        action="store_true",
        help="Skip automatic default wordlist detection when -w is not provided",
    )
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
    wizard_mode = args.wizard or (not args.list and not args.single_target)

    if args.no_wordlist and args.wordlist:
        parser.error("--no-wordlist cannot be combined with --wordlist")
    if args.bruteforce_direct and args.vhost_fuzz:
        parser.error("--bruteforce-direct cannot be combined with --vhost-fuzz")
    if args.bruteforce_direct and args.no_wordlist:
        parser.error("--bruteforce-direct requires a wordlist, not --no-wordlist")
    if args.bruteforce_rate < 1:
        parser.error("--bruteforce-rate must be at least 1")
    if args.wizard and (args.list or args.single_target):
        parser.error("--wizard cannot be combined with --url or --list")
    if wizard_mode:
        try:
            if not interactive_setup(args):
                return 1
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            return 1

    # For non-interactive CLI use, start with the included wordlist unless disabled.
    # The wizard keeps its own explicit yes/no choice.
    if not wizard_mode and not args.wordlist and not args.no_wordlist:
        default_wordlist = discover_default_wordlist()
        if default_wordlist is not None:
            args.wordlist = str(default_wordlist)
            print(f"[+] Using detected default wordlist: {default_wordlist}")

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
                address = ipaddress.ip_address(resolver)
            except ValueError:
                parser.error(f"Invalid DNS resolver IP: {resolver}")
            if "%" in resolver or address.is_link_local or address.is_multicast or address.is_unspecified:
                parser.error(
                    f"Unusable DNS resolver address: {resolver}. "
                    "Provide an unscoped, non-link-local resolver IP."
                )

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
            root_host = host[4:] if host.startswith("www.") else host
            roots.append(root_host)
        if "://" in target or is_ip(host) or "." not in host:
            direct.append(target)
    roots = list(dict.fromkeys(roots))

    wordlist = Path(args.wordlist).expanduser().resolve() if args.wordlist else None
    if wordlist and not wordlist.is_file():
        print(f"[ERROR] Wordlist does not exist: {wordlist}", file=sys.stderr)
        return 2
    if args.bruteforce_direct and not wordlist:
        print(
            "[ERROR] --bruteforce-direct needs an available or explicitly supplied wordlist.",
            file=sys.stderr,
        )
        return 2
    if args.bruteforce_direct and not roots:
        print(
            "[ERROR] --bruteforce-direct requires a domain/hostname target, not only an IP address.",
            file=sys.stderr,
        )
        return 2

    required = ["httpx"]
    if not args.no_nuclei:
        required.append("nuclei")
    if not args.no_screenshots:
        required.append("gowitness")
    if not args.no_subdomains and roots:
        required.append("subfinder")
    if wordlist and roots and not args.bruteforce_direct:
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

    out_dir = create_run_output_dir(args.output)
    status = {
        "version": VERSION,
        "html_report_enabled": not args.no_html_report,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_path) if input_path else None,
        "single_target": args.single_target if args.single_target else None,
        "root_domain_count": len(roots), "subdomain_count": 0,
        "target_count": 0, "live_url_count": 0, "asset_count": 0,
        "software_fingerprint_count": 0, "login_panel_count": 0,
        "default_credential_review_count": 0, "cve_candidate_count": 0,
        "vhost_count": 0, "stages": {}
    }

    pipeline_failures: list[str] = []
    discovered: list[str] = []
    wordlist_names: list[str] = []
    direct_bruteforce_candidates: list[str] = []

    if args.bruteforce_direct and wordlist and roots:
        # Build host candidates and pass them directly to httpx. This skips
        # the separate dnsx resolver stage; httpx itself still has to resolve
        # candidate names to connect to their web services.
        words = read_lines(wordlist)
        print(f"[+] Wordlist file: {wordlist}")
        print(f"[+] Wordlist entries: {len(words)} non-empty, non-comment lines")
        direct_bruteforce_candidates = build_wordlist_candidates(roots, words)
        write_lines(out_dir / "wordlist-candidates.txt", direct_bruteforce_candidates)
        write_lines(out_dir / "wordlist-resolved.txt", [])
        print(
            f"[+] Direct wordlist candidates queued for httpx: "
            f"{len(direct_bruteforce_candidates)} (no dnsx pre-resolution)"
        )
        status["stages"]["wordlist_dns"] = {
            "status": "skipped",
            "reason": "--bruteforce-direct sends candidates to httpx instead of dnsx",
        }
        status["stages"]["wordlist_direct"] = {
            "status": "queued for httpx",
            "candidates": len(direct_bruteforce_candidates),
            "rate_limit": args.bruteforce_rate,
        }

    # Run the supplied/bundled wordlist first so its results are ready for the
    # main target-probing stage even when passive discovery later fails.
    if wordlist and roots and not args.bruteforce_direct:
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
            print(
                f"[WARN] Wordlist DNS resolution failed: {exc}. "
                "Continuing with the remaining discovery stages.",
                file=sys.stderr,
            )
            status["stages"]["wordlist_dns"] = {"status": "failed", "error": str(exc)}
            pipeline_failures.append("wordlist DNS")

    # Passive discovery remains enabled in direct wordlist mode unless explicitly disabled.
    if not args.no_subdomains and roots:
        roots_file, sub_file = out_dir / "root-domains.txt", out_dir / "subdomains.txt"
        write_lines(roots_file, roots)
        cmd = ["subfinder", "-dL", str(roots_file), "-silent", "-o", str(sub_file)]
        if args.subfinder_all:
            cmd.insert(1, "-all")
        rc = run_step("Subfinder: passive subdomain discovery", cmd, out_dir / "subfinder.log")
        status["stages"]["subfinder"] = rc
        if sub_file.exists():
            try:
                discovered = read_lines(sub_file)
            except OSError as exc:
                print(f"[WARN] Could not read Subfinder output: {exc}", file=sys.stderr)
        if rc:
            print(
                f"[WARN] Subfinder exited with code {rc}; continuing with any wordlist "
                "and direct-target results.",
                file=sys.stderr,
            )
            pipeline_failures.append("subfinder")

    vhost_rows: list[dict] = []
    vhost_hosts: list[str] = []
    should_run_vhost = bool(args.vhost_fuzz)
    if (
        wordlist and roots and not args.bruteforce_direct
        and not args.vhost_fuzz and not wordlist_names and not discovered
    ):
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
    elif wordlist and roots and not args.bruteforce_direct:
        if not wordlist_names and not discovered:
            status["stages"]["vhost_fuzz"] = "skipped by user after zero DNS results"
        else:
            status["stages"]["vhost_fuzz"] = "not run (DNS or Subfinder already found subdomains; use --vhost-fuzz to run both)"

    combined = combine_targets(direct, roots, wordlist_names, discovered)
    if direct_bruteforce_candidates:
        combined = list(dict.fromkeys([*combined, *direct_bruteforce_candidates]))
    combined_file, live_file = out_dir / "all-targets.txt", out_dir / "live.txt"
    write_lines(combined_file, combined)
    status["subdomain_count"] = len(set(discovered + wordlist_names + vhost_hosts))
    status["target_count"] = len(combined)

    details_file = out_dir / "httpx-details.jsonl"
    httpx_command = [
        "httpx", "-l", str(combined_file), "-silent", "-no-color",
        "-timeout", str(args.timeout), "-td", "-server", "-title",
        "-status-code", "-json", "-o", str(details_file),
    ]
    if args.bruteforce_direct:
        httpx_command.extend(["-rate-limit", str(args.bruteforce_rate)])
    print(f"[+] httpx targets queued: {len(combined)}", flush=True)
    rc = run_step(
        "httpx: identify live services and fingerprint technologies",
        httpx_command,
        out_dir / "httpx.log",
        progress_file=details_file,
    )
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
    if args.bruteforce_direct:
        live_hosts = {
            (urlparse(url).hostname or "").lower().rstrip(".")
            for url in live
        }
        live_candidates = sorted(set(direct_bruteforce_candidates) & live_hosts)
        write_lines(out_dir / "wordlist-live.txt", live_candidates)
        status["subdomain_count"] = len(set(discovered + wordlist_names + vhost_hosts + live_candidates))
        status["stages"]["wordlist_direct"] = {
            "status": "completed",
            "candidates": len(direct_bruteforce_candidates),
            "live_candidate_hosts": len(live_candidates),
            "rate_limit": args.bruteforce_rate,
        }
    status["asset_count"] = len(assets)
    status["software_fingerprint_count"] = len(fingerprints)
    if not live:
        print("[!] No live web URLs were returned by httpx; downstream stages were not run because there is nothing to inspect.")
        status["stages"]["login_panels"] = "not run: httpx returned no live URLs"
        status["stages"]["cve_lookup"] = "not run: httpx returned no live URLs"
        status["stages"]["nuclei"] = "not run: httpx returned no live URLs"
        status["stages"]["gowitness"] = "not run: httpx returned no live URLs"
        save_report(out_dir, status)
        return 1 if pipeline_failures else 0

    failures = list(pipeline_failures)
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
        print(f"    Wordlist candidates: {out_dir / 'wordlist-candidates.txt'}")
        if args.bruteforce_direct:
            print("    Wordlist mode: direct candidates passed to httpx (dnsx skipped)")
        else:
            print(f"    Wordlist DNS results: {out_dir / 'wordlist-resolved.txt'}")
            print(f"    DNS log: {out_dir / 'dnsx.log'}")
    if (out_dir / "vhost-findings.csv").is_file():
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
