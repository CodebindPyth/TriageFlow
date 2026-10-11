# TriageFlow

**TriageFlow** is a Python command-line orchestrator for authorized web-security reconnaissance. It connects **Subfinder**, **custom wordlist-based subdomain discovery**, **httpx**, **Nuclei**, and **GoWitness** into one repeatable pipeline and stores results in a timestamped directory.

> **Authorization only:** Run this tool only against systems you own or targets explicitly included in your written authorization, lab, or bug-bounty scope. The confirmation prompt is an operational reminder, not a substitute for permission.

## Why TriageFlow?

Each tool has a different job. TriageFlow handles the hand-offs between them, so you do not have to manually copy output from one command into the next:

1. Accept one target (`-u`) or a file of targets (`-l`).
2. Normalize and deduplicate supplied entries, then identify DNS root domains suitable for subdomain discovery.
3. Optionally run Subfinder and/or build candidate subdomains from a custom wordlist (`-w`).
4. Combine direct targets, root domains, and discovered names into one deduplicated list.
5. Run httpx to find responding HTTP/HTTPS services.
6. Feed the **same live URL list** to Nuclei and GoWitness.
7. Save command logs, findings, screenshots, and machine-readable and human-readable summaries.

## Tools and their roles

| Tool | Purpose in this workflow | Output/use |
|---|---|---|
| **Subfinder** | Passive subdomain enumeration for supplied root domains. `--subfinder-all` asks it to use all configured sources; this may be slower and some sources may need API keys. | `subdomains.txt` |
| **Custom wordlist (`-w`)** | Combines each wordlist entry with each root domain, checks whether the candidate resolves using the system DNS resolver, and adds resolving names to the target set. Full hostnames already ending in a root domain are also accepted. | `wordlist-candidates.txt`, `wordlist-resolved.txt` |
| **httpx (ProjectDiscovery)** | Probes the combined targets to identify reachable web services. This is the ProjectDiscovery CLI tool, not the unrelated Python HTTPX library. | `live.txt` |
| **Nuclei** | Runs template-based checks against each URL in `live.txt`, filtered by the configured severities. Findings are written as JSON Lines for later review. | `nuclei-findings.jsonl` |
| **GoWitness** | Captures screenshots from the exact same `live.txt` list, making it easier to visually review web applications. Artifact layout can vary by GoWitness version. | `gowitness/` and `gowitness.log` |

### Pipeline overview

```text
-u target  OR  -l targets.txt
          |
          v
  Root domains + direct targets
          |
     +----+----------------+
     |                     |
     v                     v
  Subfinder          Custom wordlist (-w)
     |              candidate DNS resolution
     +----------+----------+
                v
     Deduplicate target list
                |
                v
              httpx
                |
           live.txt
          /         \
         v           v
      Nuclei      GoWitness
   JSONL findings  screenshots
          \         /
           v       v
       Logs + summaries
```

Subfinder and the custom wordlist are complementary. If discovery is disabled with `--no-subdomains`, the wordlist can still be used; Subfinder will be skipped. Wordlist DNS resolution is a quick filter, not proof that a hostname hosts a web service—httpx makes that determination next.

## Installation

### Requirements

- Python 3.10+
- Go (needed only if you want TriageFlow to attempt automatic installation of missing Go-based tools)
- ProjectDiscovery `httpx`, `nuclei`, `subfinder`, and `gowitness`, depending on which stages you want to run
- Network/DNS access appropriate to your authorized environment

TriageFlow checks for required executables. When a tool is missing, it attempts `go install` into `~/go/bin` if Go is available, and reports tools that remain unavailable. Ensure `~/go/bin` is on `PATH` for later terminal sessions. Automatic installation can fail because of network restrictions, Go-version incompatibilities, or OS package-manager problems; inspect the messages and logs rather than assuming installation succeeded.

### Clone and inspect options

```bash
git clone https://github.com/CodebindPyth/TriageFlow.git
cd TriageFlow
python3 triageflow.py --help
```

No third-party Python packages are required for the CLI itself. The security tools are separate executables.

## Usage

```bash
# One authorized domain; Subfinder discovery enabled
python3 triageflow.py -u example.com

# One authorized domain, ask Subfinder to use all configured sources
python3 triageflow.py -u example.com --subfinder-all

# Add custom subdomain candidates from a wordlist
python3 triageflow.py -u example.com -w ./wordlists/subdomains-small.txt

# Combine Subfinder and custom wordlist discovery
python3 triageflow.py -u example.com --subfinder-all -w ./wordlists/subdomains-small.txt

# Multiple targets (one URL, hostname, or IP per line)
python3 triageflow.py -l targets.txt

# Skip Subfinder; process supplied targets and optional wordlist only
python3 triageflow.py -u example.com --no-subdomains -w ./wordlists/subdomains-small.txt

# Choose output directory, Nuclei severity levels, and timeout
python3 triageflow.py -u example.com -o ./results --severity medium,high,critical --timeout 10

# Run only discovery and HTTP probing (no Nuclei or screenshots)
python3 triageflow.py -u example.com --no-nuclei --no-screenshots
```

### Arguments

| Argument | Description |
|---|---|
| `-u`, `--url` | One domain, hostname, IP, or URL to process. |
| `-l`, `--list` | Input file containing one target per line; blank lines and `#` comments are ignored. |
| `-w`, `--wordlist` | Custom subdomain wordlist, one label or hostname per line. Candidates are checked with system DNS and resolving names are added. |
| `-o`, `--output` | Base directory for results; each run gets its own timestamped subdirectory. |
| `--no-subdomains` | Skip Subfinder. Direct targets and any `-w` candidates can still be processed. |
| `--subfinder-all` | Pass Subfinder's `-all` option. |
| `--severity` | Comma-separated Nuclei severities; default is `medium,high,critical`. |
| `--timeout` | httpx timeout in seconds; default is `10`. |
| `--no-nuclei` | Skip the Nuclei stage. |
| `--no-screenshots` | Skip the GoWitness stage. |

Before scanning, the program asks you to type `YES` to confirm the targets are yours or explicitly in scope. Any other answer cancels execution.

## Results

A run creates a timestamped directory under `triageflow-results/` by default, for example:

```text
triageflow-results/20261011-173000/
├── root-domains.txt          # DNS root domains supplied for discovery
├── subdomains.txt            # names returned by Subfinder, if enabled
├── wordlist-candidates.txt   # generated candidates from -w, if used
├── wordlist-resolved.txt     # wordlist candidates resolving via system DNS
├── all-targets.txt           # deduplicated inputs for httpx
├── live.txt                  # web URLs reported by httpx
├── nuclei-findings.jsonl     # Nuclei findings (if enabled)
├── gowitness/                # screenshots/database artifacts (if enabled)
├── subfinder.log             # Subfinder output/diagnostics, if enabled
├── httpx.log                 # httpx output/diagnostics
├── nuclei.log                # Nuclei output/diagnostics, if enabled
├── gowitness.log             # GoWitness output/diagnostics, if enabled
├── summary.json              # machine-readable run summary
└── README.md                 # human-readable run summary
```

Some files are omitted when their stage is not used. Tool-specific artifact names can change between tool versions. Logs are retained to make failures easier to diagnose.

## Important implementation details and limitations

- **Shared input:** Nuclei and GoWitness both consume `live.txt`; therefore discovered hosts are included in both stages if httpx reports them live.
- **DNS wordlist filtering:** the script uses the operating system's DNS resolver through Python's `socket.getaddrinfo`. It does not perform brute-force DNS against arbitrary resolvers, and a failed lookup can reflect local DNS/network conditions.
- **Findings are not verdicts:** Nuclei results can be false positives or require manual verification. A finding is not automatically proof of exploitability.
- **Tool compatibility:** command-line flags can vary between tool versions. If a stage fails, inspect its corresponding log and compare the command with that installed version's help output.
- **No guarantee of full coverage:** passive discovery sources, DNS behavior, timeouts, rate limits, and scope all affect results.
- **Sensitive output:** screenshots and logs may contain tokens, internal hostnames, or personal data. Protect them and do not commit scan results to a public repository.
- **Safe use:** respect written scope, rate limits, and rules of engagement. Do not scan systems without authorization.

## Project status

Early-stage utility. The goal is to provide a transparent, repeatable orchestration layer—not to replace the underlying tools or automatically declare a system secure/insecure. Contributions should keep the README aligned with actual command-line behavior.
