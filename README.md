# TriageFlow v2.0.0

**TriageFlow v2** is a beginner-friendly Python command-line orchestrator for authorized web-security reconnaissance. It connects **Subfinder**, **custom wordlist-based subdomain discovery**, **httpx**, **Nuclei**, and **GoWitness**, then enriches HTTP results with software-version inventory, NVD CVE candidates, and login-panel discovery.

> **New here?** Start with the [Greek step-by-step guide](QUICKSTART_EL.md), or simply run `python3 triageflow.py` to open the guided setup wizard. You do not need to memorize command-line options.
>
> **Authorization only:** Run this tool only against systems you own or targets explicitly included in your written authorization, lab, or bug-bounty scope. The confirmation prompt is an operational reminder, not a substitute for permission.

## Why TriageFlow?

Each tool has a different job. TriageFlow handles the hand-offs between them, so you do not have to manually copy output from one command into the next:

1. Accept one target (`-u`) or a file of targets (`-l`).
2. Normalize and deduplicate supplied entries, then identify DNS root domains suitable for subdomain discovery.
3. Optionally run Subfinder and/or build candidate subdomains from a custom wordlist (`-w`).
4. Combine direct targets, root domains, and discovered names into one deduplicated list.
5. Run httpx with JSON output, technology detection, server headers, titles, status codes, and asset details.
6. Build CSV asset/software inventories.
7. Query the NIST NVD API for candidate CVEs and classify results using CPE applicability hints where available.
8. Check likely login panels using bounded GET requests only and create a default-credential hygiene checklist; no credentials are submitted.
9. Optionally capture screenshots for **all live URLs**, including discovered live subdomains, with GoWitness.
10. Generate a self-contained HTML report plus CSV, JSON and Markdown outputs.

## Tools and their roles

| Tool | Purpose in this workflow | Output/use |
|---|---|---|
| **Subfinder** | Passive subdomain enumeration for supplied root domains. `--subfinder-all` asks it to use all configured sources; this may be slower and some sources may need API keys. | `subdomains.txt` |
| **Custom wordlist (`-w`)** | Combines each wordlist entry with each root domain, checks whether the candidate resolves using the system DNS resolver, and adds resolving names to the target set. Full hostnames already ending in a root domain are also accepted. | `wordlist-candidates.txt`, `wordlist-resolved.txt` |
| **httpx (ProjectDiscovery)** | Probes targets and records response status, title, server header, and detected technologies as JSONL. This is the ProjectDiscovery CLI tool, not the unrelated Python HTTPX library. | `live.txt`, `httpx-details.jsonl` |
| **Software inventory** | Extracts product/version observations visible to httpx. | `software-inventory.csv` |
| **NVD CVE lookup** | Searches NIST NVD API 2.0 for a limited number of versioned product candidates. Results are keyword matches that require validation against the affected-version range. | `cve-candidates.json`, `cve-candidates.md` |
| **Login-panel discovery** | Sends bounded HTTP GET requests to common login paths and records likely panels. It never attempts to authenticate or submit credentials. | `login-panels.csv` |
| **Nuclei** | Runs template-based checks against each URL in `live.txt`, filtered by the configured severities. Findings are written as JSON Lines for later review. | `nuclei-findings.jsonl` |
| **GoWitness** | Optional screenshots from the same `live.txt` list; discovered subdomains are included when they respond to httpx. Artifact layout can vary by GoWitness version. | `gowitness/` and `gowitness.log` |
| **Asset inventory** | Flattens HTTP results into an easy-to-filter CSV. | `asset-inventory.csv` |
| **Default-account hygiene review** | Associates detected login pages with visible product fingerprints and provides vendor links and manual hardening checks. It does not try usernames or passwords. | `default-credentials-review.md`, `default-credentials-review.csv` |
| **HTML report** | Combines assets, fingerprints, CVE candidates, login pages, the default-account checklist, Nuclei findings and stage status into one local page. | `report.html` |

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
       live URLs + JSONL
                |
       +--------+---------+
       |        |         |
       v        v         v
   Inventory  NVD CVEs  Login panels
       |        |         |
       +--------+---------+
                |
          +-----+-----+
          v           v
        Nuclei     GoWitness
       findings    screenshots
          +-----------+
                |
          Logs + summary
```

Subfinder and the custom wordlist are complementary. If discovery is disabled with `--no-subdomains`, the wordlist can still be used; Subfinder will be skipped. Wordlist DNS resolution is a quick filter, not proof that a hostname hosts a web service—httpx makes that determination next.

## What is new in v2?

- **Guided screenshot choice:** during interactive setup, choose whether GoWitness should capture screenshots. In the Standard profile screenshots default to yes; in Quick they default to no, but you can change that answer.
- **Single HTML report:** `report.html` is generated by default and can be opened locally in a browser. It contains an overview and tables for assets, software versions, CVE candidates, login panels, manual credential hygiene review, Nuclei findings, and stage status.
- **Asset inventory:** `asset-inventory.csv` includes observed URL, hostname, IPs when available, status, title, server, technologies, CNAME and CDN fields when supplied by httpx.
- **Better CVE triage:** each CVE candidate gets a per-result label. Where NVD CPE applicability data is present, TriageFlow checks whether the observed product/version fits the advertised criteria. These checks are heuristic hints, not a final version-range verdict; vendor advisories remain authoritative.
- **Default-account hygiene report:** found login panels are paired with recognizable software fingerprints where possible and produce a vendor-guidance checklist. TriageFlow does **not** submit default credentials or run credential spraying. Use an approved, controlled configuration audit to validate authentication settings.
- **Versioning and tests:** `python3 triageflow.py --version` reports the version; unit tests cover fingerprinting, CPE triage labels, wizard options, and reports.

## Enrichment features

- **Version fingerprinting:** httpx runs with technology detection and records server/title/status metadata. Product/version strings that are exposed by the target are written to `software-inventory.csv`; many services intentionally hide or suppress precise versions, so an empty version is normal.
- **Known-CVE candidates:** versioned products are searched through the official [NIST NVD API](https://nvd.nist.gov/developers/vulnerabilities). By default the tool queries at most five distinct product/version pairs to limit latency and API usage. Set the `NVD_API_KEY` environment variable to use an NVD API key. Review `cve-candidates.md` and `cve-candidates.json`: keyword results are leads, not proof of impact, and affected-version ranges must be checked manually.
- **Login-panel discovery:** TriageFlow makes GET-only requests to a small set of common paths on up to 25 distinct live origins by default, then writes `login-panels.csv`. It does not submit usernames/passwords, follow redirects, or attempt authentication. Use this inventory to plan an explicitly authorized manual configuration audit.
- **Community contributions:** see `CONTRIBUTING.md` for the fork-and-pull-request workflow.

## Installation

### Requirements

- Python 3.10+
- Go (needed only if you want TriageFlow to attempt automatic installation of missing Go-based tools)
- ProjectDiscovery `httpx`, `nuclei`, `subfinder`, and `gowitness`, depending on which stages you want to run
- Network/DNS access appropriate to your authorized environment

TriageFlow checks for required executables. When a tool is missing, it attempts `go install` into `~/go/bin` if Go is available, and reports tools that remain unavailable. Ensure `~/go/bin` is on `PATH` for later terminal sessions. Automatic installation can fail because of network restrictions, Go-version incompatibilities, or OS package-manager problems; inspect the messages and logs rather than assuming installation succeeded.

### Clone and start (recommended for beginners)

```bash
git clone https://github.com/CodebindPyth/TriageFlow.git
cd TriageFlow
python3 triageflow.py
```

Running the program **without arguments** opens the guided wizard. It asks whether you want to scan one target or a file, which wordlist to use, and whether you want the Standard or Quick profile. Before any scan starts, it still requires the authorization confirmation.

To see every CLI option without starting a scan:

```bash
python3 triageflow.py --version
python3 triageflow.py --help
```

You can explicitly launch the same wizard with `python3 triageflow.py --wizard`. See [QUICKSTART_EL.md](QUICKSTART_EL.md) for explanations in Greek, output files, troubleshooting, and example commands.

The Python code uses standard-library modules only; Go-based recon tools are installed separately.

## Usage

**Beginner path:** run `python3 triageflow.py` with no arguments and follow the prompts. Choose **Standard** for all enabled stages or **Quick** to skip Subfinder, Nuclei, and screenshots.

For direct CLI use:

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

# Run without Nuclei or screenshots
python3 triageflow.py -u example.com --no-nuclei --no-screenshots

# Skip only the generated HTML report
python3 triageflow.py -u example.com --no-html-report
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
| `--no-screenshots` | Skip GoWitness screenshots. In the wizard, choose yes/no independently of the profile. |
| `--no-html-report` | Skip `report.html`; CSV/JSON/Markdown output remains. |
| `--version` | Show the TriageFlow version. |
| `--no-login-check` | Skip login-panel discovery. |
| `--max-login-hosts` | Maximum number of distinct origins checked for login panels; default `25`. |
| `--no-cve-lookup` | Skip NVD CVE candidate lookups. |
| `--max-cve-products` | Maximum versioned product/version pairs queried in NVD; default `5`. |

Before scanning, the program asks you to type `YES` to confirm the targets are yours or explicitly in scope. Any other answer cancels execution.

## Results

A run creates a timestamped directory under `triageflow-results/` by default, for example:

```text
triageflow-results/20261011-173000/
├── root-domains.txt          # DNS root domains supplied for discovery
├── subdomains.txt            # names returned by Subfinder, if enabled
├── wordlist-candidates.txt   # generated candidates from -w, if used
├── wordlist-resolved.txt     # wordlist candidates resolving via system DNS
├── all-targets.txt               # deduplicated inputs for httpx
├── live.txt                      # responding HTTP/HTTPS URLs
├── httpx-details.jsonl           # response and fingerprint details
├── asset-inventory.csv           # flattened web asset inventory
├── software-inventory.csv        # observed software/product versions
├── login-panels.csv              # likely login endpoints; GET-only checks
├── default-credentials-review.md # manual hygiene checklist; not a login test
├── default-credentials-review.csv
├── cve-candidates.json           # NVD results with CPE triage labels
├── cve-candidates.md             # readable CVE candidate report
├── nuclei-findings.jsonl         # Nuclei findings (if enabled)
├── report.html                   # consolidated local report (if enabled)
├── gowitness/                    # screenshots/database artifacts (if enabled)
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
- **Findings are not verdicts:** Nuclei results, software fingerprints, and NVD keyword/CPE hints can be false positives or require manual verification. Observed banners can be incomplete or inaccurate.
- **Tool compatibility:** command-line flags and JSON keys can vary between tool versions. If a stage fails, inspect its corresponding log and compare the command with that installed version's help output.
- **NVD rate limits:** unauthenticated NVD requests are throttled deliberately. The tool limits the number of queried product/version pairs; consider setting `NVD_API_KEY` for larger inventories.
- **No guarantee of full coverage:** passive discovery sources, DNS behavior, timeouts, rate limits, and scope all affect results.
- **Default-credential handling:** TriageFlow only creates a manual configuration-review checklist. It does not attempt authentication or submit default passwords.
- **Sensitive output:** screenshots, reports, and logs may contain tokens, internal hostnames, or personal data. Protect them and do not commit scan results to a public repository.
- **Safe use:** respect written scope, rate limits, and rules of engagement. Do not scan systems without authorization.

## Project status

Early-stage utility. The goal is to provide a transparent, repeatable orchestration layer—not to replace the underlying tools or automatically declare a system secure/insecure. Contributions should keep the README aligned with actual command-line behavior.
