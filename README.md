# TriageFlow v2.0.10

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

## Default behavior

A normal run enables passive Subfinder discovery (unless `--no-subdomains` is supplied), HTTP service fingerprinting, login-panel discovery, NVD CVE candidate lookup, Nuclei checks, GoWitness screenshots and the HTML report. Use the matching `--no-*` switch when you intentionally want a stage disabled. The guided wizard's Quick profile is also an explicit choice to omit selected stages. Login discovery uses bounded same-origin GET requests only; it follows login-like links found in returned HTML and checks common authentication paths, but JavaScript-only or custom unlinked pages can still be missed. It never submits usernames/passwords or tests default credentials.

## Tools and their roles

| Tool | Purpose in this workflow | Output/use |
|---|---|---|
| **Subfinder** | Passive subdomain enumeration for supplied root domains. `--subfinder-all` asks it to use all configured sources; this may be slower and some sources may need API keys. | `subdomains.txt` |
| **Custom wordlist (`-w`)** | Builds in-scope hostname candidates and resolves them in parallel using ProjectDiscovery `dnsx` with a short per-query timeout. It reads DNS servers from `/etc/resolv.conf` by default and checks the system hosts file. Full hostnames from another domain are rejected. | `wordlist-candidates.txt`, `wordlist-resolved.txt`, `dnsx.log` |
| **Virtual-host fallback (ffuf)** | `--vhost-fuzz` runs alongside DNS discovery. For direct Host-header discovery without first resolving candidates through `dnsx`, use the standalone `vhost_direct.py` entry point described below. | `vhost-findings.csv`, `vhost-findings.json`, `vhost-subdomains.txt`, `ffuf-vhost-*.log` |
| **httpx (ProjectDiscovery)** | Probes targets and records response status, title, server header, and detected technologies as JSONL. This is the ProjectDiscovery CLI tool, not the unrelated Python HTTPX library. | `live.txt`, `httpx-details.jsonl` |
| **Software inventory** | Extracts product/version observations visible to httpx. | `software-inventory.csv` |
| **NVD CVE lookup** | Searches NIST NVD API 2.0 for a limited number of versioned product candidates. Results are keyword matches that require validation against the affected-version range. | `cve-candidates.json`, `cve-candidates.md` |
| **Login-panel discovery** | Sends bounded HTTP GET requests to common login paths and records likely panels. It never attempts to authenticate or submit credentials. | `login-panels.csv` |
| **Nuclei** | Runs template-based checks against each URL in `live.txt`, filtered by the configured severities. Findings are written as JSON Lines for later review. | `nuclei-findings.jsonl` |
| **GoWitness** | Optional screenshots from the same `live.txt` list; discovered subdomains are included when they respond to httpx. Artifact layout can vary by GoWitness version. | `gowitness/` and `gowitness.log` |
| **Asset inventory** | Flattens HTTP results into an easy-to-filter CSV. | `asset-inventory.csv` |
| **Default-account hygiene review** | Associates detected login pages with visible product fingerprints and provides vendor links and manual hardening checks. It does not try usernames or passwords. | `default-credentials-review.md`, `default-credentials-review.csv` |
| **HTML report** | Combines assets, fingerprints, CVE candidates, login pages, the default-account checklist, Nuclei findings and stage status into one local page. | `report.html` |

## Direct virtual-host discovery without DNS pre-resolution

If you want to test virtual hosts directly, without first sending every candidate through dnsx, use the standalone `vhost_direct.py` entry point. It sends requests to the supplied base URL and varies only the HTTP Host header, using ffuf. It requires ffuf, but not dnsx or Subfinder.

```bash
python3 vhost_direct.py \
  -u http://inlanefreight.local/ \
  -w /home/kali/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  --rate 100 \
  --max-time 120
```

Use a wordlist of single labels (for example, admin, dev, portal). The base URL itself must be reachable from Kali; the script asks you to confirm authorization before sending requests. Results are saved in a timestamped directory under `triageflow-results/`: `vhost-findings.csv`, `vhost-findings.json`, `vhost-subdomains.txt`, and `ffuf-vhost.log`. These results are separate from the main `triageflow.py` pipeline's `live.txt`.

## Direct wordlist brute-force in the main TriageFlow pipeline

Use `--bruteforce-direct` when you want the **normal `triageflow.py` pipeline** to queue wordlist-generated hostname candidates directly for `httpx`, without the separate `dnsx` pre-resolution stage. Subfinder remains enabled unless you explicitly pass `--no-subdomains`. `httpx` still has to resolve hostnames internally to connect to web services, so this bypasses only the standalone `dnsx` pass, not the DNS resolution needed for HTTP connections.

```bash
python3 triageflow.py \
  -u http://inlanefreight.local/ \
  -w /home/kali/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  --bruteforce-direct \
  --bruteforce-rate 10
```

The direct mode skips the standalone `dnsx` pre-resolution stage, feeds generated candidates to `httpx`, and still runs Subfinder unless `--no-subdomains` is supplied. By default, login-panel discovery, NVD CVE lookup, Nuclei and GoWitness screenshots are enabled. Each can be deliberately disabled with its corresponding `--no-login-check`, `--no-cve-lookup`, `--no-nuclei` or `--no-screenshots` option. The request-rate limit defaults to 50 requests per second and can be adjusted with `--bruteforce-rate`. Candidate names are recorded in `wordlist-candidates.txt`; candidates that produced live HTTP results are listed in `wordlist-live.txt`. The HTML report displays screenshot images from its sibling `gowitness/` folder, and the report must stay with that folder. Use this only on systems explicitly in scope for your assessment.

Long-running stages now print a heartbeat every 10 seconds. During `httpx`, TriageFlow also reports how many JSONL result records have been saved so far. This is progress feedback, not a count of every attempted request: names that do not respond will not add a result record. A very large candidate list can still take a long time; for example, 100,000 candidates at 50 requests/second has a theoretical rate-limit floor of about 33 minutes, before DNS and connection delays.

### Pipeline overview

```text
-u target  OR  -l targets.txt
          |
          v
  Root domains + direct targets
          |
          v
  Custom wordlist DNS (dnsx)
  SecLists if installed, else bundled
          |
          v
  Passive Subfinder (unless skipped)
          |
          v
  Deduplicate: direct + roots + wordlist + passive
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

Subfinder and the wordlist are complementary. In direct CLI mode, the program first looks for a local SecLists DNS wordlist and falls back to the bundled starter list; the wizard lets you choose whether to use the detected list. `--no-subdomains` skips Subfinder but still uses the wordlist, while `--no-wordlist` disables automatic wordlist selection. DNS resolution is only a quick filter, not proof that a hostname hosts a web service—httpx makes that determination next.

## What is new in v2?

- **Wordlist-first discovery:** direct CLI runs automatically look for an installed SecLists `Discovery/DNS/subdomains-top1million-5000.txt`; if none is found, they use `wordlists/subdomains-small.txt` when `-w` is omitted. DNS checks for those wordlist candidates run before Subfinder. Resolved wordlist names are placed in `all-targets.txt` before passive Subfinder results and are passed to httpx, then to later stages if they respond. Use `-w /path/to/wordlist.txt` for a larger list, or `--no-wordlist` to skip automatic wordlist selection. DNS checks use ProjectDiscovery `dnsx` concurrently (100 threads, one attempt, 2-second per-query timeout) with progress messages and wildcard filtering. The selected path and number of input entries are printed before DNS begins; scoped/link-local IPv6 nameservers are excluded from `/etc/resolv.conf`.
- **Private/lab DNS:** usable resolver addresses are read from `/etc/resolv.conf`; scoped/link-local IPv6 entries such as `fe80::1%eth1` are skipped. The system hosts file is also checked. For an unusual lab setup, use `--dns-resolvers 10.0.0.1` with the DNS server supplied by the lab.
- **Virtual-host fallback:** DNS enumeration cannot discover a web virtual host that has no DNS record. If both Subfinder and wordlist DNS return no subdomains, TriageFlow asks whether you want ffuf to test HTTP `Host` headers using the same wordlist. Confirm only if this is an authorized target. Add `--vhost-fuzz` to run this stage explicitly regardless of DNS results. Vhost-only names may not be DNS-resolvable and therefore are not automatically included in `live.txt` or GoWitness screenshots.
- **Guided screenshot choice:** during interactive setup, choose whether GoWitness should capture screenshots. In the Standard profile screenshots default to yes; in Quick they default to no, but you can change that answer.
- **Single HTML report:** `report.html` is generated by default and can be opened locally in a browser. It contains an overview and tables for assets, software versions, CVE candidates, login panels, manual credential hygiene review, Nuclei findings, and stage status.
- **Asset inventory:** `asset-inventory.csv` includes observed URL, hostname, IPs when available, status, title, server, technologies, CNAME and CDN fields when supplied by httpx.
- **Better CVE triage:** each CVE candidate gets a per-result label. Where NVD CPE applicability data is present, TriageFlow checks whether the observed product/version fits the advertised criteria. These checks are heuristic hints, not a final version-range verdict; vendor advisories remain authoritative.
- **Default-account hygiene report:** found login panels are paired with recognizable software fingerprints where possible and produce a vendor-guidance checklist. TriageFlow does **not** submit default credentials or run credential spraying. Use an approved, controlled configuration audit to validate authentication settings.
- **Versioning and tests:** `python3 triageflow.py --version` reports the version; unit tests cover fingerprinting, CPE triage labels, wizard options, reports, and virtual-host output files.

## Enrichment features

- **Version fingerprinting:** httpx runs with technology detection and records server/title/status metadata. Product/version strings that are exposed by the target are written to `software-inventory.csv`; many services intentionally hide or suppress precise versions, so an empty version is normal.
- **Known-CVE candidates:** versioned products are searched through the official [NIST NVD API](https://nvd.nist.gov/developers/vulnerabilities). By default the tool queries at most five distinct product/version pairs to limit latency and API usage. Set the `NVD_API_KEY` environment variable to use an NVD API key. Review `cve-candidates.md` and `cve-candidates.json`: keyword results are leads, not proof of impact, and affected-version ranges must be checked manually.
- **Login-panel discovery:** TriageFlow makes bounded GET-only requests to common paths and same-origin login/account links found in returned HTML on up to 25 distinct live origins by default. It can record multiple login URLs per origin (up to 8 panels and 40 page requests per origin), then writes `login-panels.csv` plus `login-discovery-summary.json`. It checks same-origin redirect targets but never sends credentials or attempts authentication. JavaScript-only or unlinked routes may still be missed.
- **Community contributions:** see `CONTRIBUTING.md` for the fork-and-pull-request workflow.

## Installation

### Requirements

- Python 3.10+
- Go (needed only if you want TriageFlow to attempt automatic installation of missing Go-based tools)
- Chrome or Chromium when screenshots are enabled, plus the applicable GoWitness CLI
- ProjectDiscovery `httpx`, `nuclei`, `subfinder`, and `gowitness`, depending on which stages you want to run
- ProjectDiscovery `dnsx` when wordlist discovery is enabled (automatic local SecLists detection, falling back to the bundled list)
- `ffuf` when you enable virtual-host discovery or accept its fallback prompt
- Network/DNS access appropriate to your authorized environment

TriageFlow checks for required executables in `PATH`, `~/go/bin`, and the directories reported by `go env GOBIN`/`GOPATH`. It skips installation when a tool already exists in one of those locations, and attempts `go install` only for tools that are genuinely missing. This avoids repeated downloads when Go uses a custom binary directory. Tools that remain unavailable are reported before the scan starts. If screenshots are enabled but Chrome/Chromium cannot be found on `PATH`, it prints a warning before the scan starts. Ensure `~/go/bin` is on `PATH` for later terminal sessions. Automatic installation can fail because of network restrictions, Go-version incompatibilities, or OS package-manager problems; inspect the messages and logs rather than assuming installation succeeded.

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

**Beginner path:** run `python3 triageflow.py` with no arguments and follow the prompts. Choose **Standard** for all enabled stages or **Quick** to skip Subfinder, Nuclei, and screenshots. The reports now distinguish a true zero-result login scan from a stage that was skipped, failed, or never ran.

For direct CLI use:

```bash
# One authorized domain; a local SecLists wordlist is preferred, otherwise the bundled list runs first
python3 triageflow.py -u example.com

# One authorized domain, ask Subfinder to use all configured sources
python3 triageflow.py -u example.com --subfinder-all

# Add custom subdomain candidates from a wordlist
python3 triageflow.py -u example.com -w ./wordlists/subdomains-small.txt

# Also test HTTP virtual hosts using the same wordlist (authorized lab only)
python3 triageflow.py -u inlanefreight.local --no-subdomains \
  -w /path/to/subdomains-top1million-5000.txt --vhost-fuzz

# Use a custom wordlist first, then add Subfinder results
python3 triageflow.py -u example.com --subfinder-all -w ./wordlists/subdomains-small.txt

# Skip automatic default wordlist selection for this run
python3 triageflow.py -u example.com --no-wordlist

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
| `-w`, `--wordlist` | Custom subdomain wordlist, one label or hostname per line. Runs before Subfinder; resolved candidates are passed to httpx. |
| `-o`, `--output` | Base directory for results; each run gets its own timestamped subdirectory. |
| `--no-subdomains` | Skip Subfinder. Direct targets and any `-w` candidates can still be processed. |
| `--no-wordlist` | Skip automatic default wordlist detection. Cannot be combined with `-w`. |
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
| `--dns-threads` | Concurrent DNS workers for the custom wordlist; default `100`. |
| `--dns-timeout` | Per-query dnsx timeout in seconds; default `2`. |
| `--dns-resolvers` | Comma-separated DNS resolver IPs; by default the tool reads `/etc/resolv.conf`. Useful in labs with private DNS. |
| `--vhost-fuzz` | Run ffuf Host-header discovery with the wordlist, even if DNS finds subdomains. |
| `--vhost-rate` | Maximum ffuf virtual-host requests per second; default `100`. |
| `--vhost-max-time` | Maximum runtime per root domain for ffuf; default `120` seconds. |

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
- **DNS wordlist filtering:** ProjectDiscovery dnsx checks candidates concurrently with bounded per-query timeout and one retry. The configured system DNS resolvers are preferred, so private lab domains may resolve if the lab DNS is configured. A DNS response is not proof that a web service exists; httpx checks live HTTP/HTTPS separately. If a hostname ends in `.local`, passive public subdomain sources often have no useful public records; use the DNS resolver provided by the lab. If you interrupt discovery, TriageFlow returns cleanly without a Python stack trace.
- **Findings are not verdicts:** Nuclei results, software fingerprints, and NVD keyword/CPE hints can be false positives or require manual verification. Observed banners can be incomplete or inaccurate.
- **Tool compatibility:** command-line flags and JSON keys can vary between tool versions. If a stage fails, inspect its corresponding log and compare the command with that installed version's help output.
- **NVD rate limits:** unauthenticated NVD requests are throttled deliberately. The tool limits the number of queried product/version pairs; consider setting `NVD_API_KEY` for larger inventories.
- **No guarantee of full coverage:** passive discovery sources, DNS behavior, timeouts, rate limits, and scope all affect results.
- **Default-credential handling:** TriageFlow only creates a manual configuration-review checklist. It does not attempt authentication or submit default passwords.
- **Sensitive output:** screenshots, reports, and logs may contain tokens, internal hostnames, or personal data. Protect them and do not commit scan results to a public repository.
- **Safe use:** respect written scope, rate limits, and rules of engagement. Do not scan systems without authorization.

## Project status

Early-stage utility. The goal is to provide a transparent, repeatable orchestration layer—not to replace the underlying tools or automatically declare a system secure/insecure. Contributions should keep the README aligned with actual command-line behavior.
