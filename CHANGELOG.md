# Changelog

## 2.0.9 — 2026-10-12

### Fixed
- Collect multiple distinct login panels per origin instead of stopping at the first one, with per-origin page and panel limits to keep probing bounded.
- Fix HTML report screenshot-gallery CSS that contained literal `\\n` text rather than actual CSS rule breaks.
- Create collision-resistant timestamped output directories so fast consecutive runs do not fail with `FileExistsError`.
- Normalize fingerprint URL origins without lowercasing case-sensitive path names.
- Fix the form-tag detection regex used by login discovery and add regression tests for multi-panel detection, CSS rendering, URL path case, and output directory uniqueness.

## 2.0.8 — 2026-10-11

### Fixed / Changed
- Login discovery now checks expanded common paths and follows login-like links found in same-origin HTML pages, with a bounded per-origin request budget; it remains GET-only and never submits credentials.
- Added `login-discovery-summary.json` with coverage metrics and explicit limitations.
- HTML report now includes a screenshot gallery referencing local files in the `gowitness/` directory and a login discovery coverage table.
- Software fingerprints for the same URL/product/version are merged across `tech`, `webserver`, and `server` sources to remove duplicate rows.
- `--bruteforce-direct` bypasses the standalone `dnsx` stage only; Subfinder remains enabled unless `--no-subdomains` is requested.
- When no live URLs exist, downstream stages are reported as not run due to missing inputs rather than as manually skipped.
- Added tests for linked custom login routes, duplicate-fingerprint merging and report screenshot rendering.

## 2.0.7 — 2026-10-11

### Fixed
- Print a progress heartbeat every 10 seconds for long-running external tools instead of leaving the terminal silent while waiting.
- During the httpx stage, report the number of JSONL result records saved incrementally and show the combined target count and elapsed runtime.
- Stop and clean up the child process when Ctrl+C interrupts a running pipeline stage.
- Added a regression test for heartbeat output and incremental JSONL record counting.

## 2.0.6 — 2026-10-11

### Fixed
- Preserve the supplied HTTP/HTTPS base URL when the target is `www.example` but wordlist discovery normalizes its root to `example`.
- Reject scoped, link-local, multicast, and unspecified IP addresses passed as explicit DNS resolvers.
- Added regression tests for normalized `www.` base URL selection and wordlist candidate scope/validation.

## 2.0.5 — 2026-10-11

### Added
- Added `--bruteforce-direct` to the main `triageflow.py` pipeline: wordlist-generated host candidates are fed directly to httpx, bypassing the separate dnsx and Subfinder stages.
- Added `--bruteforce-rate` (default 50 requests/second) and saved generated candidates plus live HTTP candidate matches in `wordlist-candidates.txt` and `wordlist-live.txt`.
- Normalize a leading `www.` when deriving a root for subdomain wordlist generation.
- Added the standalone `vhost_direct.py` helper for direct Host-header discovery in authorized labs.

## 2.0.4 — 2026-10-11

### Fixed
- Ignore interface-scoped and link-local IPv6 nameservers read from `/etc/resolv.conf` when constructing dnsx's comma-separated resolver list.
- Log the selected wordlist path and count of non-empty input entries before resolving, making unexpectedly large candidate counts diagnosable.
- Added tests for scoped/link-local resolver filtering.

## 2.0.3 — 2026-10-11

### Changed
- Direct CLI runs first look for an existing SecLists DNS wordlist (`Discovery/DNS/subdomains-top1million-5000.txt`) and fall back to the bundled starter list; `--no-wordlist` opts out, while the wizard keeps its explicit choice.
- Wordlist DNS discovery now runs before passive Subfinder discovery, and resolved wordlist results are prioritized in the combined target file.
- Subfinder failures no longer discard successful wordlist discoveries; the pipeline continues with available direct and resolved targets and reports the failed stage.

### Fixed
- DNS wordlist errors no longer prevent the passive/direct-target stages from continuing.
- The no-live-target path records Nuclei and GoWitness as skipped instead of leaving the stages absent.
- HTML reports now display the actual run version rather than a hard-coded v2.0.1 string.
- IPv6 targets are no longer truncated at the first colon during hostname parsing.
- Added tests for bundled wordlist availability, local wordlist selection, target order, dynamic report versions, and IPv6 parsing.

## 2.0.2 — 2026-10-11

### Fixed
- Tool preflight now checks `PATH`, `~/go/bin`, and configured Go `GOBIN`/`GOPATH` binary directories before installing anything.
- Existing Go tools are reused; `go install` is attempted only for binaries that are still missing after checking those paths.
- Added a regression test for an already-installed tool in a custom `GOBIN` directory.

## 2.0.1 — 2026-10-11

### Fixed
- Replaced thousands of serial DNS lookups with parallel dnsx resolution, bounded timeouts, wildcard filtering, and periodic progress messages.
- Ctrl+C during wordlist DNS checks now stops cleanly and saves the partial status/report where possible.
- Private lab DNS resolvers can be supplied from `/etc/resolv.conf` or with `--dns-resolvers`.

### Added
- If both DNS and Subfinder find no subdomains, ask before running ffuf HTTP virtual-host discovery with the same wordlist. The `--vhost-fuzz` flag enables the check explicitly.
- Virtual-host findings are stored in CSV, JSON and text files and displayed in the HTML report.
- Unit tests for target scoping and virtual-host outputs.

## 2.0.0 — 2026-10-11

### Added
- Guided setup lets the user independently choose screenshot capture and consolidated HTML report generation.
- Screenshot preflight warns when no Chrome/Chromium browser is available on PATH.
- Single-file report.html combines asset inventory, software fingerprints, NVD CVE candidates, login panels, default-account hygiene review, Nuclei findings, and stage results.
- asset-inventory.csv adds an easy-to-filter asset list using fields reported by ProjectDiscovery httpx.
- default-credentials-review.md and .csv provide a product-aware manual configuration checklist. No credentials are submitted or tested.
- CVE candidates now show per-result triage labels based on NVD CPE applicability criteria when present, with keyword-only results clearly distinguished.
- Added --version and --no-html-report options.
- Added unit tests for CPE triage, reports, output escaping, wizard selection, and screenshot options.

### Changed
- Replaced sequential `socket.getaddrinfo` wordlist checks with parallel ProjectDiscovery dnsx resolution.
- Bounded DNS waiting with a two-second query timeout, one attempt, 100 workers, and a progress message every 10 seconds.
- Enabled dnsx wildcard DNS filtering; reads system DNS resolvers from `/etc/resolv.conf` and checks the system hosts file for private lab names.
- Added `--dns-resolvers`, `--dns-threads`, and `--dns-timeout` CLI options.
- Ctrl+C during the wordlist DNS stage stops without a Python traceback and saves the partial status/report when possible.
- Ignores malformed wordlist entries and full hostnames belonging to another root domain.
- Greek quickstart and README explain how to use v2 and interpret each report.
- GoWitness captures screenshots from the same live.txt list used by downstream stages, so responding discovered subdomains are included when screenshot capture is enabled.

### Important limitations
- CPE version comparisons are heuristic triage hints and must be checked against vendor advisories and NVD applicability details.
- Product versions that are hidden or missing from server responses cannot always be fingerprinted.
- Default credentials are not automatically tested; validate account hygiene using an authorized, controlled procedure.
- Reports and screenshots can contain sensitive information. Keep scan artifacts private.
