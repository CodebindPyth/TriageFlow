# Changelog

## 2.0.3 — 2026-10-11

### Changed
- Direct CLI runs now use the bundled starter wordlist by default unless `--no-wordlist` is supplied; the guided wizard keeps its explicit wordlist choice.
- Wordlist DNS discovery now runs before passive Subfinder discovery, and resolved wordlist results are prioritized in the combined target file.
- Subfinder failures no longer discard successful wordlist discoveries; the pipeline continues with available direct and resolved targets and reports the failed stage.

### Fixed
- DNS wordlist errors no longer prevent the passive/direct-target stages from continuing.
- The no-live-target path records Nuclei and GoWitness as skipped instead of leaving the stages absent.
- HTML reports now display the actual run version rather than a hard-coded v2.0.1 string.
- Added tests for bundled wordlist availability, target order, and dynamic report versions.

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
