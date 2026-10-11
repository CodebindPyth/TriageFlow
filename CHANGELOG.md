# Changelog

## 2.0.0 — 2026-10-11

### Added
- Guided setup lets the user independently choose screenshot capture and consolidated HTML report generation.
- Single-file report.html combines asset inventory, software fingerprints, NVD CVE candidates, login panels, default-account hygiene review, Nuclei findings, and stage results.
- asset-inventory.csv adds an easy-to-filter asset list using fields reported by ProjectDiscovery httpx.
- default-credentials-review.md and .csv provide a product-aware manual configuration checklist. No credentials are submitted or tested.
- CVE candidates now show per-result triage labels based on NVD CPE applicability criteria when present, with keyword-only results clearly distinguished.
- Added --version and --no-html-report options.
- Added unit tests for CPE triage, reports, output escaping, wizard selection, and screenshot options.

### Changed
- Greek quickstart and README explain how to use v2 and interpret each report.
- GoWitness captures screenshots from the same live.txt list used by downstream stages, so responding discovered subdomains are included when screenshot capture is enabled.

### Important limitations
- CPE version comparisons are heuristic triage hints and must be checked against vendor advisories and NVD applicability details.
- Product versions that are hidden or missing from server responses cannot always be fingerprinted.
- Default credentials are not automatically tested; validate account hygiene using an authorized, controlled procedure.
- Reports and screenshots can contain sensitive information. Keep scan artifacts private.
