#!/usr/bin/env python3
"""Deterministic cross-tool evidence correlation and labeled-fixture evaluation.

This module assesses whether scanner records are linked to the same observed assets.
It deliberately does not claim that a scanner result or CVE candidate is a confirmed
vulnerability. It performs no network requests and never launches security tools.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from itertools import zip_longest
from pathlib import Path
from urllib.parse import urlsplit


def _host(value: object) -> str:
    """Extract a normalized hostname from a URL, host:port, or bare hostname."""
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text if "://" in text or text.startswith("//") else "//" + text)
        host = parsed.hostname or ""
    except ValueError:
        return ""
    return host.casefold().rstrip(".")


def _product_key(value: object) -> str:
    product = re.sub(r"[^a-z0-9]", "", str(value or "").casefold())
    aliases = {
        "apache": "apachehttpserver",
        "httpd": "apachehttpserver",
        "apachehttpserver": "apachehttpserver",
        "tomcat": "apachetomcat",
        "apachetomcat": "apachetomcat",
    }
    return aliases.get(product, product)


def _version_key(value: object) -> str:
    return str(value or "").strip().casefold()


def _fingerprint_index(fingerprints: list[dict]) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = defaultdict(list)
    for item in fingerprints:
        host = _host(item.get("url"))
        if host:
            index[host].append(item)
    return index


def _asset_index(assets: list[dict]) -> dict[str, dict]:
    index = {}
    for item in assets:
        host = _host(item.get("hostname") or item.get("url"))
        if host and host not in index:
            index[host] = item
    return index


def _classify_cve_candidate(candidate: dict, fingerprints: list[dict]) -> dict:
    product = _product_key(candidate.get("product"))
    version = _version_key(candidate.get("observed_version"))
    product_fingerprints = [
        row for row in fingerprints
        if _product_key(row.get("product")) == product
        and _version_key(row.get("version")) == version
        and product and version
    ]
    source_hosts = sorted({
        _host(url) for url in candidate.get("source_urls", []) if _host(url)
    })
    fingerprint_hosts = sorted({
        _host(row.get("url")) for row in product_fingerprints if _host(row.get("url"))
    })
    same_host = sorted(set(source_hosts) & set(fingerprint_hosts))
    match_text = str(candidate.get("match_confidence", "")).casefold()

    if match_text.startswith("cpe applicability supports"):
        if same_host:
            classification = "linked_cpe_supported_candidate"
            evidence_confidence = "high"
        elif product_fingerprints:
            classification = "fingerprint_seen_but_source_host_unlinked"
            evidence_confidence = "medium"
        else:
            classification = "cpe_supported_candidate_without_fingerprint"
            evidence_confidence = "low"
    elif match_text.startswith("cpe product matched"):
        classification = "cpe_product_version_unconfirmed"
        evidence_confidence = "low"
    else:
        classification = "keyword_only_lead"
        evidence_confidence = "low"

    return {
        "candidate_id": str(candidate.get("candidate_id") or candidate.get("id") or ""),
        "product": str(candidate.get("product") or ""),
        "observed_version": str(candidate.get("observed_version") or ""),
        "match_confidence": str(candidate.get("match_confidence") or "unknown"),
        "classification": classification,
        "evidence_confidence": evidence_confidence,
        "source_hosts": source_hosts,
        "matching_fingerprint_hosts": fingerprint_hosts,
        "same_host_correlation": same_host,
        "matching_fingerprint_count": len(product_fingerprints),
        "validation_state": "candidate_not_confirmed",
    }


def correlate_evidence(evidence: dict) -> dict:
    """Correlate saved Nuclei, CVE, asset, software fingerprint, and login artifacts."""
    assets = evidence.get("assets", []) if isinstance(evidence.get("assets"), list) else []
    fingerprints = evidence.get("software_fingerprints", []) if isinstance(evidence.get("software_fingerprints"), list) else []
    nuclei = evidence.get("nuclei_findings", []) if isinstance(evidence.get("nuclei_findings"), list) else []
    cves = evidence.get("cve_candidates", []) if isinstance(evidence.get("cve_candidates"), list) else []
    panels = evidence.get("login_panels", []) if isinstance(evidence.get("login_panels"), list) else []

    assets_by_host = _asset_index(assets)
    fingerprints_by_host = _fingerprint_index(fingerprints)

    duplicate_counts = Counter()
    for item in nuclei:
        host = _host(item.get("matched_at") or item.get("host"))
        template_id = str(item.get("template_id") or item.get("template-id") or item.get("name") or "unknown")
        duplicate_counts[(host, template_id.casefold())] += 1

    correlated_nuclei = []
    for item in nuclei:
        host = _host(item.get("matched_at") or item.get("host"))
        template_id = str(item.get("template_id") or item.get("template-id") or item.get("name") or "unknown")
        asset = assets_by_host.get(host)
        host_fingerprints = fingerprints_by_host.get(host, [])
        if asset and host_fingerprints:
            classification, strength = "corroborated_scanner_finding", "strong"
        elif asset:
            classification, strength = "asset_matched_scanner_finding", "partial"
        elif host_fingerprints:
            classification, strength = "fingerprint_context_asset_missing", "partial"
        else:
            classification, strength = "unlinked_scanner_finding", "weak"
        correlated_nuclei.append({
            "template_id": template_id,
            "name": str(item.get("name") or ""),
            "severity_as_reported": str(item.get("severity_as_reported") or "unknown"),
            "matched_at": str(item.get("matched_at") or item.get("host") or ""),
            "host": host,
            "classification": classification,
            "evidence_strength": strength,
            "asset_record_found": bool(asset),
            "same_host_fingerprint_count": len(host_fingerprints),
            "duplicate_count_for_host_and_template": duplicate_counts[(host, template_id.casefold())],
            "validation_state": "scanner_reported_unverified",
        })

    correlated_cves = [_classify_cve_candidate(candidate, fingerprints) for candidate in cves]

    panel_context = []
    for panel in panels:
        host = _host(panel.get("origin") or panel.get("login_url"))
        host_fingerprints = fingerprints_by_host.get(host, [])
        panel_context.append({
            "origin": str(panel.get("origin") or ""),
            "login_url": str(panel.get("login_url") or ""),
            "host": host,
            "observed_products": sorted({
                f"{row.get('product', '')} {row.get('version', '')}".strip()
                for row in host_fingerprints if row.get("product")
            }),
            "classification": "login_panel_with_fingerprint_context" if host_fingerprints else "login_panel_without_fingerprint_context",
            "validation_state": "login_panel_is_not_a_vulnerability",
        })

    versions_by_product: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in fingerprints:
        host = _host(row.get("url"))
        product = _product_key(row.get("product"))
        version = str(row.get("version") or "").strip()
        if host and product and version:
            versions_by_product[(host, product)].add(version)
    conflicts = [
        {"host": host, "product_key": product, "observed_versions": sorted(versions)}
        for (host, product), versions in sorted(versions_by_product.items())
        if len(versions) > 1
    ]

    summary = {
        "asset_records": len(assets),
        "software_fingerprints": len(fingerprints),
        "nuclei_records": len(nuclei),
        "cve_candidates": len(cves),
        "login_panels": len(panels),
        "corroborated_nuclei_findings": sum(x["classification"] == "corroborated_scanner_finding" for x in correlated_nuclei),
        "unlinked_nuclei_findings": sum(x["classification"] == "unlinked_scanner_finding" for x in correlated_nuclei),
        "linked_cpe_supported_candidates": sum(x["classification"] == "linked_cpe_supported_candidate" for x in correlated_cves),
        "keyword_only_cve_leads": sum(x["classification"] == "keyword_only_lead" for x in correlated_cves),
        "software_version_conflicts": len(conflicts),
        "interpretation": "Correlation measures evidence linkage only. It does not prove exploitability or confirm a vulnerability.",
    }
    return {
        "schema_version": 1,
        "summary": summary,
        "nuclei_findings": correlated_nuclei,
        "cve_candidates": correlated_cves,
        "login_panel_context": panel_context,
        "software_version_conflicts": conflicts,
    }


def evaluate_labeled_fixtures(fixture_path: Path) -> dict:
    """Evaluate deterministic classifications against explicitly labeled regression cases."""
    document = json.loads(fixture_path.read_text(encoding="utf-8"))
    cases = document.get("cases", [])
    cve_total = cve_correct = nuclei_total = nuclei_correct = 0
    details = []
    for case in cases:
        result = correlate_evidence(case.get("evidence", {}))
        expected = case.get("expected", {})
        actual_cves = [item["classification"] for item in result["cve_candidates"]]
        actual_nuclei = [item["classification"] for item in result["nuclei_findings"]]
        expected_cves = expected.get("cve_classifications", [])
        expected_nuclei = expected.get("nuclei_classifications", [])
        # Count unexpected/missing classifications as errors rather than silently
        # allowing zip() to truncate the comparison.
        cve_pairs = list(zip_longest(actual_cves, expected_cves, fillvalue=None))
        nuclei_pairs = list(zip_longest(actual_nuclei, expected_nuclei, fillvalue=None))
        cve_total += len(cve_pairs)
        nuclei_total += len(nuclei_pairs)
        cve_hits = sum(actual == expected_value for actual, expected_value in cve_pairs)
        nuclei_hits = sum(actual == expected_value for actual, expected_value in nuclei_pairs)
        cve_correct += cve_hits
        nuclei_correct += nuclei_hits
        details.append({
            "case_id": case.get("id", "unknown"),
            "cve_expected": expected_cves,
            "cve_actual": actual_cves,
            "cve_correct": cve_hits,
            "nuclei_expected": expected_nuclei,
            "nuclei_actual": actual_nuclei,
            "nuclei_correct": nuclei_hits,
        })
    total = cve_total + nuclei_total
    correct = cve_correct + nuclei_correct
    return {
        "fixture_name": document.get("name", fixture_path.name),
        "cases": len(cases),
        "labeled_cve_classifications": cve_total,
        "cve_classification_accuracy": round(cve_correct / cve_total, 4) if cve_total else None,
        "labeled_nuclei_classifications": nuclei_total,
        "nuclei_classification_accuracy": round(nuclei_correct / nuclei_total, 4) if nuclei_total else None,
        "total_labeled_classifications": total,
        "overall_classification_accuracy": round(correct / total, 4) if total else None,
        "passed": correct == total and total > 0,
        "details": details,
        "note": "This is labeled synthetic regression coverage for deterministic correlation rules, not a measure of real-world vulnerability detection accuracy.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Correlate saved evidence or evaluate the labeled regression fixture.")
    parser.add_argument("--evaluate", type=Path, help="Evaluate a labeled fixture JSON file; no targets are contacted")
    parser.add_argument("--input", type=Path, help="JSON file containing evidence arrays to correlate")
    parser.add_argument("--output", type=Path, help="Write correlation JSON to this path")
    args = parser.parse_args()
    if args.evaluate:
        try:
            report = evaluate_labeled_fixtures(args.evaluate)
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            parser.error(f"Could not evaluate fixture: {exc}")
        print(json.dumps(report, indent=2))
        return 0 if report["passed"] else 1
    if args.input:
        try:
            evidence = json.loads(args.input.read_text(encoding="utf-8"))
            report = correlate_evidence(evidence)
            serialized = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
            if args.output:
                args.output.write_text(serialized, encoding="utf-8")
            else:
                print(serialized, end="")
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            parser.error(f"Could not correlate input: {exc}")
        return 0
    parser.error("Provide --evaluate or --input.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
