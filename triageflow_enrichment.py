"""Passive software fingerprinting, CVE candidate lookup, and login-panel discovery.

This module never submits credentials or attempts authentication.
"""
from __future__ import annotations

import csv
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlsplit

VERSION_RE = re.compile(
    r"(?P<product>[A-Za-z][A-Za-z0-9._ +()\-]{0,59}?)(?:/|:|\s+)"
    r"(?:v)?(?P<version>\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?)",
    re.IGNORECASE,
)
PASSWORD_INPUT_RE = re.compile(
    r"<input\b(?=[^>]*(?:type\s*=\s*['\"]?password\b|"
    r"name\s*=\s*['\"]?(?:password|passwd|pwd)\b))[^>]*>",
    re.IGNORECASE,
)
TITLE_RE = re.compile(r"<title\b[^>]*>(.*?)</title\s*>", re.IGNORECASE | re.DOTALL)
LOGIN_WORD_RE = re.compile(r"\b(log\s?in|sign\s?in|password|username|authenticate)\b", re.I)
LOGIN_PATH_RE = re.compile(r"(?:login|log-in|signin|sign-in|authenticate|auth|administrator|admin)", re.I)
IGNORED_CVE_PRODUCTS = {
    "http", "https", "http/2", "http/3", "hsts", "tls", "ssl", "gzip", "brotli",
    "cloudflare", "cloudfront", "akamai", "varnish",
}
CVE_PRODUCT_ALIASES = {
    "apache": "Apache HTTP Server",
    "httpd": "Apache HTTP Server",
    "apache http server": "Apache HTTP Server",
    "tomcat": "Apache Tomcat",
}


def read_httpx_jsonl(path: Path) -> list[dict]:
    """Read JSONL output from ProjectDiscovery httpx, ignoring malformed lines."""
    records = []
    if not path.is_file():
        return records
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def httpx_url(record: dict) -> str:
    """Return the best URL field found in a httpx JSON object."""
    for key in ("url", "input", "final_url"):
        value = record.get(key)
        if isinstance(value, str) and value.startswith(("http://", "https://")):
            return value
    return ""


def _values(value) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return []


def collect_fingerprints(records: list[dict]) -> list[dict]:
    """Normalize version/product observations from httpx's tech/server fields."""
    results = []
    seen = set()
    for record in records:
        url = httpx_url(record)
        observations = []
        for key in ("tech", "technologies", "webserver", "server"):
            for raw in _values(record.get(key)):
                observations.append((key, raw.strip()))
        for source, raw in observations:
            match = VERSION_RE.search(raw)
            if match:
                product = " ".join(match.group("product").split()).strip(" ._:-")
                version = match.group("version").strip()
            else:
                product = " ".join(raw.split()).strip()
                version = ""
            if not product:
                continue
            key = (url, product.casefold(), version, source)
            if key in seen:
                continue
            seen.add(key)
            results.append({
                "url": url,
                "product": product,
                "version": version,
                "source": source,
                "raw_fingerprint": raw,
                "status_code": record.get("status_code", ""),
                "title": record.get("title", ""),
            })
    return results


def write_software_inventory(records: list[dict], output_path: Path) -> list[dict]:
    """Write observed products and any parsed versions to CSV."""
    fingerprints = collect_fingerprints(records)
    fields = ["url", "product", "version", "source", "raw_fingerprint", "status_code", "title"]
    with output_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(fingerprints)
    return fingerprints


def _cvss(cve: dict) -> tuple[str, str]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        data = values[0].get("cvssData") or {}
        score = data.get("baseScore", "")
        severity = data.get("baseSeverity") or values[0].get("baseSeverity") or ""
        return (str(score) if score != "" else "", str(severity))
    return "", ""


def _english_description(cve: dict) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if item.get("lang") == "en":
            return str(item.get("value", "")).replace("\n", " ").strip()
    return ""


def _version_tokens(value: str) -> tuple:
    """Approximate a version comparison using numeric and alphabetic components."""
    return tuple(
        (0, int(token)) if token.isdigit() else (1, token.casefold())
        for token in re.findall(r"\d+|[A-Za-z]+", value)
    )


def _compare_versions(left: str, right: str) -> int | None:
    """Compare common numeric versions; return None for ambiguous vendor schemes."""
    a, b = list(_version_tokens(left)), list(_version_tokens(right))
    length = max(len(a), len(b))
    a.extend([(0, 0)] * (length - len(a)))
    b.extend([(0, 0)] * (length - len(b)))
    for first, second in zip(a, b):
        if first == second:
            continue
        # Mixed numeric/text component comparisons can be vendor-specific.
        if first[0] != second[0]:
            return None
        return -1 if first[1] < second[1] else 1
    return 0


def _iter_cpe_matches(value):
    """Recursively walk NVD configurations and yield CPE applicability objects."""
    if isinstance(value, dict):
        matches = value.get("cpeMatch")
        if isinstance(matches, list):
            for match in matches:
                if isinstance(match, dict):
                    yield match
        for key, child in value.items():
            if key != "cpeMatch":
                yield from _iter_cpe_matches(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_cpe_matches(child)


def _cpe_product_matches(criteria: str, product: str) -> bool:
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0].casefold() != "cpe":
        return False
    observed = re.sub(r"[^a-z0-9]", "", product.casefold())
    vendor = re.sub(r"[^a-z0-9]", "", parts[3].replace("\\", "").casefold())
    cpe_product = re.sub(r"[^a-z0-9]", "", parts[4].replace("\\", "").casefold())
    combined = vendor + cpe_product
    return bool(observed) and (
        observed == cpe_product
        or observed == combined
        or (len(observed) >= 5 and observed in cpe_product)
        or (len(cpe_product) >= 5 and cpe_product in observed)
    )


def _classify_cve_match(cve: dict, product: str, version: str) -> tuple[str, list[str]]:
    """Compare the observed product/version to NVD CPE criteria when available."""
    related = []
    positive = []
    criteria_seen = []
    for match in _iter_cpe_matches(cve.get("configurations", [])):
        if match.get("vulnerable") is False:
            continue
        criteria = str(match.get("criteria") or match.get("cpe23Uri") or "")
        if not criteria or not _cpe_product_matches(criteria, product):
            continue
        criteria_seen.append(criteria)
        parts = criteria.split(":")
        cpe_version = parts[5].replace("\\", "") if len(parts) > 5 else "*"
        start_in = str(match.get("versionStartIncluding") or "")
        start_ex = str(match.get("versionStartExcluding") or "")
        end_in = str(match.get("versionEndIncluding") or "")
        end_ex = str(match.get("versionEndExcluding") or "")

        if cpe_version not in ("*", "-", ""):
            if cpe_version.casefold() == version.casefold():
                positive.append(criteria)
            continue

        # Ranges are useful when version tokens can be compared. Any ambiguous
        # cross-scheme comparison is classified as unknown instead of a positive match.
        inside = True
        known = False
        if start_in:
            cmp = _compare_versions(version, start_in)
            if cmp is None:
                known = False
                inside = False
            elif cmp < 0:
                inside = False
                known = True
            else:
                known = True
        if start_ex:
            cmp = _compare_versions(version, start_ex)
            if cmp is None:
                known = False
                inside = False
            elif cmp <= 0:
                inside = False
                known = True
            else:
                known = True
        if end_in:
            cmp = _compare_versions(version, end_in)
            if cmp is None:
                known = False
                inside = False
            elif cmp > 0:
                inside = False
                known = True
            else:
                known = True
        if end_ex:
            cmp = _compare_versions(version, end_ex)
            if cmp is None:
                known = False
                inside = False
            elif cmp >= 0:
                inside = False
                known = True
            else:
                known = True
        if inside and known:
            positive.append(criteria)
        elif not (start_in or start_ex or end_in or end_ex):
            related.append(criteria)

    if positive:
        return "CPE applicability supports observed version (verify vendor advisory)", list(dict.fromkeys(positive))
    if criteria_seen:
        if related:
            return "CPE product matched; affected version range is unspecified", list(dict.fromkeys(related))
        return "CPE product found, but observed version was not confirmed in matched criteria", list(dict.fromkeys(criteria_seen))
    return "Keyword-only candidate; no matching product CPE criteria found", []


def query_nvd_cves(fingerprints: list[dict], output_path: Path, max_products: int = 5) -> dict:
    """Query NVD with bounded keyword lookups and triage each CVE against its CPE applicability."""
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    grouped = {}
    for item in fingerprints:
        product = str(item.get("product", "")).strip()
        version = str(item.get("version", "")).strip()
        if not product or not version or product.casefold() in IGNORED_CVE_PRODUCTS:
            continue
        query_product = CVE_PRODUCT_ALIASES.get(product.casefold(), product)
        key = (query_product, version)
        grouped.setdefault(key, set()).add(item.get("url", ""))

    selected = list(grouped.items())[:max(1, max_products)]
    results = []
    errors = []
    for index, ((product, version), urls) in enumerate(selected):
        if index:
            # NVD applies a lower request quota without an API key.
            time.sleep(0.7 if api_key else 6.2)
        params = urllib.parse.urlencode({
            "keywordSearch": f"{product} {version}",
            "resultsPerPage": "20",
        })
        request = urllib.request.Request(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}",
            headers={
                "User-Agent": "TriageFlow/2.0 (software-inventory; authorized assessment)",
                **({"apiKey": api_key} if api_key else {}),
            },
        )
        entry = {
            "product": product,
            "observed_version": version,
            "source_urls": sorted(url for url in urls if url),
            "query": f"{product} {version}",
            "match_method": "NVD keywordSearch plus local CPE applicability triage",
            "cves": [],
        }
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
            for item in payload.get("vulnerabilities", []):
                cve = item.get("cve") or {}
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue
                score, severity = _cvss(cve)
                match_confidence, matching_cpes = _classify_cve_match(cve, product, version)
                entry["cves"].append({
                    "id": cve_id,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "published": cve.get("published", ""),
                    "last_modified": cve.get("lastModified", ""),
                    "cvss_score": score,
                    "severity": severity,
                    "description": _english_description(cve)[:1200],
                    "match_confidence": match_confidence,
                    "matching_cpes": matching_cpes,
                })
            # Prioritize CPE matches first, then CVSS, and retain keyword-only leads too.
            entry["cves"].sort(
                key=lambda cve: (
                    0 if cve["match_confidence"].startswith("CPE applicability supports") else
                    1 if cve["match_confidence"].startswith("CPE product matched") else
                    2,
                    -(float(cve["cvss_score"]) if str(cve["cvss_score"]).replace(".", "", 1).isdigit() else 0.0),
                )
            )
            entry["total_results"] = payload.get("totalResults", len(entry["cves"]))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            error = f"{product} {version}: {exc}"
            errors.append(error)
            entry["error"] = str(exc)
        results.append(entry)

    all_cves = [cve for entry in results for cve in entry["cves"]]
    document = {
        "source": "NIST National Vulnerability Database API 2.0",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "queries_attempted": len(selected),
        "products_available": len(grouped),
        "api_key_configured": bool(api_key),
        "notice": (
            "NVD keyword search results are leads. CPE classifications are automated triage hints, "
            "not a final affected-version verdict; confirm vendor advisories, version ranges, and configuration."
        ),
        "results": results,
        "summary": {
            "cve_candidates": len(all_cves),
            "cpe_version_supported": sum(
                1 for cve in all_cves
                if cve["match_confidence"].startswith("CPE applicability supports")
            ),
            "keyword_only": sum(
                1 for cve in all_cves
                if cve["match_confidence"].startswith("Keyword-only")
            ),
        },
        "errors": errors,
    }
    output_path.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
    markdown = [
        "# CVE lookup candidates", "",
        "Source: NIST National Vulnerability Database (NVD) API 2.0.", "",
        "**Important:** CPE classifications are automated triage hints, not a final verdict. Verify the affected-version range, vendor advisory, configuration, and whether the reported product is truly running on the asset.", "",
        f"- Distinct product/version queries: {len(selected)}",
        f"- CVE keyword candidates: {len(all_cves)}",
        f"- CPE version-support hints: {document['summary']['cpe_version_supported']}",
        f"- Keyword-only candidates: {document['summary']['keyword_only']}", "",
    ]
    if not results:
        markdown += ["No versioned products were suitable for an NVD query.", ""]
    for result in results:
        markdown += [
            f"## {result['product']} {result['observed_version']}", "",
            f"- Source URLs: {', '.join(result['source_urls']) or 'not available'}",
            f"- NVD keyword result count: {result.get('total_results', len(result['cves']))}",
            f"- Lookup method: {result['match_method']}",
        ]
        if result.get("error"):
            markdown.append(f"- Lookup error: {result['error']}")
        for cve in result["cves"]:
            detail = cve["description"] or "No English description provided."
            suffix = f" — CVSS {cve['cvss_score']} {cve['severity']}".rstrip()
            markdown.append(
                f"- [{cve['id']}]({cve['url']}){suffix} "
                f"**[{cve['match_confidence']}]**: {detail}"
            )
            if cve["matching_cpes"]:
                markdown.append("  - Matching CPE criteria: " + "; ".join(cve["matching_cpes"]))
        markdown.append("")
    if len(grouped) > len(selected):
        markdown += [
            f"Note: {len(grouped) - len(selected)} additional product/version pairs were skipped by the configured limit ({max_products}).",
            "Increase --max-cve-products or set NVD_API_KEY to use the higher documented API quota.", "",
        ]
    output_path.with_suffix(".md").write_text("\n".join(markdown) + "\n", encoding="utf-8")
    if errors:
        output_path.with_suffix(".errors.txt").write_text("\n".join(errors) + "\n", encoding="utf-8")
    return {
        "queries_attempted": len(selected),
        "products_available": len(grouped),
        "errors": len(errors),
        "cve_candidates": len(all_cves),
        "cpe_version_supported": document["summary"]["cpe_version_supported"],
        "keyword_only": document["summary"]["keyword_only"],
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects to unknown hosts while probing a scoped URL."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _page_title(body: str) -> str:
    match = TITLE_RE.search(body)
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200] if match else ""


def detect_login_panels(
    live_urls: list[str],
    output_path: Path,
    max_hosts: int = 25,
    timeout: float = 2.5,
) -> list[dict]:
    """Use bounded GET requests to identify likely login pages; never submit credentials."""
    from concurrent.futures import ThreadPoolExecutor

    paths = ["/", "/login", "/signin", "/sign-in", "/admin/login",
             "/wp-login.php", "/user/login", "/administrator"]
    origins = []
    for value in live_urls:
        candidate = value if value.startswith(("http://", "https://")) else f"http://{value}"
        parsed = urlsplit(candidate)
        if not parsed.scheme or not parsed.netloc:
            continue
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in origins:
            origins.append(origin)
    origins = origins[:max(1, max_hosts)]

    def probe_origin(origin: str) -> dict | None:
        opener = urllib.request.build_opener(_NoRedirect)
        for path in paths:
            time.sleep(0.05)
            target = urljoin(origin + "/", path.lstrip("/"))
            request = urllib.request.Request(
                target,
                headers={
                    "User-Agent": "TriageFlow/1.0 (authorized login-panel discovery)",
                    "Accept": "text/html,application/xhtml+xml,*/*;q=0.3",
                },
            )
            try:
                response = opener.open(request, timeout=timeout)
                status = getattr(response, "status", 200)
                headers = response.headers
                body = response.read(512_000).decode("utf-8", errors="replace")
                response.close()
            except urllib.error.HTTPError as exc:
                status = exc.code
                headers = exc.headers
                body = exc.read(512_000).decode("utf-8", errors="replace") if exc.fp else ""
            except (urllib.error.URLError, TimeoutError, OSError):
                continue

            location = headers.get("Location", "") if headers else ""
            location_path = urlsplit(location).path if location else ""
            redirect_to_login = (
                status in (301, 302, 303, 307, 308)
                and bool(LOGIN_PATH_RE.search(location_path))
            )
            content_type = headers.get("Content-Type", "") if headers else ""
            if body and content_type and "html" not in content_type.lower() and not redirect_to_login:
                continue

            title = _page_title(body)
            has_password = bool(PASSWORD_INPUT_RE.search(body))
            has_form = bool(re.search(r"<form\b", body, re.I))
            login_words = bool(LOGIN_WORD_RE.search(re.sub(r"<[^>]+>", " ", body)))
            route_hint = bool(LOGIN_PATH_RE.search(urlsplit(target).path))
            if not (has_password or redirect_to_login or (route_hint and has_form and login_words)):
                continue

            panel_url = target
            evidence = []
            if has_password:
                evidence.append("password input field")
            if redirect_to_login:
                redirected_url = urljoin(target, location)
                if urlsplit(redirected_url).netloc.lower() == urlsplit(origin).netloc.lower():
                    panel_url = redirected_url
                    evidence.append(f"redirect to {location_path or location}")
                else:
                    evidence.append("login-like redirect to another host (not followed)")
            if route_hint and has_form and login_words:
                evidence.append("login-like route with form and login terms")
            return {
                "origin": origin,
                "login_url": panel_url,
                "detected_from": target,
                "status_code": status,
                "title": title,
                "evidence": "; ".join(evidence),
                "credentials_submitted": False,
            }
        return None

    # Bound concurrency so one unresponsive origin does not stall the whole run.
    with ThreadPoolExecutor(max_workers=5) as pool:
        findings = [item for item in pool.map(probe_origin, origins) if item is not None]

    fields = ["origin", "login_url", "detected_from", "status_code", "title", "evidence", "credentials_submitted"]
    with output_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(findings)
    return findings
