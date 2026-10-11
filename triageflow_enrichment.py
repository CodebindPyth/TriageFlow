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


def query_nvd_cves(fingerprints: list[dict], output_path: Path, max_products: int = 5) -> dict:
    """Query NVD for versioned product/version pairs; results are candidates, not verdicts."""
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
            # NVD documents lower request limits without an API key.
            time.sleep(0.7 if api_key else 6.2)
        params = urllib.parse.urlencode({
            "keywordSearch": f"{product} {version}",
            "resultsPerPage": "20",
        })
        request = urllib.request.Request(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}",
            headers={
                "User-Agent": "TriageFlow/1.0 (software-inventory; authorized assessment)",
                **({"apiKey": api_key} if api_key else {}),
            },
        )
        entry = {
            "product": product,
            "observed_version": version,
            "source_urls": sorted(url for url in urls if url),
            "query": f"{product} {version}",
            "match_method": "NVD keywordSearch; validate affected CPE/version range manually",
            "cves": [],
        }
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
            for item in payload.get("vulnerabilities", []):
                cve = item.get("cve") or {}
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue
                score, severity = _cvss(cve)
                entry["cves"].append({
                    "id": cve_id,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "published": cve.get("published", ""),
                    "last_modified": cve.get("lastModified", ""),
                    "cvss_score": score,
                    "severity": severity,
                    "description": _english_description(cve)[:1200],
                })
            entry["total_results"] = payload.get("totalResults", len(entry["cves"]))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            error = f"{product} {version}: {exc}"
            errors.append(error)
            entry["error"] = str(exc)
        results.append(entry)

    document = {
        "source": "NIST National Vulnerability Database API 2.0",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "queries_attempted": len(selected),
        "products_available": len(grouped),
        "api_key_configured": bool(api_key),
        "notice": (
            "Keyword matches are leads, not proof that the observed version is vulnerable. "
            "Verify the exact product, version range, configuration, and vendor advisory."
        ),
        "results": results,
        "errors": errors,
    }
    output_path.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
    markdown = [
        "# CVE lookup candidates", "",
        "Source: NIST National Vulnerability Database (NVD) API 2.0.", "",
        "**Important:** keyword results may not affect the exact observed version. Verify affected product/version ranges and vendor advisories before reporting a vulnerability.", "",
    ]
    if not results:
        markdown += ["No versioned products were suitable for an NVD query.", ""]
    for entry in results:
        markdown += [
            f"## {entry['product']} {entry['observed_version']}", "",
            f"- Source URLs: {', '.join(entry['source_urls']) or 'not available'}",
            f"- Candidates returned: {entry.get('total_results', len(entry['cves']))}",
        ]
        if entry.get("error"):
            markdown.append(f"- Lookup error: {entry['error']}")
        for cve in entry["cves"]:
            detail = cve["description"] or "No English description provided."
            suffix = f" — CVSS {cve['cvss_score']} {cve['severity']}".rstrip()
            markdown.append(f"- [{cve['id']}]({cve['url']}){suffix}: {detail}")
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
        "cve_candidates": sum(len(entry["cves"]) for entry in results),
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
    max_hosts: int = 50,
    timeout: float = 3.0,
) -> list[dict]:
    """Use rate-bounded GET requests to identify likely login pages; never submit credentials."""
    paths = [
        "/", "/login", "/signin", "/sign-in", "/admin/login",
        "/wp-login.php", "/user/login", "/administrator",
    ]
    opener = urllib.request.build_opener(_NoRedirect)
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
    findings = []
    seen_panels = set()
    for origin in origins:
        for path in paths:
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
            content_type = headers.get("Content-Type", "") if headers else ""
            if body and content_type and "html" not in content_type.lower():
                continue
            title = _page_title(body)
            has_password = bool(PASSWORD_INPUT_RE.search(body))
            has_form = bool(re.search(r"<form\b", body, re.I))
            login_words = bool(LOGIN_WORD_RE.search(re.sub(r"<[^>]+>", " ", body)))
            route_hint = bool(LOGIN_PATH_RE.search(urlsplit(target).path))
            redirect_to_login = status in (301, 302, 303, 307, 308) and bool(LOGIN_PATH_RE.search(location_path))
            if not (has_password or redirect_to_login or (route_hint and has_form and login_words)):
                continue
            panel_url = urljoin(target, location) if redirect_to_login else target
            dedupe_key = (origin, panel_url)
            if dedupe_key in seen_panels:
                continue
            seen_panels.add(dedupe_key)
            evidence = []
            if has_password:
                evidence.append("password input field")
            if redirect_to_login:
                evidence.append(f"redirect to {location_path or location}")
            if route_hint and has_form and login_words:
                evidence.append("login-like route with form and login terms")
            findings.append({
                "origin": origin,
                "login_url": panel_url,
                "detected_from": target,
                "status_code": status,
                "title": title,
                "evidence": "; ".join(evidence),
                "credentials_submitted": False,
            })
            break

    fields = ["origin", "login_url", "detected_from", "status_code", "title", "evidence", "credentials_submitted"]
    with output_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(findings)
    return findings
