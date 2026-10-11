"""Reporting helpers for TriageFlow v2.

Reports are local, self-contained and use only Python's standard library.
No function in this module attempts authentication or submits credentials.
"""
from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from urllib.parse import urlsplit


ASSET_FIELDS = [
    "url", "hostname", "ip_addresses", "status_code", "title", "webserver",
    "technologies", "cname", "cdn", "response_time",
]
CREDENTIAL_REVIEW_FIELDS = [
    "origin", "login_url", "title", "probable_product", "observed_versions",
    "review_status", "recommended_manual_checks", "security_reference",
    "credentials_submitted",
]

PRODUCT_GUIDES = [
    (("wordpress",), "WordPress", "https://wordpress.org/documentation/article/hardening-wordpress/"),
    (("jenkins",), "Jenkins", "https://www.jenkins.io/doc/book/security/"),
    (("grafana",), "Grafana", "https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/"),
    (("tomcat", "apache tomcat"), "Apache Tomcat", "https://tomcat.apache.org/tomcat-10.1-doc/manager-howto.html"),
    (("phpmyadmin", "php my admin"), "phpMyAdmin", "https://docs.phpmyadmin.net/en/latest/"),
    (("gitlab",), "GitLab", "https://docs.gitlab.com/administration/"),
    (("sonarqube", "sonar qube"), "SonarQube", "https://docs.sonarsource.com/sonarqube-server/"),
    (("kibana", "elasticsearch"), "Elastic Stack", "https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html"),
    (("nexus repository", "sonatype nexus"), "Sonatype Nexus Repository", "https://help.sonatype.com/en/security.html"),
    (("jira", "confluence"), "Atlassian application", "https://confluence.atlassian.com/security"),
]
GENERIC_SECURITY_GUIDE = "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item is not None)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def read_csv_rows(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    try:
        with path.open("r", newline="", encoding="utf-8", errors="replace") as stream:
            return list(csv.DictReader(stream))
    except OSError:
        return []


def write_asset_inventory(httpx_records: list[dict], output_path: Path) -> list[dict]:
    """Flatten httpx JSONL observations into an inventory that's easy to filter in a spreadsheet."""
    rows = []
    seen = set()
    for item in httpx_records:
        url = _as_text(item.get("url") or item.get("input") or item.get("final_url"))
        if not url:
            continue
        parsed = urlsplit(url)
        row = {
            "url": url,
            "hostname": parsed.hostname or _as_text(item.get("host")),
            "ip_addresses": _as_text(item.get("a") or item.get("ip")),
            "status_code": _as_text(item.get("status_code")),
            "title": _as_text(item.get("title")),
            "webserver": _as_text(item.get("webserver") or item.get("server")),
            "technologies": _as_text(item.get("tech") or item.get("technologies")),
            "cname": _as_text(item.get("cname")),
            "cdn": _as_text(item.get("cdn_name") or item.get("cdn")),
            "response_time": _as_text(item.get("time") or item.get("response_time")),
        }
        key = row["url"]
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)
    with output_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=ASSET_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return rows


def _product_family(panel: dict, related: list[dict]) -> tuple[str, str]:
    corpus = " ".join(
        [str(panel.get("title", "")), str(panel.get("login_url", ""))]
        + [str(item.get("product", "")) + " " + str(item.get("raw_fingerprint", ""))
           for item in related]
    ).casefold()
    for aliases, label, url in PRODUCT_GUIDES:
        if any(alias in corpus for alias in aliases):
            return label, url
    return "Unknown / custom login application", GENERIC_SECURITY_GUIDE


def write_default_credentials_review(
    login_panels: list[dict],
    fingerprints: list[dict],
    output_dir: Path,
) -> list[dict]:
    """Produce a manual checklist for default-account hygiene; never test credentials."""
    rows = []
    for panel in login_panels:
        origin = _as_text(panel.get("origin"))
        hostname = urlsplit(origin).hostname
        related = [
            item for item in fingerprints
            if hostname and urlsplit(_as_text(item.get("url"))).hostname == hostname
        ]
        product, reference = _product_family(panel, related)
        observed_products = sorted({
            f"{_as_text(item.get('product'))} {_as_text(item.get('version'))}".strip()
            for item in related if _as_text(item.get("product"))
        })
        rows.append({
            "origin": origin,
            "login_url": _as_text(panel.get("login_url")),
            "title": _as_text(panel.get("title")),
            "probable_product": product,
            "observed_versions": "; ".join(observed_products),
            "review_status": "MANUAL REVIEW REQUIRED — NOT TESTED",
            "recommended_manual_checks": (
                "Confirm setup forced a unique administrator password; rotate any vendor/sample "
                "credentials; disable unused accounts; require MFA where available; restrict the "
                "management interface to trusted networks; review authentication logs."
            ),
            "security_reference": reference,
            "credentials_submitted": "No",
        })

    csv_path = output_dir / "default-credentials-review.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=CREDENTIAL_REVIEW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    md = [
        "# Default-credentials hygiene review", "",
        "**Safety note:** TriageFlow does not attempt default usernames/passwords. This is a review checklist based on detected login panels and visible software fingerprints, not an authentication test.", "",
    ]
    if not rows:
        md += [
            "No login panels were detected in the checked paths, so no per-panel checklist was created.",
            "This does not prove that login interfaces are absent. Check the asset inventory and organization-approved configuration records as well.", "",
        ]
    for index, row in enumerate(rows, start=1):
        md += [
            f"## {index}. {row['probable_product']}", "",
            f"- Login URL: {row['login_url']}",
            f"- Page title: {row['title'] or 'Not available'}",
            f"- Observed software: {row['observed_versions'] or 'No matching version fingerprint'}",
            f"- Status: {row['review_status']}",
            f"- Checks: {row['recommended_manual_checks']}",
            f"- Vendor/security guidance: {row['security_reference']}", "",
        ]
    (output_dir / "default-credentials-review.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return rows


def _load_json(path: Path, default):
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return default


def _load_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    result = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            result.append(item)
    return result


def _cell(value) -> str:
    return html.escape(_as_text(value), quote=True)


def _table(title: str, columns: list[tuple[str, str]], rows: list[dict], empty: str) -> str:
    head = "".join(f"<th>{html.escape(label)}</th>" for _, label in columns)
    if not rows:
        body = f'<tr><td colspan="{len(columns)}" class="empty">{html.escape(empty)}</td></tr>'
    else:
        rendered = []
        for row in rows:
            cells = []
            for key, _label in columns:
                value = row.get(key, "")
                if key == "url" or key == "login_url":
                    href = _as_text(value)
                    if href.startswith(("http://", "https://")):
                        cells.append(f'<td><a href="{_cell(href)}" rel="noreferrer">{_cell(href)}</a></td>')
                        continue
                if key == "cve_link":
                    cve = row.get("id", "")
                    href = row.get("url", "")
                    if str(cve).startswith("CVE-") and str(href).startswith("https://nvd.nist.gov/vuln/detail/"):
                        cells.append(f'<td><a href="{_cell(href)}" rel="noreferrer">{_cell(cve)}</a></td>')
                        continue
                    value = cve
                cells.append(f"<td>{_cell(value)}</td>")
            rendered.append("<tr>" + "".join(cells) + "</tr>")
        body = "".join(rendered)
    return (
        f'<section><h2>{html.escape(title)}</h2><div class="table-wrap">'
        f'<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div></section>'
    )


def generate_html_report(output_dir: Path, status: dict) -> Path:
    """Generate a single-file HTML report with local results only and escaped table cells."""
    assets = read_csv_rows(output_dir / "asset-inventory.csv")
    software = read_csv_rows(output_dir / "software-inventory.csv")
    panels = read_csv_rows(output_dir / "login-panels.csv")
    default_review = read_csv_rows(output_dir / "default-credentials-review.csv")
    cve_doc = _load_json(output_dir / "cve-candidates.json", {})
    cve_rows = []
    for product in cve_doc.get("results", []) if isinstance(cve_doc, dict) else []:
        for cve in product.get("cves", []):
            cve_rows.append({
                "product": f"{product.get('product', '')} {product.get('observed_version', '')}".strip(),
                "id": cve.get("id", ""),
                "cve_link": cve.get("id", ""),
                "url": cve.get("url", ""),
                "severity": cve.get("severity", ""),
                "cvss_score": cve.get("cvss_score", ""),
                "description": cve.get("description", ""),
                "match_method": product.get("match_method", ""),
            })
    nuclei = _load_jsonl(output_dir / "nuclei-findings.jsonl")
    nuclei_rows = []
    for item in nuclei:
        info = item.get("info") or {}
        nuclei_rows.append({
            "severity": info.get("severity", ""),
            "name": info.get("name", item.get("template-id", "")),
            "matched_at": item.get("matched-at", item.get("host", "")),
            "template": item.get("template-id", ""),
            "type": item.get("type", ""),
        })

    card_specs = [
        ("Targets", status.get("target_count", 0)),
        ("Live URLs", status.get("live_url_count", 0)),
        ("Subdomains", status.get("subdomain_count", 0)),
        ("Software rows", status.get("software_fingerprint_count", len(software))),
        ("Login panels", status.get("login_panel_count", len(panels))),
        ("CVE candidates", status.get("cve_candidate_count", len(cve_rows))),
        ("Nuclei findings", len(nuclei_rows)),
    ]
    cards = "".join(
        f'<div class="card"><span>{html.escape(str(label))}</span><strong>{html.escape(str(value))}</strong></div>'
        for label, value in card_specs
    )
    stages = status.get("stages", {})
    stage_rows = [{"stage": key, "result": json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)}
                  for key, value in stages.items()]
    style = """
:root{color-scheme:light dark;font-family:system-ui,-apple-system,Segoe UI,sans-serif}
body{margin:0;background:#10151d;color:#e8edf4;line-height:1.5}
header{padding:2rem clamp(1rem,4vw,3rem);background:#182334;border-bottom:1px solid #344155}
main{max-width:1440px;margin:auto;padding:1.25rem}
h1{margin:0 0 .35rem;font-size:clamp(1.7rem,3vw,2.6rem)}h2{margin-top:2rem}
.subtitle,.muted{color:#b9c6d7}
.notice{border-left:4px solid #e8b45e;background:#242a33;padding:1rem;margin-top:1rem;border-radius:.25rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:.8rem;margin:1.25rem 0}
.card{background:#1b2533;border:1px solid #344155;border-radius:.75rem;padding:1rem}
.card span{display:block;color:#bac8d9;font-size:.85rem}.card strong{display:block;font-size:1.8rem;margin-top:.25rem}
.table-wrap{overflow:auto;border:1px solid #344155;border-radius:.5rem}
table{border-collapse:collapse;width:100%;min-width:700px;background:#171f2b}
th,td{text-align:left;padding:.65rem .8rem;border-bottom:1px solid #303d50;vertical-align:top;max-width:500px;overflow-wrap:anywhere}
th{background:#243247;position:sticky;top:0}tr:last-child td{border-bottom:0}
a{color:#8fc7ff}.empty{color:#bac8d9;text-align:center;padding:1.25rem}
footer{padding:2rem;color:#9caec4;text-align:center}
@media print{body{background:white;color:#111}.card,table{background:white;color:#111}.notice{background:#f8f1e3}a{color:#0645ad}header{background:white;color:#111}}
"""
    sections = [
        _table("Asset inventory", [
            ("url", "URL"), ("hostname", "Hostname"), ("ip_addresses", "IPs"),
            ("status_code", "Status"), ("title", "Title"), ("webserver", "Web server"),
            ("technologies", "Technologies"), ("cname", "CNAME"),
        ], assets, "No HTTP assets recorded."),
        _table("Software and versions", [
            ("url", "URL"), ("product", "Product"), ("version", "Version"),
            ("source", "Source"), ("raw_fingerprint", "Observed fingerprint"),
        ], software, "No software fingerprints were parsed."),
        _table("Potential CVE matches", [
            ("product", "Product/version"), ("cve_link", "CVE"), ("severity", "Severity"),
            ("cvss_score", "CVSS"), ("description", "Description"), ("match_method", "Match method"),
        ], cve_rows, "No CVE candidates recorded. This is not proof that the assets are free from vulnerabilities."),
        _table("Login panels", [
            ("login_url", "Login URL"), ("title", "Title"), ("status_code", "HTTP status"),
            ("evidence", "Detection evidence"),
        ], panels, "No login panels detected in the checked paths."),
        _table("Default-credential hygiene checklist", [
            ("probable_product", "Probable product"), ("login_url", "Login URL"),
            ("review_status", "Status"), ("recommended_manual_checks", "Recommended checks"),
            ("security_reference", "Vendor/security reference"),
        ], default_review, "No detected login panels to review. Hidden or custom login routes may still exist."),
        _table("Nuclei findings", [
            ("severity", "Severity"), ("name", "Finding"), ("matched_at", "Matched URL"),
            ("template", "Template ID"), ("type", "Type"),
        ], nuclei_rows, "No Nuclei findings recorded, or the Nuclei stage was skipped."),
        _table("Pipeline stages", [("stage", "Stage"), ("result", "Result")],
               stage_rows, "No stage metadata recorded."),
    ]
    content = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TriageFlow v2 Security Recon Report</title><style>{style}</style></head>
<body><header><h1>TriageFlow v2 — Recon Report</h1>
<div class="subtitle">Generated at {_cell(status.get('finished_utc', 'unknown'))} · Output folder: {_cell(output_dir.name)}</div>
<div class="notice"><strong>Interpretation note:</strong> CVE matches and technology fingerprints are investigation leads, not confirmed vulnerabilities.
Login-panel discovery is GET-only. No default credentials were submitted or tested. Screenshots are captured only when enabled.</div></header>
<main><div class="cards">{cards}</div>
{"".join(sections)}
</main><footer>TriageFlow v2 · Authorized assessment only · Keep reports, logs and screenshots private when they contain sensitive data.</footer></body></html>
"""
    path = output_dir / "report.html"
    path.write_text(content, encoding="utf-8")
    return path
