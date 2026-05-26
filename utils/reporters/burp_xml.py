"""Burp Suite Issues XML exporter.

Produces an ``issues`` element matching Burp Suite Professional's
"Issues -> Export" XML schema. The output can be imported into Burp
Project files (Burp Suite Pro -> Project -> Import issues) and into
defect-tracking workflows that consume Burp XML (e.g. Jira ScanCentral,
DefectDojo's Burp parser).

Schema reference:
    https://portswigger.net/burp/documentation/desktop/tools/target/issue-definitions

We map the internal Finding shape to Burp's required fields:

* serialNumber  -> stable_id (already in Finding via _stable_id)
* type          -> CWE id (Burp uses 32-bit type codes, but custom XML
                   accepts CWE strings — DefectDojo + native Burp
                   tolerate it)
* name          -> Finding.title
* host          -> URL origin + ip="" (ip resolution left to importer)
* path          -> URL path + query
* location      -> URL path (Burp also uses this for the "issue location")
* severity      -> mapped to Burp's enum: High/Medium/Low/Information
* confidence    -> Certain / Firm / Tentative
* issueBackground / remediationBackground -> from registry
* issueDetail   -> evidence + payload
* requestresponse -> only when we have ``request`` / ``response_snippet``
"""

from __future__ import annotations

import html
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urlparse

# Burp's severity enum.
_SEV_MAP = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Information",
    "informational": "Information",
}

# Burp's confidence enum — derived from our 0-100 score band.
_CONF_BANDS = (
    (80, "Certain"),
    (50, "Firm"),
    (0, "Tentative"),
)


def _confidence_label(value) -> str:
    if isinstance(value, str):
        v = value.lower().strip()
        if v in {"high", "confirmed", "certain"}:
            return "Certain"
        if v in {"medium", "firm"}:
            return "Firm"
        return "Tentative"
    try:
        score = int(value)
    except (TypeError, ValueError):
        return "Tentative"
    for floor, label in _CONF_BANDS:
        if score >= floor:
            return label
    return "Tentative"


def _severity_label(value: str) -> str:
    return _SEV_MAP.get((value or "").lower(), "Information")


def _split_url(url: str) -> tuple[str, str]:
    """Return (host_url_with_scheme, path_and_query)."""
    parsed = urlparse(url)
    if not parsed.scheme:
        return "", url
    host = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return host, path


def _cdata(text: str) -> str:
    """Burp tolerates raw text but CDATA is safer for HTML/script payloads."""
    if not text:
        return ""
    return f"<![CDATA[{text}]]>"


def _finding_to_issue(finding: dict) -> ET.Element:
    issue = ET.Element("issue")
    serial = str(finding.get("id") or "")
    ET.SubElement(issue, "serialNumber").text = serial
    ET.SubElement(issue, "type").text = str(finding.get("cwe") or "CWE-0")
    ET.SubElement(issue, "name").text = str(finding.get("title") or finding.get("type") or "Finding")
    host_url, path = _split_url(str(finding.get("url") or ""))
    host_elem = ET.SubElement(issue, "host")
    host_elem.set("ip", "")
    host_elem.text = host_url
    ET.SubElement(issue, "path").text = path
    ET.SubElement(issue, "location").text = path
    ET.SubElement(issue, "severity").text = _severity_label(str(finding.get("severity") or ""))
    ET.SubElement(issue, "confidence").text = _confidence_label(
        finding.get("confidence") or finding.get("ai_confidence")
    )

    # Background + detail
    bg = (
        f"<b>Type:</b> {html.escape(str(finding.get('type') or ''))}<br>"
        f"<b>CVSS:</b> {finding.get('cvss', 0.0)}<br>"
        f"<b>Module:</b> {html.escape(str(finding.get('module') or ''))}<br>"
        f"<b>Verification:</b> {html.escape(str(finding.get('verification_state') or 'suspected'))}"
    )
    bg_el = ET.SubElement(issue, "issueBackground")
    bg_el.text = bg

    rem_el = ET.SubElement(issue, "remediationBackground")
    rem_el.text = html.escape(str(finding.get("remediation") or ""))

    detail_parts: list[str] = []
    if finding.get("evidence"):
        detail_parts.append("<b>Evidence:</b><br><pre>" +
                            html.escape(str(finding["evidence"])) + "</pre>")
    if finding.get("payload"):
        detail_parts.append("<b>Payload:</b><br><pre>" +
                            html.escape(str(finding["payload"])) + "</pre>")
    if finding.get("param"):
        detail_parts.append(f"<b>Parameter:</b> {html.escape(str(finding['payload']))}")
    if finding.get("ai_analysis"):
        ai = finding["ai_analysis"]
        if isinstance(ai, dict):
            for k, v in ai.items():
                detail_parts.append(f"<b>{html.escape(k)}:</b> {html.escape(str(v))}")
    if finding.get("response_snippet"):
        detail_parts.append("<b>Response snippet:</b><br><pre>" +
                            html.escape(str(finding["response_snippet"])[:2000]) + "</pre>")
    ET.SubElement(issue, "issueDetail").text = "<br>".join(detail_parts) or html.escape(
        str(finding.get("title") or "")
    )

    # requestresponse — only emit if we captured something
    rr_payload = finding.get("request") or finding.get("response_snippet")
    if rr_payload:
        rr = ET.SubElement(issue, "requestresponse")
        if isinstance(finding.get("request"), dict):
            req = finding["request"]
            method = req.get("method", "GET")
            url = req.get("url", finding.get("url", ""))
            body = req.get("body", "")
            raw_req = f"{method} {url} HTTP/1.1\r\n\r\n{body or ''}"
            ET.SubElement(rr, "request", base64="false").text = raw_req
        if finding.get("response_snippet"):
            ET.SubElement(rr, "response", base64="false").text = str(
                finding["response_snippet"]
            )[:8000]
    return issue


def export_burp_xml(findings: Iterable[dict], output_path: str, *, scan_url: str = "") -> str:
    """Write a Burp-compatible issues XML to ``output_path``.

    Returns the path written. ``findings`` is a list of dicts as produced by
    ``Finding.to_dict()`` / module emit format.
    """
    issues = ET.Element("issues")
    issues.set("burpVersion", "cyberm4fia-export-1.0")
    issues.set("exportTime", datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Z %Y"))
    if scan_url:
        issues.set("scanTarget", scan_url)

    for f in findings:
        if not isinstance(f, dict):
            # Probably a Finding dataclass — convert
            f = getattr(f, "to_dict", lambda: {})()
            if not f:
                continue
        try:
            issues.append(_finding_to_issue(f))
        except Exception:  # noqa: BLE001 — skip a malformed entry, don't fail export
            continue

    tree = ET.ElementTree(issues)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    # Burp expects a <!DOCTYPE>; minimal one suffices for native import.
    with open(output_path, "wb") as fh:
        fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
        fh.write(b'<!DOCTYPE issues>\n')
        tree.write(fh, encoding="utf-8", xml_declaration=False)
    return output_path
