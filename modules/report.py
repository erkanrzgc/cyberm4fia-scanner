"""
cyberm4fia-scanner - Report Module
HTML, JSON, and Markdown report generation with CVSS/CWE enrichment
"""

import os

import json
import html as html_module
from datetime import datetime
from utils.colors import log_success, log_error
from utils.finding import (
    VULN_REGISTRY,
    _DEFAULT_VULN,
    build_scan_artifacts,
    normalize_all,
)
from utils.request import get_runtime_stats
from utils.request import ScanExceptions

def _resolve_report_stats(stats=None):
    """Resolve runtime metrics, preferring explicit scan-context stats over globals."""
    resolved = dict(stats or {})
    runtime_stats = get_runtime_stats()

    if resolved.get("duration_seconds") is None and runtime_stats.get("start_time"):
        duration_delta = datetime.now() - datetime.fromtimestamp(
            runtime_stats["start_time"]
        )
        resolved["duration_seconds"] = round(duration_delta.total_seconds(), 2)

    resolved.setdefault("total_requests", runtime_stats["total_requests"])
    resolved.setdefault("waf_blocks", runtime_stats["waf_blocks"])
    resolved.setdefault("errors", runtime_stats["errors"])
    resolved.setdefault("retries", runtime_stats["retries"])
    return resolved

def get_severity(vuln_type):
    """Get severity level for a vulnerability type"""
    if vuln_type in VULN_REGISTRY:
        return VULN_REGISTRY[vuln_type]["severity"]

    for key, info in VULN_REGISTRY.items():
        if key in vuln_type:
            return info["severity"]

    return _DEFAULT_VULN["severity"]

def generate_html_report(vulns, url, mode, scan_dir, stats=None):
    """Generate HTML vulnerability report with CVSS & CWE enrichment"""
    try:
        os.makedirs(scan_dir, exist_ok=True)
    except ScanExceptions as e:
        log_error(f"Could not create report directory: {e}")
        return None

    filename = os.path.join(scan_dir, "report.html")

    # Normalize vulnerabilities to Finding objects to get CVSS, CWE, Remediation
    findings = normalize_all(vulns)

    # Sort findings by severity (Critical -> High -> Medium -> Low -> Info)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: severity_order.get(x.severity, 5))

    vuln_html = ""
    for f in findings:
        severity = f.severity
        param = html_module.escape(str(f.param) if f.param else "N/A")
        payload = html_module.escape(str(f.payload) if f.payload else "N/A")
        description = html_module.escape(str(f.description) if f.description else "N/A")
        evidence = html_module.escape(str(f.evidence) if f.evidence else "N/A")
        confidence = html_module.escape(str(f.confidence).upper() if getattr(f, "confidence", "") else "N/A")
        verification_state = html_module.escape(
            str(getattr(f, "verification_state", "") or "N/A").upper()
        )
        exploitability = html_module.escape(
            str(getattr(f, "exploitability", "") or "N/A").upper()
        )
        cvss = f.cvss
        cwe = html_module.escape(str(f.cwe))
        remediation = html_module.escape(str(f.remediation))
        title = html_module.escape(str(f.title))
        vurl = html_module.escape(str(f.url))
        response_snippet = html_module.escape(
            str(getattr(f, "response_snippet", "") or "N/A")
        )

        # Check for exploit data
        exploit_html = ""
        if f.exploit_data:
            data = f.exploit_data
            exploit_type = data.get("exploit_type", "")

            if "Cookie_Stealer" in exploit_type:
                exploit_html += """
                <div class="exploit-data" style="margin-top: 15px; background: #16213e; padding: 10px; border-radius: 5px;">
                    <h4 style="color: #00ff88; margin-top: 0;">🔥 XSS Exploit Payloads</h4>
                """
                if "exploits" in data:
                    for exp in data["exploits"]:
                        desc = html_module.escape(str(exp.get("description", "")))
                        exploit_html += f"<p style='color: #c8d6e5;'>• {desc}</p>"
                exploit_html += "</div>"
            else:
                db_name = html_module.escape(str(data.get("database", "Unknown")))
                exploit_html += f"""
                <div class="exploit-data" style="margin-top: 15px; background: #16213e; padding: 10px; border-radius: 5px;">
                    <h4 style="color: #00ff88; margin-top: 0;">🔥 Extracted Data (DB: {db_name})</h4>
                """

            if "tables" in data and data["tables"]:
                exploit_html += f"<p><strong>Tables:</strong> <code style='color: #ff9f43'>{html_module.escape(', '.join(data['tables'][:15]))} {'...' if len(data['tables']) > 15 else ''}</code></p>"

            if "data" in data:
                for table, content in data["data"].items():
                    exploit_html += "<div style='margin-top: 10px; border-top: 1px solid #333; padding-top: 5px;'>"
                    exploit_html += f"<h5 style='color: #0abde3; margin: 5px 0;'>Table: {html_module.escape(str(table))}</h5>"
                    if "columns" in content:
                        exploit_html += f"<div style='margin-bottom: 5px;'><span style='color: #888;'>Columns:</span> <code style='color: #5f27cd'>{html_module.escape(', '.join(content['columns']))}</code></div>"

                    if "rows" in content and content["rows"]:
                        exploit_html += "<div style='max-height: 200px; overflow-y: auto; background: #111; padding: 5px; border-radius: 3px;'>"
                        for row in content["rows"]:
                            if isinstance(row, dict):
                                row_str = " | ".join(
                                    [
                                        f"<b>{html_module.escape(str(k))}</b>: {html_module.escape(str(v))}"
                                        for k, v in row.items()
                                    ]
                                )
                            else:
                                row_str = html_module.escape(str(row))
                            exploit_html += f"<div style='font-family: monospace; color: #c8d6e5; border-bottom: 1px dashed #333;'>{row_str}</div>"
                        exploit_html += "</div>"
                    exploit_html += "</div>"

            exploit_html += "</div>"

        vuln_html += f"""
        <div class="vuln-card {severity}" data-severity="{severity}">
            <h3>
                <span class="badge {severity}">{severity.upper()}</span>
                {title} <span style="font-size: 0.6em; color: #888; margin-left:10px;">({cwe} | CVSS: {cvss})</span>
            </h3>
            <div class="detail-row">
                <div class="detail-label">Vulnerable URL</div>
                <div style="word-break: break-all;"><a href="{vurl}" style="color: var(--accent); text-decoration: none;">{vurl}</a></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Parameter</div>
                <div><code>{param}</code></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Payload</div>
                <div><code>{payload}</code></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Confidence</div>
                <div>{confidence}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Verification</div>
                <div>{verification_state}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Exploitability</div>
                <div>{exploitability}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Description</div>
                <div>{description}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Evidence</div>
                <div>{evidence}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Response Snippet</div>
                <div><code>{response_snippet}</code></div>
            </div>
            <div class="detail-row" style="margin-top: 10px; padding-top: 10px; border-top: 1px dashed #333;">
                <div class="detail-label" style="color: var(--cyber-green);">Remediation</div>
                <div style="color: #a8b2c1;">{remediation}</div>
            </div>
            {exploit_html}
        </div>
        """

    # Calculate Stats
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1

    report_stats = _resolve_report_stats(stats)
    duration_seconds = report_stats.get("duration_seconds")
    duration = f"{duration_seconds}s" if duration_seconds is not None else "N/A"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>cyberm4fia-scanner Scan Report</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --card-bg: #151b2b;
            --border-color: #2a3441;
            --text-main: #e2e8f0;
            --text-muted: #94a3b8;
            --accent: #3b82f6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --info: #3b82f6;
            --cyber-green: #00ff88;
        }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ text-align: center; padding: 40px 0; border-bottom: 1px solid var(--border-color); margin-bottom: 30px; }}
        .header h1 {{ color: var(--cyber-green); font-size: 2.5em; margin: 0 0 10px 0; text-transform: uppercase; letter-spacing: 2px; text-shadow: 0 0 10px rgba(0, 255, 136, 0.3); }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 10px; padding: 20px; text-align: center; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }}
        .stat-card.total {{ border-top: 4px solid var(--accent); }}
        .stat-card.critical {{ border-top: 4px solid var(--critical); cursor: pointer; transition: 0.2s; }}
        .stat-card.high {{ border-top: 4px solid var(--high); cursor: pointer; transition: 0.2s; }}
        .stat-card.medium {{ border-top: 4px solid var(--medium); cursor: pointer; transition: 0.2s; }}
        .stat-card.low {{ border-top: 4px solid var(--low); cursor: pointer; transition: 0.2s; }}
        .stat-card:hover {{ transform: scale(1.02); }}
        .stat-value {{ font-size: 2.2em; font-weight: 700; margin-bottom: 5px; }}
        .total .stat-value {{ color: var(--accent); }}
        .critical .stat-value {{ color: var(--critical); }}
        .high .stat-value {{ color: var(--high); }}
        .medium .stat-value {{ color: var(--medium); }}
        .low .stat-value {{ color: var(--low); }}
        .stat-label {{ color: var(--text-muted); text-transform: uppercase; font-size: 0.8em; letter-spacing: 1px; }}
        .target-info {{ background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 10px; padding: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }}
        .target-info p {{ margin: 5px 0; }}
        .target-info strong {{ color: var(--cyber-green); }}
        .exec-summary {{ background: #0f172a; padding: 15px; border-radius: 8px; border-left: 4px solid var(--accent); margin-bottom: 30px; font-size: 0.9em; }}
        .exec-summary span {{ margin-right: 20px; }}
        .vuln-list {{ display: flex; flex-direction: column; gap: 20px; }}
        .vuln-card {{ background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 10px; padding: 25px; position: relative; overflow: hidden; transition: opacity 0.3s; }}
        .vuln-card::before {{ content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 5px; }}
        .vuln-card.critical::before {{ background: var(--critical); }}
        .vuln-card.high::before {{ background: var(--high); }}
        .vuln-card.medium::before {{ background: var(--medium); }}
        .vuln-card.low::before {{ background: var(--low); }}
        .vuln-card.info::before {{ background: var(--info); }}
        .vuln-card h3 {{ margin: 0 0 15px 0; color: var(--text-main); font-size: 1.3em; display: flex; align-items: center; gap: 10px; }}
        .badge {{ padding: 4px 10px; border-radius: 4px; font-size: 0.6em; font-weight: bold; text-transform: uppercase; color: #fff; }}
        .badge.critical {{ background: var(--critical); }}
        .badge.high {{ background: var(--high); }}
        .badge.medium {{ background: var(--medium); color: #000; }}
        .badge.low {{ background: var(--low); color: #000; }}
        .badge.info {{ background: var(--info); }}
        .detail-row {{ display: grid; grid-template-columns: 140px 1fr; gap: 10px; margin-bottom: 8px; align-items: baseline; }}
        .detail-label {{ color: var(--text-muted); font-weight: 600; font-size: 0.9em; }}
        code {{ background: #090e17; padding: 4px 8px; border-radius: 4px; font-family: 'Consolas', 'Monaco', monospace; color: #ff7b72; word-break: break-all; border: 1px solid #1f2937; font-size: 0.9em; }}
        .exploit-data {{ margin-top: 20px; background: #090e17; border: 1px solid #1f2937; padding: 15px; border-radius: 6px; }}
        .exploit-data h4 {{ color: var(--cyber-green); margin: 0 0 10px 0; border-bottom: 1px solid #1f2937; padding-bottom: 5px; }}
        .filter-nav {{ display: flex; gap: 10px; margin-bottom: 20px; }}
        .filter-btn {{ background: var(--card-bg); border: 1px solid var(--border-color); color: var(--text-main); padding: 8px 16px; border-radius: 5px; cursor: pointer; }}
        .filter-btn.active {{ background: var(--accent); border-color: var(--accent); }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>cyberm4fia-scanner Report</h1>
            <p style="color: var(--text-muted);">Advanced Vulnerability Scanner</p>
        </div>
        
        <div class="target-info">
            <div>
                <p><strong>TARGET:</strong> {html_module.escape(str(url))}</p>
                <p><strong>SCAN MODE:</strong> {html_module.escape(str(mode).upper())}</p>
            </div>
            <div style="text-align: right;">
                <p><strong>DATE:</strong> {datetime.now().strftime("%Y-%m-%d")}</p>
                <p><strong>TIME:</strong> {datetime.now().strftime("%H:%M:%S")}</p>
            </div>
        </div>

        <div class="exec-summary">
            <span><strong>⏱️ Duration:</strong> {duration}</span>
            <span><strong>🌐 Requests:</strong> {report_stats["total_requests"]}</span>
            <span><strong>🛡️ WAF Blocks:</strong> {report_stats["waf_blocks"]}</span>
            <span><strong>⚠️ Errors:</strong> {report_stats["errors"]}</span>
        </div>

        <div class="summary-grid">
            <div class="stat-card total" onclick="filterVulns('all')">
                <div class="stat-value">{len(findings)}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card critical" onclick="filterVulns('critical')">
                <div class="stat-value">{counts["critical"]}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high" onclick="filterVulns('high')">
                <div class="stat-value">{counts["high"]}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium" onclick="filterVulns('medium')">
                <div class="stat-value">{counts["medium"]}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low" onclick="filterVulns('low')">
                <div class="stat-value">{counts["low"]}</div>
                <div class="stat-label">Low / Info</div>
            </div>
        </div>
        
        <div class="filter-nav">
            <button class="filter-btn active" onclick="filterVulns('all')" id="btn-all">All Findings</button>
            <button class="filter-btn" onclick="filterVulns('critical')" id="btn-critical">Critical</button>
            <button class="filter-btn" onclick="filterVulns('high')" id="btn-high">High</button>
            <button class="filter-btn" onclick="filterVulns('medium')" id="btn-medium">Medium</button>
            <button class="filter-btn" onclick="filterVulns('low')" id="btn-low">Low</button>
        </div>
        
        <div class="vuln-list" id="vuln-list">
            {vuln_html if vuln_html else "<div class='vuln-card' style='text-align:center;'><h3 style='color: var(--text-muted);'>No vulnerabilities detected during this scan.</h3></div>"}
        </div>
    </div>
    <script>
        function filterVulns(severity) {{
            // Update buttons
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById('btn-' + severity).classList.add('active');
            
            // Filter cards
            const cards = document.querySelectorAll('.vuln-card');
            cards.forEach(card => {{
                if (severity === 'all' || card.getAttribute('data-severity') === severity || (severity === 'low' && card.getAttribute('data-severity') === 'info')) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)

    log_success(f"HTML Report saved: {filename}")
    return filename

def generate_json_report(vulns, url, mode, stats, scan_dir, artifacts=None):
    """Generate JSON report"""
    try:
        os.makedirs(scan_dir, exist_ok=True)
    except ScanExceptions:
        pass

    filename = os.path.join(scan_dir, "scan.json")
    artifacts = artifacts or build_scan_artifacts(vulns)

    report = {
        "target": url,
        "mode": mode,
        "date": str(datetime.now()),
        "stats": stats,
        "vulnerabilities": vulns,
        "observations": [obs.to_dict() for obs in artifacts["observations"]],
        "findings": [finding.to_dict() for finding in artifacts["findings"]],
        "attack_paths": [path.to_dict() for path in artifacts["attack_paths"]],
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    log_success(f"JSON saved: {filename}")
    return filename

def generate_payload_report(scan_dir, url, vulns):
    """Generate text-based payload report"""
    try:
        os.makedirs(scan_dir, exist_ok=True)
    except ScanExceptions:
        pass

    filename = os.path.join(scan_dir, "payloads.txt")
    findings = normalize_all(vulns)

    with open(filename, "w") as f:
        f.write("# cyberm4fia-scanner Vulnerability Report\n")
        f.write(f"# Target: {url}\n")
        f.write(f"# Date: {datetime.now()}\n")
        f.write(f"# Total Vulnerabilities: {len(findings)}\n\n")

        for f_obj in findings:
            f.write(f"{'=' * 50}\n")
            f.write(f"Type: {f_obj.title} ({f_obj.severity.upper()})\n")
            f.write(f"CWE / CVSS: {f_obj.cwe} / {f_obj.cvss}\n")
            f.write(f"Parameter: {f_obj.param or 'N/A'}\n")
            f.write(f"Payload: {f_obj.payload or 'N/A'}\n")
            f.write(f"URL: {f_obj.url or 'N/A'}\n")

            if f_obj.exploit_data:
                data = f_obj.exploit_data
                f.write(
                    f"--- Exploit Data (DB: {data.get('database', 'Unknown')}) ---\n"
                )
                if "tables" in data:
                    f.write(f"Tables: {', '.join(data['tables'])}\n")
                if "data" in data:
                    for table, content in data["data"].items():
                        f.write(f"Table: {table}\n")
                        if "columns" in content:
                            f.write(f"  Columns: {', '.join(content['columns'])}\n")
                        if "rows" in content:
                            f.write("  Rows:\n")
                            for row in content["rows"]:
                                f.write(f"    {row}\n")

            f.write("\n")

    log_success(f"Payload report saved: {filename}")
    return filename

def generate_markdown_report(vulns, url, mode, scan_dir, stats=None):
    """Generate Professional Markdown Report for Bug Bounty Platforms."""
    try:
        os.makedirs(scan_dir, exist_ok=True)
    except ScanExceptions as e:
        log_error(f"Could not create report directory: {e}")
        return None

    filename = os.path.join(scan_dir, "report.md")
    findings = normalize_all(vulns)

    # Sort findings by severity (Critical -> High -> Medium -> Low -> Info)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: severity_order.get(x.severity, 5))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1

    report_stats = _resolve_report_stats(stats)
    duration_seconds = report_stats.get("duration_seconds")
    duration = f"{duration_seconds}s" if duration_seconds is not None else "N/A"

    md = f"""# cyberm4fia-scanner Executive Vulnerability Report

**Target:** `{url}`  
**Scan Mode:** `{mode.upper()}`  
**Date Generated:** `{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}`  

---

## 📊 Executive Summary

- **Duration:** {duration}
- **Total Requests:** {report_stats["total_requests"]}
- **WAF Blocks:** {report_stats["waf_blocks"]}
- **Network Errors:** {report_stats["errors"]}

### Severity Breakdown

| Severity | Count |
|----------|-------|
| 🛑 **Critical** | {counts["critical"]} |
| 🔴 **High** | {counts["high"]} |
| 🟠 **Medium** | {counts["medium"]} |
| 🟢 **Low / Info** | {counts["low"] + counts["info"]} |
| **Total** | **{len(findings)}** |

---

## 🐛 Detailed Findings

"""
    if not findings:
        md += "> ✅ **Secure:** No vulnerabilities detected during this scan.\\n"
    else:
        for idx, f in enumerate(findings, 1):
            severity = f.severity.upper()

            md += f"### {idx}. [{severity}] {f.title}\n\n"
            md += f"- **Endpoint:** `{f.url or 'N/A'}`\n"
            md += f"- **CWE ID:** `{f.cwe}`\n"
            md += f"- **CVSS Score:** `{f.cvss}`\n"
            md += f"- **Vulnerable Parameter:** `{f.param or 'N/A'}`\n"
            md += f"- **Verification State:** `{f.verification_state}`\n"
            md += f"- **Exploitability:** `{f.exploitability}`\n"

            payload = f.payload or "N/A"
            md += f"\n**Payload Used:**\n```text\n{payload}\n```\n"

            md += f"\n**🛡️ Remediation:**\n> {f.remediation}\n\n"

            if f.exploit_data:
                data = f.exploit_data
                md += "**🧠 Exploit Proof-of-Concept:**\n```json\n"
                md += json.dumps(data, indent=2)
                md += "\n```\n"

            md += "---\n\n"

    with open(filename, "w") as f:
        f.write(md)

    log_success(f"Markdown Report saved: {filename}")
    return filename
