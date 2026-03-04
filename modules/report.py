"""
cyberm4fia-scanner - Report Module
HTML and JSON report generation
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import html as html_module
from datetime import datetime
from utils.colors import log_success, log_info, log_error


SEVERITY_MAP = {
    "SQLi": "critical",
    "Blind_SQLi": "critical",
    "CMDi": "critical",
    "XSS": "high",
    "LFI": "high",
    "RFI": "high",
    "DOM_XSS": "medium",
    "Blind_CMDi": "medium",
}


def get_severity(vuln_type):
    """Get severity level for a vulnerability type"""
    for key, level in SEVERITY_MAP.items():
        if key in vuln_type:
            return level
    return "low"


def generate_html_report(vulns, url, mode, scan_dir):
    """Generate HTML vulnerability report"""
    try:
        os.makedirs(scan_dir, exist_ok=True)
    except Exception as e:
        log_error(f"Could not create report directory: {e}")
        return None

    filename = os.path.join(scan_dir, "report.html")

    vuln_html = ""
    for v in vulns:
        severity = get_severity(v.get("type", ""))
        param = v.get("param") or v.get("field", "N/A")
        payload = html_module.escape(str(v.get("payload", "N/A")[:100]))

        # Check for exploit data
        exploit_html = ""
        if "exploit_data" in v:
            data = v["exploit_data"]
            exploit_type = data.get("exploit_type", "")

            if "Cookie_Stealer" in exploit_type:
                # XSS exploit - show payload links
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
                # SQLi exploit - show DB data
                db_name = html_module.escape(str(data.get("database", "Unknown")))
                exploit_html += f"""
                <div class="exploit-data" style="margin-top: 15px; background: #16213e; padding: 10px; border-radius: 5px;">
                    <h4 style="color: #00ff88; margin-top: 0;">🔥 Extracted Data (DB: {db_name})</h4>
                """

            if "tables" in data and data["tables"]:
                exploit_html += f"<p><strong>Tables:</strong> <code style='color: #ff9f43'>{html_module.escape(', '.join(data['tables'][:15]))} {'...' if len(data['tables']) > 15 else ''}</code></p>"

            if "data" in data:
                for table, content in data["data"].items():
                    exploit_html += f"<div style='margin-top: 10px; border-top: 1px solid #333; padding-top: 5px;'>"
                    exploit_html += f"<h5 style='color: #0abde3; margin: 5px 0;'>Table: {table}</h5>"
                    if "columns" in content:
                        exploit_html += f"<div style='margin-bottom: 5px;'><span style='color: #888;'>Columns:</span> <code style='color: #5f27cd'>{html_module.escape(', '.join(content['columns']))}</code></div>"

                    if "rows" in content and content["rows"]:
                        exploit_html += "<div style='max-height: 200px; overflow-y: auto; background: #111; padding: 5px; border-radius: 3px;'>"
                        for row in content["rows"]:
                            if isinstance(row, dict):
                                # Generic handler for dict rows
                                row_str = " | ".join(
                                    [
                                        f"<b>{html_module.escape(str(k))}</b>: {html_module.escape(str(v))}"
                                        for k, v in row.items()
                                    ]
                                )
                            else:
                                row_str = html_module.escape(str(row))
                            exploit_html += f"<div style='font-family: monospace; color: #c8d6e5; border-bottom: 1px dashed #333;'>{row_str}</div>"  # row_str already escaped above
                        exploit_html += "</div>"
                    exploit_html += "</div>"

            exploit_html += "</div>"

        vuln_html += f"""
        <div class="vuln {severity}">
            <h3>
                <span class="badge {severity}">{severity.upper()}</span>
                {html_module.escape(str(v.get("type", "Unknown")))}
            </h3>
            <div class="detail-row">
                <div class="detail-label">Parameter</div>
                <div>{html_module.escape(str(param))}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Payload</div>
                <div><code>{payload}</code></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Target URL</div>
                <div style="word-break: break-all;"><a href="{html_module.escape(str(v.get("url", "N/A")))}" style="color: var(--accent); text-decoration: none;">{html_module.escape(str(v.get("url", "N/A")))}</a></div>
            </div>
            {exploit_html}
        </div>
        """

    # Calculate Stats
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        severity = get_severity(v.get("type", ""))
        if severity in counts:
            counts[severity] += 1

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
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            text-align: center;
            padding: 40px 0;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: var(--cyber-green);
            font-size: 2.5em;
            margin: 0 0 10px 0;
            text-transform: uppercase;
            letter-spacing: 2px;
            text-shadow: 0 0 10px rgba(0, 255, 136, 0.3);
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        .stat-card.total {{ border-top: 4px solid var(--accent); }}
        .stat-card.critical {{ border-top: 4px solid var(--critical); }}
        .stat-card.high {{ border-top: 4px solid var(--high); }}
        .stat-card.medium {{ border-top: 4px solid var(--medium); }}
        .stat-card.low {{ border-top: 4px solid var(--low); }}
        .stat-value {{
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 5px;
        }}
        .total .stat-value {{ color: var(--accent); }}
        .critical .stat-value {{ color: var(--critical); }}
        .high .stat-value {{ color: var(--high); }}
        .medium .stat-value {{ color: var(--medium); }}
        .low .stat-value {{ color: var(--low); }}
        .stat-label {{
            color: var(--text-muted);
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }}
        .target-info {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }}
        .target-info p {{ margin: 5px 0; }}
        .target-info strong {{ color: var(--cyber-green); }}
        .vuln-list {{
            display: flex;
            flex-direction: column;
            gap: 20px;
        }}
        .vuln {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 25px;
            position: relative;
            overflow: hidden;
        }}
        .vuln::before {{
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 5px;
        }}
        .vuln.critical::before {{ background: var(--critical); }}
        .vuln.high::before {{ background: var(--high); }}
        .vuln.medium::before {{ background: var(--medium); }}
        .vuln.low::before {{ background: var(--low); }}
        .vuln h3 {{
            margin: 0 0 15px 0;
            color: var(--text-main);
            font-size: 1.4em;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.6em;
            font-weight: bold;
            text-transform: uppercase;
            color: #fff;
        }}
        .badge.critical {{ background: var(--critical); }}
        .badge.high {{ background: var(--high); }}
        .badge.medium {{ background: var(--medium); color: #000; }}
        .badge.low {{ background: var(--low); color: #000; }}
        .detail-row {{
            display: grid;
            grid-template-columns: 120px 1fr;
            gap: 10px;
            margin-bottom: 10px;
            align-items: baseline;
        }}
        .detail-label {{
            color: var(--text-muted);
            font-weight: 600;
        }}
        code {{
            background: #090e17;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: 'Consolas', 'Monaco', monospace;
            color: #ff7b72;
            word-break: break-all;
            border: 1px solid #1f2937;
        }}
        .exploit-data {{
            margin-top: 20px;
            background: #090e17;
            border: 1px solid #1f2937;
            padding: 15px;
            border-radius: 6px;
        }}
        .exploit-data h4 {{
            color: var(--cyber-green);
            margin: 0 0 10px 0;
            border-bottom: 1px solid #1f2937;
            padding-bottom: 5px;
        }}
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

        <div class="summary-grid">
            <div class="stat-card total">
                <div class="stat-value">{len(vulns)}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-value">{counts["critical"]}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">{counts["high"]}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">{counts["medium"]}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">{counts["low"]}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        <h2 style="color: var(--cyber-green); border-bottom: 1px solid var(--border-color); padding-bottom: 10px; margin-bottom: 20px;">Detailed Findings</h2>
        
        <div class="vuln-list">
            {vuln_html if vuln_html else "<div class='vuln' style='text-align:center;'><h3 style='color: var(--text-muted);'>No vulnerabilities detected during this scan.</h3></div>"}
        </div>
    </div>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)

    log_success(f"HTML Report saved: {filename}")
    return filename


def generate_json_report(vulns, url, mode, stats, scan_dir):
    """Generate JSON report"""
    try:
        os.makedirs(scan_dir, exist_ok=True)
    except:
        pass

    filename = os.path.join(scan_dir, "scan.json")

    report = {
        "target": url,
        "mode": mode,
        "date": str(datetime.now()),
        "stats": stats,
        "vulnerabilities": vulns,
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    log_success(f"JSON saved: {filename}")
    return filename


def generate_payload_report(scan_dir, url, vulns):
    """Generate text-based payload report"""
    try:
        os.makedirs(scan_dir, exist_ok=True)
    except:
        pass

    filename = os.path.join(scan_dir, "payloads.txt")

    with open(filename, "w") as f:
        f.write(f"# cyberm4fia-scanner Vulnerability Report\n")
        f.write(f"# Target: {url}\n")
        f.write(f"# Date: {datetime.now()}\n")
        f.write(f"# Total Vulnerabilities: {len(vulns)}\n\n")

        for v in vulns:
            f.write(f"{'=' * 50}\n")
            f.write(f"Type: {v.get('type', 'Unknown')}\n")
            f.write(f"Parameter: {v.get('param') or v.get('field', 'N/A')}\n")
            f.write(f"Payload: {v.get('payload', 'N/A')}\n")
            f.write(f"URL: {v.get('url', 'N/A')}\n")

            if "exploit_data" in v:
                data = v["exploit_data"]
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
                            f.write(f"  Rows:\n")
                            for row in content["rows"]:
                                f.write(f"    {row}\n")

            f.write(f"\n")


def generate_markdown_report(vulns, url, mode, scan_dir):
    """Generate Professional Markdown Report for Bug Bounty Platforms."""
    try:
        os.makedirs(scan_dir, exist_ok=True)
    except Exception as e:
        log_error(f"Could not create report directory: {e}")
        return None

    filename = os.path.join(scan_dir, "report.md")

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        counts[get_severity(v.get("type", ""))] += 1

    md = f"""# cyberm4fia-scanner Executive Vulnerability Report

**Target:** `{url}`  
**Scan Mode:** `{mode.upper()}`  
**Date Generated:** `{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}`  

---

## 📊 Summary Statistics

| Severity | Count |
|----------|-------|
| 🛑 **Critical** | {counts["critical"]} |
| 🔴 **High** | {counts["high"]} |
| 🟠 **Medium** | {counts["medium"]} |
| 🟢 **Low** | {counts["low"]} |
| **Total** | **{len(vulns)}** |

---

## 🐛 Detailed Findings

"""
    if not vulns:
        md += "> ✅ **Secure:** No vulnerabilities detected during this scan.\n"
    else:
        for idx, v in enumerate(vulns, 1):
            severity = get_severity(v.get("type", "")).upper()
            vtype = v.get("type", "Unknown")

            md += f"### {idx}. [{severity}] {vtype} Vulnerability\n\n"
            md += f"- **Endpoint:** `{v.get('url', 'N/A')}`\n"
            md += f"- **Method:** `{v.get('method', 'GET').upper()}`\n"
            md += f"- **Vulnerable Parameter:** `{v.get('param') or v.get('field', 'N/A')}`\n"

            payload = v.get("payload", "N/A")
            md += f"\n**Payload Used:**\n```text\n{payload}\n```\n"

            if "exploit_data" in v:
                data = v["exploit_data"]
                md += "\n**🧠 Exploit Proof-of-Concept:**\n```json\n"
                md += json.dumps(data, indent=2)
                md += "\n```\n"

            md += "---\n\n"

    with open(filename, "w") as f:
        f.write(md)

    log_success(f"Markdown Report saved: {filename}")
    return filename

    log_success(f"Payload report saved: {filename}")
    return filename
