"""
cyberm4fia-scanner - DOM XSS Static Analyzer
Performs lightweight, fast regex-based static analysis to detect DOM XSS via JS Sources and Sinks.
Inspired by XSStrike.
"""

import sys
import os
import re
from urllib.parse import urljoin, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import log_info, log_success, Colors
from utils.request import smart_request
from bs4 import BeautifulSoup


# XSS Sources - where attacker input enters
SOURCES = r"\b(?:document\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\.(href|search|hash|pathname)|window\.name|history\.(pushState|replaceState)(local|session)Storage)\b"

# XSS Sinks - where attacker input executes
SINKS = r"\b(?:eval|evaluate|execCommand|assign|navigate|getResponseHeaderopen|showModalDialog|Function|set(?:Timeout|Interval|Immediate)|execScript|crypto\.generateCRMFRequest|ScriptElement\.(?:src|text|textContent|innerText)|.*?\.onEventName|document\.(?:write|writeln)|.*?\.innerHTML|Range\.createContextualFragment|(?:document|window)\.location)\b"


def analyze_js_content(script_content, script_name):
    """
    Analyzes Javascript content line by line to detect source -> sink flows.
    Returns list of discovered potentials.
    """
    findings = []
    lines = script_content.split("\n")

    # Track variables assigned from sources
    controlled_vars = set()

    source_found = False
    sink_found = False

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        # 1. Did we hit a source on this line?
        src_match = re.search(SOURCES, line, re.IGNORECASE)
        if src_match:
            source_found = True
            source_snippet = src_match.group(0)

            # Did they assign it to a variable? e.g. var myHash = location.hash;
            var_match = re.search(r"(?:var|let|const)\s+([a-zA-Z0-9_$]+)\s*=", line)
            if var_match:
                controlled_vars.add(var_match.group(1))

        # 2. Are they using a previously controlled variable?
        used_controlled_var = False
        for var in controlled_vars:
            if re.search(r"\b" + re.escape(var) + r"\b", line):
                used_controlled_var = True
                break

        # 3. Did we hit a sink?
        sink_match = re.search(SINKS, line, re.IGNORECASE)
        if sink_match:
            sink_snippet = sink_match.group(0)
            sink_found = True

            # High confidence: Source is used directly in a Sink on the same line
            if src_match:
                findings.append(
                    {
                        "type": "Direct Flow",
                        "file": script_name,
                        "line_num": i + 1,
                        "line_content": line,
                        "source": source_snippet,
                        "sink": sink_snippet,
                        "confidence": "HIGH",
                    }
                )
            # Medium confidence: A previously controlled variable hits a sink
            elif used_controlled_var:
                findings.append(
                    {
                        "type": "Variable Flow",
                        "file": script_name,
                        "line_num": i + 1,
                        "line_content": line,
                        "source": f"Variable ({var})",
                        "sink": sink_snippet,
                        "confidence": "MEDIUM",
                    }
                )

    # Low confidence: Both exist in the file broadly, but we couldn't track exact flow
    if source_found and sink_found and not findings:
        findings.append(
            {
                "type": "Same Script Block",
                "file": script_name,
                "line_num": "N/A",
                "line_content": "Source and Sink both present in this script.",
                "source": "Found",
                "sink": "Found",
                "confidence": "LOW",
            }
        )

    return findings


def scan_dom_static(url, delay=0):
    """
    Statically analyzes the DOM and linked JS files for DOM-based XSS vectors.
    """
    log_info(f"[*] Starting Static DOM XSS Analysis for {url}")

    try:
        resp = smart_request("get", url, delay=delay)
        if not resp:
            return []

        soup = BeautifulSoup(resp.text, "lxml")
        scripts = soup.find_all("script")

        all_findings = []

        for idx, script in enumerate(scripts):
            # Inline script
            if script.string:
                findings = analyze_js_content(script.string, f"Inline_Script_{idx + 1}")
                if findings:
                    all_findings.extend(findings)

            # External script
            if script.get("src"):
                src_url = urljoin(url, script.get("src"))
                # Skip external domains to prevent scanning entire CDNs like jQuery
                if urlparse(src_url).netloc == urlparse(url).netloc:
                    try:
                        js_resp = smart_request("get", src_url, delay=delay)
                        if js_resp and js_resp.text:
                            findings = analyze_js_content(js_resp.text, src_url)
                            if findings:
                                all_findings.extend(findings)
                    except Exception:
                        pass

        if all_findings:
            log_success(
                f"[!!!] Found {len(all_findings)} Potential DOM XSS points via Static Analysis!"
            )
            for f in all_findings:
                conf_color = (
                    Colors.RED
                    if f["confidence"] == "HIGH"
                    else (Colors.YELLOW if f["confidence"] == "MEDIUM" else Colors.BLUE)
                )
                print(
                    f"  {conf_color}[{f['confidence']}]{Colors.END} {Colors.BOLD}File:{Colors.END} {f['file']} | {Colors.BOLD}Line:{Colors.END} {f['line_num']}"
                )
                print(
                    f"      {Colors.CYAN}Source:{Colors.END} {f['source']} -> {Colors.CYAN}Sink:{Colors.END} {f['sink']}"
                )
                if f["line_content"] != "Source and Sink both present in this script.":
                    print(
                        f"      {Colors.DIM}Snippet: {f['line_content'][:100].strip()}{Colors.END}"
                    )

        return all_findings

    except Exception as e:
        log_info(f"[-] Static DOM Analysis failed: {e}")
        return []


if __name__ == "__main__":
    test_url = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    scan_dom_static(test_url)
