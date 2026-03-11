"""
cyberm4fia-scanner - Nuclei-Style Template Engine
Parses and executes community YAML templates for vulnerability scanning.
"""

import sys
import os
import yaml
import re
from urllib.parse import urlparse, urljoin
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import log_info, log_success, log_warning, log_error, log_vuln
from utils.request import increment_vulnerability_count, smart_request

TEMPLATE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates"
)


def ensure_template_dir():
    if not os.path.exists(TEMPLATE_DIR):
        os.makedirs(TEMPLATE_DIR)
        _create_sample_template()


def _create_sample_template():
    sample = {
        "id": "cve-2021-41773",
        "info": {
            "name": "Apache 2.4.49 - Path Traversal",
            "author": "cyberm4fia",
            "severity": "high",
            "description": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49.",
        },
        "requests": [
            {
                "method": "GET",
                "path": ["/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd"],
                "matchers": [
                    {"type": "word", "words": ["root:x:0:0:root"]},
                    {"type": "status", "status": [200]},
                ],
            }
        ],
    }
    with open(os.path.join(TEMPLATE_DIR, "cve-2021-41773.yaml"), "w") as f:
        yaml.dump(sample, f)


def load_templates():
    ensure_template_dir()
    templates = []
    for root, _, files in os.walk(TEMPLATE_DIR):
        for file in files:
            if file.endswith((".yaml", ".yml")):
                try:
                    with open(os.path.join(root, file), "r") as f:
                        tpl = yaml.safe_load(f)
                        if tpl and "id" in tpl and "requests" in tpl:
                            templates.append(tpl)
                except Exception as e:
                    log_warning(f"Error loading template {file}: {e}")
    return templates


def _match_response(resp, matchers):
    """Evaluate response against a list of matchers (AND logic between matchers)."""
    for matcher in matchers:
        m_type = matcher.get("type", "")

        # Word Matcher (OR logic within words)
        if m_type == "word":
            words = matcher.get("words", [])
            part = matcher.get("part", "body")

            target_text = (
                resp.text
                if part == "body"
                else "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            )

            # Case insensitive usually preferred in Nuclei
            matched_any = False
            for w in words:
                if w.lower() in target_text.lower():
                    matched_any = True
                    break
            if not matched_any:
                return False

        # Status matcher (OR logic within statuses)
        elif m_type == "status":
            statuses = matcher.get("status", [])
            if resp.status_code not in statuses:
                return False

        # Regex Matcher (OR logic within regexes)
        elif m_type == "regex":
            regexes = matcher.get("regex", [])
            part = matcher.get("part", "body")
            target_text = (
                resp.text
                if part == "body"
                else "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            )

            matched_any = False
            for r in regexes:
                if re.search(r, target_text, re.IGNORECASE):
                    matched_any = True
                    break
            if not matched_any:
                return False

    return True


def run_templates(url, delay=0):
    """Run all loaded YAML templates against the target URL."""
    templates = load_templates()
    if not templates:
        return []

    log_info(f"Running {len(templates)} YAML templates against {url}")
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    vulns = []

    for tpl in templates:
        tid = tpl.get("id")
        name = tpl.get("info", {}).get("name", "Unknown vulnerability")
        severity = tpl.get("info", {}).get("severity", "info").upper()

        for req in tpl.get("requests", []):
            method = req.get("method", "GET").lower()
            paths = req.get("path", ["/"])
            headers = req.get("headers", {})
            body = req.get("body", None)
            matchers = req.get("matchers", [])

            for path in paths:
                # Handle Nuclei style {{BaseURL}} substitution
                path = path.replace("{{BaseURL}}", "")
                if not path.startswith("/"):
                    path = "/" + path

                target = urljoin(base_url, path)

                try:
                    resp = smart_request(
                        method,
                        target,
                        headers=headers,
                        data=body,
                        delay=delay,
                        allow_redirects=False,
                    )
                    if _match_response(resp, matchers):
                        increment_vulnerability_count()

                        log_vuln(f"TEMPLATE MATCH! [{tid}] - {name} ({severity})")
                        log_success(f"Target: {target}")

                        vulns.append(
                            {
                                "type": "Template",
                                "id": tid,
                                "name": name,
                                "severity": severity,
                                "url": target,
                                "method": method.upper(),
                            }
                        )
                        # Usually break after first successful path per request block
                        break

                except Exception as e:
                    pass

    return vulns
