"""
cyberm4fia-scanner - Guaranteed Findings Generator
Deep security checks that produce actionable findings on ANY target.

Unlike exploit modules that require injection points, these checks analyze
the target's security posture from the outside and are guaranteed to
produce meaningful results regardless of WAF/CDN/framework.

Categories:
  1. Sensitive File & Path Probing
  2. Information Disclosure Detection
  3. SSL/TLS Deep Analysis
  4. DNS Security Analysis (SPF/DKIM/DMARC)
  5. Security Misconfiguration Detection
"""

import re
import json
import socket
import ssl
import time
import os
from urllib.parse import urlparse, urljoin
from datetime import datetime

from utils.colors import log_info, log_success, log_warning, log_vuln
from utils.request import smart_request, increment_vulnerability_count, ScanExceptions
from utils.brand_protection import check_phishing_domains
from utils.qishing import analyze_image_for_qishing, QR_MODULES_AVAILABLE
from modules.osv_scanner import check_tech_stack_vulns, analyze_exposed_manifest

# ── Sensitive Files & Paths ──────────────────────────────────────────────
SENSITIVE_PATHS = [
    # Version Control
    ("/.git/config", ["[core]", "[remote", "repositoryformatversion"], "Git Config Exposed", "HIGH"),
    ("/.git/HEAD", ["ref: refs/", "heads/"], "Git HEAD Exposed", "HIGH"),
    ("/.svn/entries", ["svn", "dir"], "SVN Entries Exposed", "HIGH"),
    ("/.hg/requires", ["revlogv1", "store"], "Mercurial Config Exposed", "HIGH"),

    # Environment & Config Files
    ("/.env", ["DB_", "APP_", "SECRET", "KEY=", "PASSWORD", "TOKEN"], "Environment File Exposed", "CRITICAL"),
    ("/.env.local", ["DB_", "APP_", "SECRET"], ".env.local Exposed", "CRITICAL"),
    ("/.env.production", ["DB_", "APP_", "SECRET"], ".env.production Exposed", "CRITICAL"),
    ("/.env.backup", ["DB_", "APP_"], ".env.backup Exposed", "CRITICAL"),
    ("/config.php.bak", ["<?php", "mysql", "password"], "PHP Config Backup Exposed", "CRITICAL"),
    ("/wp-config.php.bak", ["DB_NAME", "DB_PASSWORD", "DB_HOST"], "WordPress Config Backup", "CRITICAL"),
    ("/config.yml", ["database:", "secret:", "password:"], "YAML Config Exposed", "HIGH"),
    ("/config.json", ["password", "secret", "apiKey"], "JSON Config Exposed", "HIGH"),
    ("/composer.json", ["require", "autoload"], "Composer Config Exposed", "LOW"),
    ("/package.json", ["dependencies", "scripts"], "Package.json Exposed", "LOW"),
    ("/Gemfile", ["source", "gem "], "Gemfile Exposed", "LOW"),

    # Debug & Admin
    ("/phpinfo.php", ["phpinfo()", "PHP Version", "php_uname"], "PHPInfo Exposed", "HIGH"),
    ("/info.php", ["phpinfo()", "PHP Version"], "PHP Info Page", "HIGH"),
    ("/debug", ["debug", "traceback", "stack"], "Debug Mode Active", "MEDIUM"),
    ("/server-status", ["Apache Server Status", "Total accesses"], "Apache Server Status", "MEDIUM"),
    ("/server-info", ["Apache Server Information"], "Apache Server Info", "MEDIUM"),
    ("/nginx-status", ["Active connections", "server accepts"], "Nginx Status Page", "MEDIUM"),
    ("/_debug", ["django", "traceback", "debug"], "Django Debug", "HIGH"),
    ("/__debug__/", ["django", "toolbar"], "Django Debug Toolbar", "HIGH"),

    # Backup Files
    ("/backup.sql", ["INSERT INTO", "CREATE TABLE", "DROP TABLE"], "SQL Backup Exposed", "CRITICAL"),
    ("/dump.sql", ["INSERT INTO", "CREATE TABLE"], "SQL Dump Exposed", "CRITICAL"),
    ("/database.sql", ["INSERT INTO", "CREATE TABLE"], "Database Dump Exposed", "CRITICAL"),
    ("/backup.zip", [], "Backup Archive Found", "HIGH"),
    ("/backup.tar.gz", [], "Backup Archive Found", "HIGH"),
    ("/site.tar.gz", [], "Site Archive Found", "HIGH"),

    # API Docs
    ("/swagger.json", ["swagger", "paths", "definitions"], "Swagger API Docs Exposed", "MEDIUM"),
    ("/openapi.json", ["openapi", "paths", "components"], "OpenAPI Docs Exposed", "MEDIUM"),
    ("/api-docs", ["swagger", "api"], "API Documentation Exposed", "LOW"),
    ("/swagger-ui/", ["swagger", "api"], "Swagger UI Exposed", "LOW"),
    ("/graphql", ["query", "type"], "GraphQL Endpoint Found", "LOW"),
    ("/graphiql", ["graphiql", "graphql"], "GraphiQL Interface Exposed", "MEDIUM"),

    # Error pages & logs
    ("/error.log", ["[error]", "warning", "fatal"], "Error Log Exposed", "HIGH"),
    ("/access.log", ["GET ", "POST ", "HTTP/"], "Access Log Exposed", "MEDIUM"),
    ("/debug.log", ["debug", "error", "warning"], "Debug Log Exposed", "HIGH"),
    ("/application.log", ["error", "exception", "trace"], "Application Log Exposed", "HIGH"),

    # Source Maps
    ("/main.js.map", ["sources", "mappings", "sourceRoot"], "JavaScript Source Map", "MEDIUM"),
    ("/app.js.map", ["sources", "mappings"], "App Source Map", "MEDIUM"),
    ("/bundle.js.map", ["sources", "mappings"], "Bundle Source Map", "MEDIUM"),

    # Cloud Metadata (if directly accessible)
    ("/latest/meta-data/", ["ami-id", "instance-id", "instance-type"], "AWS Metadata Accessible", "CRITICAL"),

    # Admin panels
    ("/admin", ["admin", "login", "dashboard"], "Admin Panel Found", "LOW"),
    ("/admin/login", ["login", "password", "username"], "Admin Login Found", "LOW"),
    ("/wp-admin/", ["wordpress", "login", "wp-"], "WordPress Admin", "LOW"),
    ("/administrator/", ["administrator", "login"], "Joomla Admin", "LOW"),

    # Well-known
    ("/.well-known/security.txt", ["Contact:", "Policy:"], "Security.txt Found", "INFO"),
    ("/.well-known/openid-configuration", ["issuer", "authorization_endpoint"], "OpenID Config", "INFO"),
]

# ── Source Map Detection Paths (dynamic) ────────────────────────────────
SOURCE_MAP_PATTERNS = [
    "//# sourceMappingURL=",
    "//@ sourceMappingURL=",
]


def _check_sensitive_files(url, delay):
    """Probe for sensitive files and paths."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    log_info("🔎 Probing for sensitive files & paths...")

    checked = 0
    for path, signatures, name, severity in SENSITIVE_PATHS:
        try:
            test_url = urljoin(base, path)
            resp = smart_request("get", test_url, delay=delay)

            # Skip 404, 403, redirects to login, etc.
            if resp.status_code in [404, 403, 401, 405, 500, 502, 503]:
                continue

            if resp.status_code == 200:
                # Check for actual content (not a generic 200 page)
                if signatures:
                    text_lower = resp.text.lower()
                    matched_sigs = [
                        s for s in signatures
                        if s.lower() in text_lower
                    ]
                    if matched_sigs:
                        increment_vulnerability_count()
                        log_vuln(f"[{severity}] {name}: {test_url}")
                        findings.append({
                            "type": "Sensitive_File",
                            "url": test_url,
                            "path": path,
                            "description": name,
                            "severity": severity,
                            "matched_signatures": matched_sigs[:3],
                            "evidence": resp.text[:300],
                        })
                        
                        # OSV-Scanner Integration: Check dependencies if it's a manifest
                        if "package.json" in path or "composer.json" in path:
                            manifest_type = "package.json" if "package.json" in path else "composer.json"
                            osv_findings = analyze_exposed_manifest(test_url, resp.text, manifest_type)
                            if osv_findings:
                                findings.extend(osv_findings)
                else:
                    # Binary files (zip, tar.gz) — check content-type
                    ct = resp.headers.get("content-type", "")
                    if any(t in ct.lower() for t in [
                        "application/zip", "application/gzip",
                        "application/x-tar", "application/octet-stream",
                    ]):
                        increment_vulnerability_count()
                        log_vuln(f"[{severity}] {name}: {test_url}")
                        findings.append({
                            "type": "Sensitive_File",
                            "url": test_url,
                            "path": path,
                            "description": name,
                            "severity": severity,
                            "content_type": ct,
                        })

            # Also check for 301/302 to non-login pages
            elif resp.status_code in [301, 302]:
                location = resp.headers.get("location", "")
                # If redirect is to the same path (not login), might be accessible
                if path.rstrip("/") in location and "login" not in location.lower():
                    findings.append({
                        "type": "Sensitive_Path_Redirect",
                        "url": test_url,
                        "path": path,
                        "description": f"{name} (redirect to {location})",
                        "severity": "LOW",
                    })

            checked += 1
        except ScanExceptions:
            continue

    return findings


def _check_source_maps(url, delay):
    """Detect JavaScript source maps."""
    findings = []

    try:
        resp = smart_request("get", url, delay=delay)
        if resp.status_code != 200:
            return findings

        # Find JS file references
        js_files = re.findall(
            r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
            resp.text,
        )

        # Also check inline sourceMappingURL
        for pattern in SOURCE_MAP_PATTERNS:
            maps = re.findall(
                rf'{re.escape(pattern)}(\S+)',
                resp.text,
            )
            for map_url in maps:
                full_url = urljoin(url, map_url)
                try:
                    map_resp = smart_request("get", full_url, delay=delay)
                    if map_resp.status_code == 200 and "sources" in map_resp.text:
                        increment_vulnerability_count()
                        log_vuln(f"Source Map Found: {full_url}")

                        # Extract source file names
                        try:
                            map_data = map_resp.json()
                            sources = map_data.get("sources", [])[:10]
                        except (json.JSONDecodeError, ValueError):
                            sources = []

                        findings.append({
                            "type": "Source_Map_Exposure",
                            "url": full_url,
                            "description": (
                                "JavaScript source map exposes original source code. "
                                f"Contains {len(sources)} source file(s)."
                            ),
                            "severity": "MEDIUM",
                            "sources": sources,
                        })
                except ScanExceptions:
                    pass

        # Check .js.map for each JS file
        for js_file in js_files[:10]:
            js_url = urljoin(url, js_file)
            map_url = js_url.split("?")[0] + ".map"
            try:
                map_resp = smart_request("get", map_url, delay=delay)
                if map_resp.status_code == 200 and "sources" in map_resp.text:
                    try:
                        map_data = map_resp.json()
                        sources = map_data.get("sources", [])[:10]
                    except (json.JSONDecodeError, ValueError):
                        sources = []

                    if sources:
                        increment_vulnerability_count()
                        log_vuln(f"Source Map Found: {map_url}")
                        findings.append({
                            "type": "Source_Map_Exposure",
                            "url": map_url,
                            "description": (
                                f"Source map for {js_file} exposes "
                                f"{len(sources)} source file(s)."
                            ),
                            "severity": "MEDIUM",
                            "sources": sources,
                        })
            except ScanExceptions:
                pass

    except ScanExceptions:
        pass

    return findings


def _check_version_disclosure(url, delay):
    """Detect version disclosure in headers and meta tags."""
    findings = []

    try:
        resp = smart_request("get", url, delay=delay)

        # Check headers for version info
        version_headers = {
            "server": "Server Version Disclosed",
            "x-powered-by": "Technology Stack Disclosed",
            "x-aspnet-version": "ASP.NET Version Disclosed",
            "x-aspnetmvc-version": "ASP.NET MVC Version Disclosed",
            "x-generator": "Generator Disclosed",
            "x-drupal-cache": "Drupal Detected",
            "x-varnish": "Varnish Cache Detected",
            "x-runtime": "Runtime Info Disclosed",
        }

        for header, desc in version_headers.items():
            value = resp.headers.get(header, "")
            if value:
                # Check if it contains a version number
                if re.search(r'\d+\.\d+', value) or header in [
                    "x-powered-by", "server", "x-aspnet-version",
                    "x-aspnetmvc-version",
                ]:
                    findings.append({
                        "type": "Version_Disclosure",
                        "url": url,
                        "header": header,
                        "value": value,
                        "description": f"{desc}: {value}",
                        "severity": "LOW",
                    })

        # Check meta generator tag
        generator_match = re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
            resp.text,
            re.IGNORECASE,
        )
        if generator_match:
            gen_value = generator_match.group(1)
            findings.append({
                "type": "Version_Disclosure",
                "url": url,
                "header": "meta-generator",
                "value": gen_value,
                "description": f"CMS/Framework disclosed via meta tag: {gen_value}",
                "severity": "LOW",
            })
            
            # Try to extract version and check OSV
            version_match = re.search(r'([\d\.]+)', gen_value)
            if version_match:
                name_clean = gen_value.replace(version_match.group(1), "").strip().lower()
                if name_clean:
                    tech_stack = {name_clean: version_match.group(1).strip(".")}
                    osv_findings = check_tech_stack_vulns(url, tech_stack)
                    if osv_findings:
                        findings.extend(osv_findings)

        # Check for error page version disclosure
        error_urls = [
            urljoin(url, "/this-page-definitely-does-not-exist-404-test"),
            urljoin(url, "/a" * 300),  # Long URL might trigger different error
        ]
        for err_url in error_urls:
            try:
                err_resp = smart_request("get", err_url, delay=delay)
                # Look for version strings in error pages
                version_patterns = [
                    r"Apache/(\d+\.\d+\.\d+)",
                    r"nginx/(\d+\.\d+\.\d+)",
                    r"Microsoft-IIS/(\d+\.\d+)",
                    r"PHP/(\d+\.\d+\.\d+)",
                    r"Node\.js v(\d+\.\d+\.\d+)",
                    r"Express (\d+\.\d+)",
                ]
                for pat in version_patterns:
                    match = re.search(pat, err_resp.text, re.IGNORECASE)
                    if match:
                        increment_vulnerability_count()
                        findings.append({
                            "type": "Version_Disclosure_Error",
                            "url": err_url,
                            "description": (
                                f"Version disclosed in error page: "
                                f"{match.group(0)}"
                            ),
                            "severity": "LOW",
                            "evidence": match.group(0),
                        })
                        break
            except ScanExceptions:
                pass

    except ScanExceptions:
        pass

    return findings


def _check_ssl_tls(url, delay):
    """Deep SSL/TLS analysis."""
    findings = []
    parsed = urlparse(url)

    if parsed.scheme != "https":
        findings.append({
            "type": "No_HTTPS",
            "url": url,
            "description": "Site does not use HTTPS — all traffic is unencrypted.",
            "severity": "HIGH",
        })
        return findings

    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

                # Check certificate expiry
                if cert:
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        try:
                            expiry = datetime.strptime(
                                not_after, "%b %d %H:%M:%S %Y %Z"
                            )
                            days_left = (expiry - datetime.utcnow()).days

                            if days_left < 0:
                                increment_vulnerability_count()
                                findings.append({
                                    "type": "SSL_Certificate_Expired",
                                    "url": url,
                                    "description": (
                                        f"SSL certificate expired "
                                        f"{abs(days_left)} days ago!"
                                    ),
                                    "severity": "HIGH",
                                    "expiry_date": not_after,
                                })
                            elif days_left < 30:
                                findings.append({
                                    "type": "SSL_Certificate_Expiring",
                                    "url": url,
                                    "description": (
                                        f"SSL certificate expires in "
                                        f"{days_left} day(s)"
                                    ),
                                    "severity": "MEDIUM",
                                    "expiry_date": not_after,
                                })
                        except ValueError:
                            pass

                    # Check certificate subject
                    subject = dict(
                        x[0] for x in cert.get("subject", ())
                    )
                    issuer = dict(
                        x[0] for x in cert.get("issuer", ())
                    )

                    # Self-signed check
                    if subject == issuer:
                        increment_vulnerability_count()
                        findings.append({
                            "type": "SSL_Self_Signed",
                            "url": url,
                            "description": "Self-signed SSL certificate detected.",
                            "severity": "MEDIUM",
                        })

                # Check cipher strength
                if cipher:
                    cipher_name = cipher[0]
                    weak_ciphers = [
                        "RC4", "DES", "3DES", "NULL",
                        "EXPORT", "anon", "MD5",
                    ]
                    for weak in weak_ciphers:
                        if weak.upper() in cipher_name.upper():
                            increment_vulnerability_count()
                            findings.append({
                                "type": "SSL_Weak_Cipher",
                                "url": url,
                                "description": (
                                    f"Weak cipher in use: {cipher_name}"
                                ),
                                "severity": "MEDIUM",
                                "cipher": cipher_name,
                            })
                            break

    except ssl.SSLError as e:
        findings.append({
            "type": "SSL_Error",
            "url": url,
            "description": f"SSL/TLS error: {e}",
            "severity": "MEDIUM",
        })
    except (socket.timeout, socket.error, OSError):
        pass

    return findings


def _check_dns_security(url, delay):
    """Check DNS security records (SPF, DKIM, DMARC)."""
    import subprocess

    findings = []
    parsed = urlparse(url)
    domain = parsed.hostname
    if not domain:
        return findings

    log_info(f"🔐 Checking DNS security for {domain}...")

    dns_checks = [
        (domain, "TXT", "SPF", "v=spf1"),
        (f"_dmarc.{domain}", "TXT", "DMARC", "v=dmarc1"),
    ]

    for query_domain, record_type, check_name, expected_prefix in dns_checks:
        try:
            result = subprocess.run(
                ["dig", "+short", record_type, query_domain],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout.strip()

            if not output or expected_prefix.lower() not in output.lower():
                findings.append({
                    "type": f"DNS_{check_name}_Missing",
                    "url": url,
                    "domain": domain,
                    "description": (
                        f"{check_name} record not found for {domain}. "
                        f"Email spoofing may be possible."
                    ),
                    "severity": "MEDIUM",
                })
            else:
                # Check for weak SPF (e.g., +all)
                if check_name == "SPF" and "+all" in output:
                    increment_vulnerability_count()
                    findings.append({
                        "type": "DNS_SPF_Permissive",
                        "url": url,
                        "domain": domain,
                        "description": (
                            "SPF record uses '+all' — any server "
                            "can send email as this domain."
                        ),
                        "severity": "HIGH",
                        "record": output,
                    })
                elif check_name == "SPF" and "~all" in output:
                    findings.append({
                        "type": "DNS_SPF_Softfail",
                        "url": url,
                        "domain": domain,
                        "description": (
                            "SPF uses soft fail (~all). Consider "
                            "using hard fail (-all) for better protection."
                        ),
                        "severity": "LOW",
                        "record": output,
                    })

                # Check DMARC policy
                if check_name == "DMARC":
                    if "p=none" in output.lower():
                        findings.append({
                            "type": "DNS_DMARC_None",
                            "url": url,
                            "domain": domain,
                            "description": (
                                "DMARC policy is 'none' — no enforcement. "
                                "Should be 'quarantine' or 'reject'."
                            ),
                            "severity": "LOW",
                            "record": output,
                        })

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    return findings


def _check_security_misconfig(url, delay):
    """Check for common security misconfigurations."""
    findings = []

    try:
        resp = smart_request("get", url, delay=delay)

        # ── CORS Wildcard Check ──
        try:
            cors_resp = smart_request(
                "get", url, delay=delay,
                headers={"Origin": "https://evil.com"},
            )
            acao = cors_resp.headers.get("access-control-allow-origin", "")
            acac = cors_resp.headers.get(
                "access-control-allow-credentials", ""
            )

            if acao == "*":
                findings.append({
                    "type": "CORS_Wildcard",
                    "url": url,
                    "description": (
                        "CORS allows any origin (*). If credentials "
                        "are not used, this may be acceptable."
                    ),
                    "severity": "LOW",
                })
            elif "evil.com" in acao:
                severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                increment_vulnerability_count()
                findings.append({
                    "type": "CORS_Misconfigured",
                    "url": url,
                    "description": (
                        "CORS reflects arbitrary Origin header"
                        + (
                            " WITH credentials — critical data "
                            "exfiltration possible!"
                            if severity == "HIGH"
                            else "."
                        )
                    ),
                    "severity": severity,
                    "evidence": f"ACAO: {acao}, ACAC: {acac}",
                })
        except ScanExceptions:
            pass

        # ── Cache Control ──
        cache_control = resp.headers.get("cache-control", "")
        if not cache_control or "no-store" not in cache_control.lower():
            # Check if the page has sensitive content indicators
            sensitive_indicators = [
                "password", "login", "account", "profile",
                "dashboard", "admin",
            ]
            if any(ind in resp.text.lower()[:2000] for ind in sensitive_indicators):
                findings.append({
                    "type": "Missing_Cache_Control",
                    "url": url,
                    "description": (
                        "Page with sensitive content lacks "
                        "'Cache-Control: no-store'. Sensitive data "
                        "may be cached by proxies."
                    ),
                    "severity": "LOW",
                })

        # ── HTTP to HTTPS Redirect ──
        if url.startswith("https://"):
            http_url = url.replace("https://", "http://", 1)
            try:
                http_resp = smart_request(
                    "get", http_url, delay=delay,
                    follow_redirects=False,
                )
                if http_resp.status_code == 200:
                    findings.append({
                        "type": "No_HTTPS_Redirect",
                        "url": http_url,
                        "description": (
                            "HTTP version of the site is accessible "
                            "without redirect to HTTPS."
                        ),
                        "severity": "MEDIUM",
                    })
            except ScanExceptions:
                pass

        # ── Clickjacking (detailed) ──
        xfo = resp.headers.get("x-frame-options", "")
        csp = resp.headers.get("content-security-policy", "")
        if not xfo and "frame-ancestors" not in csp:
            findings.append({
                "type": "Clickjacking_Vulnerable",
                "url": url,
                "description": (
                    "No X-Frame-Options or CSP frame-ancestors. "
                    "Page can be embedded in an iframe for "
                    "clickjacking attacks."
                ),
                "severity": "MEDIUM",
            })

    except ScanExceptions:
        pass

    return findings


def _check_brand_protection(url, delay):
    """Deep check for typosquatting domains and Brand Protection issues."""
    findings = []
    try:
        log_info("  → Checking Brand Protection (DNS Typosquatting)...")
        bp_findings = check_phishing_domains(url)
        if bp_findings:
            increment_vulnerability_count(len(bp_findings))
            findings.extend(bp_findings)
    except Exception as e:
        log_warning(f"Error during brand protection check: {e}")
    return findings


def _check_qishing(url, delay):
    """Crawl images on the page and detect potential QR Phishing (Qishing)."""
    findings = []
    if not QR_MODULES_AVAILABLE:
        log_warning("  → Skipping Qishing check: pyzbar/pillow not installed.")
        return findings

    try:
        log_info("  → Checking for Qishing (QR Code Phishing)...")
        resp = smart_request("get", url, delay=delay)
        if resp.status_code != 200:
            return findings

        # Extract all image tags
        import re
        img_srcs = re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
        
        parsed_target = urlparse(url)
        target_domain = parsed_target.netloc.split(':')[0]
        
        checked_imgs = 0
        for src in img_srcs:
            if checked_imgs >= 10:  # Limit to 10 images to save time
                break
                
            img_url = urljoin(url, src)
            try:
                # Fetch image bytes
                img_resp = smart_request("get", img_url, delay=delay)
                if img_resp.status_code == 200:
                    q_findings = analyze_image_for_qishing(img_url, img_resp.content, target_domain)
                    if q_findings:
                        for f in q_findings:
                            if f["severity"] == "HIGH":
                                increment_vulnerability_count()
                        findings.extend(q_findings)
            except ScanExceptions:
                pass
            checked_imgs += 1
            
    except Exception as e:
        log_warning(f"Error during qishing check: {e}")
        
    return findings


def scan_guaranteed(url, delay, options=None):
    """
    Run all guaranteed finding checks.

    Returns list of vulnerability/finding dicts.
    """
    options = options or {}
    all_findings = []

    log_info("🎯 Running Guaranteed Security Checks...")

    # 1. Sensitive File Probing
    all_findings.extend(_check_sensitive_files(url, delay))

    # 2. Source Map Detection
    all_findings.extend(_check_source_maps(url, delay))

    # 3. Version Disclosure
    all_findings.extend(_check_version_disclosure(url, delay))

    # 4. SSL/TLS Analysis
    all_findings.extend(_check_ssl_tls(url, delay))

    # 5. DNS Security
    all_findings.extend(_check_dns_security(url, delay))

    # 6. Security Misconfiguration
    all_findings.extend(_check_security_misconfig(url, delay))
    
    # 7. Brand Protection (Typosquatting)
    all_findings.extend(_check_brand_protection(url, delay))
    
    # 8. Qishing (QR Code Phishing)
    all_findings.extend(_check_qishing(url, delay))

    if all_findings:
        log_success(
            f"🎯 Guaranteed checks complete: "
            f"{len(all_findings)} finding(s)"
        )
    else:
        log_info("🎯 Guaranteed checks: No additional findings.")

    return all_findings
