"""
cyberm4fia-scanner - Business Logic Scanner
Detects logic flaws: price manipulation, quantity abuse, role escalation,
duplicate actions, negative values, and parameter tampering.
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.colors import log_info, log_success
from utils.request import smart_request
from utils.request import ScanExceptions

# ─────────────────────────────────────────────────────
# Business Logic Test Patterns
# ─────────────────────────────────────────────────────
PRICE_PARAMS = [
    "price",
    "amount",
    "cost",
    "total",
    "fee",
    "charge",
    "rate",
    "value",
    "sum",
]
QUANTITY_PARAMS = ["quantity", "qty", "count", "num", "number", "items", "units"]
ROLE_PARAMS = [
    "role", "user_type", "usertype", "type", "level", "access",
    "privilege", "is_admin", "isAdmin", "admin", "ADMIN", "Admin",
    "is_staff", "group", "isadmin", "ISADMIN", "user_priv",
]
ID_PARAMS = [
    "id", "user_id", "uid", "account_id", "account", "profile_id",
    "userId", "album_id", "order_id", "item_id", "doc_id", "file_id",
    "msg_id", "comment_id", "invoice_id", "ticket_id",
]
DISCOUNT_PARAMS = ["discount", "coupon", "promo", "code", "voucher", "offer"]

# Manipulation values
NEGATIVE_VALUES = ["-1", "-100", "-999", "-0.01"]
ZERO_VALUES = ["0", "0.00", "0.001"]
OVERFLOW_VALUES = ["999999999", "2147483647", "99999.99"]
ROLE_VALUES = [
    "admin", "ADMIN", "Admin", "administrator", "root",
    "superuser", "staff", "moderator", "1", "true",
]
IDOR_VALUES = ["1", "0", "2", "admin", "root"]

# Advanced IDOR — HTTP methods for method-switching bypass
IDOR_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

# Advanced IDOR — file extensions to append for access bypass
IDOR_FILE_EXTENSIONS = [".json", ".xml", ".txt", ".config", ".csv"]

# Advanced IDOR — API version downgrade paths
IDOR_VERSION_DOWNGRADES = ["/v1/", "/v2/", "/api/v1/", "/api/v2/"]

# Advanced Mass Assignment — extra field payloads
MASS_ASSIGNMENT_PAYLOADS = [
    {"admin": True}, {"ADMIN": True}, {"Admin": True},
    {"isadmin": True}, {"ISADMIN": True}, {"is_admin": True},
    {"role": "admin"}, {"role": "ADMIN"}, {"role": "administrator"},
    {"user_priv": "admin"}, {"user_priv": "administrator"},
    {"admin": 1}, {"admin": "1"}, {"verified": True},
    {"active": True}, {"approved": True}, {"is_staff": True},
    {"credits": 99999}, {"balance": 99999},
    {"org": "target_org"}, {"account_type": "premium"},
]

def _detect_form_params(forms):
    """Analyze forms to find interesting parameters for logic testing."""
    targets = []

    for form in forms:
        inputs = form.get("inputs", [])
        action = form.get("action", "")
        method = form.get("method", "GET").upper()

        for inp in inputs:
            name = ""
            if hasattr(inp, "get"):
                name = inp.get("name", "")
            elif hasattr(inp, "attrs"):
                name = inp.get("name", "")
            if not name:
                continue

            name_lower = name.lower()

            # Classify the parameter
            param_type = None
            if any(p in name_lower for p in PRICE_PARAMS):
                param_type = "price"
            elif any(p in name_lower for p in QUANTITY_PARAMS):
                param_type = "quantity"
            elif any(p in name_lower for p in ROLE_PARAMS):
                param_type = "role"
            elif any(p in name_lower for p in ID_PARAMS):
                param_type = "idor"
            elif any(p in name_lower for p in DISCOUNT_PARAMS):
                param_type = "discount"

            if param_type:
                targets.append(
                    {
                        "action": action,
                        "method": method,
                        "param_name": name,
                        "param_type": param_type,
                        "form": form,
                    }
                )

    return targets

def _detect_url_params(url):
    """Detect interesting parameters in URL query string."""
    targets = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for param_name in params:
        name_lower = param_name.lower()

        param_type = None
        if any(p in name_lower for p in PRICE_PARAMS):
            param_type = "price"
        elif any(p in name_lower for p in QUANTITY_PARAMS):
            param_type = "quantity"
        elif any(p in name_lower for p in ROLE_PARAMS):
            param_type = "role"
        elif any(p in name_lower for p in ID_PARAMS):
            param_type = "idor"
        elif any(p in name_lower for p in DISCOUNT_PARAMS):
            param_type = "discount"

        if param_type:
            targets.append(
                {
                    "action": url,
                    "method": "GET",
                    "param_name": param_name,
                    "param_type": param_type,
                    "original_value": params[param_name][0],
                }
            )

    return targets

def _test_price_manipulation(url, param_name, method="GET", form_data=None, delay=0):
    """Test if price can be manipulated to negative or zero."""
    findings = []

    test_values = NEGATIVE_VALUES + ZERO_VALUES

    for value in test_values:
        try:
            if method == "POST":
                data = dict(form_data or {})
                data[param_name] = value
                resp = smart_request("post", url, data=data, delay=delay, timeout=5)
            else:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param_name] = [value]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                resp = smart_request("get", test_url, delay=delay, timeout=5)

            # Check if the request was accepted (not rejected)
            if resp.status_code in (200, 201, 302):
                # Look for signs of acceptance
                body_lower = resp.text.lower()
                rejected = any(
                    kw in body_lower
                    for kw in [
                        "invalid",
                        "error",
                        "must be positive",
                        "cannot be negative",
                        "minimum",
                        "not allowed",
                    ]
                )

                if not rejected:
                    findings.append(
                        {
                            "type": "Business Logic",
                            "vuln": "Price Manipulation",
                            "param": param_name,
                            "payload": value,
                            "severity": "HIGH",
                            "description": f"Server accepted {param_name}={value} without validation",
                            "url": url,
                        }
                    )
                    log_success(f"💰 Price manipulation! {param_name}={value} accepted")
                    return findings  # One is enough

        except ScanExceptions:
            pass

    return findings

def _test_quantity_abuse(url, param_name, method="GET", form_data=None, delay=0):
    """Test quantity for negative, zero, and overflow values."""
    findings = []

    test_values = NEGATIVE_VALUES + ZERO_VALUES + OVERFLOW_VALUES

    for value in test_values:
        try:
            if method == "POST":
                data = dict(form_data or {})
                data[param_name] = value
                resp = smart_request("post", url, data=data, delay=delay, timeout=5)
            else:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param_name] = [value]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                resp = smart_request("get", test_url, delay=delay, timeout=5)

            if resp.status_code in (200, 201, 302):
                body_lower = resp.text.lower()
                rejected = any(
                    kw in body_lower
                    for kw in [
                        "invalid",
                        "error",
                        "minimum",
                        "maximum",
                        "out of range",
                    ]
                )
                if not rejected:
                    vuln_type = (
                        "Negative Quantity"
                        if "-" in value
                        else (
                            "Zero Quantity"
                            if value.startswith("0")
                            else "Quantity Overflow"
                        )
                    )
                    findings.append(
                        {
                            "type": "Business Logic",
                            "vuln": vuln_type,
                            "param": param_name,
                            "payload": value,
                            "severity": "HIGH" if "-" in value else "MEDIUM",
                            "description": f"{vuln_type}: {param_name}={value} accepted",
                            "url": url,
                        }
                    )
                    log_success(f"📦 {vuln_type}! {param_name}={value}")
                    return findings

        except ScanExceptions:
            pass

    return findings

def _test_role_escalation(url, param_name, method="GET", form_data=None, delay=0):
    """Test if role/privilege can be escalated."""
    findings = []

    for value in ROLE_VALUES:
        try:
            if method == "POST":
                data = dict(form_data or {})
                data[param_name] = value
                resp = smart_request("post", url, data=data, delay=delay, timeout=5)
            else:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param_name] = [value]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                resp = smart_request("get", test_url, delay=delay, timeout=5)

            if resp.status_code in (200, 201, 302):
                body_lower = resp.text.lower()
                # Check if we got elevated access indicators
                elevated = any(
                    kw in body_lower
                    for kw in [
                        "admin",
                        "dashboard",
                        "panel",
                        "management",
                        "settings",
                        "configuration",
                        "users",
                    ]
                )
                if elevated:
                    findings.append(
                        {
                            "type": "Business Logic",
                            "vuln": "Role Escalation",
                            "param": param_name,
                            "payload": value,
                            "severity": "CRITICAL",
                            "description": f"Role escalation via {param_name}={value}",
                            "url": url,
                        }
                    )
                    log_success(f"👑 Role escalation! {param_name}={value}")
                    return findings

        except ScanExceptions:
            pass

    return findings

def _test_idor(url, param_name, method="GET", form_data=None, delay=0):
    """Test for Insecure Direct Object Reference with 20+ advanced techniques."""
    findings = []

    # Get baseline with original value
    try:
        baseline = smart_request(
            "get" if method == "GET" else "post", url, delay=delay, timeout=5
        )
        baseline_len = len(baseline.text)
        baseline_status = baseline.status_code
    except ScanExceptions:
        return findings

    def _report_idor(technique, payload, resp):
        findings.append({
            "type": "Business Logic",
            "vuln": "IDOR",
            "param": param_name,
            "payload": f"{technique}: {payload}",
            "severity": "HIGH",
            "description": f"IDOR via {technique} — {param_name}={payload}",
            "url": url,
        })
        log_success(f"🔓 IDOR via {technique}! {param_name}={payload}")

    # Technique 1: Classic ID swap
    for value in IDOR_VALUES:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = [value]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            resp = smart_request("get", test_url, delay=delay, timeout=5)
            if resp.status_code == 200 and abs(len(resp.text) - baseline_len) > 100:
                _report_idor("ID Swap", value, resp)
                return findings
        except ScanExceptions:
            pass

    # Technique 2: HTTP Method Switching (GET→POST→PUT→DELETE)
    if baseline_status == 403:
        for alt_method in IDOR_METHODS:
            if alt_method == method:
                continue
            try:
                resp = smart_request(
                    alt_method.lower(), url, delay=delay, timeout=5
                )
                if resp.status_code == 200:
                    _report_idor("Method Switch", alt_method, resp)
                    return findings
            except ScanExceptions:
                pass

    # Technique 3: Path Traversal IDOR (/users/delete/my_id/../victim_id)
    parsed = urlparse(url)
    path = parsed.path
    if path.count("/") >= 2:
        segments = path.rstrip("/").rsplit("/", 1)
        for victim_id in ["1", "2", "0"]:
            traversal_path = f"{segments[0]}/..{victim_id}"
            try:
                test_url = urlunparse(parsed._replace(path=traversal_path))
                resp = smart_request("get", test_url, delay=delay, timeout=5)
                if resp.status_code == 200 and abs(len(resp.text) - baseline_len) > 100:
                    _report_idor("Path Traversal", traversal_path, resp)
                    return findings
            except ScanExceptions:
                pass

    # Technique 4: File Extension Append (.json, .xml, .txt)
    for ext in IDOR_FILE_EXTENSIONS:
        try:
            test_url = url.rstrip("/") + ext
            resp = smart_request("get", test_url, delay=delay, timeout=5)
            if resp.status_code == 200 and baseline_status in (401, 403):
                _report_idor("Extension Bypass", ext, resp)
                return findings
        except ScanExceptions:
            pass

    # Technique 5: Case Manipulation on path (/Admin, /ADMIN, /aDmin)
    path_lower = parsed.path.lower()
    if "admin" in path_lower:
        case_variants = [
            parsed.path.replace("admin", v)
            for v in ["Admin", "ADMIN", "aDmin", "adMin", "admIn", "admiN"]
        ]
        for variant in case_variants:
            try:
                test_url = urlunparse(parsed._replace(path=variant))
                resp = smart_request("get", test_url, delay=delay, timeout=5)
                if resp.status_code == 200 and baseline_status in (401, 403):
                    _report_idor("Case Manipulation", variant, resp)
                    return findings
            except ScanExceptions:
                pass

    # Technique 6: Wildcard ID (/api/users/*)
    if param_name in parsed.query or parsed.path.rstrip("/").split("/")[-1].isdigit():
        try:
            wildcard_path = "/".join(parsed.path.rstrip("/").split("/")[:-1]) + "/*"
            test_url = urlunparse(parsed._replace(path=wildcard_path))
            resp = smart_request("get", test_url, delay=delay, timeout=5)
            if resp.status_code == 200 and len(resp.text) > baseline_len * 2:
                _report_idor("Wildcard ID", "*", resp)
                return findings
        except ScanExceptions:
            pass

    # Technique 7: API Version Downgrade (/v3/ → /v1/)
    for old_ver in IDOR_VERSION_DOWNGRADES:
        if "/v3/" in parsed.path or "/v4/" in parsed.path:
            try:
                downgraded = parsed.path.replace("/v3/", old_ver).replace("/v4/", old_ver)
                test_url = urlunparse(parsed._replace(path=downgraded))
                resp = smart_request("get", test_url, delay=delay, timeout=5)
                if resp.status_code == 200 and baseline_status in (401, 403):
                    _report_idor("API Version Downgrade", old_ver, resp)
                    return findings
            except ScanExceptions:
                pass

    # Technique 8: HTTP Parameter Pollution (?user_id=attacker&user_id=victim)
    parsed = urlparse(url)
    if param_name in parsed.query:
        for victim in ["1", "2", "0"]:
            try:
                hpp_query = f"{parsed.query}&{param_name}={victim}"
                test_url = urlunparse(parsed._replace(query=hpp_query))
                resp = smart_request("get", test_url, delay=delay, timeout=5)
                if resp.status_code == 200 and abs(len(resp.text) - baseline_len) > 100:
                    _report_idor("HPP", f"{param_name}={victim}", resp)
                    return findings
            except ScanExceptions:
                pass

    # Technique 9: Content-Type Switch (JSON → XML or vice versa)
    if method == "POST":
        for ct in ["application/json", "application/xml", "text/plain"]:
            try:
                data = dict(form_data or {})
                data[param_name] = "1"
                resp = smart_request(
                    "post", url, data=data, delay=delay, timeout=5,
                    headers={"Content-Type": ct},
                )
                if resp.status_code == 200 and abs(len(resp.text) - baseline_len) > 100:
                    _report_idor("Content-Type Switch", ct, resp)
                    return findings
            except ScanExceptions:
                pass

    return findings


def _test_mass_assignment(url, forms=None, delay=0):
    """Test for mass assignment with 11+ role payload variants across multiple endpoints."""
    findings = []
    forms = forms or []
    headers = {"Content-Type": "application/json"}

    # Detect POST endpoints from forms (register, login, profile update, etc.)
    target_urls = [url]
    for form in forms:
        action = form.get("action", "")
        form_method = form.get("method", "GET").upper()
        if form_method == "POST" and action:
            target_urls.append(action)

    for target_url in target_urls:
        try:
            baseline = smart_request(
                "post", target_url, json={"test": "normal"},
                headers=headers, delay=delay, timeout=5,
            )
        except ScanExceptions:
            continue

        # Try each payload set
        for payload in MASS_ASSIGNMENT_PAYLOADS:
            try:
                resp = smart_request(
                    "post", target_url, json=payload,
                    headers=headers, delay=delay, timeout=5,
                )
                if resp.status_code in (200, 201):
                    body = resp.text.lower()
                    for key, value in payload.items():
                        val_str = str(value).lower()
                        if val_str in body and val_str not in baseline.text.lower():
                            findings.append({
                                "type": "Business Logic",
                                "vuln": "Mass Assignment",
                                "param": key,
                                "payload": str(value),
                                "severity": "CRITICAL",
                                "description": f"Server accepted extra param: {key}={value}",
                                "url": target_url,
                            })
                            log_success(f"⚡ Mass assignment: {key}={value} at {target_url}")
                            return findings
            except ScanExceptions:
                pass

    return findings

def scan_business_logic(url, forms=None, delay=0):
    """
    Main Business Logic scanner entry point.
    Tests forms and URL params for logic flaws.
    """
    log_info("Starting Business Logic Scanner...")
    all_findings = []
    forms = forms or []

    # Detect targets from forms
    form_targets = _detect_form_params(forms)
    url_targets = _detect_url_params(url)
    all_targets = form_targets + url_targets

    if all_targets:
        log_info(f"Found {len(all_targets)} parameters to test")

    for target in all_targets:
        action = target["action"]
        method = target["method"]
        param_name = target["param_name"]
        param_type = target["param_type"]

        # Build form data for POST requests
        form_data = {}
        if "form" in target:
            for inp in target["form"].get("inputs", []):
                name = inp.get("name", "") if hasattr(inp, "get") else ""
                value = inp.get("value", "test") if hasattr(inp, "get") else "test"
                if name:
                    form_data[name] = value

        if param_type == "price":
            log_info(f"  → Testing price manipulation: {param_name}")
            all_findings.extend(
                _test_price_manipulation(action, param_name, method, form_data, delay)
            )

        elif param_type == "quantity":
            log_info(f"  → Testing quantity abuse: {param_name}")
            all_findings.extend(
                _test_quantity_abuse(action, param_name, method, form_data, delay)
            )

        elif param_type == "role":
            log_info(f"  → Testing role escalation: {param_name}")
            all_findings.extend(
                _test_role_escalation(action, param_name, method, form_data, delay)
            )

        elif param_type == "idor":
            log_info(f"  → Testing IDOR: {param_name}")
            all_findings.extend(
                _test_idor(action, param_name, method, form_data, delay)
            )

    # Always test mass assignment
    log_info("  → Testing mass assignment...")
    all_findings.extend(_test_mass_assignment(url, forms, delay))

    if not all_findings:
        log_info("No business logic flaws detected.")

    log_success(f"Business logic scan complete. {len(all_findings)} finding(s).")
    return all_findings
