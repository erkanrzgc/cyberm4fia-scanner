"""
cyberm4fia-scanner - CSRF Module
Cross-Site Request Forgery detection
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
from urllib.parse import urlparse, urljoin
import httpx

from utils.colors import Colors, log_info, log_success, log_vuln, log_warning
from utils.request import smart_request, lock, Stats

# Common anti-CSRF token field names
CSRF_TOKEN_NAMES = [
    "csrf",
    "csrf_token",
    "csrftoken",
    "csrfmiddlewaretoken",
    "_csrf",
    "_token",
    "token",
    "authenticity_token",
    "xsrf",
    "xsrf_token",
    "_xsrf",
    "anti_csrf",
    "anticsrf",
    "nonce",
    "_wpnonce",
    "wp_nonce",
    "form_token",
    "form_key",
    "formtoken",
    "__requestverificationtoken",
    "verification_token",
    "securitytoken",
    "security_token",
]

# HTTP headers that provide CSRF protection
CSRF_HEADERS = [
    "x-csrf-token",
    "x-xsrf-token",
    "x-requested-with",
]

# Methods that change state (need CSRF protection)
STATE_CHANGING_METHODS = ["post", "put", "delete", "patch"]

# Field names that indicate sensitive/state-changing actions
# Even in GET forms, these should have CSRF protection
SENSITIVE_FIELDS = [
    "password",
    "passwd",
    "pass",
    "password_new",
    "password_conf",
    "new_password",
    "confirm_password",
    "old_password",
    "email",
    "delete",
    "remove",
    "transfer",
    "amount",
    "account",
    "admin",
    "role",
    "privilege",
]


def _has_csrf_token(form):
    """Check if a form contains an anti-CSRF token."""
    inputs = form.find_all("input")

    for inp in inputs:
        name = (inp.get("name") or "").lower()
        input_type = (inp.get("type") or "").lower()

        # Check if any input name matches known CSRF token names
        for token_name in CSRF_TOKEN_NAMES:
            if token_name in name:
                value = inp.get("value", "")
                # Token should have a non-empty, random-looking value
                if value and len(value) >= 8:
                    return True, name, value[:20] + "..."
                elif value:
                    return True, name, value

    # Check for hidden inputs with long random values (likely tokens)
    for inp in inputs:
        if inp.get("type", "").lower() == "hidden":
            value = inp.get("value", "")
            name = inp.get("name", "")
            # Long random-looking value = probably a token
            if len(value) >= 32 and re.match(r"^[a-zA-Z0-9+/=_-]+$", value):
                return True, name, value[:20] + "..."

    return False, None, None


def _check_samesite_cookie(headers):
    """Check if cookies have SameSite attribute."""
    set_cookies = headers.get("Set-Cookie", "")
    if not set_cookies:
        return None

    if "samesite=strict" in set_cookies.lower():
        return "Strict"
    elif "samesite=lax" in set_cookies.lower():
        return "Lax"
    elif "samesite=none" in set_cookies.lower():
        return "None (unsafe!)"
    return "Not set"


def _check_csrf_headers(url):
    """Check if the server expects CSRF-related headers."""
    found = []
    try:
        resp = smart_request("get", url, delay=0)
        for header in CSRF_HEADERS:
            if header in [h.lower() for h in resp.headers]:
                found.append(header)
    except httpx.RequestError:
        pass
    return found


def _get_form_info(form, url):
    """Extract useful info from a form for reporting."""
    action = form.get("action") or url
    method = form.get("method", "get").lower()
    inputs = form.find_all(["input", "textarea", "select"])
    field_names = [
        i.get("name")
        for i in inputs
        if i.get("name") and i.get("type", "").lower() != "hidden"
    ]
    return {
        "action": action,
        "method": method,
        "fields": field_names[:5],
    }


def scan_csrf(url, forms, delay):
    """Scan forms for CSRF vulnerabilities."""
    log_info(f"Testing CSRF protection on {len(forms)} form(s)...")
    vulns = []

    if not forms:
        log_info("No forms found to test for CSRF")
        return vulns

    # Check SameSite cookie
    try:
        resp = smart_request("get", url, delay=0)
        samesite = _check_samesite_cookie(resp.headers)
        if samesite:
            if samesite in ["Strict", "Lax"]:
                log_info(f"  Cookie SameSite: {samesite} (partial CSRF protection)")
            else:
                log_warning(f"  Cookie SameSite: {samesite}")
    except Exception:
        pass

    for i, form in enumerate(forms):
        form_info = _get_form_info(form, url)
        method = form_info["method"]

        # Check if form needs CSRF protection
        # POST/PUT/DELETE always need it
        # GET forms need it if they have sensitive fields (password, delete, etc)
        needs_check = method in STATE_CHANGING_METHODS

        if not needs_check and method == "get":
            # Check if GET form has sensitive field names
            all_field_names = [
                (inp.get("name") or "").lower() for inp in form.find_all("input")
            ]
            for field in all_field_names:
                for sensitive in SENSITIVE_FIELDS:
                    if sensitive in field:
                        needs_check = True
                        break
                if needs_check:
                    break

        if not needs_check:
            continue

        has_token, token_name, token_val = _has_csrf_token(form)
        fields_str = ", ".join(form_info["fields"][:3]) or "N/A"

        if has_token:
            log_success(
                f"  Form #{i + 1} [{method.upper()}] → Token found: {token_name}"
            )
        else:
            with lock:
                Stats.vulnerabilities_found += 1

            log_vuln("CSRF VULNERABILITY FOUND!")
            log_success(f"  Form #{i + 1} [{method.upper()}] → NO anti-CSRF token!")
            log_success(f"  Fields: {fields_str}")
            log_success(f"  Action: {form_info['action']}")

            # Generate exploit PoC
            action_url = urljoin(url, form_info["action"])
            poc = _generate_csrf_poc(form, action_url)

            print(f"\n{Colors.BOLD}    ╔══ CSRF EXPLOIT PoC ══╗{Colors.END}")
            print(f"    Save as .html and open in browser while")
            print(f"    victim is logged in:")
            print(f"{Colors.GREY}")
            for line in poc.split("\n"):
                print(f"    {line}")
            print(f"{Colors.END}")
            print(f"{Colors.BOLD}    ╚═════════════════════╝{Colors.END}\n")

            vulns.append(
                {
                    "type": "CSRF",
                    "param": fields_str,
                    "method": method,
                    "action": form_info["action"],
                    "fields": form_info["fields"],
                    "url": url,
                    "poc": poc,
                }
            )

    if not vulns:
        log_info("  All forms have CSRF protection ✅")

    return vulns


def _generate_csrf_poc(form, action_url):
    """Generate a CSRF Proof of Concept HTML page."""
    method = form.get("method", "get").lower()
    inputs = form.find_all(["input", "textarea", "select"])

    fields_html = ""
    for inp in inputs:
        name = inp.get("name", "")
        value = inp.get("value", "")
        input_type = inp.get("type", "text").lower()

        if not name:
            continue

        if input_type == "hidden":
            fields_html += f'  <input type="hidden" name="{name}" value="{value}" />\n'
        elif input_type == "submit":
            fields_html += f'  <input type="submit" value="{value or "Submit"}" />\n'
        elif input_type == "password":
            fields_html += (
                f'  <input type="hidden" name="{name}" value="hacked123" />\n'
            )
        else:
            fields_html += (
                f'  <input type="hidden" name="{name}" value="csrf_test" />\n'
            )

    poc = f"""<html>
<body>
<h1>CSRF PoC - cyberm4fia-scanner</h1>
<form action="{action_url}" method="{method}">
{fields_html.rstrip()}
  <input type="submit" value="Click Me!" />
</form>
<script>
  // Auto-submit (remove for manual test)
  // document.forms[0].submit();
</script>
</body>
</html>"""

    return poc
