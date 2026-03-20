"""
cyberm4fia-scanner - Secrets & API Key Scanner
Scans HTML and Javascript files for hardcoded sensitive information like AWS keys, Stripe tokens, etc.
"""
from utils.request import ScanExceptions

import re
import urllib.parse
from bs4 import BeautifulSoup
import math
from utils.colors import log_success, log_vuln
from utils.request import (
    get_request_delay,
    increment_vulnerability_count,
    lock,
    smart_request,
)

VISITED_JS = set()

SECRET_PATTERNS = {
    "AWS Access Key ID": r"(?i)AKIA[0-9A-Z]{16}",
    "Stripe Standard API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": r"rk_live_[0-9a-zA-Z]{24}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth Access Token": r"ya29\.[0-9A-Za-z\-_]+",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth Action": r"gho_[a-zA-Z0-9]{36}",
    "Slack Token": r"xox[baprs]-[0-9]{12,}-[0-9]{12,}-[a-zA-Z0-9]{24}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "PayPal Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Amazon MWS Auth Token": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Heroku API Key": r"(?i)heroku[^0-9a-zA-Z]{0,10}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "Generic Client Secret": r"(?i)(?:client_secret|api_secret|app_secret|secret_key)[\"'\s:=]+([\w\-\/]{20,})",
}


def shannon_entropy(data):
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += -p_x * math.log(p_x, 2)
    return entropy


def scan_text_for_secrets(text, source_url):
    """Scan raw text against all secret patterns."""
    vulns = []
    if not text:
        return vulns

    for secret_name, pattern in SECRET_PATTERNS.items():
        matches = set(re.findall(pattern, text))
        for match in matches:
            # For the generic pattern, we expect a tuple due to the capture group
            if isinstance(match, tuple):
                match_val = match[0] if match else ""
            else:
                match_val = match

            if not match_val:
                continue

            # Avoid AWS Pre-signed URL false positives
            if secret_name == "AWS Access Key ID":
                idx = text.find(match_val)
                if idx != -1:
                    context = text[max(0, idx - 40) : idx].lower()
                    if "amz-credential" in context:
                        continue

            # Entropy Check for Generic Secrets
            # Real tokens usually have an entropy between ~3.5 and ~5.0
            # Common English text or simple repetitive arrays are lower.
            # High-entropy random bases (like UUIDs) are usually around ~3.8-4.5
            if secret_name == "Generic Client Secret":
                ent = shannon_entropy(match_val)
                if ent < 3.2 or ent > 5.5:
                    continue  # Ignore low-entropy or extreme high-entropy junk
                # Avoid matching UUIDs unless specifically required
                if re.match(
                    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    match_val,
                    re.I,
                ):
                    continue

            # Mask the secret partially for output
            if len(match_val) > 10 and "KEY-----" not in match_val:
                masked = match_val[:5] + "*" * (len(match_val) - 9) + match_val[-4:]
            else:
                masked = match_val

            vulns.append(
                {
                    "type": "Secret_Exposure",
                    "secret_type": secret_name,
                    "value": masked,
                    "url": source_url,
                }
            )
    return vulns


def scan_secrets(url, response_text):
    """Scan the HTML and referenced JS files for secrets."""
    vulns = []

    # 1. Scan the main HTML body
    found = scan_text_for_secrets(response_text, url)
    if found:
        vulns.extend(found)

    # 2. Find and scan JS files
    try:
        soup = BeautifulSoup(response_text, "lxml")
        scripts = soup.find_all("script", src=True)

        for script in scripts:
            src = script["src"]
            full_url = urllib.parse.urljoin(url, src)

            with lock:
                if full_url in VISITED_JS:
                    continue
                VISITED_JS.add(full_url)

            try:
                resp = smart_request("get", full_url, delay=get_request_delay())
                js_found = scan_text_for_secrets(resp.text, full_url)
                if js_found:
                    vulns.extend(js_found)
            except ScanExceptions:
                pass
    except ScanExceptions:
        pass

    # Reporting
    for v in vulns:
        increment_vulnerability_count()
        log_vuln("SENSITIVE DATA EXPOSURE FOUND!")
        log_success(f"Type: {v['secret_type']}")
        log_success(f"Value: {v['value']}")
        log_success(f"Source: {v['url']}")

    return vulns
