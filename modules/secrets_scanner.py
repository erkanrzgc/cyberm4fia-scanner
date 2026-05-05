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
    "Stripe Publishable Live Key": r"pk_live_[0-9a-zA-Z]{24,}",
    "Stripe Test Secret Key": r"sk_test_[0-9a-zA-Z]{24,}",
    "Stripe Test Publishable Key": r"pk_test_[0-9a-zA-Z]{24,}",
    "Supabase Project URL": r"https?://[a-z0-9\-]{20}\.supabase\.co",
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
    # ── Modern AI API Keys (Claude-OSINT) ──
    "Anthropic API Key": r"sk-ant-[a-zA-Z0-9\-_]{32,128}",
    "OpenAI API Key": r"sk-[a-zA-Z0-9]{32,64}",
    "OpenAI Project Key": r"sk-proj-[a-zA-Z0-9]{32,128}",
    "HuggingFace API Token": r"hf_[a-zA-Z0-9]{32,64}",
    "Cloudflare API Token": r"[a-zA-Z0-9_-]{40,45}",
    # ── Package Registry Tokens ──
    "npm Access Token": r"npm_[a-zA-Z0-9]{36}",
    "PyPI API Token": r"pypi-[a-zA-Z0-9\-_]{32,128}",
    "Docker Hub Access Token": r"dckr_[a-zA-Z0-9\-_]{36,48}",
    # ── Platform / Service Tokens ──
    "Datadog API Key": r"datadog[a-f0-9]{32}",
    "Atlassian API Token": r"ATATT3[a-zA-Z0-9\-_]{32,128}",
    "Postman API Key": r"PMAK-[a-f0-9]{24}-[a-f0-9]{24}",
    "Linear API Key": r"lin_api_[a-zA-Z0-9]{40}",
    "Firebase Web API Key": r"AIzaSy[a-zA-Z0-9\-_]{33}",
    "Supabase Service Role Key": r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    # ── Database Connection Strings ──
    "MongoDB Connection String": r"mongodb(?:\+srv)?://[^@\s]+@[a-zA-Z0-9.\-]+(/[^\s]*)",
    "PostgreSQL Connection String": r"postgres(?:ql)?://[^@\s]+@[a-zA-Z0-9.\-]+(:\d+)?/[^\s]+",
    "Redis Connection String": r"redis://[^@\s]*@[a-zA-Z0-9.\-]+(:\d+)",
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


# Match-against-context heuristics to drop dummy/example/env-reference values
# (idea adapted from VICE's high-confidence pattern handling).
_PLACEHOLDER_REGEX = re.compile(
    r"your[_\-]|example|placeholder|xxx{2,}|yyy{2,}|zzz{2,}"
    r"|changeme|replace[_\-]|insert[_\-]|TODO|FIXME|<.*?>",
    re.IGNORECASE,
)
_ENV_REF_REGEX = re.compile(
    r"process\.env\.|import\.meta\.env\.|os\.environ|getenv\(|System\.getenv",
    re.IGNORECASE,
)


def is_placeholder_value(value: str, context_window: str = "") -> bool:
    """
    Return True when the matched value (and optional ±40-char context) looks
    like documentation, env-var reference, or template noise rather than a
    real leaked secret.
    """
    if not value:
        return True
    if _PLACEHOLDER_REGEX.search(value):
        return True
    if context_window and _ENV_REF_REGEX.search(context_window):
        return True
    return False


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
            if "AWS Access Key" in secret_name:
                idx = text.find(match_val)
                if idx != -1:
                    context = text[max(0, idx - 40) : idx].lower()
                    if "amz-credential" in context:
                        continue

            # Drop placeholders and env-variable references for everything
            # except literal markers (private-key headers self-evidently real).
            if "PRIVATE KEY" not in secret_name:
                idx = text.find(match_val)
                ctx = text[max(0, idx - 40) : idx + len(match_val) + 40] if idx != -1 else ""
                if is_placeholder_value(match_val, ctx):
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
