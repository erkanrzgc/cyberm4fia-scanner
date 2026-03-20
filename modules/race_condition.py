"""
cyberm4fia-scanner - Race Condition Scanner
Detects TOCTOU and concurrency bugs by sending parallel requests.
Tests: coupon reuse, double-spend, vote manipulation, auth race.
"""

import time
import asyncio
import httpx
from collections import Counter

from utils.colors import log_info, log_success, log_warning
from utils.request import ScanExceptions

# ─────────────────────────────────────────────────────
# Race Condition Patterns
# ─────────────────────────────────────────────────────
RACE_PATTERNS = {
    "coupon": {
        "description": "Coupon/promo code double redemption",
        "keywords": ["coupon", "promo", "discount", "redeem", "voucher", "code"],
        "method": "POST",
    },
    "transfer": {
        "description": "Double-spend / balance race",
        "keywords": [
            "transfer",
            "send",
            "withdraw",
            "payment",
            "checkout",
            "pay",
            "purchase",
        ],
        "method": "POST",
    },
    "vote": {
        "description": "Multiple vote / like / follow",
        "keywords": ["vote", "like", "follow", "upvote", "star", "favorite", "rate"],
        "method": "POST",
    },
    "signup": {
        "description": "Duplicate account creation",
        "keywords": ["register", "signup", "sign-up", "create-account"],
        "method": "POST",
    },
    "delete": {
        "description": "Race in deletion (delete already-deleted resource)",
        "keywords": ["delete", "remove", "destroy"],
        "method": "DELETE",
    },
}

async def _send_request(client, method, url, data=None, headers=None, cookies=None):
    """Send a single async request and return timing + response info."""
    start = time.time()
    try:
        kwargs = {
            "headers": headers or {},
            "timeout": httpx.Timeout(10),
        }
        if cookies:
            kwargs["cookies"] = cookies
        if data:
            kwargs["data"] = data

        resp = await client.request(method.upper(), url, **kwargs)
        body = resp.text
        return {
            "status": resp.status_code,
            "length": len(body),
            "time": time.time() - start,
            "body_preview": body[:300],
            "headers": dict(resp.headers),
        }

    except ScanExceptions as e:
        return {
            "status": 0,
            "length": 0,
            "time": time.time() - start,
            "error": str(e),
        }

async def _race_burst(
    method, url, concurrent=50, data=None, headers=None, cookies=None
):
    """Send N concurrent requests as simultaneously as possible."""
    limits = httpx.Limits(
        max_connections=concurrent, max_keepalive_connections=concurrent
    )
    async with httpx.AsyncClient(
        limits=limits, verify=False, follow_redirects=True
    ) as client:
        # Pre-connect with a warmup request
        await _send_request(client, "GET", url, headers=headers, cookies=cookies)

        # Fire all requests simultaneously
        tasks = [
            _send_request(
                client, method, url, data=data, headers=headers, cookies=cookies
            )
            for _ in range(concurrent)
        ]
        results = await asyncio.gather(*tasks)

    return results

def _analyze_race_results(results, concurrent):
    """Analyze race condition results for anomalies."""
    findings = []

    # Filter out errors
    valid = [r for r in results if r.get("status", 0) > 0]
    if len(valid) < concurrent * 0.5:
        return findings  # Too many failures

    # Count unique response lengths
    length_counts = Counter(r["length"] for r in valid)

    # Check for interesting patterns
    success_count = sum(1 for r in valid if r["status"] in (200, 201, 204))
    error_count = sum(1 for r in valid if r["status"] in (400, 403, 409, 429))

    # Pattern 1: All succeed (should have been limited)
    if success_count >= concurrent * 0.9:
        findings.append(
            {
                "pattern": "mass_success",
                "detail": f"All {success_count}/{concurrent} requests succeeded. Expected rate limiting or deduplication.",
                "severity": "HIGH",
            }
        )

    # Pattern 2: Mix of success and failure (race window exists)
    elif success_count > 1 and error_count > 0:
        success_rate = success_count / len(valid) * 100
        if success_count > 1:
            findings.append(
                {
                    "pattern": "race_window",
                    "detail": f"{success_count} succeeded, {error_count} failed ({success_rate:.0f}% success). Race window detected.",
                    "severity": "CRITICAL",
                }
            )

    # Pattern 3: Varying response lengths (state mutation)
    if len(length_counts) > 3:
        findings.append(
            {
                "pattern": "state_mutation",
                "detail": f"Response lengths vary significantly ({len(length_counts)} unique lengths). State may be mutating.",
                "severity": "MEDIUM",
            }
        )

    # Pattern 4: Response time variance (some locked, some not)
    times = [r["time"] for r in valid]
    if times:
        avg_time = sum(times) / len(times)
        max_time = max(times)
        if max_time > avg_time * 3 and max_time > 1.0:
            findings.append(
                {
                    "pattern": "lock_contention",
                    "detail": f"High time variance (avg: {avg_time:.2f}s, max: {max_time:.2f}s). Database lock contention.",
                    "severity": "MEDIUM",
                }
            )

    return findings

def _detect_race_targets(url, forms, delay=0):
    """Auto-detect endpoints likely vulnerable to race conditions."""
    targets = []

    # Check URL parameters
    url_lower = url.lower()
    for pattern_name, pattern in RACE_PATTERNS.items():
        for keyword in pattern["keywords"]:
            if keyword in url_lower:
                targets.append(
                    {
                        "url": url,
                        "method": pattern["method"],
                        "pattern": pattern_name,
                        "description": pattern["description"],
                    }
                )
                break

    # Check forms
    for form in forms:
        action = str(form.get("action", "")).lower()
        method = form.get("method", "GET").upper()

        for pattern_name, pattern in RACE_PATTERNS.items():
            for keyword in pattern["keywords"]:
                if keyword in action:
                    # Build form data
                    form_data = {}
                    inputs = form.get("inputs", [])
                    if hasattr(inputs, "__iter__"):
                        for inp in inputs:
                            if hasattr(inp, "get"):
                                name = inp.get("name", "")
                            elif hasattr(inp, "attrs"):
                                name = inp.get("name", "")
                            else:
                                continue
                            if name:
                                form_data[name] = inp.get("value", "test")

                    targets.append(
                        {
                            "url": form.get("action", url),
                            "method": method,
                            "data": form_data,
                            "pattern": pattern_name,
                            "description": pattern["description"],
                        }
                    )
                    break

    return targets

def scan_race_condition(url, forms=None, delay=0, concurrent=50, cookie=None):
    """
    Main Race Condition scanner entry point.
    Tests endpoints for TOCTOU and concurrency bugs.
    """
    log_info(f"Starting Race Condition Scanner (concurrent={concurrent})...")

    all_findings = []
    forms = forms or []

    # Parse cookies
    cookies = {}
    if cookie:
        for part in cookie.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k.strip()] = v.strip()

    # Auto-detect race targets
    targets = _detect_race_targets(url, forms, delay)

    if not targets:
        # If no obvious targets, test the URL itself
        log_info("No obvious race targets found. Testing URL directly...")
        targets = [
            {
                "url": url,
                "method": "GET",
                "pattern": "general",
                "description": "General endpoint race test",
            }
        ]

    for target in targets:
        target_url = target["url"]
        method = target["method"]
        data = target.get("data")
        pattern = target["pattern"]

        log_info(f"Testing race on: {target_url} ({pattern}: {target['description']})")

        try:
            # Run the race burst
            results = asyncio.run(
                _race_burst(
                    method,
                    target_url,
                    concurrent=concurrent,
                    data=data,
                    cookies=cookies if cookies else None,
                )
            )

            # Analyze results
            analysis = _analyze_race_results(results, concurrent)

            for finding in analysis:
                vuln = {
                    "type": "Race Condition",
                    "url": target_url,
                    "method": method,
                    "pattern": pattern,
                    "description": f"{target['description']}: {finding['detail']}",
                    "severity": finding["severity"],
                    "concurrent_requests": concurrent,
                    "analysis": finding["pattern"],
                }
                all_findings.append(vuln)

                if finding["severity"] == "CRITICAL":
                    log_success(f"🔥 [CRITICAL] Race Condition! {finding['detail']}")
                elif finding["severity"] == "HIGH":
                    log_warning(f"⚠️  [HIGH] Potential Race: {finding['detail']}")
                else:
                    log_info(f"[{finding['severity']}] {finding['detail']}")

        except ScanExceptions as e:
            log_warning(f"Race test failed for {target_url}: {e}")

    if not all_findings:
        log_info("No race conditions detected.")

    log_success(f"Race condition scan complete. {len(all_findings)} finding(s).")
    return all_findings
