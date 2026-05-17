"""Active WAF fingerprinting — wafw00f-style probe-based detection.

``utils/waf.WAFDetector`` already covers passive detection: take the
headers/cookies/body of a normal response and pattern-match. This module
adds the **active** half: send WAF-tickling probes (XSS / SQLi / LFI
imitations) and read the *block response* itself for signatures that
never appear on benign traffic (e.g. F5 BIG-IP's "The requested URL was
rejected" page, Cloudflare's "Attention Required!" Ray ID, AWS WAF's
``Request blocked.``).

Why both layers?
----------------
A polished WAF deployment hides its passive fingerprints — strips
``Server``, drops vendor cookies. The block page is much harder to
disguise because the customer paid for those copy-pasted vendor strings.
Active probes also confirm the WAF is *actually inline* on the request
path, not merely a TLS terminator.

Public surface:
    active_fingerprint(target_url, *, http_get) -> WafFingerprintReport

The HTTP callable is injectable so tests don't need a real network.
``ScanFindings``-shaped dicts are emitted for the standard pipeline.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from utils.colors import log_info, log_success


# ── Probe catalogue ────────────────────────────────────────────────────────


# Each probe is a (label, query_string) — appended as ``?wafprobe=<payload>``
# so we don't accidentally land on a real endpoint. The point is to trip
# the WAF, not exploit the app.
_DEFAULT_PROBES: tuple[tuple[str, str], ...] = (
    ("xss",  "<script>alert(1)</script>"),
    ("sqli", "' OR 1=1--"),
    ("lfi",  "../../../../etc/passwd"),
    ("cmdi", ";cat /etc/passwd"),
    ("rce",  "${jndi:ldap://x/a}"),
)


# Signatures keyed by WAF name. ``status`` is a set of status codes the
# WAF usually returns for blocked requests; ``body`` is a list of
# substring fingerprints (case-folded); ``headers`` are header-name
# fingerprints. Any match → that WAF is detected.
WAF_BLOCK_SIGNATURES: dict[str, dict[str, Any]] = {
    "Cloudflare": {
        "status": {403, 503},
        "headers": ["cf-ray", "server: cloudflare"],
        "body": [
            "attention required! | cloudflare",
            "cf-error-details",
            "cloudflare ray id",
        ],
    },
    "AWS WAF": {
        "status": {403, 405},
        "headers": ["x-amzn-errortype", "x-amzn-requestid"],
        "body": ["request blocked", "the request could not be satisfied"],
    },
    "Akamai Kona": {
        "status": {403},
        "headers": ["akamaighost"],
        "body": ["access denied", "akamai reference"],
    },
    "Imperva / Incapsula": {
        "status": {403},
        "headers": ["x-iinfo", "x-cdn: incapsula"],
        "body": [
            "incident id",
            "powered by incapsula",
            "request unsuccessful",
        ],
    },
    "F5 BIG-IP ASM": {
        "status": {403, 419},
        "headers": ["server: bigip", "x-wa-info"],
        "body": ["the requested url was rejected", "support id"],
    },
    "Sucuri CloudProxy": {
        "status": {403, 406},
        "headers": ["x-sucuri-id", "server: sucuri"],
        "body": ["access denied - sucuri website firewall"],
    },
    "Fortinet FortiWeb": {
        "status": {403, 406},
        "headers": ["server: fortiweb", "fgd_token"],
        "body": ["the request has been denied", ".fyi_err_page"],
    },
    "Barracuda": {
        "status": {403},
        "headers": ["server: barracuda", "barra_counter_session"],
        "body": ["barracuda web application firewall"],
    },
    "Citrix NetScaler AppFirewall": {
        "status": {403, 404},
        "headers": ["via: ns-cache", "cneonction"],
        "body": ["violation of security policy"],
    },
    "ModSecurity / OWASP CRS": {
        "status": {403, 406, 501},
        "headers": ["server: mod_security", "server: modsecurity"],
        "body": [
            "mod_security",
            "not acceptable",
            "you don't have permission to access",
        ],
    },
    "Wallarm": {
        "status": {403},
        "headers": ["nginx-wallarm"],
        "body": ["nginx-wallarm"],
    },
    "NAXSI": {
        "status": {403, 412},
        "headers": ["x-data-origin: naxsi"],
        "body": ["naxsi blocked", "x-naxsi-sig"],
    },
    "PerimeterX / HUMAN": {
        "status": {403, 429},
        "headers": ["x-px-block", "set-cookie: _px"],
        "body": ["please verify you are a human", "perimeterx, inc"],
    },
    "DataDome": {
        "status": {403},
        "headers": ["x-datadome", "set-cookie: datadome"],
        "body": ["datadome"],
    },
    "Reblaze": {
        "status": {403},
        "headers": ["set-cookie: rbzid"],
        "body": ["reblaze secure web gateway"],
    },
    "StackPath": {
        "status": {403, 503},
        "headers": ["server: stackpath", "x-sp-"],
        "body": ["stackpath"],
    },
    "Edgecast": {
        "status": {403},
        "headers": ["server: ecs", "server: edgecast"],
        "body": ["edgecast"],
    },
    "Azure Front Door": {
        "status": {403},
        "headers": ["x-azure-ref"],
        "body": ["microsoft-azure-application-gateway"],
    },
    "Google Cloud Armor": {
        "status": {403},
        "headers": ["x-goog-"],
        "body": [
            "our systems have detected unusual traffic",
            "google cloud armor",
        ],
    },
    "Qrator": {
        "status": {403},
        "headers": ["server: qrator", "x-qrator-id"],
        "body": ["qrator filtering"],
    },
    "Sangfor": {
        "status": {403},
        "headers": ["server: sangfor"],
        "body": ["sangfor"],
    },
    "Alibaba Yundun": {
        "status": {403, 405},
        "headers": ["server: yundun", "x-yundun"],
        "body": ["aliyun", "yundun"],
    },
    "Tencent Cloud WAF": {
        "status": {403},
        "headers": ["server: tencent-waf", "x-nws-log-uuid"],
        "body": ["tencent cloud waf"],
    },
}


@dataclass
class WafProbeOutcome:
    label: str
    payload: str
    status: int
    body_hash: str
    matched_waf: Optional[str] = None
    match_reasons: list[str] = field(default_factory=list)


@dataclass
class WafFingerprintReport:
    target: str
    baseline_status: int = 0
    baseline_hash: str = ""
    detected_wafs: list[str] = field(default_factory=list)
    probe_outcomes: list[WafProbeOutcome] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_findings(self) -> list[dict]:
        """Vuln-dict shape for the standard finding pipeline."""
        if not self.detected_wafs:
            return []
        return [
            {
                "type": "WAF_Detected",
                "url": self.target,
                "severity": "info",
                "evidence": (
                    f"Active probes triggered block response matching: "
                    f"{', '.join(self.detected_wafs)}"
                ),
                "module": "waf_fingerprint",
                "waf": self.detected_wafs,
            }
        ]


# ── Helpers ────────────────────────────────────────────────────────────────


def _hash_body(body: str) -> str:
    return hashlib.sha1((body or "").encode("utf-8", "ignore")).hexdigest()


def _match_signature(
    *,
    status: int,
    body: str,
    headers: dict[str, str],
    signature: dict[str, Any],
) -> list[str]:
    """Return the list of reasons this signature matched (empty if no match)."""
    reasons: list[str] = []
    body_lc = (body or "").lower()
    header_blob = " ".join(
        f"{k.lower()}: {str(v).lower()}" for k, v in (headers or {}).items()
    )

    expected_status = signature.get("status") or set()
    if expected_status and status in expected_status:
        reasons.append(f"status={status}")

    for fingerprint in signature.get("headers", []):
        if fingerprint.lower() in header_blob:
            reasons.append(f"header~={fingerprint}")
    for fingerprint in signature.get("body", []):
        if fingerprint.lower() in body_lc:
            reasons.append(f"body~={fingerprint}")
    # A status-only hit is too weak to claim a WAF — require at least one
    # header or body fingerprint as corroboration.
    has_strong_match = any(
        r.startswith("header~=") or r.startswith("body~=") for r in reasons
    )
    return reasons if has_strong_match else []


def _identify_waf(
    *,
    status: int,
    body: str,
    headers: dict[str, str],
) -> tuple[Optional[str], list[str]]:
    """Return (waf_name, reasons) for the first signature that matches."""
    for waf_name, signature in WAF_BLOCK_SIGNATURES.items():
        reasons = _match_signature(
            status=status, body=body, headers=headers, signature=signature
        )
        if reasons:
            return waf_name, reasons
    return None, []


# ── Public API ─────────────────────────────────────────────────────────────


def active_fingerprint(
    target_url: str,
    *,
    http_get: Callable,
    probes: tuple[tuple[str, str], ...] = _DEFAULT_PROBES,
    timeout: float = 10.0,
) -> WafFingerprintReport:
    """Run probe-based WAF detection against ``target_url``.

    ``http_get(url, timeout)`` must return an object with ``status_code``,
    ``text``, and ``headers`` — the duck-typed httpx response shape.
    Network failures are absorbed into ``report.errors`` rather than
    raising — fingerprinting is best-effort, never blocks the scan.
    """
    report = WafFingerprintReport(target=target_url)

    # Baseline request — what does this server return normally?
    try:
        baseline = http_get(target_url, timeout=timeout)
        report.baseline_status = getattr(baseline, "status_code", 0)
        report.baseline_hash = _hash_body(getattr(baseline, "text", "") or "")
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"baseline: {type(exc).__name__}: {exc}")

    detected: set[str] = set()
    sep = "&" if "?" in target_url else "?"

    for label, payload in probes:
        probe_url = f"{target_url}{sep}wafprobe={payload}"
        try:
            response = http_get(probe_url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"probe {label}: {type(exc).__name__}: {exc}")
            continue

        status = getattr(response, "status_code", 0)
        body = getattr(response, "text", "") or ""
        headers = dict(getattr(response, "headers", {}) or {})
        body_hash = _hash_body(body)

        waf, reasons = _identify_waf(status=status, body=body, headers=headers)
        outcome = WafProbeOutcome(
            label=label,
            payload=payload,
            status=status,
            body_hash=body_hash,
            matched_waf=waf,
            match_reasons=reasons,
        )
        report.probe_outcomes.append(outcome)
        if waf:
            detected.add(waf)

    report.detected_wafs = sorted(detected)
    if detected:
        log_success(
            f"WAF fingerprint: detected {', '.join(report.detected_wafs)}"
        )
    else:
        log_info("WAF fingerprint: no block-signature matches")
    return report
