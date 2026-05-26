"""Normalization helpers — dict → Observation/Finding conversion + dedup.

Public:
  - compute_confidence_score(vuln_dict)
  - observation_from_vuln(vuln_dict) -> Observation
  - normalize_vuln(vuln_dict) -> Finding
  - deduplicate_findings(vuln_list) -> list

Private helpers prefixed with ``_`` are imported by ``artifacts``.
"""

from __future__ import annotations

import hashlib
from urllib.parse import urlparse

from .registry import VULN_REGISTRY, _DEFAULT_VULN
from .types import Finding, Observation


def _truncate_text(value, limit: int = 280):
    text = str(value or "").strip()
    if not text:
        return None
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _extract_request_details(vuln_dict):
    request = vuln_dict.get("request")
    if isinstance(request, dict):
        return request

    request_fields = {
        "method": vuln_dict.get("request_method"),
        "headers": vuln_dict.get("request_headers"),
        "body": vuln_dict.get("request_body"),
    }
    request_fields = {
        key: value
        for key, value in request_fields.items()
        if value not in (None, "", {}, [])
    }
    return request_fields or None


def _extract_response_snippet(vuln_dict):
    return _truncate_text(
        vuln_dict.get("response_snippet")
        or vuln_dict.get("response")
        or vuln_dict.get("body_preview")
    )


def _coerce_repro_steps(vuln_dict):
    repro_steps = vuln_dict.get("repro_steps")
    if isinstance(repro_steps, list):
        return [str(step) for step in repro_steps if str(step).strip()] or None
    if isinstance(repro_steps, str) and repro_steps.strip():
        return [repro_steps.strip()]

    steps = []
    url = vuln_dict.get("url")
    if url:
        steps.append(f"Request {url}")
    param = vuln_dict.get("param")
    payload = vuln_dict.get("payload")
    if param and payload:
        steps.append(f"Set parameter '{param}' to '{payload}'")
    elif param:
        steps.append(f"Inspect parameter '{param}'")
    return steps or None


def compute_confidence_score(vuln_dict):
    """
    Compute a 0-100 confidence score for a vulnerability finding.

    Scoring criteria:
    - Payload reflection in response:  +30
    - Expected status code:            +20
    - Evidence string match:           +25
    - Exploit data / PoC proof:        +25
    - Timing-only (blind):             -15
    - WAF bypass technique used:       +10
    - Multiple confirmation vectors:   +10
    """
    score = 0

    payload = str(vuln_dict.get("payload", ""))
    evidence = str(vuln_dict.get("evidence", "")).lower()
    response = str(vuln_dict.get("response_snippet", "") or vuln_dict.get("response", ""))
    vuln_type = str(vuln_dict.get("type", "")).lower()
    description = str(vuln_dict.get("description", "")).lower()

    # 1. Payload reflected in response (+30)
    if payload and response and payload in response:
        score += 30
    elif payload and evidence and payload.lower() in evidence:
        score += 25

    # 2. Status code indicates success (+20)
    status = vuln_dict.get("status_code") or vuln_dict.get("response_code")
    if status:
        status = int(status) if str(status).isdigit() else 0
        if status in (200, 500, 302):
            score += 20
        elif status in (403, 406, 503):
            score -= 10  # WAF block indicators

    # 3. Evidence string present (+25)
    if evidence and len(evidence) > 10:
        score += 25
    elif evidence:
        score += 10

    # 4. Exploit data / PoC present (+25)
    if vuln_dict.get("exploit_data"):
        score += 25

    # 5. Confirmed / verified keywords (+15)
    if "confirmed" in evidence or "confirmed" in description:
        score += 15
    elif "verified" in evidence or "verified" in description:
        score += 10

    # 6. Timing-only detection penalty (-15)
    if "blind" in vuln_type or "time" in vuln_type:
        if not vuln_dict.get("exploit_data") and "confirmed" not in evidence:
            score -= 15

    # 7. WAF bypass bonus (+10)
    if vuln_dict.get("waf_bypassed") or "waf" in description:
        score += 10

    # 8. Multiple evidence items (+10)
    if vuln_dict.get("response_snippet") and vuln_dict.get("evidence"):
        score += 10

    # Clamp to 0-100
    return max(0, min(100, score))


def _score_to_confidence(score):
    """Map a 0-100 confidence score to a label."""
    if score >= 80:
        return "confirmed"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    return "low"


def _infer_confidence(vuln_dict, severity):
    """Infer confidence level using smart scoring."""
    explicit = vuln_dict.get("confidence")
    if explicit and str(explicit).lower() in ("confirmed", "high", "medium", "low"):
        return str(explicit).lower()

    score = compute_confidence_score(vuln_dict)

    # Severity-based floor: critical/high vulns get at least medium
    if score < 40 and severity in {"critical", "high"}:
        score = max(score, 40)

    return _score_to_confidence(score)


def _stable_id(prefix, *parts):
    raw = "::".join(str(part or "") for part in parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def _build_asset_id(url):
    parsed = urlparse(url or "")
    host = parsed.netloc or parsed.path or "unknown"
    return _stable_id("asset", host)


def _infer_surface(vuln_dict):
    vuln_type = str(vuln_dict.get("type", "")).lower()
    url = str(vuln_dict.get("url", "")).lower()

    if vuln_type.startswith("api_") or "/api/" in url:
        return "api"
    if any(
        token in vuln_type for token in ("cloud", "takeover", "bucket", "subdomain")
    ):
        return "infrastructure"
    if any(token in vuln_type for token in ("header", "cors", "csrf")):
        return "http"
    return "web"


def _coerce_evidence_items(vuln_dict):
    items = []
    evidence = str(vuln_dict.get("evidence", "")).strip()
    if evidence:
        items.append({"kind": "evidence", "value": evidence})

    response_snippet = _extract_response_snippet(vuln_dict)
    if response_snippet:
        items.append({"kind": "response_snippet", "value": response_snippet})

    request = _extract_request_details(vuln_dict)
    if request:
        items.append({"kind": "request", "value": request})

    exploit_data = vuln_dict.get("exploit_data")
    if exploit_data:
        items.append({"kind": "exploit_data", "value": exploit_data})

    return items or None


def _infer_verification_state(vuln_dict, confidence):
    if vuln_dict.get("verification_state"):
        return str(vuln_dict["verification_state"]).lower()
    if vuln_dict.get("exploit_data"):
        return "exploitable"
    if confidence in {"confirmed", "high"}:
        return "verified"
    return "suspected"


def _infer_exploitability(vuln_dict, severity, verification_state):
    explicit = vuln_dict.get("exploitability")
    if explicit:
        return str(explicit).lower()
    if vuln_dict.get("exploit_data") or verification_state == "exploitable":
        return "high"
    if severity in {"critical", "high"} and verification_state == "verified":
        return "medium"
    if severity in {"critical", "high"}:
        return "medium"
    return "low"


def _build_replay_recipe(vuln_dict, request_details, repro_steps):
    if vuln_dict.get("replay_recipe"):
        return vuln_dict["replay_recipe"]

    url = vuln_dict.get("url", "")
    if not url:
        return None

    recipe = {
        "method": (request_details or {}).get("method")
        or vuln_dict.get("method")
        or vuln_dict.get("request_method")
        or "GET",
        "url": url,
        "steps": repro_steps or [],
    }
    if vuln_dict.get("param"):
        recipe["param"] = vuln_dict["param"]
    if vuln_dict.get("payload"):
        recipe["payload"] = vuln_dict["payload"]
    return recipe


def observation_from_vuln(vuln_dict: dict) -> Observation:
    """Adapt a legacy module result into a raw observation."""
    vuln_type = vuln_dict.get("type", "Unknown")
    registry = VULN_REGISTRY.get(vuln_type, _DEFAULT_VULN)
    severity = str(vuln_dict.get("severity", registry["severity"])).lower()
    confidence = _infer_confidence(vuln_dict, severity)
    url = vuln_dict.get("url", "")
    request_details = _extract_request_details(vuln_dict)
    repro_steps = _coerce_repro_steps(vuln_dict)
    response_snippet = _extract_response_snippet(vuln_dict)

    return Observation(
        id=_stable_id(
            "obs",
            vuln_type,
            url,
            vuln_dict.get("param"),
            vuln_dict.get("payload"),
            vuln_dict.get("evidence"),
        ),
        observation_type=vuln_type,
        url=url,
        module=vuln_type,
        asset_id=_build_asset_id(url),
        surface=_infer_surface(vuln_dict),
        description=vuln_dict.get("description", registry["title"]),
        severity=severity,
        confidence=confidence,
        evidence=str(vuln_dict.get("evidence", "")),
        param=vuln_dict.get("param", ""),
        payload=vuln_dict.get("payload", ""),
        request=request_details,
        response_snippet=response_snippet,
        repro_steps=repro_steps,
        tags=[vuln_type.lower(), _infer_surface(vuln_dict)],
        raw=dict(vuln_dict),
    )


def normalize_vuln(vuln_dict: dict) -> Finding:
    """
    Convert a legacy vulnerability dict into a Finding object.
    Enriches it with CVSS, CWE, severity, and remediation from the registry.
    """
    observation = observation_from_vuln(vuln_dict)
    raw = observation.raw or vuln_dict
    vuln_type = observation.observation_type
    registry = VULN_REGISTRY.get(vuln_type, _DEFAULT_VULN)
    severity = observation.severity
    evidence_items = _coerce_evidence_items(raw)
    verification_state = _infer_verification_state(raw, observation.confidence)
    replay_recipe = _build_replay_recipe(
        raw, observation.request, observation.repro_steps
    )

    return Finding(
        title=registry["title"],
        severity=severity,
        cvss=registry["cvss"],
        cwe=registry["cwe"],
        url=observation.url,
        module=vuln_type,
        finding_type=vuln_type,
        description=raw.get("description", registry["title"]),
        param=raw.get("param", ""),
        payload=raw.get("payload", ""),
        evidence=raw.get("evidence", ""),
        cve=raw.get("cve", ""),
        component=raw.get("component", ""),
        version=raw.get("version", ""),
        confidence=observation.confidence,
        remediation=registry["remediation"],
        id=_stable_id(
            "finding",
            vuln_type,
            observation.url,
            raw.get("param"),
            raw.get("payload"),
            raw.get("evidence"),
        ),
        asset_id=observation.asset_id,
        surface=observation.surface,
        verification_state=verification_state,
        exploitability=_infer_exploitability(raw, severity, verification_state),
        # Registry can opt unknown types into a separate triage queue
        # (e.g. _DEFAULT_VULN ships ``validation_stage="needs_triage"``).
        validation_stage=str(
            raw.get("validation_stage")
            or registry.get("validation_stage")
            or "suspected"
        ),
        context=str(raw.get("context", "")) if raw.get("context") else None,
        source=raw.get("source"),
        exploit_data=raw.get("exploit_data"),
        repro_steps=observation.repro_steps,
        request=observation.request,
        response_snippet=observation.response_snippet,
        evidence_items=evidence_items,
        preconditions=raw.get("preconditions") or None,
        replay_recipe=replay_recipe,
        observation_refs=[observation.id],
        attack_path_refs=list(raw.get("attack_path_refs", []) or []) or None,
        extra={
            k: v
            for k, v in raw.items()
            if k
            not in (
                "type",
                "url",
                "description",
                "param",
                "payload",
                "evidence",
                "cve",
                "component",
                "version",
                "severity",
                "confidence",
                "context",
                "source",
                "exploit_data",
                "repro_steps",
                "request",
                "request_method",
                "request_headers",
                "request_body",
                "response",
                "response_snippet",
                "body_preview",
                "preconditions",
                "replay_recipe",
                "verification_state",
                "exploitability",
                "attack_path_refs",
            )
        }
        or None,
    )


def deduplicate_findings(vuln_list: list) -> list:
    """Remove duplicate vulnerabilities (same type, payload, param) or deduplicate host-level findings."""
    seen = set()
    unique_vulns = []

    for vuln in vuln_list:
        if isinstance(vuln, Finding):
            vuln = vuln.to_dict()
        vuln_type = vuln.get("type", "")
        url = vuln.get("url", "")
        param = vuln.get("param", "")
        payload = vuln.get("payload", "")
        evidence = vuln.get("evidence", "")

        host = urlparse(url).netloc

        # Site-wide issues only need to be reported once per host,
        # so we strip the path/query parameters.
        if vuln_type in [
            "Missing_Security_Header",
            "Debug_Info",
            "Tech_Fingerprint",
            "CVE_Intel",
        ]:
            sig = f"{vuln_type}::{host}::{evidence}"
        else:
            # For injection/XSS, we need exact URL, param, and payload to match
            sig = f"{vuln_type}::{url}::{param}::{payload}"

        if sig not in seen:
            seen.add(sig)
            unique_vulns.append(vuln)

    return unique_vulns


def _normalize_with_observations(
    vuln_list: list,
) -> tuple[list[Observation], list[Finding]]:
    """Normalize legacy results while preserving their raw observation layer."""
    observations = []
    normalized = []
    for vuln in vuln_list:
        if isinstance(vuln, Finding):
            normalized.append(vuln)
            observation_refs = vuln.observation_refs or [
                _stable_id(
                    "obs", vuln.finding_type or vuln.module, vuln.url, vuln.param
                )
            ]
            observations.append(
                Observation(
                    id=observation_refs[0],
                    observation_type=vuln.finding_type or vuln.module,
                    url=vuln.url,
                    module=vuln.module,
                    asset_id=vuln.asset_id or _build_asset_id(vuln.url),
                    surface=vuln.surface or "web",
                    description=vuln.description,
                    severity=vuln.severity,
                    confidence=vuln.confidence,
                    evidence=vuln.evidence,
                    param=vuln.param,
                    payload=vuln.payload,
                    request=vuln.request,
                    response_snippet=vuln.response_snippet,
                    repro_steps=vuln.repro_steps,
                    raw=vuln.to_dict(),
                )
            )
        elif isinstance(vuln, Observation):
            observations.append(vuln)
            normalized.append(normalize_vuln(vuln.raw or vuln.to_dict()))
        else:
            observation = observation_from_vuln(vuln)
            observations.append(observation)
            normalized.append(normalize_vuln(vuln))

    return observations, normalized
