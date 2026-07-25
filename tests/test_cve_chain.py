"""Tests for utils/cve_chain — finding-set chain detection."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from utils.cve_chain import (
    ChainRule,
    DEFAULT_CHAINS,
    chain_findings,
    chain_findings_to_dicts,
    chain_with_llm,
)


pytestmark = pytest.mark.unit


# ── chain_findings (rule-based) ──────────────────────────────────────────────


def test_ssrf_plus_metadata_triggers_known_chain():
    findings = [
        {"type": "SSRF", "url": "https://t/api/fetch", "severity": "high"},
        {"type": "Cloud_Metadata_Reachable", "url": "https://t/", "severity": "high"},
    ]
    chains = chain_findings(findings)
    names = {c.name for c in chains}
    assert any("AWS IMDS" in n or "SSRF" in n for n in names)


def test_no_chain_when_requires_not_satisfied():
    findings = [{"type": "Missing_HSTS_Header", "url": "https://t/", "severity": "low"}]
    assert chain_findings(findings) == []


def test_chain_includes_matched_findings():
    findings = [
        {"type": "Subdomain_Takeover", "url": "https://dev.t/", "severity": "critical"},
    ]
    chains = chain_findings(findings)
    assert chains
    assert chains[0].matched_findings == findings


def test_multiple_chains_can_fire_simultaneously():
    findings = [
        {"type": "Subdomain_Takeover", "url": "https://dev.t/", "severity": "critical"},
        {"type": "JWT_None_Algorithm", "url": "https://t/api", "severity": "critical"},
    ]
    chains = chain_findings(findings)
    names = [c.name for c in chains]
    assert any("Subdomain" in n for n in names)
    assert any("JWT" in n for n in names)


def test_chain_severity_propagates():
    findings = [{"type": "JWT_None_Algorithm", "url": "x", "severity": "critical"}]
    chains = chain_findings(findings)
    assert chains[0].severity == "critical"


def test_chain_findings_to_dicts_shape():
    findings = [
        {"type": "SSRF", "url": "https://t/api/fetch", "severity": "high"},
    ]
    out = chain_findings_to_dicts(findings)
    if out:
        first = out[0]
        assert first["type"] == "Attack_Path"
        assert first["module"] == "cve_chain"
        assert "matched_finding_types" in first


def test_xss_idor_combined_chain():
    findings = [
        {"type": "XSS_Param", "url": "https://t/a", "severity": "high"},
        {"type": "IDOR", "url": "https://t/b", "severity": "high"},
    ]
    chains = chain_findings(findings)
    names = [c.name for c in chains]
    assert any("XSS" in n and "IDOR" in n for n in names)


# ── Custom ChainRule ────────────────────────────────────────────────────────


def test_custom_chain_rule_is_honoured():
    custom = (
        ChainRule(
            name="custom_test_chain",
            requires=("Custom_Vuln_A", "Custom_Vuln_B"),
            severity="medium",
        ),
    )
    findings = [
        {"type": "Custom_Vuln_A", "url": "x"},
        {"type": "Custom_Vuln_B", "url": "y"},
    ]
    chains = chain_findings(findings, chains=custom)
    assert chains and chains[0].name == "custom_test_chain"


def test_partial_requirements_skip_chain():
    custom = (
        ChainRule(
            name="needs_three",
            requires=("A", "B", "C"),
        ),
    )
    findings = [{"type": "A"}, {"type": "B"}]  # missing C
    assert chain_findings(findings, chains=custom) == []


# ── LLM-augmented ─────────────────────────────────────────────────────────


def test_llm_chain_returns_empty_without_client():
    assert chain_with_llm([{"type": "SSRF", "url": "x"}], ai_client=None) == []


def test_llm_chain_returns_empty_when_client_unavailable():
    ai = MagicMock(available=False)
    assert chain_with_llm([{"type": "SSRF"}], ai_client=ai) == []


def test_llm_chain_parses_valid_json_response():
    ai = MagicMock(available=True)
    ai.generate.return_value = (
        '[{"name": "LLM chain", "requires": ["SSRF"], '
        '"severity": "high", "story": "ssrf to internal services"}]'
    )
    findings = [{"type": "SSRF", "url": "x"}]
    chains = chain_with_llm(findings, ai_client=ai)
    assert chains and chains[0].name == "LLM chain"


def test_llm_chain_drops_proposals_with_missing_findings():
    """Model may hallucinate types that aren't in the input — we drop those."""
    ai = MagicMock(available=True)
    ai.generate.return_value = (
        '[{"name": "fake", "requires": ["NonExistentVuln"], "severity": "high"}]'
    )
    findings = [{"type": "SSRF", "url": "x"}]
    chains = chain_with_llm(findings, ai_client=ai)
    assert chains == []


def test_llm_chain_handles_garbage_output():
    ai = MagicMock(available=True)
    ai.generate.return_value = "Sorry, I cannot help with that."
    assert chain_with_llm([{"type": "SSRF"}], ai_client=ai) == []


def test_llm_chain_absorbs_exceptions():
    ai = MagicMock(available=True)
    ai.generate.side_effect = RuntimeError("upstream down")
    assert chain_with_llm([{"type": "SSRF"}], ai_client=ai) == []


# ── DEFAULT_CHAINS sanity ──────────────────────────────────────────────────


def test_default_catalogue_is_non_trivial():
    assert len(DEFAULT_CHAINS) >= 6


@pytest.mark.parametrize("rule", DEFAULT_CHAINS)
def test_every_default_chain_has_requires_and_story(rule):
    assert rule.requires
    assert rule.story
