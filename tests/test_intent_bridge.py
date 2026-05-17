"""Tests for utils/intent_bridge — vuln-dict → intent + pipeline merge."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from utils.intent_bridge import (
    _high_value_vuln_types,
    findings_to_intents,
    merge_pipeline_findings,
    run_intent_pipeline,
)


pytestmark = pytest.mark.unit


# ─── findings_to_intents ─────────────────────────────────────────────────────


def test_findings_to_intents_filters_to_high_value_types():
    vulns = [
        {"type": "XSS_Param", "url": "http://t/x", "param": "q"},
        {"type": "Missing_HSTS_Header", "url": "http://t/", "param": ""},
        {"type": "SQLi_Param", "url": "http://t/s", "param": "id"},
    ]
    intents = findings_to_intents(vulns)
    types = [i["vuln_type"] for i in intents]
    assert "Missing_HSTS_Header" not in types  # low-value, dropped
    assert "XSS_Param" in types
    assert "SQLi_Param" in types


def test_findings_to_intents_sorts_critical_first():
    vulns = [
        {"type": "XSS_Param", "url": "http://t/x", "severity": "high", "cvss": 6.1},
        {"type": "SQLi_Param", "url": "http://t/s", "severity": "critical", "cvss": 9.8},
        {"type": "SSRF", "url": "http://t/r", "severity": "high", "cvss": 8.6},
    ]
    intents = findings_to_intents(vulns)
    # Critical (SQLi) must come first; then high sorted by cvss desc.
    assert intents[0]["vuln_type"] == "SQLi_Param"


def test_findings_to_intents_caps_at_max_intents():
    vulns = [
        {"type": "XSS_Param", "url": f"http://t/{i}", "param": "q"}
        for i in range(50)
    ]
    intents = findings_to_intents(vulns, max_intents=5)
    assert len(intents) == 5


def test_findings_to_intents_assigns_specific_goal_per_type():
    vulns = [
        {"type": "SSRF", "url": "http://t/r", "param": "u"},
        {"type": "XXE", "url": "http://t/x", "param": "xml"},
    ]
    intents = findings_to_intents(vulns)
    by_type = {i["vuln_type"]: i for i in intents}
    assert "SSRF" in by_type["SSRF"]["goal"]
    assert "external entity" in by_type["XXE"]["goal"].lower()


def test_empty_vulns_returns_empty_intents():
    assert findings_to_intents([]) == []
    assert findings_to_intents(None) == []  # type: ignore[arg-type]


def test_high_value_set_includes_canonical_classes():
    hv = _high_value_vuln_types()
    for t in ("XSS_Param", "SQLi_Param", "SSRF", "LFI_Param", "CMDi_Param"):
        assert t in hv


# ─── merge_pipeline_findings ─────────────────────────────────────────────────


def test_merge_adds_new_findings_to_vulnerabilities():
    scan_result = {
        "url": "http://t/",
        "vulnerabilities": [
            {"type": "XSS_Param", "url": "http://t/x", "param": "q"},
        ],
    }
    ctx = SimpleNamespace(
        findings=[
            {"type": "SQLi_Param", "url": "http://t/s", "param": "id"},
        ],
        stage_results=[{"stage": "exploit", "intents_run": 1, "succeeded": 1}],
    )
    merged = merge_pipeline_findings(scan_result, ctx)
    assert merged is scan_result
    types = sorted(v["type"] for v in merged["vulnerabilities"])
    assert types == ["SQLi_Param", "XSS_Param"]
    assert merged["intent_pipeline_added"] == 1
    assert len(merged["intent_pipeline_stages"]) == 1


def test_merge_deduplicates_against_existing():
    scan_result = {
        "url": "http://t/",
        "vulnerabilities": [
            {"type": "XSS_Param", "url": "http://t/x", "param": "q"},
        ],
    }
    ctx = SimpleNamespace(
        findings=[
            {"type": "XSS_Param", "url": "http://t/x", "param": "q"},  # dup
        ],
        stage_results=[],
    )
    merge_pipeline_findings(scan_result, ctx)
    assert len(scan_result["vulnerabilities"]) == 1
    assert scan_result["intent_pipeline_added"] == 0


def test_merge_handles_none_input():
    assert merge_pipeline_findings(None, SimpleNamespace(findings=[])) is None
    sr = {"url": "x"}
    assert merge_pipeline_findings(sr, None) is sr


# ─── run_intent_pipeline ─────────────────────────────────────────────────────


def test_run_intent_pipeline_skips_without_high_value_vulns():
    scan_result = {
        "url": "http://t/",
        "vulnerabilities": [
            {"type": "Missing_HSTS_Header", "url": "http://t/"},
        ],
    }
    with patch("utils.agent_orchestrator.run_mission") as run_mission_mock:
        out = run_intent_pipeline(scan_result, ai_client=None)
    run_mission_mock.assert_not_called()
    assert out is scan_result


def test_run_intent_pipeline_invokes_orchestrator_when_intents_exist():
    scan_result = {
        "url": "http://t/",
        "vulnerabilities": [
            {"type": "XSS_Param", "url": "http://t/x", "param": "q"},
        ],
    }
    fake_ctx = SimpleNamespace(
        findings=[
            {
                "type": "XSS_Param",
                "url": "http://t/x",
                "param": "q",
                "confidence": 95,
                "evidence": "confirmed via sandbox",
            },
            {
                "type": "AI_Discovered",
                "url": "http://t/x",
                "param": "q",
                "confidence": 80,
            },
        ],
        stage_results=[
            {"stage": "exploit", "intents_run": 1, "succeeded": 1},
        ],
    )
    ai_client = MagicMock(available=True)
    with patch(
        "utils.agent_orchestrator.run_mission", return_value=fake_ctx
    ) as run_mission_mock, patch(
        "utils.agent_orchestrator.build_default_pipeline"
    ) as pipeline_mock:
        run_intent_pipeline(scan_result, ai_client=ai_client, max_iterations=2)

    run_mission_mock.assert_called_once()
    call_kwargs = run_mission_mock.call_args.kwargs
    assert call_kwargs["ai_client"] is ai_client
    intents = call_kwargs["intents"]
    assert intents and intents[0]["vuln_type"] == "XSS_Param"
    pipeline_mock.assert_called_once_with(
        ai_client=ai_client, max_iterations=2, min_confidence=50.0,
    )
    # AI_Discovered finding (new) merged in; the duplicate XSS_Param ignored.
    assert scan_result["intent_pipeline_added"] == 1


def test_run_intent_pipeline_missing_url_is_noop():
    out = run_intent_pipeline(
        {"vulnerabilities": [{"type": "XSS_Param", "url": "http://t/x"}]},
        ai_client=None,
    )
    assert "intent_pipeline_added" not in out


def test_run_intent_pipeline_none_input():
    assert run_intent_pipeline(None) is None
