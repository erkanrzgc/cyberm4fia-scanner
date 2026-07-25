"""Tests for utils.severity_exit (CI exit-code gating)."""

from __future__ import annotations


import pytest

from utils.severity_exit import (
    CODE_CLEAN,
    CODE_CRITICAL,
    CODE_HIGH,
    CODE_LOW,
    CODE_MEDIUM,
    compute_exit_code,
    describe,
)

pytestmark = pytest.mark.unit


class TestComputeExitCode:
    def test_no_findings_is_clean(self):
        assert compute_exit_code([]) == CODE_CLEAN
        assert compute_exit_code(None) == CODE_CLEAN

    def test_only_info(self):
        assert compute_exit_code([{"severity": "info"}]) == CODE_LOW

    def test_only_low(self):
        assert compute_exit_code([{"severity": "low"}]) == CODE_LOW

    def test_only_medium(self):
        assert compute_exit_code([{"severity": "medium"}]) == CODE_MEDIUM

    def test_only_high(self):
        assert compute_exit_code([{"severity": "high"}]) == CODE_HIGH

    def test_only_critical(self):
        assert compute_exit_code([{"severity": "critical"}]) == CODE_CRITICAL

    def test_worst_wins(self):
        assert (
            compute_exit_code([
                {"severity": "low"},
                {"severity": "critical"},
                {"severity": "info"},
            ])
            == CODE_CRITICAL
        )

    def test_case_insensitive_severity(self):
        assert compute_exit_code([{"severity": "CRITICAL"}]) == CODE_CRITICAL
        assert compute_exit_code([{"severity": "  High  "}]) == CODE_HIGH

    def test_finding_object_with_attribute(self):
        class F:
            severity = "critical"
        assert compute_exit_code([F()]) == CODE_CRITICAL


class TestThresholdGate:
    def test_high_threshold_swallows_medium(self):
        assert compute_exit_code([{"severity": "medium"}], threshold="high") == CODE_CLEAN

    def test_high_threshold_passes_critical(self):
        assert compute_exit_code([{"severity": "critical"}], threshold="high") == CODE_CRITICAL

    def test_critical_threshold_swallows_high(self):
        assert compute_exit_code([{"severity": "high"}], threshold="critical") == CODE_CLEAN

    def test_low_threshold_passes_info(self):
        assert compute_exit_code([{"severity": "info"}], threshold="low") == CODE_LOW

    def test_never_threshold_swallows_all(self):
        assert compute_exit_code([{"severity": "critical"}], threshold="never") == CODE_CLEAN

    def test_env_var_threshold(self, monkeypatch):
        monkeypatch.setenv("SCAN_EXIT_THRESHOLD", "critical")
        assert compute_exit_code([{"severity": "high"}]) == CODE_CLEAN

    def test_env_var_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("SCAN_EXIT_THRESHOLD", raising=False)
        # default threshold is "info" which passes everything
        assert compute_exit_code([{"severity": "info"}]) == CODE_LOW


class TestDescribe:
    def test_describes_all_codes(self):
        for code in (CODE_CLEAN, CODE_CRITICAL, CODE_HIGH, CODE_MEDIUM, CODE_LOW):
            assert describe(code)
        assert "unknown" in describe(99)
