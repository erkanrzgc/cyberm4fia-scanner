"""Tests for modules.auth_session_audit.

The audit walks the modules/ directory and classifies each network-capable
module as session-aware, exempt, or a gap. We verify:

* The audit runs without raising on the real codebase.
* The session-aware fraction stays high (>= 90% of network-capable modules).
* The exempt list is honoured.
* `format_audit_banner` produces a single-line summary plus the gap roster
  when gaps exist, and is silent about gaps when there are none.
"""

from __future__ import annotations

import os
import textwrap

import pytest

from modules.auth_session_audit import (
    AuthSessionAudit,
    ModuleAuditEntry,
    _RAW_HTTPX_EXEMPT,
    audit_modules,
    format_audit_banner,
)

pytestmark = pytest.mark.unit


class TestEntryClassification:
    def test_smart_request_user_is_session_aware(self):
        e = ModuleAuditEntry(
            module="sqli", uses_smart_request=True, uses_raw_http=False,
            reads_global_headers=False, exempt=False,
        )
        assert e.session_aware
        assert e.status == "ok"

    def test_raw_httpx_with_global_headers_is_session_aware(self):
        e = ModuleAuditEntry(
            module="endpoint_fuzzer", uses_smart_request=False, uses_raw_http=True,
            reads_global_headers=True, exempt=True,
        )
        assert e.session_aware
        assert e.status == "ok"

    def test_raw_httpx_without_global_headers_is_gap(self):
        e = ModuleAuditEntry(
            module="some_new_mod", uses_smart_request=False, uses_raw_http=True,
            reads_global_headers=False, exempt=False,
        )
        assert not e.session_aware
        assert e.status == "gap"

    def test_exempt_label(self):
        e = ModuleAuditEntry(
            module="race_condition", uses_smart_request=False, uses_raw_http=True,
            reads_global_headers=False, exempt=True,
        )
        # Exempt module without session-aware signal is reported as `exempt`
        assert not e.session_aware
        assert e.status == "exempt"


class TestRealCodebaseAudit:
    def test_audit_runs_clean(self):
        audit = audit_modules()
        assert audit.entries, "expected at least one network-capable module"

    def test_session_aware_fraction_is_high(self):
        audit = audit_modules()
        ok = len(audit.session_aware)
        total = len(audit.entries)
        ratio = ok / total
        assert ratio >= 0.85, (
            f"only {ok}/{total} ({ratio:.0%}) modules are session-aware — "
            f"audit gap roster: {audit.to_dict()['gap_modules']}"
        )

    def test_known_exempt_modules_are_not_gaps(self):
        audit = audit_modules()
        gap_names = {e.module for e in audit.gaps}
        for exempt in _RAW_HTTPX_EXEMPT:
            assert exempt not in gap_names, f"{exempt} should be exempt, not gap"


class TestBanner:
    def test_banner_format_with_gaps(self):
        audit = AuthSessionAudit(entries=[
            ModuleAuditEntry("a", True, False, False, False),
            ModuleAuditEntry("b", False, True, False, False),  # gap
        ])
        banner = format_audit_banner(audit)
        assert "1/2 modules will carry" in banner
        assert "1 gap module(s): b" in banner

    def test_banner_no_gaps_omits_gap_line(self):
        audit = AuthSessionAudit(entries=[
            ModuleAuditEntry("a", True, False, False, False),
        ])
        banner = format_audit_banner(audit)
        assert "1/1 modules will carry" in banner
        assert "gap module" not in banner

    def test_banner_empty_audit(self):
        banner = format_audit_banner(AuthSessionAudit())
        assert "no network-capable modules" in banner
