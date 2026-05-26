"""Tests for the v2.1 phase boundary tracking in ScanSession.

Existing ``test_session_manager.py`` covers URL-level resume + atomic
writes. This file specifically tests:

* ``mark_phase_done`` appends to the ``phases_completed`` list (no
  duplicates) and survives a save / load cycle.
* Calling with ``vulns_snapshot`` persists mid-pipeline findings *before*
  ``finalize_session`` runs — the original gap that lost everything on
  AI-phase crashes.
* ``ScanContext`` exposes the same API via ``mark_phase_done`` /
  ``is_phase_done``, including the no-op behavior when no session is
  active.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from core.scan_context import ScanContext
from core.session import ScanSession

pytestmark = pytest.mark.unit


@pytest.fixture
def session_file():
    with tempfile.TemporaryDirectory() as d:
        yield os.path.join(d, "session.json")


class TestPhaseTracking:
    def test_empty_session_has_no_phases(self, session_file):
        s = ScanSession(session_file)
        assert s.completed_phases == []
        assert s.is_phase_done("anything") is False

    def test_mark_phase_done_appends(self, session_file):
        s = ScanSession(session_file)
        s.mark_phase_done("pre_scan")
        s.mark_phase_done("discovery_seed")
        assert s.completed_phases == ["pre_scan", "discovery_seed"]

    def test_mark_phase_done_is_idempotent(self, session_file):
        s = ScanSession(session_file)
        s.mark_phase_done("post_scan")
        s.mark_phase_done("post_scan")
        s.mark_phase_done("post_scan")
        assert s.completed_phases == ["post_scan"]
        assert s.is_phase_done("post_scan") is True

    def test_phases_survive_save_load(self, session_file):
        s = ScanSession(session_file)
        s.mark_phase_done("pre_scan")
        s.mark_phase_done("scan_urls")

        s2 = ScanSession.load(session_file)
        assert s2.is_phase_done("pre_scan")
        assert s2.is_phase_done("scan_urls")
        assert not s2.is_phase_done("reporting")

    def test_empty_phase_name_is_noop(self, session_file):
        s = ScanSession(session_file)
        s.mark_phase_done("")
        assert s.completed_phases == []

    def test_no_session_file_does_not_crash(self):
        s = ScanSession(None)
        # No file = no autosave, but in-memory phase tracking still works
        s.mark_phase_done("pre_scan")
        assert s.is_phase_done("pre_scan")


class TestVulnSnapshot:
    def test_snapshot_persists_findings_mid_pipeline(self, session_file):
        s = ScanSession(session_file)
        snapshot = [
            {"type": "XSS_Param", "url": "http://x/q", "payload": "<svg>"},
            {"type": "Secret_Leak", "url": "http://x/.env", "evidence": "API_KEY=..."},
        ]
        s.mark_phase_done("post_scan", vulns_snapshot=snapshot)

        reloaded = ScanSession.load(session_file)
        types = {v["type"] for v in reloaded.data["vulnerabilities"]}
        assert types == {"XSS_Param", "Secret_Leak"}

    def test_snapshot_is_deduplicated(self, session_file):
        s = ScanSession(session_file)
        finding = {"type": "XSS_Param", "url": "http://x/q", "payload": "<svg>"}
        s.mark_phase_done("phase_a", vulns_snapshot=[finding])
        s.mark_phase_done("phase_b", vulns_snapshot=[finding])  # duplicate

        reloaded = ScanSession.load(session_file)
        assert len(reloaded.data["vulnerabilities"]) == 1

    def test_no_snapshot_does_not_clobber_vulns(self, session_file):
        s = ScanSession(session_file)
        s.add_vulnerabilities([
            {"type": "XSS_Param", "url": "http://x/q", "payload": "<svg>"},
        ])
        s.mark_phase_done("phase_a")  # no snapshot arg

        reloaded = ScanSession.load(session_file)
        assert len(reloaded.data["vulnerabilities"]) == 1
        assert reloaded.is_phase_done("phase_a")


class TestScanContextWrapper:
    def test_no_session_means_phase_calls_are_noop(self):
        # ScanContext with session=None should accept the calls without raising
        ctx = ScanContext.__new__(ScanContext)
        ctx.session = None
        ctx.mark_phase_done("anything")  # no crash
        assert ctx.is_phase_done("anything") is False

    def test_inactive_session_is_noop(self, session_file):
        ctx = ScanContext.__new__(ScanContext)
        ctx.session = ScanSession(None)  # active=False
        ctx.mark_phase_done("post_scan", vulns_snapshot=[{"type": "X"}])
        assert ctx.is_phase_done("post_scan") is False

    def test_active_session_records_phase(self, session_file):
        ctx = ScanContext.__new__(ScanContext)
        ctx.session = ScanSession(session_file)
        ctx.mark_phase_done("recon", vulns_snapshot=[
            {"type": "Tech_Fingerprint", "url": "http://x/", "evidence": "nginx/1.18"},
        ])
        assert ctx.is_phase_done("recon")
        assert ctx.is_phase_done("post_scan") is False

        # The mid-pipeline snapshot survives a fresh load
        s2 = ScanSession.load(session_file)
        assert s2.is_phase_done("recon")
        assert len(s2.data["vulnerabilities"]) == 1
