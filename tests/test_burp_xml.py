"""Tests for utils.reporters.burp_xml.

The XML must be well-formed, contain the right Burp severity enum, and
preserve the CWE id + evidence per finding.
"""

from __future__ import annotations

import os
import tempfile
import xml.etree.ElementTree as ET

import pytest

from utils.reporters.burp_xml import (
    _confidence_label,
    _severity_label,
    export_burp_xml,
)

pytestmark = pytest.mark.unit


SAMPLE = [
    {
        "id": "fnd-001",
        "title": "Sensitive Information Exposure",
        "cwe": "CWE-200",
        "cvss": 7.5,
        "severity": "critical",
        "url": "https://target.tld/.env?x=1",
        "module": "passive",
        "type": "Secret_Leak",
        "evidence": "OPENAI_API_KEY=sk-proj-...",
        "payload": "API key in .env",
        "verification_state": "verified",
        "confidence": "high",
        "remediation": "Move .env out of docroot.",
    },
    {
        "id": "fnd-002",
        "title": "Clickjacking Exploitable",
        "cwe": "CWE-1021",
        "cvss": 5.4,
        "severity": "medium",
        "url": "https://target.tld/account/delete",
        "module": "active",
        "type": "Clickjacking_Exploitable",
        "verified": True,
        "evidence": "no XFO + no CSP frame-ancestors",
    },
]


def _parse(path: str) -> ET.Element:
    return ET.parse(path).getroot()


class TestSeverityMap:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("critical", "High"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
            ("info", "Information"),
            ("anything-else", "Information"),
        ],
    )
    def test_severity_label(self, value, expected):
        assert _severity_label(value) == expected


class TestConfidenceMap:
    def test_high_string(self):
        assert _confidence_label("high") == "Certain"

    def test_medium_string(self):
        assert _confidence_label("medium") == "Firm"

    def test_numeric_high(self):
        assert _confidence_label(95) == "Certain"

    def test_numeric_mid(self):
        assert _confidence_label(60) == "Firm"

    def test_numeric_low(self):
        assert _confidence_label(10) == "Tentative"

    def test_garbage(self):
        assert _confidence_label("???") == "Tentative"
        assert _confidence_label(None) == "Tentative"


class TestExport:
    def test_writes_valid_xml(self):
        with tempfile.TemporaryDirectory() as d:
            out = export_burp_xml(SAMPLE, os.path.join(d, "issues.xml"), scan_url="https://target.tld/")
            assert os.path.exists(out)
            root = _parse(out)
            assert root.tag == "issues"
            assert root.get("scanTarget") == "https://target.tld/"

    def test_emits_one_issue_per_finding(self):
        with tempfile.TemporaryDirectory() as d:
            out = export_burp_xml(SAMPLE, os.path.join(d, "issues.xml"))
            root = _parse(out)
            issues = root.findall("issue")
            assert len(issues) == 2

    def test_preserves_cwe_severity_confidence(self):
        with tempfile.TemporaryDirectory() as d:
            out = export_burp_xml(SAMPLE, os.path.join(d, "issues.xml"))
            root = _parse(out)
            first = root.find("issue")
            assert first.findtext("type") == "CWE-200"
            assert first.findtext("severity") == "High"
            assert first.findtext("confidence") == "Certain"

    def test_url_split_host_path(self):
        with tempfile.TemporaryDirectory() as d:
            out = export_burp_xml(SAMPLE, os.path.join(d, "issues.xml"))
            root = _parse(out)
            first = root.find("issue")
            assert first.findtext("host") == "https://target.tld"
            assert first.findtext("path") == "/.env?x=1"

    def test_evidence_appears_in_detail(self):
        with tempfile.TemporaryDirectory() as d:
            out = export_burp_xml(SAMPLE, os.path.join(d, "issues.xml"))
            root = _parse(out)
            first = root.find("issue")
            detail = first.findtext("issueDetail") or ""
            assert "OPENAI_API_KEY" in detail or "sk-proj" in detail

    def test_empty_findings_list_writes_empty_doc(self):
        with tempfile.TemporaryDirectory() as d:
            out = export_burp_xml([], os.path.join(d, "issues.xml"))
            root = _parse(out)
            assert root.tag == "issues"
            assert root.findall("issue") == []

    def test_malformed_entry_skipped_not_raises(self):
        """A finding missing required fields shouldn't blow up the export."""
        bad_findings = [
            {"this": "is", "not": "a finding"},  # no url, no severity
            SAMPLE[0],
        ]
        with tempfile.TemporaryDirectory() as d:
            out = export_burp_xml(bad_findings, os.path.join(d, "issues.xml"))
            root = _parse(out)
            # Should still produce at least the well-formed one
            issues = root.findall("issue")
            assert len(issues) >= 1
