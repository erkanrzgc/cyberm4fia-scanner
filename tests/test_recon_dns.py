"""Tests for modules/recon_dns — DNS deep enum (SPF, DMARC, DKIM, CAA, AXFR)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from modules.recon_dns import (
    DnsReport,
    _parse_dmarc,
    _parse_spf,
    _stringify_txt,
    deep_dns_enum,
)


pytestmark = pytest.mark.unit


# ── Pure helpers ─────────────────────────────────────────────────────────────


def test_parse_spf_extracts_record_and_includes():
    spf, includes = _parse_spf(
        ["v=spf1 include:_spf.google.com include:mailgun.org -all"]
    )
    assert spf.startswith("v=spf1")
    assert includes == ["_spf.google.com", "mailgun.org"]


def test_parse_spf_case_insensitive():
    spf, _ = _parse_spf(["V=SPF1 -all"])
    assert spf.lower().startswith("v=spf1")


def test_parse_spf_none_when_absent():
    assert _parse_spf(["something else"]) == (None, [])


def test_parse_dmarc():
    record = "v=DMARC1; p=reject; rua=mailto:dmarc@x.com"
    assert _parse_dmarc([record]) == record
    assert _parse_dmarc(["not dmarc"]) is None


def test_stringify_txt_joins_chunks():
    rdata = MagicMock(strings=[b"hello", b"world"])
    assert _stringify_txt(rdata) == "helloworld"


# ── deep_dns_enum: SPF / DMARC / CAA scenarios ───────────────────────────────


class _FakeRecord:
    """dnspython-record-shaped duck for the tests."""

    def __init__(self, **fields):
        self.__dict__.update(fields)

    def to_text(self):
        return getattr(self, "_text", "")


def _make_resolver(answers: dict[tuple[str, str], list]) -> MagicMock:
    """Build a resolver mock that returns lists by (qname, rdtype) lookup."""
    resolver = MagicMock(spec=dns.resolver.Resolver)

    def fake_resolve(qname, rdtype, lifetime=5):
        key = (str(qname).rstrip("."), str(rdtype))
        result = answers.get(key)
        if not result:
            raise dns.resolver.NoAnswer()
        return result

    resolver.resolve.side_effect = fake_resolve
    return resolver


def test_missing_spf_yields_finding():
    resolver = _make_resolver({})
    report = deep_dns_enum(
        "example.com",
        resolver=resolver,
        dkim_selectors=(),
        attempt_axfr=False,
        attempt_reverse=False,
    )
    types = [f["type"] for f in report.security_findings]
    assert "Missing_SPF" in types
    assert "Missing_DMARC" in types
    assert "Missing_CAA" in types


def test_weak_spf_policy_flagged():
    spf_record = MagicMock(strings=[b"v=spf1 +all"])
    resolver = _make_resolver(
        {("example.com", "TXT"): [spf_record]}
    )
    report = deep_dns_enum(
        "example.com",
        resolver=resolver,
        dkim_selectors=(),
        attempt_axfr=False,
        attempt_reverse=False,
    )
    types = [f["type"] for f in report.security_findings]
    assert "Weak_SPF_Policy" in types


def test_dmarc_p_none_flagged():
    dmarc_record = MagicMock(strings=[b"v=DMARC1; p=none"])
    resolver = _make_resolver(
        {("_dmarc.example.com", "TXT"): [dmarc_record]}
    )
    report = deep_dns_enum(
        "example.com",
        resolver=resolver,
        dkim_selectors=(),
        attempt_axfr=False,
        attempt_reverse=False,
    )
    types = [f["type"] for f in report.security_findings]
    assert "Weak_DMARC_Policy" in types


def test_present_caa_silences_missing_finding():
    caa_record = MagicMock()
    caa_record.to_text = lambda: '0 issue "letsencrypt.org"'
    resolver = _make_resolver({("example.com", "CAA"): [caa_record]})
    report = deep_dns_enum(
        "example.com",
        resolver=resolver,
        dkim_selectors=(),
        attempt_axfr=False,
        attempt_reverse=False,
    )
    types = [f["type"] for f in report.security_findings]
    assert "Missing_CAA" not in types
    assert "letsencrypt.org" in report.caa[0]


def test_dkim_selector_brute_finds_present_selector():
    dkim_record = MagicMock(strings=[b"v=DKIM1; k=rsa; p=BASE64KEY"])
    resolver = _make_resolver(
        {("default._domainkey.example.com", "TXT"): [dkim_record]}
    )
    report = deep_dns_enum(
        "example.com",
        resolver=resolver,
        dkim_selectors=("default", "selector1"),
        attempt_axfr=False,
        attempt_reverse=False,
    )
    assert "default" in report.dkim_selectors
    assert "v=DKIM1" in report.dkim_selectors["default"]
    assert "selector1" not in report.dkim_selectors


def test_axfr_success_emits_high_severity_finding():
    ns_record = MagicMock()
    ns_record.target.to_text.return_value = "ns1.example.com."
    a_record = MagicMock(address="1.2.3.4")
    resolver = _make_resolver({
        ("example.com", "NS"): [ns_record],
        ("ns1.example.com", "A"): [a_record],
    })

    with patch(
        "modules.recon_dns._attempt_axfr",
        return_value=["host1", "host2", "host3"],
    ):
        report = deep_dns_enum(
            "example.com",
            resolver=resolver,
            dkim_selectors=(),
            attempt_axfr=True,
            attempt_reverse=False,
        )
    assert "ns1.example.com" in report.axfr_results
    types = [f["type"] for f in report.security_findings]
    assert "DNS_Zone_Transfer_Allowed" in types


def test_axfr_failure_does_not_raise():
    ns_record = MagicMock()
    ns_record.target.to_text.return_value = "ns1.example.com."
    a_record = MagicMock(address="1.2.3.4")
    resolver = _make_resolver({
        ("example.com", "NS"): [ns_record],
        ("ns1.example.com", "A"): [a_record],
    })

    with patch("modules.recon_dns._attempt_axfr", return_value=[]):
        report = deep_dns_enum(
            "example.com",
            resolver=resolver,
            dkim_selectors=(),
            attempt_axfr=True,
            attempt_reverse=False,
        )
    assert report.axfr_results == {}
    types = [f["type"] for f in report.security_findings]
    assert "DNS_Zone_Transfer_Allowed" not in types


def test_timeouts_are_absorbed_into_empty_results():
    resolver = MagicMock(spec=dns.resolver.Resolver)
    resolver.resolve.side_effect = dns.exception.Timeout()

    report = deep_dns_enum(
        "example.com",
        resolver=resolver,
        dkim_selectors=(),
        attempt_axfr=False,
        attempt_reverse=False,
    )
    assert report.a_records == []
    assert report.spf is None


def test_report_finding_carries_module_marker():
    resolver = _make_resolver({})
    report = deep_dns_enum(
        "example.com",
        resolver=resolver,
        dkim_selectors=(),
        attempt_axfr=False,
        attempt_reverse=False,
    )
    for f in report.security_findings:
        assert f["module"] == "recon_dns"
        assert f["url"] == "example.com"


def test_dnsreport_add_finding_appends():
    report = DnsReport(domain="x")
    report.add_finding("T", "high", "ev", cwe="CWE-1")
    assert report.security_findings == [
        {
            "type": "T",
            "url": "x",
            "severity": "high",
            "evidence": "ev",
            "cwe": "CWE-1",
            "module": "recon_dns",
        }
    ]
