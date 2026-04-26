"""Tests for utils/meta_tools — fixture-based parser tests, no real binaries."""

from __future__ import annotations

import json

import pytest

from utils.meta_tools import (
    NmapScan,
    NucleiFinding,
    SqlmapResult,
    parse_nmap_xml,
    parse_nuclei_jsonl,
    parse_sqlmap_json,
    summarize_for_ai,
)


pytestmark = pytest.mark.unit


# ─── Nmap fixtures ───────────────────────────────────────────────────────────


_NMAP_XML = """<?xml version="1.0"?>
<nmaprun args="nmap -sV scanme.nmap.org">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <hostnames><hostname name="scanme.nmap.org" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="6.6.1p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.7"/>
      </port>
      <port protocol="tcp" portid="9929">
        <state state="closed"/>
        <service name="nping-echo"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class TestNmapParser:
    def test_extracts_host_and_open_ports(self):
        scan = parse_nmap_xml(_NMAP_XML)
        assert isinstance(scan, NmapScan)
        assert len(scan.hosts) == 1
        host = scan.hosts[0]
        assert host.address == "45.33.32.156"
        assert host.hostname == "scanme.nmap.org"
        assert len(host.ports) == 3
        assert len(host.open_ports) == 2
        assert {p.port for p in host.open_ports} == {22, 80}

    def test_open_port_count_aggregate(self):
        scan = parse_nmap_xml(_NMAP_XML)
        assert scan.open_port_count == 2

    def test_service_metadata_carried_through(self):
        scan = parse_nmap_xml(_NMAP_XML)
        ssh = next(p for p in scan.hosts[0].ports if p.port == 22)
        assert ssh.service == "ssh"
        assert ssh.product == "OpenSSH"
        assert ssh.version == "6.6.1p1"

    def test_empty_input_returns_empty_scan(self):
        assert parse_nmap_xml("").hosts == ()
        assert parse_nmap_xml("   ").hosts == ()

    def test_malformed_xml_returns_empty_scan(self):
        assert parse_nmap_xml("<not really xml").hosts == ()


# ─── Nuclei fixtures ─────────────────────────────────────────────────────────


_NUCLEI_JSONL = "\n".join([
    json.dumps({
        "template-id": "exposed-env-file",
        "info": {
            "name": ".env file exposed",
            "severity": "high",
            "tags": ["exposure", "config"],
            "classification": {"cvss-score": 7.5},
            "description": "An .env file was reachable.",
        },
        "matched-at": "https://example.test/.env",
        "host": "example.test",
    }),
    "",  # blank line tolerated
    json.dumps({
        "template-id": "tech-detect",
        "info": {"name": "tech detect", "severity": "info", "tags": "tech"},
        "matched-at": "https://example.test/",
        "host": "example.test",
    }),
    "{not valid json",  # invalid line skipped
])


class TestNucleiParser:
    def test_parses_two_valid_findings_skips_invalid(self):
        findings = parse_nuclei_jsonl(_NUCLEI_JSONL)
        assert len(findings) == 2
        assert all(isinstance(f, NucleiFinding) for f in findings)

    def test_high_severity_marked_critical(self):
        findings = parse_nuclei_jsonl(_NUCLEI_JSONL)
        env_finding = findings[0]
        assert env_finding.severity == "high"
        assert env_finding.is_critical is True
        assert env_finding.cvss == 7.5
        assert env_finding.tags == ("exposure", "config")

    def test_info_severity_not_critical(self):
        findings = parse_nuclei_jsonl(_NUCLEI_JSONL)
        assert findings[1].is_critical is False

    def test_string_tags_split_into_tuple(self):
        findings = parse_nuclei_jsonl(_NUCLEI_JSONL)
        assert findings[1].tags == ("tech",)

    def test_empty_input(self):
        assert parse_nuclei_jsonl("") == ()
        assert parse_nuclei_jsonl("\n\n") == ()


# ─── SQLMap fixtures ─────────────────────────────────────────────────────────


_SQLMAP_JSON_API = json.dumps({
    "success": True,
    "data": {
        "url": "http://target.test/item.php?id=1",
        "dbms": "MySQL",
        "injection": [
            {
                "parameter": "id",
                "place": "GET",
                "data": {
                    "1": {
                        "title": "AND boolean-based blind",
                        "payload": "id=1 AND 4321=4321",
                    },
                    "2": {
                        "title": "UNION query - 5 columns",
                        "payload": "id=1 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL",
                    },
                },
            }
        ],
    },
})


class TestSqlmapParser:
    def test_extracts_injections_from_api_envelope(self):
        result = parse_sqlmap_json(_SQLMAP_JSON_API)
        assert isinstance(result, SqlmapResult)
        assert result.vulnerable is True
        assert result.target.endswith("item.php?id=1")
        assert result.db_type == "MySQL"
        assert len(result.injections) == 2

    def test_techniques_dedup_preserves_order(self):
        result = parse_sqlmap_json(_SQLMAP_JSON_API)
        techs = result.techniques_used
        assert techs[0] == "AND boolean-based blind"
        assert "UNION query - 5 columns" in techs

    def test_accepts_dict_directly(self):
        obj = json.loads(_SQLMAP_JSON_API)
        result = parse_sqlmap_json(obj)
        assert result.vulnerable is True

    def test_empty_json_is_not_vulnerable(self):
        assert parse_sqlmap_json("{}").vulnerable is False
        assert parse_sqlmap_json("").vulnerable is False
        assert parse_sqlmap_json("garbage").vulnerable is False


# ─── AI summarizer ───────────────────────────────────────────────────────────


class TestAiSummarizer:
    def test_summarizes_nmap_scan(self):
        text = summarize_for_ai(parse_nmap_xml(_NMAP_XML))
        assert "Nmap:" in text
        assert "1 host" in text
        assert "open port" in text
        assert "22/tcp" in text or ":22" in text

    def test_summarizes_nuclei_findings(self):
        findings = parse_nuclei_jsonl(_NUCLEI_JSONL)
        text = summarize_for_ai(findings)
        assert "Nuclei:" in text
        assert "exposed-env-file" in text
        assert "1 high/critical" in text

    def test_summarizes_sqlmap_result(self):
        result = parse_sqlmap_json(_SQLMAP_JSON_API)
        text = summarize_for_ai(result)
        assert "VULNERABLE" in text
        assert "MySQL" in text

    def test_empty_input_returns_empty_string(self):
        assert summarize_for_ai("not a known type") == ""
        assert summarize_for_ai(()) == ""
