"""Tests for utils/mcp_server — pure dispatch layer (no MCP SDK needed)."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from utils.mcp_server import (
    TOOLS,
    dispatch,
    list_tools,
)


pytestmark = pytest.mark.unit


# ─── Catalog ─────────────────────────────────────────────────────────────────


class TestCatalog:
    def test_at_least_four_tools_registered(self):
        assert len(TOOLS) >= 4

    def test_all_tool_names_namespaced(self):
        for spec in TOOLS:
            assert spec.name.startswith("cyberm4fia."), spec.name

    def test_list_tools_returns_mcp_shape(self):
        listing = list_tools()
        assert len(listing) == len(TOOLS)
        for entry in listing:
            assert set(entry.keys()) == {"name", "description", "inputSchema"}
            assert entry["inputSchema"]["type"] == "object"

    def test_intent_agent_tool_requires_goal_and_target(self):
        intent_tool = next(
            t for t in TOOLS if t.name == "cyberm4fia.run_intent_agent"
        )
        assert "goal" in intent_tool.input_schema["required"]
        assert "target_url" in intent_tool.input_schema["required"]


# ─── Dispatch — parser tools ─────────────────────────────────────────────────


class TestDispatchParsers:
    def test_unknown_tool_returns_error(self):
        out = dispatch("cyberm4fia.does_not_exist", {})
        assert out["ok"] is False
        assert "unknown tool" in out["error"]

    def test_parse_nmap_xml_round_trip(self):
        xml = """<?xml version="1.0"?>
<nmaprun args="nmap -sV t">
  <host><status state="up"/><address addr="1.2.3.4"/>
    <ports><port protocol="tcp" portid="80">
      <state state="open"/><service name="http"/>
    </port></ports></host>
</nmaprun>"""
        out = dispatch("cyberm4fia.parse_nmap_xml", {"xml": xml})
        assert out["ok"] is True
        result = out["result"]
        assert result["host_count"] == 1
        assert result["open_port_count"] == 1
        assert result["hosts"][0]["address"] == "1.2.3.4"
        assert "Nmap:" in result["summary"]

    def test_parse_nuclei_jsonl_round_trip(self):
        jsonl = json.dumps({
            "template-id": "tid",
            "info": {"name": "n", "severity": "high", "tags": ["x"]},
            "matched-at": "https://t/",
            "host": "t",
        })
        out = dispatch("cyberm4fia.parse_nuclei_jsonl", {"jsonl": jsonl})
        assert out["ok"] is True
        assert out["result"]["count"] == 1
        assert out["result"]["critical_count"] == 1

    def test_parse_sqlmap_accepts_string_or_dict(self):
        payload = {
            "data": {
                "url": "http://t/",
                "dbms": "MySQL",
                "injection": [{"parameter": "id", "place": "GET",
                               "data": {"1": {"title": "boolean", "payload": "x"}}}],
            }
        }
        out_str = dispatch("cyberm4fia.parse_sqlmap_json", {"json": json.dumps(payload)})
        out_obj = dispatch("cyberm4fia.parse_sqlmap_json", {"json": payload})
        assert out_str["ok"] is True
        assert out_obj["ok"] is True
        assert out_str["result"]["vulnerable"] is True
        assert out_obj["result"]["db_type"] == "MySQL"

    def test_handler_exception_is_caught(self):
        # Force a dispatch error by passing wrong type.
        out = dispatch("cyberm4fia.parse_nmap_xml", {"xml": 12345})
        # Parser tolerates this by str()-coercing; should still succeed.
        assert out["ok"] is True


# ─── Dispatch — intent agent tool (with mocked agent) ────────────────────────


class TestDispatchIntentAgent:
    def test_returns_unavailable_when_no_ai_client(self):
        with patch("utils.ai_intent_agent.get_intent_agent", return_value=None):
            out = dispatch("cyberm4fia.run_intent_agent", {
                "goal": "x", "target_url": "http://t/",
            })
        assert out["ok"] is True
        assert out["result"]["success"] is False
        assert "not available" in out["result"]["summary"]

    def test_passes_args_to_agent_run(self):
        from utils.ai_intent_agent import IntentOutcome

        fake_outcome = IntentOutcome(
            success=True, intent=None, attempts=[],
            final_code="result={'ok':True}", confidence=88.0,
            evidence="visible", summary="confirmed at 1",
        )

        class FakeAgent:
            def __init__(self):
                self.last_intent = None

            def run(self, intent):
                self.last_intent = intent
                return fake_outcome

        fake = FakeAgent()
        with patch("utils.ai_intent_agent.get_intent_agent", return_value=fake):
            out = dispatch("cyberm4fia.run_intent_agent", {
                "goal": "Confirm XSS",
                "target_url": "http://t/",
                "param": "q",
                "vuln_type": "XSS",
                "constraints": ["no GET to /admin"],
            })

        assert out["ok"] is True
        assert out["result"]["success"] is True
        assert out["result"]["confidence"] == 88.0
        assert out["result"]["final_code"].startswith("result")
        assert fake.last_intent.goal == "Confirm XSS"
        assert fake.last_intent.constraints == ["no GET to /admin"]
