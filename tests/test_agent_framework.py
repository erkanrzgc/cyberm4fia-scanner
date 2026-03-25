import pytest
from unittest.mock import MagicMock, patch
from utils.agent_framework import (
    Agent, ReconAgent, ExploitAgent, ReportAgent, AgentOrchestrator
)

@pytest.fixture
def mock_ai():
    mock = MagicMock()
    mock.available = True
    mock.generate.return_value = "Mocked AI response"
    return mock

def test_base_agent_rule_based():
    agent = Agent("TestAgent", "test", "You are a test agent")
    # without AI client, it falls back to rule-based
    
    think_res = agent.think({"target": "test.com"})
    assert "Analyzing context" in think_res
    
    act_res = agent.act({"target": "test.com"})
    assert act_res["action"] == "rule_based"

def test_base_agent_with_ai(mock_ai):
    agent = Agent("TestAgent", "test", "You are a test agent", ai_client=mock_ai)
    
    think_res = agent.think({"target": "test.com"})
    assert think_res == "Mocked AI response"
    assert len(agent.memory) == 1
    assert mock_ai.generate.call_count == 1

def test_recon_agent_rule_based():
    agent = ReconAgent()
    res = agent.act({"target": "test.com"})
    assert "recon" in res["recommended_modules"]
    assert res["target"] == "test.com"

def test_exploit_agent_rule_based():
    agent = ExploitAgent()
    res = agent.act({"vulnerabilities": [{"type": "SQLi", "severity": "high"}]})
    assert len(res["recommended_exploits"]) == 1
    assert "UNION-based extraction" in "\n".join(res["recommended_exploits"][0]["techniques"])

def test_report_agent_rule_based():
    agent = ReportAgent()
    res = agent.act({"findings": [{"severity": "critical"}]})
    assert res["total_findings"] == 1
    assert res["severity_breakdown"]["critical"] == 1
    assert res["risk_level"] == "CRITICAL"

@patch("scanner.scan_target")
def test_orchestrator_mission(mock_scan_target):
    mock_scan_target.return_value = {
        "vulnerabilities": [{"type": "XSS", "url": "http://example.com/xss"}],
        "findings": [{"id": "f1", "type": "XSS"}],
        "observations": [],
        "attack_paths": [],
        "recon_data": {},
        "stats": {"total_requests": 10},
        "scan_dir": "/tmp/test",
        "log_file": "/tmp/test/scan.txt",
        "total_vulns": 1,
    }

    orchestrator = AgentOrchestrator()  # Rule-based fallback mode

    # Run a complete mission (scan_target is mocked)
    mission = orchestrator.run_mission("http://example.com")

    assert mission.target == "http://example.com"
    assert mission.status == "completed"
    assert len(mission.agents_used) == 3
    assert len(mission.tasks) == 3  # recon, exploit, report
    assert len(mission.findings) > 0  # findings from real scan pipeline
    mock_scan_target.assert_called_once()
