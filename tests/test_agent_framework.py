import pytest
from unittest.mock import MagicMock
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

def test_orchestrator_mission():
    orchestrator = AgentOrchestrator() # Rule-based fallback mode
    
    # Run a complete mission
    mission = orchestrator.run_mission("example.com")
    
    assert mission.target == "example.com"
    assert mission.status == "completed"
    assert len(mission.agents_used) == 3
    assert len(mission.tasks) == 3 # recon, exploit, report
