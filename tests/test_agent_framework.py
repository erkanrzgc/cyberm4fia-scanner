from unittest.mock import patch
from utils.agent_framework import (
    AgentOrchestrator, AgentTask, AgentMemory, MissionReport
)


def test_agent_task_creation():
    task = AgentTask(
        id="test_1",
        description="Run recon",
        agent_role="executor",
    )
    assert task.id == "test_1"
    assert task.status == "pending"
    assert task.result is None
    assert task.created_at  # auto-populated


def test_agent_task_completion():
    task = AgentTask(
        id="test_2",
        description="Run XSS scan",
        agent_role="executor",
        status="completed",
        result={"finding_count": 3},
    )
    assert task.status == "completed"
    assert task.result["finding_count"] == 3


def test_mission_report_creation():
    report = MissionReport(target="http://example.com", start_time="2026-01-01T00:00:00")
    assert report.target == "http://example.com"
    assert report.status == "in_progress"
    assert report.findings == []
    assert report.agents_used == []


def test_mission_report_to_dict():
    report = MissionReport(
        target="http://example.com",
        start_time="2026-01-01T00:00:00",
        end_time="2026-01-01T00:05:00",
        agents_used=["Planner", "Executor"],
        findings=[{"type": "XSS"}],
        summary="Found 1 XSS",
        status="completed",
    )
    d = report.to_dict()
    assert d["target"] == "http://example.com"
    assert d["finding_count"] == 1
    assert d["status"] == "completed"
    assert d["task_count"] == 0


def test_agent_memory_init():
    memory = AgentMemory("http://test.com")
    assert memory.target == "http://test.com"
    assert memory.iterations == []
    assert memory.modules_run == set()
    assert memory.all_findings == []
    assert memory.waf_detected is None


def test_agent_memory_add_findings():
    memory = AgentMemory("http://test.com")
    memory.add_findings([{"type": "SQLi", "severity": "high"}])
    assert len(memory.all_findings) == 1
    memory.add_findings([{"type": "XSS", "severity": "medium"}])
    assert len(memory.all_findings) == 2


def test_agent_memory_add_iteration():
    memory = AgentMemory("http://test.com")
    memory.add_iteration(
        plan={"modules": ["recon"]},
        results={"recon": {"ip": "1.2.3.4"}},
        summary="Found IP address",
    )
    assert len(memory.iterations) == 1
    assert memory.iterations[0]["plan"]["modules"] == ["recon"]


def test_agent_memory_context_window():
    memory = AgentMemory("http://test.com")
    memory.modules_run.add("recon")
    memory.tech_stack = [{"name": "nginx"}, {"name": "PHP"}]
    memory.waf_detected = "Cloudflare"
    memory.add_findings([{"type": "XSS", "severity": "high", "url": "http://test.com/x"}])
    memory.add_iteration(
        plan={"modules": ["xss"]},
        results={"xss": [{"type": "XSS"}]},
        summary="Found reflected XSS",
    )

    ctx = memory.get_context_window()
    assert "http://test.com" in ctx
    assert "nginx" in ctx
    assert "Cloudflare" in ctx
    assert "recon" in ctx
    assert "Total findings: 1" in ctx


def test_orchestrator_fallback_plan_initial():
    orch = AgentOrchestrator(ai_client=None)
    memory = AgentMemory("http://test.com")
    plan = orch._fallback_plan(memory)
    assert "recon" in plan["modules"]
    assert "tech_detect" in plan["modules"]
    assert plan["done"] is False


def test_orchestrator_fallback_plan_after_recon():
    orch = AgentOrchestrator(ai_client=None)
    memory = AgentMemory("http://test.com")
    memory.modules_run = {"recon", "tech_detect", "header_audit"}
    plan = orch._fallback_plan(memory)
    # Should pick core vuln modules now
    assert plan["done"] is False
    core_vulns = {"xss", "sqli", "lfi", "cmdi", "ssrf", "ssti"}
    assert set(plan["modules"]).issubset(core_vulns)


def test_orchestrator_fallback_plan_all_done():
    orch = AgentOrchestrator(ai_client=None)
    memory = AgentMemory("http://test.com")
    memory.modules_run = {
        "recon", "tech_detect", "header_audit",
        "xss", "sqli", "lfi", "cmdi", "ssrf", "ssti",
        "xxe", "csrf", "cors", "jwt", "smuggling", "deserialization",
    }
    plan = orch._fallback_plan(memory)
    assert plan["done"] is True


def test_orchestrator_fallback_summarize():
    orch = AgentOrchestrator(ai_client=None)
    memory = AgentMemory("http://test.com")
    results = {
        "recon": {"ip": "1.2.3.4"},
        "xss": [{"type": "XSS"}],
    }
    summary = orch._fallback_summarize(results, memory)
    assert "http://test.com" in summary
    assert "recon" in summary
    assert "xss" in summary


@patch("scanner.scan_target")
def test_orchestrator_mission(mock_scan_target):
    """Test that the orchestrator completes a mission in fallback mode."""
    orch = AgentOrchestrator(ai_client=None)

    # Run mission — deterministic fallback mode
    mission = orch.run_mission("http://example.com")

    assert mission.target == "http://example.com"
    assert mission.status == "completed"
    assert len(mission.agents_used) == 3
    assert len(mission.tasks) > 0
