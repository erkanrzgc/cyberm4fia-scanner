"""
cyberm4fia-scanner — Multi-Agent Framework
Foundation for autonomous pentesting with specialized AI agents.
Inspired by PentAGI and Revelion architectures.
"""

import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

from utils.colors import Colors, log_info, log_success, log_warning, log_error
from utils.request import ScanExceptions


@dataclass
class AgentTask:
    """A task assigned to an agent."""
    id: str
    description: str
    agent_role: str
    status: str = "pending"  # pending, running, completed, failed
    result: Optional[dict] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: str = ""


@dataclass
class MissionReport:
    """Final report from an orchestrated mission."""
    target: str
    start_time: str
    end_time: str = ""
    agents_used: list = field(default_factory=list)
    tasks: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    summary: str = ""
    status: str = "in_progress"

    def to_dict(self):
        return {
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "agents_used": self.agents_used,
            "task_count": len(self.tasks),
            "finding_count": len(self.findings),
            "summary": self.summary,
            "status": self.status,
        }


class Agent:
    """
    Base AI agent with role-specific behavior.
    Each agent has a unique system prompt and processes tasks through think→act→report cycle.
    """

    def __init__(self, name, role, system_prompt, ai_client=None):
        self.name = name
        self.role = role
        self.system_prompt = system_prompt
        self.ai_client = ai_client
        self.memory = []  # Agent's working memory for current mission
        self.task_history = []

    def think(self, context):
        """
        Analyze context and plan next action.
        
        Args:
            context: Dict with target info, previous results, etc.
            
        Returns:
            Analysis string from AI or rule-based logic.
        """
        if self.ai_client and getattr(self.ai_client, "available", False):
            prompt = self._build_prompt("think", context)
            try:
                response = self.ai_client.generate(
                    prompt=prompt,
                    system=self.system_prompt,
                    model_role=self.role,
                )
                self.memory.append({"action": "think", "result": response})
                return response
            except ScanExceptions as e:
                log_warning(f"[{self.name}] AI think failed: {e}")

        # Fallback: rule-based analysis
        return self._rule_based_think(context)

    def act(self, context):
        """
        Execute an action based on context.
        
        Args:
            context: Dict with target info and think results.
            
        Returns:
            Action result dict.
        """
        if self.ai_client and getattr(self.ai_client, "available", False):
            prompt = self._build_prompt("act", context)
            try:
                response = self.ai_client.generate(
                    prompt=prompt,
                    system=self.system_prompt,
                    model_role=self.role,
                )
                result = {"action": "act", "result": response, "raw": context}
                self.memory.append(result)
                return result
            except ScanExceptions as e:
                log_warning(f"[{self.name}] AI act failed: {e}")

        return self._rule_based_act(context)

    def report(self, findings):
        """
        Generate a report from agent findings.
        
        Args:
            findings: List of finding dicts from this agent's work.
            
        Returns:
            Report string.
        """
        if self.ai_client and getattr(self.ai_client, "available", False):
            prompt = self._build_prompt("report", {"findings": findings})
            try:
                return self.ai_client.generate(
                    prompt=prompt,
                    system=self.system_prompt,
                    model_role=self.role,
                )
            except ScanExceptions:
                pass

        return self._rule_based_report(findings)

    def _build_prompt(self, action_type, context):
        """Build a role-specific prompt."""
        ctx_str = json.dumps(context, default=str, indent=2)[:2000]
        memory_str = ""
        if self.memory:
            recent = self.memory[-3:]
            memory_str = f"\n\nRecent memory:\n{json.dumps(recent, default=str)[:500]}"

        return f"[{action_type.upper()}] As {self.name} ({self.role}):\n\nContext:\n{ctx_str}{memory_str}"

    def _rule_based_think(self, context):
        return f"[{self.name}] Analyzing context with {len(context)} items"

    def _rule_based_act(self, context):
        return {"agent": self.name, "action": "rule_based", "context_size": len(context)}

    def _rule_based_report(self, findings):
        return f"[{self.name}] {len(findings)} finding(s) collected"

    def reset(self):
        """Clear agent memory for new mission."""
        self.memory = []


class ReconAgent(Agent):
    """Reconnaissance specialist — tech detection, port scan, subdomain enum."""

    SYSTEM_PROMPT = """You are a cybersecurity reconnaissance specialist agent.
Your job is to gather intelligence about the target:
- Identify technologies, frameworks, and versions
- Discover open ports and running services
- Find subdomains and related assets
- Map the attack surface

Output structured JSON with your findings.
Always be thorough but efficient. Prioritize high-value targets."""

    def __init__(self, ai_client=None):
        super().__init__(
            name="ReconAgent",
            role="exploit",
            system_prompt=self.SYSTEM_PROMPT,
            ai_client=ai_client,
        )

    def _rule_based_think(self, context):
        target = context.get("target", "unknown")
        return f"Planning reconnaissance for {target}: tech detect → port scan → subdomain enum"

    def _rule_based_act(self, context):
        """Run reconnaissance modules."""
        target = context.get("target", "")
        results = {
            "agent": self.name,
            "target": target,
            "recommended_modules": ["recon", "waf_detect", "crawler"],
            "priority_checks": [
                "Technology fingerprinting",
                "Port scanning (top 100)",
                "Subdomain enumeration",
                "WAF detection",
                "Directory discovery",
            ],
        }
        self.memory.append({"action": "recon_plan", "result": results})
        return results

    def _rule_based_report(self, findings):
        tech_count = len([f for f in findings if "tech" in str(f.get("type", "")).lower()])
        return f"Recon complete: {len(findings)} findings, {tech_count} technologies identified"


class ExploitAgent(Agent):
    """Exploitation specialist — payload crafting, WAF bypass, exploit chaining."""

    SYSTEM_PROMPT = """You are a cybersecurity exploitation specialist agent.
Your job is to find and exploit vulnerabilities:
- Craft and test payloads for web vulnerabilities (XSS, SQLi, CMDi, LFI, SSRF)
- Bypass WAF protections using advanced evasion techniques
- Chain vulnerabilities for maximum impact
- Generate proof-of-concept for each finding

Output structured JSON with exploit results.
Always include evidence and reproduction steps."""

    def __init__(self, ai_client=None):
        super().__init__(
            name="ExploitAgent",
            role="exploit",
            system_prompt=self.SYSTEM_PROMPT,
            ai_client=ai_client,
        )

    def _rule_based_think(self, context):
        vulns = context.get("vulnerabilities", [])
        tech = context.get("tech_stack", {})
        return (f"Planning exploitation: {len(vulns)} potential vulns, "
                f"tech stack: {list(tech.keys())[:5]}")

    def _rule_based_act(self, context):
        vulns = context.get("vulnerabilities", [])
        results = {
            "agent": self.name,
            "vuln_count": len(vulns),
            "recommended_exploits": [],
            "chain_opportunities": [],
        }

        for vuln in vulns:
            vtype = vuln.get("type", "").lower()
            sev = vuln.get("severity", "medium").lower()

            if sev in ("critical", "high"):
                results["recommended_exploits"].append({
                    "vuln_type": vtype,
                    "url": vuln.get("url", ""),
                    "priority": "high",
                    "techniques": self._suggest_techniques(vtype),
                })

        self.memory.append({"action": "exploit_plan", "result": results})
        return results

    def _suggest_techniques(self, vuln_type):
        """Suggest exploitation techniques by vuln type."""
        techniques = {
            "sqli": ["UNION-based extraction", "Boolean blind", "Time-based blind", "Stacked queries"],
            "xss": ["DOM manipulation", "Event handler injection", "SVG payload", "CSP bypass"],
            "cmdi": ["Pipe injection", "Command chaining", "Backtick execution", "Reverse shell"],
            "lfi": ["Path traversal", "PHP filter chain", "Log poisoning", "Proc self"],
            "ssrf": ["Cloud metadata", "Internal port scan", "Protocol smuggling"],
            "ssti": ["Template sandbox escape", "Object introspection", "RCE via template"],
        }
        for key, techs in techniques.items():
            if key in vuln_type:
                return techs
        return ["Manual analysis required"]

    def _rule_based_report(self, findings):
        crits = len([f for f in findings if f.get("severity") == "critical"])
        highs = len([f for f in findings if f.get("severity") == "high"])
        return f"Exploitation complete: {crits} critical, {highs} high severity findings"


class ReportAgent(Agent):
    """Reporting specialist — findings summary, risk assessment, remediation."""

    SYSTEM_PROMPT = """You are a cybersecurity reporting specialist agent.
Your job is to create clear, actionable reports:
- Summarize findings with business impact
- Assign risk scores and prioritize remediation
- Write executive summaries for leadership
- Provide technical details for developers

Output clear, structured reports with remediation steps."""

    def __init__(self, ai_client=None):
        super().__init__(
            name="ReportAgent",
            role="summary",
            system_prompt=self.SYSTEM_PROMPT,
            ai_client=ai_client,
        )

    def _rule_based_think(self, context):
        findings = context.get("findings", [])
        return f"Preparing report for {len(findings)} findings"

    def _rule_based_act(self, context):
        findings = context.get("findings", [])
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "medium").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "agent": self.name,
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "risk_level": self._assess_risk(severity_counts),
        }

    def _assess_risk(self, severity_counts):
        """Assess overall risk level."""
        if severity_counts.get("critical", 0) > 0:
            return "CRITICAL"
        if severity_counts.get("high", 0) > 0:
            return "HIGH"
        if severity_counts.get("medium", 0) > 0:
            return "MEDIUM"
        return "LOW"

    def _rule_based_report(self, findings):
        sev_counts = {}
        for f in findings:
            sev = f.get("severity", "medium")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        lines = [f"Security Assessment Report — {len(findings)} findings"]
        for sev, count in sorted(sev_counts.items()):
            lines.append(f"  {sev.upper()}: {count}")
        return "\n".join(lines)


class AgentOrchestrator:
    """
    Coordinates multiple agents for autonomous pentesting missions.
    
    Flow:
    1. ReconAgent scans target → tech stack, ports, attack surface
    2. ExploitAgent tests vulnerabilities → findings with PoC
    3. ReportAgent summarizes → executive + technical report
    """

    def __init__(self, ai_client=None):
        self.ai_client = ai_client
        self.recon = ReconAgent(ai_client=ai_client)
        self.exploit = ExploitAgent(ai_client=ai_client)
        self.reporter = ReportAgent(ai_client=ai_client)
        self.agents = [self.recon, self.exploit, self.reporter]

    def run_mission(self, target, scope=None):
        """
        Run a full pentesting mission on a target.
        
        Args:
            target: Target URL or hostname.
            scope: Optional scope restrictions.
            
        Returns:
            MissionReport with all findings.
        """
        mission = MissionReport(
            target=target,
            start_time=datetime.now().isoformat(),
            agents_used=[a.name for a in self.agents],
        )

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 55}")
        print(f"  🤖 Multi-Agent Pentesting Mission")
        print(f"{'═' * 55}{Colors.END}")
        print(f"  Target: {target}")
        print(f"  Agents: {', '.join(a.name for a in self.agents)}")
        print()

        context = {"target": target, "scope": scope or {}}

        # Phase 1: Reconnaissance
        log_info(f"[Phase 1] {self.recon.name} — Reconnaissance")
        recon_think = self.recon.think(context)
        log_info(f"  Think: {recon_think[:100]}")
        recon_result = self.recon.act(context)
        mission.tasks.append(AgentTask(
            id="recon_1", description="Reconnaissance scan",
            agent_role="recon", status="completed", result=recon_result
        ))

        # Phase 2: Exploitation Planning
        context["recon_results"] = recon_result
        context["vulnerabilities"] = context.get("vulnerabilities", [])

        log_info(f"[Phase 2] {self.exploit.name} — Exploitation Planning")
        exploit_think = self.exploit.think(context)
        log_info(f"  Think: {exploit_think[:100]}")
        exploit_result = self.exploit.act(context)
        mission.tasks.append(AgentTask(
            id="exploit_1", description="Vulnerability exploitation",
            agent_role="exploit", status="completed", result=exploit_result
        ))

        # Phase 3: Reporting
        context["exploit_results"] = exploit_result
        context["findings"] = mission.findings

        log_info(f"[Phase 3] {self.reporter.name} — Report Generation")
        report_result = self.reporter.act(context)
        report_text = self.reporter.report(mission.findings)
        mission.summary = report_text
        mission.tasks.append(AgentTask(
            id="report_1", description="Report generation",
            agent_role="report", status="completed", result=report_result
        ))

        # Finalize
        mission.end_time = datetime.now().isoformat()
        mission.status = "completed"

        log_success(f"Mission completed: {len(mission.findings)} finding(s)")
        self._print_mission_summary(mission)

        # Reset agent memories
        for agent in self.agents:
            agent.reset()

        return mission

    def delegate(self, task_description, agent):
        """
        Delegate a specific task to a specific agent.
        
        Args:
            task_description: What the agent should do.
            agent: Agent instance.
            
        Returns:
            Agent result dict.
        """
        log_info(f"Delegating to {agent.name}: {task_description[:60]}")
        context = {"task": task_description}
        result = agent.act(context)
        return result

    def _print_mission_summary(self, mission):
        """Print formatted mission summary."""
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'─' * 55}")
        print(f"  ✅ Mission Complete")
        print(f"{'─' * 55}{Colors.END}")
        print(f"  Target:   {mission.target}")
        print(f"  Duration: {mission.start_time[:19]} → {mission.end_time[:19]}")
        print(f"  Tasks:    {len(mission.tasks)}")
        print(f"  Findings: {len(mission.findings)}")
        print(f"  Status:   {mission.status}")
        if mission.summary:
            print(f"\n  Summary:\n  {mission.summary[:200]}")
        print()
