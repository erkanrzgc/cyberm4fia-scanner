"""AI-driven Planner-Executor-Summarizer orchestrator (Cairn-inspired)."""

from __future__ import annotations

import signal
import time
from datetime import datetime

from utils.colors import Colors, log_info, log_success, log_warning
from utils.scan_intelligence import get_scan_intelligence

from ._prompts import PLANNER_SYSTEM, SUMMARIZER_SYSTEM
from .depth import DepthTracker
from .dispatcher import execute_module
from .memory import AgentMemory
from .types import AgentTask, MissionReport


class AgentOrchestrator:
    """
    AI-driven pentesting orchestrator with Planner-Executor-Summarizer loop.

    Flow (per iteration):
    1. PLANNER (AI) → analyzes context, decides which modules to run
    2. EXECUTOR → runs the chosen modules
    3. SUMMARIZER (AI) → summarizes results, feeds back to planner
    4. Repeat until AI says "done" or max iterations reached
    """

    MAX_ITERATIONS = 5
    MAX_TIME = 600  # 10 minutes

    def __init__(self, ai_client=None):
        if ai_client is None:
            try:
                from utils.ai import get_ai, get_dual_ai, init_ai
                dual = get_dual_ai()
                if dual and dual.available:
                    ai_client = dual
                else:
                    ai = get_ai()
                    if ai.available:
                        ai_client = ai
                    else:
                        ai_client = init_ai()
            except Exception:
                pass

        self.ai_client = ai_client
        self.interrupted = False
        self.depth_tracker = DepthTracker()

    def _get_ai_client(self, role="exploit"):
        """Get the best AI client for a role."""
        if self.ai_client is None:
            return None
        if hasattr(self.ai_client, "get_client_for_role"):
            return self.ai_client.get_client_for_role(role)
        if getattr(self.ai_client, "available", False):
            return self.ai_client
        return None

    def _handle_interrupt(self, signum, frame):
        print(f"\n{Colors.YELLOW}⚠ Agent interrupted. Finishing current iteration...{Colors.END}")
        self.interrupted = True

    def _ai_plan(self, memory):
        """Ask AI to decide the next scan step."""
        client = self._get_ai_client("exploit")
        if not client or not getattr(client, "available", False):
            return self._fallback_plan(memory)

        from utils.ai import _extract_json
        context = memory.get_context_window()

        prompt = f"""Current scan state:

{context}

Based on this data, what should I scan next? Pick the most effective modules (max 3).
If we have enough data, set "done": true.

Respond with JSON only."""

        try:
            response = client.generate(
                prompt, system=PLANNER_SYSTEM,
                temperature=0.3, model_role="exploit",
            )
            result = _extract_json(response)
            if result and isinstance(result, dict) and result.get("modules"):
                return result
        except Exception as e:
            log_warning(f"  Planner AI error: {e}")

        return self._fallback_plan(memory)

    def _fallback_plan(self, memory):
        """Deterministic fallback when AI is unavailable."""
        if not memory.modules_run:
            return {
                "reasoning": "Starting with reconnaissance (fallback mode)",
                "modules": ["recon", "tech_detect", "header_audit"],
                "priority": "high",
                "done": False,
            }

        # Phase 2: Core vulnerability scanning
        core_vulns = {"xss", "sqli", "lfi", "cmdi", "ssrf", "ssti"}
        remaining = core_vulns - memory.modules_run
        if remaining:
            mods = list(remaining)[:3]
            return {
                "reasoning": f"Running core vuln scanners: {', '.join(mods)}",
                "modules": mods,
                "priority": "high",
                "done": False,
            }

        # Phase 3: Advanced testing
        advanced = {"xxe", "csrf", "cors", "jwt", "smuggling", "deserialization"}
        remaining = advanced - memory.modules_run
        if remaining:
            mods = list(remaining)[:3]
            return {
                "reasoning": f"Running advanced scanners: {', '.join(mods)}",
                "modules": mods,
                "priority": "medium",
                "done": False,
            }

        return {"reasoning": "All key modules completed", "modules": [], "done": True}

    def _ai_summarize(self, results, memory):
        """Ask AI to summarize scan results."""
        client = self._get_ai_client("analysis")
        if not client or not getattr(client, "available", False):
            return self._fallback_summarize(results, memory)

        result_text = []
        for mod_id, data in results.items():
            if isinstance(data, list):
                severities = {}
                for d in data:
                    if isinstance(d, dict):
                        sev = d.get("severity", "info")
                        severities[sev] = severities.get(sev, 0) + 1
                sev_str = ", ".join(f"{k}:{v}" for k, v in severities.items())
                result_text.append(f"- {mod_id}: {len(data)} findings ({sev_str or 'raw'})")
            elif isinstance(data, dict):
                if "error" in data:
                    result_text.append(f"- {mod_id}: ERROR - {data['error']}")
                else:
                    result_text.append(f"- {mod_id}: completed")
            else:
                result_text.append(f"- {mod_id}: {str(data)[:80]}")

        prompt = f"""Summarize these scan results for {memory.target}:

{chr(10).join(result_text)}

Total findings: {len(memory.all_findings)}
Modules run: {', '.join(sorted(memory.modules_run))}

Give a tactical summary for planning the next scan step."""

        try:
            response = client.generate(
                prompt, system=SUMMARIZER_SYSTEM,
                temperature=0.2, model_role="analysis",
            )
            if response:
                return response
        except Exception:
            pass

        return self._fallback_summarize(results, memory)

    def _fallback_summarize(self, results, memory):
        """Simple rule-based summary when AI is unavailable."""
        lines = [f"Scan update for {memory.target}:"]
        for mod_id, data in results.items():
            if isinstance(data, list):
                lines.append(f"  {mod_id}: {len(data)} results")
            elif isinstance(data, dict) and "error" in data:
                lines.append(f"  {mod_id}: failed")
            else:
                lines.append(f"  {mod_id}: completed")
        lines.append(f"Total findings: {len(memory.all_findings)}")
        return "\n".join(lines)

    def run_mission(self, target, scope=None):
        """Run the AI-driven pentesting loop."""
        start_time = time.time()
        memory = AgentMemory(target)
        memory._orchestrator_depth = self.depth_tracker
        old_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self._handle_interrupt)

        mission = MissionReport(
            target=target,
            start_time=datetime.now().isoformat(),
            agents_used=["Planner", "Executor", "Summarizer"],
        )

        # ── Banner ──
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 58}")
        print("  🤖 AGENT MODE — AI-Driven Penetration Test")
        print(f"  Target: {target}")
        print(f"  Max iterations: {self.MAX_ITERATIONS} | Timeout: {self.MAX_TIME}s")
        print(f"{'═' * 58}{Colors.END}\n")

        ai_available = bool(self._get_ai_client("exploit"))
        if not ai_available:
            log_warning("AI not available — running in deterministic fallback mode")
            log_info("For AI-driven mode: export NVIDIA_API_KEY=your_key")

        for iteration in range(1, self.MAX_ITERATIONS + 1):
            elapsed = time.time() - start_time
            if elapsed > self.MAX_TIME:
                log_warning(f"Time limit reached ({self.MAX_TIME}s)")
                break

            if self.interrupted:
                break

            print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'─' * 58}")
            print(f"  Iteration {iteration}/{self.MAX_ITERATIONS}")
            print(f"{'─' * 58}{Colors.END}")

            print(f"{Colors.DIM}  Ctrl+C to stop after this iteration{Colors.END}")
            try:
                time.sleep(1.5)
            except KeyboardInterrupt:
                self.interrupted = True
                break

            # ── PLAN ──
            icon = "🧠" if ai_available else "📋"
            print(f"\n  {Colors.CYAN}{icon} PLANNER:{Colors.END}", end=" ")
            plan = self._ai_plan(memory)

            reasoning = plan.get("reasoning", "")
            modules = plan.get("modules", [])[:3]
            done = plan.get("done", False)
            priority = plan.get("priority", "medium")

            print(reasoning)
            if modules:
                print(f"  {Colors.BOLD}→ {', '.join(modules)} [{priority}]{Colors.END}")

            # Record decision for Auditability (APTS)
            get_scan_intelligence().record_ai_decision(
                target=target,
                module=",".join(modules),
                reasoning=reasoning,
                action=f"Priority: {priority}, Done: {done}"
            )

            if done or not modules:
                log_success("AI determined scan is complete ✓")
                break

            # ── EXECUTE ──
            print(f"\n  {Colors.YELLOW}⚡ EXECUTOR:{Colors.END}")
            results = {}
            for mod_id in modules:
                result = execute_module(mod_id, target, memory, delay=0)
                if result is not None:
                    results[mod_id] = result

            mission.tasks.append(AgentTask(
                id=f"iter_{iteration}",
                description=f"Ran: {', '.join(modules)}",
                agent_role="executor",
                status="completed",
                result={"modules": modules, "finding_count": len(memory.all_findings)},
            ))

            # ── ESCALATE (Chain Engine) ──
            new_high = [
                f for f in memory.all_findings
                if isinstance(f, dict)
                and f.get("severity", "").lower() in ("critical", "high")
                and not f.get("proven")
            ]
            if new_high:
                try:
                    from utils.vuln_chain import run_escalations
                    print(f"\n  {Colors.RED}🔗 CHAIN ENGINE:{Colors.END}")
                    proven = run_escalations(new_high)
                    if proven:
                        memory.add_findings(proven)
                        mission.findings.extend(proven)
                except Exception as e:
                    log_warning(f"  Chain engine error: {e}")

            # ── SUMMARIZE ──
            icon = "📝" if ai_available else "📊"
            print(f"\n  {Colors.GREEN}{icon} SUMMARIZER:{Colors.END}")
            summary = self._ai_summarize(results, memory)
            for line in summary.split("\n")[:6]:
                if line.strip():
                    print(f"  {line.strip()}")

            memory.add_iteration(plan, results, summary)

        # ── Restore signal handler ──
        signal.signal(signal.SIGINT, old_handler)
        self.interrupted = False

        # ── Final Report ──
        total_time = time.time() - start_time
        mission.findings = memory.all_findings
        mission.end_time = datetime.now().isoformat()
        mission.status = "completed"

        # Generate final AI summary if available
        client = self._get_ai_client("summary")
        if client and getattr(client, "available", False) and memory.all_findings:
            try:
                from utils.ai import generate_scan_summary
                stats = {"requests": 0, "waf": 0}
                final_summary = generate_scan_summary(
                    client, memory.all_findings, target, stats
                )
                if final_summary:
                    mission.summary = final_summary
            except Exception:
                pass

        if not mission.summary:
            mission.summary = (
                f"Agent scan of {target}: {len(memory.all_findings)} findings "
                f"in {len(memory.iterations)} iterations ({total_time:.0f}s)"
            )

        self._print_final_report(mission, memory, total_time)
        return mission

    def _print_final_report(self, mission, memory, total_time):
        """Print formatted final report."""
        findings = memory.all_findings
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'═' * 58}")
        print("  ✅ AGENT MISSION COMPLETE")
        print(f"{'═' * 58}{Colors.END}")
        print(f"  Target:     {mission.target}")
        print(f"  Iterations: {len(memory.iterations)}")
        print(f"  Modules:    {', '.join(sorted(memory.modules_run))}")
        print(f"  Time:       {total_time:.1f}s")
        print(f"  Findings:   {len(findings)}")

        if severity_counts:
            sev_str = "  Severity:   "
            parts = []
            for sev in ("critical", "high", "medium", "low", "info"):
                count = severity_counts.get(sev, 0)
                if count:
                    color = {
                        "critical": Colors.RED, "high": Colors.RED,
                        "medium": Colors.YELLOW, "low": Colors.CYAN,
                        "info": Colors.DIM,
                    }.get(sev, "")
                    parts.append(f"{color}{sev}: {count}{Colors.END}")
            print(sev_str + " | ".join(parts))

        if mission.summary:
            print(f"\n  {Colors.BOLD}Executive Summary:{Colors.END}")
            for line in mission.summary.split("\n")[:5]:
                if line.strip():
                    print(f"  {line.strip()}")

        print()
