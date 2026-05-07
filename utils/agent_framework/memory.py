"""Agent memory — persistent context across iterations + intelligence fetch."""

from __future__ import annotations

import time


class AgentMemory:
    """Persistent context across agent iterations with intelligence integration."""

    def __init__(self, target: str):
        self.target = target
        self.iterations = []
        self.modules_run = set()
        self.all_findings = []
        self.tech_stack = []
        self.discovered_endpoints = []
        self.waf_detected = None
        self.recon_data = {}
        # Intelligence integration (0-Day Machine knowledge loop)
        self.intel_report = None
        self.target_profile = None
        self.scan_recommendation = None
        self._load_intelligence(target)

    def _load_intelligence(self, target: str):
        """Load past intelligence for this target from the knowledge loop."""
        try:
            from utils.scan_intelligence import get_scan_intelligence
            from utils.target_profiler import TargetProfiler

            intel = get_scan_intelligence()
            self.intel_report = intel.query_intelligence(target)
            profiler = TargetProfiler()
            self.target_profile = profiler.build_profile(target)
            self.scan_recommendation = profiler.get_scan_recommendation(
                target,
                tech_stack=self.target_profile.tech_stack,
                waf_name=self.target_profile.waf_name,
                defences=self.target_profile.defences,
                past_findings=self.target_profile.total_findings,
                past_scans=self.target_profile.total_scans,
            )
            if self.intel_report and self.intel_report.past_scans > 0:
                from utils.colors import log_info
                log_info(
                    f"🧠 Intelligence loaded: {self.intel_report.past_scans} past scans, "
                    f"priority {self.scan_recommendation.priority_score:.0f}/100"
                )
        except Exception:
            pass

    def add_iteration(self, plan: dict, results: dict, summary: str):
        self.iterations.append({
            "plan": plan,
            "results": results,
            "summary": summary,
            "timestamp": time.time(),
        })

    def add_findings(self, findings: list):
        self.all_findings.extend(findings)

    def get_context_window(self, max_chars: int = 3000) -> str:
        """Build context for the planner from memory, enriched with intelligence."""
        ctx = [f"Target: {self.target}"]

        if self.scan_recommendation:
            ctx.append(f"Priority Score: {self.scan_recommendation.priority_score:.0f}/100")
        if self.intel_report and self.intel_report.past_scans > 0:
            ctx.append(f"Past Scans: {self.intel_report.past_scans}")
            if self.intel_report.known_defences:
                defs = ", ".join(f"{d.defence_type}({d.detail})" for d in self.intel_report.known_defences[:3])
                ctx.append(f"Known Defences: {defs}")
            if self.intel_report.modules_to_skip:
                ctx.append(f"Skip (no results before): {', '.join(self.intel_report.modules_to_skip[:5])}")
            if self.intel_report.modules_to_prioritize:
                ctx.append(f"Prioritize (found vulns before): {', '.join(self.intel_report.modules_to_prioritize[:5])}")

        if self.tech_stack:
            techs = ", ".join(
                t.get("name", "?") for t in self.tech_stack[:10]
                if isinstance(t, dict)
            )
            ctx.append(f"Tech Stack: {techs}")

        if self.waf_detected:
            ctx.append(f"WAF Detected: {self.waf_detected}")

        ctx.append(f"Modules already run: {', '.join(sorted(self.modules_run)) or 'none'}")
        ctx.append(f"Total findings: {len(self.all_findings)}")

        important = [
            f for f in self.all_findings
            if f.get("severity", "").lower() in ("critical", "high")
        ]
        if important:
            ctx.append("Critical/High findings:")
            for f in important[:5]:
                ctx.append(
                    f"  - {f.get('type', '?')}: {f.get('url', '?')} "
                    f"[{f.get('severity', '?')}]"
                )

        if self.iterations:
            ctx.append(f"\nLast iteration:\n{self.iterations[-1]['summary'][:500]}")

        return "\n".join(ctx)[:max_chars]
