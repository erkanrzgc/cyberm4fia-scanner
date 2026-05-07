"""Public types: APTS autonomy levels, task & mission dataclasses."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Optional


class AutonomyLevel(IntEnum):
    """APTS Graduated Autonomy Levels (L1-L4)."""
    L1_ASSISTED = 1       # AI suggests, human approves every action
    L2_SEMI_AUTO = 2      # AI auto-scans, human approves exploitation
    L3_SUPERVISED = 3     # AI exploits within scope, human monitors
    L4_AUTONOMOUS = 4     # Full autonomy — strictest safety requirements

    @classmethod
    def from_string(cls, s):
        mapping = {
            "l1": cls.L1_ASSISTED, "assisted": cls.L1_ASSISTED,
            "l2": cls.L2_SEMI_AUTO, "semi": cls.L2_SEMI_AUTO, "semi-autonomous": cls.L2_SEMI_AUTO,
            "l3": cls.L3_SUPERVISED, "supervised": cls.L3_SUPERVISED,
            "l4": cls.L4_AUTONOMOUS, "autonomous": cls.L4_AUTONOMOUS, "full": cls.L4_AUTONOMOUS,
        }
        return mapping.get(s.lower(), cls.L3_SUPERVISED)


AUTONOMY_LEVEL = AutonomyLevel.L3_SUPERVISED  # Default


def requires_approval(action_type: str) -> bool:
    """Check if an action requires human approval at the current autonomy level."""
    if AUTONOMY_LEVEL <= AutonomyLevel.L1_ASSISTED:
        return True
    if AUTONOMY_LEVEL <= AutonomyLevel.L2_SEMI_AUTO:
        return action_type in ("exploit", "shell", "exfil", "destructive", "write")
    if AUTONOMY_LEVEL <= AutonomyLevel.L3_SUPERVISED:
        return action_type in ("destructive", "scope_exit")
    return False  # L4 full autonomy


@dataclass
class AgentTask:
    """A task assigned to an agent."""
    id: str
    description: str
    agent_role: str
    status: str = "pending"
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
