"""Multi-Agent Framework — Cairn-inspired autonomous pentesting harness.

Replaces the former 1019-LOC ``utils/agent_framework.py`` with seven
cohesive sub-modules. Public surface preserved verbatim.

Sub-modules:
  - _constants    → APTS / anti-shallow / WAF-bypass constants
  - _prompts      → planner + summarizer system prompts
  - types         → APTS autonomy levels, AgentTask, MissionReport
  - memory        → AgentMemory (persistent context per target)
  - dispatcher    → MODULE_MAP + execute_module
  - depth         → ModuleDepth, DepthTracker (anti-shallow)
  - orchestrator  → AgentOrchestrator (planner-executor-summarizer)
"""

from ._constants import (
    BROWSER_REQUIRED_MODULES,
    CHAIN_LINK_TIMEOUT,
    EXHAUSTION_REQUIREMENTS,
    MAX_FAILED_CANDIDATES_PER_DEPTH,
    MIN_PROBES_PER_CLASS,
    WAF_BYPASS_LEVELS,
    WAF_SENSITIVE_MODULES,
)
from ._prompts import PLANNER_SYSTEM, SUMMARIZER_SYSTEM
from .depth import DepthTracker, ModuleDepth
from .dispatcher import MODULE_MAP, execute_module
from .memory import AgentMemory
from .orchestrator import AgentOrchestrator
from .types import (
    AUTONOMY_LEVEL,
    AgentTask,
    AutonomyLevel,
    MissionReport,
    requires_approval,
)

__all__ = [
    # types
    "AutonomyLevel",
    "AUTONOMY_LEVEL",
    "requires_approval",
    "AgentTask",
    "MissionReport",
    # memory
    "AgentMemory",
    # depth
    "ModuleDepth",
    "DepthTracker",
    # dispatcher
    "MODULE_MAP",
    "execute_module",
    # orchestrator
    "AgentOrchestrator",
    # constants
    "MIN_PROBES_PER_CLASS",
    "EXHAUSTION_REQUIREMENTS",
    "WAF_BYPASS_LEVELS",
    "BROWSER_REQUIRED_MODULES",
    "WAF_SENSITIVE_MODULES",
    "MAX_FAILED_CANDIDATES_PER_DEPTH",
    "CHAIN_LINK_TIMEOUT",
    # prompts
    "PLANNER_SYSTEM",
    "SUMMARIZER_SYSTEM",
]
