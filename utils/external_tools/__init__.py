"""Unified adapters for battle-tested external pentest CLIs.

Each tool subclasses :class:`~utils.external_tools.base.ExternalTool`, giving
the scanner one contract for availability checks, command building, timed
execution, and structured output parsing — instead of bespoke shell-outs
scattered across modules.
"""

from utils.external_tools.arjun import ArjunTool
from utils.external_tools.base import ExternalTool, ToolResult
from utils.external_tools.cloudhunter import CloudHunterTool
from utils.external_tools.garak import GarakTool
from utils.external_tools.gitleaks import GitleaksTool
from utils.external_tools.gowitness import GowitnessTool
from utils.external_tools.kube_hunter import KubeHunterTool
from utils.external_tools.masscan import MasscanTool
from utils.external_tools.smbmap import SmbmapTool
from utils.external_tools.sslyze import SslyzeTool
from utils.external_tools.testssl import TestsslTool
from utils.external_tools.wpscan import WpscanTool

__all__ = [
    "ExternalTool",
    "ToolResult",
    "MasscanTool",
    "ArjunTool",
    "SslyzeTool",
    "TestsslTool",
    "WpscanTool",
    "SmbmapTool",
    "KubeHunterTool",
    "GowitnessTool",
    "GitleaksTool",
    "CloudHunterTool",
    "GarakTool",
]
