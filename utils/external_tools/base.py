"""Base adapter for external penetration-testing CLI tools.

Mirrors the project's existing functional wrappers (``recon_tools``,
``nuclei_runner``) but unifies them behind one class contract so new tools are
added by implementing just two methods: ``get_command`` and ``parse_output``.
``run`` handles availability, timeout, and error capture uniformly — a failing
tool never raises, it returns a diagnostic :class:`ToolResult`.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

_DEFAULT_TIMEOUT = 300.0  # seconds for a single tool invocation


@dataclass
class ToolResult:
    """One tool invocation's structured output plus diagnostics."""

    tool: str
    available: bool = True
    returncode: int | None = None
    parsed: Any = None
    raw_stdout: str = ""
    raw_stderr: str = ""
    error: str = ""
    duration_seconds: float = 0.0

    @property
    def succeeded(self) -> bool:
        """True only when the tool ran, exited 0, and parsing succeeded."""
        return self.available and not self.error and self.returncode == 0


class ExternalTool(ABC):
    """Adapter contract for a single external CLI tool.

    Subclasses set ``binary`` and implement ``get_command`` / ``parse_output``.
    """

    binary: str = ""
    default_timeout: float = _DEFAULT_TIMEOUT

    @abstractmethod
    def get_command(self, target: str, **kwargs) -> list[str]:
        """Build the argv list to execute against ``target``."""

    @abstractmethod
    def parse_output(self, stdout: str, stderr: str, returncode: int) -> Any:
        """Turn raw tool output into structured data."""

    def to_findings(self, parsed: Any, *, target: str = "") -> list[dict]:
        """Map parsed output into scanner finding dicts.

        Default is empty — tools that only contribute reconnaissance data (open
        ports, parameters) override this only if they surface vuln-style issues.
        """
        return []

    def is_available(self) -> bool:
        return bool(self.binary) and shutil.which(self.binary) is not None

    def run(self, target: str, *, timeout: float | None = None, **kwargs) -> ToolResult:
        """Execute the tool, returning a diagnostic ``ToolResult`` — never raises."""
        if not self.is_available():
            return ToolResult(
                tool=self.binary,
                available=False,
                error=f"{self.binary} not found in PATH",
            )

        cmd = self.get_command(target, **kwargs)
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout if timeout is not None else self.default_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=self.binary, error="timeout",
                duration_seconds=round(time.monotonic() - t0, 3),
            )
        except OSError as exc:
            return ToolResult(
                tool=self.binary, error=f"OSError: {exc}",
                duration_seconds=round(time.monotonic() - t0, 3),
            )

        parsed: Any = None
        parse_error = ""
        try:
            parsed = self.parse_output(proc.stdout, proc.stderr, proc.returncode)
        except Exception as exc:  # noqa: BLE001 — parsing must never crash the run
            parse_error = f"parse failed: {type(exc).__name__}: {exc}"

        return ToolResult(
            tool=self.binary,
            returncode=proc.returncode,
            parsed=parsed,
            raw_stdout=proc.stdout,
            raw_stderr=proc.stderr,
            error=parse_error,
            duration_seconds=round(time.monotonic() - t0, 3),
        )
