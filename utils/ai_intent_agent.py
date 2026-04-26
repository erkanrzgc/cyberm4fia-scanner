"""
cyberm4fia-scanner — Intent-Driven AI Agent (with Self-Healing Loop)

Inspired by the autonomous-agent direction in oritera/Cairn:
the LLM does not just pick payloads from a fixed set, it writes
an actual Python exploit script which is then run inside a
subprocess sandbox. If the script errors out or fails to confirm
the vulnerability, the traceback / output is fed back to the LLM
for repair, and the loop runs again.

Flow per attempt
----------------
    1. Build prompt from `Intent` (goal + target + constraints).
    2. LLM emits a Python script (must set `result = {...}`).
    3. Sandbox runs it (timeout + memory + import whitelist).
    4. If `result["confirmed"]` → success, return.
    5. Else feed stdout/stderr/traceback back as a repair prompt
       and try again until `max_iterations`.

Threat model: see ``utils.code_executor`` — best-effort isolation,
not a hard security boundary. Only run against in-scope targets.
"""

from __future__ import annotations

import json
import re
import textwrap
from dataclasses import dataclass, field
from typing import Optional

from utils.code_executor import (
    DEFAULT_ALLOWED_MODULES,
    ExecutionResult,
    execute_python,
)
from utils.colors import log_info, log_success, log_warning


# ─── Data classes ────────────────────────────────────────────────────────────


@dataclass
class Intent:
    """High-level description of what the agent should accomplish."""
    goal: str                                       # e.g. "Confirm reflected XSS in `q` parameter"
    target_url: str
    param: str = ""
    vuln_type: str = ""                             # XSS, SQLi, LFI, SSRF, CMDi, ...
    http_method: str = "GET"
    notes: str = ""                                 # any extra context (WAF, tech stack, ...)
    constraints: list[str] = field(default_factory=list)
    extra_modules: list[str] = field(default_factory=list)


@dataclass
class IntentAttempt:
    """One round of (LLM → sandbox) inside the self-healing loop."""
    iteration: int
    code: str
    execution: ExecutionResult
    confirmed: bool
    confidence: float
    evidence: str
    fail_reason: str = ""


@dataclass
class IntentOutcome:
    """Final outcome returned by `IntentAgent.run`."""
    success: bool
    intent: Intent
    attempts: list[IntentAttempt] = field(default_factory=list)
    final_code: str = ""
    confidence: float = 0.0
    evidence: str = ""
    summary: str = ""

    @property
    def iterations_used(self) -> int:
        return len(self.attempts)


# ─── Prompts ─────────────────────────────────────────────────────────────────


_SYSTEM_PROMPT = textwrap.dedent("""
    You are an offensive-security engineer writing AUTONOMOUS Python exploit
    scripts. Each script is run inside a sandbox. You MUST follow this contract:

    1. Output a SINGLE fenced ```python block. No prose outside the block.
    2. The script must be self-contained. Allowed top-level imports include:
       requests, httpx, urllib, json, re, base64, hashlib, time. Anything else
       will fail at import time.
    3. Set a top-level variable `result` to a JSON-serialisable dict shaped as:
           {
             "confirmed": bool,        # True only if you have hard evidence
             "confidence": int,        # 0..100
             "evidence": str,          # short snippet proving exploitation
             "payload": str,           # the payload that worked (if any)
             "notes": str              # short reasoning (≤ 200 chars)
           }
    4. NEVER mutate the local filesystem outside /tmp. NEVER spawn subprocesses.
    5. Be conservative — only set `confirmed=True` when the response truly
       proves the vulnerability (reflected payload in a dangerous context,
       SQL error, file contents, etc.). False positives are worse than misses.
    6. If you cannot prove it, set confirmed=False and explain in `notes` what
       you would try next round.
""").strip()


_REPAIR_PROMPT_TPL = textwrap.dedent("""
    Your previous script did NOT confirm the vulnerability.

    What went wrong:
    {fail_reason}

    Sandbox stdout (last 1k chars):
    {stdout}

    Sandbox stderr (last 500 chars):
    {stderr}

    Traceback (if any):
    {traceback}

    Previous `result` value (if any): {prev_result}

    Write a NEW script that fixes the issue. Do NOT repeat the same approach.
    Vary the payload, encoding, headers, or detection logic. Same output
    contract as before (single fenced python block, sets `result` dict).
""").strip()


# ─── Agent ───────────────────────────────────────────────────────────────────


class IntentAgent:
    """LLM writes exploit code, sandbox runs it, errors loop back as repairs."""

    DEFAULT_MAX_ITERATIONS = 3
    DEFAULT_TIMEOUT_S = 15

    def __init__(
        self,
        ai_client,
        *,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        sandbox_timeout: float = DEFAULT_TIMEOUT_S,
        sandbox_memory_mb: int = 256,
    ):
        self.client = ai_client
        self.max_iterations = max_iterations
        self.sandbox_timeout = sandbox_timeout
        self.sandbox_memory_mb = sandbox_memory_mb

    @property
    def available(self) -> bool:
        return bool(self.client) and getattr(self.client, "available", False)

    # ─── Entry point ─────────────────────────────────────────────────────

    def run(self, intent: Intent) -> IntentOutcome:
        outcome = IntentOutcome(success=False, intent=intent)

        if not self.available:
            outcome.summary = "AI client not available; intent agent skipped"
            return outcome

        log_info(
            f"🧠 Intent Agent: {intent.vuln_type or 'generic'} "
            f"goal={intent.goal[:80]} target={intent.target_url[:60]}"
        )

        last_attempt: Optional[IntentAttempt] = None
        for i in range(1, self.max_iterations + 1):
            code = self._ask_llm_for_code(intent, i, last_attempt)
            if not code:
                log_warning(f"  Intent Gen-{i}: empty / unparseable LLM response")
                continue

            execution = self._run_in_sandbox(code, intent)
            confirmed, confidence, evidence, fail = self._interpret(execution)

            attempt = IntentAttempt(
                iteration=i,
                code=code,
                execution=execution,
                confirmed=confirmed,
                confidence=confidence,
                evidence=evidence,
                fail_reason=fail,
            )
            outcome.attempts.append(attempt)
            last_attempt = attempt

            if confirmed:
                log_success(
                    f"  ✅ Intent CONFIRMED at gen-{i} "
                    f"(confidence={confidence:.0f}%)"
                )
                outcome.success = True
                outcome.final_code = code
                outcome.confidence = confidence
                outcome.evidence = evidence
                outcome.summary = f"confirmed at iteration {i}"
                return outcome

            log_warning(
                f"  ✗ Intent Gen-{i} not confirmed ({fail or 'no positive signal'})"
            )

        outcome.summary = (
            f"no confirmed exploit after {self.max_iterations} iterations"
        )
        return outcome

    # ─── LLM step ────────────────────────────────────────────────────────

    def _ask_llm_for_code(
        self,
        intent: Intent,
        iteration: int,
        last_attempt: Optional[IntentAttempt],
    ) -> str:
        if last_attempt is None:
            user_prompt = self._initial_prompt(intent)
        else:
            user_prompt = self._repair_prompt(intent, last_attempt)

        # Higher creativity on retries (within reason).
        temperature = min(0.2 + 0.2 * (iteration - 1), 0.7)

        response = self.client.generate(
            user_prompt,
            system=_SYSTEM_PROMPT,
            temperature=temperature,
        )
        return _extract_python_block(response or "")

    def _initial_prompt(self, intent: Intent) -> str:
        constraints = (
            "\n".join(f"- {c}" for c in intent.constraints)
            if intent.constraints
            else "- (none)"
        )
        return textwrap.dedent(f"""
            INTENT
            ------
            Goal:        {intent.goal}
            Vuln type:   {intent.vuln_type or 'generic'}
            Target URL:  {intent.target_url}
            Parameter:   {intent.param or '(none)'}
            HTTP method: {intent.http_method}
            Notes:       {intent.notes or '(none)'}

            Constraints:
            {constraints}

            Write the FIRST attempt: a single fenced ```python block. Set the
            top-level `result` dict per the system prompt contract.
        """).strip()

    def _repair_prompt(self, intent: Intent, last: IntentAttempt) -> str:
        ex = last.execution
        prev_result = ""
        try:
            prev_result = json.dumps(ex.return_value)[:400]
        except (TypeError, ValueError):
            prev_result = repr(ex.return_value)[:400]

        return _REPAIR_PROMPT_TPL.format(
            fail_reason=last.fail_reason or "no positive signal",
            stdout=(ex.stdout or "")[-1000:],
            stderr=(ex.stderr or "")[-500:],
            traceback=(ex.traceback or "")[-800:],
            prev_result=prev_result or "(none)",
        )

    # ─── Sandbox step ────────────────────────────────────────────────────

    def _run_in_sandbox(self, code: str, intent: Intent) -> ExecutionResult:
        extra = set(intent.extra_modules) if intent.extra_modules else set()
        return execute_python(
            code,
            timeout=self.sandbox_timeout,
            max_memory_mb=self.sandbox_memory_mb,
            allowed_modules=DEFAULT_ALLOWED_MODULES,
            extra_modules=extra,
        )

    # ─── Interpret sandbox result ────────────────────────────────────────

    @staticmethod
    def _interpret(ex: ExecutionResult) -> tuple[bool, float, str, str]:
        """Return (confirmed, confidence, evidence, fail_reason)."""
        if ex.killed_by_timeout:
            return False, 0.0, "", "sandbox timeout"
        if ex.exception_type:
            return (
                False,
                0.0,
                "",
                f"runtime error: {ex.exception_type}: {ex.exception_message}",
            )
        if ex.exit_code != 0:
            return False, 0.0, "", f"non-zero exit {ex.exit_code}"

        rv = ex.return_value
        if not isinstance(rv, dict):
            return False, 0.0, "", "script did not set `result` dict"

        confirmed = bool(rv.get("confirmed"))
        try:
            confidence = float(rv.get("confidence") or 0)
        except (TypeError, ValueError):
            confidence = 0.0
        evidence = str(rv.get("evidence") or "")[:500]

        if confirmed and confidence >= 60:
            return True, confidence, evidence, ""
        if confirmed and confidence < 60:
            return False, confidence, evidence, f"confidence {confidence:.0f} below 60"
        return False, confidence, evidence, str(rv.get("notes") or "")[:200]


# ─── Module-level helpers ────────────────────────────────────────────────────


_PY_BLOCK_RE = re.compile(r"```(?:python)?\s*\n?(.*?)```", re.DOTALL | re.IGNORECASE)


def _extract_python_block(text: str) -> str:
    """Pull the first ```python ... ``` block out of an LLM response."""
    if not text:
        return ""
    m = _PY_BLOCK_RE.search(text)
    if m:
        return m.group(1).strip()
    # Fallback: if the whole text already looks like Python (no fences), keep it.
    stripped = text.strip()
    if stripped.startswith(("import ", "from ", "#", "def ", "result")):
        return stripped
    return ""


def get_intent_agent(ai_client=None) -> Optional[IntentAgent]:
    """Convenience constructor that pulls the default AI client when needed."""
    if ai_client is None:
        try:
            from utils.ai import get_ai
            ai_client = get_ai()
        except Exception:
            return None
    if not ai_client or not getattr(ai_client, "available", False):
        return None
    return IntentAgent(ai_client)
