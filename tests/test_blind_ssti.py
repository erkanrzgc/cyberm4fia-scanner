"""Tests for modules/blind_ssti — arithmetic / time-based / OOB oracles."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from modules.blind_ssti import (
    SstiProbe,
    detect_arithmetic_echo,
    detect_oob,
    detect_time_based,
    oob_probes,
    scan_for_blind_ssti,
    time_based_probes,
)


pytestmark = pytest.mark.unit


def _resp(text: str = "") -> SimpleNamespace:
    return SimpleNamespace(status_code=200, text=text)


# ── Arithmetic echo ─────────────────────────────────────────────────────────


def test_arithmetic_jinja2_marker_match():
    """49 in the body is the canonical Jinja2 SSTI signal."""

    def submit(payload):
        if payload == "{{7*7}}":
            return _resp("Hello, your answer is 49 (computed).")
        return _resp("no match")

    findings = detect_arithmetic_echo(submit, url="https://t/", param="q")
    assert any(f.engine == "Jinja2" for f in findings)
    assert findings[0].oracle == "arithmetic"


def test_arithmetic_twig_marker_match():
    """Twig multiplies string by int: 7*'7' → '7777777'."""

    def submit(payload):
        if "7*'7'" in payload:
            return _resp("rendered: 7777777")
        return _resp("nope")

    findings = detect_arithmetic_echo(submit, url="https://t/", param="q")
    assert any(f.engine == "Twig" for f in findings)


def test_arithmetic_no_echo_no_finding():
    def submit(payload):
        return _resp("error: invalid template")  # no marker

    findings = detect_arithmetic_echo(submit, url="https://t/", param="q")
    assert findings == []


def test_arithmetic_submit_exception_isolated():
    state = {"calls": 0}

    def submit(payload):
        state["calls"] += 1
        if state["calls"] == 2:
            raise RuntimeError("connection reset")
        if payload == "{{7*7}}":
            return _resp("49")
        return _resp("noise")

    findings = detect_arithmetic_echo(submit, url="https://t/", param="q")
    # Jinja2 finding still emitted despite later probe failure.
    assert any(f.engine == "Jinja2" for f in findings)


# ── Time-based ──────────────────────────────────────────────────────────────


def test_time_based_detected_with_synthetic_clock():
    """Synthetic clock: baseline 50ms, each probe ~3.5s — well above threshold."""
    # Sequence: baseline(start, end), then for each of N probes (start, end).
    # time_based_probes() returns 3 by default → 1 + 3*2 = 7 ticks.
    ticks = iter([
        0.0, 0.05,    # baseline 50ms
        1.0, 4.5,     # Jinja2 probe — 3.5s
        5.0, 8.5,     # Twig probe — 3.5s
        9.0, 12.5,    # Freemarker probe — 3.5s
    ])

    def submit(_payload):
        return _resp("ok")

    findings = detect_time_based(
        submit,
        url="https://t/",
        param="q",
        clock=lambda: next(ticks),
        safety_margin_ms=500.0,
    )
    # All three probes have sleep_seconds=3 and ran for 3500ms → fire.
    assert len(findings) >= 1
    assert all(f.oracle == "time_based" for f in findings)


def test_time_based_no_finding_when_fast():
    fast = iter([0.0, 0.01, 0.05, 0.06, 0.1, 0.11, 0.15, 0.16])

    def submit(_payload):
        return _resp("ok")

    findings = detect_time_based(
        submit,
        url="https://t/",
        param="q",
        clock=lambda: next(fast),
        safety_margin_ms=500.0,
    )
    assert findings == []


def test_time_based_uses_explicit_baseline():
    """Caller-supplied baseline avoids the in-band measurement."""
    ticks = iter([
        1.0, 4.5,
        5.0, 8.5,
        9.0, 12.5,
    ])

    def submit(_payload):
        return _resp("ok")

    findings = detect_time_based(
        submit,
        url="https://t/",
        param="q",
        baseline_ms=0.0,
        clock=lambda: next(ticks),
    )
    assert findings


# ── OOB ─────────────────────────────────────────────────────────────────────


def test_oob_finding_when_callback_received():
    received_tokens: set[str] = set()

    def submit(payload):
        if "jinja2_oob_token" in payload:
            received_tokens.add("jinja2_oob_token")
        return _resp("ok")

    def callback_seen(token):
        return token in received_tokens

    findings = detect_oob(
        submit,
        url="https://t/",
        param="q",
        callback_url="https://oast.example",
        token="probe-shared-token",
        oob_received=callback_seen,
        probes=(
            SstiProbe(
                "jinja2_oob",
                "Jinja2",
                "PAYLOAD-jinja2_oob_token",
                oob_marker="jinja2_oob_token",
            ),
        ),
    )
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].oracle == "oob"


def test_oob_no_finding_when_no_callback():
    def submit(_payload):
        return _resp("ok")

    findings = detect_oob(
        submit,
        url="https://t/",
        param="q",
        callback_url="https://oast.example",
        token="probe-shared-token",
        oob_received=lambda _: False,
    )
    assert findings == []


def test_oob_probes_embed_token_into_payloads():
    probes = oob_probes("https://oast.example", "my-token")
    assert all("my-token" in p.payload for p in probes)
    assert all(p.oob_marker == "my-token" for p in probes)


# ── Orchestrator ───────────────────────────────────────────────────────────


def test_orchestrator_runs_only_arithmetic_by_default():
    def submit(payload):
        if "{{7*7}}" == payload:
            return _resp("49")
        return _resp("noop")

    findings = scan_for_blind_ssti(submit, url="https://t/", param="q")
    oracles = {f["oracle"] for f in findings}
    assert "arithmetic" in oracles
    assert "time_based" not in oracles
    assert "oob" not in oracles


def test_orchestrator_finding_dict_shape():
    def submit(payload):
        if "{{7*7}}" == payload:
            return _resp("=49=")
        return _resp("")

    findings = scan_for_blind_ssti(submit, url="https://t/", param="x")
    assert findings[0]["module"] == "blind_ssti"
    assert findings[0]["type"] == "Blind_SSTI"
    assert findings[0]["engine"] == "Jinja2"


def test_time_based_probes_factory_covers_known_engines():
    probes = time_based_probes(seconds=2)
    engines = {p.engine for p in probes}
    assert "Jinja2" in engines
    assert "Twig" in engines
    assert "Freemarker" in engines
    for probe in probes:
        assert probe.sleep_seconds == 2
