import pytest
from utils.finding import compute_confidence_score, _infer_confidence

def test_compute_confidence_score_high():
    vuln = {
        "payload": "<script>alert(1)</script>",
        "response_snippet": "<html><script>alert(1)</script></html>",
        "status_code": 200,
        "evidence": "Payload confirmed in response",
    }
    score = compute_confidence_score(vuln)
    # 30(payload) + 20(status) + 10(evidence+response) + 15(confirmed) + 25(evidence length) = 100
    assert score >= 80

def test_compute_confidence_score_low():
    vuln = {
        "type": "Time-based Blind SQLi",
        "status_code": 503, # WAF block
    }
    score = compute_confidence_score(vuln)
    # 0 base - 10(WAF block) - 15(blind)
    assert score == 0

def test_infer_confidence_override():
    vuln = {
        "confidence": "HIGH"
    }
    assert _infer_confidence(vuln, "low") == "high"

def test_infer_confidence_from_score():
    vuln = {
        "payload": "' OR 1=1--",
        "response": "syntax error",
        "evidence": "SQL syntax error confirmed",
        "exploit_data": {"test": 1}
    }
    # payload not in response directly, but exploit_data (+25), confirmed (+15), evidence (+25)
    # score = 65 -> high
    conf = _infer_confidence(vuln, "high")
    assert conf in ["high", "confirmed"]
