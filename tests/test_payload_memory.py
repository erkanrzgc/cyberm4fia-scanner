import pytest
import os
import tempfile
from utils.payload_memory import PayloadMemory

@pytest.fixture
def memory():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    
    mem = PayloadMemory(db_path=path)
    yield mem
    
    if os.path.exists(path):
        os.remove(path)

def test_remember_and_recall(memory):
    memory.remember(
        target="example.com",
        vuln_type="XSS",
        payload="<script>alert(1)</script>",
        confidence=90
    )
    
    results = memory.recall(target="example.com")
    assert len(results) == 1
    assert results[0]["payload"] == "<script>alert(1)</script>"
    assert results[0]["confidence"] == 90

def test_deduplication(memory):
    for _ in range(3):
        memory.remember("test.com", "SQLi", "' OR 1=1--", confidence=50)
    
    results = memory.recall()
    assert len(results) == 1
    assert results[0]["success_count"] == 1 # Currently we don't increment this in the code, but there should be 1 entry

def test_confidence_updater(memory):
    memory.remember("test.com", "SQLi", "payload1", confidence=50)
    memory.remember("test.com", "SQLi", "payload1", confidence=90) # Should update
    memory.remember("test.com", "SQLi", "payload1", confidence=40) # Should NOT update
    
    results = memory.recall()
    assert len(results) == 1
    assert results[0]["confidence"] == 90

def test_get_context_for_ai(memory):
    memory.remember("test.com", "XSS", "payload1", technique="SVG", waf_bypassed="Cloudflare")
    context = memory.get_context_for_ai()
    
    assert "payload1" in context
    assert "SVG" in context
    assert "Cloudflare" in context
