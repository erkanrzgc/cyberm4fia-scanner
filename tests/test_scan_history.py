import pytest
import os
import tempfile
from utils.scan_history import ScanHistory

@pytest.fixture
def history():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    
    # Needs to be closed so sqlite3 can use it
    
    hist = ScanHistory(db_path=path)
    yield hist
    
    if os.path.exists(path):
        os.remove(path)

def test_save_and_get_previous(history):
    findings = [
        {"type": "XSS", "url": "http://test.com/", "severity": "medium", "param": "id"}
    ]
    history.save_scan("test.com", findings)
    
    prev = history.get_previous("test.com")
    assert prev is not None
    assert prev["findings"][0]["type"] == "XSS"

def test_compute_drift_new_vuln(history):
    # Scan 1
    history.save_scan("test.com", [{"type": "CORS", "url": "http://test.com/api", "severity": "low"}])
    
    # Scan 2: added XSS
    scan2 = [
        {"type": "CORS", "url": "http://test.com/api", "severity": "low"},
        {"type": "XSS", "url": "http://test.com/login", "severity": "high"}
    ]
    
    report = history.compute_drift("test.com", scan2)
    assert report is not None
    assert report.new_count == 1
    assert report.same_count == 1
    assert report.fixed_count == 0
    assert report.worse_count == 0

def test_compute_drift_fixed_and_worse(history):
    # Scan 1
    scan1 = [
        {"type": "XSS", "url": "http://test.com/login", "severity": "medium", "param": "q"},
        {"type": "SQLi", "url": "http://test.com/api", "severity": "high"}
    ]
    history.save_scan("test.com", scan1)
    
    # Scan 2: SQLi fixed, XSS got worse
    scan2 = [
        {"type": "XSS", "url": "http://test.com/login", "severity": "high", "param": "q"}
    ]
    
    report = history.compute_drift("test.com", scan2)
    assert report is not None
    assert report.fixed_count == 1
    assert report.worse_count == 1
    assert report.items[0].status in ("FIXED", "WORSE")
