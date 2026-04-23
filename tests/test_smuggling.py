import pytest
from unittest.mock import patch, MagicMock

from modules.smuggling import scan_smuggling

@patch("modules.smuggling._send_raw")
@patch("os.path.exists")
@patch("subprocess.run")
def test_scan_smuggling_smuggler_integration(mock_run, mock_exists, mock_send):
    """Test that the external Smuggler MCP script is integrated and its output is parsed correctly."""
    
    # Mock network calls to return "OK" to simulate no basic smuggling
    mock_send.return_value = "OK"
    
    # Mock os.path.exists to simulate smuggler.py is present
    mock_exists.return_value = True
    
    # Mock subprocess.run to simulate Smuggler finding a vulnerability
    mock_result = MagicMock()
    mock_result.stdout = "CRITICAL: HTTP Request Smuggling detected via TE.CL payload"
    mock_run.return_value = mock_result
    
    findings = scan_smuggling("https://example.com")
    
    # Ensure subprocess was called
    mock_run.assert_called_once()
    
    # Ensure it generated findings (could be more than 1 due to other checks returning "OK")
    assert len(findings) >= 1
    assert any(f["variant"] == "Smuggler Script Match" and f["severity"] == "CRITICAL" for f in findings)

@patch("modules.smuggling._send_raw")
@patch("os.path.exists")
def test_scan_smuggling_cl_te(mock_exists, mock_send):
    """Test basic CL.TE smuggling detection."""
    
    # Mock os.path.exists to simulate smuggler.py is missing (skip subprocess)
    mock_exists.return_value = False
    
    # Mock network responses to trigger CL.TE detection
    # _test_cl_te requires timing differences
    call_count = [0]
    
    def side_effect(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 2:  # The CL.TE smuggle request
            import time
            time.sleep(3.5)
        return "OK"
        
    mock_send.side_effect = side_effect
    
    findings = scan_smuggling("https://example.com")
    
    # We should have one CL.TE finding
    assert len(findings) > 0
    assert any(f["variant"] == "CL.TE" for f in findings)
    
@patch("modules.smuggling._send_raw")
@patch("os.path.exists")
def test_scan_smuggling_invalid_url(mock_exists, mock_send):
    """Test scan_smuggling with invalid URL."""
    findings = scan_smuggling("invalid-url")
    assert len(findings) == 0
    mock_send.assert_not_called()
