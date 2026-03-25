import pytest
from unittest.mock import patch, MagicMock

from scanner import scan_target
from core.scan_options import build_default_scan_options

@pytest.fixture
def mock_modules():
    """Mock the runner modules so they don't do real network requests."""
    with patch("scanner.run_phase_modules", return_value=[]) as mock_phase_modules:
        with patch("scanner.smart_request", return_value=MagicMock(content=b"<html></html>")):
            yield mock_phase_modules

@pytest.fixture
def mock_asyncio_run():
    """Mock asyncio.run so we don't block in scan_target."""
    with patch("asyncio.run", return_value=[]) as mock_run:
        # scan_target calls asyncio.run(run_modules_async(...))
        yield mock_run

def test_scan_pipeline_end_to_end_fast(mock_asyncio_run, mock_modules):
    """Test the orchestration of scan_target with Fast Recon profile."""
    options = build_default_scan_options()

    # Enable just a few modules like stealth/fast recon
    options["recon"] = True
    options["subdomain"] = True

    scan_target("http://test.local", "normal", 0.0, options, options)

    # Verify run_modules_async was called by asyncio
    mock_asyncio_run.assert_called_once()
    args = mock_asyncio_run.call_args[0]
    # args[0] is the coroutine returned by run_modules_async_impl
    coro = args[0]
    assert "coroutine object run_modules_async" in str(coro)
    # Close the coroutine to avoid "never awaited" warning
    coro.close()

def test_scan_pipeline_with_mocked_engine(mock_modules):
    """Test scan_target where asyncio run_modules_async returns mocked findings."""
    options = build_default_scan_options()
    options["html"] = True # trigger HTML report Generation
    options["json_output"] = True 
    
    dummy_findings = [
        {"type": "XSS", "url": "http://test.local/vuln"},
        {"type": "SQLi", "url": "http://test.local/login"}
    ]
    
    with patch("core.engine.run_modules_async") :
        with patch("asyncio.run", return_value=(dummy_findings, {"recon":{}, "subdomains":[]})) :
            scan_target("http://test.local", "normal", 0.0, options, options)
            
            # Since scanner.run_phase_modules is patched by mock_modules,
            # we should assert it was called for reporting 
            assert mock_modules.called
