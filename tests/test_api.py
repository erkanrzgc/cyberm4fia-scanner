"""
Tests for api_server.py — FastAPI endpoint tests.
"""

import pytest
import threading

try:
    import httpx
    import api_server
    from api_server import app

    HAS_API_DEPS = True
except ImportError:
    HAS_API_DEPS = False

class _NoopThread:
    """Thread stub used to avoid background network activity in tests."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self.target = target
        self.args = args
        self.kwargs = kwargs or {}
        self.daemon = daemon
        self.started = False

    def start(self):
        self.started = True

@pytest.mark.skipif(not HAS_API_DEPS, reason="FastAPI/httpx not installed")
class TestAPIServer:
    """Tests for FastAPI endpoints."""

    async def _request(self, method, path, **kwargs):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.request(method, path, **kwargs)

    def setup_method(self):
        api_server.SCANS.clear()

    def teardown_method(self):
        api_server.SCANS.clear()

    @pytest.mark.asyncio
    async def test_index(self):
        resp = await self._request("GET", "/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "cyberm4fia-scanner API"
        assert "endpoints" in data
        assert "docs" in data

    @pytest.mark.asyncio
    async def test_list_scans_empty(self):
        resp = await self._request("GET", "/api/scans")
        assert resp.status_code == 200
        data = resp.json()
        assert "scans" in data
        assert isinstance(data["scans"], list)

    @pytest.mark.asyncio
    async def test_get_nonexistent_scan(self):
        resp = await self._request("GET", "/api/scan/nonexistent")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_nonexistent_scan(self):
        resp = await self._request("DELETE", "/api/scan/nonexistent")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_start_scan_no_url(self):
        resp = await self._request("POST", "/api/scan", json={})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_start_scan_success(self, monkeypatch):
        monkeypatch.setattr(api_server.threading, "Thread", _NoopThread)

        resp = await self._request(
            "POST",
            "/api/scan",
            json={"url": "http://example.com", "modules": ["ssti"], "mode": "quick"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "scan_id" in data
        assert data["status"] == "queued"
        assert data["url"] == "http://example.com"
        assert data["scan_id"] in api_server.SCANS
        assert api_server.SCANS[data["scan_id"]]["status"] == "queued"
        assert api_server.SCANS[data["scan_id"]]["mode"] == "normal"
        assert api_server.SCANS[data["scan_id"]]["options"]["ssti"] is True
        assert api_server.SCANS[data["scan_id"]]["options"]["html"] is True
        assert api_server.SCANS[data["scan_id"]]["options"]["sarif"] is True

    @pytest.mark.asyncio
    async def test_start_scan_rejects_unknown_module(self):
        resp = await self._request(
            "POST",
            "/api/scan",
            json={"url": "http://example.com", "modules": ["not-a-module"]},
        )

        assert resp.status_code == 422
        assert "Unknown API modules" in resp.text

    @pytest.mark.asyncio
    async def test_report_nonexistent(self):
        resp = await self._request("GET", "/api/report/nonexistent")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_json_report_nonexistent(self):
        resp = await self._request("GET", "/api/report/nonexistent/json")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_sarif_report_nonexistent(self):
        resp = await self._request("GET", "/api/report/nonexistent/sarif")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_openapi_docs(self):
        resp = await self._request("GET", "/docs")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_openapi_schema(self):
        resp = await self._request("GET", "/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        assert schema["info"]["title"] == "cyberm4fia-scanner API"
        assert "paths" in schema

    @pytest.mark.asyncio
    async def test_cancel_running_scan_sets_cancelling_status(self):
        api_server.SCANS["scan123"] = {
            "id": "scan123",
            "url": "http://example.com",
            "status": "running",
            "created_at": "now",
            "progress": {"completed": 1, "total": 5},
            "cancel_event": threading.Event(),
        }

        resp = await self._request("DELETE", "/api/scan/scan123")

        assert resp.status_code == 200
        assert resp.json() == {"status": "cancelling"}
        assert api_server.SCANS["scan123"]["status"] == "cancelling"
        assert api_server.SCANS["scan123"]["cancel_event"].is_set() is True

    @pytest.mark.asyncio
    async def test_scan_events_endpoint_streams_progress_payload(self):
        api_server.SCANS["scan123"] = {
            "id": "scan123",
            "url": "http://example.com",
            "status": "completed",
            "created_at": "now",
            "progress": {"phase": "completed", "completed": 2, "total": 2},
            "total_vulns": 1,
            "cancel_event": threading.Event(),
        }

        resp = await self._request("GET", "/api/scan/scan123/events")

        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        assert "event: progress" in resp.text
        assert '"status": "completed"' in resp.text

    @pytest.mark.asyncio
    async def test_json_and_sarif_report_downloads(self, tmp_path):
        scan_dir = tmp_path / "scan123"
        scan_dir.mkdir()
        (scan_dir / "findings.json").write_text('{"summary":{"total":1}}')
        (scan_dir / "results.sarif").write_text('{"version":"2.1.0"}')

        api_server.SCANS["scan123"] = {
            "id": "scan123",
            "url": "http://example.com",
            "status": "completed",
            "created_at": "now",
            "scan_dir": str(scan_dir),
            "cancel_event": threading.Event(),
        }

        json_resp = await api_server.get_json_report("scan123")
        sarif_resp = await api_server.get_sarif_report("scan123")

        assert json_resp.status_code == 200
        assert json_resp.media_type == "application/json"
        assert json_resp.path.endswith("findings.json")

        assert sarif_resp.status_code == 200
        assert sarif_resp.media_type == "application/sarif+json"
        assert sarif_resp.path.endswith("results.sarif")

    @pytest.mark.asyncio
    async def test_get_scan_returns_reasoned_findings_and_attack_paths(self):
        api_server.SCANS["scan123"] = {
            "id": "scan123",
            "url": "http://example.com",
            "status": "completed",
            "created_at": "now",
            "total_vulns": 1,
            "stats": {},
            "progress": {},
            "vulns": [{"type": "XSS_Param", "url": "http://example.com?q=1"}],
            "observations": [{"id": "obs_1", "observation_type": "XSS_Param"}],
            "findings": [{"id": "finding_1", "type": "XSS_Param"}],
            "attack_paths": [{"id": "path_1", "name": "XSS_Param → Session Hijacking"}],
            "cancel_event": threading.Event(),
        }

        resp = await self._request("GET", "/api/scan/scan123")

        assert resp.status_code == 200
        data = resp.json()
        assert data["findings"][0]["id"] == "finding_1"
        assert data["observations"][0]["id"] == "obs_1"
        assert data["attack_paths"][0]["id"] == "path_1"

    def test_run_scan_job_uses_shared_scanner_pipeline(self, monkeypatch, tmp_path):
        import scanner as scanner_mod

        api_server.SCANS["scan123"] = {
            "id": "scan123",
            "url": "http://example.com",
            "status": "queued",
            "created_at": "now",
            "progress": {},
            "cancel_event": threading.Event(),
        }

        captured = {}

        def fake_scan_target(url, mode, delay, options, runtime_options, **kwargs):
            captured["url"] = url
            captured["mode"] = mode
            captured["delay"] = delay
            captured["options"] = dict(options)
            captured["runtime_options"] = dict(runtime_options)
            captured["kwargs"] = kwargs
            return {
                "vulnerabilities": [{"type": "SSTI", "url": url}],
                "observations": [{"id": "obs_1"}],
                "findings": [{"id": "finding_1"}],
                "attack_paths": [{"id": "path_1"}],
                "stats": {"total_requests": 3},
                "scan_dir": str(tmp_path),
                "total_vulns": 1,
            }

        monkeypatch.setattr(scanner_mod, "scan_target", fake_scan_target)

        api_server._run_scan_job(
            "scan123",
            "http://example.com",
            "stealth",
            {"ssti": True, "html": True, "sarif": True, "json_output": True},
        )

        assert captured["mode"] == "stealth"
        assert captured["delay"] == 3
        assert captured["options"]["ssti"] is True
        assert (
            captured["runtime_options"]["cancel_event"]
            is api_server.SCANS["scan123"]["cancel_event"]
        )
        assert captured["kwargs"]["summary_printer"] is None
        assert captured["kwargs"]["persist_console_log"] is False
        assert api_server.SCANS["scan123"]["status"] == "completed"
        assert api_server.SCANS["scan123"]["total_vulns"] == 1
