"""
Tests for api_server.py — FastAPI endpoint tests
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

try:
    from fastapi.testclient import TestClient
    from api_server import app

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


@pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")
class TestAPIServer:
    """Tests for FastAPI endpoints."""

    def setup_method(self):
        self.client = TestClient(app)

    def test_index(self):
        resp = self.client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "cyberm4fia-scanner API"
        assert "endpoints" in data
        assert "docs" in data

    def test_list_scans_empty(self):
        resp = self.client.get("/api/scans")
        assert resp.status_code == 200
        data = resp.json()
        assert "scans" in data
        assert isinstance(data["scans"], list)

    def test_get_nonexistent_scan(self):
        resp = self.client.get("/api/scan/nonexistent")
        assert resp.status_code == 404

    def test_delete_nonexistent_scan(self):
        resp = self.client.delete("/api/scan/nonexistent")
        assert resp.status_code == 404

    def test_start_scan_no_url(self):
        resp = self.client.post("/api/scan", json={})
        assert resp.status_code == 422  # Pydantic validation error

    def test_start_scan_success(self):
        resp = self.client.post(
            "/api/scan",
            json={"url": "http://example.com", "modules": ["xss"], "mode": "quick"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "scan_id" in data
        assert data["status"] == "queued"
        assert data["url"] == "http://example.com"

    def test_report_nonexistent(self):
        resp = self.client.get("/api/report/nonexistent")
        assert resp.status_code == 404

    def test_openapi_docs(self):
        resp = self.client.get("/docs")
        assert resp.status_code == 200

    def test_openapi_schema(self):
        resp = self.client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        assert schema["info"]["title"] == "cyberm4fia-scanner API"
        assert "paths" in schema
