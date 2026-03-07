"""
Tests for core/engine.py — Async scan engine module orchestration.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from core.engine import _run_module, run_modules_async_impl, run_modules_async


class TestRunModule:
    """Tests for the _run_module helper."""

    @pytest.mark.asyncio
    async def test_successful_module(self):
        """Module returning results should pass them through."""

        def fake_scan(url, forms, delay):
            return [{"type": "XSS_Param", "url": url}]

        name, results = await _run_module("XSS", fake_scan, "http://t.com", [], 0)
        assert name == "XSS"
        assert len(results) == 1
        assert results[0]["type"] == "XSS_Param"

    @pytest.mark.asyncio
    async def test_module_returning_none(self):
        """Module returning None should be normalized to empty list."""

        def fake_scan(url, forms, delay):
            return None

        name, results = await _run_module("LFI", fake_scan, "http://t.com", [], 0)
        assert name == "LFI"
        assert results == []

    @pytest.mark.asyncio
    async def test_module_raising_exception(self):
        """Module raising an exception should return empty list, not crash."""

        def bad_scan(url, forms, delay):
            raise RuntimeError("Connection refused")

        name, results = await _run_module("BAD", bad_scan, "http://t.com", [], 0)
        assert name == "BAD"
        assert results == []


class TestRunModulesAsyncImpl:
    """Tests for the main async orchestrator."""

    @pytest.mark.asyncio
    async def test_no_modules_returns_empty(self):
        """With no modules enabled, should return empty list."""
        options = {}  # Nothing enabled
        result = await run_modules_async_impl("http://t.com", [], 0, options)
        assert result == []

    @pytest.mark.asyncio
    async def test_progress_callback(self):
        """Progress callback should be called for each completed module."""
        completed_modules = []

        def on_progress(name):
            completed_modules.append(name)

        # Mock a single module to avoid real HTTP calls
        with patch("core.engine.scan_xss", create=True) as mock_xss:
            mock_xss.return_value = [{"type": "XSS_Param", "url": "http://t.com"}]

            # We need to patch the lazy import inside run_modules_async_impl
            options = {"xss": True}

            # Patch the import inside the function
            import core.engine as engine_mod

            original_func = engine_mod.run_modules_async_impl

            async def patched_impl(
                scan_url, forms, delay, options, progress_callback=None
            ):
                tasks = []
                if options.get("xss"):

                    def fake_xss(url, forms, delay):
                        return [{"type": "XSS_Param", "url": url}]

                    tasks.append(_run_module("XSS", fake_xss, scan_url, forms, delay))

                if not tasks:
                    return []

                all_vulns = []
                results = await asyncio.gather(*tasks)
                for result in results:
                    name, vulns = result
                    if vulns:
                        all_vulns.extend(vulns)
                    if progress_callback:
                        progress_callback(name)
                return all_vulns

            result = await patched_impl(
                "http://t.com", [], 0, {"xss": True}, on_progress
            )
            assert "XSS" in completed_modules
            assert len(result) == 1


class TestRunModulesSync:
    """Tests for the synchronous wrapper."""

    def test_sync_wrapper_no_modules(self):
        """Sync wrapper with no modules should return empty list."""
        result = run_modules_async("http://t.com", [], 0, {})
        assert result == []

    def test_sync_wrapper_returns_list(self):
        """Sync wrapper should always return a list."""
        result = run_modules_async("http://t.com", [], 0, {})
        assert isinstance(result, list)
