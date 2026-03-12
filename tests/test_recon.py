"""
Tests for modules/recon.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import modules.recon as recon_mod


class TestRecon:
    def test_light_recon_skips_port_scan(self, monkeypatch):
        calls = []

        monkeypatch.setattr(
            recon_mod.socket,
            "gethostbyname",
            lambda host: "127.0.0.1",
        )
        monkeypatch.setattr(
            recon_mod,
            "get_server_info",
            lambda url: {"server": "nginx", "all_headers": {"Server": "nginx"}},
        )
        monkeypatch.setattr(
            recon_mod.asyncio,
            "run",
            lambda coro: calls.append(coro) or [],
        )

        result = recon_mod.run_recon("http://example.com", deep=False)

        assert calls == []
        assert result["ip"] == "127.0.0.1"
        assert result["open_ports"] == []
        assert result["total_headers"] > 0
