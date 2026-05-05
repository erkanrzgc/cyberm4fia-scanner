"""Tests for modules.baas_audit — Backend-as-a-Service misconfiguration audit.

Covers three providers users routinely misconfigure when they ship apps from
AI code assistants (the niche CheckVibe.dev targets):

1. Supabase   — anonymous JWT leaked + RLS-disabled tables readable
2. Firebase   — Realtime DB `/.json` and Firestore lists open to public reads
3. Clerk      — *secret* (sk_*) key leaked in client-shipped JS
                (the publishable pk_* key is meant to be public; flagging
                that would be noise — only sk_* matters)

All HTTP calls are mocked. No live BaaS contact ever happens in tests.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


pytestmark = pytest.mark.unit


def _resp(status_code=200, body=None, headers=None, text=None):
    r = MagicMock()
    r.status_code = status_code
    if text is not None:
        r.text = text
        r.json = MagicMock(side_effect=ValueError("not json"))
    elif isinstance(body, (dict, list)):
        r.text = json.dumps(body)
        r.json = MagicMock(return_value=body)
    else:
        r.text = body or ""
        r.json = MagicMock(side_effect=ValueError("not json"))
    r.headers = headers or {}
    return r


# ─── Provider detection ─────────────────────────────────────────────────────


class TestProviderDetection:
    def test_detects_supabase_url_and_anon_key_in_html(self):
        from modules.baas_audit import _detect_providers

        html = """
        <script>
          const SUPABASE_URL = "https://abcd1234.supabase.co";
          const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.aaa";
        </script>
        """
        providers = _detect_providers(html)

        assert "supabase" in providers
        sb = providers["supabase"]
        assert sb["url"] == "https://abcd1234.supabase.co"
        assert sb["anon_key"].startswith("eyJ")

    def test_detects_firebase_database_url(self):
        from modules.baas_audit import _detect_providers

        html = """
        firebase.initializeApp({
          databaseURL: "https://my-app-default-rtdb.firebaseio.com",
          projectId: "my-app",
          apiKey: "AIzaSyAbcdef1234567890ABCDEFGHIJKLMNOPQR"
        });
        """
        providers = _detect_providers(html)

        assert "firebase" in providers
        fb = providers["firebase"]
        assert fb["database_url"] == "https://my-app-default-rtdb.firebaseio.com"

    def test_detects_clerk_secret_key_in_client_bundle(self):
        from modules.baas_audit import _detect_providers

        # An sk_* key in client-shipped JS is a hard CRITICAL — pk_* alone is fine.
        # Build the secret-shaped fixture at runtime so the literal pattern
        # never appears in source (avoids tripping push-protection scanners).
        prefix = "sk_" + "live_"
        fake_key = prefix + "abcdefghijklmnopqrstuvwxyz0123456789"
        html = f'const CLERK_SECRET_KEY = "{fake_key}";'
        providers = _detect_providers(html)

        assert "clerk" in providers
        assert providers["clerk"].get("secret_key", "").startswith(prefix)

    def test_publishable_clerk_key_alone_is_not_a_finding(self):
        from modules.baas_audit import _detect_providers

        html = 'const CLERK_PUBLISHABLE_KEY = "pk_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaa";'
        providers = _detect_providers(html)

        # We may detect that the app uses Clerk, but no `secret_key` should be set.
        if "clerk" in providers:
            assert "secret_key" not in providers["clerk"]

    def test_no_baas_returns_empty(self):
        from modules.baas_audit import _detect_providers

        assert _detect_providers("<html><body>plain site</body></html>") == {}


# ─── Supabase: RLS-disabled table read ──────────────────────────────────────


class TestSupabaseRLS:
    def test_anon_can_read_table_flags_rls_disabled(self):
        from modules.baas_audit import _check_supabase

        # Supabase REST returns a JSON list when anon SELECT is allowed.
        leaky = _resp(200, body=[
            {"id": 1, "email": "a@x.com"},
            {"id": 2, "email": "b@x.com"},
        ])
        provider = {
            "url": "https://abcd1234.supabase.co",
            "anon_key": "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x",
        }
        with patch("modules.baas_audit.smart_request", return_value=leaky):
            findings = _check_supabase(provider, delay=0)

        assert any(f["type"] == "BaaS_Supabase_RLS_Disabled" for f in findings)
        f = next(f for f in findings if f["type"] == "BaaS_Supabase_RLS_Disabled")
        assert f["severity"] in ("HIGH", "CRITICAL")

    def test_rls_protected_table_returns_no_finding(self):
        from modules.baas_audit import _check_supabase

        # PostgREST replies 401 / empty list when RLS blocks anonymous reads.
        protected = _resp(401, body={"message": "JWT expired"})
        provider = {
            "url": "https://abcd1234.supabase.co",
            "anon_key": "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x",
        }
        with patch("modules.baas_audit.smart_request", return_value=protected):
            findings = _check_supabase(provider, delay=0)

        assert all(f["type"] != "BaaS_Supabase_RLS_Disabled" for f in findings)


# ─── Firebase: open Realtime DB ─────────────────────────────────────────────


class TestFirebaseRealtimeDB:
    def test_open_realtime_db_returns_data_for_anonymous(self):
        from modules.baas_audit import _check_firebase

        # Firebase Realtime DB returns JSON for `/.json` when read rules are public.
        leaky = _resp(200, body={"users": {"u1": {"email": "a@x.com"}}})
        provider = {"database_url": "https://my-app-default-rtdb.firebaseio.com"}
        with patch("modules.baas_audit.smart_request", return_value=leaky):
            findings = _check_firebase(provider, delay=0)

        assert any(f["type"] == "BaaS_Firebase_Open_RTDB" for f in findings)
        f = next(f for f in findings if f["type"] == "BaaS_Firebase_Open_RTDB")
        assert f["severity"] == "CRITICAL"

    def test_locked_realtime_db_returns_no_finding(self):
        from modules.baas_audit import _check_firebase

        # Locked RTDB returns 401/`Permission denied`.
        locked = _resp(401, body={"error": "Permission denied"})
        provider = {"database_url": "https://my-app-default-rtdb.firebaseio.com"}
        with patch("modules.baas_audit.smart_request", return_value=locked):
            findings = _check_firebase(provider, delay=0)

        assert all(f["type"] != "BaaS_Firebase_Open_RTDB" for f in findings)


# ─── Clerk: secret key leak ────────────────────────────────────────────────


class TestClerkSecretLeak:
    def test_sk_live_in_provider_is_critical_finding(self):
        from modules.baas_audit import _check_clerk

        # Build secret-shaped fixture at runtime to avoid push-protection hits.
        prefix = "sk_" + "live_"
        provider = {"secret_key": prefix + ("a" * 24)}
        findings = _check_clerk(provider, source_url="https://target/app.js")

        assert findings, "expected a Clerk secret-key finding"
        f = findings[0]
        assert f["type"] == "BaaS_Clerk_Secret_Key_Leak"
        assert f["severity"] == "CRITICAL"

    def test_no_secret_key_means_no_finding(self):
        from modules.baas_audit import _check_clerk

        # Provider detected (e.g. only publishable key), but no sk_* leak.
        findings = _check_clerk({}, source_url="https://target/app.js")
        assert findings == []


# ─── Top-level orchestrator ────────────────────────────────────────────────


class TestScanEntry:
    def test_no_baas_short_circuits(self):
        from modules.baas_audit import scan_baas_audit

        plain_resp = _resp(200, text="<html><body>nothing</body></html>")
        with patch("modules.baas_audit.smart_request", return_value=plain_resp):
            findings = scan_baas_audit("https://target.example", delay=0)

        assert findings == []

    def test_html_with_supabase_anon_key_runs_rls_probe(self):
        from modules.baas_audit import scan_baas_audit

        html = """
        <script>
          const SUPABASE_URL = "https://proj.supabase.co";
          const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x";
        </script>
        """
        # First call: fetch landing page.
        # Subsequent calls: RLS probes returning a populated table.
        landing = _resp(200, text=html, headers={"Content-Type": "text/html"})
        leaky_table = _resp(200, body=[{"id": 1, "email": "a@x.com"}])

        responses = iter([landing] + [leaky_table] * 30)
        with patch("modules.baas_audit.smart_request",
                   side_effect=lambda *a, **kw: next(responses)):
            findings = scan_baas_audit("https://target.example", delay=0)

        types = {f["type"] for f in findings}
        assert "BaaS_Supabase_RLS_Disabled" in types

    def test_network_errors_do_not_crash_scan(self):
        from modules.baas_audit import scan_baas_audit
        from utils.request import ScanExceptions

        exc_cls = ScanExceptions[0] if isinstance(ScanExceptions, tuple) \
            else ScanExceptions
        with patch("modules.baas_audit.smart_request",
                   side_effect=exc_cls("boom")):
            findings = scan_baas_audit("https://target.example", delay=0)

        assert findings == []
