"""
Integration-style tests for modules/api_scanner.py using a WSGI fixture app.
"""

from urllib.parse import urlparse

import pytest

try:
    import httpx

    from modules import api_scanner
    from tests.fixtures_vuln_api_app import create_app
    from utils.auth import auth_manager

    HAS_INTEGRATION_DEPS = True
except ImportError:
    HAS_INTEGRATION_DEPS = False


@pytest.mark.skipif(not HAS_INTEGRATION_DEPS, reason="httpx not installed")
def test_scan_api_detects_openapi_auth_issues_via_wsgi_fixture(monkeypatch):
    app = create_app()

    monkeypatch.setattr(
        api_scanner,
        "smart_request",
        lambda method, url, **kwargs: _wsgi_request(app, method, url, **kwargs),
    )
    # After the api_scanner.py ➜ api_spec_parser.py split, spec parsing
    # functions import smart_request in their own module namespace.
    from modules import api_spec_parser
    monkeypatch.setattr(
        api_spec_parser,
        "smart_request",
        lambda method, url, **kwargs: _wsgi_request(app, method, url, **kwargs),
    )
    monkeypatch.setattr(api_scanner, "test_bola", lambda target, delay=0: [])
    monkeypatch.setattr(api_scanner, "test_rate_limiting", lambda target, delay=0: [])
    monkeypatch.setattr(api_scanner, "test_mass_assignment", lambda target, delay=0: [])
    monkeypatch.setattr(api_scanner, "test_verb_tampering", lambda url, delay=0: [])
    monkeypatch.setattr(api_scanner, "test_graphql_introspection", lambda url, delay=0: [])
    monkeypatch.setattr(api_scanner, "test_jwt_issues", lambda url, headers, delay=0: [])

    findings = api_scanner.scan_api("http://fixture.local", delay=0)
    finding_types = {finding["type"] for finding in findings}

    assert "API_Auth_Scheme" in finding_types
    assert "API_Unauth_Access" in finding_types
    assert "API_BFLA" in finding_types


def _wsgi_request(app, method, url, **kwargs):
    parsed = urlparse(url)
    request_path = parsed.path or "/"
    if parsed.query:
        request_path += f"?{parsed.query}"

    headers = dict(kwargs.pop("headers", {}) or {})
    auth_kwargs = {}
    auth_manager.inject_auth(headers, auth_kwargs)
    params = auth_kwargs.pop("params", None)
    if params:
        separator = "&" if "?" in request_path else "?"
        query_string = "&".join(f"{key}={value}" for key, value in params.items())
        request_path = f"{request_path}{separator}{query_string}"

    transport = httpx.WSGITransport(app=app)
    with httpx.Client(
        transport=transport,
        base_url="http://fixture.local",
        follow_redirects=True,
    ) as client:
        return client.request(
            method.upper(),
            request_path,
            headers=headers,
            json=kwargs.get("json"),
            data=kwargs.get("data"),
        )
