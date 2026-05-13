"""Page-level + host-level hook runners (passive, secrets, csrf, csp, hsts)."""

from __future__ import annotations


# ── Page hook runners ────────────────────────────────────────────────────────

def _run_passive_hook(state):
    from modules.passive import scan_passive

    return scan_passive(state["scan_url"], response=state["response"])


def _run_secrets_hook(state):
    from modules.secrets_scanner import scan_secrets

    return scan_secrets(state["scan_url"], state["response"].text)


def _run_csrf_hook(state):
    from modules.csrf import scan_csrf

    return scan_csrf(state["scan_url"], state["forms"], state["delay"])


# ── Host-level hook dedup (CSP/HSTS are per-host, not per-URL) ───────────────
_csp_checked_hosts: set = set()
_hsts_checked_hosts: set = set()


def _run_csp_bypass_hook(state):
    from urllib.parse import urlparse
    from modules.csp_bypass import scan_csp_bypass

    host = urlparse(state["scan_url"]).netloc
    if host in _csp_checked_hosts:
        return []  # already reported for this host
    _csp_checked_hosts.add(host)
    return scan_csp_bypass(state["scan_url"], response=state["response"])


def _run_cookie_hsts_hook(state):
    from urllib.parse import urlparse
    from modules.cookie_hsts_audit import scan_cookie_hsts

    host = urlparse(state["scan_url"]).netloc
    if host in _hsts_checked_hosts:
        return []  # already reported for this host
    _hsts_checked_hosts.add(host)
    return scan_cookie_hsts(state["scan_url"], response=state["response"])


