"""HSTS active verifier.

Combines three live checks:

1. **Preload list status** — query the Chromium HSTS preload list API. A
   domain absent from the preload list is downgradable on first-hit
   regardless of any HSTS response header.
2. **max-age parser** — verify the header (if present) meets ``max-age >=
   31536000`` AND has ``includeSubDomains``. Weak values are exploitable
   even without absence.
3. **First-hit downgrade probe** — request ``http://<host>/`` and verify
   the server returns a 301/302 that *also* carries ``Strict-Transport-
   Security``. A naked 301 → HTTPS without HSTS on the redirect itself is
   strippable on the first hit.

Promotes to ``HSTS_Downgrade_Exploitable`` when any check fails.

The preload-list API call is the only network dependency outside the
target itself. It's wrapped in a try/except so an offline scanner still
gets the other two signals.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from .base import VerificationOutcome, applies_to_header, apply_outcome

logger = logging.getLogger(__name__)

_HEADER_TARGETS = ("strict-transport-security",)
_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_PRELOAD_API = "https://hstspreload.org/api/v2/status?domain={domain}"
_MIN_SAFE_MAX_AGE = 31_536_000  # 1 year — the preload-list requirement
_PRELOAD_TIMEOUT = 5.0


@dataclass
class HSTSVerifier:
    finding_kind: str = "Missing_Security_Header"
    header_targets: tuple[str, ...] = _HEADER_TARGETS

    def applies_to(self, finding: dict) -> bool:
        return applies_to_header(finding, self.header_targets)

    def verify(self, finding: dict, target_url: str) -> VerificationOutcome:
        signals: list[str] = []
        exploitable = False

        # 1. Re-fetch headers (cheap)
        headers = self._fetch_headers(target_url)
        hsts_value = ""
        if headers is not None:
            hsts_value = (headers.get("strict-transport-security") or "").strip()

        # 2. max-age parse + includeSubDomains check
        if not hsts_value:
            signals.append("HSTS header absent")
            exploitable = True
        else:
            m = _MAX_AGE_RE.search(hsts_value)
            max_age = int(m.group(1)) if m else 0
            if max_age == 0:
                signals.append("max-age=0 (disables HSTS)")
                exploitable = True
            elif max_age < _MIN_SAFE_MAX_AGE:
                signals.append(f"max-age={max_age} below 1-year threshold")
                exploitable = True
            if "includesubdomains" not in hsts_value.lower():
                signals.append("includeSubDomains missing")
                exploitable = True
            if "preload" not in hsts_value.lower():
                signals.append("preload directive missing")

        # 3. Preload list status
        host = urlparse(target_url).hostname or ""
        preload_status = self._check_preload(host)
        if preload_status:
            signals.append(f"preload list: {preload_status}")
            if preload_status not in ("preloaded",):
                exploitable = True

        # 4. First-hit downgrade probe
        downgrade = self._first_hit_downgrade(target_url)
        if downgrade:
            signals.append(downgrade)
            exploitable = True

        if exploitable:
            return VerificationOutcome(
                verified=True,
                promoted_type="HSTS_Downgrade_Exploitable",
                evidence="; ".join(signals) or "HSTS misconfiguration",
                severity_override="high",
                cvss_override=7.4,
            )
        return VerificationOutcome(
            verified=False,
            evidence="HSTS appears correctly configured",
        )

    # ── helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _fetch_headers(url: str) -> dict | None:
        try:
            from utils.request import smart_request
        except ImportError:
            return None
        try:
            resp = smart_request("get", url)
        except Exception:
            return None
        return {k.lower(): v for k, v in resp.headers.items()}

    @staticmethod
    def _check_preload(host: str) -> str:
        if not host:
            return ""
        try:
            import httpx
        except ImportError:
            return ""
        try:
            r = httpx.get(_PRELOAD_API.format(domain=host), timeout=_PRELOAD_TIMEOUT)
            if r.status_code != 200:
                return ""
            data = r.json()
        except Exception as exc:  # noqa: BLE001
            logger.debug("preload check failed for %s: %s", host, exc)
            return ""
        status = str(data.get("status") or "").strip()
        return status

    @staticmethod
    def _first_hit_downgrade(target_url: str) -> str:
        """Probe http:// of the target and check the redirect carries HSTS."""
        if not target_url.startswith("https://"):
            return ""
        http_url = "http://" + target_url[len("https://"):]
        try:
            import httpx
        except ImportError:
            return ""
        try:
            r = httpx.get(http_url, follow_redirects=False, timeout=5.0)
        except Exception as exc:  # noqa: BLE001
            logger.debug("first-hit probe failed: %s", exc)
            return ""
        if r.status_code not in (301, 302, 307, 308):
            return ""
        # Redirect exists — does it also carry HSTS?
        if not r.headers.get("strict-transport-security"):
            return "HTTP→HTTPS redirect carries no HSTS (strippable on first hit)"
        return ""


def verify_hsts(findings: list, target_url: str) -> list:
    verifier = HSTSVerifier()
    for f in findings:
        if not verifier.applies_to(f):
            continue
        outcome = verifier.verify(f, target_url)
        apply_outcome(f, outcome)
    return findings
