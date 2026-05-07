"""Smart Payload Engine — context/filter/WAF-aware payload generation.

Replaces the former 942-LOC ``modules/smart_payload.py`` (and its
sibling ``modules/smart_payload_inject.py``) with seven cohesive
sub-modules. Public surface preserved verbatim — every existing
``from modules.smart_payload import probe_*_context`` keeps working.

Sub-modules:
  - _xss_detection  → XSS probe constants + 4-layer detection helpers
  - _xss_payloads   → mutation engine + context-aware payload generator
  - xss             → ``probe_xss_context`` orchestrator
  - sqli            → DB-aware ``probe_sqli_context``
  - cmdi            → separator-aware ``probe_cmdi_context``
  - lfi             → traversal+wrapper aware ``probe_lfi_context``
"""

from .cmdi import probe_cmdi_context
from .lfi import probe_lfi_context
from .sqli import probe_sqli_context
from .xss import probe_xss_context

__all__ = [
    "probe_xss_context",
    "probe_sqli_context",
    "probe_cmdi_context",
    "probe_lfi_context",
]
