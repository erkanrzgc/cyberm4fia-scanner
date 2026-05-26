"""External-tool report exporters.

Each submodule converts the internal findings dict-list into the file format
of a specific external tool (Burp Suite Pro Issues XML, DefectDojo helper,
etc.). SARIF, HTML, Markdown, and the native scan.json/findings.json formats
are still produced by ``core/output.py``.
"""

from __future__ import annotations

from .burp_xml import export_burp_xml

__all__ = ["export_burp_xml"]
