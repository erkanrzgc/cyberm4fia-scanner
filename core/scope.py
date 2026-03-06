"""
cyberm4fia-scanner — Scope Control

URL filtering system for controlling which URLs are in-scope during a scan.
Supports inclusion patterns (--scope) and exclusion patterns (--exclude).

Usage:
    python3 scanner.py -u https://target.com --all --scope "*.target.com" --exclude "/logout,/static,*.pdf"
"""

import fnmatch
from urllib.parse import urlparse
from utils.colors import log_info, log_warning


class ScopeFilter:
    """
    Controls which URLs are in-scope for scanning.

    Examples:
        scope = ScopeFilter(
            include=["*.example.com"],
            exclude=["/logout", "/static/*", "*.pdf"]
        )
        scope.is_allowed("https://app.example.com/login")    # True
        scope.is_allowed("https://evil.com/xss")             # False
        scope.is_allowed("https://app.example.com/logout")   # False
        scope.is_allowed("https://app.example.com/doc.pdf")  # False
    """

    def __init__(self, include: list = None, exclude: list = None):
        self.include_patterns = include or []
        self.exclude_patterns = exclude or []
        self._stats = {"allowed": 0, "blocked_scope": 0, "blocked_exclude": 0}

        if self.include_patterns:
            log_info(f"Scope include: {', '.join(self.include_patterns)}")
        if self.exclude_patterns:
            log_info(f"Scope exclude: {', '.join(self.exclude_patterns)}")

    def is_allowed(self, url: str) -> bool:
        """Check if a URL is within scope."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or "/"
        full = hostname + path

        # Check inclusion (if patterns defined, URL must match at least one)
        if self.include_patterns:
            if not any(
                self._match(pattern, hostname, path, full)
                for pattern in self.include_patterns
            ):
                self._stats["blocked_scope"] += 1
                return False

        # Check exclusion (if URL matches any exclude pattern, block it)
        if self.exclude_patterns:
            if any(
                self._match(pattern, hostname, path, full)
                for pattern in self.exclude_patterns
            ):
                self._stats["blocked_exclude"] += 1
                return False

        self._stats["allowed"] += 1
        return True

    def filter_urls(self, urls: list) -> list:
        """Filter a list of URLs, returning only in-scope ones."""
        filtered = [u for u in urls if self.is_allowed(u)]
        blocked = len(urls) - len(filtered)
        if blocked:
            log_warning(
                f"Scope: {blocked} URL(s) filtered out, {len(filtered)} remaining"
            )
        return filtered

    def _match(self, pattern: str, hostname: str, path: str, full: str) -> bool:
        """Match a pattern against URL components."""
        pattern = pattern.strip()

        # Domain wildcard: *.example.com (must have dot in remainder)
        if pattern.startswith("*.") and "." in pattern[2:]:
            domain = pattern[2:]
            return hostname == domain or hostname.endswith("." + domain)

        # Extension pattern: *.pdf, *.js (no dot in remainder = file extension)
        if pattern.startswith("*.") and "." not in pattern[2:]:
            return fnmatch.fnmatch(path, f"*{pattern[1:]}")

        # Full domain: example.com
        if "." in pattern and "/" not in pattern and "*" not in pattern:
            return hostname == pattern

        # Path pattern: /logout, /static/*
        if pattern.startswith("/"):
            return fnmatch.fnmatch(path, pattern)

        # Generic glob match against full URL path
        return fnmatch.fnmatch(full, pattern)

    @property
    def active(self) -> bool:
        """Whether scope filtering is active."""
        return bool(self.include_patterns or self.exclude_patterns)

    @property
    def stats(self) -> dict:
        return dict(self._stats)


# Global scope filter (set by scanner.py at startup)
_active_scope = ScopeFilter()


def get_scope() -> ScopeFilter:
    """Get the currently active scope filter."""
    return _active_scope


def set_scope(scope: ScopeFilter):
    """Set the active scope filter."""
    global _active_scope
    _active_scope = scope
