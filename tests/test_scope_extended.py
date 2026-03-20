"""
Extended edge-case tests for core/scope.py ScopeFilter.
Complements the basic tests already in test_core.py.
"""

from core.scope import ScopeFilter, get_scope, set_scope

class TestProtocolAndPort:
    """URL scheme and port edge cases."""

    def test_http_vs_https_treated_same(self):
        """Include pattern should work for both HTTP and HTTPS."""
        scope = ScopeFilter(include=["*.example.com"])
        assert scope.is_allowed("http://app.example.com/page")
        assert scope.is_allowed("https://app.example.com/page")

    def test_port_in_url(self):
        """URLs with non-standard ports should still match domain patterns."""
        scope = ScopeFilter(include=["example.com"])
        # urlparse puts port in parsed.port, hostname stays "example.com"
        assert scope.is_allowed("https://example.com:8443/api")

    def test_port_in_subdomain_url(self):
        """Wildcard domain with port should work."""
        scope = ScopeFilter(include=["*.example.com"])
        assert scope.is_allowed("https://api.example.com:3000/v1/users")

class TestQueryAndFragment:
    """Query string and fragment identifier handling."""

    def test_query_string_url(self):
        """URLs with query parameters should be matched correctly."""
        scope = ScopeFilter(include=["*.target.com"])
        assert scope.is_allowed("https://app.target.com/search?q=test&page=1")

    def test_fragment_url(self):
        """URLs with fragment identifiers should match."""
        scope = ScopeFilter(include=["*.target.com"])
        assert scope.is_allowed("https://app.target.com/page#section-2")

    def test_exclude_path_with_query(self):
        """Path exclusion should still work when URL has query params."""
        scope = ScopeFilter(exclude=["/logout"])
        assert not scope.is_allowed("https://example.com/logout?redirect=/home")

class TestPathPatterns:
    """Path exclusion and pattern matching edge cases."""

    def test_nested_static_path(self):
        """Wildcard path pattern should match nested subdirectories."""
        scope = ScopeFilter(exclude=["/static/*"])
        assert not scope.is_allowed("https://example.com/static/js/app.js")
        assert not scope.is_allowed("https://example.com/static/css/style.css")
        assert scope.is_allowed("https://example.com/api/data")

    def test_exact_path_no_trailing(self):
        """Exact path exclusion without wildcard should match exactly."""
        scope = ScopeFilter(exclude=["/admin"])
        assert not scope.is_allowed("https://example.com/admin")
        # /admin/users should NOT be excluded by exact /admin pattern
        # (depends on fnmatch behavior — /admin pattern won't match /admin/users)
        assert scope.is_allowed("https://example.com/admin/users")

    def test_multiple_extension_exclude(self):
        """Multiple extension excludes should all work."""
        scope = ScopeFilter(exclude=["*.pdf", "*.jpg", "*.png", "*.css", "*.js"])
        assert scope.is_allowed("https://example.com/page.html")
        assert scope.is_allowed("https://example.com/api/data")
        assert not scope.is_allowed("https://example.com/style.css")
        assert not scope.is_allowed("https://example.com/app.js")
        assert not scope.is_allowed("https://example.com/photo.png")

class TestEdgeCases:
    """Boundary and malformed input handling."""

    def test_empty_url(self):
        """Empty URL should not crash the filter."""
        scope = ScopeFilter(include=["*.example.com"])
        # Should return False (doesn't match include) but should NOT raise
        result = scope.is_allowed("")
        assert isinstance(result, bool)

    def test_url_without_scheme(self):
        """URL without scheme should be handled gracefully."""
        scope = ScopeFilter(include=["*.example.com"])
        # urlparse may not parse correctly but should not crash
        result = scope.is_allowed("example.com/page")
        assert isinstance(result, bool)

    def test_unicode_url(self):
        """Unicode characters in URL should not crash."""
        scope = ScopeFilter(include=["*.example.com"])
        result = scope.is_allowed("https://app.example.com/search?q=über")
        assert result is True

    def test_very_long_url(self):
        """Very long URL should not crash."""
        scope = ScopeFilter(include=["*.example.com"])
        long_path = "/a" * 5000
        result = scope.is_allowed(f"https://app.example.com{long_path}")
        assert result is True

class TestStatsAccuracy:
    """Verify stat counters track correctly."""

    def test_stats_count_all_categories(self):
        """Stats should accurately track allowed, scope-blocked, and exclude-blocked."""
        scope = ScopeFilter(include=["*.target.com"], exclude=["/logout"])

        # Allowed
        scope.is_allowed("https://app.target.com/dashboard")
        scope.is_allowed("https://api.target.com/v1/data")

        # Blocked by scope (not in *.target.com)
        scope.is_allowed("https://evil.com/xss")

        # Blocked by exclude rule
        scope.is_allowed("https://app.target.com/logout")

        stats = scope.stats
        assert stats["allowed"] == 2
        assert stats["blocked_scope"] == 1
        assert stats["blocked_exclude"] == 1

    def test_stats_reset_per_instance(self):
        """Each ScopeFilter instance should have independent stats."""
        s1 = ScopeFilter(include=["*.a.com"])
        s2 = ScopeFilter(include=["*.b.com"])

        s1.is_allowed("https://app.a.com/x")
        s2.is_allowed("https://evil.com/y")

        assert s1.stats["allowed"] == 1
        assert s1.stats["blocked_scope"] == 0
        assert s2.stats["allowed"] == 0
        assert s2.stats["blocked_scope"] == 1

class TestGlobalScopeFunctions:
    """Tests for module-level get_scope / set_scope."""

    def test_default_scope_allows_all(self):
        """Default global scope should allow everything."""
        scope = get_scope()
        assert not scope.active
        assert scope.is_allowed("https://anything.com/page")

    def test_set_and_get_scope(self):
        """set_scope should update the global scope correctly."""
        original = get_scope()
        try:
            custom = ScopeFilter(include=["*.custom.com"])
            set_scope(custom)

            retrieved = get_scope()
            assert retrieved.active
            assert retrieved.is_allowed("https://app.custom.com/x")
            assert not retrieved.is_allowed("https://other.com/y")
        finally:
            # Restore original to avoid side effects on other tests
            set_scope(original)
