"""Integration tests for ExternalTool wrappers — exercises the *real* binaries.

These tests are excluded from the default ``pytest`` run and only execute
when invoked explicitly:

    pytest -m integration tests/integration/

Each test skips gracefully when its prerequisite (binary, service, env var)
is missing, so a partial setup still produces a meaningful pass/skip report.
"""
