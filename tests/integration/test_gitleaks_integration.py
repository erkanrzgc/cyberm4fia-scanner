"""Real-binary integration test: GitleaksTool.

Writes a throw-away source tree containing a synthetic AWS-shaped key, runs
the real gitleaks binary against it, asserts the wrapper surfaces the leak.

Skipped when:
  - gitleaks is not installed
"""

from __future__ import annotations

import pytest

from tests.integration.conftest import requires_binary
from utils.external_tools.gitleaks import GitleaksTool

pytestmark = requires_binary("gitleaks")

# Synthetic AWS-shaped key — pattern matches gitleaks' built-in rules but the
# value is unusable. Do not rotate this anywhere real.
_FAKE_AWS_KEY = "AKIA" + "EXAMPLE0123456789AB"


@pytest.fixture
def repo_with_leak(tmp_path):
    secret_file = tmp_path / "config" / "aws.env"
    secret_file.parent.mkdir(parents=True)
    secret_file.write_text(
        "# fixture for gitleaks integration test\n"
        f"AWS_ACCESS_KEY_ID={_FAKE_AWS_KEY}\n"
    )
    # gitleaks --no-git also works on a plain directory; no need to init a repo.
    return tmp_path


def test_gitleaks_detects_aws_shaped_secret(repo_with_leak):
    result = GitleaksTool().run(str(repo_with_leak), timeout=60)
    # gitleaks exits with code 1 when leaks are found — that's success here.
    assert result.parsed["count"] >= 1, (
        f"gitleaks did not flag the fixture key. stderr={result.raw_stderr[:200]!r}"
    )
    rules = {leak["rule"] for leak in result.parsed["leaks"]}
    assert any("aws" in r.lower() for r in rules), f"expected an aws rule, got {rules}"
