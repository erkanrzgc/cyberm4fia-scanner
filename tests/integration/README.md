# Integration tests

These exercise the **real** external-tool binaries that the unit-test
wrappers parse against documented sample output. They catch:

- Schema drift when a tool version changes its JSON/text output
- CLI flag breakage we wouldn't notice from sample-driven tests
- Real failure modes (truncation, ANSI colour codes leaking, non-zero exits)

They are **excluded from the default `pytest` run** so a normal `pytest`
stays fast (<5 minutes, no Docker dependency) and CI doesn't need a fleet
of container fixtures.

## Run them

```bash
# All integration tests (most will skip if their binary or service is missing).
pytest -m integration tests/integration/ -v

# Just one tool.
pytest -m integration tests/integration/test_arjun_integration.py -v
```

A test that has no prerequisites met **skips**, it doesn't fail. So you
can run the whole suite incrementally as you install more tooling.

## Bring the fixture services up

Three tests need *just* a binary on PATH (no Docker):

- `test_arjun_integration.py` — spins its own HTTP server in-process
- `test_gitleaks_integration.py` — uses a `tmp_path` fixture
- `test_masscan_integration.py` — uses a loopback listener in-process

The rest need services from `docker-compose.integration.yml`:

```bash
# 1. Generate the throwaway TLS cert + key
mkdir -p tests/integration/fixtures/tls
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout tests/integration/fixtures/tls/key.pem \
  -out tests/integration/fixtures/tls/cert.pem \
  -days 3650 -subj "/CN=weak-tls-fixture.test"

# 2. Bring up the services
docker compose -f docker-compose.integration.yml up -d

# 3. Run the suite
pytest -m integration tests/integration/ -v

# 4. Tear down
docker compose -f docker-compose.integration.yml down -v
```

## Per-tool prerequisites

| Test | Binary | Other prereq |
|---|---|---|
| `arjun` | `arjun` | — |
| `gitleaks` | `gitleaks` | — |
| `masscan` | `masscan` | CAP_NET_RAW (test self-skips if not granted) |
| `sslyze` | `sslyze` | `weak-tls` service (port 8443) |
| `testssl` | `testssl.sh` | `weak-tls` service (port 8443) |
| `smbmap` | `smbmap` | `samba` service (port 1445) |
| `gowitness` | `gowitness` + chromium | `http-target` service (port 8081) |
| `wpscan` | `wpscan` | `wordpress` service (port 8080) + `WPSCAN_API_TOKEN` env |
| `kube-hunter` | `kube-hunter` | A reachable Kubernetes API on `127.0.0.1:6443` (e.g. `kind`) |
| `cloudhunter` | `cloudhunter` | `SCANNER_INTEGRATION_NETWORK=1` (outbound to public cloud endpoints) |

## Why not in CI by default

Running all of these in GitHub Actions every push would:

- Add ~30 minutes per run (vs the current ~4 min unit suite)
- Require pinned tool versions / a custom CI image
- Introduce network/container flakiness

The intended cadence is **nightly** (or per-release) on a self-hosted runner
or as a manual workflow_dispatch — wire that up in `.github/workflows/` only
when there's an owner for triaging the inevitable schema-drift failures.
