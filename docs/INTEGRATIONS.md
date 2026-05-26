# Integrations

cyberm4fia-scanner emits three machine-readable artefacts on every scan:

| File | Format | Consumers |
|---|---|---|
| `scans/<target>/results.sarif` | SARIF 2.1.0 | GitHub Code Scanning, DefectDojo (SARIF parser), Sonatype, Sysdig |
| `scans/<target>/issues.burp.xml` | Burp Suite Issues XML | Burp Suite Pro (Project → Import issues), DefectDojo (Burp parser) |
| `scans/<target>/findings.json` | Native enhanced JSON | custom dashboards, internal triage tooling |

Plus the human-readable: `report.md`, `report.html`, `scan.txt`, and the
`pocs/` directory containing self-contained HTML exploit PoCs.

---

## DefectDojo

DefectDojo natively supports both SARIF and Burp Suite Issues XML — pick
whichever fits your existing pipeline. SARIF carries more accurate
severity/CWE mapping; Burp XML preserves request/response evidence.

### Via UI

1. *Findings* → *Import Scan Results*
2. **Scan type:**
   - `SARIF` → upload `scans/<target>/results.sarif`
   - `Burp Scan` → upload `scans/<target>/issues.burp.xml`
3. Pick the Product + Engagement.

### Via API (CI-friendly)

```bash
curl -sS -X POST \
  -H "Authorization: Token $DOJO_TOKEN" \
  -F "scan_type=SARIF" \
  -F "engagement=$ENGAGEMENT_ID" \
  -F "file=@scans/$TARGET/results.sarif" \
  https://defectdojo.internal/api/v2/import-scan/
```

Replace `scan_type=SARIF` with `scan_type=Burp Scan` for the XML upload.

DefectDojo deduplicates findings across uploads via the SARIF `ruleId`
(CWE) + URL, so re-running the scanner against the same target updates
existing findings instead of creating duplicates.

---

## Burp Suite Professional

1. **Project → Import issues** in Burp Pro.
2. Select `scans/<target>/issues.burp.xml`.
3. The findings appear under the *Target → Issues* tree, grouped by host.

The export preserves: CWE id (in `<type>`), severity (mapped to Burp's
High/Medium/Low/Information enum), confidence (Certain/Firm/Tentative),
evidence + payload (in `<issueDetail>`), and request/response if the
finding captured them.

PoC HTML files live in `scans/<target>/pocs/` and can be sent to the
Burp Repeater or opened in a browser side-by-side for triage.

---

## GitHub Code Scanning (free tier)

The repo ships `.github/workflows/security-scan.yml` with a step that
uploads `results.sarif` via `github/codeql-action/upload-sarif@v3`.
Findings appear under the repo's **Security → Code scanning** tab with
deduplication, dismissal workflow, and PR annotations.

Required repo permissions: `security-events: write` (granted via
`permissions:` in the workflow, or by enabling **Settings → Actions →
Workflow permissions → Read and write**).

---

## CI/CD Exit Code Gating

The scanner exits with a per-severity code:

| Code | Meaning |
|---|---|
| `0` | Clean — no findings at the configured threshold |
| `1` | At least one **CRITICAL** finding |
| `2` | At least one **HIGH** finding |
| `3` | At least one **MEDIUM** finding |
| `4` | At least one **LOW** / **INFO** finding |
| `10` | Scanner internal error |

Higher severities win — a scan with both Critical and Low exits `1`.

### Tuning the gate

Set `SCAN_EXIT_THRESHOLD` (env var) to pick which tiers fail the build:

| `SCAN_EXIT_THRESHOLD=` | Exits non-zero on… |
|---|---|
| `critical` | Critical only |
| `high` *(default in CI workflow)* | Critical, High |
| `medium` | Critical, High, Medium |
| `low` / `info` | any finding |
| `never` | never (always exit 0) |

In GitHub Actions, set the threshold via repo / org **Variables**:

```yaml
env:
  SCAN_EXIT_THRESHOLD: ${{ vars.SCAN_EXIT_THRESHOLD || 'high' }}
```

### Shell example

```bash
python3 scanner.py -u https://my-app.tld --xss --sqli --tech --sarif
case $? in
  0) echo "clean";;
  1) echo "CRITICAL — block deploy"; exit 1;;
  2) echo "HIGH — require security review";;
  3|4) echo "advisory only";;
  10) echo "scanner crashed"; exit 1;;
esac
```

---

## Jenkins pipeline

```groovy
pipeline {
  stages {
    stage('Security scan') {
      steps {
        sh '''
          python3 scanner.py -u "$TARGET_URL" --xss --sqli --tech --sarif --quiet
        '''
        recordIssues(tools: [sarif(pattern: 'scans/**/results.sarif')])
      }
    }
  }
}
```

The `warnings-ng` Jenkins plugin (≥ 11.x) parses SARIF natively; per-build
trends, deltas, and Jira/GitHub mirroring come for free.

---

## GitLab CI

```yaml
security-scan:
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - python3 scanner.py -u "$TARGET_URL" --sarif --json --quiet
  artifacts:
    when: always
    reports:
      sast: scans/*/results.sarif    # GitLab parses SARIF as SAST
    paths:
      - scans/
  allow_failure: false               # exit code gates the pipeline
```

GitLab Ultimate parses SARIF directly into the **Secure → Vulnerability
report** dashboard with merge-request annotations.

---

## Programmatic export

If you want a different format, the internal `Finding` dataclass can be
serialised arbitrarily:

```python
from utils.finding import normalize_all
from utils.reporters import export_burp_xml

# Findings from a programmatic scan or loaded from findings.json
findings = [...]
normalized = normalize_all(findings)

# Burp XML
export_burp_xml([f.to_dict() for f in normalized], "out.xml")

# Custom JSON
import json
with open("custom.json", "w") as f:
    json.dump([f.to_dict() for f in normalized], f, indent=2, default=str)
```
