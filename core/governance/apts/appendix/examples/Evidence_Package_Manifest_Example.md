# Evidence Package Manifest Example

Informative Appendix Example (non-normative)

This fictional example shows how the [Evidence Package Manifest](../Evidence_Package_Manifest.md) can be used to organize one verified finding, its supporting artifacts, and its handoff trail. It is not a required format and does not replace the manifest guidance, auditability requirements, or reporting requirements.

The sample uses fictional systems, identifiers, hashes, and file names. Replace them with operator-specific evidence references, retention rules, and customer-approved redaction decisions.

---

## Scenario

A customer authorized an autonomous web application test against a staging API. The platform reported a high-severity authorization bypass after confirming that the affected endpoint was in scope, reproducing the request sequence, and routing the finding through human review before report export.

| Field | Example Value |
|-------|---------------|
| **Engagement ID** | `eng-2026-042` |
| **Finding ID** | `APT-FIND-2026-042-003` |
| **Finding Title** | Example authorization bypass in staging API |
| **Customer Scope Reference** | `roe-2026-042-v3.yaml` |
| **Claimed Severity** | High |
| **Confidence** | 0.91 |
| **Report Export ID** | `report-export-2026-042-final` |

---

## Example Package Layout

```text
evidence-package/
├── manifest.yaml
├── artifacts/
│   ├── ev-001-scope-check.json
│   ├── ev-002-request-response.har
│   ├── ev-003-replay-result.json
│   ├── ev-004-human-review.md
│   └── ev-005-redaction-log.json
└── exports/
    ├── customer-report.pdf
    └── ticket-export.json
```

---

## Example Manifest

```yaml
manifest_version: 1
engagement_id: eng-2026-042
finding_id: APT-FIND-2026-042-003
finding_title: Example authorization bypass in staging API
severity: high
confidence: 0.91
scope_reference: roe-2026-042-v3.yaml
created_at: 2026-04-21T17:40:00Z
manifest_hash: 3a8c5d0e111122223333444455556666777788889999aaaabbbbccccddddeeee  # Hash of the canonical manifest excluding this field

scope_context:
  target: api.staging.example.invalid
  environment: staging
  allowed_window: 2026-04-21T16:00:00Z/2026-04-21T20:00:00Z
  autonomy_level: L2 Supervised
  scope_decision_log_id: ar-log-2026-042-00071

artifacts:
  - id: ev-001
    type: scope_validation
    path: artifacts/ev-001-scope-check.json
    media_type: application/json
    sha256: 111122223333444455556666777788889999aaaabbbbccccddddeeee0000ffff
    captured_at: 2026-04-21T17:08:11Z
    captured_by: scope-enforcement-service
    sensitivity: internal
    supports:
      - APTS-SE-006
      - APTS-SE-015
  - id: ev-002
    type: http_request_response
    path: artifacts/ev-002-request-response.har
    media_type: application/json
    sha256: 22223333444455556666777788889999aaaabbbbccccddddeeee00001111ffff
    captured_at: 2026-04-21T17:09:04Z
    captured_by: http-recorder
    sensitivity: restricted
    redaction_status: redacted
    supports:
      - APTS-AR-010
      - APTS-RP-001
      - APTS-RP-005
  - id: ev-003
    type: reproduction_result
    path: artifacts/ev-003-replay-result.json
    media_type: application/json
    sha256: 3333444455556666777788889999aaaabbbbccccddddeeee000011112222ffff
    captured_at: 2026-04-21T17:18:32Z
    captured_by: replay-runner
    sensitivity: internal
    supports:
      - APTS-RP-001
      - APTS-RP-004
  - id: ev-004
    type: human_review_record
    path: artifacts/ev-004-human-review.md
    media_type: text/markdown
    sha256: 444455556666777788889999aaaabbbbccccddddeeee0000111122223333ffff
    captured_at: 2026-04-21T17:33:10Z
    captured_by: reviewer-queue
    sensitivity: confidential
    supports:
      - APTS-RP-002
  - id: ev-005
    type: redaction_log
    path: artifacts/ev-005-redaction-log.json
    media_type: application/json
    sha256: 55556666777788889999aaaabbbbccccddddeeee00001111222233334444ffff
    captured_at: 2026-04-21T17:35:00Z
    captured_by: report-redaction-service
    sensitivity: internal
    supports:
      - APTS-AR-015
      - APTS-RP-005

provenance:
  - event: scope_check
    timestamp: 2026-04-21T17:08:11Z
    actor: scope-enforcement-service
    audit_log_id: ar-log-2026-042-00071
    result: in_scope
    evidence_id: ev-001
  - event: finding_detected
    timestamp: 2026-04-21T17:09:04Z
    actor: autonomous-agent
    audit_log_id: ar-log-2026-042-00088
    result: suspected
    evidence_id: ev-002
  - event: reproduction
    timestamp: 2026-04-21T17:18:32Z
    actor: replay-runner
    audit_log_id: ar-log-2026-042-00120
    result: reproduced
    evidence_id: ev-003
  - event: human_review
    timestamp: 2026-04-21T17:33:10Z
    actor: qualified-reviewer-07
    audit_log_id: ar-log-2026-042-00145
    result: approved_for_report
    evidence_id: ev-004
  - event: report_redaction
    timestamp: 2026-04-21T17:35:00Z
    actor: report-redaction-service
    audit_log_id: ar-log-2026-042-00152
    result: redacted
    evidence_id: ev-005

reproduction:
  status: reproduced
  attempts:
    - timestamp: 2026-04-21T17:18:32Z
      actor: replay-runner
      result: reproduced
      notes: Bounded request replay produced the same authorization decision without accessing production data.
  reviewer_confirmation:
    reviewer: qualified-reviewer-07
    reviewed_at: 2026-04-21T17:33:10Z
    decision: approved_for_report
    notes: Evidence shows in-scope staging target, reproducible behavior, and customer-safe redactions.

redaction:
  status: redacted
  policy_reference: redaction-policy-2026-01
  redacted_fields:
    - example session identifier
    - internal staging user name
    - customer-specific path segment
  reviewer: qualified-reviewer-07
  notes: Raw values remain in restricted evidence storage; customer report contains redacted placeholders only.

chain_of_custody:
  - timestamp: 2026-04-21T17:40:00Z
    actor: evidence-archive-service
    action: package_created
    storage_location: restricted-evidence-vault
    audit_log_id: ar-log-2026-042-00160
  - timestamp: 2026-04-21T18:00:00Z
    actor: report-export-service
    action: customer_report_exported
    storage_location: customer-delivery-portal
    audit_log_id: ar-log-2026-042-00188

exports:
  - system: customer_report
    path: exports/customer-report.pdf
    exported_at: 2026-04-21T18:00:00Z
    export_hash: 6666777788889999aaaabbbbccccddddeeee000011112222333344445555ffff
  - system: ticketing
    external_id: SEC-2026-1042
    path: exports/ticket-export.json
    exported_at: 2026-04-21T18:05:00Z
    export_hash: 777788889999aaaabbbbccccddddeeee0000111122223333444455556666ffff
```

---

## Requirement Traceability

| Manifest Element | Example Evidence | Related Requirements |
|------------------|------------------|----------------------|
| Scope context and pre-action decision | `ev-001-scope-check.json` | APTS-SE-006, APTS-SE-015 |
| Raw request/response artifact with hash | `ev-002-request-response.har` | APTS-AR-010, APTS-RP-005 |
| Reproduction result | `ev-003-replay-result.json` | APTS-RP-001, APTS-RP-004 |
| Human review record | `ev-004-human-review.md` | APTS-RP-002 |
| Redaction log | `ev-005-redaction-log.json` | APTS-AR-015, APTS-RP-005 |
| Export hashes and custody events | `customer-report.pdf`, `ticket-export.json` | APTS-AR-010, APTS-AR-011, APTS-RP-005, APTS-RP-015 |

---

## Customer Review Walkthrough

A customer or reviewer can use the manifest to ask focused verification questions:

1. **Scope:** Does `ev-001` show that the target, time window, and action were in scope before the request was sent?
2. **Integrity:** Do artifact hashes match the files delivered in the evidence package?
3. **Provenance:** Can the operator trace discovery, reproduction, review, redaction, and export through audit log IDs?
4. **Reproducibility:** Does `ev-003` show a bounded replay that supports the finding without unnecessary production impact?
5. **Human review:** Does `ev-004` identify the reviewer, decision, timestamp, and evidence considered?
6. **Redaction:** Does `ev-005` explain what was redacted and where raw restricted evidence is retained?
7. **Downstream handoff:** Can the final report and ticket export be tied back to the same finding, evidence package, and custody trail?

---

## Common Pitfalls This Example Avoids

- Reporting a finding without preserving the pre-action scope decision
- Mixing raw evidence, model summaries, and reviewer conclusions without provenance
- Redacting sensitive values without recording the redaction decision
- Exporting a ticket or report without a hash tying it back to the evidence package
- Treating human approval as a free-text comment instead of an auditable review event

---

> **Disclaimer:** This example is fictional and non-normative. It illustrates one possible evidence package structure and does not mandate field names, file formats, storage layout, or customer disclosure obligations.
