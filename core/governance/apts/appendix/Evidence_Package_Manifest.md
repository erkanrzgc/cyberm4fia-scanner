# Evidence Package Manifest

Informative Appendix (non-normative)

This appendix provides an illustrative evidence package manifest for autonomous penetration testing findings and audit artifacts. It is intended to help platform operators, customers, and reviewers connect the Auditability and Reporting requirements into one verifiable handoff artifact. It does not prescribe one mandatory file format.

For a completed fictional package walkthrough, see [Evidence Package Manifest Example](examples/Evidence_Package_Manifest_Example.md).

## Purpose

APTS requires platforms to preserve evidence, hash artifacts, maintain provenance, document chain of custody, and support downstream finding integrity. Those requirements are distributed across multiple domains and can be difficult to implement consistently without a concrete example.

This appendix provides:

- a minimal manifest structure for findings and supporting artifacts
- example YAML and JSON representations
- field guidance for provenance, hashing, redaction, and downstream export references
- review questions customers and auditors can use to validate the platform's evidence pipeline

## Design Principles

A useful evidence package manifest should:

- link one finding to the raw artifacts that support it
- preserve cryptographic integrity for each artifact
- record provenance events from discovery through report generation
- distinguish raw evidence from analyst or model-generated summaries
- record redaction and sensitivity handling decisions
- support downstream exports without breaking chain of custody

## Recommended Manifest Sections

### 1. Finding identity

Use stable identifiers so the manifest can be referenced from reports, tickets, and audit logs.

Recommended fields:

- `engagement_id`
- `finding_id`
- `finding_title`
- `severity`
- `confidence`
- `scope_reference`

### 2. Artifact inventory

Each supporting artifact should have a durable identifier and integrity metadata.

Recommended fields:

- `id`
- `type`
- `path`
- `media_type`
- `sha256`
- `captured_at`
- `captured_by`
- `sensitivity`

### 3. Provenance chain

Capture the lifecycle of the finding across automated and human steps.

Recommended fields:

- `event`
- `timestamp`
- `actor`
- `audit_log_id`
- `result`
- `notes`

### 4. Reproduction and review state

Record how the platform or reviewer validated the claim.

Recommended fields:

- `reproduction_attempts`
- `human_review`
- `review_decision`
- `reviewed_at`

### 5. Redaction and sensitive-data handling

Record what was redacted and why.

Recommended fields:

- `redaction_status`
- `redacted_fields`
- `handling_notes`

### 6. Downstream exports

Track handoff to other systems without severing provenance.

Recommended fields:

- `system`
- `external_id`
- `exported_at`
- `export_hash`

## Example YAML Manifest

```yaml
engagement_id: eng-2026-001
finding_id: apt-find-001
finding_title: Example authenticated path traversal
severity: high
confidence: 0.92
scope_reference: roe-2026-001
summary: |
  The finding was confirmed through a bounded authenticated request sequence and
  independently reproduced before report generation.

artifacts:
  - id: ev-001
    type: http_request_response
    path: evidence/ev-001.http
    media_type: text/plain
    sha256: 6b7c9f7de1b0d9d91234567890abcdef1234567890abcdef1234567890abcd
    captured_at: 2026-04-18T12:00:00Z
    captured_by: platform-http-recorder
    sensitivity: confidential
  - id: ev-002
    type: screenshot
    path: evidence/ev-002.png
    media_type: image/png
    sha256: 9df55d9e0f1c2b3a1234567890abcdef1234567890abcdef1234567890abcd
    captured_at: 2026-04-18T12:01:10Z
    captured_by: browser-capture-service
    sensitivity: restricted

provenance:
  - event: discovery
    actor: autonomous-agent
    audit_log_id: log-123
    timestamp: 2026-04-18T12:00:00Z
    result: suspected
  - event: reproduction
    actor: replay-runner
    audit_log_id: log-456
    timestamp: 2026-04-18T12:10:00Z
    result: reproduced
  - event: human_review
    actor: reviewer-01
    audit_log_id: log-789
    timestamp: 2026-04-18T12:30:00Z
    result: approved

reproduction_attempts:
  - timestamp: 2026-04-18T12:10:00Z
    actor: replay-runner
    status: reproduced
    notes: request sequence replay matched original evidence

human_review:
  reviewer: reviewer-01
  reviewed_at: 2026-04-18T12:30:00Z
  decision: approved
  notes: evidence complete and sufficient for customer verification

redaction:
  redaction_status: partially_redacted
  redacted_fields:
    - session_cookie
    - internal_user_email
  handling_notes: customer-approved redaction policy applied before report export

exports:
  - system: ticketing
    external_id: SEC-123
    exported_at: 2026-04-18T13:00:00Z
    export_hash: 727f49aa1234567890abcdef1234567890abcdef1234567890abcdef1234
```

## Example JSON Shape

```json
{
  "engagement_id": "eng-2026-001",
  "finding_id": "apt-find-001",
  "finding_title": "Example authenticated path traversal",
  "severity": "high",
  "confidence": 0.92,
  "artifacts": [
    {
      "id": "ev-001",
      "type": "http_request_response",
      "path": "evidence/ev-001.http",
      "sha256": "6b7c9f7de1b0d9d91234567890abcdef1234567890abcdef1234567890abcd"
    }
  ],
  "provenance": [
    {
      "event": "discovery",
      "audit_log_id": "log-123",
      "timestamp": "2026-04-18T12:00:00Z",
      "result": "suspected"
    }
  ]
}
```

## Field Mapping to APTS Requirements

| Manifest area | Primary requirements |
| --- | --- |
| Artifact paths and hashes | `APTS-AR-010`, `APTS-RP-005` |
| Chain of custody and transfers | `APTS-AR-011`, `APTS-AR-012` |
| Evidence sensitivity and redaction | `APTS-AR-015`, `APTS-RP-001` |
| Finding provenance and verification | `APTS-RP-001`, `APTS-RP-002`, `APTS-RP-004` |
| Machine-readable reporting handoff | `APTS-RP-011`, `APTS-RP-015` |
| Export integrity to downstream systems | `APTS-RP-015`, `APTS-TP-014` |

## Validation Guidance for Customers and Reviewers

When evaluating a platform's evidence handling, ask:

- Can every reported finding be mapped to raw artifacts with stable hashes?
- Can the operator show the provenance events that link discovery, reproduction, and human review?
- Are redaction decisions recorded explicitly rather than applied silently?
- Can downstream ticket or report exports be tied back to the original evidence package without ambiguity?
- Can the customer verify that the manifest itself stayed consistent across archive, review, and export steps?

## Implementation Notes

Recommended implementation practices:

- generate the manifest as part of the report build pipeline rather than as a manual afterthought
- store the manifest adjacent to evidence artifacts and audit-log references
- avoid embedding raw secrets directly in the manifest; reference redacted artifacts instead
- sign or externally hash the final manifest before customer delivery
- keep machine-generated summaries distinct from raw evidence artifacts

## Non-goals

This appendix does not:

- require one universal manifest format for every operator
- replace the normative requirement text in the Auditability or Reporting domains
- define a complete case-management system for every downstream workflow

Use this appendix as an implementation and review aid for evidence integrity and finding reproducibility.