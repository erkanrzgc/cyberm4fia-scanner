# Human Review Record Template

Informative Appendix (non-normative)

This appendix provides an illustrative template for documenting the human review gate required for critical findings and other high-consequence decisions in autonomous penetration testing workflows. It is intended to help platform operators, customers, and reviewers implement and verify the relevant APTS requirements consistently. It does not prescribe one mandatory format for all platforms.

## Purpose

APTS already requires structured human review and approval records for higher-risk actions and critical findings. In practice, reviewers and customers benefit from a concrete template that shows what a complete human review record should contain.

This appendix shows:

- a compact field set for a finding-level human review record
- an example YAML record
- a JSON-equivalent structure
- review questions customers and reviewers can use when inspecting records
- cross-references to the APTS requirements this artifact helps support

## Primary Use Cases

Use a human review record when the platform needs to document:

- critical finding approval before customer delivery
- reviewer confirmation that evidence was checked and reproduction was assessed
- reviewer disposition decisions such as approve, reject, downgrade, or move to appendix-only treatment
- explicit accountability for a human override or approval event

## Design Principles

A human review record should:

- identify the finding and engagement unambiguously
- capture reviewer identity and qualification clearly
- separate evidence verification from severity or delivery decisions
- record the reviewer decision in a way a third party can audit later
- preserve timestamps and approval/authentication evidence
- be easy to cross-check against audit logs, evidence manifests, and final reports

## Recommended Template Sections

### 1. Record metadata

Use stable identifiers so the review record can be correlated with the finding, engagement, and audit trail.

Recommended fields:

- `review_record_id`
- `engagement_id`
- `finding_id`
- `report_version`
- `review_stage`
- `created_at`
- `last_updated_at`

### 2. Finding summary

Capture enough context for the reviewer to understand what is being approved without relying on memory alone.

Recommended fields:

- `title`
- `severity`
- `confidence_score`
- `classification`
- `affected_assets`
- `finding_status_before_review`

### 3. Reviewer identity and qualification

Document who performed the review and why they were authorized to do so.

Recommended fields:

- `reviewer_name`
- `reviewer_role`
- `reviewer_contact`
- `reviewer_qualification`
- `delegation_basis`

### 4. Evidence and verification checks

Record what the reviewer actually examined.

Recommended fields:

- `evidence_artifacts_reviewed`
- `reproduction_status`
- `reverification_status`
- `provenance_checked`
- `notes_on_evidence_quality`

### 5. Reviewer decision

Make the final human decision explicit and machine-readable.

Recommended fields:

- `decision`
- `delivery_disposition`
- `severity_adjustment`
- `required_follow_up`
- `review_notes`

Suggested decision values:

- `approved`
- `approved_with_notes`
- `rejected`
- `requires_retest`
- `appendix_only`
- `intermittent_confirmed`

### 6. Approval proof and timestamps

Document when approval happened and what authenticated it.

Recommended fields:

- `review_started_at`
- `review_completed_at`
- `approval_timestamp`
- `authentication_method`
- `authentication_reference`
- `signature_token`

## Example YAML Template

```yaml
review_record_id: rr-2026-0042
engagement_id: eng-2026-001
finding_id: finding-critical-007
report_version: 3
review_stage: pre-delivery-critical-review
created_at: 2026-04-20T09:00:00Z
last_updated_at: 2026-04-20T09:12:00Z

finding_summary:
  title: Authenticated remote code execution via plugin upload
  severity: Critical
  confidence_score: 96
  classification: confirmed
  affected_assets:
    - app.example.com
  finding_status_before_review: confirmed

reviewer:
  reviewer_name: Jane Doe
  reviewer_role: Senior Offensive Security Reviewer
  reviewer_contact: jane.doe@example.com
  reviewer_qualification:
    - OSCP
    - 8 years offensive security experience
  delegation_basis: ho-role-senior-reviewer

evidence_verification:
  evidence_artifacts_reviewed:
    - epm-2026-001#artifact-14
    - epm-2026-001#artifact-18
  reproduction_status: reproduced
  reverification_status: reproduced
  provenance_checked: true
  notes_on_evidence_quality: Raw request/response pair and shell output align with reported impact

review_decision:
  decision: approved
  delivery_disposition: include_in_main_report
  severity_adjustment: none
  required_follow_up:
    - include remediation note on plugin signature enforcement
  review_notes: Evidence and reproduction support the reported finding and severity

approval_proof:
  review_started_at: 2026-04-20T09:03:00Z
  review_completed_at: 2026-04-20T09:12:00Z
  approval_timestamp: 2026-04-20T09:12:00Z
  authentication_method: sso-mfa
  authentication_reference: session-9f8b2a
  signature_token: reviewer-approved-2026-0042
```

## JSON-Equivalent Structure

```json
{
  "review_record_id": "rr-2026-0042",
  "engagement_id": "eng-2026-001",
  "finding_id": "finding-critical-007",
  "report_version": 3,
  "review_stage": "pre-delivery-critical-review",
  "created_at": "2026-04-20T09:00:00Z",
  "last_updated_at": "2026-04-20T09:12:00Z",
  "finding_summary": {
    "title": "Authenticated remote code execution via plugin upload",
    "severity": "Critical",
    "confidence_score": 96,
    "classification": "confirmed",
    "affected_assets": ["app.example.com"],
    "finding_status_before_review": "confirmed"
  },
  "reviewer": {
    "reviewer_name": "Jane Doe",
    "reviewer_role": "Senior Offensive Security Reviewer",
    "reviewer_contact": "jane.doe@example.com",
    "reviewer_qualification": ["OSCP", "8 years offensive security experience"],
    "delegation_basis": "ho-role-senior-reviewer"
  },
  "evidence_verification": {
    "evidence_artifacts_reviewed": ["epm-2026-001#artifact-14", "epm-2026-001#artifact-18"],
    "reproduction_status": "reproduced",
    "reverification_status": "reproduced",
    "provenance_checked": true,
    "notes_on_evidence_quality": "Raw request/response pair and shell output align with reported impact"
  },
  "review_decision": {
    "decision": "approved",
    "delivery_disposition": "include_in_main_report",
    "severity_adjustment": "none",
    "required_follow_up": ["include remediation note on plugin signature enforcement"],
    "review_notes": "Evidence and reproduction support the reported finding and severity"
  },
  "approval_proof": {
    "review_started_at": "2026-04-20T09:03:00Z",
    "review_completed_at": "2026-04-20T09:12:00Z",
    "approval_timestamp": "2026-04-20T09:12:00Z",
    "authentication_method": "sso-mfa",
    "authentication_reference": "session-9f8b2a",
    "signature_token": "reviewer-approved-2026-0042"
  }
}
```

## Reviewer Questions

When inspecting a human review record, ask:

- does the record identify the exact finding and report version under review
- is the reviewer qualified and clearly authorized to approve this class of finding
- can the listed evidence artifacts be located and cross-checked against the evidence package or audit trail
- does the decision align with the reproduction and re-verification status
- is the approval authenticated and timestamped in a way that can be independently audited

## Related APTS Requirements

This template can help operators and reviewers implement or verify:

- APTS-RP-002 Finding Verification and Human Review Pipeline
- APTS-HO-004 Authority Delegation Matrix
- APTS-HO-005 Delegation Chain-of-Custody and Decision Audit Trail
- APTS-AR-001 Structured Event Logging with Schema Validation
- APTS-AR-011 Chain of Custody for Evidence

## Notes

This appendix is intentionally lightweight. Organizations may embed these fields into ticketing systems, approval dashboards, signed review forms, or case-management records as long as the resulting artifact remains auditable and cross-referenceable.