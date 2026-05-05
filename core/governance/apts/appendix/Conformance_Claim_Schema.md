# Conformance Claim Schema

Informative Appendix (non-normative)

This appendix provides an illustrative machine-readable schema for publishing an APTS conformance claim. It is intended to complement the existing [Conformance Claim Template](Conformance_Claim_Template.md) by giving platform operators, customers, and reviewers a structured format that can be exchanged, validated, archived, and compared consistently.

It does not prescribe one mandatory file format for all platforms.

## Purpose

APTS already provides a human-readable conformance claim template. In practice, teams often also need a machine-readable form that can:

- express the claimed tier and platform metadata consistently
- record requirement-by-requirement status in a structured way
- reference supporting evidence artifacts
- document exceptions, compensating controls, and assessment limitations
- support procurement, internal governance, and periodic reassessment workflows

This appendix offers a practical starter structure without turning one schema into a normative requirement.

## Design Principles

A useful machine-readable conformance claim should:

- map clearly to the existing human-readable conformance claim template
- separate factual metadata from supporting commentary
- allow requirement-level evidence references
- distinguish met, partially met, not met, and not applicable states explicitly
- record who performed the assessment and when
- support future automation without requiring it

## Recommended Top-Level Sections

### 1. Claim metadata

Recommended fields:

- `claim_id`
- `standard_version`
- `published_at`
- `assessment_date`
- `assessment_type`
- `claim_owner`

### 2. Platform information

Recommended fields:

- `platform_name`
- `platform_version`
- `operator_type`
- `deployment_model`
- `foundation_model_disclosure_reference`

### 3. Claimed conformance

Recommended fields:

- `claimed_tier`
- `claimed_domains`
- `autonomy_levels_supported`
- `assessment_scope`

### 4. Requirement status records

Each requirement entry should support:

- `requirement_id`
- `status`
- `rationale`
- `evidence_refs`
- `notes`
- `compensating_controls`

### 5. Evidence references

Recommended fields:

- `id`
- `type`
- `path_or_uri`
- `sha256`
- `captured_at`
- `sensitivity`

### 6. Exceptions and limitations

Recommended fields:

- `requirement_id`
- `exception_type`
- `description`
- `approval_reference`
- `review_by`

### 7. Assessment attestation

Recommended fields:

- `reviewer`
- `organization`
- `method`
- `attestation_statement`

## Example YAML Structure

```yaml
claim_id: apts-claim-2026-001
standard_version: 0.1.0
published_at: 2026-04-18T00:00:00Z
assessment_date: 2026-04-17
assessment_type: internal_self_assessment

claim_owner:
  organization: Example Security Team
  contact: security@example.com

platform:
  platform_name: Example Autonomous Pentest Platform
  platform_version: 2.4.1
  operator_type: enterprise_internal_team
  deployment_model: self_hosted
  foundation_model_disclosure_reference: disclosures/model-disclosure-2026-04.md

claimed_conformance:
  claimed_tier: 2
  claimed_domains:
    - SE
    - SC
    - HO
    - AL
    - AR
    - MR
    - TP
    - RP
  autonomy_levels_supported:
    - L1
    - L2
    - L3
  assessment_scope:
    environments:
      - production_staging
      - non_production
    exclusions:
      - client_side_agents

requirements:
  - requirement_id: APTS-SE-001
    status: met
    rationale: machine-parseable Rules of Engagement enforced before initialization
    evidence_refs:
      - ev-roe-schema
      - ev-scope-validation-log
  - requirement_id: APTS-SC-009
    status: met
    rationale: multi-path kill switch demonstrated in staging and acceptance tests
    evidence_refs:
      - ev-kill-switch-demo
  - requirement_id: APTS-TP-016
    status: not_applicable
    rationale: not claiming Tier 3 conformance
  - requirement_id: APTS-SE-022
    status: partially_met
    rationale: client-side agent support disabled in the current deployment profile
    compensating_controls:
      - feature gated off in production
      - documented deployment restriction

evidence:
  - id: ev-roe-schema
    type: config_sample
    path_or_uri: evidence/roe-schema-example.yaml
    sha256: 39fd1c4b1234567890abcdef1234567890abcdef1234567890abcdef1234
    captured_at: 2026-04-17T12:00:00Z
    sensitivity: internal
  - id: ev-kill-switch-demo
    type: test_recording
    path_or_uri: evidence/kill-switch-demo.mp4
    sha256: 7a1b9eab1234567890abcdef1234567890abcdef1234567890abcdef1234
    captured_at: 2026-04-17T14:10:00Z
    sensitivity: confidential

exceptions:
  - requirement_id: APTS-SE-022
    exception_type: feature_not_deployed
    description: client-side agent support is intentionally disabled in this environment
    approval_reference: arch-review-2026-04
    review_by: 2026-10-01

attestation:
  reviewer: Jane Doe
  organization: Example Security Team
  method: internal_review_with_independent_signoff
  attestation_statement: >
    The above claim reflects the reviewed deployment scope and supporting
    evidence available at the assessment date.
```

## Example JSON Shape

```json
{
  "claim_id": "apts-claim-2026-001",
  "standard_version": "0.1.0",
  "platform": {
    "platform_name": "Example Autonomous Pentest Platform",
    "platform_version": "2.4.1"
  },
  "claimed_conformance": {
    "claimed_tier": 2,
    "claimed_domains": ["SE", "SC", "HO", "AL", "AR", "MR", "TP", "RP"]
  },
  "requirements": [
    {
      "requirement_id": "APTS-SE-001",
      "status": "met",
      "evidence_refs": ["ev-roe-schema", "ev-scope-validation-log"]
    }
  ]
}
```

## Suggested Status Values

Recommended requirement status values:

- `met`
- `partially_met`
- `not_met`
- `not_applicable`
- `planned`

Use explicit values rather than free-form text so reviewers can compare claims more consistently.

## Mapping to the Existing Conformance Claim Template

| Machine-readable area | Human-readable template section |
| --- | --- |
| Claim metadata | title and administrative metadata |
| Platform information | platform/operator overview |
| Claimed conformance | claimed tier and deployment scope |
| Requirement status records | requirement-by-requirement claim body |
| Evidence references | supporting evidence and appendices |
| Exceptions and limitations | caveats, limitations, and compensating controls |
| Assessment attestation | reviewer signoff or assessment statement |

## Validation Guidance for Customers and Reviewers

When evaluating a machine-readable conformance claim, ask:

- Does the claim identify the exact APTS version and platform version under review?
- Are all requirement statuses explicit rather than implied?
- Can each `met` or `partially_met` requirement be traced to one or more evidence references?
- Are exceptions and compensating controls documented separately from fully met requirements?
- Does the machine-readable claim stay consistent with the published human-readable conformance claim?

## Implementation Notes

Recommended implementation practices:

- keep the human-readable and machine-readable claim artifacts versioned together
- validate the structured claim against a documented internal schema before publication
- use stable evidence identifiers rather than embedding large evidence bodies directly
- record reassessment dates for recurring or materially changed deployments
- treat the machine-readable claim as a companion artifact, not a replacement for narrative explanation

## Non-goals

This appendix does not:

- require all APTS operators to publish machine-readable conformance claims
- define a certification workflow or scoring system
- replace the existing [Conformance Claim Template](Conformance_Claim_Template.md)

Use this appendix as a practical interoperability and review aid for teams that want a structured conformance artifact.