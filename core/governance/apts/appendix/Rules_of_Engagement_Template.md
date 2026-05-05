# Rules of Engagement Template

Informative Appendix (non-normative)

This appendix provides an illustrative machine-readable Rules of Engagement (RoE) template for autonomous penetration testing engagements. It is intended to help platform operators, customers, and reviewers implement and verify the requirements in the Scope Enforcement, Human Oversight, and Graduated Autonomy domains. It does not prescribe one mandatory format for all platforms.

## Purpose

APTS requires platforms to ingest and validate machine-parseable Rules of Engagement before testing begins. In practice, customers and operators benefit from a concrete starter template that makes those requirements easier to implement, exchange, and review consistently.

This appendix shows:

- a minimal YAML example
- an XML example
- a JSON-equivalent structure
- field-level guidance connecting the template to relevant APTS requirements
- review questions customers and reviewers can use during evaluation

## Design Principles

A machine-readable RoE template should:

- separate authorization, scope, and safety controls into explicit fields
- be strict enough for automated validation and pre-action enforcement
- be versioned and auditable
- default-deny when required sections are missing or ambiguous
- support both one-time and recurring engagements
- support review by customers, operators, and independent reviewers

## Recommended Template Sections

### 1. Engagement metadata

Use stable identifiers so the platform can correlate findings, audit logs, approvals, and recurring test cycles.

Recommended fields:

- `engagement_id`
- `roe_version`
- `engagement_model`
- `created_at`
- `updated_at`
- `customer_reference`

### 2. Authorization

Capture the authoritative approval chain for the engagement.

Recommended fields:

- `customer`
- `asset_owner`
- `approval_reference`
- `valid_from`
- `valid_until`
- `approvers`

### 3. Temporal boundaries

Represent all authorized test windows in a machine-enforceable form.

Recommended fields:

- `timezone`
- `start_time`
- `end_time`
- `maintenance_windows`
- `maximum_run_duration_minutes`

### 4. Targets

Define the allowed target universe explicitly.

Recommended fields:

- `domains`
- `ip_ranges`
- `cloud`
- `api`
- `client_side_agents`

### 5. Asset criticality and hard deny list

Document production sensitivity and explicit no-test assets.

Recommended fields:

- `asset_criticality`
- `hard_deny_list`
- `sensitive_data_locations`

### 6. Allowed and prohibited actions

Translate contractual or operational limits into machine-enforceable controls.

Recommended fields:

- `allowed_actions`
- `prohibited_actions`
- `requires_explicit_human_approval`

### 7. Rate limiting and production impact controls

Document the operational safety envelope.

Recommended fields:

- `per_target_rps`
- `global_rps`
- `max_payload_size`
- `backoff_on_error_rate_percent`
- `health_degradation_stop_threshold`

### 8. Credential policy

Define how credentials and secrets may be used, stored, delegated, and destroyed.

Recommended fields:

- `client_provided`
- `platform_issued`
- `discovered_credentials`
- `reuse_restrictions`
- `revoke_at_end`

### 9. Authority delegation reference and escalation

Reference the Authority Delegation Matrix that governs who may approve higher-risk actions. The RoE may identify engagement-specific escalation contacts and timeout behavior, but it should not redefine approval authority that belongs in the ADM.

Recommended fields:

- `authority_delegation_matrix`
- `timeout_behavior`
- `escalation_contacts`
- `kill_switch_contacts`

## Example YAML Template

```yaml
engagement_id: eng-2026-001
roe_version: 1
engagement_model: one_time
created_at: 2026-04-18T00:00:00Z
updated_at: 2026-04-18T00:00:00Z
customer_reference: customer-2026-q2

authorization:
  customer: Example Corp
  asset_owner: app-team@example.com
  approval_reference: signed-roe-2026-001
  valid_from: 2026-04-18T00:00:00Z
  valid_until: 2026-04-20T00:00:00Z
  approvers:
    - name: Security Lead
      contact: security-lead@example.com
    - name: Asset Owner
      contact: app-owner@example.com

temporal_boundaries:
  timezone: UTC
  start_time: 2026-04-18T02:00:00Z
  end_time: 2026-04-18T06:00:00Z
  maximum_run_duration_minutes: 240
  maintenance_windows:
    - start: 2026-04-18T03:00:00Z
      end: 2026-04-18T03:30:00Z
      action: pause

targets:
  domains:
    - name: app.example.com
      wildcard_policy: exact_only
    - name: api.example.com
      wildcard_policy: exact_only
  ip_ranges:
    - 203.0.113.0/24
  cloud:
    accounts:
      - id: prod-account-1
        provider: aws
        regions:
          - us-east-1
  api:
    base_urls:
      - https://api.example.com
    allowed_methods:
      - GET
      - POST
  client_side_agents:
    allowed: false

asset_criticality:
  default: unknown
  assets:
    - target: app.example.com
      criticality: production
    - target: api.example.com
      criticality: production

hard_deny_list:
  - target: 169.254.169.254
    reason: cloud metadata endpoint
  - target: idp.example.com
    reason: identity provider
  - target: db-prod.example.com
    reason: production database

allowed_actions:
  - passive_reconnaissance
  - authenticated_read_only_checks
  - bounded_exploitation_attempts

prohibited_actions:
  - destructive_testing
  - persistence
  - lateral_movement
  - social_engineering
  - data_exfiltration

requires_explicit_human_approval:
  - credential_use
  - data_access
  - configuration_change
  - client_side_agent_activation

rate_limits:
  per_target_rps: 10
  global_rps: 50
  max_payload_size: 1048576
  backoff_on_error_rate_percent: 20
  health_degradation_stop_threshold: 0.2

credential_policy:
  client_provided: allowed
  platform_issued: allowed
  discovered_credentials: do_not_use_without_approval
  reuse_restrictions:
    - no_cross_target_reuse
    - no_post_engagement_reuse
  revoke_at_end: true

authority_delegation_matrix:
  matrix_id: adm-2026-001
  version: "1.0"
  effective_from: "2026-04-01T00:00:00Z"
  approval_reference: approval-ticket-2026-041
  role_binding_reference: shift-roster-2026-04-18-day

timeout_behavior:
  medium_risk: deny
  high_risk: deny
  critical_risk: pause_and_escalate

incident_and_stop_conditions:
  kill_switch_contacts:
    - secops@example.com
  stop_on_scope_violation: true
  stop_on_target_degradation: true
  legal_escalation_contact: legal@example.com

reporting_and_evidence:
  evidence_retention_days: 90
  classification_default: confidential
  report_recipients:
    - security-lead@example.com
    - app-owner@example.com
```

## Example JSON Shape

```json
{
  "engagement_id": "eng-2026-001",
  "roe_version": 1,
  "engagement_model": "one_time",
  "authorization": {
    "customer": "Example Corp",
    "approval_reference": "signed-roe-2026-001"
  },
  "temporal_boundaries": {
    "timezone": "UTC",
    "start_time": "2026-04-18T02:00:00Z",
    "end_time": "2026-04-18T06:00:00Z"
  },
  "targets": {
    "domains": [
      { "name": "app.example.com", "wildcard_policy": "exact_only" }
    ],
    "ip_ranges": ["203.0.113.0/24"]
  },
  "allowed_actions": ["passive_reconnaissance", "authenticated_read_only_checks"],
  "prohibited_actions": ["destructive_testing", "lateral_movement"]
}
```

## Example XML Shape

```xml
<rules_of_engagement>
  <engagement_id>eng-2026-001</engagement_id>
  <roe_version>1</roe_version>
  <engagement_model>one_time</engagement_model>
  <authorization>
    <customer>Example Corp</customer>
    <approval_reference>signed-roe-2026-001</approval_reference>
  </authorization>
  <temporal_boundaries>
    <timezone>UTC</timezone>
    <start_time>2026-04-18T02:00:00Z</start_time>
    <end_time>2026-04-18T06:00:00Z</end_time>
  </temporal_boundaries>
  <targets>
    <domains>
      <domain wildcard_policy="exact_only">app.example.com</domain>
    </domains>
    <ip_ranges>
      <cidr>203.0.113.0/24</cidr>
    </ip_ranges>
  </targets>
  <allowed_actions>
    <action>passive_reconnaissance</action>
    <action>authenticated_read_only_checks</action>
  </allowed_actions>
  <prohibited_actions>
    <action>destructive_testing</action>
    <action>lateral_movement</action>
  </prohibited_actions>
</rules_of_engagement>
```

## Field Mapping to APTS Requirements

| Template area | Primary requirements |
| --- | --- |
| Authorization | `APTS-SE-001`, `APTS-HO-004` |
| Temporal boundaries | `APTS-SE-004`, `APTS-SE-008`, `APTS-SE-017` |
| Domains and IP ranges | `APTS-SE-002`, `APTS-SE-003`, `APTS-SE-012` |
| Asset criticality and deny list | `APTS-SE-005`, `APTS-SE-009`, `APTS-SE-010` |
| Per-action scope validation inputs | `APTS-SE-006`, `APTS-SE-024`, `APTS-SE-025` |
| Rate limits and impact controls | `APTS-SE-019`, `APTS-SC-004`, `APTS-SC-010` |
| Credential policy | `APTS-SE-023`, `APTS-MR-019` |
| Approval and escalation reference | `APTS-HO-001`, `APTS-HO-003`, `APTS-HO-004`, `APTS-HO-011` |
| Agent-specific boundaries | `APTS-SE-022`, `APTS-AL-014` |

## Validation Guidance for Customers and Reviewers

When reviewing a platform's RoE implementation, ask:

- Can the platform reject an RoE file that omits time boundaries, authorization proof, or target lists?
- Does the platform default-deny ambiguous wildcards, missing asset criticality, or incomplete approval fields?
- Can the platform map every network action back to one RoE field and one audit-log entry?
- Can the platform demonstrate that production deny list entries override broader scope includes?
- Can the customer independently inspect the machine-readable RoE that the platform actually enforced?

## Implementation Notes

Recommended implementation practices:

- use explicit schema validation before engagement start
- store accepted RoE documents with version history and hashes
- reject free-form overrides that are not represented in the validated RoE object
- log every material RoE-derived decision with the source field reference
- require re-validation whenever the RoE changes during a recurring engagement

## Non-goals

This appendix does not:

- create a new mandatory file format for all APTS-conformant platforms
- replace the normative requirement text in the domain READMEs
- attempt to capture every legal or commercial clause in an engagement contract

Use this template as an implementation and review aid rather than a required canonical schema.
