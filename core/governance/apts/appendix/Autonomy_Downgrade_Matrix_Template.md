# Autonomy Downgrade Matrix Template

This appendix is informative and does not create or modify APTS requirements.

## Purpose

Use this template to define how an autonomous penetration testing platform pauses, caps, or downgrades autonomy when safety, scope, incident, or trust-boundary signals indicate that the current autonomy level may no longer be appropriate. It supports APTS-AL-025 and APTS-AL-026 by making downgrade triggers, required approvals, evidence preservation, and re-authorization conditions explicit before incidents occur.

The matrix should be tailored to the platform's operating model, customer requirements, Rules of Engagement, and Authority Delegation Matrix. It can be implemented as a table, policy-as-code artifact, incident-response runbook, or approval workflow.

## How to Use This Template

1. Define the platform's permitted autonomy levels and the authority required to authorize each level.
2. Identify events that require pause, downgrade, or re-authorization review.
3. For each event, document the maximum permitted autonomy level until the condition is resolved.
4. Define who can approve resumption or re-escalation and what evidence must be preserved.
5. Review the matrix after incidents, major model/tool changes, and customer-specific RoE changes.

## Matrix Metadata

| Field | Example / guidance |
|-------|--------------------|
| Matrix ID | `autonomy-downgrade-matrix-2026-04` |
| Platform / deployment | Product, tenant, environment, or service name |
| Applicable RoE | RoE document ID and version |
| Authority reference | Authority Delegation Matrix ID/version |
| Supported autonomy levels | L1, L2, L3, L4, or a platform-specific subset |
| Owner | Role responsible for maintaining the matrix |
| Review cadence | At least after incidents, model/tool changes, or RoE updates |
| Last reviewed | Timestamp and reviewer |

## Downgrade Decision Matrix

| Trigger | Examples | Immediate response | Temporary autonomy cap | Approval to resume / re-escalate | Evidence to preserve |
|---------|----------|--------------------|------------------------|----------------------------------|----------------------|
| Scope boundary uncertainty | Conflicting asset ownership, DNS drift, wildcard ambiguity, unexpected redirect into excluded target | Pause affected action and require operator review | L1 for affected scope | Scope owner or authorized operator | Scope decision log, target identifier, request/response evidence |
| Confirmed scope violation | Action executed outside approved scope or time window | Halt affected workflow and start incident process | L1 or testing halted | Customer contact plus escalation authority | Full action trace, audit log, timestamps, affected assets |
| Customer-impact threshold breach | Error rate, latency, resource use, or service instability exceeds RoE limit | Activate safety controls and stop high-impact actions | L1 until impact reviewed | Customer contact and safety authority | Metrics, alerts, rollback state, customer notification record |
| Unexpected credential or sensitive-data access | Discovery of production secrets, privileged tokens, or regulated data beyond planned testing | Stop chain, preserve evidence, and escalate | L1 | Dual approval or named escalation authority | Evidence hash, redaction record, custody log, affected data categories |
| Tool or connector overreach | Browser agent, scanner, shell runner, MCP-style connector, or data connector attempts capability outside its approval profile | Disable or isolate connector | L1 until connector reviewed | Platform owner or connector authority | Connector config, invocation log, credential scope, network/file access evidence |
| Prompt-injection or instruction-manipulation signal | External content attempts to override RoE, widen target scope, exfiltrate data, or suppress logging | Isolate input/source and require human decision | L2 or lower for affected workflow | Security reviewer or manipulation-resistance owner | Prompt/input transcript, model/tool output, decision log |
| Model or provider behavior drift | Foundation model update, decision-pattern anomaly, unexplained approval-rate change, or degraded refusal behavior | Pause higher-autonomy decisions and investigate | L2 until re-attested | Model/platform owner plus independent reviewer | Model/version metadata, telemetry, comparison results, re-attestation evidence |
| Audit or evidence integrity gap | Missing logs, hash mismatch, timestamp gap, custody ambiguity, or non-reproducible finding chain | Stop actions that depend on unverifiable evidence | L1 until evidence integrity restored | Audit owner or independent reviewer | Missing/invalid records, hash comparison, remediation action |
| Operator unavailable or handoff incomplete | On-call operator unreachable, stale approvals, incomplete shift handoff, or authority transfer unclear | Expire pending approvals and pause queued actions | L1 until incoming operator accepts handoff | Incoming operator and escalation path | Handoff record, approval queue, notification attempts |
| Incident-response activation | SEV-1/SEV-2 incident, watchdog alert, isolation breach, or external provider compromise | Follow incident-response runbook | Testing halted or L1 | Incident commander and customer contact | Incident timeline, containment actions, customer communications |
| Corrective action pending | Root cause known but fix, rollback, or safety-control re-verification incomplete | Resume only bounded validation if approved | L1/L2 as documented | Different authority than incident manager for re-escalation | Root cause analysis, corrective-action proof, safety-control test results |

## Required Response Fields

For each matrix row, define:

- **Trigger condition:** Observable event that causes review, pause, downgrade, or halt.
- **Detection source:** Monitoring rule, operator report, customer alert, audit check, or automated guardrail.
- **Immediate response:** What the platform must do before further autonomous action.
- **Autonomy cap:** Maximum level allowed while the trigger remains unresolved.
- **Approval path:** Role or authority required to resume or re-escalate.
- **Evidence requirements:** Audit, telemetry, and customer-facing evidence to preserve.
- **Re-authorization condition:** Objective condition that must be satisfied before returning to the previous level.

## Example Policy-as-Code Shape

The following illustrative YAML fragment shows how a platform might encode downgrade rules. It is not a required format.

```yaml
matrix_id: "autonomy-downgrade-matrix-2026-04"
applies_to:
  roe_id: "roe-customer-a-2026-q2"
  authority_delegation_matrix: "adm-2026-04"
  supported_levels: ["L1", "L2", "L3", "L4"]
rules:
  - trigger_id: "scope_boundary_uncertainty"
    detection_sources:
      - "scope_validator"
      - "operator_report"
    immediate_response: "pause_affected_action"
    temporary_autonomy_cap: "L1"
    approval_to_resume:
      - "scope_owner"
      - "authorized_operator"
    evidence_to_preserve:
      - "scope_decision_log"
      - "target_identifier"
      - "request_response_trace"
    reauthorization_condition: "scope_owner_confirms_target_and_window"

  - trigger_id: "tool_connector_overreach"
    detection_sources:
      - "connector_policy_guard"
      - "audit_log_review"
    immediate_response: "disable_or_isolate_connector"
    temporary_autonomy_cap: "L1"
    approval_to_resume:
      - "platform_owner"
      - "connector_authority"
    evidence_to_preserve:
      - "connector_configuration"
      - "tool_invocation_log"
      - "credential_scope_record"
    reauthorization_condition: "connector_profile_reviewed_and_reapproved"
```

## Re-Authorization Checklist

Before returning to the previous autonomy level, verify:

- [ ] the trigger condition is resolved or explicitly accepted by the authorized party
- [ ] root cause analysis is documented for incidents or boundary failures
- [ ] corrective actions are implemented and independently verified where required
- [ ] safety controls, scope enforcement, and audit logging are re-tested for the affected path
- [ ] customer notification and approval requirements are satisfied when applicable
- [ ] re-authorization is approved by the required role and recorded in the audit trail
- [ ] any required cooling-off period or independent review condition has been met

## Reviewer Questions

- Does each trigger define an immediate safe response rather than relying on ad hoc operator judgment?
- Is the autonomy cap conservative enough for the unresolved condition?
- Are tool, connector, prompt-injection, and evidence-integrity failures represented alongside traditional incident triggers?
- Does the matrix name the authority required to resume or re-escalate?
- Can every downgrade, re-authorization, and exception be reconciled against the audit trail?
- Are customer approval and notification requirements clear for customer-impact or scope-boundary events?

## Related Requirements and Appendices

- APTS-SE-006: Pre-Action Scope Validation
- APTS-SC-009: Kill Switch
- APTS-SC-018: Incident Containment and Recovery
- APTS-HO-011 through APTS-HO-014: Escalation triggers
- APTS-HO-019: 24/7 Operational Continuity and Shift Handoff
- APTS-AL-018: Incident Response During Autonomous Testing
- APTS-AL-025: Autonomy Level Authorization, Transition, and Reauthorization
- APTS-AL-026: Incident Investigation and Autonomy Level Adjustment
- APTS-MR-018: AI Model Input/Output Architectural Boundary
- APTS-TP-022: Re-attestation on Material Foundation Model Change
- [Authority Delegation Matrix Template](Authority_Delegation_Matrix_Template.md)
- [Incident Response Integration](Incident_Response_Integration.md)
- [Rules of Engagement Template](Rules_of_Engagement_Template.md)
