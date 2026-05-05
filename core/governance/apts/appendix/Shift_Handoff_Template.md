# Shift Handoff Template

This appendix is informative and does not create or modify APTS requirements.

## Purpose

Use this template to document operational continuity when responsibility for an autonomous penetration testing engagement transfers from one operator or shift to another. It supports APTS-HO-019 by making active engagement state, pending decisions, safety signals, and authority changes explicit before the incoming operator allows testing to continue.

The template is intentionally lightweight. Teams may implement it as a ticket form, runbook section, dashboard workflow, or signed record in the platform, provided the handoff record is preserved with the engagement audit trail.

## When to Use This Template

Use a handoff record when any of the following occur:

- an always-on or long-running engagement crosses an operator shift boundary
- kill-switch authority, approval authority, or escalation responsibility changes hands
- approvals granted by an outgoing operator may be acted on by an incoming operator
- active alert suppressions, scope exceptions, or safety concerns remain open
- customer-impact, incident-response, or autonomy-downgrade decisions are pending

## Handoff Metadata

| Field | Example / guidance |
|-------|--------------------|
| Handoff ID | `handoff-2026-04-18-day-to-night` |
| Engagement ID | Customer, workspace, or engagement identifier |
| Platform / environment | Production service, customer tenant, or internal deployment |
| Outgoing operator | Name, role ID, and contact method |
| Incoming operator | Name, role ID, and contact method |
| Handoff time | Timestamp with timezone |
| Covered operating window | Start and end time for the incoming shift |
| Current testing phase | Reconnaissance, validation, exploitation, reporting, cleanup, or paused |
| Applicable Rules of Engagement | RoE document ID and version |
| Authority Delegation Matrix reference | Matrix ID/version and applicable role row |
| Audit log reference | Link or identifier for the handoff record in the audit trail |

## Current Engagement State

| Field | Status / notes |
|-------|----------------|
| Engagement status | active / paused / completing / incident-response / customer hold |
| Current autonomy level | L1 / L2 / L3 / L4 and reason for current level |
| Active target set | Targets currently in scope for automated or operator-directed action |
| Excluded or paused targets | Assets excluded, paused, or awaiting customer clarification |
| Current rate limits / blast-radius limits | Any temporary throttles or extra safeguards in force |
| Active safety controls | Kill switch, pause, rollback, health monitoring, watchdogs |
| Current kill-switch authority | Primary, secondary, emergency authority, and escalation path |
| Customer contacts on duty | Customer or stakeholder contacts for escalation during the shift |

## Pending Operator Decisions

Use this section to prevent stale approvals from silently carrying across shifts.

| Decision ID | Action / context | Requested by | Current status | Expiry | Incoming-shift action |
|-------------|------------------|--------------|----------------|--------|-----------------------|
| `approval-001` | Example: high-impact payload validation against target group A | Operator or system | pending / approved / rejected / expired | Time and timezone | re-review / re-request / cancel / proceed |

For each pending item, record whether the incoming operator must re-approve the action before execution. Critical or irreversible actions should require synchronous confirmation rather than inherited approval.

## Open Escalations and Safety Signals

| Signal | Requirement area | Current response | Owner | Required next action |
|--------|------------------|------------------|-------|----------------------|
| Scope anomaly | SE / HO / AL | paused affected action | incoming operator | confirm scope before resuming |
| Suppression rule active | HO-019 | review due during next shift | incoming operator | justify, expire, or remove suppression |
| Customer-impact warning | SC / HO / AL | monitoring increased | escalation lead | notify if threshold crossed |
| Model/tool behavior anomaly | AL / MR / TP | autonomy capped | platform owner | investigate before re-escalation |

## Desensitization Monitoring

Use this section to make alert-fatigue and response-time degradation visible to the incoming shift. The handoff should capture whether operators are still responding to safety signals promptly or whether suppressions, repeated alerts, or delayed acknowledgments indicate reduced monitoring effectiveness.

| Indicator | Current trend / evidence | Outgoing-shift notes | Incoming-shift action |
|-----------|--------------------------|----------------------|-----------------------|
| Safety-alert response time | Stable / increasing / decreasing; include dashboard or log reference | Note delayed responses, missed pages, or escalation delays | continue monitoring / escalate / restore notification channel |
| Alert acknowledgment rate | Percentage or count acknowledged during outgoing shift | Note unacknowledged alerts or repeated snoozes | review backlog / assign owner / remove stale suppression |
| Alert-fatigue indicators | Repeated dismissals, muted channels, duplicate alerts, or operator overload | Note whether fatigue may affect critical-signal handling | reduce noise / escalate staffing / lower autonomy level |
| Suppression pressure | New, extended, or contested suppression rules | Note justification, expiry, and safety impact | expire / re-justify / remove before resuming |

## Active Findings and Evidence

| Item | Status / notes |
|------|----------------|
| Findings under validation | IDs, affected targets, confidence, pending reviewer actions |
| Evidence packages in progress | Manifest IDs, hash status, redaction status, storage location |
| Customer-visible findings pending review | Items that may require notification or report inclusion |
| Cleanup / rollback state | Reversible actions that still need verification |
| Evidence integrity concerns | Missing hashes, timestamp gaps, custody changes, or export issues |

## Tool and Connector State

Document externally connected tools so the incoming operator understands which capabilities remain active.

| Connector / tool | Capability | Credential scope | Current state | Required incoming action |
|------------------|------------|------------------|---------------|--------------------------|
| Browser agent | Web interaction | Engagement-scoped account | enabled / disabled / paused | review session state |
| Scanner | Network testing | Target-scoped token | enabled / disabled / paused | confirm rate limits |
| Shell or runner | Code execution | Sandbox-scoped identity | enabled / disabled / paused | confirm boundary controls |
| Data connector | Evidence retrieval | Read-only evidence store | enabled / disabled / paused | confirm audit logging |

Include any emergency revocations, temporary credentials, or connector-specific approval constraints that apply during the incoming shift.

## Incoming Operator Acceptance Checklist

The incoming operator should complete this checklist before permitting queued or autonomous actions to continue.

- [ ] I reviewed the active scope, exclusions, and paused targets.
- [ ] I reviewed current autonomy level and any temporary autonomy caps.
- [ ] I can activate the applicable kill switch and understand the escalation path.
- [ ] I reviewed all pending approvals and identified any that require re-approval.
- [ ] I reviewed active suppressions and their expiry or re-justification deadlines.
- [ ] I reviewed desensitization indicators, including response-time trends and alert acknowledgment rates.
- [ ] I reviewed open safety signals, incidents, or customer-impact concerns.
- [ ] I reviewed active tools/connectors and any elevated credential state.
- [ ] I confirmed access to dashboards, logs, notifications, and customer contacts.
- [ ] I accepted responsibility for the incoming operating window in the audit trail.

## Sign-Off

| Role | Name / ID | Timestamp | Notes |
|------|-----------|-----------|-------|
| Outgoing operator |  |  | Handoff prepared and transferred |
| Incoming operator |  |  | Handoff reviewed and accepted |
| Escalation authority, if applicable |  |  | Required only when authority changes or open escalations exist |

## Reviewer Questions

- Does the handoff record identify the current operator, kill-switch authority, and escalation path?
- Are pending approvals expired, re-requested, or explicitly accepted by the incoming operator?
- Are active alert suppressions justified with review dates so suppression drift is visible?
- Are response-time trends, alert acknowledgment rates, and alert-fatigue indicators visible to the incoming operator?
- Are customer-impact warnings, incidents, and autonomy-downgrade considerations carried into the next shift?
- Can the handoff record be reconciled against the immutable audit trail and approval history?

## Related Requirements and Appendices

- APTS-HO-004: Authority Delegation Matrix
- APTS-HO-005: Delegation Chain-of-Custody and Decision Audit Trail
- APTS-HO-009: Multi-Operator Kill Switch Authority and Handoff
- APTS-HO-015: Real-Time Activity Monitoring and Multi-Channel Notification
- APTS-HO-019: 24/7 Operational Continuity and Shift Handoff
- APTS-AL-025: Autonomy Level Authorization, Transition, and Reauthorization
- [Authority Delegation Matrix Template](Authority_Delegation_Matrix_Template.md)
- [Rules of Engagement Template](Rules_of_Engagement_Template.md)
- [Incident Response Integration](Incident_Response_Integration.md)
