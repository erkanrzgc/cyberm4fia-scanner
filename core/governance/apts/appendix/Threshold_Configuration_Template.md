# Threshold Configuration Template

Informative Appendix (non-normative)

This template provides a simple starting point for documenting the threshold configuration referenced by APTS-SC-008. It is intentionally lightweight so operators can adapt it to their environment without building a full schema before they are ready.

Use this appendix to record the practical limits and escalation points that govern autonomous testing behavior. Keep it under version control, review it after material platform or staffing changes, and update it when the engagement profile or target environment changes.

## How to Use This Template

1. Copy the table into your platform documentation or configuration record
2. Fill in the values that apply to your environment
3. Record who owns the setting and when it was last reviewed
4. Add or remove rows as needed for your deployment model
5. Keep units and escalation behavior explicit

## Threshold Configuration Table

| Control | Default value | Unit | Escalation point | Stop point | Owner | Last reviewed |
|---|---|---|---|---|---|---|
| Maximum requests per second | 10 | requests/second | >8 sustained for 60 seconds | >10 sustained for 60 seconds | Security Operations Lead | YYYY-MM-DD |
| Maximum concurrent connections | 20 | connections per target | >15 active | >20 active | Platform Engineering | YYYY-MM-DD |
| Maximum payload size | 100 | MB | >80 MB planned payload | >100 MB planned payload | Platform Engineering | YYYY-MM-DD |
| Cumulative risk score | 70 | score | >=50 requires human review | >=70 halt autonomous actions | Security Operations Lead | YYYY-MM-DD |
| Approval threshold | Medium | impact tier | Medium and above require approval | N/A | Engagement Lead | YYYY-MM-DD |
| Halt threshold | Critical | impact tier | High requires elevated approval | Critical triggers halt/kill workflow | Security Operations Lead | YYYY-MM-DD |
| Health-check failure threshold | 3 | consecutive failures | 2 failed checks | 3 failed checks | Site Reliability / Operations | YYYY-MM-DD |
| Human approval timeout | 15 | minutes | 10 minutes escalates to backup approver | 15 minutes defaults to deny/pause | Engagement Lead | YYYY-MM-DD |

## Optional Notes

- Record whether values apply globally, per target, or per engagement
- If different target classes need different limits, keep one table per class
- If a value is inherited from another control system, note the source of truth
- If the platform uses machine-readable configuration, link the file path or config object here

## Example Change Log Entry

- 2026-04-22: Reduced maximum requests per second for production targets from 15 to 10 after health-check degradation was observed during internal validation

## Related APTS Requirements

This template can help operators document or verify:

- APTS-SC-006 Threshold Escalation Workflow
- APTS-SC-007 Cumulative Risk Scoring with Time-Based Decay
- APTS-SC-008 Threshold Configuration with Schema Validation
- APTS-HO-002 Real-Time Monitoring and Intervention Capability
- APTS-HO-003 Decision Timeout and Default-Safe Behavior
