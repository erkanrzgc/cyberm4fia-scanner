# Human Oversight: Implementation Guide

Practical guidance for implementing APTS Human Oversight requirements. Each section provides a brief implementation approach, key considerations, and common pitfalls.

> **Note:** This guide is informative, not normative. Recommended defaults and example values are suggested starting points; the [Human Oversight README](README.md) contains the authoritative requirements. Where this guide and the README differ, the README governs.

---

## APTS-HO-001: Mandatory Pre-Approval Gates for Autonomy Levels L1 and L2

**Implementation:** Implement role-based approval workflows for exploitation attempts, lateral movement, data access requests, and persistence mechanisms. Route requests through designated approvers based on risk level and engagement scope.

**Key Considerations:**
- Define approval thresholds by action type (for example, high-risk exploits require manager approval)
- Maintain approval audit trails with timestamps and decision rationale
- Use templated approval forms to ensure consistency

**Common Pitfalls:**
- Approver fatigue leading to rubber-stamp approvals
- Unclear escalation criteria causing bottlenecks
- Approval timeouts causing testing delays without fallback mechanisms

---

## APTS-HO-002: Real-Time Monitoring and Intervention Capability

**Implementation:** Deploy a centralized dashboard displaying live activity feed, system health metrics, scope boundaries, pending approval queues, and real-time anomaly detection alerts with drill-down capabilities.

**Key Considerations:**
- Include visual scope boundaries and current target status
- Implement color-coded severity indicators for anomalies
- Provide audit logs with search and filter functionality
- Ensure dashboard responsiveness under high-frequency updates

**Common Pitfalls:**
- Information overload causing missed critical alerts
- Slow refresh rates masking real-time anomalies
- Accessibility barriers for non-technical stakeholders

---

## APTS-HO-003: Decision Timeout and Default-Safe Behavior

**Implementation:** Define maximum response time SLAs (for example, 5 minutes for critical decisions) with automatic escalation. Default behavior on timeout must be DENY, PAUSE, or KILL depending on context. Never proceed with uncertain decisions.

**Key Considerations:**
- Publish SLAs clearly to all stakeholders
- Implement progressive escalation (team lead → manager → director)
- Log all timeout triggers and escalation paths

**Common Pitfalls:**
- Overlong SLAs enabling scope creep during waits
- Missing escalation during off-hours
- Unclear default behavior causing ambiguous outcomes

---

## APTS-HO-004: Authority Delegation Matrix

**Implementation:** Document a clear matrix defining who can approve what actions at which autonomy levels. Include approval authority, delegation rules, and escalation chains. Distribute to all operators and maintain version control.

**Key Considerations:**
- Include role definitions, authority limits, and delegation permissions
- Require signed acknowledgment from approvers
- Review and update quarterly or after personnel changes

**Common Pitfalls:**
- Outdated matrices after staffing changes
- Unclear authority boundaries creating decision paralysis
- Informal approvals not captured in the matrix

---

## APTS-HO-005: Delegation Chain-of-Custody and Decision Audit Trail

**Implementation:** Implement immutable decision logs with cryptographic signatures for all approvals. Capture approver identity, timestamp, decision, and rationale. Use tamper-evident storage (for example, append-only logs or blockchain).

**Key Considerations:**
- Include delegation chains showing who approved on whose authority
- Implement log retention policies complying with engagement agreements
- Enable full-text search across decision history

**Common Pitfalls:**
- Logs that are too verbose, obscuring key decisions
- Difficulty correlating decisions with outcomes
- Missing context causing ambiguous audit trails

---

## APTS-HO-006: Graceful Pause Mechanism with State Preservation

**Implementation:** Implement pause functionality that suspends autonomous operations while preserving system state, including network sessions, tool state, and execution context. Allow resumption without restart.

**Key Considerations:**
- Preserve active network connections and authentication tokens
- Document pause duration and resume conditions
- Test resumption after extended pauses (24+ hours)

**Common Pitfalls:**
- State corruption during pause/resume cycles
- Expired credentials preventing clean resumption
- Loss of context or execution stack causing incorrect resumption

---

## APTS-HO-007: Mid-Engagement Redirect Capability

**Implementation:** Provide operators with ability to redirect scope, retarget systems, or change techniques mid-engagement without restarting. Capture reason for redirection and update engagement baseline.

**Key Considerations:**
- Validate new targets against overall engagement scope
- Log scope changes for compliance and billing purposes
- Implement smooth transition to new targets without lingering connections

**Common Pitfalls:**
- Redirects leading to out-of-scope testing
- Lost baseline data after redirection
- State from previous target leaking to new target

---

## APTS-HO-008: Immediate Kill Switch with State Dump

**Implementation:** Implement a two-phase emergency kill switch triggerable by operators. Phase 1 (within 5 seconds) ceases all new testing actions while allowing in-flight operations to complete. Phase 2 (within 60 seconds) force-terminates all connections, revokes temporary credentials, and preserves full system state, memory, and execution context for forensic analysis.

**Key Considerations:**
- Test kill switch activation time regularly
- Preserve volatile evidence before system shutdown
- Document all state dumps with timestamps
- Design kill switch to be always accessible, never blocked by system state

**Common Pitfalls:**
- Kill switch disabled by system state or runaway processes
- State dumps incomplete or corrupted
- No mechanism to verify kill switch activation

---

## APTS-HO-009: Multi-Operator Kill Switch Authority and Handoff

**Implementation:** Establish primary and secondary kill switch authorities with manager override capability. Define clear authority chains and implement role-based access control for kill switch triggers.

**Key Considerations:**
- Ensure secondary authority can activate if primary is unavailable
- Log all kill switch activations with triggering authority
- Establish manager review triggers if secondary activates

**Common Pitfalls:**
- Single point of failure if only one operator can trigger
- Unclear authority boundaries during handoffs
- Missing manager notification on secondary authority activation

---

## APTS-HO-010: Mandatory Human Decision Points Before Irreversible Actions

**Implementation:** Gate all irreversible actions (data deletion, persistence installation, destructive payloads) with explicit human approval. Include action scope, reversal difficulty, and impact assessment in approval request.

**Key Considerations:**
- Define what constitutes "irreversible" per engagement context
- Require two-person rule for high-impact irreversible actions
- Document reason approver accepted irreversibility risk

**Common Pitfalls:**
- Fuzzy definition of irreversible actions
- Approvers underestimating reversal difficulty
- Missing documentation of reversal assessment

---

## APTS-HO-011: Unexpected Findings Escalation Framework

**Implementation:** Establish escalation triggers for indicators of compromise (IoCs), illegal content, zero-day vulnerabilities, and out-of-scope system access. Route findings to appropriate stakeholders with severity and context.

**Key Considerations:**
- Define escalation matrix mapping finding types to escalation paths
- Include severity assessment and supporting evidence
- Notify legal and compliance teams for potential legal findings
- Preserve evidence chain for potential law enforcement

**Common Pitfalls:**
- Over-escalation causing alert fatigue
- Missing escalation of subtle findings (for example, minor OOS access)
- Delayed escalation due to classification ambiguity

---

## APTS-HO-012: Impact Threshold Breach Escalation

**Implementation:** Monitor impact metrics against engagement baselines. Escalate immediately when impact exceeds pre-approved thresholds (for example, system downtime, data exposure, user impact). Define rollback procedures upon escalation.

**Key Considerations:**
- Quantify impact metrics clearly (downtime duration, records exposed, systems affected)
- Set escalation thresholds conservatively to allow buffer before critical breach (for example, escalate at 80% of halt threshold so operators have time to assess before automatic termination)
- Include automated impact monitoring with anomaly detection

**Common Pitfalls:**
- Thresholds set too high, missing legitimate breaches
- Inability to measure impact accurately in real-time
- Missing rollback capability after escalation

---

## APTS-HO-013: Confidence-Based Escalation (Scope Uncertainty)

**Implementation:** Escalate to human review when confidence in scope/target determination drops below acceptable thresholds. Include confidence scoring in technical assessment and escalation request.

**Key Considerations:**
- Define confidence thresholds per finding type
- Establish confidence scoring methodology
- Route low-confidence findings to senior technical staff
- Document confidence assessment rationale

**Common Pitfalls:**
- Inflated confidence scores during rapid testing
- Over-escalation of low-confidence findings
- Missing mechanism to improve confidence before escalation

---

## APTS-HO-014: Legal and Compliance Escalation Triggers

**Implementation:** Establish escalation criteria for findings with legal implications (data privacy violations, regulatory breaches, industry compliance issues). Route to legal and compliance teams with supporting evidence.

**Key Considerations:**
- Include legal counsel in pre-engagement scope definition
- Maintain clean evidence chain for potential regulatory reporting
- Document escalation decisions and follow-up actions
- Review findings against applicable regulations

**Common Pitfalls:**
- Unclear definition of legal/compliance triggers
- Delayed notification to legal team
- Evidence contamination during investigation

---

## APTS-HO-015: Real-Time Activity Monitoring and Multi-Channel Notification

**Implementation:** Monitor all autonomous activities in real-time. Deliver notifications via multiple channels (email, SMS, Slack, dashboard alerts) with delivery confirmation. Include priority levels and escalation chains.

**Key Considerations:**
- Verify notification delivery and track read receipts
- Implement retry logic for missed notifications
- Include detailed context in notifications (target, action, scope impact)
- Define notification SLAs per severity level

**Common Pitfalls:**
- Single notification channel creating single point of failure
- Notification flooding reducing engagement
- Missing acknowledgment mechanism causing repeated alerts

---

## APTS-HO-016: Alert Fatigue Mitigation and Smart Aggregation

**Implementation:** Implement intelligent alert aggregation grouping similar events, suppression rules for benign findings, and dynamic escalation thresholds. Provide operators with customizable alert preferences.

**Key Considerations:**
- Use machine learning or rule-based deduplication
- Allow operators to tune alert thresholds per target
- Implement alert suppression windows for routine activities
- Monitor alert metrics to detect desensitization

**Common Pitfalls:**
- Overly aggressive aggregation missing critical events
- Alert suppression rules becoming outdated
- Inability to override aggregation during critical operations

---

## APTS-HO-017: Stakeholder Notification and Engagement Closure

**Implementation:** Establish notification workflows for engagement status, findings disclosure, and formal closure procedures. Include stakeholder sign-off on findings and remediation recommendations.

**Key Considerations:**
- Define notification timeline per engagement phase
- Implement findings review process with stakeholder input
- Document closure procedures and sign-off requirements
- Provide remediation guidance alongside findings

**Common Pitfalls:**
- Premature findings disclosure before validation
- Missing stakeholder involvement in closure procedures
- Inadequate remediation guidance causing implementation delays

---

## APTS-HO-018: Operator Qualification, Training, and Competency Governance

**Implementation:** Define minimum competency standards for operators by role (junior, senior, lead) covering technical skills, compliance knowledge, and decision-making capability. Implement certification program with written and practical assessments.

**Key Considerations:**
- Establish role-based competency matrices
- Include soft skills (communication, judgment, crisis management)
- Require annual recertification
- Document competency assessments in personnel files

**Common Pitfalls:**
- Competency standards too generic or rigid
- Insufficient practical assessment of decision-making
- Missing recertification enforcement

**Operator Competency Framework by Autonomy Level:**

| Autonomy Level | Required Competencies | Recommended Training Hours |
|---------------|----------------------|---------------------------|
| L1 (Assisted) | Platform operation, basic pentesting methodology, scope interpretation, kill switch operation | 16 hours classroom + 8 hours hands-on lab |
| L2 (Supervised) | All L1 plus: escalation handling, approval decision-making, incident triage, risk scoring interpretation | 24 hours classroom + 16 hours hands-on lab |
| L3 (Semi-Autonomous) | All L2 plus: business impact analysis, campaign management, boundary monitoring, advanced incident response | 32 hours classroom + 24 hours hands-on lab |
| L4 (Autonomous) | All L3 plus: autonomous system oversight, behavioral anomaly detection, strategic decision-making, tabletop exercise completion | 40 hours classroom + 32 hours hands-on lab |

Competency MUST be validated through practical assessment (not just attendance). Reassessment is required annually or after any incident involving operator error.

---

## APTS-HO-019: 24/7 Operational Continuity and Shift Handoff

**Implementation:** Establish 24/7 shift coverage with formal handoff procedures including stale approval expiry, decision log review, and desensitization monitoring. Implement mechanisms preventing operator fatigue and decision degradation.

**Key Considerations:**
- Require written handoff notes capturing ongoing engagements
- Expire approvals after a documented validity window to force reassessment. Recommended starting defaults: 4 hours for Low-impact approvals, 1 hour for Medium, 30 minutes for High, and synchronous confirmation (no pre-approval) for Critical actions. Document chosen windows with rationale.
- Monitor operator fatigue through performance metrics
- Implement mandatory breaks to prevent desensitization

**Common Pitfalls:**
- Informal handoffs missing critical context
- Stale approvals proceeding without reassessment
- No desensitization monitoring allowing degraded decisions

**Shift Handoff Checklist:**

The [Shift Handoff Template](../appendix/Shift_Handoff_Template.md) provides an optional record structure for preserving this context with the engagement audit trail.

The outgoing operator MUST complete the following before transferring authority:

1. [ ] Confirm engagement status (active/paused/completing) with incoming operator
2. [ ] Transfer kill switch authority and confirm incoming operator can activate it
3. [ ] Brief on current testing phase, active targets, and any in-flight high-risk actions
4. [ ] Review open escalations and pending approvals with incoming operator
5. [ ] Share any anomalies, incidents, or concerns observed during the shift
6. [ ] Confirm incoming operator has access to all monitoring dashboards and notification channels
7. [ ] Log handoff timestamp, outgoing operator ID, incoming operator ID, and handoff summary
8. [ ] Incoming operator confirms readiness by acknowledging the handoff in the platform

Handoff MUST NOT be completed until the incoming operator explicitly acknowledges. During the handoff window (recommended: 15 minutes overlap), both operators share authority.

---

## Implementation Roadmap

**Phase 1 (implement before any autonomous pentesting begins):**
APTS-HO-001 (approval gates), APTS-HO-002 (monitoring dashboard), APTS-HO-003 (decision timeout), APTS-HO-004 (authority delegation), APTS-HO-006 (pause mechanism), APTS-HO-007 (mid-engagement redirect), APTS-HO-008 (kill switch), APTS-HO-010 (irreversible action gates), APTS-HO-011 through APTS-HO-014 (escalation frameworks), APTS-HO-015 (real-time notifications).

Start with kill switch and pause controls (APTS-HO-008, APTS-HO-006, APTS-HO-007) as the safety foundation. Then implement approval gates (APTS-HO-001) and decision timeout (APTS-HO-003). Layer the monitoring dashboard (APTS-HO-002), escalation triggers (APTS-HO-011 through APTS-HO-014), and notifications (APTS-HO-015) before first engagement.

**Phase 2 (implement within first 3 engagements):**
APTS-HO-005 (delegation audit trail), APTS-HO-009 (multi-operator kill switch), APTS-HO-016 (alert fatigue mitigation, SHOULD), APTS-HO-017 (stakeholder notification), APTS-HO-018 (operator qualification, training, and competency governance), APTS-HO-019 (24/7 operational continuity, SHOULD).

Prioritize APTS-HO-009 (kill switch redundancy) first. Add operator qualifications (APTS-HO-018) based on team size and engagement tempo.
