# Incident Response Integration

Informative Appendix (non-normative)

This appendix maps APTS requirements to incident response phases without introducing new requirements. For normative requirements, see domain-specific READMEs. See [Cross-Domain Integration Matrix](Cross_Domain_Integration.md) for how events trigger requirements across domains.

This appendix unifies incident response requirements across APTS domains. Incident response capabilities are distributed across multiple domains because different aspects of incident handling fall under different governance concerns. It provides a complete workflow for identifying, responding to, and recovering from incidents during autonomous penetration testing.

---

## Incident Response Requirement Map

This table maps IR phases to the specific requirements that govern each phase, with substantive descriptions of what each requirement demands:

| Phase | Requirements | Domain | What This Requirement Demands |
|-------|-------------|--------|------|
| **Detection** | APTS-SC-010 | SC | Platform health monitoring with continuous collection of heartbeat (timestamp, process ID, memory/CPU, active test count, queue depth), resource utilization (CPU, memory, disk, network), process state validation, and behavioral baseline deviation. Anomaly detection triggers alerts based on statistically significant deviations from baseline (probe rates, target-switching frequency, approval escalation frequency, decision latency, action success rates, rollback frequency) with confidence scoring and documented escalation policies. |
| | APTS-HO-015 | HO | Maintain real-time activity feed of ALL testing actions accessible to operators with multi-channel notifications: dashboard alerts with action summary, email with decision links and approval windows, SMS with delivery confirmation (for high-priority items), and automated calls for CRITICAL alerts. Feed must be accessible in real time without requiring API polling. |
| **Escalation: Unexpected Findings** | APTS-HO-011 | HO | Detect and immediately escalate: (1) indicators of external breach or attacker activity, (2) illegal content or evidence of crimes, (3) critical zero-day vulnerabilities with active exploit code, (4) system access outside authorized scope, (5) violations of security policies or compliance frameworks, (6) system stability threats (service crashes, data corruption). Escalation must be human-reviewed before autonomous continuation. |
| **Escalation: Impact Breaches** | APTS-HO-012 | HO | Continuously monitor actual testing impact on target systems (availability, resource consumption, data integrity, security events triggered) against documented thresholds. When impact exceeds thresholds, automatically escalate and pause pending human decision. Impact measurement must reflect real system behavior, not predictions. |
| **Escalation: Scope Uncertainty** | APTS-HO-013 | HO | When confidence in scope boundary determination or target legitimacy falls below 75%, automatically escalate and pause. Confidence model must be documented. Examples: ambiguous domain ownership, unclear network boundaries, questionable asset classification. Prevents autonomous continuation when scope is uncertain. |
| **Escalation: Legal/Compliance** | APTS-HO-014 | HO | Identify and immediately escalate potential violations: (1) GDPR, CCPA, HIPAA, PCI-DSS personal data access, (2) government or classified information exposure, (3) third-party systems or restricted access, (4) regulatory breach notification obligations triggered, (5) IP address ranges owned by unaffiliated organizations. |
| **Containment: Kill Switch** | APTS-SC-009 | SC | Provide multiple independent kill switch mechanisms (operator-initiated local halt, remote halt by authorized personnel, automatic failsafe on control plane loss) with two-phase halt: Phase 1 (within 5 seconds) ceases initiating new requests/exploits/actions with in-flight operations continuing; Phase 2 (within 60 seconds) completes in-flight operations gracefully, preserves state, terminates spawned processes, closes connections, flushes logs. Terminate ALL child processes, connections, and agents spawned during testing (not just primary process). Track all spawned processes, network connections, and external agents. Gracefully terminate processes, close connections, stop cloud/distributed agents, revoke temporary credentials, cancel queued actions. |
| **Containment: State Preservation** | APTS-HO-008 | HO | Execute state dump capturing system memory, running processes, open connections, pending operations, and platform state (decision queue, active escalations, approval status) before any containment procedures. State must be preserved on independent storage for forensic investigation within the Phase 2 window (within 60 seconds of kill switch activation). |
| **Notification: Operator** | APTS-HO-015 | HO | Multi-channel operator notification via dashboard, email (with decision links), SMS (confirmation required), and automated calls (CRITICAL only). Notifications must reach operator within platform's documented response SLA and include incident summary, systems affected, severity, recommended action, decision deadline. |
| **Notification: Stakeholders** | APTS-HO-017 | HO | Define and execute stakeholder notification workflows per documented SLAs: (1) engagement status updates (frequency per engagement), (2) finding summaries and severity distribution, (3) critical notifications (CRITICAL findings or incidents within timeframe defined in IR plan), (4) escalation notifications (major thresholds crossed), (5) completion and final report delivery (by documented deadline), (6) post-engagement follow-up. All SLAs and workflows documented before engagement begins. |
| **Notification: External Alerts** | APTS-SC-017 | SC | External watchdog (on independent infrastructure) monitors platform health and anomalies. On confirmed incident, watchdog notifies customers within documented SLA via out-of-band channels (phone, SMS, email) independent of compromised platform. Notification includes: what happened, systems affected, automated containment actions taken, next steps, point of contact. Alternative escalation if customer not acknowledging within defined window. |
| **Recovery: Rollback** | APTS-SC-014 | SC | Track state for reversible actions (account creation, file modification, config changes, process starts) with: action name, timestamp, target resource ID, pre-action state, rollback procedure, verification method. Persist state after each action. Maintain explicit rollback procedures as executable scripts (no manual steps). Execute rollback and complete within documented maximum rollback time. Trigger alerts if verification fails. |
| **Recovery: Evidence Preservation** | APTS-SC-016 | SC | BEFORE rollback begins, capture evidence: screenshots, logs, error messages, modified file contents, database queries, privilege escalation proofs. Store in write-once, tamper-evident storage with read-only access. Persist per engagement's data retention policy. Rollback operations MUST NOT access or modify evidence storage. |
| **Recovery: Cleanup** | APTS-SC-016 | SC | Automated cleanup removes all test artifacts (temporary files, created accounts, installed tools, backdoors, test data, activity logs). Procedures MUST be idempotent (safe to run multiple times), atomic (complete or fail, no partial state), and verifiable. Cleanup completes within documented timeframe. Failed cleanup logged and escalated for manual remediation. |
| **Investigation: Root Cause** | APTS-AL-026 | AL | Conduct structured investigation: (1) root cause analysis of how incident occurred, (2) impact assessment (systems, data, duration of exposure), (3) review of whether autonomy level was appropriate for the incident that occurred, (4) identification of control improvements, (5) determination of whether autonomy level should be downgraded. Document findings and recommendation. |
| **Investigation: Audit Trail** | APTS-AR-001 through APTS-AR-012 | AR | Retrieve and analyze complete audit logs from incident start to end. Audit trail must be immutable, cryptographically signed, append-only with sufficient detail to reconstruct all decisions, escalations, approvals, and platform actions. Use audit data to validate platform-reported timeline and confirm investigation findings. |
| **Investigation: Evidence Chain** | APTS-RP-001 | RP | Extract and validate evidence from findings discovered during incident. Evidence must include raw technical artifacts (packets, logs, command output), cryptographic hashes, timestamps. Validate evidence chain to confirm findings accurately reflect what platform discovered and how decisions were made. |
| **External Response: Provider** | APTS-TP-005 | TP | If incident involves provider compromise: (1) assess data exposure (what data was on provider systems), (2) notify provider of compromise, (3) assess engagement continuation feasibility, (4) customer notification per documented incident response plan. Procedures must enable rapid containment of exposure and assessment of whether testing can continue. |
| **External Response: Tenant Breach** | APTS-TP-018 | TP | If multi-tenant isolation breached (engagement data leaked to other engagement): (1) detect via monitoring of cross-engagement access attempts and audit log analysis, (2) immediately isolate affected systems, (3) assess scope (engagements, data categories, record quantities), (4) notify all affected customers promptly per incident response plan including what data leaked, time window, remediation taken. |
| **Reporting: Incident Report** | APTS-AL-018, APTS-RP-011 | AL, RP | Generate incident report for customer including: incident timeline (discovery, occurrence, detection, containment, recovery), root cause, affected systems and data, impact assessment, containment actions taken, recovery procedures executed, lessons learned, preventive measures implemented, evidence of re-verified safety controls. Deliver within timeframe defined in IR plan. The platform must require customer acknowledgment and approval before testing resumes. |

---

**Notification Types:**
- **Preliminary notification** (within 1 hour for SEV-1, 4 hours for SEV-2): "We have detected an incident affecting your engagement. Investigation is underway. Details to follow." Does not require confirmed root cause.
- **Confirmed incident notification** (within 4 hours for SEV-1, 24 hours for SEV-2): Includes confirmed scope of impact, root cause (if known), containment actions taken, and next steps. Requires initial investigation completion.

Organizations SHOULD send preliminary notifications promptly rather than delaying to gather complete information.

---

## Unified Incident Severity Classification

A recommended incident severity model that maps across domains. Severity determines response urgency and notification channels:

### SEV-1 (Critical)

**Triggers:**
- Active data breach: sensitive data (PII, credentials, payment info) exfiltrated or accessible
- Service outage: target system unavailable or severely degraded due to platform actions
- Cross-tenant data leakage: engagement data leaked to another engagement
- Scope violation: platform accessed system outside authorized engagement scope
- Critical zero-day discovered on client system (not created by platform)
- Evidence of external attacker on platform (compromised provider, injected code, stolen credentials)
- Regulatory breach: GDPR/CCPA/HIPAA data access triggering mandatory notification
- System instability: platform behavior indicates potential cascade failure risk

**Required Actions:**
- Kill switch activation within 5 seconds (Phase 1)
- Complete shutdown within 60 seconds (Phase 2)
- Executive notification within 1 hour
- Customer notification within 2 hours (or regulatory timeline, whichever is shorter)
- State preservation and forensic capture
- External watchdog immediate escalation
- Incident investigation and root cause within 24 hours
- Post-incident report to customer within 5 business days

**Notifications:**
- Operator: automated call + SMS + email
- Customer: phone call from incident commander + formal incident report
- Regulatory authorities: per applicable law (GDPR 72 hours, HIPAA 60 days, and other regulatory timelines)
- Insurance carrier (if applicable)

**Impact on Testing:**
- Autonomous operations halted permanently until root cause investigated and safety controls re-verified
- Autonomy level downgrade evaluation mandatory

---

### SEV-2 (High)

**Triggers:**
- Impact threshold breach: actual platform testing impact exceeded documented limits (response time, error rate, resource consumption)
- Safety threshold breach: cumulative risk score exceeds critical threshold
- Provider compromise discovered: third-party system supporting platform is compromised
- Confidence below 75%: scope boundary or target legitimacy uncertain
- Compliance boundary violation detected: potential GDPR/CCPA/HIPAA exposure identified (not yet confirmed)
- Circuit breaker activation: sustained target degradation prevents recovery

**Required Actions:**
- Automated pause of all new testing actions (within 5 seconds)
- Operator escalation within 5 minutes
- Customer notification within 1 hour
- Root cause investigation within 4 hours
- Decision on testing resumption before operator approval timeout (varies per escalation policy)

**Notifications:**
- Operator: SMS + email with decision links
- Customer: email notification with incident summary and actions taken
- Incident record created for post-incident review

**Impact on Testing:**
- Autonomous operations paused, awaiting human decision
- Operator can resume, modify scope, or escalate further
- If provider compromise, assess engagement continuation; customer may suspend testing pending investigation

---

### SEV-3 (Medium)

**Triggers:**
- Anomalous behavior: platform behavior deviates from baseline (increased escalations, unusual action patterns)
- Non-critical scope drift: probing slightly outside intended scope but accessing no sensitive systems
- Confidence threshold warning: confidence approaching 75% threshold
- High false positive rate detected
- Unusual error patterns (but system stable)
- Elevated alert volume from monitoring systems

**Required Actions:**
- Alert to operator within 15 minutes
- Investigation within 4 hours
- Documentation in engagement record
- Assessment of root cause (platform issue, target instability, legitimate discovery)

**Notifications:**
- Operator: email alert, visible on dashboard
- Customer: update in engagement status feed if relevant

**Impact on Testing:**
- Continues with operator awareness
- May trigger reduced testing intensity or additional monitoring
- Potential pause if root cause unknown

---

### SEV-4 (Low)

**Triggers:**
- Minor anomalies: single health check failure (one of many passing)
- Recoverable errors: transient network glitches, temporary API throttling
- Informational alerts: test action resulted in expected error (legitimate discovery)
- Configuration drift (non-security): minor settings change

**Required Actions:**
- Logged and visible in audit trail
- Operator review at next checkpoint (daily or per engagement schedule)
- No escalation unless pattern emerges

**Notifications:**
- None (unless pattern emerges to SEV-3)

**Impact on Testing:**
- Continues normally
- No pause or escalation

---

## Incident Response Workflow

This section walks through the complete sequence of incident response and the APTS requirements that govern each phase:

### Phase 1: Detection (0-5 minutes)

**What triggers detection:**
- Continuous health monitoring (APTS-SC-010) detects platform anomalies (heartbeat gaps, resource spikes, anomalous decision patterns)
- Real-time activity feed (APTS-HO-015) shows operator unexpected actions or findings
- External watchdog (APTS-SC-017) detects platform availability or metric divergence
- Operator manual report of incident symptoms
- Target system alerts (IDS, logging) indicating platform behavior

**Requirements that apply:**
- APTS-SC-010: Continuously monitor platform health and anomaly detection with confidence scoring
- APTS-HO-015: Operator visibility into activity feed with real-time notifications
- APTS-SC-017: External watchdog independent monitoring and anomaly confirmation

**Operator actions:**
- Review incident summary from monitoring system
- Verify incident severity classification
- Decide whether to escalate immediately or investigate further
- Preserve initial state if incident severity unknown

---

### Phase 2: Escalation & Decision (0-30 minutes depending on severity)

**Escalation triggers (APTS-HO-011 through APTS-HO-014):**
1. **Unexpected findings escalation (APTS-HO-011):** Detects external breach indicators, illegal content, critical zero-days, out-of-scope access, compliance violations, system stability threats. Halts autonomous operations for human review.
2. **Impact breach escalation (APTS-HO-012):** Continuously monitors impact and escalates when thresholds exceeded. Pause triggers automatic operator notification and escalation.
3. **Scope uncertainty escalation (APTS-HO-013):** Confidence falls below 75%; escalates with human authorization required to resume.
4. **Legal/compliance escalation (APTS-HO-014):** Detects GDPR/CCPA/HIPAA data access, government info, third-party systems, breach notification obligations, suspicious IP ranges. Escalates for legal review.

**Requirements that apply:**
- APTS-HO-011, HO-012, HO-013, HO-014: Define escalation triggers and decision processes
- APTS-HO-015: Multi-channel operator notification with decision deadline
- APTS-HO-017: Stakeholder notification workflow activation

**Operator decision:**
- Review escalation reason and evidence
- Assess severity classification
- Approve containment if SEV-1/SEV-2, or mitigate if SEV-3/SEV-4
- If uncertain, escalate to senior operator or manager per APTS-HO-009

---

### Phase 3: Containment (0-5 seconds for Phase 1; 0-60 seconds total for Phase 2)

**Kill switch requirements (APTS-SC-009):**

**Phase 1 (within 5 seconds) - Safety-Critical Cessation:**
- Cease initiating new network requests to target systems
- Cease initiating new exploit attempts and payloads
- Cease initiating new testing actions
- All in-flight operations continue to completion (Phase 1 measures cessation of new decision-layer action initiation; network stack may complete)

**Phase 2 (within 60 seconds total) - Graceful Shutdown:**
- Complete all in-flight network operations gracefully
- Terminate all spawned processes and child agents
- Close all open network connections
- Revoke temporary credentials issued during testing
- Preserve system state for forensic investigation
- Flush and finalize all logs

**State preservation (APTS-HO-008):**
- Execute state dump capturing memory, running processes, pending operations
- Preserve on independent storage for investigation

**Requirements that apply:**
- APTS-SC-009: Kill switch with two-phase halt and process tree termination
- APTS-HO-008: State dump execution

---

### Phase 4: Notification (0-1 hour depending on severity)

**Operator notification (APTS-HO-015):**
- Dashboard alert with incident summary
- Email with decision links and approval window
- SMS confirmation (high-priority)
- Automated call (CRITICAL only)
- Status: kill switch activated, containment in progress, investigation started

**Stakeholder/Customer notification (APTS-HO-017, APTS-SC-017):**
- For SEV-1: phone call from incident commander within 1 hour, formal incident report within 5 business days
- For SEV-2: email with incident summary and status within 1 hour
- For SEV-3: engagement status feed update
- For SEV-4: logged, no notification unless pattern emerges

**External watchdog notification (APTS-SC-017):**
- Confirm incident independently via audit log analysis
- Notify customer via out-of-band channels if watchdog-confirmed
- Include: what happened, systems affected, automated actions, next steps, contact info

**Regulatory notification (APTS-TP-A01 if breach, Advisory):**
- Assess applicable regulations (GDPR 72-hour notification, HIPAA 60-day, and other applicable regulatory timelines)
- Initiate notification process within regulatory timeline

**Requirements that apply:**
- APTS-HO-015: Operator multi-channel notification
- APTS-HO-017: Stakeholder notification workflows
- APTS-SC-017: External watchdog and operator notification
- APTS-TP-A01 (Advisory), TP-005: Breach notification (if applicable)

---

### Phase 5: Recovery (1-24 hours depending on severity)

**Evidence preservation (APTS-SC-016, APTS-RP-001):**
- Capture screenshots, logs, error messages, modified files, database queries, privilege proofs
- Store in write-once storage before any rollback
- Document chain of custody
- Calculate cryptographic hashes for integrity verification

**Rollback (APTS-SC-014):**
- Execute rollback procedures for all reversible actions (created accounts, modified configurations, and changed permissions)
- Complete within documented maximum rollback time (typically hours to days depending on action)
- Verify rollback success before proceeding to cleanup
- Alert if verification fails

**Automated cleanup (APTS-SC-016):**
- Execute cleanup removing all test artifacts (temp files, created accounts, tools, test data)
- Procedures must be idempotent and atomic
- Complete within documented timeframe
- Log and escalate if cleanup fails
- Verify all artifacts removed

**Requirements that apply:**
- APTS-SC-014: Rollback procedures and verification
- APTS-SC-016: Evidence preservation and cleanup
- APTS-SC-018: Incident containment and recovery procedures (for platform incidents)

---

### Phase 6: Investigation (4-48 hours)

**Root cause analysis (APTS-AL-026):**
- Determine how incident occurred (platform defect, misconfiguration, operator error, external event)
- Identify control that should have prevented incident
- Assess whether autonomy level was appropriate
- Determine if autonomy level downgrade is required
- Use the [Autonomy Downgrade Matrix Template](Autonomy_Downgrade_Matrix_Template.md), if adopted, to confirm the temporary autonomy cap, required approver, and re-authorization evidence

**Audit trail analysis (APTS-AR-001 through APTS-AR-012):**
- Retrieve complete immutable audit logs from incident start to end
- Verify timeline matches initial incident report
- Confirm all decisions, escalations, approvals logged
- Identify any audit log gaps or anomalies

**Evidence validation (APTS-RP-001 through APTS-RP-004):**
- Extract raw technical evidence from findings discovered during incident
- Validate cryptographic evidence chain
- Confirm all findings include raw evidence (packets, logs, command output)
- Verify confidence scoring for each finding

**Requirements that apply:**
- APTS-AL-026: Incident investigation and autonomy level adjustment
- APTS-AR-001 through APTS-AR-012: Audit trail completeness
- APTS-RP-001 through APTS-RP-004: Evidence-based finding validation

---

### Phase 7: Post-Incident (1-5 business days)

**Safety control re-verification (APTS-SC-018 for platform incidents):**
- Before resuming testing, re-verify all safety controls are functional:
  - Kill switches responsive and operational
  - Health monitoring active and detecting anomalies
  - Anomaly detection baseline re-established
  - Escalation workflow functioning
  - Rollback procedures tested and functional
  - Blast radius limits enforced
- All safety controls MUST pass before resuming testing

**Post-incident report (APTS-AL-018, APTS-RP-011):**
- Incident timeline: discovery time, occurrence time, containment, recovery, investigation completion
- Root cause with evidence
- Affected systems and data (scope, quantity)
- Impact assessment (confidentiality, integrity, availability)
- Containment actions taken and their effectiveness
- Recovery procedures executed
- Lessons learned
- Preventive measures implemented
- Evidence of re-verified safety controls

**Customer notification and approval:**
- Deliver report within documented timeframe (typically 5 business days for SEV-1)
- Include recommended changes or restrictions on future testing
- The platform must require customer acknowledgment and approval before testing resumes
- For SEV-1 incidents involving safety controls, the platform must downgrade autonomy level until the customer reviews and approves resumption

**Requirements that apply:**
- APTS-SC-018: Incident containment and recovery (re-verification of controls)
- APTS-AL-018, APTS-RP-011: Executive summary generation and incident reporting

---

## Common Incident Scenarios

These scenarios illustrate how APTS requirements activate in realistic situations:

### Scenario 1: Platform Causes Service Outage

**Incident:** Platform's aggressive testing causes target application response time to exceed 500% of baseline; service becomes slow and some users experience timeouts.

**Detection (5 mins):**
- APTS-SC-010: Health monitoring detects response time spike
- APTS-HO-015: Real-time feed shows elevated target latency
- Severity: SEV-2 (High) - impact threshold breached

**Escalation (5-10 mins):**
- APTS-HO-012 (Impact threshold breach): Automatically pauses further aggressive actions
- Escalation to operator with impact metrics and recommendation to reduce testing intensity
- Operator receives SMS and email with decision deadline

**Operator Decision (10-15 mins):**
- Operator reviews impact data and current target status
- Options: (a) reduce testing intensity for this target, (b) pause testing until customer approval, (c) kill switch
- Operator chooses (a): reduce from 50 req/sec to 10 req/sec

**Recovery (15-30 mins):**
- Testing continues at reduced intensity
- Health check interval increased from 60 sec to 30 sec
- Platform continues monitoring for degradation
- If degradation persists, escalate to (b) or (c)

**Investigation (4 hours):**
- Review audit trail: which testing actions caused spike?
- Assess: was intensity setting appropriate for this target? Can platform detect non-vulnerable services?
- Determine if autonomy level adjustment needed (likely not, incident was correctly handled by escalation)

**Post-Incident (24 hours):**
- Notify customer: testing caused temporary slowdown, mitigation applied, continuing with reduced intensity
- Include: incident timeline, root cause, actions taken, customer approval to resume
- Adjust future engagement scope: exclude this service from high-intensity testing, or increase monitoring

---

### Scenario 2: Cross-Tenant Data Leakage Detected

**Incident:** Operator notices that Engagement A's shell access credentials are appearing in Engagement B's logs (isolation breach).

**Detection (5 mins):**
- APTS-SC-010: Anomaly detection or APTS-TP-017 isolation monitoring detects cross-engagement access attempt
- Severity: SEV-1 (Critical) - multi-tenant isolation breached

**Escalation & Containment (3-30 mins):**
- APTS-SC-009: Kill switches activated for both affected engagements (Phase 1 within 3 sec, Phase 2 within 30 sec); all processes, connections, and agents for both engagements terminated
- APTS-HO-008: State dumps captured for forensic investigation
- Operator notified via automated call (CRITICAL)

**Notification (1 hour):**
- APTS-TP-018: All affected customers notified immediately
  - Customer A: "Your credentials discovered in Customer B's logs"
  - Customer B: "Attempted access using Customer A's credentials detected"
  - Both notified within incident response plan timeline (typically 1 hour)
- External watchdog confirms incident independently and escalates

**Investigation (4-24 hours):**
- APTS-AL-026: Root cause analysis: isolation misconfiguration, software bug, or operator error?
- APTS-TP-018: Assess scope: how long was leakage window? What data was exposed?
- APTS-AR-001 through AR-012: Audit trail analysis: when did credentials leak? How?
- APTS-TP-017: Assess isolation architecture: what failed?

**Recovery (4-48 hours):**
- APTS-SC-018: Fix isolation vulnerability (reconfigure namespace, rebuild container, patch software)
- APTS-SC-014, SC-016: For Engagement A, rollback any actions taken with Customer B's system, cleanup all artifacts
- APTS-SC-016: Preserve evidence in write-once storage for forensic and regulatory investigation
- Credential rotation: all customer credentials in HSM re-issued, old credentials revoked

**Compliance (24-72 hours):**
- APTS-TP-A01 (Advisory): Assess GDPR/CCPA/HIPAA notification requirements (data breach with customer A's data exposed to Customer B)
- Notify regulators if required
- Prepare customer compensation plan

**Post-Incident (5 business days):**
- APTS-RP-011: Comprehensive incident report for both customers including:
  - Timeline of leakage window
  - What data was exposed (credentials, test findings, engagement details)
  - Impact assessment (Customer B had access to Customer A's sensitive data)
  - Root cause (for example, shared encryption key, container namespace misconfiguration)
  - Remediation (isolation architectural fix, credential rotation, enhanced monitoring)
  - Preventive measures (monthly isolation penetration tests per APTS-TP-017, and network TAP analysis)
- Customers must approve before testing resumes
- Autonomy level downgrade mandatory until isolation architecture re-verified

---

### Scenario 3: AI Model Drift Detected Mid-Engagement

**Incident:** Platform's decision-making pattern anomaly detected: escalation frequency drops 40% despite constant input profiles. Investigation reveals AI model version was auto-updated by provider, changing decision behavior.

**Detection (15 mins):**
- APTS-SC-010: Anomaly detection identifies statistically significant decision-making pattern deviation (escalations/hour dropped from 2.5 to 1.5)
- Confidence scoring on anomaly: medium confidence (clear pattern, but benign cause not yet identified)
- Severity: SEV-3 (Medium) initially, escalate to SEV-2 if unable to determine cause

**Escalation (15-30 mins):**
- APTS-HO-013 (Scope uncertainty): If confidence in decisions falls below 75% due to unexplained model change, escalate to operator
- Operator contacted with anomaly details and recommendation to pause pending investigation
- Operator pauses new testing actions for affected engagement

**Investigation (1-2 hours):**
- APTS-AL-026: Determine if model change was intentional or unauthorized
- Review APTS-TP-002 (Model version pinning): Was specific model version pinned? Did platform auto-update without approval?
- APTS-TP-019 (AI model provenance): Check model training data history; was customer data used to train new version?
- APTS-AR-001 through AR-012: Audit all decisions made under new model version; were they sound?

**Recovery & Remediation (1-4 hours):**
- Rollback to previous model version (requires APTS-TP-002 version pinning support)
- Re-assess any decisions made under new model that might be unsound
- Verify no customer data leaked into model training (APTS-TP-019)

**Customer Notification (1-2 hours):**
- Inform customer of model change and decision review
- If customer data was NOT used for training: approval to resume with version-pinned model
- If customer data WAS used for training: escalate to CRITICAL, suspend engagement pending investigation

**Post-Incident (4-8 hours):**
- Implement APTS-TP-002: version pinning with no auto-updates
- Update incident response plan to address AI model lifecycle events
- Training data governance review (APTS-TP-019)

---

### Scenario 4: Platform Discovers Illegal Content on Target

**Incident:** During web application testing, platform's file enumeration discovers child sexual abuse material (CSAM) on a web server.

**Detection (5 mins):**
- APTS-HO-011: Escalation trigger: illegal content detected
- Severity: SEV-1 (Critical)

**Immediate Response (5-10 mins):**
- APTS-SC-009: Kill switch activated (testing halted, no further system access)
- APTS-HO-015: Operator notified immediately via automated call
- APTS-HO-011: Escalation to human reviewer immediately; autonomous operations paused

**Escalation & Decision (10-30 mins):**
- Operator reviews discovery with evidence (file listing, metadata, not content access)
- Legal consultation: obligation to report to law enforcement
- Decide: (a) cease testing and report to NCMEC/FBI, (b) continue testing if findings are unrelated and system access permitted, with law enforcement notification

**Evidence Preservation (immediately):**
- APTS-SC-016: Evidence captured without modifying target system (file listings, metadata)
- APTS-RP-001: Raw evidence documented with chain of custody
- Stored securely in write-once storage

**Regulatory Notification (within 1-4 hours per jurisdiction):**
- Report to National Center for Missing & Exploited Children (NCMEC) if in US
- Local law enforcement notification
- Customer notification: platform discovered content and reported per legal obligation

**Investigation & Post-Incident (4-24 hours):**
- Root cause: how was CSAM stored on customer's system? Was customer aware?
- APTS-AL-026: Assess autonomy level appropriateness (correct escalation occurred)
- APTS-RP-011: Document incident without disclosing actual content, include law enforcement report reference

---

### Scenario 5: Operator Credentials Compromised

**Incident:** Operator's API key used to approve unauthorized testing action on unrelated customer's system. External watchdog detects and flags divergence between operator's typical approval patterns and this action.

**Detection (10 mins):**
- APTS-SC-010: Anomaly detection identifies unusual approval pattern (operator approving actions outside their normal engagement)
- APTS-SC-017: External watchdog independently validates audit logs and confirms unauthorized action
- Severity: SEV-1 (Critical) - potential operator credential compromise

**Immediate Response (10-30 mins):**
- APTS-SC-009: Kill switch activated for all engagements with operator's approval chain
- APTS-HO-009: Authority transfer to backup operator per chain of command
- Operator's credentials revoked (API key, session tokens)
- Investigation: was operator's key stolen or was operator manipulated?

**Containment (30 mins - 2 hours):**
- Review all actions approved by compromised operator in last 24-48 hours
- APTS-SC-014, SC-016: Rollback any unauthorized actions, cleanup artifacts
- Preserve evidence of breach

**Investigation (2-24 hours):**
- Forensic analysis: was key stolen (phishing, malware) or operator coerced?
- APTS-HO-018: Assess operator competency and training after incident
- If key theft: determine scope of exposure (what systems accessed with key?)
- If operator coerced: assess social engineering attack

**Recovery & Prevention (4-24 hours):**
- Operator credential re-issuance with new secure key
- APTS-HO-009: Authority review and re-confirmation
- APTS-HO-018: Security training refresher
- Implement additional controls: hardware token requirement for CRITICAL approvals, dual operator approval for suspicious actions

**Customer Notification (1-4 hours):**
- Notify customers whose systems were accessed: operator credentials compromised, unauthorized approval detected and blocked by external watchdog
- No actual damage occurred; isolation and external monitoring prevented exploitation

---

## Cross-Domain Consistency

When implementing incident response, the escalation paths, containment mechanisms, and notification workflows must operate as a coherent sequence rather than independent processes. This section describes the integration points:

### Escalation-to-Containment Integration

- **Escalation triggers (APTS-HO-011 through APTS-HO-014)** must be defined and configured BEFORE testing begins
- When escalation threshold is crossed, escalation MUST directly activate **containment mechanisms (APTS-SC-009)**
- For SEV-1 incidents, escalation must automatically activate kill switch Phase 1 (cease new actions within 5 seconds)
- For SEV-2 incidents, escalation must pause new autonomous actions pending operator decision (operator may resume, mitigate, or kill switch)
- For SEV-3/SEV-4, escalation notifies operator without automatic pause; operator decides on pause

### Notification-to-Escalation Integration

- **Real-time activity feed (APTS-HO-015)** must show escalation state (pending, in progress, resolved)
- **Stakeholder notification (APTS-HO-017)** must include escalation status in engagement updates
- The platform must notify the customer of escalation within documented SLA (typically 1 hour for SEV-1, 4 hours for SEV-2)
- The platform may require customer approval before autonomous testing resumes after SEV-1 escalation

### Investigation-to-Recovery Integration

- **Root cause investigation (APTS-AL-026)** must determine whether autonomy level was appropriate
- If investigation determines autonomy level was too high, **autonomy level downgrade** is mandatory before testing resumes
- **Audit trail (APTS-AR-001 through APTS-AR-012)** must support investigation by providing complete decision timeline
- **Evidence preservation (APTS-SC-016)** must occur BEFORE rollback so investigation can validate findings

### Recovery-to-Resumption Integration

- **Safety control re-verification (APTS-SC-018)** must complete before testing resumes after SEV-1 incident
- **Post-incident report (APTS-RP-011)** must be delivered and customer-approved before resumption
- **Autonomy level downgrade (if applicable)** must be implemented before testing resumes at higher autonomy level
- The platform must require both operator and customer approval before testing resumption

---

## Reference to Cross-Domain Integration

For how requirements interact across all domains (not just incident response), see [Cross-Domain Integration Matrix](Cross_Domain_Integration.md). That document maps requirements to their dependencies and integration points across Safety Controls, Human Oversight, Graduated Autonomy, Auditability, Supply Chain Trust, and Reporting domains.
