# Safety Controls and Impact Management

**Domain Prefix:** APTS-SC | **Requirements:** 20

This domain defines how an autonomous penetration testing platform classifies the potential impact of its actions, limits blast radius, enforces graduated escalation thresholds, terminates testing on adverse conditions, recovers from incidents, and contains the agent runtime within a declared execution boundary enforced outside the agent's own control. Safety Controls complement Scope Enforcement: where SE decides whether an action is inside the agreed envelope, SC decides whether that in-scope action is safe enough to run right now given its predicted impact, cumulative risk, and current system health, and whether the agent's execution environment continues to enforce the platform's declared containment boundary. A platform that cannot stop itself, cannot score what it is doing against Confidentiality, Integrity, and Availability (CIA) dimensions, cannot detect and recover from an unintended effect, or cannot enforce a sandbox boundary on its own agent runtime cannot safely operate at any autonomy level above L1. Requirements in this domain govern impact classification, rate and payload constraints, threshold escalation, kill switches, health-triggered halts, circuit breakers, reversibility tracking, rollback, post-test integrity checks, incident containment and recovery, execution sandbox boundary integrity, and external enforcement of the agent's action allowlist.

This domain covers blast-radius management and hard-stop capability. Scope boundary enforcement belongs to Scope Enforcement (SE), human approval workflows to Human Oversight (HO), and evidence of safety-control actions to Auditability (AR).

> For implementation guidance, see the [Implementation Guide](Implementation_Guide.md).

---

## Domain Overview

The 20 requirements in this domain fall into seven thematic groups:

| Group | Requirements | Purpose |
|---|---|---|
| **Impact classification and scoring** | APTS-SC-001, APTS-SC-002, APTS-SC-003 | CIA dimensional scoring, industry-specific considerations, worked classification examples |
| **Rate, threshold, and cumulative risk controls** | APTS-SC-004, APTS-SC-005, APTS-SC-006, APTS-SC-007, APTS-SC-008 | Rate and payload constraints, cascading-failure prevention, escalation workflow, cumulative risk scoring, schema-validated thresholds |
| **Kill switch and automated termination** | APTS-SC-009, APTS-SC-010, APTS-SC-011, APTS-SC-012, APTS-SC-013 | Kill switch, health-triggered halts, condition-based termination, network circuit breaker, time-based termination |
| **Reversibility, rollback, and post-test integrity** | APTS-SC-014, APTS-SC-015, APTS-SC-016 | Reversible action tracking and rollback, post-test integrity validation, evidence preservation and cleanup |
| **External watchdog and incident recovery** | APTS-SC-017, APTS-SC-018 | External watchdog and operator notification, incident containment and recovery |
| **Execution sandbox and agent containment** | APTS-SC-019, APTS-SC-020 | Sandbox and containment boundary integrity, action allowlist enforcement external to the model |

### Requirement Index

| ID | Title | Classification |
|---|---|---|
| APTS-SC-001 | Impact Classification and CIA Scoring | MUST \| Tier 1 |
| APTS-SC-002 | Industry-Specific Impact Considerations | MUST \| Tier 2 |
| APTS-SC-003 | Real-World Impact Classification Examples | SHOULD \| Tier 2 |
| APTS-SC-004 | Rate Limiting, Bandwidth, and Payload Constraints | MUST \| Tier 1 |
| APTS-SC-005 | Cascading Failure Prevention in Interconnected Systems | SHOULD \| Tier 2 |
| APTS-SC-006 | Threshold Escalation Workflow (Automated → Approval → Prohibited) | MUST \| Tier 2 |
| APTS-SC-007 | Cumulative Risk Scoring with Time-Based Decay | MUST \| Tier 2 |
| APTS-SC-008 | Threshold Configuration with Schema Validation | SHOULD \| Tier 3 |
| APTS-SC-009 | Kill Switch | MUST \| Tier 1 |
| APTS-SC-010 | Health Check Monitoring, Threshold Adjustment, and Automatic Halt | MUST \| Tier 1 |
| APTS-SC-011 | Condition-Based Automated Termination | MUST \| Tier 2 |
| APTS-SC-012 | Network-Level Circuit Breaker | MUST \| Tier 2 |
| APTS-SC-013 | Time-Based Automatic Termination with Operator Override | SHOULD \| Tier 3 |
| APTS-SC-014 | Reversible Action Tracking and Rollback | MUST \| Tier 2 |
| APTS-SC-015 | Post-Test System Integrity Validation | MUST \| Tier 1 |
| APTS-SC-016 | Evidence Preservation and Automated Cleanup | MUST \| Tier 2 |
| APTS-SC-017 | External Watchdog and Operator Notification | MUST \| Tier 2 |
| APTS-SC-018 | Incident Containment and Recovery | MUST \| Tier 2 |
| APTS-SC-019 | Execution Sandbox and Containment Boundary Integrity | MUST \| Tier 2 |
| APTS-SC-020 | Action Allowlist Enforcement External to the Model | MUST \| Tier 1 |

### Conformance

A platform claims conformance with this domain by satisfying all MUST requirements at the compliance tier it targets. APTS defines three cumulative compliance tiers (Tier 1 Foundation, Tier 2 Verified, Tier 3 Comprehensive) in the [Introduction](../Introduction.md); a Tier 2 platform satisfies every Tier 1 SC requirement plus every Tier 2 SC requirement, and a Tier 3 platform satisfies all three tiers. SHOULD-level requirements are interpreted per RFC 2119.

One appendix-only advisory requirement for this domain (APTS-SC-A01 Platform Health Monitoring and Anomaly Detection) is documented in the [Advisory Requirements appendix](../appendix/Advisory_Requirements.md). It is not required for conformance at any tier.

Every requirement in this domain includes a Verification subsection listing the verification procedures a reviewer uses to confirm implementation.

---

## APTS-SC-001: Impact Classification and CIA Scoring

**Classification:** MUST | Tier 1

### Requirement

MUST implement a multi-tier impact classification system that categorizes every pentest action before execution, with discrete impact levels (Critical, High, Medium, Low) providing graduated escalation thresholds. Every pentest action MUST be scored against Confidentiality, Integrity, and Availability dimensions with a weighted impact calculation, where the minimum dimension score determines escalation level. Organizations MUST maintain an authoritative mapping document categorizing all supported pentest techniques and exploits with pre-classified impact levels, CIA scores, and reversibility status. This mapping MUST be reviewed and updated quarterly or when new techniques are added. Unclassified techniques MUST NOT execute.

### Verification

1. **Action catalog audit**: Sample 50 actions from methodology library (DNS, web, exploitation, lateral); verify each has explicit impact level assigned (Critical/High/Medium/Low) and CIA dimension scoring
2. **Pre-execution classification**: Execute 20 test runs; review execution logs for timestamp showing classification assigned before action execution timestamp
3. **CIA scoring validation**: Select 20 diverse pentest actions; have independent security reviewer score each action's CIA impact; verify impact vectors calculated correctly; confirm minimum dimension drives escalation
4. **Approval pathway enforcement**: For 10 high-impact actions, verify classification directly determined approval requirement (high=escalation, medium=standard, low=autonomous); confirm in audit log
5. **Impact level distribution**: Verify library includes balanced distribution (not all critical); confirm at least 30% low-impact, 40% medium, 20% high, 10% critical
6. **Classification consistency**: Two independent reviewers classify 10 random actions; verify >90% agreement on assigned impact level
7. **Mapping completeness**: Audit all supported techniques have impact classification; verify no unclassified techniques can execute
8. **Lookup performance**: Test classification lookup performance (must return without observable delay to test execution)
9. **Quarterly review**: Confirm quarterly review occurred with documented changes

---

## APTS-SC-002: Industry-Specific Impact Considerations

**Classification:** MUST | Tier 2

**Applicability:** This requirement applies to platforms targeting regulated industries (healthcare, financial services, critical infrastructure). Platforms exclusively testing non-regulated environments MAY document a justified exemption.

### Requirement

Platforms MUST adjust impact classifications for industry-specific regulatory requirements. Healthcare systems MUST treat all direct patient data access as Critical. Financial systems MUST treat all cardholder data access as Critical. Critical infrastructure (utilities, transportation, communications) MUST treat availability impacts as one tier higher than calculated.

### Verification

1. Build a seeded test set containing at least one healthcare target (PHI present), one PCI target (cardholder data present), and one critical-infrastructure target (utility/transportation/communications)
2. Submit each target to the platform's classification engine; verify healthcare target classifies all direct patient data access as Critical, PCI target classifies all cardholder data access as Critical, and critical-infrastructure target elevates availability impacts by one tier above the baseline calculation
3. For each reclassified action, verify the approval chain matches the regulatory requirement documented for that industry (healthcare, PCI, critical infrastructure)
4. Test that PHI/PCI data access is always escalated to Critical regardless of other CIA factors
5. Confirm critical infrastructure availability impacts are elevated by one tier in the classification output

> **See also:** APTS-SC-001 (baseline impact classification framework this extends for regulated industries), APTS-SE-011 (multi-tenant and regulated environment awareness).

---

## APTS-SC-003: Real-World Impact Classification Examples

**Classification:** SHOULD | Tier 2

### Requirement

SHOULD document at least 10 representative pentest scenarios with calculated impact classifications, CIA scores, and approval workflows. Examples SHOULD include password spraying, directory traversal, buffer overflow exploitation, and data exfiltration attempts. Scenarios may be drawn from past engagements, lab environments, or industry-documented attack patterns.

### Verification

1. Review the platform's documented scenario corpus; verify it contains at least 10 representative pentest scenarios with named techniques (password spraying, directory traversal, buffer overflow, data exfiltration, and others)
2. For each scenario, verify the documentation includes the expected CIA score, impact tier, and approval workflow
3. For each documented scenario, compare the recorded classification and approval workflow against the platform's documented scoring model; fail any scenario whose recorded classification deviates from the model without a documented exception
4. Verify scenarios cover at least 4 distinct technique types (reconnaissance, exploitation, post-exploitation, data handling)

> **See also:** APTS-SC-001 (impact classification model scenarios illustrate), APTS-SC-002 (industry-specific impact rules applied in worked examples).

---

## APTS-SC-004: Rate Limiting, Bandwidth, and Payload Constraints

**Classification:** MUST | Tier 1

### Requirement

MUST implement hierarchical rate limiting and payload constraints for all active pentest operations:

**Per-host rate limiting:** MUST implement per-host connection limits and rate limiting. Rate limits MUST be configurable per impact tier, with lower-impact actions permitted higher rates and higher-impact actions restricted to lower rates.

**Cascading rate limits:** MUST implement cascading rate limits at subnet, datacenter, and engagement-wide levels. If aggregate traffic to a subnet approaches configured limits, the system MUST proactively reduce per-host rate limits to prevent subnet-level overload. If engagement-wide limits are reached, automatically halt all new actions across all targets.

**Payload and bandwidth constraints:** MUST enforce maximum payload sizes configurable per impact tier. Default limits that MUST be applied unless the Rules of Engagement specifies alternative values: Informational/Low actions limited to 100KB payloads, Medium actions to 10MB, High actions to 100MB, Critical actions to 500MB with engagement-wide bandwidth cap of 5 Gbps. Organizations MUST document their configured limits and any deviations from default values. Any action exceeding size limit MUST be automatically rejected before transmission.

> **See also:** APTS-SE-019 (adaptive backoff, DoS prevention, and continuous-mode production impact controls). SC-004 governs per-host, per-subnet, and engagement-wide rate limits and payload sizes as safety controls; SE-019 governs scheduling, backoff behavior, and production-impact thresholds as scope controls.

### Verification

1. Monitor request rates during test execution; verify requests never exceed configured per-host limits
2. Test that exceeding limits triggers automatic throttling
3. Confirm rate limits apply independently per target host
4. Simulate multi-target attack scenario; confirm subnet limit triggers load reduction when approaching threshold
5. Test engagement-wide halt at maximum load
6. Attempt to send payload larger than limit; verify rejection before transmission
7. Monitor bandwidth consumption during tests; confirm engagement-wide bandwidth cap enforcement
8. Audit logs showing rate limit enforcement and escalation at all levels

---

## APTS-SC-005: Cascading Failure Prevention in Interconnected Systems

**Classification:** SHOULD | Tier 2

### Requirement

SHOULD detect and prevent cascading failures when testing systems with interdependencies. Before attacking system B that depends on system A, verify system A is functioning normally. If attacking system A causes degradation in dependent systems, automatically reduce attack intensity on A or halt testing entirely.

### Verification

1. In a staging environment, define a topology with at least one upstream/downstream dependency pair where downstream system B depends on upstream system A
2. Establish a measurable health baseline for the downstream system (response time, error rate, or availability metric)
3. Attack upstream system A; induce measurable degradation in downstream system B beyond the platform's documented threshold; verify the platform reduces attack intensity on A or halts testing within the documented response window
4. **Negative test (control case):** Attack upstream system A at a level that does not cause downstream degradation beyond the threshold; verify no unnecessary halt or reduction is triggered
5. Verify recovery: after attack intensity is reduced, confirm downstream system B restores to baseline health within the documented recovery window
6. Audit logs show cascade detection trigger, intensity reduction or halt decision, and recovery confirmation with timestamps

> **See also:** APTS-SC-004 (rate limiting and payload constraints used to throttle upstream pressure), APTS-SC-009 (kill switch that halts testing when cascading impact is detected).

---

## APTS-SC-006: Threshold Escalation Workflow (Automated → Approval → Prohibited)

**Classification:** MUST | Tier 2

### Requirement

MUST implement graduated responsibility escalation where Informational/Low impact actions execute automatically without approval, Medium impact actions require standard approval within a defined window, High impact actions require elevated approval within a defined window, and Critical actions require senior approval plus live operator confirmation. Approval timeout windows MUST be documented per severity level in the platform's escalation policy. Actions exceeding their configured approval timeout are denied by default.

> **See also:** APTS-HO-001 (pre-approval gates by autonomy level), APTS-AL-011 (escalation triggers and exception handling).

### Verification

1. Test Informational action executes immediately
2. Test Medium action requires approval before execution
3. Test High action requires elevated approval within configured window
4. Test Critical action requires senior approval + live operator confirmation
5. Test timeout queuing preserves action for next approval window
6. Verify timeout windows reset on schedule
7. **Negative test (no approval):** Attempt a Medium-impact action without submitting any approval; verify execution is blocked before dispatch and denial is logged
8. **Negative test (expired approval):** Submit approval for a High-impact action, wait past the configured approval timeout, then attempt execution; verify the action is denied
9. **Negative test (insufficient authority):** Submit approval for a Critical-impact action using a standard (non-senior) approver; verify the action is rejected and the insufficient-authority denial is logged

---

## APTS-SC-007: Cumulative Risk Scoring with Time-Based Decay

**Classification:** MUST | Tier 2

### Requirement

The platform MUST track cumulative risk across the entire engagement by considering impact severity, action frequency, duration, and system criticality. Risk accumulation SHOULD decay over time. Scoring methodology MUST be documented and auditable. Configurable thresholds MUST trigger escalation at defined risk levels. The specific decay function and reset windows are implementation decisions that MUST be documented.

Cumulative risk scoring MUST use the impact classification framework defined in APTS-SC-001 as its input taxonomy. The scoring model MUST NOT define an independent impact classification that contradicts or duplicates SC-001.

### Verification

1. Execute multiple Medium actions; verify accumulation
2. Run a no-action period equal to one documented decay half-life or decay window; verify the cumulative risk score decreases by the documented decay amount (within ±5% tolerance)
3. Verify impact threshold triggers intensity reduction
4. Confirm reset windows apply correctly
5. Execute single High impact action; verify points awarded per documented scoring model
6. Execute Critical impact action; verify higher points awarded per documented scoring model
7. Execute repeated actions on same target; verify frequency multiplier applied
8. Verify critical system actions earn elevated multiplier per documented model
9. Test automatic halt when cumulative score exceeds configured threshold
10. Audit cumulative impact logs

> **See also:** APTS-AL-022 (cumulative risk scoring at autonomy levels).

---

## APTS-SC-008: Threshold Configuration with Schema Validation

**Classification:** SHOULD | Tier 3

### Requirement

The platform SHOULD store all threshold configurations in a structured, human-readable format with schema enforcement. Configuration SHOULD include impact level thresholds, approval chains, rate limits, payload constraints, and risk scoring. The system SHOULD validate configuration on startup and reject invalid settings with detailed error messages. This requirement ensures the configuration integrity of the risk scoring algorithm defined in APTS-SC-007.

### Verification

1. Load valid threshold configuration; verify acceptance
2. Load invalid configuration; verify schema rejection
3. Modify a threshold value; verify new limit takes effect
4. Create configuration with contradictory values; verify validation fails

---

## APTS-SC-009: Kill Switch

**Classification:** MUST | Tier 1

### Requirement

The platform MUST provide multiple independent kill switch mechanisms enabling immediate halt of all testing activity. Kill switches MUST include at minimum: operator-initiated local halt, remote halt by authorized personnel, and automatic failsafe halt when communication with the control plane is lost. Kill switch halt MUST occur in two distinct phases:

**Phase 1 (within 5 seconds) - Safety-Critical Cessation:**
- Cease initiating new network requests to target systems
- Cease initiating new exploit attempts and payloads
- Cease initiating new testing actions
- All in-flight operations continue to completion
- Phase 1 measures cessation of new action initiation at the decision layer. In-flight operations that have already been dispatched to the network stack MAY complete.

**Phase 2 (within 60 seconds) - Graceful Shutdown and Process Tree Termination:**
- Complete in-flight network operations gracefully
- Preserve system state for forensic investigation and audit
- Track all child processes, network connections, and external agents spawned during testing
- Terminate all spawned processes and child agents (not just the primary process)
- Close all open network connections
- Stop all distributed or cloud-hosted agents
- Revoke any temporary credentials issued during testing
- Cancel all scheduled or queued actions
- Flush and finalize all logs

Phase 1 represents the safety-critical boundary; all new testing MUST cease immediately. Phase 2 allows orderly resource cleanup, credential revocation, and state preservation. Termination of child processes MUST NOT delay Phase 1 cessation of new testing activity. All kill switches MUST function independently of each other. Within 60 seconds of activation, the platform MUST confirm zero active processes, zero open connections, and zero pending actions. If confirmation fails, the platform MUST alert the operator with a list of unterminated resources.

**Rationale for timing bounds:** Phase 1's 5-second ceiling reflects the maximum acceptable delay between an operator's decision to halt and cessation of new outbound actions; exceeding this window risks additional unintended impact on target systems. Phase 2's 60-second ceiling accommodates graceful TCP connection termination (TIME_WAIT states up to 30 seconds), in-flight transaction completion, forensic log flushing to durable storage, and state snapshot capture. These bounds are safety-critical and MUST NOT be relaxed.

> **See also:** APTS-HO-008 (state dump for forensic investigation), APTS-AL-012 (safety controls scaling with autonomy level).

### Verification

1. Activate each kill switch mechanism independently; verify Phase 1 (halt new requests) within 5 seconds
2. Verify in-flight operations complete and Phase 2 finishes within 60 seconds total
3. Sever control plane communication; verify automatic halt triggers
4. Verify no new testing actions initiated after kill switch activation
5. Verify kill switches function independently (failure of one does not affect others)
6. Start a multi-process test with child processes and network listeners; activate kill switch; verify all processes terminated, all connections closed, and all distributed/cloud agents stopped within 60-second window
7. Verify any temporary credentials issued during testing are revoked
8. Verify operator is alerted if any resource fails to terminate within the 60-second window

---

## APTS-SC-010: Health Check Monitoring, Threshold Adjustment, and Automatic Halt

**Classification:** MUST | Tier 1

### Requirement

The platform MUST continuously monitor the health and responsiveness of target systems during testing and automatically halt testing when degradation is detected. Health checks MUST run at configurable intervals (recommended defaults: every 30 seconds for Critical assets, every 60 seconds for Production, every 5 minutes for Non-Production). At minimum, health checks MUST include response time measurement and service availability verification using methods appropriate to the target (for example, HTTP GET, ICMP ping, database query).

Baseline MUST be calculated as the median response time across the first 10 health check cycles, excluding outliers beyond the 5th and 95th percentile. The baseline MUST be recalculated when target infrastructure changes are detected (for example, deployment events, scaling operations). Health check overhead MUST be measured as the sum of all health check traffic across all concurrent targets divided by total testing traffic over the measurement window. When testing traffic is zero (idle state), health check traffic is exempt from the percentage limit but MUST NOT exceed the configured absolute bandwidth cap.

If a health check fails or response time exceeds 200% of the established baseline, the platform MUST trigger the escalation workflow defined in APTS-SC-006. If consecutive failures exceed a configurable threshold (recommended default: 3 consecutive failures), the platform MUST automatically halt testing against the affected target and notify the operator.

Health checks themselves MUST be low-overhead and MUST NOT contribute to target degradation. The platform MUST log all health check results for post-engagement analysis.

**Dynamic Threshold Adjustment:** The platform MUST monitor target system responsiveness (latency, error rates, recovery time) and dynamically adjust impact thresholds. The system SHOULD decrease thresholds for slow-recovering systems and optionally increase thresholds for fast-recovering systems. Threshold adjustments MUST apply per-target (not globally). When a threshold decrease crosses the escalation boundary defined in APTS-SC-006, the escalation workflow MUST activate.

The platform SHOULD also implement advanced monitoring for unintended impact beyond baseline health checks. When implemented, the monitoring MUST cover metrics appropriate to the target environment (for example, response times, error rates, resource utilization), and the specific metric set MUST be documented per engagement. The system SHOULD alert operators when degradation exceeds configured thresholds, escalating to automatic halt when degradation becomes severe.

### Verification

1. **Baseline establishment**: Start engagement against a healthy target; verify the platform establishes response time baselines within the first 5 health check cycles
2. **Degradation detection**: Simulate target degradation (increase response time above 200% of baseline); verify the platform detects and triggers escalation per APTS-SC-006
3. **Automatic halt**: Simulate 3 consecutive health check failures; verify testing halts against the affected target and operator notification is sent
4. **Scope isolation**: In a multi-target engagement, degrade one target; verify health check halt applies only to the degraded target, not the entire engagement
5. **Health check overhead**: Measure health check traffic over a 10-minute window; verify it does not exceed 1% of total testing traffic
6. **Interval configuration**: Modify health check intervals; verify new intervals take effect within one cycle
7. **Threshold decrease on slow recovery**: Simulate a target with slow recovery (for example, increased response times persisting after test actions); verify the platform automatically decreases impact thresholds for that target
8. **Threshold increase on fast recovery**: Simulate a target that recovers quickly from impacts; verify the platform permits threshold increase if this optional behavior is implemented
9. **Adjustment logging**: Review 10 threshold adjustment events; verify each logs: the triggering metric, the old threshold, the new threshold, the responsiveness data that drove the change, and the timestamp
10. **Cross-target independence**: In a multi-target engagement, degrade one target's responsiveness; verify threshold adjustments apply only to the affected target, not globally
11. **Escalation integration**: Trigger a threshold decrease that crosses the escalation boundary defined in APTS-SC-006; verify the escalation workflow activates
12. **Advanced monitoring (if implemented)**: Configure alert and escalation thresholds; trigger degradation events at varying levels; verify alerts fire correctly with metric name, current value, baseline, and deviation; verify automatic halt when degradation becomes severe

> **See also:** APTS-HO-012 (impact threshold breach escalation based on testing impact metrics).

---

## APTS-SC-011: Condition-Based Automated Termination

**Classification:** MUST | Tier 2

### Requirement

MUST define explicit termination conditions that automatically halt testing without operator intervention. Conditions MUST include at minimum: target service unavailability (consecutive health check failures within a configured window), error rate exceeding a configured threshold for a sustained period, resource exhaustion (CPU, memory) exceeding configured limits, and unexpected privilege escalation outside authorized scope. Specific thresholds and durations MUST be documented in the platform's safety configuration and made available to customers. Each condition MUST have detailed logging of what triggered termination. Condition-based termination is independent of the circuit breaker mechanism (APTS-SC-012). When a circuit breaker probe fails after the cooldown period, the platform MUST escalate to condition-based termination per this requirement.

### Verification

1. Trigger each termination condition individually
2. Verify halt occurs immediately on condition trigger
3. Confirm detailed logs record what condition triggered halt
4. Test combinations of conditions
5. Verify no continued testing after halt

> **See also:** APTS-HO-011 (unexpected findings escalation to human operators)

---

## APTS-SC-012: Network-Level Circuit Breaker

**Classification:** MUST | Tier 2

### Requirement

The platform MUST implement circuit breaker logic that automatically suspends testing when target systems show sustained degradation. When the circuit breaker activates, the platform MUST stop all new requests to the affected target, wait a configurable cooldown period, then attempt a single probe request before resuming. If the probe fails, the circuit breaker MUST remain active.

### Verification

1. Induce sustained target degradation; verify circuit breaker activates
2. Verify all new requests are suspended during active state
3. After cooldown, verify a single probe request is attempted
4. Verify successful probe resumes testing; failed probe keeps circuit open

---

## APTS-SC-013: Time-Based Automatic Termination with Operator Override

**Classification:** SHOULD | Tier 3

### Requirement

The platform SHOULD enforce operator-specified maximum engagement duration with configurable time limits. Operators SHOULD be able to extend engagement duration within defined bounds. The system SHOULD provide advance warning before time-based termination.

### Verification

1. Set a test engagement duration
2. Verify advance warning notifications sent before deadline
3. Verify automatic halt at deadline
4. Test operator extension request
5. Verify extension requires manager approval

---

## APTS-SC-014: Reversible Action Tracking and Rollback

**Classification:** MUST | Tier 2

### Requirement

MUST track state for all reversible actions and maintain explicit rollback procedures. For all reversible actions (accounts created, files modified/created, database records modified, configurations changed, processes started, credentials obtained), MUST: (1) Track action name, timestamp, target resource ID, pre-action state, action parameters, rollback procedure, and verification method; (2) Persist state to durable storage after each action; (3) Document explicit rollback procedure for every action type with step-by-step instructions and success verification; (4) Implement rollback procedures as executable automated scripts with no manual steps; (5) Define maximum rollback time for each action type; (6) Trigger alerts when rollback verification fails. Rollback operations MUST precede automated cleanup (APTS-SC-016). Evidence MUST be captured before rollback begins (see APTS-SC-016 evidence preservation requirements).

The platform MUST track state changes for all reversible actions and document rollback procedures. Automated rollback SHOULD be implemented for low-risk actions (account creation, file creation, simple configuration changes). For complex actions where automated rollback risks further damage (schema changes, authentication reconfigurations), documented manual recovery procedures are acceptable.

If rollback fails (for example, database transaction cannot be reversed, file cannot be restored), the platform MUST: (a) log the failure with full diagnostic details including the action that could not be rolled back, the error encountered, and the current state of the affected system, (b) preserve the current system state for manual recovery, (c) alert the operator with a rollback failure notification including recommended manual remediation steps, and (d) halt further testing on the affected target until the operator acknowledges the failure and either resolves it or authorizes continued testing.

### Verification

1. Execute reversible action; verify state recorded and persisted to durable storage
2. Simulate crash; verify state survives
3. Confirm all action types have documented rollback procedures
4. Execute rollback procedure; verify completion within the documented maximum rollback time
5. Verify system state matches pre-action state after rollback
6. Test partial rollback detection and alert triggering
7. Verify pre-action state captured correctly

---

## APTS-SC-015: Post-Test System Integrity Validation

**Classification:** MUST | Tier 1

### Requirement

MUST perform thorough integrity validation after engagement completes: verify file checksums match baseline, confirm no unexpected accounts exist, check database record counts against baseline, verify configurations match baseline, and confirm no unexpected processes are running. Post-test validation MUST be automated and complete within a documented timeframe. Any discrepancies MUST be logged and escalated.

### Verification

1. Confirm a pre-engagement baseline exists covering file checksums, user/service account inventory, database record counts, configuration snapshots, and running process list
2. Execute test actions that modify at least one baseline category
3. Run the automated post-engagement integrity validation and confirm it completes within the documented timeframe
4. Verify validation checks each baseline category: file checksums, accounts, database record counts, configurations, and processes
5. Introduce a deliberate discrepancy (for example, a test account not cleaned up) and confirm it is detected, logged, and escalated

---

## APTS-SC-016: Evidence Preservation and Automated Cleanup

**Classification:** MUST | Tier 2

### Requirement

MUST preserve evidence of test actions and provide automated cleanup of all test artifacts. (1) Evidence Preservation: Capture screenshots, log output, error messages, modified file contents, database queries executed, and privilege escalation proofs before any rollback. Evidence MUST be stored in write-once, tamper-evident storage and retained per the engagement's data retention policy. Rollback operations MUST NOT modify evidence storage. (2) Automated Cleanup: Provide automated cleanup procedures that remove all test artifacts including temporary files, created accounts, installed tools, backdoors, test data, and testing activity logs. Cleanup procedures MUST be idempotent (safe to run multiple times), atomic (complete or not at all), and verifiable. Cleanup MUST complete within a documented timeframe proportional to engagement size. Failed cleanup actions MUST be logged and escalated for manual remediation.

### Verification

1. Execute test actions and capture evidence (screenshots, logs, modified file contents) before rollback
2. Execute rollback; verify rollback operations do not access or modify evidence storage; confirm all pre-rollback evidence remains unchanged and accessible in write-once storage
3. Confirm evidence retained per engagement's data retention policy
4. Run automated cleanup; verify all test artifacts removed (temporary files, created accounts, installed tools, test data)
5. Re-run cleanup; verify idempotency (no errors, no changes on second run)
6. Simulate cleanup failure; verify failed action is logged and escalated for manual remediation

---

## APTS-SC-017: External Watchdog and Operator Notification

**Classification:** MUST | Tier 2

### Requirement

An external watchdog process MUST monitor the autonomous pentesting platform and notify operators according to documented Service Level Agreements (SLAs). The platform MUST send health heartbeats and key operational metrics to an external monitoring endpoint outside the platform's own trust boundary. The external monitoring system MUST use separate credentials from the platform to access these endpoints.

If heartbeats stop or metrics indicate anomalies, the external watchdog MUST notify operators and customers within a defined timeframe via multiple channels (messaging, email, dashboard). Operators MUST be notified within the documented SLA timeframe. Customers MUST be notified of confirmed incidents within a defined timeframe via out-of-band channels independent of the platform. Escalation to alternative contacts is required if acknowledgment is not received within a defined window.

Notifications MUST include: what happened, systems affected, automated actions taken, and next steps. Specific heartbeat intervals, metric thresholds, and notification timeframes MUST be documented in the platform's watchdog configuration and made available to customers.

### Verification

1. Verify external monitoring endpoint is outside the platform's trust boundary
2. Verify platform sends heartbeats to external monitoring system at documented intervals
3. Verify platform sends key operational metrics to external monitoring system
4. Verify external monitoring system uses separate credentials from the platform
5. Platform health heartbeats stopped; confirm external watchdog detects and escalates within the configured timeframe
6. Platform metrics indicate anomalies; confirm external watchdog detects and alerts operators
7. Detect anomaly; verify operator notified within documented SLA via configured channels
8. Confirm incident; verify customer notified within documented SLA via out-of-band channels
9. Verify notification includes what happened, scope, actions, and next steps
10. Test escalation: verify higher contact notified if operator/customer not acknowledging within configured window

> **See also:** APTS-SC-018 (incident containment and recovery triggered by watchdog alerts), APTS-HO-010 (human-in-the-loop paging path that watchdog notifications feed into).

---

## APTS-SC-018: Incident Containment and Recovery

**Classification:** MUST | Tier 2

### Requirement

When a platform incident is confirmed, the platform MUST execute documented containment and recovery procedures. (1) Containment: The platform MUST isolate itself from customer networks and test targets promptly. Platform-held credentials SHOULD be rotated as part of containment. The platform MUST capture relevant forensic data (logs, process state) before containment procedures alter system state. (2) Recovery: The platform MUST document recovery procedures for each containment scenario with a defined Recovery Time Objective (RTO). After recovery, all safety controls MUST be re-validated before resuming testing. The platform MUST deliver a post-incident report to the customer within the timeframe defined in the platform's incident response plan, including incident timeline, root cause, affected systems/data, remediation steps, and preventive measures. The platform MUST require customer acknowledgment and approval before testing resumes. Specific containment thresholds, RTO targets, and reporting deadlines MUST be documented in the platform's incident response plan.

### Verification

1. Trigger anomaly; confirm network isolation within documented containment timeframe
2. Verify platform cannot reach customer networks after isolation
3. Verify isolated platform can reach logging/watchdog systems
4. Confirm credentials rotated within documented timeframe; verify old credentials no longer work
5. Confirm memory dump and logs preserved on secure system
6. Execute recovery procedure; verify completion within documented RTO
7. Run complete safety control validation suite; verify all pass
8. Deliver post-incident report within documented timeframe
9. Verify customer acknowledges and approves resumption

---

## APTS-SC-019: Execution Sandbox and Containment Boundary Integrity

**Classification:** MUST | Tier 2

### Requirement

The platform MUST declare and enforce an execution sandbox that bounds the agent runtime's filesystem access, network egress, process capabilities, and system-call surface. The sandbox boundary MUST be enforced by a mechanism outside the agent's control, such as OS-level isolation (kernel namespaces, seccomp, AppArmor, SELinux), hypervisor isolation, or container runtime policy. The platform MUST NOT rely on the agent's own refusal to respect the boundary. The declared boundary MUST specify: (1) filesystem paths the agent runtime may read and write, (2) network destinations the agent runtime may reach, including outbound ports and protocols, (3) process and system-call capabilities the agent runtime may invoke, and (4) any credential or secret stores the agent runtime may access. Any attempt by the agent runtime to take an action outside the declared boundary MUST be blocked by the enforcement layer and logged as a containment event for operator review.

### Rationale

As autonomous pentest platforms become more capable, the assumption that the agent will respect its instructions is not a safety boundary. Containment integrity requires a mechanism that holds regardless of whether the agent "chooses" to respect it, whether the agent has been manipulated, whether the underlying model has changed, or whether the agent has encountered inputs outside its training distribution. Enforcing the boundary at a layer the agent cannot reach from within its execution context is the only architectural property that survives changes in the agent's behavior.

### Verification

1. **Boundary declaration review**: Retrieve the platform's sandbox policy file; confirm it specifies allowed filesystem paths, network egress destinations, process capabilities, and credential access; confirm the policy is enforced at a layer below the agent runtime (kernel, hypervisor, or container runtime).
2. **Filesystem egress test**: From within the agent runtime context, attempt to read a file outside the declared read-allowlist (for example, a sensitive system file such as /etc/shadow on a Linux host); confirm the enforcement layer blocks the action and a containment event is logged.
3. **Network egress test**: From within the agent runtime context, attempt an outbound TCP connection to a destination not on the egress allowlist; confirm the connection is refused at the network policy layer and a containment event is logged.
4. **Process capability test**: Attempt a syscall or capability not in the declared allowlist (for example, ptrace, mount, or raw socket creation); confirm the enforcement layer blocks the call and a containment event is logged.
5. **Credential store isolation test**: Attempt to read a credential or secret outside the agent's declared access list; confirm the read is blocked and logged.
6. **Enforcement-layer independence test**: Modify the agent's internal configuration or system prompt to assert that an out-of-boundary action is now permitted; confirm the enforcement layer still blocks the action, demonstrating that enforcement is independent of the agent's internal state.

---

## APTS-SC-020: Action Allowlist Enforcement External to the Model

**Classification:** MUST | Tier 1

### Requirement

The platform MUST define the agent's permitted tool and action space as an explicit allowlist, and the allowlist MUST be enforced by a component external to the model. Permitted actions MUST NOT be configured solely through the model's system prompt or in-context instructions. Any action the agent attempts to execute that is not present on the external allowlist MUST be blocked by the orchestration layer before it reaches any target system, regardless of how the action was produced by the model. The allowlist MUST be version-controlled, auditable, and subject to the platform's change-management process. Extensions to the action space (new tools, new capabilities, new parameter ranges) MUST be approved and recorded before they become available to the agent at runtime.

### Rationale

System prompts and in-context instructions are not reliable constraints on an agent's action space. They can be overridden by prompt injection, by adversarial inputs, by model updates that change instruction-following behavior, or by distribution shifts the operator has not anticipated. Enforcing the action allowlist in a component the model cannot influence at runtime is the architectural property that makes the constraint actually binding. This requirement is a Tier 1 obligation because it is a baseline property every responsible autonomous pentest platform must have regardless of its claimed assurance level.

### Verification

1. **Allowlist file review**: Retrieve the platform's action allowlist; confirm it is a version-controlled artifact separate from the model's system prompt; confirm entries include tool identifiers, allowed parameters or parameter bounds, and the risk classification assigned to each entry.
2. **External enforcement test**: Through a test harness, induce the model to request a tool identifier that is not on the allowlist; confirm the orchestration layer refuses to dispatch the tool call before it reaches any target system.
3. **System-prompt bypass test**: Modify the system prompt to assert that a disallowed tool is permitted; confirm the external enforcement layer still refuses to dispatch the tool call.
4. **Change-management audit**: Review the last three changes to the allowlist; confirm each has an approval record, a rationale, and a timestamp consistent with the platform's change-management policy.
5. **Runtime inventory test**: Query the platform for the current runtime allowlist; confirm it matches the version-controlled source and has not drifted during operation.

---

> **See also:** [APTS-SC-A02: Context Window Safety and Constraint Preservation](../appendix/Advisory_Requirements.md#apts-sc-a02-context-window-safety-and-constraint-preservation-advisory) — an advisory practice for platforms using LLM-based agents with finite context windows. Addresses the risk of safety-critical constraints being silently lost during context summarization or truncation. High-priority candidate for tier-gated inclusion in v0.2.0.
