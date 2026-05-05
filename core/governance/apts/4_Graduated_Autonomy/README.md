# Graduated Autonomy Levels

**Domain Prefix:** APTS-AL | **Requirements:** 28

This domain defines four levels of operational autonomy for autonomous penetration testing platforms (L1 Assisted through L4 Autonomous) and the controls each level requires. Graduated autonomy is the central safety mechanism of APTS: it ensures that the degree of independent action a platform takes is matched by proportionate human oversight, boundary enforcement, escalation handling, and audit coverage. Requirements in this domain govern how a platform earns the right to operate at a given level, what it must do at that level, and how it transitions or is downgraded between levels. This domain is also the source of the canonical phase model (Reconnaissance → Enumeration → Identification → Exploitation → Post-Exploitation → Reporting) used by the rest of the standard.

**Applicability.** This domain applies to platforms that expose an operator-adjustable level of autonomy over pentest execution. Platforms that operate in a single fixed mode, or that use declarative policy rather than operator-facing autonomy tiers, should map their execution behavior to the nearest APTS Level and document any architectural deviations in their conformance claim. The Level framework describes the autonomy spectrum; it does not prescribe a specific product architecture. Vendors whose architecture does not map cleanly to an APTS Level may propose alternative patterns to the project for consideration in a future revision.

This domain covers level-specific obligations and transitions between autonomy levels. Scope boundary definition belongs to Scope Enforcement (SE), hard-stop controls to Safety Controls (SC), human approval mechanics to Human Oversight (HO), and the audit trail for level transitions to Auditability (AR).

> For implementation guidance, see the [Implementation Guide](Implementation_Guide.md).

---

## Autonomy Levels Overview

APTS defines four discrete autonomy levels. Each level expands what the platform may do without per-action human approval, and each level imposes additional safety, oversight, and audit obligations to compensate for that expansion.

| Level | Name | Human Role | Platform Authority |
|---|---|---|---|
| **L1** | Assisted | Operator commands every action | Executes one technique per command, no chaining, no inference |
| **L2** | Supervised | Operator approves at every phase boundary | Chains techniques within a single phase; proposes next actions |
| **L3** | Semi-Autonomous | Operator sets boundaries, intervenes on exceptions | Executes complete attack chains within pre-approved boundaries |
| **L4** | Autonomous | Operator reviews periodically (weekly/monthly) | Manages multi-target campaigns, dynamic scope, adaptive strategy |

**L1 Assisted** is the baseline for any platform that performs offensive actions on behalf of an operator. The operator selects every target, every technique, and every parameter. The platform executes and reports; it never decides what to do next.

**L2 Supervised** permits the platform to chain related techniques within a single attack phase (for example, multiple enumeration techniques against a discovered host) without per-technique approval, but every transition between phases requires explicit operator authorization. The operator remains in the loop for every meaningful change in risk posture.

**L3 Semi-Autonomous** permits the platform to traverse complete attack chains across all phases, autonomously, provided every action falls within pre-established boundaries (scope, technique allowlist, impact thresholds, escalation triggers). Human oversight shifts from per-action approval to exception-based intervention: the operator is alerted and can intervene only when boundary conditions are crossed or pre-defined escalation triggers fire. L3-classified platforms MUST have documented boundary conditions that trigger mandatory human escalation.

**L4 Autonomous** permits the platform to manage long-duration multi-target campaigns, dynamically discover and include new targets within pre-approved discovery rules, adapt its strategy based on findings, and operate without between-action human contact. Human oversight is exercised through periodic review cycles (weekly summaries, monthly audits, quarterly strategic reviews, annual reauthorization) rather than real-time approval. L4 places the heaviest demands on the supporting organization, not just the platform: dedicated 24/7 monitoring, tested incident response, kill switch authority delegation across all operating hours, and rehearsed tabletop exercises.

### Tier and Level Mapping

APTS Compliance Tiers (Tier 1 Foundation, Tier 2 Verified, Tier 3 Comprehensive) and autonomy Levels (L1 through L4) are distinct concepts and MUST NOT be conflated:

- A **Tier** is a conformance posture: which APTS requirements a platform satisfies.
- A **Level** is an operational mode: how much independent action the platform takes during an engagement.

A Tier 1 platform satisfies the foundational APTS requirements and is generally suitable for L1 operation. A Tier 2 platform satisfies the requirements needed to operate at L2 and L3. A Tier 3 platform satisfies the requirements needed to operate at L4. Several requirements in this domain (APTS-AL-008, APTS-AL-013, APTS-AL-015, APTS-AL-017) are classified at lower Tiers despite describing higher-Level behavior. This is intentional: the requirement applies to any platform that *offers* the corresponding Level, regardless of which Tier the platform targets overall. A platform that does not offer the corresponding Level may treat such requirements as not applicable.

### Requirement Index

| ID | Title | Classification | Primary Level |
|---|---|---|---|
| APTS-AL-001 | Single Technique Execution | MUST \| Tier 1 | L1 |
| APTS-AL-002 | Human-Directed Target and Technique Selection | MUST \| Tier 1 | L1 |
| APTS-AL-003 | Parameter Configuration by Human Operator | MUST \| Tier 1 | L1 |
| APTS-AL-004 | No Automated Chaining or Sequential Decision-Making | MUST \| Tier 1 | L1 |
| APTS-AL-005 | Mandatory Logging and Human-Reviewable Audit Trail | MUST \| Tier 1 | L1 |
| APTS-AL-006 | Basic Scope Validation and Policy Enforcement | MUST \| Tier 1 | L1 |
| APTS-AL-007 | Multi-Step Technique Chaining Within Single Phase | MUST \| Tier 2 | L2 |
| APTS-AL-008 | Real-Time Human Monitoring and Approval Gates | MUST \| Tier 1 | L2 |
| APTS-AL-009 | Tool-Proposed Actions with Operator Modification Capability | SHOULD \| Tier 2 | L2 |
| APTS-AL-010 | Step-by-Step Audit Log with Phase Transitions | MUST \| Tier 2 | L2 |
| APTS-AL-011 | Escalation Triggers and Exception Handling | MUST \| Tier 1 | All levels |
| APTS-AL-012 | Kill Switch and Pause Capability | MUST \| Tier 1 | All levels |
| APTS-AL-013 | Complete Attack Chain Execution Within Boundaries | MUST \| Tier 2 | L3 |
| APTS-AL-014 | Boundary Definition and Enforcement Framework | MUST \| Tier 1 | All levels |
| APTS-AL-015 | Pre-Approved Action Categories and Decision Trees | MUST \| Tier 2 | L3 |
| APTS-AL-016 | Continuous Boundary Monitoring and Breach Detection | MUST \| Tier 1 | All levels |
| APTS-AL-017 | Multi-Target Assessment Management | MUST \| Tier 2 | L3 |
| APTS-AL-018 | Incident Response During Autonomous Testing | MUST \| Tier 2 | L2-L4 |
| APTS-AL-019 | Multi-Target Campaign Management Without Intervention | SHOULD \| Tier 3 | L4 |
| APTS-AL-020 | Dynamic Scope Adjustment and Target Discovery | SHOULD \| Tier 3 | L4 |
| APTS-AL-021 | Adaptive Testing Strategy and Resource Reallocation | SHOULD \| Tier 3 | L4 |
| APTS-AL-022 | Continuous Risk Assessment and Automated Escalation | SHOULD \| Tier 3 | L4 |
| APTS-AL-023 | Complete Audit Trail and Forensic Reconstruction | SHOULD \| Tier 3 | L4 |
| APTS-AL-024 | Periodic Autonomous Review Cycles | SHOULD \| Tier 3 | L4 |
| APTS-AL-025 | Autonomy Level Authorization, Transition, and Reauthorization | MUST \| Tier 2 | All levels |
| APTS-AL-026 | Incident Investigation and Autonomy Level Adjustment | MUST \| Tier 2 | All levels |
| APTS-AL-027 | Evasion and Stealth Mode Governance | SHOULD \| Tier 3 | All levels |
| APTS-AL-028 | Containment Verification for L3 and L4 Autonomy | MUST \| Tier 3 | L3-L4 |

### Conformance

A platform claims conformance with this domain by satisfying all MUST requirements at the tier it targets. APTS defines three cumulative tiers (Tier 1 Foundation, Tier 2 Verified, Tier 3 Comprehensive) in the [Introduction](../Introduction.md); a Tier 2 platform satisfies every Tier 1 AL requirement plus every Tier 2 AL requirement, and a Tier 3 platform satisfies all three tiers. SHOULD-level requirements are interpreted per RFC 2119. As described in the Tier and Level Mapping above, level-specific requirements apply only to platforms that offer the corresponding autonomy level.

One advisory practice relevant to this domain (APTS-AL-A01 Continuous Improvement and Maturity Roadmap) is documented in the [Advisory Requirements appendix](../appendix/Advisory_Requirements.md). It is not required for conformance at any tier.

Every requirement in this domain includes a Verification subsection listing the verification procedures used to confirm implementation.

### Canonical Phase Model

Several requirements in this domain refer to "phases" of an attack chain. APTS uses the following canonical phase model throughout:

**Reconnaissance → Enumeration → Identification → Exploitation → Post-Exploitation → Reporting**

Phase boundaries are significant: at L2, the operator MUST approve every transition from one phase to the next; at L3, transitions may proceed autonomously provided pre-approved boundary checks pass. Within a single phase, related techniques may be chained according to the autonomy level in use.

---

## APTS-AL-001: Single Technique Execution

**Classification:** MUST | Tier 1

### Requirement

At Level 1 Assisted autonomy, the tool MUST execute only a single, isolated attack technique per operation. A technique is an atomic action: a single logical operation that cannot be meaningfully subdivided without changing its purpose. Examples: a port scan across multiple ports is one technique; a SQL injection test using multiple payloads against one parameter is one technique; DNS record enumeration is one technique; a brute-force authentication attempt using a wordlist against one target is one technique. Each technique produces one set of results and targets one logical objective. The tool MUST NOT chain multiple techniques or make decisions about subsequent actions without explicit human direction.

### Verification

- Examine audit logs: each entry represents one completed technique
- No log entries show tool initiating secondary techniques without explicit command
- Operator can demonstrate starting any technique and explain why it was chosen
- Test use: operator issues 100 commands, 100 techniques execute, 0 unexpected actions

---

## APTS-AL-002: Human-Directed Target and Technique Selection

**Classification:** MUST | Tier 1

### Requirement

All target selection and technique selection at Level 1 MUST originate from explicit human command. The tool MUST NOT perform target discovery, vulnerability prioritization, or technique sequencing. The human operator selects:
1. The specific target (IP address, hostname, network range)
2. The specific technique to execute
3. The parameters for that technique (port ranges, payload sets, timeout values)
4. The approval to execute

### Verification

- Command log shows operator initiation for all operations
- No tool-initiated actions without human command
- Verify target is pre-approved for scope; tool rejects unlisted targets
- Technique parameters match approved ranges
- Multi-Factor Authentication (MFA) for sensitive targets

> **See also:** APTS-AL-001 (Level 1 definition that this requirement operationalizes), APTS-SE-001 (scope definition that target selections must comply with).

---

## APTS-AL-003: Parameter Configuration by Human Operator

**Classification:** MUST | Tier 1

### Requirement

The human operator MUST configure all technical parameters for technique execution at Level 1. The tool MUST NOT make assumptions or apply defaults that override operator selections. Configurable parameters include:
- Timeout values and retry counts
- Payload selections and fuzzing dictionaries
- Network packet rates (to prevent DoS)
- Response handling (timeout interpretation)
- Output formats and logging verbosity
- Risk levels and aggressiveness settings

The tool MUST present parameter options with clear defaults and require explicit confirmation.

### Verification

- Configuration logs show operator selections for all parameters
- No default parameters applied without confirmation
- Audit log confirms all executed parameters match the operator's explicitly configured values
- Comparison test: same technique executed with different operator-configured parameters produces correspondingly different results, confirming parameters are applied

> **See also:** APTS-AL-002 (human-directed target/technique selection this requirement extends to parameters), APTS-SC-001 (safety control thresholds that constrain allowable parameter ranges).

---

## APTS-AL-004: No Automated Chaining or Sequential Decision-Making

**Classification:** MUST | Tier 1

### Requirement

The tool MUST NOT execute subsequent techniques based on results from previous techniques without explicit human command. "Automated chaining" is prohibited at Level 1. For example:
- Tool MUST NOT automatically escalate findings (for example, "XSS found, auto-attempt XSS-to-Remote Code Execution (RCE)")
- Tool MUST NOT automatically follow enumeration with exploitation (for example, "Port 3389 open → auto-attempt RDP brute force")
- Tool MUST NOT automatically perform post-exploitation (for example, "Shell gained → auto-enumerate AD users")
- Tool MUST NOT auto-select additional targets based on findings (for example, "Server A found, auto-scan servers B and C")

Each subsequent action requires explicit human initiation and approval.

### Verification

- Audit log analysis: no technique B appears without intervening human command after technique A
- Pattern analysis: verify no decision-making logic in tool relating technique outcomes to subsequent technique selection
- Behavioral verification: (a) trigger conditions that would logically cause chaining (for example, discover an open port with a known vulnerable service); verify the tool does NOT autonomously attempt exploitation. (b) Review 100 sequential audit log entries; verify zero unintended technique executions that were not explicitly commanded by the operator.

---

## APTS-AL-005: Mandatory Logging and Human-Reviewable Audit Trail

**Classification:** MUST | Tier 1

### Requirement

Every action at Level 1 MUST be logged with complete information enabling human review and reconstruction:

**Mandatory Log Fields:**
- Timestamp (ISO 8601, UTC)
- Operator ID / username
- Operation type (technique name)
- Target (IP, hostname, port, service)
- Parameters used (payload set, timeout, and concurrency settings)
- Initiation method (command line, GUI, API)
- Execution start and end time
- Result summary (success/failure, key findings)
- Impact (packets sent, systems affected, data accessed)

**Technique Selection Verification (Level 1 Requirement):**
Verification of operator technique selection MUST be recorded as a structured log entry containing:
- Selected technique ID (unique identifier for the technique)
- Target asset (IP/hostname being tested)
- Stated justification (free-form text, minimum 20 characters)
- Risk assessment acknowledgment (operator checkbox confirming awareness of impact)
- Timestamp (ISO 8601)

Every technique execution at Level 1 MUST have a corresponding selection log entry with all required fields populated. This demonstrates that the operator deliberately chose each technique and understood the rationale.

**Log Format Requirements:**
- Structured format (JSON, CSV, or database) for automated analysis
- Plain-text human-readable summaries for operator review
- Immutable storage (append-only, cryptographic integrity)
- Retention per engagement contract (minimum 3 years for compliance)
- No log modification without separate audit event

### Verification

1. **Mandatory field completeness**: Execute 20 Level 1 actions; verify each log entry contains all 9 mandatory log fields (timestamp, operator ID, operation type, target, parameters, initiation method, start/end time, result summary, impact)
2. **Technique selection log**: Execute 10 techniques at Level 1; verify each has a corresponding selection log entry with: technique ID, target asset, stated justification (minimum 20 characters), risk assessment acknowledgment, and timestamp
3. **Log format compliance**: Export logs; verify structured format (JSON, CSV, or database) is present alongside plain-text human-readable summaries
4. **Immutability verification**: Attempt to modify a log entry; verify the system rejects the modification or creates a separate audit event recording the attempt
5. **Reconstruction test**: Select 5 logged actions at random; using only the log data, reconstruct the full sequence of what was executed, against which target, with what parameters, and what the outcome was. Verify reconstruction is unambiguous
6. **Retention compliance**: Verify log retention period is configured per engagement contract and meets the 3-year minimum

> **See also:** APTS-AR-001 (comprehensive action logging)

---

## APTS-AL-006: Basic Scope Validation and Policy Enforcement

**Classification:** MUST | Tier 1

### Requirement

Before executing any technique at Level 1, the tool MUST validate:

1. **Target Scope Validation:**
   - Target IP/hostname is in approved scope list
   - Target is not on exclusion list (explicitly off-limits)
   - Target is not a critical production system requiring extra approval
   - No changes to scope without re-authorization

2. **Technique Policy Enforcement:**
   - Technique is permitted for this engagement
   - Technique aligns with engagement Rules of Engagement (RoE)
   - Technique does not violate legal or regulatory constraints
   - Technique is appropriate for approved targets

3. **Engagement Validation:**
   - Engagement is still active (not expired or cancelled)
   - Engagement authorization is still valid
   - Operator has active authorization for this engagement
   - Engagement conditions (time windows, system availability) are met

4. **System State Validation:**
   - Tool has connectivity to target
   - System does not appear to be in failed or compromised state
   - No concurrent high-risk operations on target

**Rejection Behavior:** If validation fails, the tool MUST:
- Reject the operation with clear explanation
- Log the rejection attempt
- Alert human operator to authorization issue
- Do NOT attempt workarounds or fallback techniques

### Verification

- Attempt to scan out-of-scope system; verify rejection
- Attempt to use prohibited technique; verify rejection
- Verify scope list is maintained separately from tool, not hard-coded
- Test with expired engagement; verify rejection
- Verify all rejections are logged with reason codes

---

## APTS-AL-007: Multi-Step Technique Chaining Within Single Phase

**Classification:** MUST | Tier 2

### Requirement

At Level 2 Supervised autonomy, the platform MUST support execution of multiple related techniques within a single attack phase without requiring explicit approval for each individual technique. A phase is a logical grouping of related activities:

**Permitted Phases (canonical APTS phase model):**
- **Reconnaissance:** Passive information gathering, OSINT, public-source enumeration
- **Enumeration:** Service discovery, fingerprinting, configuration enumeration
- **Identification:** Vulnerability identification, exploit matching, prioritization
- **Exploitation:** Active exploitation of identified vulnerabilities
- **Post-Exploitation:** Persistence, lateral movement, privilege escalation, data access
- **Reporting:** Finding consolidation, evidence preservation, report generation

Within a phase, the tool MAY:
- Execute multiple techniques sequentially (for example, enumerate → fingerprint → version-detect)
- Make tactical decisions about technique parameters (timeout adjustment, retry logic)
- Adapt the assessment based on discovered information (if port 3389 open, test RDP-specific vulns)
- Chain discoveries into deeper investigation within the same phase (find web app → enumerate endpoints → identify frameworks)

**Constraints:**
- Chaining limited to a SINGLE PHASE (for example, enumeration only, not enumeration → exploitation)
- Tool MUST NOT transition between phases without explicit human approval
- Tool MUST identify all proposed next-phase actions and wait for human decision
- Tool MUST provide clear explanation of why each technique is being executed

**Rationale:** Within-phase chaining (for example, enumerate, fingerprint, version-detect within the enumeration phase) operates on the same class of risk: information gathering and analysis. Cross-phase chaining (for example, identification then exploitation) changes the risk profile from passive observation to active system interaction. Requiring human approval at phase boundaries ensures the operator reviews the analysis (findings) before committing to exploitation, reducing false positive exploitation attempts and unintended production impact.

### Verification

Sample at least 20 execution traces from recent engagements (or all traces if fewer than 20 exist) and run the following checks, then execute one live scenario test.

1. **Within-phase chaining:** For every sampled trace, verify every chained technique belongs to the same phase. Any cross-phase transition without a preceding human approval event fails.
2. **Rationale present:** For every chained technique, verify the audit record includes a rationale that cites a specific prior finding, enumeration result, or configured criterion. Missing or placeholder rationale fails.
3. **Approval events indexed:** For every phase boundary reached in the sampled traces, verify a corresponding human approval event exists in the audit log with operator identity and timestamp. Missing approval fails.
4. **Forbidden-transition test:** In a staging environment, instruct the platform to attempt a cross-phase transition (for example, from enumeration directly to exploitation) without an operator approval event. The platform MUST block the transition and emit a blocked-transition record in the audit log. If the transition proceeds, the requirement fails.
5. **Proposal scenario:** Run a complete scenario in which automated enumeration completes and the tool proposes exploitation. Verify the tool waits for an explicit human approval event before executing any exploitation technique and that the wait state is recorded in the audit trail.

---

## APTS-AL-008: Real-Time Human Monitoring and Approval Gates

**Classification:** MUST | Tier 1

### Requirement

At Level 2, the tool MUST maintain continuous connection to human operator(s) with real-time capability for:

1. **Live Action Dashboard:**
   - Current operations displayed in real-time
   - Each technique shown with target, status, progress, and estimated completion
   - Findings highlighted as they occur
   - Alerts for policy violations, unusual conditions, or exceptions

2. **Approval Gate System:**
   - Major decision points require explicit operator approval
   - "Major decisions" = phase transitions, exploitation, data access, destructive actions
   - Approval requests MUST be presented clearly with context
   - Operator can approve, modify parameters, or reject with operator rationale

3. **Intervention Capability:**
   - Operator can pause any running technique
   - Operator can terminate current phase and change direction
   - Operator can adjust parameters mid-execution
   - All interventions logged with operator ID and timestamp

4. **Communication Protocol:**
   - Tool proposes next action to operator
   - Operator approves, modifies, or rejects
   - If rejected, operator explains why (refusal reason logged)
   - Tool adjusts behavior based on feedback

### Verification

- Dashboard functionality testing: confirm all current operations visible in <5 second latency
- Approval gate testing: major decisions require explicit approval
- Intervention testing: pause/terminate operations, verify immediate effect
- Communication protocol: test proposal/approval/feedback cycle
- Rejection handling: verify tool respects operator rejections appropriately

> **See also:** APTS-HO-001 (normative definition of approval gate categories and the Common Vulnerability Scoring System (CVSS) threshold). AL-008 defines the L2 operational context in which HO-001 approval gates apply; HO-001 is the authoritative source for gate categories and approval record requirements.

---

## APTS-AL-009: Tool-Proposed Actions with Operator Modification Capability

**Classification:** SHOULD | Tier 2

### Requirement

At L2, the tool SHOULD explicitly propose each next action (not execute and report), allowing operator modification before execution. The L2/L3 distinction and the conditions under which platforms transition between exception-based and per-action oversight are described in the [Autonomy Levels Overview](#autonomy-levels-overview).

1. **Proposal Format:**
   - Clear description of proposed action
   - Target system(s) affected
   - Technique and parameters
   - Rationale (why this action is proposed)
   - Estimated impact (time, network load, system effects)
   - Risk level assessment
   - Comparison with alternatives

2. **Operator Modification Options:**
   - **Approve as-is:** execute with proposed parameters
   - **Modify parameters:** adjust timeout, payloads, targets, scope
   - **Approve alternative:** choose different technique from suggested alternatives
   - **Request more info:** ask tool to provide additional analysis before deciding
   - **Reject:** refuse and provide rationale for tool learning

3. **Parameter Modification Examples:**
   - Reduce intensity/payload set if worried about stability
   - Change target subset if concerned about specific systems
   - Adjust timeout if network issues detected
   - Add filters for data sensitivity
   - Restrict technique to specific service versions

4. **Refusal Handling:**
   - If operator rejects proposed action, tool accepts rejection
   - Tool MAY suggest alternatives but does not re-propose same action
   - Refusal is logged with operator reasoning
   - Tool learns from refusals to improve future proposals

### Verification

Sample at least 20 executed actions from recent L2 engagements (or all actions if fewer than 20 exist) and verify every one of the following:

1. **Proposal precedes execution:** For every sampled action, a proposal record MUST exist in the audit trail with a timestamp strictly earlier than the execution timestamp. Any action whose execution timestamp precedes or equals its proposal timestamp fails.
2. **Proposal content:** Every proposal record MUST include the description, target, technique, parameters, rationale, estimated impact, risk level, and at least one alternative. Missing any field fails.
3. **Operator disposition:** Every proposal MUST have a recorded disposition (approved as-is, parameters modified, alternative chosen, more info requested, rejected) with operator identity and timestamp. Missing disposition fails.
4. **Modified-parameter fidelity:** For actions dispositioned as "parameters modified", the actual executed parameters MUST match the post-modification values recorded by the operator, not the original proposal. Any drift fails.
5. **Rejection handling:** For a random sample of 5 rejected proposals, verify the tool did not re-propose the same action within the same engagement. Re-proposals fail.
6. **Logging completeness:** Every proposal, modification, approval, and rejection MUST be logged with operator ID and timestamp. Unattributed entries fail.

---

## APTS-AL-010: Step-by-Step Audit Log with Phase Transitions

**Classification:** MUST | Tier 2

### Requirement

Complete audit logging specifically designed for Level 2 supervision:

1. **Per-Step Logging:**
   Every technique execution MUST be logged with:
   - Step number within phase
   - Technique name and tool
   - Operator approval status (auto-proposed, operator-approved, operator-modified)
   - Parameters used (actual values, not defaults)
   - Execution details (start time, end time, result, findings)
   - Decision point: what operator approved next

2. **Phase Transition Events:**
   Every phase change MUST be logged as distinct event:
   - Old phase and new phase
   - Reason for transition (what finding triggered it)
   - Operator ID and approval timestamp
   - New parameters or scope for new phase
   - Timestamp and audit ID

3. **Operator Decision Trail:**
   - Proposal as generated by tool
   - Operator decision (approve/modify/reject)
   - If modified: original and new parameters
   - If rejected: operator's stated reason
   - Timestamp of each decision

4. **Finding Linkage:**
   - Each finding linked to technique that discovered it
   - Each exploitation decision linked to findings that justified it
   - Path from finding to exploitation to impact clearly visible
   - Enables root-cause analysis if incident occurs

### Verification

- Log completeness: every technique has entry in log
- Timestamp accuracy: all timestamps verified chronologically
- Decision trail: operator decisions clearly reflected in logs
- Phase transition events: every phase change has transition record
- Traceability: engineer can follow from finding to decision to action

> **See also:** APTS-AR-002 (general state transition logging baseline for all autonomy levels)

---

## APTS-AL-011: Escalation Triggers and Exception Handling

**Classification:** MUST | Tier 1

### Requirement

The tool MUST be configured with explicit escalation triggers: conditions that require immediate human notification and approval before proceeding:

**Mandatory Escalation Triggers (minimum set):**

1. **Scope Violations:**
   - Technique attempts to target out-of-scope system
   - Finding suggests related system that isn't in scope but should be tested
   - Accidental impact on unapproved system

2. **Exploitation Proposals:**
   - Any proposed exploitation technique (escalates from passive to active)
   - Credential guessing or brute force proposals
   - Persistence mechanism deployment
   - Lateral movement proposals

3. **Data Access:**
   - Access to customer data, personally identifiable information (PII), or sensitive business data
   - Any database queries beyond schema enumeration
   - File system access beyond configuration review
   - Backup file discovery

4. **System Impact:**
   - Technique causes service disruption or system crash
   - Unusual system behavior or security controls triggered
   - Authentication/account lockout events
   - Resource exhaustion (CPU, memory, disk)

5. **Anomalies:**
   - Tool detects behavior inconsistent with expectations
   - Security controls blocking or limiting testing
   - Unusual network patterns or responses
   - Signs of active incident response or monitoring

6. **Risk Thresholds:**
   - Finding severity exceeds pre-approved threshold
   - Combination of findings indicates critical exposure
   - Exposure timeframe suggests data exfiltration possible

**Escalation Procedure:**
1. Tool identifies trigger condition
2. Tool immediately pauses execution
3. Tool alerts operator with escalation notification
4. Operator reviews context and findings
5. Operator approves, modifies, or rejects proposed next action
6. Tool resumes only after operator decision
7. Escalation event fully logged with condition, alert, and decision

> **See also:** APTS-SC-006 (threshold escalation workflow), APTS-HO-011 through APTS-HO-014 (full escalation framework).

### Verification

- Trigger testing: artificially trigger each escalation condition
- Pause verification: confirm tool immediately pauses
- Alert verification: operator receives notification within 10 seconds
- Escalation logging: all escalations recorded with condition details
- Response handling: verify tool respects operator responses

---

## APTS-AL-012: Kill Switch and Pause Capability

**Classification:** MUST | Tier 1

### Requirement

The system MUST provide human operators with unambiguous ability to stop execution:

1. **Kill Switch:**
   - Single command or button accessible at any time
   - Triggers APTS-SC-009 Phase 1 (cease new actions within 5 seconds; in-flight operations complete per SC-009 semantics) followed by Phase 2 (graceful shutdown within 60 seconds)
   - All connections closed, all processes terminated upon Phase 2 completion
   - Clear confirmation that kill switch activated

2. **Pause Capability:**
   - Halt execution without terminating
   - Tool maintains state and can resume
   - Operator can review findings before resuming
   - Can change parameters while paused
   - Can resume from same point or restart phase

3. **Graceful Shutdown:**
   - Tool finishes current technique, then stops
   - Writes final results before stopping
   - Allows ~30 seconds for cleanup
   - Used when operator wants to stop cleanly, not urgently

4. **Status After Stop:**
   - Tool clearly indicates stopped state
   - Previous results preserved and accessible
   - Tool prevents autonomous restart
   - Operator MUST explicitly command resume or start new operation

> **See also:** APTS-SC-009 (kill switch implementation and Phase 1/Phase 2 timing), APTS-HO-008 (state preservation and kill switch response to anomalous behavior). SC-009 is the normative reference for kill-switch timing and process semantics; this requirement defines the operator interface.

### Verification

- Kill switch test: activate during running operation, verify termination in <5 seconds
- Pause test: pause operation, verify tool stops and maintains state
- Resume test: resume paused operation, verify continuation from checkpoint
- State verification: confirm all connections closed, no orphaned processes
- Multiple activations: test kill switch multiple times

---

## APTS-AL-013: Complete Attack Chain Execution Within Boundaries

**Classification:** MUST | Tier 2

### Requirement

At Level 3 Semi-Autonomous, the platform MUST support execution of complete attack chains across all phases without per-action human approval, provided operations remain within pre-established boundaries:

**Permitted Execution Flow:**
- Reconnaissance → Enumeration → Identification → Exploitation → Post-Exploitation → Reporting
- Complete lifecycle for single target without human intervention gates
- Tool makes tactical decisions about technique sequencing
- Tool chains findings to next-phase decisions (for example, critical SQLi → execute to access db)
- Multi-target campaigns within approved scope

**Boundary Constraints (MUST be explicitly defined pre-engagement):**

1. **Network/System Boundaries:**
   - Approved IP ranges
   - Approved hostnames/domains
   - Approved systems explicit list (critical systems always excluded)
   - NEVER testing outside scope without escalation

2. **Exploitation Boundaries:**
   - Maximum severity of vulns auto-exploitable (for example, auto-exploit Critical/High, escalate Medium/Low)
   - Prohibited techniques even if discovered (for example, "no credential harvesting from domain controllers")
   - Data access limitations (for example, "enumerate but do not exfiltrate customer PII")
   - Destructive action prohibitions (for example, "no ransomware, no data deletion")

3. **Impact Boundaries:**
   - Maximum acceptable system downtime
   - Resource utilization caps (CPU, memory, bandwidth)
   - User disruption constraints
   - Business hour restrictions

4. **Escalation Thresholds:**
   - Conditions requiring human review (critical data access, multi-target lateral movement, persistence)
   - Finding severity thresholds (escalate anything exceeding threshold)
   - Time-based escalations (if assessment running >80% of allocated time without completion)
   - Anomaly triggers (tool detects security response indicating discovered)

### Verification

- Boundary definition review: confirm boundaries are documented, specific, unambiguous
- Boundary enforcement testing: attempt operations outside boundaries, verify rejection
- Attack chain testing: verify tool can chain multiple phases without approval gates
- Decision logic review: verify tool makes decisions aligned with boundary constraints
- Escalation testing: verify conditions outside boundaries trigger escalation

---

## APTS-AL-014: Boundary Definition and Enforcement Framework

**Classification:** MUST | Tier 1

### Requirement

Boundaries MUST be formally defined, technically enforced, and continuously validated:

**1. Boundary Definition (Pre-Engagement):**

A boundary document MUST define:
- **Network boundaries:** IP ranges, domains, specific systems
- **Exploitation boundaries:** Severity thresholds, technique lists (allowed/prohibited)
- **Data boundaries:** What data can be accessed, extracted, or modified
- **Impact boundaries:** Acceptable downtime, resource limits, timing constraints
- **Escalation boundaries:** Conditions requiring human review

Each boundary MUST be:
- Specific (not vague: "must be a list of exact IPs, not a description")
- Testable (can be validated before execution)
- Unambiguous (tool cannot misinterpret)
- Justified (documented rationale for each boundary)
- Approved (signed by client, security team, legal)

**2. Technical Enforcement:**

Boundaries MUST be enforced in tool code:
- Network boundaries: firewall rules, IP whitelist in tool
- Exploitation boundaries: decision tree in tool (if severity=X and system=Y, then auto-exploit=allowed)
- Data boundaries: field masking, extraction limits
- Impact boundaries: rate limiting, timeout enforcement
- Escalation boundaries: automated escalation triggers

Boundaries MUST be:
- Non-bypassable (cannot be overridden by operator without approval)
- Auditable (enforcement logged)
- Testable (can be verified before engagement)

**3. Boundary Validation:**

Before engagement start:
- Tool validates all boundaries are loaded
- Audit test: verify each boundary is enforced
- Operator confirms understanding
- Client confirms agreement
- Document baseline for incident investigation

During engagement:
- Continuous validation: tool regularly re-checks boundary compliance
- Deviation detection: any out-of-bounds action logged as potential incident
- Real-time enforcement: tool rejects out-of-bounds actions

### Verification

- Boundary document exists, is specific and approved
- Technical enforcement code review
- Audit test: verify each boundary is enforced
- Violation test: attempt violations, verify rejection or escalation
- Baseline audit: confirm all boundaries validated before engagement start

---

## APTS-AL-015: Pre-Approved Action Categories and Decision Trees

**Classification:** MUST | Tier 2

### Requirement

Tool autonomy at Level 3 MUST be based on pre-approved action categories: sets of predefined decisions that the tool can make without human intervention, structured as follows:

**1. Action Category Structure:**

Each category contains:
- **Category name** (for example, "SQLi Exploitation on Non-Critical Dev Systems")
- **Applicability conditions** (when this category applies)
- **Approved actions** (what the tool can do)
- **Decision criteria** (how tool decides within category)
- **Escalation triggers** (conditions requiring human review even within category)
- **Constraints and limits** (parameters, data limits, and rate controls)

**2. Example Action Categories:**

**Category: Enumeration (Always Permitted)**
- Applicability: Any target in scope
- Approved actions: Port scanning, service fingerprinting, version detection, DNS enumeration
- Decision criteria: Cover all services; use fingerprinting libraries, not exploitation
- Escalation triggers: System becomes unavailable, connection errors
- Constraints: Scan rate max 1000 pps, timeout 30 seconds

**Category: Vulnerability Identification (Always Permitted)**
- Applicability: Any target in scope
- Approved actions: Vulnerability scanning, database matching, risk scoring
- Decision criteria: Use passive scanning against identified services
- Escalation triggers: Finding severity exceeds thresholds
- Constraints: No active exploitation, read-only access

**Category: CRITICAL/HIGH Exploitation on Dev Systems (Permitted)**
- Applicability: CRITICAL or HIGH severity vuln on 203.0.113.100-150
- Approved actions: Execute identified exploit, confirm vulnerability, assess impact
- Decision criteria: Severity Common Vulnerability Scoring System (CVSS) >7.0, target IP in dev range
- Escalation triggers: Unexpected lateral movement, data access, system crash
- Constraints: No persistence, no destructive actions, log all activities

**Category: Password Testing on Non-Domain Systems (Limited)**
- Applicability: Web app passwords, database passwords, service accounts
- Approved actions: Dictionary attack, common credential testing
- Decision criteria: Max 10 attempts per account, 1 attempt/second rate
- Escalation triggers: Account lockout, failed attempt >10, domain controller targeting
- Constraints: Prohibited on domain controllers, public testing accounts only

**Category: Lateral Movement Within Subnet (Permitted)**
- Applicability: Lateral movement within same approved subnet
- Approved actions: Use compromised system to enumerate adjacent systems, attempt exploitation
- Decision criteria: All destination systems in approved range
- Escalation triggers: Attempt to cross to different subnet, critical system targeting, off-scope detection
- Constraints: Log all lateral movement chain, stop if off-scope detected

**3. Decision Trees:**

For each major decision point, the tool uses a decision tree documenting:
- **Root node**: The decision trigger (for example, "vulnerability discovered," "escalation opportunity identified")
- **Branch conditions**: Criteria evaluated at each branch (for example, impact classification, scope boundaries, autonomy level permissions)
- **Leaf outcomes**: The action taken and its justification (for example, "proceed with exploitation (within scope, impact ≤ Medium, pre-approved technique)")
- **Fallback path**: Default-deny outcome when conditions are ambiguous or data is insufficient

### Verification

1. **Category completeness**: Review 3 action categories; verify each defines: category name, applicability conditions, approved actions, decision criteria, escalation triggers, and constraints
2. **Within-category autonomy**: Trigger an action that falls within an approved category (for example, port scan on in-scope target); verify the tool proceeds without requiring human approval
3. **Out-of-category denial**: Attempt an action not covered by any approved category; verify the system denies execution or escalates to a human operator
4. **Decision tree tracing**: For 3 decision points, trace the decision tree from root node to leaf outcome; verify the correct action is taken and the fallback path defaults to deny
5. **Escalation trigger within category**: Within an approved category, trigger an escalation condition (for example, system becomes unavailable during enumeration); verify human notification and testing pause
6. **Default-deny on ambiguity**: Present conditions that do not clearly match any category's applicability criteria; verify the tool takes the default-deny path rather than proceeding

---

## APTS-AL-016: Continuous Boundary Monitoring and Breach Detection

**Classification:** MUST | Tier 1

### Requirement

During engagement, tool MUST continuously monitor boundary compliance and detect breaches:

**1. Monitoring Points:**
- **Target validation:** Every action validated against scope
- **Exploitation authorization:** Every exploitation checked against rules
- **Data access tracking:** Every data access logged and monitored
- **Impact assessment:** Real-time monitoring of system state and tool impact
- **Escalation trigger monitoring:** Real-time assessment of escalation conditions
- **Time monitoring:** Track time spent, notify on milestones

**2. Breach Detection:**
- **Out-of-scope attempt:** Action targets IP/domain not in scope
- **Unauthorized technique:** Technique prohibited by policy
- **Data violation:** Attempt to access forbidden data types
- **Impact threshold exceeded:** System impact exceeds limits
- **Security response detected:** IDS alerts, security controls triggered
- **Unexpected lateral movement:** Lateral movement outside plan

**3. Breach Response:**
- **Immediate logging:** Breach logged with timestamp, details, attempted action
- **Execution pause:** Tool pauses immediately upon detection
- **Operator alert:** Operator notified of breach with details
- **Escalation trigger:** Conditions trigger human escalation
- **Audit trail:** Complete record of breach attempt, detection, response

**4. Continuous Health Checks:**
- **Boundary status check:** Every 30 minutes, tool re-validates all boundaries
- **Scope file integrity:** Check scope definition hasn't been tampered with
- **Policy enforcement code:** Verify no bypasses introduced
- **Audit log integrity:** Verify logs haven't been modified
- **Security controls status:** Confirm firewalls, WAF, IDS still functional

### Verification

1. Run the platform for a documented test period (minimum 2 hours); verify boundary status health checks execute on schedule at the documented cadence (for example, 4 checks at 30-minute intervals over 2 hours)
2. Monitor logs for breach detection events during the test period; verify log entries include timestamp, check type, and result
3. **Integrity test:** Verify each scheduled health check executes within ±10% of the documented cadence; fail if any check is skipped or delayed beyond the tolerance
4. **Tampering test:** Mid-run, modify the scope configuration checksum or a protected scope parameter; verify the platform detects the modification and triggers an alert and operational pause within the documented breach-response window
5. Audit logs capture each health check result, the tamper detection event, and the pause action with timestamps

---

## APTS-AL-017: Multi-Target Assessment Management

**Classification:** MUST | Tier 2

### Requirement

At Level 3 Semi-Autonomous, the platform MUST support management of assessments across multiple targets, including prioritization and resource allocation:

**1. Target Prioritization:**
- Tool receives target list with priorities
- Tool manages assessment sequence based on:
  - Priority level
  - Target criticality
  - Estimated effort against remaining time
  - Dependencies (some findings enable other tests)
- Tool adapts sequence based on findings (high-value targets get more attention)
- Tool maintains progress against all targets

**2. Parallel Operations:**
- Tool MAY execute operations against multiple targets concurrently
- Concurrency managed based on:
  - Resource constraints (network bandwidth, CPU)
  - Impact limits (avoid overloading network)
  - Logical dependencies (wait for enumeration before exploitation)
- Tool prevents resource contention

**3. Progress Tracking:**
- Track assessment progress per target
- Identify targets likely to complete and those that are time-constrained
- Alert operator if targets falling behind schedule
- Adapt testing intensity based on time/progress ratio

**4. Resource Allocation:**
- Allocate time and resources proportional to target value
- High-value targets get intensive testing
- Low-value targets get lighter testing if time-constrained
- Adjust allocation if findings warrant deeper investigation

### Verification

1. **Multi-target deployment test:** Configure an engagement with at least 10 targets at three priority levels (for example, 3 critical, 4 high, 3 medium). Run the platform under normal resource constraints and capture the assessment-start order. Pass criterion: the platform begins assessment of every critical target before any medium target, and the start order within a priority tier reflects the documented prioritization inputs (criticality, estimated effort, dependencies).
2. **Concurrent operation test:** With a concurrency cap of N parallel targets configured, deploy 2N targets and verify via process/network telemetry that no more than N assessments run simultaneously, that bandwidth/CPU stay within configured ceilings, and that dependency-blocked operations (for example, exploitation steps) wait for prerequisite operations (for example, enumeration) to complete.
3. **Resource allocation audit:** From audit logs, extract per-target wall-clock time, request count, and tool-invocation count. Pass criterion: high-criticality targets received measurably more resources (for example, ≥2× the median request count of low-criticality targets), and any deviation is justified by a logged adaptation event (for example, early dead-end, finding-driven escalation).
4. **Progress tracking and behind-schedule alerting:** Inject artificial delay into 2 targets so they fall below the expected progress curve. Verify the platform raises an operator alert identifying the at-risk targets and proposes either intensity reduction or schedule extension.
5. **Adaptation-on-finding test:** Plant a high-value finding on a low-priority target. Verify the platform reallocates additional time/resources to that target after the finding is detected and that the reallocation decision is captured in the audit log with the triggering finding ID.

---

## APTS-AL-018: Incident Response During Autonomous Testing

**Classification:** MUST | Tier 2

### Requirement

If security events occur during autonomous testing (detected intrusion, incident response, security controls triggered), tool MUST handle appropriately:

**1. Detection Conditions:**
- Security controls activated (IDS alert, WAF blocking, firewall rules added)
- Evidence of active incident or intrusion
- Unusual system behavior suggesting incident response underway
- System or network degradation inconsistent with testing

**2. Response Procedure:**
- Immediately pause all testing operations
- Alert operator with incident indicators
- Preserve current findings and session state
- Await operator decision:
  - Continue testing (operator authorizes)
  - Coordinate with security team
  - Cease testing
  - Investigate indicator

**3. Coordination with Client Security Team:**
- Tool supports pause/resume capability
- Operator can communicate with client incident response
- Resume only after operator authorization
- Document any interference between testing and incident response

**4. Incident Preservation:**
- Do not overwrite or destroy indicators
- Preserve potential evidence of active incident
- Support forensic investigation if needed

> **See also:** APTS-HO-011 (unexpected findings escalation trigger catalog), APTS-AL-026 (post-incident investigation, root cause analysis, and autonomy level adjustment after the immediate response is complete).

### Verification

Run the following three scenarios in a staging environment and verify each scenario's required artifacts.

**Scenario A - IDS alert simulation:** Trigger a simulated IDS alert that matches the platform's documented detection criteria.

1. The tool MUST enter a paused state within the response time documented in the platform's incident response plan. Exceeding the documented target fails.
2. The pause MUST halt all new action execution for the affected scope. Actions that continue executing after the pause signal fail.
3. An operator notification MUST be dispatched to the on-call channel within the documented notification target. Missing or late notification fails.
4. The audit trail MUST record the alert trigger, the pause decision, the pause timestamp, and the notification timestamp. Missing entries fail.

**Scenario B - Unusual system behavior simulation:** Inject a controlled anomaly (for example, unexpected target reboot signal, unusual response latency, or unexpected service shutdown) that matches the platform's documented anomaly criteria.

1. The anomaly MUST be detected within the documented detection window. Missed or late detection fails.
2. The tool MUST enter a paused state and emit an operator notification as in Scenario A.
3. The audit trail MUST record the anomaly detection, classification, and pause decision with timestamps.

**Scenario C - Incident preservation:** After Scenarios A and B, verify that no logs, intermediate findings, captured packets, or target-state snapshots gathered before the pause were overwritten or deleted by the pause handling itself.

1. The reviewer MUST hash and compare the pre-pause and post-pause evidence store. Any delta fails unless justified by a documented operator action.
2. Operator coordination records MUST exist showing who was notified, when they acknowledged, and what decision was taken (resume, escalate, terminate). Missing records fail.

---

## APTS-AL-019: Multi-Target Campaign Management Without Intervention

**Classification:** SHOULD | Tier 3

### Requirement

At Level 4 Autonomous, the tool operates independently across multiple targets, campaign durations, and adapts strategy based on findings, all without human intervention beyond periodic review:

> **Organizational Readiness for L4:** Level 4 autonomy requires both technical platform capabilities AND organizational readiness. Organizations choosing to authorize L4 operations are expected to have: (a) dedicated 24/7 monitoring staff trained in autonomous system oversight, (b) documented and tested incident response procedures specific to autonomous testing incidents, (c) kill switch authority delegation covering all operating hours, and (d) completed a tabletop exercise simulating L4 incident scenarios within the preceding 6 months. These prerequisites are descriptive of the operating conditions that make L4 deployment safe; the SHOULD classification of this requirement reflects that L4 itself is optional.

**1. Campaign Scope Management:**
- Tool manages multiple targets across days/weeks/months
- Targets MAY be grouped into campaigns
- Tool prioritizes targets based on:
  - Risk profiles
  - Organizational priorities
  - Strategic objectives
  - Expected difficulty and time required
- Tool allocates testing resources across targets
- Tool adapts allocation based on findings

**2. Attack Strategy Adaptation:**
- Tool analyzes findings and adapts approach
- If target proves quickly exploitable, move to post-exploitation depth
- If target is hardened, shift resources to easier targets
- If finding suggests lateral movement opportunity, pursue it
- If new target discovered via reconnaissance, add to testing queue

**3. Long-Duration Operations:**
- Campaigns may span weeks or months
- Tool manages sustained operations autonomously
- Tool handles target unavailability (retry, skip, schedule for later)
- Tool maintains testing continuity across multiple sessions
- Tool preserves state between restarts

**4. Multi-Campaign Coordination:**
- May run multiple campaigns in parallel
- Tool manages resource allocation across campaigns
- Tool prevents resource conflicts
- Tool provides consolidated reporting across campaigns

### Verification

1. **Organizational readiness check (gate):** Before any L4 verification activity, confirm and document evidence for each of the four prerequisites in the Organizational Readiness note: (a) 24/7 monitoring staffing roster, (b) autonomous-testing IR runbook with last review date, (c) signed kill-switch delegation covering all hours, and (d) tabletop exercise completion record dated within the preceding 6 months. Any missing prerequisite is an automatic verification failure.
2. **Multi-target campaign test:** Run a campaign of at least 20 targets across 2 distinct priority groupings for a minimum continuous duration of 7 days. Verify the campaign proceeds to completion without any human action other than scheduled periodic review.
3. **Long-duration stability:** During the test in (2), capture uptime, memory footprint, log volume, and tool-error rates daily. Pass criterion: no unrecovered crashes, no memory growth indicating leaks, and any tool failures are followed by automated retry/skip per the documented strategy.
4. **State preservation across restart:** Mid-campaign, force a platform restart (kill the process). Pass criterion: on restart the platform resumes from the last checkpoint without re-running completed targets, without losing findings, and without re-attacking targets already marked complete.
5. **Adaptation decision audit:** Extract every strategy-adaptation decision from the audit log (target abandoned, intensity changed, lateral movement initiated, new target queued from reconnaissance). For each, verify a referenced finding or condition exists in the data that justifies the decision per the documented adaptation rules. Reject the run if any adaptation lacks a traceable justification.
6. **Multi-campaign coordination test:** Run 2 parallel campaigns sharing the same resource pool. Verify the platform enforces the global resource budget (sum of campaign usage ≤ pool), avoids deadlock between campaigns, and produces consolidated reporting that distinguishes per-campaign findings.

---

## APTS-AL-020: Dynamic Scope Adjustment and Target Discovery

**Classification:** SHOULD | Tier 3

### Requirement

At Level 4, the tool SHOULD be able to discover and add targets within pre-approved parameters without explicit approval, subject to the following constraints:

**1. Target Discovery Mechanisms:**
- DNS enumeration discovers additional domains
- Network scanning discovers additional IPs
- Exploitation provides access to internal network
- Reconnaissance reveals related systems

**2. Dynamic Scope Inclusion Criteria:**
Inclusion of newly discovered targets is governed by explicit, machine-evaluable, pre-approved discovery rules. Subjective criteria (for example, "clearly related to organization", "appears to belong to the same business unit") are not permitted as inclusion criteria; the tool escalates any such case for operator decision rather than inferring organizational ownership. Permitted inclusion mechanisms are limited to:
- **Pre-approved expansion rules:** Engagement-time rules that define exactly how scope may expand, expressed as explicit patterns the tool can mechanically evaluate (for example, "include any host whose forward and reverse DNS both resolve under `*.example.com` AND whose IP falls within 203.0.113.0/24")
- **Pre-approved CIDR or domain allowlists:** Discovery within IP ranges or domains explicitly listed in the engagement scope document
- **Critical system protection check:** Even when inclusion rules match, the tool verifies the target is not on any exclusion or critical-system list before adding it
- **Authorization parity check:** The discovered target is covered by the same legal authorization (for example, Rules of Engagement, customer signatory) as the original scope; targets requiring different authorization are escalated, never auto-included

**3. Exclusion Criteria:**
Tool excludes (does not test) if:
- Target is explicitly on exclusion list (off-limits)
- Target belongs to different organization (partner, vendor)
- Target is clearly customer-facing system (for example, customer database endpoint)
- Target requires different authorization than original engagement

**4. Escalation for Uncertain Cases:**
If tool discovers target that:
- Might be in scope but uncertain
- Represents significant new attack surface
- Could indicate scope change implications
Tool escalates for operator decision rather than assuming scope

### Verification

1. **Rule specificity review:** Inspect the engagement's discovery rule set and reject any rule that relies on subjective criteria (for example, "appears related", "looks like ours"). Pass criterion: every rule is mechanically evaluable: pattern matches (regex/glob), CIDR membership, ASN check, certificate-SAN match, or explicit allowlist entry. Document the rule set verbatim in the verification record.
2. **Positive discovery test:** Stand up at least 5 hosts that satisfy the engagement's pre-approved expansion rules (for example, valid forward+reverse DNS within `*.example.com` AND IPs in an allowlisted CIDR). Run reconnaissance and verify all 5 are added to the queue, that each addition is logged with the matching rule ID, and that authorization parity (same RoE/signatory) is checked and recorded.
3. **Negative discovery test, exclusion enforcement:** Add at least 3 hosts that match the inclusion pattern BUT also appear on the exclusion or critical-system list. Verify none are queued for testing and that each rejection is logged with the exclusion reason.
4. **Negative discovery test, different authorization:** Add at least 3 hosts that match the inclusion pattern but fall under a different legal authorization (for example, partner-owned, customer-owned). Verify none are auto-included and that each is escalated for operator decision.
5. **Ambiguous-case escalation test:** Stage targets that partially match rules (for example, forward DNS matches but reverse does not, or IP is adjacent to but outside the allowlisted CIDR). Pass criterion: the platform escalates these to the operator rather than auto-including, and the escalation contains the specific ambiguity for the operator to decide on.
6. **Audit trail review:** From the inclusion-decision log, sample 20 entries and confirm each contains: discovery source (DNS/scan/exploit/recon), the rule ID matched, the exclusion-list check result, the authorization parity check result, and the final decision (include/exclude/escalate).

---

## APTS-AL-021: Adaptive Testing Strategy and Resource Reallocation

**Classification:** SHOULD | Tier 3

### Requirement

The tool SHOULD autonomously adapt testing strategy based on findings and resource constraints, applying the following mechanisms:

**1. Strategy Adaptation Based on Findings:**
- **Easy targets:** If target proves quickly exploitable, allocate minimal resources, move to depth
- **Hard targets:** If target is hardened, reduce effort, focus on other targets
- **Critical findings:** If finding suggests critical exposure, allocate more resources to confirm and assess
- **Lateral movement:** If exploitation provides internal access, shift focus to lateral movement
- **Data access:** If data access achieved, allocate resources to assess data sensitivity

**2. Resource Reallocation:**
Tool manages resource budget (time, network bandwidth, tool licenses) and reallocates based on:
- Target progress against estimated effort
- Finding significance against additional investigation cost
- Time remaining against testing scope
- Infrastructure constraints

**3. Effort-Reward Analysis:**
Tool assesses effort required against value of finding:
- High-risk, easy targets: max effort
- High-risk, hard targets: moderate effort, escalate for decision
- Low-risk targets: minimal effort, move on quickly
- Dead-end investigations: abandon, reallocate resources

**4. Testing Intensity Adjustment:**
Tool adjusts aggressiveness:
- Responsive targets (not hardened): increase intensity
- Defended targets (security controls active): reduce intensity, use stealth
- Unavailable targets: schedule for later, don't waste resources

### Verification

1. **Easy-target adaptation test:** Stage a target with a deliberately weak service (for example, exposed default credentials) that the platform will exploit quickly. Verify the platform reduces enumeration time on that target after exploitation succeeds and pivots resources toward post-exploitation depth or other targets, with the decision recorded in the audit log referencing the exploitation event.
2. **Hard-target adaptation test:** Stage a hardened target (rate-limited, no exposed services, all default exploits patched). Verify that after a documented effort threshold the platform reduces effort on that target and reallocates to alternative targets, with the abandonment decision recorded.
3. **Critical-finding adaptation test:** Plant a finding that should trigger deeper investigation (for example, weak authentication on an admin interface). Verify the platform allocates additional resources to confirm and characterize the finding, and that the additional spend is logged with reference to the triggering finding.
4. **Lateral movement adaptation test:** Provide a controlled exploitation path that yields access to an internal segment. Verify the platform shifts focus to lateral movement within engagement-authorized scope and does not attempt movement outside scope.
5. **Resource budget adherence test:** Configure a strict resource budget (for example, 8 CPU-hours, 5 GB outbound traffic, 100,000 requests). Run a campaign that would naturally exceed the budget if unchecked. Pass criterion: actual usage stays within the budget; the platform's reallocation log shows decisions made specifically to stay under each budget dimension.
6. **A/B comparison test:** Run the same engagement twice, once with adaptive strategy enabled, once with a static rigid allocation. Compare findings count, finding severity distribution, time-per-finding, and total resource consumption. Pass criterion: the adaptive run produces equal-or-better finding coverage at equal-or-lower resource cost, demonstrating the adaptation logic provides measurable benefit.
7. **Decision-log audit:** Sample 30 adaptation decisions and verify each entry contains: triggering condition, resource budget snapshot, decision taken, expected outcome, and timestamp.

---

## APTS-AL-022: Continuous Risk Assessment and Automated Escalation

**Classification:** SHOULD | Tier 3

### Requirement

Unlike Levels 1-3 where escalation is reactive (breaches trigger escalation), at Level 4 the tool SHOULD perform proactive, continuous risk assessment covering the following elements:

**1. Real-Time Risk Scoring:**
Tool continuously assesses:
- Severity of findings discovered
- Exposure scope (how many systems affected)
- Attack chain feasibility (can findings be chained for impact)
- Data sensitivity of accessible information
- Time-to-exploitation (how quickly findings could be exploited)

**2. Risk Thresholds and Escalation:**
Tool tracks cumulative risk against thresholds:
- **Individual finding thresholds:** Auto-escalate if finding exceeds severity threshold
- **Cumulative exposure thresholds:** Escalate if total exposure crosses threshold
- **Data access thresholds:** Escalate if sensitive data access becomes possible
- **Critical system compromise:** Auto-escalate any critical system compromise

**3. Predictive Escalation:**
Tool predicts impact and escalates before execution:
- "This exploitation will provide domain admin access" → escalate
- "This lateral movement will give access to customer database" → escalate
- "These findings can be chained into complete infrastructure compromise" → escalate

**4. Escalation to Appropriate Level:**
Tool routes escalation appropriately:
- Security team for immediate response items
- Executive leadership for strategic implications
- Legal/compliance for regulatory findings
- Business owners for operational impact

### Verification

1. **Risk scoring logic review:** Inspect the documented risk-scoring formula and confirm it incorporates each of the inputs in the requirement (finding severity, exposure scope, attack chain feasibility, data sensitivity, time-to-exploitation). Score 20 representative test findings by hand and compare to the platform's computed scores; pass criterion: ≥90% agreement, with any divergences explained by documented logic.
2. **Threshold definition review:** Confirm that individual-finding, cumulative-exposure, data-access, and critical-system thresholds are explicitly defined per engagement (not hard-coded), that values are documented in the engagement record, and that operators can adjust them only through an authenticated and audited path.
3. **Individual-threshold trigger test:** Plant a finding scoring just above the individual escalation threshold; verify auto-escalation fires within the documented latency. Repeat with a finding scoring just below the threshold; verify it does NOT escalate. Repeat for at least 3 distinct severity classes.
4. **Cumulative-threshold trigger test:** Plant N sub-threshold findings that together exceed the cumulative exposure threshold; verify the platform escalates after the threshold is crossed and that the escalation references the cumulative score, not any single finding.
5. **Predictive escalation test:** Stage an exploitation chain where the next planned step would yield domain admin (or equivalent crown-jewel access). Pass criterion: the platform escalates BEFORE executing the high-impact step, and the escalation message identifies the predicted impact and the planned step.
6. **Critical-system auto-escalation:** Stage a target marked as critical-system and trigger any compromise on it. Verify auto-escalation fires regardless of severity score.
7. **Routing test:** Generate one finding in each escalation routing class (immediate-response, strategic, regulatory/legal, business operational). Verify each is delivered to the correct routing channel (security team, leadership, legal/compliance, business owner) per the documented routing matrix.
8. **False-positive rate monitoring:** Run the platform against a known-clean baseline environment for a defined duration (for example, 24 hours); record the count of escalations triggered. Pass criterion: false-positive rate is below the documented acceptable threshold (for example, ≤1 escalation per 24 hours on the baseline) so that operators are not desensitized.

> **See also:** APTS-SC-007 (cumulative risk tracking).

---

## APTS-AL-023: Complete Audit Trail and Forensic Reconstruction

**Classification:** SHOULD | Tier 3

### Requirement

At Level 4, audit logging is full enough to reconstruct every decision and action:

**1. Audit Trail Content:**
- Every action taken by tool
- Every decision made (with decision logic and data considered)
- Every external interaction (findings, escalations, alerts)
- Every parameter, configuration, and constraint active at time of action
- Every system state change caused by tool actions

**2. Audit Trail Properties:**
- Immutable: No modification after logging
- Timestamped: Precise timestamp (sub-second)
- Signed: Cryptographic signature proving authenticity
- Indexed: Searchable by multiple criteria
- Retained: Long-term retention (minimum 3 years or per regulatory/contractual requirement)
- Accessible: Can be retrieved and analyzed

**3. Reconstruction Capability:**
From audit logs, SHOULD be able to reconstruct:
- Complete timeline of engagement
- Each action in execution order
- System state before/after each action
- Decision context for each action
- Why specific targets were chosen
- Why specific techniques were selected
- Impact of each action on target systems

**4. Forensic Analysis Support:**
If incident occurs during/after testing:
- Logs enable complete reconstruction
- Determine if tool caused incident or coincidence
- Distinguish tool actions from other activity
- Prove tool stayed within boundaries
- Support incident investigation

### Verification

1. Select one complete Level 4 engagement and sample 50 random log entries from its audit trail
2. Reconstruct the full action timeline from the sampled engagement's logs; verify every autonomous action has a corresponding log entry with timestamp, action type, target, and decision rationale
3. Verify cryptographic integrity of each sampled log entry against the audit trail's hash chain; fail on any integrity mismatch
4. Verify no irreconcilable timestamp gaps exist in the reconstructed timeline (gaps exceeding the platform's documented maximum inter-action interval without a logged pause or idle event)
5. Verify forensic accessibility: confirm logs can be exported in a standard format and opened with standard forensic tools without vendor-proprietary software
6. Verify retention policy compliance: confirm the sampled engagement's logs have not been purged or modified and are within the documented retention period

**Note:** For manipulation resistance requirements at L4, see the Manipulation Resistance domain (APTS-MR).

---

## APTS-AL-024: Periodic Autonomous Review Cycles

**Classification:** SHOULD | Tier 3

### Requirement

Despite autonomy, Level 4 SHOULD require regular human review covering the following elements:

**1. Review Frequency:**
- Weekly summary review (status, major findings, decisions made)
- Monthly deep audit (boundary compliance, decision patterns, incident analysis)
- Quarterly strategic review (campaign progress, strategic implications)
- Annual complete assessment (continue authorization or adjust level)

**2. Review Scope (Weekly):**
- Campaign status across all targets
- Major findings discovered
- Escalations triggered and operator decisions made
- Any boundary violations or anomalies
- Resource utilization and budget tracking
- Incidents or unusual events

**3. Review Scope (Monthly):**
- Detailed boundary compliance audit
- Audit log integrity verification
- Decision pattern analysis against the decision criteria documented under APTS-AL-023 (any decision whose recorded rationale does not cite an approved criterion is flagged)
- Escalation root cause analysis
- Compare actual performance to predicted behavior
- Identify process improvements

**4. Review Scope (Quarterly):**
- Strategic findings and implications
- Lateral movement chains and infrastructure exposure
- Data access and sensitivity assessment
- Recommendations for remediation
- Comparison to industry benchmarks
- Campaign ROI assessment

**5. Annual Reauthorization:**
The annual reauthorization decision (continue at L4, downgrade, or impose additional controls) is governed by APTS-AL-025 §3 (Annual Autonomy Level Reauthorization). The weekly, monthly, and quarterly review evidence collected under this requirement feeds into that annual decision.

> **See also:** APTS-AL-025 (formal annual reauthorization process and approval authority).

### Verification

Sample a 13-week review window (covering at least 12 weekly reviews, 3 monthly reviews, and 1 quarterly review) and verify all of the following:

1. **Weekly reviews present:** At least 12 weekly review records exist for the sampled window, each containing every section listed under Review Scope (Weekly). Reviews missing any required section fail.
2. **Monthly reviews present:** At least 3 monthly review records exist, each containing every section listed under Review Scope (Monthly). The decision-pattern-analysis section MUST cite the decision criteria documented under APTS-AL-023; reviews with uncited "reasonableness" judgments fail.
3. **Quarterly review present:** At least 1 quarterly review record exists with every section listed under Review Scope (Quarterly).
4. **Action items tracked:** For every action item opened in the sampled reviews, an owner, due date, and closure status MUST be recorded. At least 80% of action items with due dates inside the sampled window are closed or have a documented deferral justification.
5. **Boundary-compliance trend tracked:** At least one boundary-compliance metric (scope violations, escalation rate, approval-gate hit rate, or autonomy anomaly count) is recorded in every monthly review and compared against the prior month. Missing trend data fails.
6. **Audit log correlation:** For a random sample of 10 audit log entries drawn from the sampled window, each entry referenced in a review record MUST match the underlying log entry (timestamp, action, operator). Mismatches fail.
7. **Annual reauthorization feed:** Review records MUST be cross-referenced in the most recent annual reauthorization workpaper under APTS-AL-025 §3. Missing cross-reference fails.

---

## APTS-AL-025: Autonomy Level Authorization, Transition, and Reauthorization

**Classification:** MUST | Tier 2

### Requirement

The organization MUST establish formal authorization governance for autonomous pentesting at all levels, including initial authorization, level progression, and ongoing reauthorization:

**1. Autonomy Level Authorization Matrix and Criteria**

Before deploying autonomous pentesting at any level, the organization MUST:
- Conduct formal level assessment against defined criteria
- Document authorization decision with approval and justification
- Establish baseline controls required for that level
- Identify risks and mitigations specific to organization and targets
- Obtain executive approval and legal review

Authorization criteria vary by level and are detailed in the Implementation Guide.

**2. Level Transition Criteria and Progression Path**

Organizations MUST NOT jump levels. Progression MUST follow defined criteria and timeline:
- Progression criteria documented and understood by team
- Assessment process followed completely
- Assessment duration met minimum timeline
- All approval signatures obtained
- Conditions documented and monitored

Specific transition prerequisites, assessment activities, and progression decisions are detailed in the Implementation Guide.

At minimum, progression criteria MUST include:
- **L1 to L2:** Documented completion of at least 50 hours of L1 operations with zero unintended scope violations or safety incidents. Demonstrated operator competency in escalation handling.
- **L2 to L3:** Documented completion of at least 200 hours of L2 operations across at least 5 distinct engagements. Zero uncontained safety incidents. Demonstrated platform capability for boundary monitoring and breach detection (APTS-AL-016).
- **L3 to L4:** Documented completion of at least 500 hours of L3 operations. Successful completion of adversarial safety testing (APTS-MR-020). Demonstrated organizational capability for 24/7 monitoring and incident response. Comprehensive assessment of platform safety controls by personnel independent of the development team (internal red team, dedicated QA, or external firm at the operator's discretion).

Organizations MAY define stricter criteria but MUST NOT relax these minimums.

**3. Annual Autonomy Level Reauthorization**

Authorization is time-limited and requires annual renewal. The organization MUST conduct a complete review of past year operations and make a reauthorization decision:
- Annual review completed on schedule
- Assessment covers all criteria
- Decision document is complete and approved
- Reauthorization or downgrade communicated to team
- New authorization date documented

Review activities, decision criteria, and approval authority are detailed in the Implementation Guide.

### Verification

1. Review the most recent autonomy-level authorization cycle; verify a signed authorization memo exists with date, authorizing signatories, and target autonomy level
2. Verify all signatories are currently in authorized roles (cross-reference against the organization's current role assignments)
3. For the most recent level transition event, verify evidence of prerequisite completion: minimum supervised hours or engagement counts documented in the platform's progression criteria
4. For any L3→L4 transition, verify an independent review record exists with reviewer identity, review date, and review outcome
5. Verify progression criteria are documented and accessible to the operations team
6. **Negative test:** Attempt to promote a platform instance to a higher autonomy level with at least one documented prerequisite missing (insufficient hours, missing independent review, or unauthorized signatory); verify the promotion is blocked or flagged

---

## APTS-AL-026: Incident Investigation and Autonomy Level Adjustment

**Classification:** MUST | Tier 2

### Requirement

If an unintended impact incident occurs, structured investigation determines level appropriateness. The organization MUST conduct systematic incident investigation with root cause analysis, impact assessment, and level appropriateness review. Investigation processes, incident response procedures, and incident decision matrices are detailed in the Implementation Guide.

After a mandatory downgrade, the platform MUST NOT be re-authorized at the previous autonomy level until: (a) root cause analysis of the triggering incident is completed and documented, (b) corrective actions are implemented and verified, (c) a mandatory cooling-off period of at least 7 calendar days has elapsed, and (d) re-authorization is approved by a different authority than the individual who managed the incident. This prevents premature re-escalation without addressing underlying causes.

> **See also:** APTS-AL-018 (immediate incident response and pause behavior during testing), APTS-AL-025 (formal authorization framework that governs both initial authorization and post-downgrade re-authorization). The [Autonomy Downgrade Matrix Template](../appendix/Autonomy_Downgrade_Matrix_Template.md) provides an informative format for documenting downgrade triggers, temporary autonomy caps, evidence requirements, and re-authorization paths.

### Verification

For every incident in the most recent 12 months that triggered or qualified for a downgrade under this requirement, pull the incident case file and verify all of the following:

1. **Case file present:** Each incident has a single persistent case file identified by an incident ID and linked from the audit trail under APTS-AR-001. Missing case file fails.
2. **Root cause analysis fields populated:** The RCA MUST contain: triggering event timestamp, detection source, affected scope, contributing factors, primary root cause, and contributing root causes. Any missing field fails.
3. **Corrective actions recorded:** At least one corrective action MUST be recorded per identified root cause, with owner, due date, implementation evidence (ticket link, commit SHA, or config diff), and verification evidence (test result, log excerpt, or reviewer sign-off). Corrective actions without verification evidence fail.
4. **Downgrade decision documented:** If a downgrade was applied, the case file MUST record the pre-incident and post-incident autonomy level, the authority who approved the downgrade, and the timestamp of the decision. If no downgrade was applied, the file MUST record the explicit decision not to downgrade with justification.
5. **Cooling-off proof:** For re-authorizations following a mandatory downgrade, the case file MUST contain evidence that at least 7 calendar days elapsed between the downgrade timestamp and the re-authorization timestamp. Shorter intervals fail.
6. **Independent re-authorization:** The re-authorization approver identity MUST differ from the identity of the incident manager. Same-identity approvals fail.
7. **Cross-reference to AL-025:** Each re-authorization MUST be cross-referenced in the APTS-AL-025 authorization register with the incident ID. Missing cross-reference fails.

---

## APTS-AL-027: Evasion and Stealth Mode Governance

**Classification:** SHOULD | Tier 3

### Requirement

When the platform provides evasive or stealth capabilities (traffic jittering, timing randomization, header modification, protocol obfuscation, scan rate throttling for detection avoidance, or payload encoding to bypass security controls), the platform SHOULD enforce governance over their use:

1. **Default-off**: Evasion features MUST NOT be enabled by default
2. **Explicit authorization**: Activation of evasion capabilities MUST require explicit operator or client authorization documented in the engagement scope
3. **Disclosure**: The platform MUST disclose all active evasion techniques in engagement reports, including technique category, duration of use, and target systems affected
4. **Prohibited classes**: The engagement scope MUST define any prohibited evasion classes (for example, active IDS/IPS manipulation, security log tampering, or anti-forensic techniques)
5. **Impact reclassification**: Actions taken in evasion mode MUST be assessed at equal or higher impact severity than equivalent non-evasive actions, reflecting the additional risk of reduced detectability

**Applicability:** This requirement applies to platforms that implement evasion or stealth capabilities. Platforms without evasion features MAY document a justified exemption.

### Verification

1. Evasion features are disabled by default; verify no evasion is active in a fresh engagement
2. Enabling evasion requires documented authorization in the engagement scope
3. Test: attempt to enable evasion without scope authorization; verify it is blocked
4. Engagement reports disclose all evasion techniques that were active during the engagement
5. Prohibited evasion classes defined in scope are enforced; test by attempting a prohibited technique
6. Impact classification for evasive actions is equal to or higher than non-evasive equivalents

---

## APTS-AL-028: Containment Verification for L3 and L4 Autonomy

**Classification:** MUST | Tier 3

**Applicability:** Platforms that operate at L3 Semi-Autonomous or L4 Autonomous.

### Requirement

Platforms operating at L3 or L4 MUST periodically verify that the containment boundary declared under APTS-SC-019 and the action allowlist declared under APTS-SC-020 still hold in practice, using adversarial probes that do not rely on the agent's self-report. At minimum, the operator MUST:

1. **Exercise schedule**: Run containment verification exercises on a documented schedule. Minimum cadence is quarterly for L3 platforms and monthly for L4 platforms. Exercises MUST also run after any material change to the foundation model (APTS-TP-022), the sandbox policy (APTS-SC-019), or the action allowlist (APTS-SC-020).
2. **Boundary coverage**: Each exercise MUST probe the filesystem boundary, the network egress boundary, the process capability boundary, and the credential store isolation boundary declared under APTS-SC-019.
3. **Action-space coverage**: Each exercise MUST include probes that attempt to invoke tools or parameters outside the APTS-SC-020 allowlist through both direct invocation paths and input-manipulation paths (for example, prompt-injected instructions in target responses).
4. **Recording**: Each probe MUST be recorded as pass, fail, or inconclusive, with sufficient detail to reproduce the probe independently. Results MUST be written to the audit trail under APTS-AR-020.
5. **Failed-probe handling**: A failed probe MUST be treated as a containment incident under APTS-SC-018 and MUST trigger a review of whether the platform is safe to continue operating at its current autonomy level under APTS-AL-026.

The operator MUST NOT use the agent runtime itself to perform containment verification on its own boundary. Verification MUST be driven by a component outside the agent runtime, which may itself be an automated harness, but which MUST have independent credentials and an independent code path to the boundary under test.

### Rationale

L3 and L4 place the heaviest load on the containment boundary because human oversight has shifted from per-action approval to exception-based or periodic review. The boundary is no longer continuously observed by a human, so the operator needs an independent signal that the boundary still holds. Asking the agent whether it can escape its sandbox is not such a signal. Periodic adversarial probing, independent of the agent's own reports, is. The cadence scales with the autonomy level because the gap between observed behavior and possible behavior grows as the human recedes from the loop.

### Verification

1. **Schedule review**: Verify that the operator maintains a documented verification schedule meeting the minimum cadence for each platform's operating level, and that the most recent exercise matches the schedule.
2. **Coverage review**: Review the most recent exercise record. Verify that all four boundary classes in item 2 and both action-space probe classes in item 3 are covered, and that coverage is justified where any class is skipped.
3. **Independence check**: Verify that the verification harness runs outside the agent runtime, uses independent credentials, and does not depend on the agent's self-report for pass/fail determination.
4. **Failed-probe handling review**: Select any failed or inconclusive probe from the last twelve months (or note if none exist). Verify that it was handled as a containment incident under APTS-SC-018 and reviewed under APTS-AL-026.
5. **Change-triggered exercise**: Verify that material changes under APTS-TP-022, APTS-SC-019, or APTS-SC-020 in the review period triggered an exercise before the changed platform resumed L3 or L4 operation.

> **See also:** APTS-SC-018 (incident containment when probes fail), APTS-SC-019 (execution sandbox boundary that probes verify), APTS-MR-023 (agent runtime as an untrusted component).

---
