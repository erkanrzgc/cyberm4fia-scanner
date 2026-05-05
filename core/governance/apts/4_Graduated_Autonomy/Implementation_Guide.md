# Graduated Autonomy: Implementation Guide

Practical guidance for implementing APTS Graduated Autonomy requirements. Each section provides a brief implementation approach, key considerations, and common pitfalls.

> **Note:** This guide is informative, not normative. Recommended defaults and example values are suggested starting points; the [Graduated Autonomy README](README.md) contains the authoritative requirements. Where this guide and the README differ, the README governs.

---

## APTS-AL-001: Single Technique Execution

**Implementation:** Implement an execution model that isolates each technique invocation. Enforce a one-technique-per-operation constraint at the API and scheduling layer. No automatic chaining or result-driven sequencing.

**Key Considerations:**
- Require explicit human command for each technique execution
- Provide clear feedback on completion status before accepting new commands
- Isolate execution contexts to prevent state leakage between operations

**Common Pitfalls:**
- Tools that auto-escalate credentials or chain exploits without human intervention
- Workflow engines that trigger successive techniques based on prior results

---

## APTS-AL-002: Human-Directed Target and Technique Selection

**Implementation:** Remove all heuristic or automated selection logic. All targeting and technique choices originate from explicit human operator commands. Validate that selections match authorized scope.

**Key Considerations:**
- Build command interfaces that require unambiguous target and technique specification
- Log all selection decisions with operator identity and timestamp
- Prevent default or inferred selections from applying

**Common Pitfalls:**
- Fuzzy matching or "best guess" target resolution
- Tool defaults that apply if parameters are incomplete
- Implicit authorization assumptions

---

## APTS-AL-003: Parameter Configuration by Human Operator

**Implementation:** Require explicit human configuration of all technique parameters before execution. Never apply tool defaults or infer parameters from context. Surface all configurable options with clear explanations.

**Key Considerations:**
- Prompt operators for every tunable parameter with safe defaults offered for review
- Reject execution if critical parameters lack explicit operator confirmation
- Document which defaults were proposed and which were operator-chosen

**Common Pitfalls:**
- Silent parameter substitution if operator omits optional fields
- Undocumented tool assumptions that override operator intent
- Parameter inheritance from previous operations

---

## APTS-AL-004: No Automated Chaining or Sequential Decision-Making

**Implementation:** Disable workflow automation and decision trees at Tier 1. Require explicit human command for every subsequent action. Build enforcement at the orchestration layer, not just by guideline.

**Key Considerations:**
- Remove or disable conditional logic that branches based on technique results
- Implement hard blocking if chaining is attempted without new human approval
- Clearly communicate wait state and expected next command

**Common Pitfalls:**
- Workflow templates that auto-progress based on success/failure conditions
- Background tasks that trigger escalation without alerting the operator
- Conditional parameter injection from prior results

---

## APTS-AL-005: Mandatory Logging and Human-Reviewable Audit Trail

**Implementation:** Capture all actions, parameters, results, operator decisions, and timestamps. Ensure logs are human-readable and forensically complete. Include operator identity, authorization scope, and approval status for each action.

**Key Considerations:**
- Log must capture intent (what was requested), execution (what was done), and outcome
- Timestamp all events with atomic clock or trusted time source
- Include sufficient context for later reconstruction without re-execution

**Common Pitfalls:**
- Binary or compressed logs that require tools to decode
- Missing operator identity or authorization source
- Sparse logging that omits intermediate steps or failed attempts

---

## APTS-AL-006: Basic Scope Validation and Policy Enforcement

**Implementation:** Validate all targets, techniques, and parameters against explicit scope rules before execution. Maintain a scope authorization document (whitelist or CIDR blocks). Block any execution outside authorized scope.

**Key Considerations:**
- Implement validation as a non-bypassable pre-execution gate
- Scope rules must be maintained by authorized personnel, not operators
- Log all scope validation decisions (pass and fail)

**Common Pitfalls:**
- Scope files that are editable by operators
- Validation logic that runs after execution begins
- Scope interpreted as "guidelines" rather than hard limits

---

## APTS-AL-007: Multi-Step Technique Chaining Within Single Phase

**Implementation:** At Tier 2, permit chaining of multiple techniques within a single phase (for example, multiple recon steps, or multiple exploitation steps on a confirmed target) without per-action human approval, provided all belong to the same pre-defined phase.

**Key Considerations:**
- Define phase boundaries explicitly in policy (for example, Reconnaissance, Exploitation, Persistence)
- Operator approves the phase and entry conditions; system chains within phase
- Log each chained step and provide operator visibility into chain progression

**Common Pitfalls:**
- Vague phase definitions that blur boundaries
- Chaining across phases without human re-approval
- Loss of visibility into which steps were automatic and which were operator-triggered

**L2/L3 Architecture Pattern:**

L2 and L3 autonomy require a state machine governing phase transitions and action authorization:

```
States: IDLE → RECONNAISSANCE → EXPLOITATION → POST_EXPLOITATION → REPORTING → CLEANUP
Transitions:
  IDLE → RECONNAISSANCE: requires operator_start_command AND scope_validated
  RECONNAISSANCE → EXPLOITATION: requires (discovery_complete OR operator_override) AND operator_approval(L2) OR boundary_check_pass(L3)
  EXPLOITATION → POST_EXPLOITATION: requires exploitation_objectives_met AND operator_review(L2) OR auto_transition(L3)
  POST_EXPLOITATION → REPORTING: requires post_exploitation_complete AND evidence_preserved
  REPORTING → CLEANUP: requires report_generated AND rollback_initiated
  ANY → IDLE: kill_switch_activated (unconditional, highest priority)
```

Each transition MUST be logged per APTS-AR-001 with: previous state, new state, transition trigger, operator ID (if applicable), and timestamp. At L2, operator approval is required for any transition into EXPLOITATION. At L3, the platform may auto-transition if pre-approved boundary checks pass, but MUST log the decision rationale.

---

## APTS-AL-008: Real-Time Human Monitoring and Approval Gates

**Implementation:** Provide a real-time dashboard showing active tests, current technique execution, findings, and escalation alerts. Implement approval gates for high-risk actions (exploitation, lateral movement) with operator override capability.

**Key Considerations:**
- Dashboard must update without requiring operator polling
- Approval gates must block execution until operator acknowledges and approves
- Provide clear escalation path and alert thresholds
- Support intervention (pause, terminate) at any point

**Common Pitfalls:**
- Approval gates that can be silently overridden
- Delays in alert delivery or dashboard updates
- Insufficient context to make approval decision

---

## APTS-AL-009: Tool-Proposed Actions with Operator Modification Capability

**Implementation:** At Tier 2, permit the tool to propose the next action(s) based on findings, but require operator approval with modification capability. Operator can reject, edit parameters, or substitute a different action.

**Key Considerations:**
- Display reasoning for tool proposal so operator can evaluate soundness
- Allow modification of proposed parameters without re-authorizing entire action
- Log operator modifications and rationale
- Reject execution if proposal logic becomes opaque or unexplainable

**Common Pitfalls:**
- Proposals that are hard to understand or justify
- Modification interfaces that are cumbersome or error-prone
- Assumption that proposal approval constitutes informed consent

---

## APTS-AL-010: Step-by-Step Audit Log with Phase Transitions

**Implementation:** Enhance the Tier 1 audit trail to capture each step explicitly, including operator decisions at phase transitions. Record when operator approves phase entry, chaining parameters, and any modifications to tool proposals.

**Key Considerations:**
- Phase transition decisions must be logged with explicit operator sign-off
- Include tool reasoning and operator rationale for modifications
- Make logs queryable by phase, operator, and decision type
- Preserve enough context to understand branching decisions

**Common Pitfalls:**
- Phase transitions logged implicitly rather than as explicit decisions
- Inability to correlate operator decisions with log entries
- Logs that omit rationale for modifications or rejections

---

## APTS-AL-011: Escalation Triggers and Exception Handling

**Implementation:** Define explicit escalation triggers for scope violations, unplanned exploitation (crashes, denial of service), anomalies, and policy breaches. Automatically pause execution and alert on any trigger. Require operator decision before resuming.

**Key Considerations:**
- Escalation triggers must be pre-defined and documented in policy
- System must support custom triggers per engagement
- Alert delivery must be reliable and timely (under 2 minutes)
- Logging must capture what triggered escalation and operator response

**Common Pitfalls:**
- Triggers so loose that they never fire, or so tight they spam alerts
- Pauses that automatically resume after timeout
- Escalations that proceed in background while operator is unaware

---

## APTS-AL-012: Kill Switch and Pause Capability

**Implementation:** Provide immediate operator-initiated pause and terminate commands with single-click activation. Pause must stop all active technique execution and pending actions. Terminate must cleanly exit and preserve logs.

**Key Considerations:**
- Kill switch must be available at all times and take effect in under 10 seconds
- Distinguish pause (resumable) from terminate (final) operations
- Preserve state on pause to allow clean resumption
- Log all pause/terminate events with operator identity and rationale

**Common Pitfalls:**
- Kill switches that require multi-step confirmation
- Pause that doesn't actually stop background tasks
- Resumption that loses context or replays unintended actions

---

## APTS-AL-013: Complete Attack Chain Execution Within Boundaries

**Implementation:** At Tier 2, permit full attack chains (recon → exploitation → post-exploitation) to execute autonomously within pre-approved boundaries. Boundaries must include scope, techniques, asset categories, and impact thresholds.

**Key Considerations:**
- Boundaries must be formally defined and technically enforced
- Pre-approval must be documented with authorization date and signoff
- System must continuously verify that chain stays within boundaries
- Any boundary breach must trigger immediate pause and escalation

**Common Pitfalls:**
- Vague boundaries that require interpretation during execution
- Boundaries defined as policy documents rather than enforced in code
- Lack of visibility into what the chain is actually doing

---

## APTS-AL-014: Boundary Definition and Enforcement Framework

**Implementation:** Establish a formal boundary definition model covering scope (targets, networks, IP ranges), techniques (tool list, not-permitted techniques), asset categories (databases, credentials, PII), and impact thresholds. Enforce via code, not policy alone.

**Key Considerations:**
- Boundaries must be version-controlled and change-tracked
- Enforcement must occur pre-execution and continuously during execution
- Support multiple boundary sets per engagement
- Integrate with scope authorization document (APTS-AL-006)

**Common Pitfalls:**
- Boundaries described in prose rather than machine-readable format
- Enforcement that relies on operator judgment
- Outdated boundaries that diverge from current authorization

---

## APTS-AL-015: Pre-Approved Action Categories and Decision Trees

**Implementation:** Define pre-approved categories of actions (for example, "SQL injection on web apps in scope", "Brute force on open SSH ports in DMZ") with clear decision criteria. Tool autonomy is restricted to these categories; other actions require human re-approval.

**Key Considerations:**
- Decision trees must have clear, measurable entry criteria
- Each category must map to pre-approved techniques and parameters
- Log which category each autonomous decision fell under
- Review and update categories quarterly or per engagement

**Common Pitfalls:**
- Categories so broad they encompass unexpected actions
- Decision trees with subjective or unmeasurable criteria
- No mechanism to challenge or override categorization

---

## APTS-AL-016: Continuous Boundary Monitoring and Breach Detection

**Implementation:** Implement real-time monitoring of all technique execution against defined boundaries. If any action breaches scope, technique list, or impact threshold, immediately pause execution and alert operator. Do not proceed without explicit re-approval.

**Key Considerations:**
- Monitoring must sample actively, not depend on post-execution review
- Detection logic must be fast enough to prevent harm (sub-second ideal)
- Alert must clearly articulate what boundary was crossed and why
- Provide mechanism for operator to acknowledge, override with caution, or correct and retry

**Common Pitfalls:**
- Batch monitoring that only checks after technique completes
- Boundaries defined but not monitored
- Alerts that are too verbose or missing key context

---

## APTS-AL-017: Multi-Target Assessment Management

**Implementation:** At Tier 2, extend orchestration to manage assessment across multiple targets simultaneously. Maintain a target queue, prioritize based on criteria (criticality, dependency), and dispatch techniques to targets while respecting per-target scope and phase.

**Key Considerations:**
- Target queue must be human-managed (no auto-discovery at Tier 2)
- Prioritization rules must be pre-defined and configurable
- Each target must have independent scope and phase state
- System must prevent resource exhaustion or unintended collateral impact

**Common Pitfalls:**
- Target queue that auto-expands to related systems
- Prioritization that operator cannot override
- Cross-target resource conflicts or interference

---

## APTS-AL-018: Incident Response During Autonomous Testing

**Implementation:** When autonomous testing triggers a security incident (for example, intrusion detection alarm, endpoint alert), immediately pause all testing, capture logs, and alert operator. Require human decision before resuming: investigate incident, modify scope, or abort test.

**Key Considerations:**
- Integrate with customer's SIEM or monitoring tools to detect real incidents
- Pause must be non-negotiable and immediate
- Provide incident context (time, system, alert) to operator for decision-making
- Log decision rationale in test report

**Common Pitfalls:**
- Testing continues in background while operator is unaware of incident
- Incident detection that only works for known alert signatures
- Operator pressure to resume before incident is investigated

---

## APTS-AL-019: Multi-Target Campaign Management Without Intervention

**Implementation:** At Tier 3, permit full autonomous operation across multiple targets and campaigns. System manages queue, phases, escalations, and incident response without human intervention between cycle reviews. Operator reviews cycle results and authorizes next cycle.

**Key Considerations:**
- Campaigns must be pre-authorized with explicit scope, targets, and success criteria
- System must operate independently for a defined cycle (for example, 1 week)
- Periodic review (for example, weekly) provides human check-in and re-authorization
- All incident responses, escalations, and scope decisions must be logged for review

**Common Pitfalls:**
- Cycles so long that incidents accumulate unnoticed
- Lack of visibility into campaign progress between reviews
- Re-authorization that is perfunctory rather than substantive

---

## APTS-AL-020: Dynamic Scope Adjustment and Target Discovery

**Implementation:** At Tier 3, permit dynamic inclusion of targets discovered within pre-approved parameters (for example, subnets, asset categories, vulnerability criteria). System auto-adds targets; operator reviews and approves via periodic cycle review.

**Key Considerations:**
- Discovery must be restricted to pre-defined parameters (no open-ended scoping)
- Discovered targets must be logged and presented to operator at cycle review
- Operator can exclude discovered targets or adjust parameters
- Technical enforcement of scope boundaries remains in place

**Common Pitfalls:**
- Discovery parameters interpreted too broadly
- Discovered targets added without logging or review
- Inability to retroactively exclude targets from completed cycles

---

## APTS-AL-021: Adaptive Testing Strategy and Resource Reallocation

**Implementation:** At Tier 3, the system may autonomously adjust testing strategy and reallocate resources based on findings (for example, deeper investigation of critical vulnerabilities, deprioritization of patched systems). Decisions must be explainable and logged for review.

**Key Considerations:**
- Strategy adaptation must remain within pre-approved technique and boundary constraints
- Adaptation logic must be rule-based and transparent, not black-box ML
- Log all adaptation decisions with reasoning
- Operator can override or reverse adaptations at cycle review

**Common Pitfalls:**
- Adaptation logic that is opaque or uses unexplainable heuristics
- Adaptations that deviate from pre-approved techniques
- Resource reallocation that causes starvation or unfair targeting

---

## APTS-AL-022: Continuous Risk Assessment and Automated Escalation

**Implementation:** At Tier 3, the system continuously computes risk scores based on findings and proactively escalates high-risk items to operator (critical vulnerabilities, potential compliance violations). Escalation does not pause testing but alerts operator to high-priority findings.

**Key Considerations:**
- Risk scoring must be documented and configurable per engagement
- Escalations must be timely (near-real-time) and not defer to cycle review
- High-risk escalations may prompt operator intervention mid-cycle
- Maintain separation between informational escalation and pause-triggering escalation

**Common Pitfalls:**
- Risk scores that are not explainable or not configurable
- Escalations that are too frequent (alert fatigue) or too rare (missed risks)
- Escalations that automatically pause testing instead of alerting

---

## APTS-AL-023: Complete Audit Trail and Forensic Reconstruction

**Implementation:** Maintain a complete, immutable audit trail that is forensically sufficient to reconstruct every action, decision, and outcome. Logs must support detailed investigation of incidents, operator decisions, and system behavior without re-running the test.

**Key Considerations:**
- Logs must capture all inputs, execution context, results, and decisions
- Logs must be tamper-evident (digital signatures or append-only storage)
- Log retention must meet regulatory and contractual requirements
- Logs must support efficient querying and export for forensic analysis

**Common Pitfalls:**
- Logs that require external tools or databases to interpret
- Log formats that change mid-engagement
- Insufficient metadata to correlate logs across systems

---

## APTS-AL-024: Periodic Autonomous Review Cycles

**Implementation:** At Tier 3, despite autonomous operation, establish periodic review cycles (weekly, bi-weekly) where operator examines cycle results, validates scope adherence, reviews escalations, and explicitly authorizes the next cycle.

**Key Considerations:**
- Review must be substantive, not perfunctory (operator inspects logs and findings)
- Review checklist should cover scope, escalations, incidents, and adaptations
- Authorization for next cycle must be documented
- Issues discovered in review should be addressed before cycle restart

**Common Pitfalls:**
- Review cycles that are too long (issues accumulate)
- Reviews that are delegated to junior staff without authority to pause
- Lack of escalation path if review raises concerns

---

## APTS-AL-025: Autonomy Level Authorization, Transition, and Reauthorization

**Implementation:** Establish formal governance for autonomy level assignment and progression. Each engagement must have documented authorization for the autonomy level being used, signed by appropriate stakeholders (customer, pentester lead, legal if required).

**Key Considerations:**
- Authorization must occur before testing begins and be documented in engagement agreement
- Progression from L1 to L2 to L3 to L4 must be explicit, not automatic
- Reauthorization may be required if scope, customer, or risk profile changes
- Maintain audit trail of all authorization decisions

**Common Pitfalls:**
- Assuming authorization from previous engagements carries over
- Progression decided by tool, not by explicit stakeholder approval
- Lack of mechanism to downgrade if trust is violated

---

## APTS-AL-026: Incident Investigation and Autonomy Level Adjustment

**Implementation:** When a security incident or escalation triggers during testing, conduct structured investigation. If incident results from system malfunction or boundary breach, downgrade autonomy level pending root-cause analysis and corrective action.

**Key Considerations:**
- Incident investigation must be documented and shared with stakeholders
- Downgrade must occur promptly; testing may resume only at lower autonomy level
- A downgrade matrix can predefine trigger conditions, temporary autonomy caps, approval paths, and evidence preservation requirements before an incident occurs
- Root-cause analysis must address system, process, or training failures
- Corrective actions must be verified before autonomy level is restored

**Common Pitfalls:**
- Incidents treated as isolated events rather than system failures
- Downgrades that are reversed without addressing root cause
- Investigation that lacks independent review

---

## APTS-AL-027: Evasion and Stealth Mode Governance

**Implementation:** Evasion and stealth techniques (anti-forensics, evasion of monitoring, credential masking) must be explicitly authorized in writing and default to OFF. If used, document all stealth measures in the test report and disclose to customer.

**Key Considerations:**
- Evasion authorization must be separate from general test authorization
- Stealth techniques MUST be listed explicitly, not inferred
- Report MUST document which techniques were used and how
- Stealth measures MUST NOT obscure the audit trail or incident response data

**Common Pitfalls:**
- Evasion enabled by default or assumed to be implicit in authorization
- Stealth that prevents detection of incidents or compliance violations
- Insufficient disclosure in report about evasion methods
- Using stealth to avoid accountability rather than to test detection

---

## APTS-AL-028: Containment Verification for L3 and L4 Autonomy

**Implementation:** Build a containment verification harness that lives outside the agent runtime and has independent credentials to the boundary components it tests. Keep the probe catalog in version control alongside the APTS-SC-019 sandbox policy and the APTS-SC-020 allowlist so that widening the boundary always comes with a new probe. Probes should be concrete and reproducible: attempt a write to a filesystem path outside the declared allow set, attempt a DNS lookup for a host outside the egress allowlist, attempt to invoke a tool with parameters outside the allowlist schema, attempt to submit a prompt-injected instruction that tries to drive the agent toward a denied tool. Run the harness on the schedule defined by the requirement, and run it automatically after any change to the sandbox policy, allowlist, or foundation model. Record every run to the audit store so that the reviewer can verify the schedule and inspect results independently of the agent.

**Key Considerations:**
- The harness is part of the platform's safety control surface; treat it with the same code review and change management as the controls it tests
- A successful probe (boundary held) is a positive signal but not proof the boundary holds against all adversaries; a failed probe is a definitive signal something is wrong
- Probes drawn from recent threat intelligence about the foundation model in use age quickly; revisit the catalog at least quarterly

**Common Pitfalls:**
- Using the agent runtime itself to run the probes, which lets a compromised or drifted agent report "all green" regardless of reality
- Running the harness on a schedule but not regenerating it after widening the allowlist, so new capabilities ship untested
- Silencing failed probes because "the sandbox is probably fine" instead of treating them as containment incidents under APTS-SC-018

---

## Implementation Roadmap

**Phase 1 (implement before any autonomous pentesting begins):**
APTS-AL-001 through APTS-AL-006 (L1 controls: single technique execution, human-directed selection, parameter configuration, no auto-chaining, audit trail, scope validation), APTS-AL-008 (real-time monitoring and approval gates), APTS-AL-011 (escalation triggers), APTS-AL-012 (kill switch and pause), APTS-AL-014 (boundary enforcement framework), APTS-AL-016 (continuous boundary monitoring).

Start with APTS-AL-001 through APTS-AL-004 (L1 constraints) as the foundation. These ensure the tool cannot operate beyond human direction. Add APTS-AL-012 (kill switch) and APTS-AL-014 (boundary enforcement) as safety controls, then APTS-AL-005, APTS-AL-006, APTS-AL-008 for audit and monitoring.

**Phase 2 (implement within first 3 engagements):**
APTS-AL-007 (multi-step chaining within phase), APTS-AL-009 (tool-proposed actions, SHOULD), APTS-AL-010 (phase transition audit), APTS-AL-013 (full attack chain within boundaries), APTS-AL-015 (pre-approved action categories), APTS-AL-017 (multi-target management), APTS-AL-018 (incident response during testing), APTS-AL-025 (autonomy level authorization and transition), APTS-AL-026 (incident-triggered level adjustment), APTS-AL-027 (evasion/stealth governance).

Implement APTS-AL-025 (authorization framework) first. It governs how the platform moves between autonomy levels. Then add APTS-AL-007 and APTS-AL-013 (chaining controls) for L2/L3 operations.

**Phase 3 (implement based on operational maturity):**
APTS-AL-019 (autonomous multi-target campaigns), APTS-AL-020 (dynamic scope adjustment), APTS-AL-021 (adaptive strategy, SHOULD), APTS-AL-022 (continuous risk assessment, SHOULD), APTS-AL-023 (complete forensic audit trail), APTS-AL-024 (periodic autonomous review, SHOULD), APTS-AL-028 (containment verification for L3 and L4 autonomy).

Phase 3 requirements apply to platforms targeting L3 Semi-Autonomous or L4 Autonomous operation. Implement APTS-AL-028 alongside APTS-SC-019 and APTS-SC-020: those three together give you a declared boundary, a declared action space, and a periodic independent check that both still hold.
