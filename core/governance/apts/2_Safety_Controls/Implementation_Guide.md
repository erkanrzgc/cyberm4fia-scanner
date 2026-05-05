# Safety Controls: Implementation Guide

Practical guidance for implementing APTS Safety Controls requirements. Each section provides a brief implementation approach, key considerations, and common pitfalls.

> **Note:** This guide is informative, not normative. Recommended defaults and example values are suggested starting points; the [Safety Controls README](README.md) contains the authoritative requirements. Where this guide and the README differ, the README governs.

---

## APTS-SC-001: Impact Classification and CIA Scoring

**Implementation:** Define 4-5 impact tiers (Critical/High/Medium/Low/Info) for all pentesting actions. Classify each technique before execution based on potential system disruption, data exposure, or service degradation.

**Key Considerations:**
- Tier definitions must be specific to your target environment (cloud/on-prem/hybrid)
- Classification should be automated where possible; manual review for ambiguous cases

**Common Pitfalls:**
- Overly broad tier definitions that don't map to real business risk
- Failing to classify low-severity actions; cumulative impact matters

---

## APTS-SC-002: Industry-Specific Impact Considerations

**Implementation:** Overlay regulatory requirements (HIPAA, PCI-DSS, GDPR, and other applicable frameworks) on impact classifications. Adjust tiers where compliance violations carry heightened penalties. Document regulatory mapping.

**Key Considerations:**
- Engage legal/compliance team during classification design
- Consider data sensitivity in addition to system impact

**Common Pitfalls:**
- Ignoring industry constraints and classifying all actions identically
- Assuming all systems in scope have identical regulatory requirements

---

## APTS-SC-003: Real-World Impact Classification Examples

**Implementation:** Document at least 10 detailed scenarios with actual impact outcomes (for example, "SQL injection on payment DB caused 15-minute query slowdown; CIA 2/9/7"). Include timestamp, technique, and measured impact.

**Key Considerations:**
- Scenarios should represent diverse target types and techniques
- Include both "went as planned" and "unexpected impact" examples

**Common Pitfalls:**
- Cherry-picking only low-impact examples
- Omitting scenarios where impact was worse than expected

---

## APTS-SC-004: Rate Limiting, Bandwidth, and Payload Constraints

**Implementation:** Implement per-host connection caps and request-per-second limits based on impact tier. Enforce at the network layer (firewall rules) or application layer (API rate limiting). Recommended starting defaults: 50 concurrent connections and 100 req/s for Low-impact actions, scaling down to 5 connections and 10 req/s for Critical-impact actions. Enforce maximum payload sizes per impact tier: Informational/Low 100KB, Medium 10MB, High 100MB, Critical 500MB, with an engagement-wide bandwidth cap of 5 Gbps. Reject any action exceeding its payload limit before transmission. Implement cascading rate limits at subnet, datacenter, and engagement-wide levels so that aggregate traffic approaching subnet limits proactively reduces per-host rates. Adjust all values based on target capacity and document chosen values with rationale.

**Key Considerations:**
- Configure rate limits per impact tier, with lower limits for higher-impact actions
- Payload size enforcement must occur before transmission, not after
- Monitor and log all rate-limit triggers for post-engagement analysis

**Common Pitfalls:**
- Setting limits so high they fail to prevent impact
- Exceeding limits during reconnaissance without realizing it
- Omitting payload size enforcement while focusing only on request rate

---

## APTS-SC-005: Cascading Failure Prevention in Interconnected Systems

**Implementation:** Map interdependencies between systems (shared databases, API gateways, load balancers). Pre-identify failure cascades. Implement kill switches at dependency nodes (for example, stop all DB queries if query queue depth > threshold).

**Key Considerations:**
- Requires deep knowledge of target architecture; work with target architects
- Simulate cascades in testing to validate detection

**Common Pitfalls:**
- Assuming no cascading effects because "it's a test"
- Discovering dependencies only after an outage occurs

---

## APTS-SC-006: Threshold Escalation Workflow (Automated → Approval → Prohibited)

**Implementation:** Implement graduated escalation by impact level: Informational/Low actions execute automatically, Medium actions require standard approval within a defined window, High actions require elevated approval, and Critical actions require senior approval plus live operator confirmation. Recommended approval SLA defaults: Medium 15 minutes, High 30 minutes, Critical requires synchronous confirmation. Document the decision tree for each level.

**Key Considerations:**
- Phases should be tied to cumulative impact, not individual actions
- Approval timeout windows must be documented per severity level (see APTS-HO-003 for timeout and default-safe behavior requirements)

**Common Pitfalls:**
- Unclear handoff between automated and manual phases
- Failing to escalate when thresholds are breached

---

## APTS-SC-007: Cumulative Risk Scoring with Time-Based Decay

**Implementation:** Track cumulative impact over rolling windows (for example, 5-minute buckets). Apply decay function so old impact counts less (for example, 50% weight for 5+ min old). Reset counters at end of each engagement phase.

**Key Considerations:**
- Decay prevents a single spike from permanently blocking tests
- Align windows with engagement phases (reconnaissance, exploitation, cleanup)

**Common Pitfalls:**
- Not resetting counters between phases; leads to false positives
- Decay functions that decay too quickly and lose signal

**Risk Decay Formula:**

A commonly used decay model is exponential time-based decay:

```
current_risk = base_risk * e^(-lambda * t)
```

Where:
- `base_risk` = initial risk score from the action (derived from SC-001 CIA classification)
- `lambda` = decay constant (recommended: 0.1 for standard engagements, 0.05 for sensitive environments)
- `t` = time elapsed since action, in hours
- `e` = Euler's number (~2.718)

Reset windows: after a configurable period of zero new risk accumulation (recommended default: 4 hours), the cumulative score resets to zero. Document the chosen decay constant and reset window in the engagement configuration.

---

## APTS-SC-008: Threshold Configuration with Schema Validation

**Implementation:** Store all thresholds (rate limits, impact tiers, CIA scores, risk scores) in a structured config file (YAML/JSON) with JSON Schema validation. Enable hot-reload without restart.

**Key Considerations:**
- Schema should enforce type, range, and logical constraints
- Version configs and maintain audit log of all changes

**Common Pitfalls:**
- Hardcoding thresholds in source code
- Invalid configs breaking the safety system at execution time

---

## APTS-SC-009: Kill Switch

**Implementation:** Implement two-phase kill switch: Phase 1 (5s) ceases all new actions and allows in-flight requests to complete; Phase 2 (60s) force-terminates all connections and cleans up resources. Operator can trigger manually or system triggers automatically.

**Key Considerations:**
- Phase 1 ensures graceful exit; Phase 2 ensures hard stop
- Test kill switch in pre-engagement drills

**Common Pitfalls:**
- Kill switch implementation too slow to prevent cascading failures
- No way to verify kill switch was effective post-activation

**Cross-Domain Integration:**

When the kill switch activates, multiple domains execute in parallel:
1. **SC domain:** SC-009 halts new actions (Phase 1), SC-016 preserves evidence, SC-014 initiates rollback
2. **AR domain:** AR-001 logs the kill switch event with timestamp, trigger source, and operator ID
3. **HO domain:** HO-008 captures state dump, HO-015 sends notifications to all configured channels
4. **SE domain:** SE-006 ceases all scope validation (no new actions to validate)

Implementation MUST ensure these cross-domain actions execute independently. A failure in AR logging MUST NOT delay SC halt. A failure in HO notification MUST NOT prevent evidence preservation.

---

## APTS-SC-010: Health Check Monitoring, Threshold Adjustment, and Automatic Halt

**Implementation:** Execute health checks (HTTP GET, ICMP ping, database query) at regular intervals on all monitored targets. Recommended starting default: every 30 seconds for Critical assets, every 60 seconds for Production, every 5 minutes for Non-Production. If check fails or response time exceeds 200% of baseline, trigger escalation workflow (see APTS-SC-006). Document chosen intervals with rationale.

**Key Considerations:**
- Health checks must be low-overhead and representative of normal operations
- Distinguish between temporary unavailability and persistent failure

**Common Pitfalls:**
- Health checks that are too noisy (high false-positive rate)
- Assuming failed health check = operator error; investigate root cause

**Cloud-Native Health Monitoring:**

For platforms deployed on Kubernetes or container orchestration:
- Use liveness and readiness probes for platform health, but implement APTS health checks as a separate monitoring layer (do not rely solely on orchestrator health checks)
- Monitor pod restart counts, OOMKilled events, and CrashLoopBackOff as platform health signals
- For serverless deployments, monitor cold start latency, concurrent execution limits, and function timeout rates
- Use cloud-native monitoring services (CloudWatch, Azure Monitor, GCP Cloud Monitoring) as data sources, but implement independent threshold evaluation rather than relying on cloud provider alerting alone

---

## APTS-SC-011: Condition-Based Automated Termination

**Implementation:** Define explicit termination conditions and encode them in configuration. Recommended starting conditions: terminate if target service is unavailable for 5 consecutive health checks; error rate exceeds 10% sustained for 60 seconds; memory exhaustion detected on target; privilege escalation occurs outside scope; or cumulative risk score exceeds halt threshold (see APTS-SC-007). Log every trigger with context. Document chosen conditions with rationale.

**Key Considerations:**
- Conditions should be specific to engagement objectives and target architecture
- Regularly review logged triggers; adjust if false positives exceed 5%

**Common Pitfalls:**
- Conditions that are too broad or vague
- Not documenting why a specific condition was chosen

---

## APTS-SC-012: Network-Level Circuit Breaker

**Implementation:** At network layer, suspend traffic to degraded targets and enforce configurable cooldown period. Before resuming, probe with low-intensity health check. Only resume if probe succeeds.

**Key Considerations:**
- Requires network device (firewall, load balancer) integration
- Cooldown prevents rapid oscillation between suspend/resume

**Common Pitfalls:**
- Circuit breaker that suspends legitimate traffic too aggressively
- Resumption probes that are too aggressive and trigger another suspension

---

## APTS-SC-013: Time-Based Automatic Termination with Operator Override

**Implementation:** Enforce operator-specified maximum engagement duration with configurable time limits. Provide advance warning before time-based termination at a configured threshold. Extensions should require manager approval and be logged with justification for audit.

**Key Considerations:**
- Duration should account for phases: reconnaissance (30%), exploitation (50%), cleanup (20%)
- Override should require second operator approval

**Common Pitfalls:**
- Duration too short, forcing rushed cleanup
- Repeated overrides without analysis of why they're needed

---

## APTS-SC-014: Reversible Action Tracking and Rollback

**Implementation:** Log all reversible actions (firewall rule adds, account creations, privilege escalations) with before/after state. Maintain rollback procedures (scripts or manual steps) for each action. Test rollback paths in staging.

**Key Considerations:**
- Capture sufficient state to enable rollback (config files, user credentials, database snapshots)
- Prioritize rolling back high-impact actions first

**Common Pitfalls:**
- Assuming all actions are reversible; some (data deletion) are permanent
- Rollback scripts that fail silently or partially

---

## APTS-SC-015: Post-Test System Integrity Validation

**Implementation:** After engagement, run automated integrity checks: file hashing, configuration comparison against baseline, user account audit, security group audit. Generate report with discrepancies. Require sign-off before concluding engagement.

**Key Considerations:**
- Baselines must be captured before test begins
- Integrity checks should be non-destructive and fast (< 1 hour)

**Common Pitfalls:**
- Integrity checks that are too broad and flag benign changes
- Missing baselines for critical systems

---

## APTS-SC-016: Evidence Preservation and Automated Cleanup

**Implementation:** Write penetration test evidence (logs, screenshots, captured traffic) to write-once storage (immutable S3 bucket, WORM drive). Schedule automated cleanup after retention period (for example, 90 days). Log all cleanup actions.

**Key Considerations:**
- Distinguish between evidence (keep long-term) and temporary artifacts (cleanup quickly)
- Ensure cleanup automation cannot be bypassed by operators

**Common Pitfalls:**
- Evidence stored in writable locations; risk of tampering
- Cleanup that is too slow or incomplete

---

## APTS-SC-017: External Watchdog and Operator Notification

**Implementation:** Deploy independent external watchdog (separate infrastructure) that periodically contacts the penetration test platform and receives health status. If no contact for 5 min, send out-of-band alert (SMS, PagerDuty) to incident commander and customer.

**Key Considerations:**
- Watchdog MUST NOT depend on same infrastructure as penetration test platform
- Out-of-band alerts ensure notification even if primary systems are down

**Common Pitfalls:**
- Watchdog on same network as test platform; defeats independence
- Alert thresholds too aggressive, causing alert fatigue

---

## APTS-SC-018: Incident Containment and Recovery

**Implementation:** On unintended impact detection: auto-isolate affected system (network segmentation), halt all tests, initiate recovery (rollback + validation). Require re-validation of platform health before resuming tests on any system.

**Key Considerations:**
- Isolation must be reversible; maintain audit trail
- Re-validation should mirror post-test integrity checks

**Common Pitfalls:**
- Isolation that is too aggressive and affects legitimate users
- Recovery procedures that are untested and fail under pressure

---

## APTS-SC-019: Execution Sandbox and Containment Boundary Integrity

**Implementation:** Run the agent runtime inside a kernel-enforced sandbox (Linux namespaces plus seccomp profile, or a hardened container runtime such as gVisor or Kata Containers), or inside a lightweight VM with a minimal hypervisor attack surface. Declare the allowed filesystem paths, outbound network destinations, and process capabilities in a policy file committed alongside the agent's other configuration. Enforce network egress through an external egress proxy or L4 network policy that the agent runtime has no credentials to bypass. Log every blocked action as a containment event and route it to the platform's incident queue.

**Key Considerations:**
- The sandbox policy is an architectural document, not a runtime prompt; treat changes to it with the same rigor as code changes
- Egress allowlisting is the single most load-bearing control; if the agent can reach arbitrary IPs, nothing else in this requirement matters
- Containment events are a signal about the platform, not a bug in the agent; do not silence them during development

**Common Pitfalls:**
- Enforcing the boundary inside the agent's own runtime (for example, as a Python wrapper around tool calls), which the agent can remove or route around
- Treating the agent's refusal to attempt an out-of-boundary action as evidence the sandbox works
- Letting the sandbox policy drift from the version-controlled source because the runtime permissions were widened for a specific test and never reverted

---

## APTS-SC-020: Action Allowlist Enforcement External to the Model

**Implementation:** Maintain the agent's tool and action allowlist as a version-controlled artifact (for example, a YAML or JSON file in the platform repository). At runtime, the orchestration layer consults the allowlist before dispatching any tool call produced by the model. Allowlist entries specify the tool identifier, parameter schemas or bounds, and the risk classification used by the threshold escalation workflow in SC-006. The model's system prompt references the allowlist for clarity but does not define it. Tool additions, removals, and parameter widening go through the same code review and approval process as any other platform change.

**Key Considerations:**
- The allowlist is the single point of truth for what the agent is allowed to do; all other components defer to it
- Parameter bounds matter as much as the tool identifier; allowing "curl" without a destination allowlist is not a meaningful constraint
- Runtime allowlist drift is a leading indicator of platform hygiene problems; validate the runtime allowlist against the source artifact on every engagement start

**Common Pitfalls:**
- Putting the allowlist in the system prompt and calling that "enforcement"
- Exposing a "shell" or "exec" tool that accepts arbitrary commands, which collapses the allowlist into whatever the model decides to run
- Allowing ad-hoc tool additions during an engagement without change-management approval

---

## Advisory Practice Implementation Guidance

### APTS-SC-A02: Context Window Safety and Constraint Preservation

> This section provides implementation guidance for the advisory practice [APTS-SC-A02](../appendix/Advisory_Requirements.md#apts-sc-a02-context-window-safety-and-constraint-preservation-advisory). It is not required for conformance at any tier.

**Implementation:** Maintain an authoritative "safety context" document outside the agent's conversation history. This document contains the current scope definition, deny lists, autonomy level, active operator directives, credential references, and escalation state. After every context compaction event (summarization, truncation, sliding window), unconditionally re-inject this document into the agent's context and verify its integrity before allowing the next action.

**Architecture Pattern - External Safety Context Store:**

1. **Safety context document:** A structured document (JSON or equivalent) maintained by the orchestration layer, not by the agent. Contains all safety-critical constraints derived from the RoE, operator directives, and platform state. Updated only by the orchestration layer when scope changes, operator directives arrive, or autonomy level changes.
2. **Compaction hook:** Register a callback on the context management system that fires after every compaction event. The hook re-injects the safety context document into the agent's working context as a system-level message that the agent cannot modify or remove.
3. **Post-injection verification:** After re-injection, a lightweight check confirms the safety context elements are present and match the authoritative source. Hash comparison is sufficient; no LLM call is needed.
4. **Resume safety:** When resuming a session from persisted message history, apply the same re-injection logic. Treat session resume as equivalent to a compaction event.

**Key Considerations:**
- The safety context document should be compact (under 2000 tokens) to minimize the overhead of re-injection on every compaction
- SC-020 (external action allowlist) provides a backstop: even if context-level constraints are lost, the external allowlist still blocks disallowed tools. SC-A02 addresses constraints that are finer-grained than the allowlist (specific deny-list hosts, operator directives, autonomy-level restrictions)
- Context compaction is not a failure; it is a routine event. The system should handle it cleanly without operator intervention

**Common Pitfalls:**
- Relying on the summarization process to preserve constraints; LLM-based summarizers routinely drop, paraphrase, or dilute constraints that appeared early in the conversation
- Storing the authoritative safety context inside the agent's context window, where the summarizer can modify it
- Re-injecting safety context only at session start but not after mid-session compaction events
- Treating the agent's claim that it remembers its constraints as evidence that the constraints survived compaction

---

## Implementation Roadmap

**Phase 1 (implement before any autonomous pentesting begins):**
SC-001 (impact classification and CIA scoring), SC-003 (real-world classification examples), SC-004 (rate limiting, bandwidth, and payload constraints), SC-009 (kill switch), SC-010 (health check monitoring), SC-015 (post-test integrity validation), SC-020 (action allowlist enforcement external to the model).

Start with the kill switch (SC-009) and the external action allowlist (SC-020). These are the two architectural properties every responsible autonomous pentest platform must have before first engagement. Then implement impact classification (SC-001, SC-003) and rate limiting (SC-004). Layer health monitoring (SC-010) and post-test validation (SC-015) before first engagement.

**Phase 2 (implement within first 3 engagements):**
SC-002 (industry-specific impacts), SC-005 (cascading failure prevention), SC-006 (escalation workflow), SC-007 (cumulative risk scoring with time-based decay), SC-011 and SC-012 (automated termination, circuit breaker), SC-014 (rollback tracking), SC-016 (evidence preservation/cleanup), SC-017 and SC-018 (watchdog, incident containment), SC-019 (execution sandbox and containment boundary integrity).

Prioritize SC-011 and SC-012 (automated termination, circuit breaker) first. They prevent runaway testing. Then add SC-006 (escalation workflow) and SC-014 (rollback) to handle controlled degradation, and SC-019 (execution sandbox) to contain the agent runtime within a boundary the model itself cannot reach.

**Phase 3 (implement for maximum assurance):**
SC-008 (threshold schema validation, SHOULD), SC-013 (time-based termination, SHOULD).
