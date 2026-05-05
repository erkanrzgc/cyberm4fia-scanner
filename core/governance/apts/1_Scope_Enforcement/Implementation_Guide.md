# Scope Enforcement: Implementation Guide

Practical guidance for implementing APTS Scope Enforcement requirements. Each section provides a brief implementation approach, key considerations, and common pitfalls.

> **Note:** This guide is informative, not normative. Recommended defaults and example values are suggested starting points; the [Scope Enforcement README](README.md) contains the authoritative requirements. Where this guide and the README differ, the README governs.

---

## APTS-SE-001: Rules of Engagement (RoE) Specification and Validation

**Implementation:** Ingest RoE documents in standardized machine-parseable format (JSON/YAML/XML) before test initialization. Validate schema, required fields, and logical consistency before proceeding.

**Key Considerations:**
- Support versioning and historical tracking of RoE changes
- Implement cryptographic verification to prevent RoE tampering

**Common Pitfalls:**
- Accepting ambiguous natural language RoE without formalization
- Failing to validate RoE before initiating actions

**Implementation Aid:** See the [Rules of Engagement Template appendix](../appendix/Rules_of_Engagement_Template.md) for an illustrative JSON/YAML/XML starter structure that customers, operators, and reviewers can use to validate required RoE fields consistently.

---

## APTS-SE-002: IP Range Validation and RFC 1918 Awareness

**Implementation:** Validate all IP ranges using CIDR notation, detect overlaps using standard IP libraries, and explicitly prevent testing against reserved ranges (RFC 1918, 169.254.0.0/16, cloud metadata endpoints).

**Key Considerations:**
- Maintain updated lists of cloud provider IP ranges and metadata endpoints
- Use standardized libraries (ipaddress, netaddr) to avoid math errors

**Common Pitfalls:**
- Accidentally testing cloud metadata services (169.254.169.254)
- Treating IPv4-mapped IPv6 addresses carelessly

---

## APTS-SE-003: Domain Scope Validation and Wildcard Handling

**Implementation:** Validate domains against authoritative registrars, implement explicit wildcard inclusion/exclusion policies, and explicitly exclude third-party infrastructure domains.

**Key Considerations:**
- Document wildcard intent (*.example.com includes all subdomains)
- Verify domain ownership through DNS records

**Common Pitfalls:**
- Overly broad wildcard interpretation
- Testing third-party CDN domains not explicitly authorized

---

## APTS-SE-004: Temporal Boundary and Timezone Handling

**Implementation:** Enforce start/end times with microsecond precision, handle daylight saving time transitions, and honor excluded testing windows. Store all timestamps in UTC, convert for display only.

**Key Considerations:**
- Implement countdown alerts before boundary expiration
- Support multiple timezone representations for client clarity

**Common Pitfalls:**
- DST boundary errors causing off-by-one-hour issues
- Testing outside authorized windows due to timezone confusion

---

## APTS-SE-005: Asset Criticality Classification and Integration

**Implementation:** Implement the four canonical criticality levels (Critical, Production, Non-Production, Unknown), map corresponding testing restrictions per level, and enforce restrictions at runtime based on asset classification.

**Key Considerations:**
- Allow dynamic reclassification with audit trails
- Restrict invasive testing on critical assets

**Common Pitfalls:**
- Misclassifying asset criticality
- Failing to enforce restrictions consistently

---

## APTS-SE-006: Pre-Action Scope Validation

**Implementation:** Before every network action (HTTP request, port scan, API call), perform atomic scope validation: verify target against RoE, IP ranges, domain scope, and temporal boundaries.

**Key Considerations:**
- Validation must complete in under 100 milliseconds per action to avoid degrading test throughput. Log and alert the operator if validation latency exceeds this threshold.
- Make validation failures fatal by default
- Log all validation decisions for audit

**Common Pitfalls:**
- Caching scope checks too long, missing updates
- Allowing actions to proceed with partial validation
- Validation latency growing unbounded under load, silently degrading test performance

**Cloud-Native Scope Validation:**

For cloud environments, scope validation must account for:
- **Ephemeral IPs:** Validate by instance ID or resource ARN in addition to IP address. Cloud IPs change on restart.
- **Serverless targets:** Validate by function ARN, API Gateway endpoint, or service name rather than IP.
- **Container orchestration:** Validate by service name, namespace, and pod labels. Individual pod IPs are transient.
- **Multi-region:** Maintain per-region scope definitions. An IP authorized in us-east-1 is not authorized in eu-west-1 unless explicitly scoped.

---

## APTS-SE-007: Dynamic Scope Monitoring and Drift Detection

**Implementation:** Continuously monitor DNS resolution, cloud infrastructure changes, and scope boundary drift. Alert on unexpected IP-to-domain mappings or infrastructure migrations outside scope.

**Key Considerations:**
- Establish baseline DNS mappings at engagement start
- Detect DNS rebinding attacks in real-time

**Common Pitfalls:**
- Not detecting legitimate DNS changes during engagement
- Ignoring CDN and load-balancer IP rotations

---

## APTS-SE-008: Temporal Scope Compliance Monitoring

**Implementation:** Enforce temporal boundaries continuously during testing, with real-time monitoring of time remaining. Implement countdown alerts at T-60 minutes, T-30 minutes, and T-5 minutes before engagement end. Begin graceful shutdown procedures to ensure all testing halts by the engagement end time.

**Key Considerations:**
- Trigger automatic test pause/termination at boundaries
- Log all temporal scope violations

**Common Pitfalls:**
- Testing past authorized end time
- Not accounting for in-flight requests after boundary

---

## APTS-SE-009: Hard Deny Lists and Critical Asset Protection

**Implementation:** Maintain immutable deny lists for critical assets (primary databases, admin interfaces, payment systems). Deny list cannot be modified mid-engagement and takes precedence over all other scope rules.

**Key Considerations:**
- Implement deny lists in firewall or network layer
- Require separate authorization to add/remove deny list items

**Common Pitfalls:**
- Making deny lists mutable during engagement
- Testing critical assets due to deny list oversight

---

## APTS-SE-010: Production Database Safeguards

**Implementation:** Implement multi-layer protections: prevent direct SQL injection testing, restrict connection attempts to production databases, enforce read-only credential usage, and log all database access attempts.

**Key Considerations:**
- Use network isolation to restrict database access
- Rotate credentials immediately post-engagement

**Common Pitfalls:**
- Using writable credentials for testing
- Allowing unrestricted database connection attempts

---

## APTS-SE-011: Multi-Tenant Environment Awareness

**Implementation:** Implement strict tenant isolation checks before all actions. Map tenants to scope and prevent cross-tenant testing. Validate tenant context in every request.

**Key Considerations:**
- Document tenant mapping and isolation strategy
- Test tenant isolation boundaries explicitly

**Common Pitfalls:**
- Accidentally testing sibling tenant data
- Not validating tenant context in API calls

---

## APTS-SE-012: DNS Rebinding Attack Prevention

**Implementation:** Validate IP address against scope before using it, monitor DNS responses for changes during request execution, and reject responses that resolve to out-of-scope IPs.

**Key Considerations:**
- Use DNS over HTTPS to prevent on-path tampering
- Implement DNS response caching with short TTLs

**Common Pitfalls:**
- Assuming DNS response consistency
- Testing 127.0.0.1 or 0.0.0.0 due to rebinding

---

## APTS-SE-013: Network Boundary and Lateral Movement Enforcement

**Implementation:** Identify network boundaries (subnet, VLAN, DMZ) from initial scope. Restrict lateral movement to in-scope networks. Implement host-based firewalling rules on test platform.

**Key Considerations:**
- Detect and prevent pivoting to out-of-scope segments
- Document network topology relative to scope

**Common Pitfalls:**
- Pivoting through compromised in-scope systems
- Testing infrastructure not explicitly authorized

---

## APTS-SE-014: Network Topology Discovery Limitations

**Implementation:** Limit network discovery with configurable host limits (for example, 1000 hosts per subnet), per-host port scan limits (for example, 20 ports per host), and time limits (for example, max 8 hours per discovery phase).

**Key Considerations:**
- Implement discovery state checkpointing
- Resume discovery respecting limit budgets

**Common Pitfalls:**
- Running unbounded scans consuming all resources
- Discovering out-of-scope infrastructure

---

## APTS-SE-015: Scope Enforcement Audit and Compliance Verification

**Implementation:** Maintain immutable audit logs of all scope decisions, validation failures, and boundary violations. Include timestamp, action, target, decision, and reasoning.

**Key Considerations:**
- Store audit logs separately from main system
- Implement tamper detection for audit logs

**Common Pitfalls:**
- Logs erasable or modifiable
- Insufficient audit detail for forensic analysis

---

## APTS-SE-016: Scope Refresh and Revalidation Cycle

**Implementation:** Revalidate scope before each test cycle or at a maximum interval of 24 hours, whichever is shorter, for continuous-mode engagements.

**Key Considerations:**
- Pause testing during revalidation windows
- Document all scope changes in audit trail

**Common Pitfalls:**
- Not detecting infrastructure migrations mid-engagement
- Continuing testing with expired authorization

---

## APTS-SE-017: Engagement Boundary Definition for Recurring Tests

**Implementation:** Assign unique engagement IDs for recurring tests. Track each test cycle separately with independent scope, temporal boundaries, and authorization validity periods.

**Key Considerations:**
- Link related cycles in reporting for trend analysis
- Maintain separate audit trails per cycle

**Common Pitfalls:**
- Treating recurring tests as single engagement
- Missing authorization renewal between cycles

---

## APTS-SE-018: Cross-Cycle Finding Correlation and Regression Detection

**Implementation:** Fingerprint findings using stable identifiers (asset, vulnerability type, location). Assign lifecycle states (new, regressed, resolved, mitigated) and track across cycles.

**Key Considerations:**
- Handle false positives and false negatives in correlation
- Distinguish new findings from regression

**Common Pitfalls:**
- Over-correlating unrelated findings across cycles
- Losing context for old findings

---

## APTS-SE-019: Rate Limiting, Adaptive Backoff, and Production Impact Controls

**Implementation:** Define configurable testing windows (hours/days), off-peak testing enforcement, and automatic intensity reduction based on production metrics. Implement circuit-breaker pattern.

**Key Considerations:**
- Monitor production performance metrics during testing
- Provide manual throttle controls for operators

**Common Pitfalls:**
- Testing during peak business hours
- Not reducing intensity when production impact detected

---

## APTS-SE-020: Deployment-Triggered Testing Governance

**Implementation:** Authenticate deployment triggers using cryptographic signatures. Validate scope and authorization before test start. Enforce hard timeout (24h typical) to prevent runaway testing.

**Key Considerations:**
- Implement trigger validation before test launch
- Log all trigger invocations

**Common Pitfalls:**
- Accepting unauthenticated triggers
- No timeout allowing testing beyond deployment window

---

## APTS-SE-021: Scope Conflict Resolution for Overlapping Engagements

**Implementation:** Detect overlapping engagements for same assets. Apply most restrictive constraints (earliest end time, lowest criticality level) when conflicts exist. Alert stakeholders.

**Key Considerations:**
- Maintain central engagement registry
- Document conflict resolution decisions

**Common Pitfalls:**
- Allowing simultaneous conflicting engagements
- Choosing permissive constraint instead of restrictive

---

## APTS-SE-022: Client-Side Agent Scope and Safety Boundaries

**Implementation:** Include agents in RoE documents. Agents validate scope independently. Implement agent kill switch mechanism and time-bomb to prevent runaway agents.

**Key Considerations:**
- Agents authenticate to controller before action
- Test kill switch mechanism regularly

**Common Pitfalls:**
- Agents without independent scope validation
- Agents untestable/unkillable by operators

---

## APTS-SE-023: Credential and Secret Lifecycle Governance

**Implementation:** Maintain real-time inventory of all testing credentials scoped to engagement. Automatically rotate credentials at engagement end. Log all credential access and usage.

**Architecture Pattern - Credential Indirection for LLM-Based Agents:**

For platforms using LLM-based agents, implement a credential manager that enforces a strict separation between credential references (which the agent sees) and credential values (which only the tool execution layer sees):

1. **Credential Manager:** A dedicated component that stores secrets in memory only (never serialized to disk outside the encrypted vault). The manager issues opaque `CredentialReference` objects containing only the credential identifier, type, username, and role.
2. **Agent Prompt Injection:** When the agent needs to know which credentials are available, the credential manager generates a secret-free summary listing references only. This summary is safe to include in the model prompt.
3. **Tool-Time Resolution:** When a tool needs to use a credential (for example, to authenticate an HTTP request), the tool execution layer resolves the opaque reference to the actual secret value at execution time, outside the model's inference context. The secret is used in the outbound request but never returned to the model.
4. **Discovery Interception:** When a tool call returns output containing a discovered credential (for example, a password in a config file), the platform intercepts the tool result, extracts the credential into the vault, and replaces the plaintext value with an opaque reference before the result enters the model context.

This pattern ensures that credentials never appear in inference requests sent to model providers, agent reasoning traces, message history, or step-level logs.

**Key Considerations:**
- Enforce minimal credential permissions (least privilege)
- Prevent credential reuse across engagements
- For discovery interception, use pattern-based detection (regex for common secret formats like API keys, JWTs, connection strings) combined with entropy analysis to identify high-entropy strings that may be secrets
- Discovery interception adds latency to tool results; implement it as a lightweight synchronous filter rather than a separate inference call

**Common Pitfalls:**
- Persistent credentials surviving engagement end
- Excessive permissions for test credentials
- Implementing credential indirection for client-provided credentials but not for discovered credentials, which still enter the model context via tool output
- Logging the full tool result (including plaintext secrets) to trace files before the interception filter runs

---

## APTS-SE-024: Cloud-Native and Ephemeral Infrastructure Governance

**Implementation:** Support cloud APIs for infrastructure enumeration. Track ephemeral resources (containers, serverless functions) with short lifecycles. Implement scope validation for dynamic IPs.

**Key Considerations:**
- Monitor cloud provider event logs for scope violations
- Handle rapid infrastructure churn

**Common Pitfalls:**
- Testing destroyed infrastructure
- Testing unintended cloud resources

---

## APTS-SE-025: API-First and Business Logic Testing Governance

**Implementation:** Track API tokens and sessions throughout engagement. Monitor token refresh and expiration. Implement schema-drift detection. Log all business logic traversal.

**Key Considerations:**
- Establish baseline API schemas before testing
- Track bearer token and session lifecycle

**Common Pitfalls:**
- Using stale or expired API tokens
- Schema changes causing unexpected behavior

---

## APTS-SE-026: Out-of-Distribution Action Monitoring

**Implementation:** Start with a small, honest metric set rather than a dashboard of everything you can measure. Three or four action-distribution metrics that the operator actually understands beat fifteen that nobody looks at. Derive the baseline from historical engagements of the same class where possible; where the platform is too new, declare the expected distribution explicitly in the engagement configuration and mark the baseline as "declared, not observed." Set thresholds in terms the operator can defend (for example, "two standard deviations above the prior-quarter average for this engagement class") rather than as a default constant copied from a blog post. Route detections to a review queue that a human actually works, not an email alias. Record every detection, decision, and baseline refresh to the audit trail so that a reviewer can later reconstruct how the platform handled unusual behavior.

**Key Considerations:**
- The value of this control comes from reviewing detections, not from generating them; a monitor with no staffed review queue is worse than no monitor because it produces compliance theater
- Baselines drift as the platform matures and as engagement classes evolve; a refresh cadence is part of the control, not an afterthought
- Detections should never auto-terminate an engagement under this control; termination decisions belong to APTS-SC-011 and APTS-AL-026

**Common Pitfalls:**
- Treating "number of tool calls per minute" as the only metric and missing everything else that matters
- Using a single global baseline across engagement classes that have nothing in common
- Silencing detections during a noisy engagement and never re-enabling them
- Writing detection events to the agent runtime's own log instead of the isolated audit store required by APTS-AR-020

---

## Implementation Roadmap

**Phase 1 (implement before any autonomous pentesting begins):**
SE-001 through SE-006 (RoE validation, IP/domain/temporal scope, asset classification, pre-action validation), SE-008 (temporal compliance), SE-009 (deny lists), SE-015 (scope enforcement audit). These are all APTS Tier 1 requirements and form the minimum viable scope enforcement layer.

Start with SE-001 through SE-006 as the foundation. Nothing should execute without validated scope. Layer deny lists (SE-009) and temporal controls (SE-008) next.

**Phase 2 (implement within first 3 engagements):**
SE-007 (dynamic scope monitoring), SE-010 (production DB safeguards), SE-011 (multi-tenant awareness), SE-012 (DNS rebinding prevention), SE-013 (lateral movement enforcement), SE-016 (scope revalidation), SE-017 (recurring engagement boundaries), SE-019 (rate limiting and production impact controls), SE-020 (deployment-triggered testing), SE-022 (client-side agent scope), SE-023 (credential lifecycle governance), SE-024 (cloud/ephemeral infrastructure), SE-025 (API/business logic governance), SE-026 (out-of-distribution action monitoring, SHOULD). These are primarily APTS Tier 2 requirements.

Prioritize SE-013 (lateral movement) and SE-023 (credential governance) first since they prevent the most damaging scope violations. Add SE-010, SE-012, and SE-024 based on target environment complexity.

**Phase 3 (implement for maximum assurance):**
SE-014 (topology discovery limits, SHOULD), SE-018 (cross-cycle finding correlation, SHOULD), SE-021 (overlapping engagement conflict resolution, Tier 3). These provide advanced capabilities for platforms operating at scale or in multi-customer environments.
