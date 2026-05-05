# OWASP APTS Compliance Checklists

Informative Appendix (non-normative)

This appendix is part of the OWASP Autonomous Penetration Testing Standard (APTS). It organizes all 173 tier-required requirements by domain and compliance tier so that platform operators (vendors, service providers, and enterprise security teams) and customers can quickly identify what must be satisfied for each tier within each domain. All requirements referenced here are defined in the domain READMEs, which are the authoritative source. Advisory practices (identifiers of the form `APTS-<DOMAIN>-A0x`) live in the [Advisory Requirements appendix](Advisory_Requirements.md) and are not included in tier conformance.

**How to use:** For your target compliance tier, satisfy all requirements at that tier **and all lower tiers** within each domain. Tier 2 includes all Tier 1 requirements; Tier 3 includes all Tier 1 and Tier 2 requirements.

**Notation:** Each requirement is marked **MUST** (mandatory) or **SHOULD** (recommended). Both MUST and SHOULD requirements must be satisfied for tier conformance. No partial credit.

---

## 1. Scope Enforcement (SE) --- 26 Requirements

### Tier 1 (9 Requirements)

- [ ] **APTS-SE-001** | MUST | Ingest and validate machine-parseable Rules of Engagement containing target lists, temporal boundaries, action restrictions, asset criticality, authorization proof, and escalation procedures before test initialization.
- [ ] **APTS-SE-002** | MUST | Validate all IP ranges using CIDR notation with overlap detection, private IP space identification, cloud metadata endpoint validation, IPv4/IPv6 support, and reserved address space protection.
- [ ] **APTS-SE-003** | MUST | Validate domain specifications with explicit wildcard policies, domain ownership verification, and third-party infrastructure exclusion unless explicitly authorized.
- [ ] **APTS-SE-004** | MUST | Enforce temporal boundaries with microsecond precision, UTC conversion, DST handling, maintenance window exclusions, and prevention of testing after engagement end date.
- [ ] **APTS-SE-005** | MUST | Support asset criticality levels (critical, production, non-production, unknown) with corresponding testing restrictions and conservative defaults for unknown assets.
- [ ] **APTS-SE-006** | MUST | Validate scope immediately before every network action (connections, DNS, redirects, API calls) atomically, logging failures and preventing execution on failure.
- [ ] **APTS-SE-008** | MUST | Continuously enforce temporal boundaries with countdown alerts at T-60/30/5 minutes, immediate halt at end_time, and explicit authorization required before resuming after maintenance windows.
- [ ] **APTS-SE-009** | MUST | Maintain immutable hard deny lists for production databases, critical infrastructure, PII/PHI datastores, financial systems, control systems, and identity providers with cryptographic protection.
- [ ] **APTS-SE-015** | MUST | Maintain immutable audit logs of all scope decisions with context, timestamp, outcome, and action taken; generate compliance reports comparing actions against RoE; retain logs for engagement duration plus 90 days minimum.

### Tier 2 (16 Requirements)

- [ ] **APTS-SE-007** | MUST | Continuously monitor DNS changes, cloud resource boundaries, and scope drift (subdomain explosion, lateral movement creep, credential reuse spread, network enumeration expansion), automatically pausing on detection.
- [ ] **APTS-SE-010** | MUST | Automatically identify production databases and implement multi-layered protection: detection by name/port/provider, connection prevention, credential rejection, read-only enforcement, and audit logging.
- [ ] **APTS-SE-011** | SHOULD | Identify shared infrastructure, validate tenant isolation, detect shared services, monitor for cross-tenant data access, and block modifications affecting other tenants.
- [ ] **APTS-SE-012** | MUST | Validate resolved IPs against scope before connecting, re-validate on DNS changes, apply scrutiny to low-TTL records, and log all DNS resolutions with hostname, IP, TTL, timestamp, and validation result.
- [ ] **APTS-SE-013** | MUST | Identify and enforce VLAN/subnet/cloud boundaries, restrict lateral movement with pivot counting limits, block privilege escalation to higher-criticality systems, and prevent cross-cloud-account access.
- [ ] **APTS-SE-014** | SHOULD | Limit network topology discovery to authorized subnets with configurable maximums for hosts per subnet and ports per host, enforce time-based discovery limits, and prevent exhaustive reconnaissance.
- [ ] **APTS-SE-016** | MUST | Revalidate scope every 24 hours or before each cycle for continuous/recurring modes, query authoritative asset sources, flag new assets for approval, and produce scope delta reports.
- [ ] **APTS-SE-017** | MUST | Define engagement model (continuous, scheduled recurring, or triggered), assign discrete cycle IDs with timestamps, track findings separately across cycles, and enforce authorization token validity periods.
- [ ] **APTS-SE-018** | SHOULD | Fingerprint findings using vulnerability type/asset/component/evidence, assign lifecycle states (NEW, PERSISTENT, REMEDIATED, REGRESSED), flag regressions with elevated priority, and produce trend reports.
- [ ] **APTS-SE-019** | MUST | Rate Limiting, Adaptive Backoff, and Production Impact Controls - For continuous mode, support configurable testing windows, criticality-based rate limits, automatic intensity reduction on response time degradation (>20% threshold), halt on target unresponsiveness, implement per-target and global rate limiting with adaptive backoff, use default conservative rates (10 RPS per target), automatically reduce rates on errors, and alert on out-of-scope DoS.
- [ ] **APTS-SE-020** | MUST | Authenticate deployment triggers, validate deployment target against scope, select appropriate test profile, enforce maximum execution duration, and log the complete trigger chain.
- [ ] **APTS-SE-022** | SHOULD | List agents explicitly in RoE with authorized deployment targets and actions, require independent agent scope validation, maintain real-time agent inventory, implement agent kill switch, and apply same data handling requirements.
- [ ] **APTS-SE-023** | MUST | Credential and Secret Lifecycle Governance - Maintain real-time credential inventory scoped to individual engagements, classify secrets by provenance (client-provided, platform-issued, target-discovered), enforce reuse policies, prevent unauthorized delegation, track all usage and refresh events, revoke/destroy all secrets at engagement completion, and produce credential disposal reports.
- [ ] **APTS-SE-024** | MUST | For cloud-hosted targets, enumerate permitted cloud API actions, target namespaces/accounts, and prohibited operations; validate cloud-specific actions before execution using resource-level identifiers.
- [ ] **APTS-SE-025** | MUST | For API-centric applications, include endpoint inventories, permitted workflows, and token scope boundaries in scope definitions; enforce authorization boundaries during autonomous API traversal.
- [ ] **APTS-SE-026** | SHOULD | Monitor the agent's action distribution against declared or historical baselines per engagement class, route in-scope but out-of-distribution behavior to a staffed human review queue, log detections to the isolated audit trail, and never auto-terminate on this signal alone.

### Tier 3 (1 Requirement)

- [ ] **APTS-SE-021** | SHOULD | Detect overlapping scope across engagements, apply most restrictive constraints to shared targets, prevent cross-engagement scope expansion, correctly attribute findings, and log conflicts.

---

## 2. Safety Controls & Impact Management (SC) --- 20 Requirements

### Tier 1 (6 Requirements)

- [ ] **APTS-SC-001** | MUST | Impact Classification and CIA Scoring - Implement a multi-tier impact classification system assigning impact levels (critical/high/medium/low) to every pentest action before execution with CIA dimension scoring and action-to-impact mapping.
- [ ] **APTS-SC-004** | MUST | Rate Limiting, Bandwidth, and Payload Constraints - Implement per-host connection limits and rate limiting for all active pentest operations configurable per impact tier, with subnet/engagement-wide limits and payload constraints included.
- [ ] **APTS-SC-009** | MUST | Provide multiple independent kill switch mechanisms (operator-initiated, remote halt, automatic failsafe on control plane loss) with Phase 1 cessation within 5 seconds and Phase 2 graceful shutdown within 60 seconds.
- [ ] **APTS-SC-010** | MUST | Health Check Monitoring, Threshold Adjustment, and Automatic Halt - Continuously monitor target system health at configurable intervals (30s critical, 60s production, 5min non-production), dynamically adjust thresholds based on target recovery characteristics, and automatically halt on degradation exceeding 200% baseline or 3 consecutive health check failures.
- [ ] **APTS-SC-015** | MUST | Perform automated post-engagement integrity validation: file checksums, unexpected accounts, database record counts, configuration baselines, and unexpected processes.
- [ ] **APTS-SC-020** | MUST | Enforce the agent's tool and action allowlist in a component external to the model (gateway, policy engine, or broker) rather than through the system prompt; reject any tool invocation not on the allowlist and log the rejection to the isolated audit trail.

### Tier 2 (12 Requirements)

- [ ] **APTS-SC-002** | MUST | Adjust impact classifications for regulated industries: patient data access as Critical in healthcare, cardholder data as Critical in financial, availability impacts one tier higher in critical infrastructure.
- [ ] **APTS-SC-003** | SHOULD | Document at least 10 representative pentest scenarios with calculated impact classifications, CIA scores, and approval workflows covering password spraying, directory traversal, buffer overflow, and data exfiltration.
- [ ] **APTS-SC-005** | SHOULD | Detect and prevent cascading failures by verifying dependent system health before attacking upstream systems, automatically reducing intensity or halting on dependent system degradation.
- [ ] **APTS-SC-006** | MUST | Implement graduated escalation: informational/low auto-execute, medium requires standard approval, high requires elevated approval, critical requires senior approval plus live operator confirmation.
- [ ] **APTS-SC-007** | MUST | Cumulative Risk Scoring with Time-Based Decay - Track cumulative impact score across engagements considering impact severity, action frequency, duration, system criticality, and exposure with configurable time-based decay function, severity-level reset windows, documented methodology, and configurable escalation thresholds.
- [ ] **APTS-SC-011** | MUST | Define explicit termination conditions for target unavailability, sustained error rate exceedance, resource exhaustion, and unauthorized privilege escalation with detailed logging and automatic halt.
- [ ] **APTS-SC-012** | MUST | Implement circuit breaker logic suspending testing on sustained target degradation with configurable cooldown period and single-probe recovery verification.
- [ ] **APTS-SC-014** | MUST | Track state for all reversible actions with pre-action state capture, durable storage, step-by-step rollback procedures, and automated rollback scripts.
- [ ] **APTS-SC-016** | MUST | Preserve evidence (screenshots, logs, modified files, queries, escalation proofs) in tamper-evident storage before rollback, with idempotent, atomic, and verifiable automated cleanup.
- [ ] **APTS-SC-017** | MUST | Run external watchdog on independent infrastructure with separate credentials, periodic health checks, independent metric validation, and multi-channel operator notification within documented SLAs.
- [ ] **APTS-SC-018** | MUST | Execute automatic containment (network isolation, credential rotation, memory dump, log capture) with full safety control validation and post-incident report before testing resumes.
- [ ] **APTS-SC-019** | MUST | Run the agent runtime inside a kernel-enforced execution sandbox (namespaces, seccomp, AppArmor/SELinux, or hypervisor/gVisor/Kata isolation) whose filesystem, network, process, and credential boundaries the agent holds no credentials to move; document the sandbox technology and verify boundaries through probes under APTS-AL-028.

### Tier 3 (2 Requirements)

- [ ] **APTS-SC-008** | SHOULD | Store all threshold configurations in structured, schema-validated, human-readable format with startup validation and detailed error messages for invalid settings.
- [ ] **APTS-SC-013** | SHOULD | Enforce operator-specified maximum engagement duration with configurable time limits, operator extension capability within bounds, and advance warning before termination.

---

## 3. Human Oversight & Intervention (HO) --- 19 Requirements

### Tier 1 (13 Requirements)

- [ ] **APTS-HO-001** | MUST | Implement approval gates requiring explicit human authorization before executing exploitation, lateral movement, data access, persistence, configuration changes, or social engineering at L1/L2 autonomy levels.
- [ ] **APTS-HO-002** | MUST | Provide real-time dashboard with activity feed (updated every 5 seconds), system health visualization, scope boundaries map, approval queue with SLA tracking, and incident indicators.
- [ ] **APTS-HO-003** | MUST | Define maximum response time SLAs for approval decisions with default-safe behavior on timeout: DENY for exploitation/lateral movement (15 min), PAUSE for scope decisions (30 min), KILL+PRESERVE for legal triggers (immediate).
- [ ] **APTS-HO-004** | MUST | Maintain a documented Authority Delegation Matrix specifying which personnel can approve which actions at which autonomy levels, with cascading authority and dual control for CVSS >= 9.0.
- [ ] **APTS-HO-006** | MUST | Implement pause mechanism suspending all testing while preserving complete system state (sessions, credentials, reconnaissance, exploitation progress) with 4-hour automatic session termination timeout.
- [ ] **APTS-HO-007** | MUST | Allow operators to redirect scope, techniques, priority, or intensity mid-engagement without restarting or losing state, with explicit authorization logging.
- [ ] **APTS-HO-008** | MUST | Implement one-click kill switch with automatic state dump to forensically-sealed, encrypted storage within 60 seconds, preserving all sessions, credentials, findings, and logs with 1-year minimum retention.
- [ ] **APTS-HO-010** | MUST | Enforce mandatory human approval before irreversible actions: data access, persistence, configuration changes, evidence destruction, and lateral movement with no timeout auto-approval.
- [ ] **APTS-HO-011** | MUST | Immediately escalate unexpected findings: indicators of external breach, illegal content, critical zero-days, out-of-scope system access, compliance violations, and system stability threats.
- [ ] **APTS-HO-012** | MUST | Continuously monitor actual testing impact (availability, resource consumption, data integrity, security events) and escalate when thresholds are exceeded, pausing pending human decision.
- [ ] **APTS-HO-013** | MUST | Automatically escalate when confidence in scope boundary determination or target legitimacy falls below 75%, preventing autonomous continuation without human authorization.
- [ ] **APTS-HO-014** | MUST | Identify and immediately escalate potential legal/compliance violations: GDPR, CCPA, HIPAA, PCI-DSS data access, IP exposure, breach notification obligations, third-party access, and classified information.
- [ ] **APTS-HO-015** | MUST | Maintain real-time activity feed of all testing actions with multi-channel notifications: dashboard alerts, email with decision links, SMS with delivery confirmation, automated calls for CRITICAL alerts.

### Tier 2 (6 Requirements)

- [ ] **APTS-HO-005** | MUST | Record all approval decisions, escalations, and delegations in an immutable, cryptographically-signed, append-only audit log with 90-day minimum retention (6 years for high-risk).
- [ ] **APTS-HO-009** | MUST | Define kill switch authority across multiple operators with primary/secondary/manager/CISO hierarchy and formal authority transfer during operator handoffs.
- [ ] **APTS-HO-016** | SHOULD | Implement intelligent alert aggregation, suppression rules, and escalation thresholds to reduce alert volume while preserving critical signal.
- [ ] **APTS-HO-017** | MUST | Define stakeholder notification workflows for engagement status, finding summaries, critical notifications, escalation, completion, final report delivery, and post-engagement follow-up per documented SLAs.
- [ ] **APTS-HO-018** | MUST | Operator Qualification, Training, and Competency Governance - Ensure all operators meet minimum competency standards with formal certification appropriate to their assigned autonomy level and documented competency evidence, establish training curricula per autonomy level with learning objectives, hands-on exercises, and competency validation, implement annual refresher and incident response training for autonomous tool failures, require annual competency assessments with current certifications, remediation on failure, formal mentoring relationships, and documented succession plans.
- [ ] **APTS-HO-019** | SHOULD | Implement shift handoff procedures transferring engagement state/pending approvals/open escalations, enforce stale approval expiry, review suppression rules, and monitor operator response-time trends.

---

## 4. Graduated Autonomy Levels (AL) --- 28 Requirements

### Tier 1 (11 Requirements)

- [ ] **APTS-AL-001** | MUST | Execute only one isolated attack technique per operation without chaining or sequential decision-making at Level 1.
- [ ] **APTS-AL-002** | MUST | Require all target selection, technique selection, parameter configuration, and execution approval to originate from explicit human command.
- [ ] **APTS-AL-003** | MUST | Require operator to explicitly configure all technical parameters (timeouts, payloads, packet rates, risk levels) with confirmation before application.
- [ ] **APTS-AL-004** | MUST | Prohibit automated chaining between techniques; each subsequent action requires explicit human initiation.
- [ ] **APTS-AL-005** | MUST | Log all actions with 9 mandatory fields (timestamp, operator ID, operation type, target, parameters, initiation method, execution time, result, impact) in immutable structured format.
- [ ] **APTS-AL-006** | MUST | Validate target is in approved scope, not excluded, technique is permitted, engagement is active, and operator is authorized before executing any technique.
- [ ] **APTS-AL-008** | MUST | Maintain continuous operator connection with live action dashboard, approval gates for major decisions (phase transitions, exploitation, data access), and real-time communication.
- [ ] **APTS-AL-011** | MUST | Configure explicit escalation triggers for scope violations, exploitation proposals, data access, system impact, anomalies, and risk thresholds with immediate pause and operator alert.
- [ ] **APTS-AL-012** | MUST | Provide immediate termination within 5 seconds, pause without termination while maintaining state, graceful shutdown option, and clear stopped state indication.
- [ ] **APTS-AL-014** | MUST | Formally define boundaries (network, exploitation, data, impact, escalation) as specific unambiguous approved documents with technical enforcement and pre-engagement validation.
- [ ] **APTS-AL-016** | MUST | Continuously monitor boundary compliance at every action, detect breaches, immediately pause and alert operator, and perform health checks every 30 minutes.

### Tier 2 (9 Requirements)

- [ ] **APTS-AL-007** | MUST | At Level 2, allow multi-step technique chaining within a single attack phase without per-action approval, but require human approval for phase transitions.
- [ ] **APTS-AL-009** | SHOULD | Require tool to explicitly propose each next action with description, target, technique, rationale, estimated impact, and risk level, allowing operator to approve, modify, or reject.
- [ ] **APTS-AL-010** | MUST | Log every technique execution with step number, approval status, parameters, execution details, and decision points; log phase changes as distinct events.
- [ ] **APTS-AL-013** | MUST | At Level 3, allow complete attack chain execution across all phases without per-action approval within pre-established boundaries.
- [ ] **APTS-AL-015** | MUST | Define specific pre-approved action categories with applicability conditions, decision criteria, escalation triggers, and constraints; implement decision trees that default-deny on ambiguity.
- [ ] **APTS-AL-017** | MUST | Manage multi-target assessments with priority-based execution, concurrent operations within resource/impact constraints, per-target progress tracking, and proportional resource reallocation.
- [ ] **APTS-AL-018** | MUST | On security events during testing (IDS alert, intrusion detection, security controls triggered), immediately pause all operations, alert operator, preserve state, and await decision.
- [ ] **APTS-AL-025** | MUST | Conduct formal autonomy level assessment with documented criteria, approval signatures, defined progression path, minimum assessment duration, and annual reauthorization review.
- [ ] **APTS-AL-026** | MUST | On unintended impact incidents, conduct structured investigation with root cause analysis, impact assessment, level appropriateness review, control improvements, and downgrade decision if applicable.

### Tier 3 (8 Requirements)

- [ ] **APTS-AL-019** | SHOULD | At Level 4, autonomously manage multiple targets across extended periods, prioritizing by risk and organizational priorities, adapting strategy based on findings, and maintaining testing continuity.
- [ ] **APTS-AL-020** | SHOULD | Automatically include newly discovered targets meeting defined relationship criteria (same domain, network, business unit), apply scope expansion rules and risk profiles, and escalate uncertain cases.
- [ ] **APTS-AL-021** | SHOULD | Autonomously adapt testing strategy based on findings and reallocate time and network budget based on effort-reward analysis.
- [ ] **APTS-AL-022** | SHOULD | Continuously assess real-time risk scoring (severity, exposure, attack chain feasibility, sensitivity, exploitation speed) with cumulative tracking, impact prediction, and stakeholder-routed escalations.
- [ ] **APTS-AL-023** | SHOULD | Log every action, decision, external interaction, and system state change with immutable, cryptographically signed, indexed logs retained minimum 5 years for complete forensic reconstruction.
- [ ] **APTS-AL-024** | SHOULD | Conduct weekly status summaries, monthly deep compliance audits, quarterly strategic reviews, and annual authorization review for continuation.
- [ ] **APTS-AL-027** | SHOULD | Disable evasion features by default, require explicit engagement authorization to activate, disclose all active evasion techniques in reports, and assess evasive actions at equal or higher impact severity.
- [ ] **APTS-AL-028** | MUST | At L3 and L4, perform independent containment verification (quarterly at L3, monthly at L4, and after any material change) by probing sandbox filesystem, network, process, and credential-store boundaries and the action allowlist; record pass/fail/inconclusive; a failed probe is a containment incident under APTS-SC-018; verification MUST NOT be performed by the agent runtime itself.

---

## 5. Auditability & Reproducibility (AR) --- 20 Requirements

### Tier 1 (7 Requirements)

- [ ] **APTS-AR-001** | MUST | Structured Event Logging with Schema Validation - Log all network requests, responses, and system events with millisecond-precision timestamps in a schema-validated structured format with mandatory and conditional fields by event type, including event type, source, target, status code, duration, and correlation ID.
- [ ] **APTS-AR-002** | MUST | Log every phase transition with previous state, new state, triggering condition, timestamp, and authorization status before any new phase action occurs.
- [ ] **APTS-AR-004** | MUST | Decision Point Logging and Confidence Scoring - Log all autonomous decisions with timestamp, decision type, confidence score (0-1), at least 2 alternatives evaluated, selected action with justification, risk assessment, and fallback action, with confidence methodology included.
- [ ] **APTS-AR-006** | MUST | Decision Chain of Reasoning and Alternative Evaluation - Document the complete chain of reasoning for every multi-step attack sequence including discovery, decision points, alternative paths with feasibility/resource/outcome assessments, rejection rationale, executed actions, outcomes, and impact assessment.
- [ ] **APTS-AR-010** | MUST | Hash all evidence using SHA-256 minimum covering request/response data, files/artifacts, vulnerability evidence, and forensic data, storing hashes with evidence and verifying before use.
- [ ] **APTS-AR-012** | MUST | Store logs in append-only format where each entry includes SHA-256 hash of previous entry enabling tamper detection by recomputing the chain.
- [ ] **APTS-AR-015** | MUST | Classify all evidence by sensitivity level (PUBLIC/STANDARD/CONFIDENTIAL/RESTRICTED) at capture time, encrypt CONFIDENTIAL and RESTRICTED evidence at-rest, enforce classification-based access controls, and apply retention/deletion procedures per classification.

### Tier 2 (12 Requirements)

- [ ] **APTS-AR-003** | MUST | Log resource utilization metrics (network, system, test impact) for every extended operation exceeding 1 second with documented per-engagement thresholds.
- [ ] **APTS-AR-005** | MUST | Retain logs minimum 1 year post-engagement (longer per regulation), encrypt at-rest with AES-256, maintain geographically distributed backups, use immutable append-only format, and implement hash chain verification.
- [ ] **APTS-AR-007** | MUST | Document formal risk assessment before executing any medium+ risk action evaluating target, detection, engagement, and organizational risks with specific mitigations.
- [ ] **APTS-AR-008** | MUST | Include all context elements in decision logs: prior findings, scope constraints, target state, environmental factors, time factors, resource state, and regulatory constraints with verifiable sources.
- [ ] **APTS-AR-009** | MUST | Generate transparency reports at regular intervals (minimum daily for engagements exceeding 3 days) containing summary statistics, decision quality metrics, evidence summary, reproducibility status, and audit compliance.
- [ ] **APTS-AR-011** | MUST | Maintain complete chain of custody for all evidence from creation to disposition documenting acquisition, handling, storage, access, transfer, archival, and disposal with hash verification at each transfer.
- [ ] **APTS-AR-014** | MUST | Capture screenshots as lossless PNG with metadata (timestamp, resolution, source system), preserve packet captures with full headers, hash all captures with SHA-256, redact sensitive data unless authorized, and document capture tool provenance.
- [ ] **APTS-AR-016** | MUST | Publish SHA-256 hashes of all platform executables, maintain SBOM in SPDX/CycloneDX format updated within 48 hours of changes, detect configuration drift, and disclose CVEs >= CVSS 7.0 within 72 hours.
- [ ] **APTS-AR-017** | MUST | Conduct regression testing of all safety-critical controls after platform updates, maintain test suite covering scope enforcement and kill switch logic, and prevent updates shipping without passing full suite.
- [ ] **APTS-AR-018** | MUST | Classify updates as behavior-affecting or not, notify customers before deploying behavior-affecting updates with change summary/impact/regression results/rollback procedure, and allow documented deferral.
- [ ] **APTS-AR-019** | MUST | Track AI/ML model versions with unique identifiers and behavioral fingerprints, run behavioral comparison on updates using standardized safety-critical test sets, implement drift detection before each engagement and after API changes, and block affected paths if drift detected.
- [ ] **APTS-AR-020** | MUST | Write the authoritative audit trail to append-only infrastructure the agent runtime has no credentials to reach (WORM storage, external SIEM, or dedicated log service), separate from any storage the agent can read or modify; verify isolation via tabletop review and periodic access-attempt probes.

### Tier 3 (1 Requirement)

- [ ] **APTS-AR-013** | SHOULD | Integrate trusted timestamps from RFC 3161-compliant timestamp authorities for critical evidence and findings, with ±1 second accuracy, TSA certificate chain verification, and timestamp tokens embedded with evidence.

---

## 6. Manipulation Resistance (MR) --- 23 Requirements

### Tier 1 (13 Requirements)

- [ ] **APTS-MR-001** | MUST | Implement defense-in-depth controls separating operator instructions from target-side content through cryptographic signing, sandboxing, and continuous monitoring.
- [ ] **APTS-MR-002** | MUST | Validate and sanitize all target responses before LLM processing, removing or flagging instruction-like patterns, authority claims, and malicious content.
- [ ] **APTS-MR-003** | MUST | Treat error messages exclusively as data for vulnerability analysis, not as instructions; detect error-based social engineering and maintain consistent behavior regardless of error content.
- [ ] **APTS-MR-004** | MUST | Parse configuration files for vulnerability information only, flag (not execute) embedded instructions and scope changes, and block credential injection attempts.
- [ ] **APTS-MR-005** | MUST | Identify and reject all authority claims from target content regardless of legitimacy appearance, log with context, and alert operators while maintaining original permissions.
- [ ] **APTS-MR-007** | MUST | Validate all HTTP, DNS, and logical redirects against scope before following; detect and prevent redirect chains and loops; block and alert on out-of-scope redirects.
- [ ] **APTS-MR-008** | MUST | Validate DNS resolution results including A records and CNAME aliases against scope; detect DNS poisoning and rebinding attacks; validate all connections before establishing.
- [ ] **APTS-MR-009** | MUST | Validate URLs and IPs in target responses against scope before connecting; restrict localhost and private IP access; reject dangerous protocols (file://, gopher://, ftp://); detect SSRF chains.
- [ ] **APTS-MR-010** | MUST | Detect and resist linguistic manipulation in target content appealing to completeness, logic, authority, or urgency; maintain immutable scope; alert operators to social engineering attempts.
- [ ] **APTS-MR-011** | MUST | Prevent use of secondary communication channels (email, webhooks, DNS TXT, callbacks) as instruction channels; require explicit operator approval for any out-of-band communication.
- [ ] **APTS-MR-012** | MUST | Protect scope through cryptographic signing, write-protection in memory, and integrity monitoring; make scope read-only after initialization; log and escalate all modification attempts.
- [ ] **APTS-MR-018** | MUST | Enforce architectural separation between trusted system instructions and untrusted target data; sanitize all target data before AI/ML processing; validate AI decisions through a non-AI rules engine before execution.
- [ ] **APTS-MR-019** | MUST | Encrypt discovered credentials immediately in dedicated vault, prevent plaintext appearance in logs/reports/model context, require MFA for decrypted access, and destroy after engagement.

### Tier 2 (9 Requirements)

- [ ] **APTS-MR-006** | SHOULD | Enforce immutable decision boundaries defined by operators before testing starts; escalate boundary violations, halt on ambiguity, and protect boundary state as read-only.
- [ ] **APTS-MR-013** | MUST | Test LLM models against adversarial examples designed to cause misclassification; implement detection for false positives, false negatives, and severity downgrading attempts.
- [ ] **APTS-MR-014** | MUST | Implement multi-level timeout enforcement (connection, read, request, test suite); detect tarpit services; enforce content size limits; detect infinite pagination; monitor and alert on rapid memory growth.
- [ ] **APTS-MR-015** | MUST | Do not attempt authentication without operator approval; flag suspicious authentication endpoints; escalate uncertain cases; document detection heuristics.
- [ ] **APTS-MR-016** | MUST | Detect and respect rate limiting, browser detection, and CAPTCHA/JavaScript challenges without bypass attempts; alert operator and halt gracefully.
- [ ] **APTS-MR-017** | MUST | Establish baseline response patterns before active testing; detect and classify deviations as anomalies; alert operator with context; gather data for review rather than acting autonomously.
- [ ] **APTS-MR-020** | MUST | Adversarial Validation and Resilience Testing of Safety Controls - Conduct adversarial testing of safety controls annually and after major updates with at least 3 attack scenarios per control using independent personnel, test kill switch termination within required timeframes under resistance, test scope enforcement against known bypasses, and test escalation/alerting reliability under elevated load.
- [ ] **APTS-MR-022** | MUST | Enforce trust boundaries between AI/ML model components in pipelines; validate and sanitize outputs between components; document pipeline architecture and integrity controls.
- [ ] **APTS-MR-023** | MUST | Name the agent runtime as an untrusted component in the platform threat model; document threats of agent-originated scope widening, allowlist bypass, audit-trail tampering, and credential reach; trace each to the architectural control that contains it (APTS-SC-019, APTS-SC-020, APTS-AR-020, APTS-MR-012); review at least annually and after material foundation model change.

### Tier 3 (1 Requirement)

- [ ] **APTS-MR-021** | MUST | Test multi-tenant platforms for cross-tenant data access through parameter manipulation, SQL injection, shared cache poisoning, log file access, and file system traversal; verify error message isolation.

---

## 7. Third-Party & Supply Chain Trust (TP) --- 22 Requirements

### Tier 1 (10 Requirements)

- [ ] **APTS-TP-001** | MUST | Third-Party Provider Selection and Vetting - Establish documented vetting process assessing security posture, data protection, service reliability, contractual terms, and compliance certifications for all external AI/LLM providers, establish documented evaluation criteria for all SaaS platforms, verify compliance certifications, assess data handling and encryption, and document approval before use.
- [ ] **APTS-TP-003** | MUST | Use strong authentication with secure credential storage, implement API key rotation, enforce minimum TLS 1.2 (TLS 1.3 preferred) with certificate validation, and use mutual TLS where supported.
- [ ] **APTS-TP-005** | MUST | Provider Incident Response, Breach Notification, and Mid-Engagement Compromise - Establish incident response procedures with provider contracts specifying breach notification timelines per regulatory requirements, including mid-engagement compromise procedures for rapid containment, continuation assessment, customer notification, and forensic evidence preservation.
- [ ] **APTS-TP-006** | MUST | Dependency Inventory, Risk Assessment, and Supply Chain Verification - Maintain complete SBOM with version numbers and vulnerabilities, perform risk assessment per dependency criticality, continuously monitor with documented update strategies, verify package signatures and checksums, monitor for vulnerabilities, abandoned packages, typosquatting, and dependency confusion, and validate updates in non-production before deployment.
- [ ] **APTS-TP-008** | MUST | Implement cloud hardening: least privilege IAM, AES-256 minimum encryption at rest, network security groups/ACLs, and regular compliance scanning with remediation.
- [ ] **APTS-TP-012** | MUST | Establish four-level classification framework (RESTRICTED/CONFIDENTIAL/INTERNAL/PUBLIC) defining data types, encryption requirements, transmission permissions, access controls, and retention per level.
- [ ] **APTS-TP-013** | MUST | Implement automated discovery of credentials/PII/payment data/health information, isolate in secure vaults with audit logging, report without disclosing actual values, and notify clients immediately.
- [ ] **APTS-TP-014** | MUST | Enforce TLS 1.2+ for transit, AES-256-GCM for data at rest, centralized key management with annual rotation (90 days for sensitive), and prohibit deprecated algorithms (DES, RC4, MD5, SHA-1, RSA-1024).
- [ ] **APTS-TP-018** | MUST | Detect cross-engagement data leaks via monitoring/audit/penetration testing, classify severity, notify affected customers with exposure details/timeline/remediation, and conduct forensic investigation.
- [ ] **APTS-TP-021** | MUST | Disclose the foundation model powering the agent runtime (provider, family, version or identifier, release date, and any operator fine-tunes or adapters) together with a documented capability baseline; refresh the disclosure whenever the model changes and include it in the conformance claim.

### Tier 2 (11 Requirements)

- [ ] **APTS-TP-002** | MUST | Implement explicit version identifiers for all AI models, specify exact versions in deployment (not "latest"), follow formal change management with testing, and enable rollback.
- [ ] **APTS-TP-004** | MUST | Establish availability requirements (minimum 99.5% SLA), implement continuous monitoring with alerts, document and test failover procedures, and identify fallback providers.
- [ ] **APTS-TP-009** | MUST | Establish incident response with RTO/RPO targets, perform regular backups with verified restore capability, and test disaster recovery regularly with documented results.
- [ ] **APTS-TP-010** | MUST | Select vulnerability feeds assessing CVE coverage/update frequency/data quality/SLA, verify cryptographic signatures, test quality before production, and track modifications.
- [ ] **APTS-TP-011** | SHOULD | Validate feeds against discovered services with confidence scoring, maintain test datasets measuring false negatives, document quality targets, and establish severity-based incident procedures.
- [ ] **APTS-TP-015** | MUST | Document retention periods per classification with justification, maintain inventory with expiration dates and 30-day automated reminders, use appropriate deletion methods, and verify with failed recovery tests.
- [ ] **APTS-TP-017** | MUST | Deploy isolated execution environment per engagement (container/VM/namespace) with separate storage/network/credentials, engagement-scoped encryption keys and credential vaults, segregated logs, and monthly penetration tests.
- [ ] **APTS-TP-019** | MUST | Document model source/supplier, training data categories, fine-tuning history, and verify models not retrained on other customers' data without disclosure and consent.
- [ ] **APTS-TP-020** | SHOULD | Inventory all persistent state across engagements (embeddings, RAG indexes, cached context), enforce cross-engagement isolation, enable operator inspection/export/purge, and audit decision influence.
- [ ] **APTS-TP-007** | SHOULD | Document data residency requirements and verify provider configurations enforce jurisdictional constraints on data storage and transfers.
- [ ] **APTS-TP-022** | MUST | Re-attest scope enforcement (SE), safety controls (SC), manipulation resistance (MR), and graduated autonomy (AL) whenever the foundation model undergoes a material change (provider change, family change, generation boundary cross, fine-tune or adapter change, or documented capability shift); block promotion of the new model to production engagements until the re-attestation workpaper is complete.

### Tier 3 (1 Requirement)

- [ ] **APTS-TP-016** | MUST | Generate data destruction certificates documenting destroyed data, methods, timestamps, cryptographic verification, and independent verification of inaccessibility; support customer-initiated destruction within SLA.

---

## 8. Reporting (RP) --- 15 Requirements

### Tier 1 (3 Requirements)

- [ ] **APTS-RP-006** | MUST | Disclose the platform's false positive rate methodology and measurements in every report, including overall and engagement-specific rates, flagging if rates exceed published targets.
- [ ] **APTS-RP-008** | MUST | Include a Coverage Matrix identifying specific vulnerability classes tested, excluded, and partially covered, mapped to CWE categories with detection methods documented.
- [ ] **APTS-RP-011** | MUST | Include an executive summary for non-technical stakeholders with overall risk posture, severity breakdown, key findings with business impact, scope coverage percentage, and clear language.

### Tier 2 (10 Requirements)

- [ ] **APTS-RP-001** | MUST | Include raw technical evidence (packet captures, HTTP pairs, command output, screenshots, file contents) for every finding, clearly separated from AI-generated summaries, flagging findings without raw evidence as "Unverified."
- [ ] **APTS-RP-002** | MUST | Finding Verification and Human Review Pipeline - Attempt automated reproduction of every Critical and High finding before final report, logging all attempts with timestamps and marking findings as "Confirmed" or "Unconfirmed," with re-verification and human review included.
- [ ] **APTS-RP-003** | MUST | Calculate confidence scores (0-100%) for each finding using documented, measurable factors (reproductions, evidence quality, attack path complexity) with a consistent auditable formula.
- [ ] **APTS-RP-004** | MUST | Document complete provenance chain for each finding tracing discovery to specific scanner execution with SHA-256 cryptographic hashing for tamper prevention.
- [ ] **APTS-RP-005** | MUST | Cryptographically bind all finding evidence to discovery events with SHA-256 hashes, timestamps, and unique identifiers; provide alternative artifacts for encrypted channel findings.
- [ ] **APTS-RP-009** | MUST | Document and disclose false negative rate measurement methodology with aggregate rates per vulnerability class and per-engagement risk assessments; state if rates not yet established.
- [ ] **APTS-RP-012** | MUST | Provide remediation guidance for each finding with recommended fixes, estimated effort (quick win, moderate, significant), risk-based priority, and explicit disclosure when guidance is unavailable.
- [ ] **APTS-RP-013** | MUST | Disclose engagement timeline compliance: agreed compared to actual dates, interruptions with causes/durations, scope completion percentage, and explanation of untested areas.
- [ ] **APTS-RP-014** | SHOULD | For recurring engagements, include trend analysis categorizing findings as new, resolved, or persistent with overall risk posture trend assessment supported by comparative data.
- [ ] **APTS-RP-015** | SHOULD | For downstream system integrations, enforce controls maintaining evidence links, severity classifications, and remediation guidance; prevent cross-customer leakage; redact sensitive data before export.

### Tier 3 (2 Requirements)

- [ ] **APTS-RP-007** | SHOULD | Platform supports independent reproduction of Critical findings with documented evidence, defined reproduction success threshold, and per-finding status tracking.
- [ ] **APTS-RP-010** | SHOULD | Maintain at least 3 benchmark environments with known vulnerabilities, conduct quarterly benchmark runs, and disclose detection rates per vulnerability class with gap analysis.

---

## Summary

| Domain | Tier 1 | Tier 2 | Tier 3 | Total |
|--------|--------|--------|--------|-------|
| Scope Enforcement (SE) | 9 | 16 | 1 | 26 |
| Safety Controls (SC) | 6 | 12 | 2 | 20 |
| Human Oversight (HO) | 13 | 6 | 0 | 19 |
| Graduated Autonomy (AL) | 11 | 9 | 8 | 28 |
| Auditability (AR) | 7 | 12 | 1 | 20 |
| Manipulation Resistance (MR) | 13 | 9 | 1 | 23 |
| Supply Chain Trust (TP) | 10 | 11 | 1 | 22 |
| Reporting (RP) | 3 | 10 | 2 | 15 |
| **Total** | **72** | **85** | **16** | **173** |

Tier 1 + Tier 2 + Tier 3 = 173 tier-required requirements. Advisory practices are documented separately in the [Advisory Requirements appendix](Advisory_Requirements.md) and do not count toward any tier.
