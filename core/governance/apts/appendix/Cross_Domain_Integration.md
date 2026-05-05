# Cross-Domain Integration Matrix

Informative Appendix (non-normative)

APTS domains do not operate in isolation. Events in one domain frequently trigger requirements in others. See [Testing Phase Mapping](Testing_Phase_Mapping.md) for how requirements align with pentesting lifecycle phases.

## Integration Map and Domain Dependencies

The matrix below identifies where an event or action in one domain (row) triggers or depends on requirements in another domain (column). The "What Happens" column describes the specific control activities or checks that the triggered requirements demand, making it clear what must be done rather than just referencing requirement IDs.

| Triggering Event | Source | What Happens | Target Requirements |
|-----------------|--------|--------------|---------------------|
| Kill switch activated | SC-009 | All ongoing test activity ceases within 5 seconds; all spawned processes terminate; all network connections close; system state preserved for forensic investigation. | AR-001 |
| Kill switch activated | SC-009 | Operators notified immediately via multiple independent channels (email, SMS, messaging) with details of what triggered the halt and actions taken. | HO-015 |
| Kill switch activated | SC-009 | All test artifacts, logs, and findings evidence captured and stored in immutable, tamper-evident storage before any system cleanup or shutdown occurs. | SC-016 |
| Kill switch activated | SC-009 | Platform isolated from customer networks; credentials rotated; all active sessions terminated; memory dumps and logs preserved on secure system. | SC-018 |
| Kill switch activated | SC-009 | All authentication credentials (API keys, SSH keys, test account passwords) used during testing securely erased using cryptographic methods or secure overwriting. | SE-023 |
| Kill switch activated | SC-009 | Evidence chain cryptographically validated and preserved with proof of integrity; forensic artifacts retained per engagement data retention policy. | SC-016 |
| Scope boundary violated | SE-006, SE-007 | Human operator immediately contacted for decision on containment; unauthorized target analysis frozen pending approval; violation details escalated to security lead. | HO-011 |
| Scope boundary violated | SE-006, SE-007 | Detailed audit log entry created capturing violation timestamp, target attempted, operator authorization, scope definition violated, and system response taken. | AR-001, SE-015 |
| Scope boundary violated | SE-006, SE-007 | If pre-configured, platform automatically halts all testing activities for the affected target until operator explicitly authorizes resumption. | SC-011 |
| Impact threshold exceeded | SC-007, SC-010 | Health checks show target degradation exceeding configured thresholds; escalation workflow activates based on severity (medium escalates to approval, high requires elevated approval). | HO-012 |
| Impact threshold exceeded | SC-007, SC-010 | Testing against affected target suspended; single probe request sent after cooldown period to determine if system recovered; resumption dependent on successful probe. | SC-012 |
| Impact threshold exceeded | SC-007, SC-010 | Audit trail records cumulative impact score calculations, triggering event, thresholds evaluated, escalation decision made, and timestamp of impact assessment. | AR-001 |
| Unexpected finding discovered | HO-011 | Complete forensic chain captured: raw evidence artifacts, discovery timestamp, reproduction steps, tool that discovered it, and cryptographic binding to audit logs. | AR-003, AR-004 |
| Unexpected finding discovered | HO-011 | Legal and compliance teams notified if finding indicates breach, unauthorized access, sensitive data exposure, or regulatory violation per incident escalation policy. | HO-014 |
| Unexpected finding discovered | HO-011 | Finding included in final engagement report with confidence score, evidence links, remediation guidance, and cross-referenced to all supporting audit logs. | RP-003, RP-004 |
| Autonomy level assessed | AL-025 | Approval gate thresholds, rate limits, and safety control strictness adjusted based on autonomy level (lower autonomy = stricter controls, more human gates). | SC-006 |
| Autonomy level assessed | AL-025 | Operator approval requirements and decision windows configured per autonomy level (low impact auto-approve; high impact require senior approval; critical require live confirmation). | HO-001, HO-004 |
| Autonomy level assessed | AL-025 | Health check intervals and anomaly detection sensitivity increased for lower autonomy levels; alert thresholds tightened proportionally to reduce autonomous decision scope. | HO-002, SC-010 |
| Prompt injection detected | MR-001, MR-002 | Injection attempt logged with full target content context, detected pattern, attempted override goal, and timestamp; operator alerted immediately. | AR-001 |
| Prompt injection detected | MR-001, MR-002 | Manipulation attempt escalated to human analyst; affected action chain halted pending manual review and decision on whether to retry or abandon. | HO-011 |
| Prompt injection detected | MR-001, MR-002 | Testing against affected target automatically paused; platform halts all new actions until operator explicitly authorizes resumption after reviewing the injection attempt. | SC-011 |
| AI model change detected | AR-019, TP-001 | Manipulation resistance controls re-evaluated against new model version; prompt injection defenses tested; behavior changes assessed for safety impact. | MR-005, MR-006 |
| AI model change detected | AR-019, TP-001 | Platform documentation reviewed for model version references; deployment procedures evaluated to ensure backward compatibility or explicit upgrade authorization. | Introduction |
| AI model change detected | AR-019, TP-001 | Model version change logged with timestamp, prior version, new version, trigger for change, and any re-assessment results. | AR-001 |
| Foundation model materially changed | TP-022 | SE, SC, MR, and AL are re-attested against the new model; promotion to production engagements is blocked until the re-attestation workpaper is complete; conformance claim (TP-021) is refreshed with the new disclosure. | SE, SC, MR, AL, TP-021 |
| L3 or L4 containment probe fails | AL-028 | Failed probe is treated as a containment incident under SC-018; operators notified under HO-011; threat model (MR-023) reviewed for the bypass path; engagement halted until probes pass. | SC-018, HO-011, MR-023 |
| Engagement starts | SE-001 | File checksums, database record counts, active user/service account lists, network baseline traffic, and system configurations captured for later integrity validation. | SC-015 |
| Engagement starts | SE-001 | Audit logging infrastructure initialized; cryptographic signing enabled; log retention policy applied; operator identity and credentials verified before any action. | AR-001 |
| Engagement starts | SE-001 | Rules of Engagement (RoE) parsed and validated; all scope boundaries, temporal windows, target criticality, and action restrictions validated before test begins. | SE-023, SE-006 |
| Engagement starts | SE-001 | Operator identity verified; qualifications audited (certifications, training completed, background checks); audit trail records operator accountability information. | HO-018 |
| Engagement ends | SE-004, SC-013 | All reversible actions (created accounts, modified files, configurations changed) rolled back automatically; rollback completion verified against baseline. | SC-014 |
| Engagement ends | SE-004, SC-013 | System integrity validation executed; current state compared against baseline for file checksums, account inventory, database record counts, and process lists. | SC-015 |
| Engagement ends | SE-004, SC-013 | All authentication credentials created or obtained during testing securely deleted; credential rotation completed; access logs reviewed for misuse. | SE-023 |
| Engagement ends | SE-004, SC-013 | Findings collated; evidence integrity verified; confidence scores calculated; remediation guidance provided; report generated per Reporting domain requirements. | RP-003 |
| Engagement ends | SE-004, SC-013 | Evidence artifacts, audit logs, test outputs, and engagement artifacts stored in write-once, immutable storage with cryptographic verification and retention per policy. | SC-016 |
| Credential discovered during test | SE-023 | Discovered credential classified by source and sensitivity (system credential, user password, or API key); storage location and exposure risk assessed. | SE-023 |
| Credential discovered during test | SE-023 | Discovery logged with timestamp, credential type, exposure location, and assessment of who/what could have accessed it during testing. | AR-001 |
| Credential discovered during test | SE-023 | Credential included in findings report as RESTRICTED finding with values redacted (for example, "API key ending in ...abc123"); exposure impact and remediation guidance provided. | RP-003 |
| Third-party provider incident | TP-005 | Customer notified immediately per documented timeline (typically 24-48 hours); notification includes incident description, data potentially affected, and remediation status. | HO-017 |
| Third-party provider incident | TP-005 | Impact on active engagements assessed; determination made whether to continue testing, pause temporarily, or halt pending provider remediation and security validation. | SC-010 |
| Third-party provider incident | TP-005 | Incident response recorded in audit trail with discovery timestamp, provider identification, systems affected, impact assessment, containment actions, and customer notifications. | AR-001 |
| Finding validated | RP-001, RP-002 | Confidence score calculated using objective factors: successful reproduction count, evidence quality grade, attack complexity rating, and applied to determination of finding inclusion. | RP-003 |
| Finding validated | RP-001, RP-002 | Finding compared against findings from previous engagements (if recurring) to identify if this is new, persistent unresolved, or regression of previously-fixed issue. | SE-018 |
| Finding validated | RP-001, RP-002 | Finding included in coverage metrics tracking which vulnerability classes were tested, which were detected, detection success rate per class, and overall testing thoroughness. | RP-005 |

## Domain Dependency Summary

- **Auditability (AR)**: The foundational domain referenced by every other domain. Every significant event (kill switch activation, scope violation, impact threshold breach, credential discovery) requires logging with timestamp and context. All requirements across SC, SE, HO, AL, MR, TP, and RP domains include explicit audit trail obligations. Without functioning Auditability, no other domain can prove its safety controls were operational or that requirements were met.

- **Safety Controls (SC) and Human Oversight (HO)**: Tightly coupled pair forming the engagement safety backbone. SC defines automated impact controls (rate limiting, health monitoring, circuit breakers, hard stops) while HO layers in human review gates and escalation workflows. When SC detects impact threshold breach (SC-007, SC-010), HO immediately engages for severity-appropriate decision-making. When kill switch activates, both domains execute in parallel: SC halts actions and preserves state; HO notifies operators.

- **Scope Enforcement (SE)**: Validates authorization before every testing action. Any domain that initiates network actions, creates test accounts, modifies systems, or accesses credentials depends on SE for pre-action validation (SE-006 pre-action scope checks). SE-001 Rules of Engagement specification gates engagement initialization; SE-023 credential discovery handling gates findings inclusion. SE failures propagate: scope boundary violation triggers SC-011 automatic halt, HO-011 escalation, and AR-001 logging.

- **Graduated Autonomy (AL)**: Influences SC, HO, and AR behavior by setting the operational mode. Autonomy level assessment (AL-025) directly determines: approval gate strictness in SC-006 (low autonomy = stricter approval chains; high autonomy = more autonomous decisions), human review frequency in HO-002 (low autonomy triggers alerts; high autonomy allows more autonomous action), and audit logging intensity in AR (more detailed logging for lower autonomy). Example: Level 1 autonomy requires human approval for all High/Critical findings before execution; Level 4 allows autonomous execution with 4-hour human review window post-discovery.

- **Manipulation Resistance (MR)**: Defends against prompt injection and scope widening attacks originating from target system responses. Intersects SC (when prompt injection detected, SC-011 halts affected action chain), HO (MR-001 detected injection escalated to HO-011 human review), and AR (MR-001 injection attempt logged with full context). Model change detection (TP-001) triggers MR re-assessment (MR-005, MR-006) to verify defenses remain effective.

- **Supply Chain Trust (TP)**: Feeds critical dependencies into AR (TP-001 AI provider changes logged), MR (TP-001 model integrity validated), and HO (TP-005 provider incidents escalated to HO-017 customer notification). Data classification (TP-012), sensitive data discovery (TP-013), and multi-tenancy and engagement isolation (TP-017) establish baseline trust in the engagement data itself. Credential handling (TP-013 sensitive data discovery) and data retention (TP-015, TP-016) ensure test artifacts don't leak cross-engagement.

- **Reporting (RP)**: Consumes validated findings and evidence from all domains to produce engagement deliverables. Reporting depends on AR for audit trail traceability (RP-004 provenance chain links to AR audit logs), on SC/HO for impact classification (RP-003 confidence scores incorporate SC impact assessment), on SE for scope coverage disclosure (RP-008 coverage matrix reflects actual SE-configured test profile), and on MR for manipulation detection logging (RP evidence marked Unverified if MR attempted injection during discovery). RP also validates across cycles: RP-001, RP-002 finding validation re-attempts reproduction before inclusion.

## Suggested Implementation Sequence

The following sequence reflects a practical ordering based on the dependency patterns identified above. Each phase builds on working foundations from earlier phases.

### Phase 1: Auditability Foundation (AR)

**Why first:** All other domains require functional audit logging to prove their requirements are met. Scope violations must be logged, safety control activations must be auditable, and escalation decisions must be traceable. Without AR infrastructure in place, you cannot verify that SC, SE, HO, and other domains are actually operational. Implement comprehensive audit trail capture (AR-001 event logging, AR-003 evidence chain, AR-004 evidence integrity) before testing begins. This enables all downstream domains to meet their logging obligations.

### Phase 2: Scope Enforcement and Safety Controls (SE + SC in parallel)

**Why together:** These form the essential safety boundary. SE-001 through SE-007 define and validate the testing scope before any action executes. SC-006 through SC-012 implement the graduated impact control layers (approval gates, rate limits, health monitoring, circuit breakers). SE gates which targets are authorized; SC gates how aggressively they're tested. Example: SE-005 classifies an asset as "Critical"; SC-006 escalation workflow then restricts action types allowed on that asset. Implement in parallel because they reinforce each other: SE scope violations trigger SC-011 automatic halt; SC health check failures may trigger SE-006 scope re-validation.

### Phase 3: Human Oversight (HO)

**Why after SC/SE:** HO provides decision authority for escalated situations detected by SC (impact threshold exceeded) and SE (scope boundary violated). HO-001 approval gates and HO-004 decision windows only make sense when SC and SE are generating escalation triggers. HO also depends on AL autonomy level assessment (HO-001, HO-004 configuration varies by autonomy level). Implement escalation procedures (HO-011 human review, HO-012 threshold escalation), approval chains (HO-001, HO-004 per autonomy level), and notification infrastructure (HO-015 multi-channel alerts, HO-017 provider incident notification).

### Phase 4: Graduated Autonomy (AL)

**Why fourth:** AL assessment (AL-025) determines the knobs for SC, HO, and AR behavior. It makes sense to understand what you're tuning (SC impact controls, HO approval thresholds, AR logging detail) before making autonomy-based adjustments. AL configuration sets monitoring intensity (HO-002 alert frequency), approval strictness (HO-001, HO-004 approval chains), and logging verbosity (AR detail levels). Example: assigning Level 1 autonomy means tightening SC-006 escalation thresholds, adding HO-002 real-time monitoring, and increasing AR audit detail.

### Phase 5: Manipulation Resistance (MR)

**Why fifth:** MR defends against adversarial inputs from target systems attempting to override operator instructions or scope boundaries. This is critical early but benefits from having SE scope validation already working (to define the "true" scope that MR must protect against). MR-001 instruction boundary enforcement and MR-002 response sanitization require clear definition of what constitutes "legitimate tool instruction" (from operator) compared to "target-side content" (potentially adversarial). Implement defense-in-depth: input sanitization (MR-002), instruction cryptographic verification (MR-001), and operator visibility into manipulation attempts (AR-001 logged, HO-011 escalated).

### Phase 6: Supply Chain Trust (TP)

**Why sixth:** TP establishes trust in external dependencies (AI providers, cloud services, vulnerability feeds) used by other domains. While important, it's best addressed once you have baseline safety controls working. TP-001 AI provider vetting, TP-006 dependency inventory (SBOM), and TP-012 data classification framework should be in place before extensively using external services in your testing operations. TP-017 multi-tenancy and engagement isolation is critical if operating multi-tenant; TP-013, TP-015 sensitive data handling must be operational before engaging in any testing.

### Phase 7: Reporting (RP)

**Why last:** RP aggregates validated findings and evidence from all upstream domains. RP-001, RP-002 finding validation re-attempts reproduction before reporting. RP-004 provenance chain links findings back to AR audit logs (requires AR working). RP-003 confidence scoring incorporates SC impact assessment and MR manipulation evidence. RP-008 coverage matrix reflects actual SE scope configuration. Reporting produces the engagement deliverable but depends on stable functioning of all other domains. Example report flow: SC detects finding, MR validates it's not injection-influenced, AR logs discovery with evidence chain, HO approves inclusion (if critical), RP includes with full provenance and confidence score.

### Cross-Domain Validation Points

After completing each phase, validate cross-domain integration:
- After AR + SE + SC: Verify scope violation triggers SC-011 halt and AR-001 logging.
- After HO addition: Verify SC impact threshold escalates to HO-011 human review with documented decision.
- After AL assignment: Verify autonomy level changes SC-006 approval thresholds and HO-002 monitoring intensity.
- After MR addition: Inject test prompt attempts; verify MR-001 detection, AR-001 logging, HO-011 escalation all function.
- After TP implementation: Verify TP-012 data classification applied to engagement data; TP-017 multi-tenancy and engagement isolation tested if applicable.
- After RP deployment: Generate test engagement report; verify all findings include RP-004 provenance, confidence scores, AR audit linkage, and MR manipulation status.

---

## Failure Mode Analysis

When a domain's requirements fail, other domains are affected. This table identifies critical failure cascades:

| Failed Requirement | Impact on Other Domains | Mitigation |
|-------------------|------------------------|------------|
| AR-001 (Structured Logging) fails | All domains lose audit trail. SC, HO, AL actions become unverifiable. Compliance evidence is lost. | Halt testing immediately. Logging is foundational; no domain can operate without it. |
| SC-009 (Kill Switch) fails | HO-008 (state dump) may still operate independently. Platform cannot be stopped safely. | Activate network-level circuit breaker (SC-012) as backup. Disconnect platform from network if SC-012 also fails. |
| SE-006 (Pre-Action Validation) fails | All testing actions proceed without scope verification. Risk of out-of-scope impact. | SC-010 health monitoring may detect anomalous target access. Halt immediately upon detection. |
| HO-015 (Notifications) fails | Operators unaware of escalations, incidents, and status changes. Testing continues without oversight. | SC-017 (external watchdog) provides independent monitoring. Watchdog MUST alert via independent channel. |
| TP-014 (Encryption) fails | Customer data, credentials, and evidence at risk of exposure. | Halt testing. Invoke TP-A01 (breach notification, Advisory) if unencrypted data was transmitted or stored. |
| SC-019 (Execution Sandbox) fails | Agent runtime may reach filesystem, network, or credentials outside its declared mandate. All downstream controls become advisory. | Halt testing, activate SC-018 containment, re-verify via AL-028 probes before any resumption. |
| SC-020 (External Tool Allowlist) fails | Agent may invoke tools outside its declared action space. Scope guarantees no longer hold. | Halt testing, treat as containment incident under SC-018, review MR-023 threat model for new path. |
| AR-020 (Audit Trail Isolation) fails | Agent-reachable log store cannot be trusted as authoritative record. Tamper resistance is lost. | Halt testing. Reconstruct audit trail from external sources; re-establish isolated store before resuming. |
| SC-010 (Health Monitoring) fails | Target degradation goes undetected. Platform may cause unintended impact without awareness. | SC-017 (external watchdog) provides independent health verification. Reduce testing intensity until monitoring restored. |

**General principle:** If a foundational requirement (AR-001, SE-006, SC-009) fails, the safe default is to halt testing. If a monitoring or notification requirement fails, the safe default is to reduce autonomy level and increase manual oversight until the capability is restored.

---

## Scenario Walk-Throughs

The following scenarios illustrate how cross-domain requirements activate together during real engagement events. Each scenario traces the event through every domain that responds to it.

### Scenario 1: Kill-Switch Activation During Exploitation

**Trigger:** During an L2 exploitation phase, a health check detects that the target web server's response time has exceeded 500% of baseline for three consecutive probes, indicating potential service degradation caused by testing.

**Cross-domain cascade:**

1. **SC-010** (Health Check Monitoring): Three consecutive probe failures trigger the escalation workflow.
2. **SC-007** (Cumulative Impact Tracking): Cumulative impact score crosses the Critical threshold. The platform determines that graceful halt is required.
3. **SC-009** (Kill Switch): Phase 1 activates. All new actions cease within 5 seconds; in-flight exploitation attempts complete their current network transaction but initiate no new ones.
4. **AR-001** (Structured Event Logging): Kill-switch activation logged with timestamp, triggering health-check data, cumulative impact score, and affected targets.
5. **HO-015** (Multi-Channel Notification): Operators notified via SMS, email, and dashboard alert with kill-switch details, affected target, and health-check history.
6. **SC-016** (Evidence Preservation): All exploitation evidence, partial findings, and health-check baselines written to immutable storage before any cleanup.
7. **SC-009** Phase 2: Graceful shutdown completes within 60 seconds. All network connections closed, spawned processes terminated.
8. **SE-023** (Credential Lifecycle): Testing credentials rotated or securely erased.
9. **SC-015** (Post-Test Integrity): Integrity validation compares target state against pre-engagement baseline to assess any lasting impact.

**Outcome:** The engagement is paused with full forensic evidence preserved. The operator reviews health-check data, confirms the target recovered, and decides whether to resume at reduced intensity or conclude the engagement.

### Scenario 2: Scope Violation Detected During Reconnaissance

**Trigger:** During L3 autonomous reconnaissance, DNS enumeration discovers a subdomain (internal-hr.example.com) that resolves to an IP address outside the authorized scope defined in the Rules of Engagement.

**Cross-domain cascade:**

1. **SE-006** (Pre-Action Scope Validation): The platform's pre-action check identifies that the resolved IP (10.20.30.5) is not in the authorized target list. The action (port scan of the discovered host) is blocked before execution.
2. **SE-007** (Drift Detection): The DNS discovery is flagged as potential scope drift, specifically subdomain explosion beyond the authorized count.
3. **AR-001** (Structured Event Logging): Scope violation logged with the discovered subdomain, resolved IP, the SE rule that blocked it, and the action that was prevented.
4. **HO-011** (Escalation of Unexpected Findings): The scope violation is escalated to the operator with full context: discovered asset, why it is out of scope, and what action was blocked.
5. **SC-011** (Condition-Based Halt): If pre-configured for strict scope enforcement, all reconnaissance against the parent domain pauses pending operator review.
6. **AL-025** (Autonomy Level Assessment): The scope violation event is evaluated as a factor in the ongoing autonomy assessment. Repeated scope-boundary encounters may trigger a recommendation to reduce autonomy level.

**Outcome:** The operator reviews the escalation, confirms the subdomain is out of scope, and authorizes the platform to continue reconnaissance against the remaining in-scope targets. The blocked action and operator decision are recorded in the audit trail for the engagement report.

### Scenario 3: Credential Discovery During Post-Exploitation

**Trigger:** During L2 post-exploitation of an authorized database server, the platform discovers plaintext database credentials stored in a configuration file that grant access to a second database server also within scope.

**Cross-domain cascade:**

1. **SE-023** (Credential Lifecycle): The discovered credential is classified by type (database password), source (configuration file on authorized target), and sensitivity (grants access to in-scope system).
2. **MR-019** (Credential Protection): The credential value is not stored in plaintext in any log or finding. Only the discovery event and metadata (credential type, source location, target system) are recorded in the audit trail. The actual credential value is placed in the encrypted credential vault.
3. **AR-001** (Structured Event Logging): Discovery event logged with timestamp, source system, credential type, and target system.
4. **AR-010** (Evidence Integrity): The credential discovery evidence is cryptographically bound to the audit log entry with a SHA-256 hash.
5. **HO-001** (Approval Gate): At L2, using discovered credentials to access the second database requires explicit operator approval, since credential reuse for lateral movement is a gated action category.
6. **HO-011** (Escalation): The credential discovery is escalated as an unexpected finding. The operator is presented with the credential metadata, the target system it grants access to, and the risk assessment.
7. **RP-003** (Confidence Scoring): When the credential is eventually included in the engagement report, it receives a confidence score based on evidence quality (direct discovery of plaintext credential = high confidence).
8. **RP-004** (Finding Provenance): The finding's provenance chain links back through the AR audit log to the exact discovery event, tool execution, and operator approval decision.

**Outcome:** The operator approves credential use against the second database. The platform tests the second database within the approved scope, with the full credential lifecycle (discovery, vault storage, authorized use, and eventual secure deletion at engagement end per SE-023) documented in the audit trail.
