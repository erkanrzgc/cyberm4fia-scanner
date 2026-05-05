# Auditability and Reproducibility

**Domain Prefix:** APTS-AR | **Requirements:** 20

This domain defines what an autonomous penetration testing platform MUST record, retain, and disclose so that every action it takes can later be reviewed, reproduced, attributed, and challenged. Auditability is the foundation that makes graduated autonomy safe in practice: an autonomous platform earns the right to operate with reduced human oversight only if its decisions, evidence, and state are recoverable after the fact with enough fidelity to support customer review, incident investigation, regulatory inquiry, and dispute resolution. Requirements in this domain cover structured logging, decision transparency, evidence integrity, tamper-evident storage, platform self-integrity verification, audit trail isolation from the agent runtime, and governance of platform updates that could change observable behavior.

This domain covers recording, retaining, and disclosing platform activity. Safety-control validation belongs to Manipulation Resistance (MR), final report format and delivery to Reporting (RP), and third-party dependency governance to Supply Chain Trust (TP).

> For implementation guidance, see the [Implementation Guide](Implementation_Guide.md).

---

## Domain Overview

The 20 requirements in this domain fall into six thematic groups:

| Group | Requirements | Purpose |
|---|---|---|
| **Logging fundamentals** | APTS-AR-001, APTS-AR-002, APTS-AR-003, APTS-AR-005, APTS-AR-008 | Structured event capture, phase transitions, resource metrics, retention, decision context |
| **Decision transparency** | APTS-AR-004, APTS-AR-006, APTS-AR-007, APTS-AR-009 | Confidence-scored decision logs, reasoning chains, pre-action risk assessment, customer transparency reporting |
| **Evidence integrity and chain of custody** | APTS-AR-010, APTS-AR-011, APTS-AR-013, APTS-AR-014, APTS-AR-015 | Cryptographic hashing, custody documentation, trusted timestamps, screenshot/packet capture (PCAP) standards, sensitivity classification |
| **Tamper evidence** | APTS-AR-012 | Hash-chained append-only logs |
| **Platform integrity and update governance** | APTS-AR-016, APTS-AR-017, APTS-AR-018, APTS-AR-019 | Binary/configuration/Software Bill of Materials (SBOM) integrity, regression testing across updates, customer notification, AI/ML model change tracking |
| **Audit trail isolation from the agent runtime** | APTS-AR-020 | Audit records unreachable and unmodifiable from within the agent runtime |

### Phase Model Reference

Several requirements in this domain reference attack-chain phases. APTS uses a single canonical phase model defined in the Graduated Autonomy domain: **Reconnaissance → Enumeration → Identification → Exploitation → Post-Exploitation → Reporting**. APTS-AR-002 also recognizes an Initialization state that precedes Reconnaissance. Implementations MUST use these phase names when they generate phase-transition events for APTS-AR-002.

### Requirement Index

| ID | Title | Classification |
|---|---|---|
| APTS-AR-001 | Structured Event Logging with Schema Validation | MUST \| Tier 1 |
| APTS-AR-002 | State Transition Logging | MUST \| Tier 1 |
| APTS-AR-003 | Resource Utilization Metrics Logging | MUST \| Tier 2 |
| APTS-AR-004 | Decision Point Logging and Confidence Scoring | MUST \| Tier 1 |
| APTS-AR-005 | Log Retention and Archival Requirements | MUST \| Tier 2 |
| APTS-AR-006 | Decision Chain of Reasoning and Alternative Evaluation | MUST \| Tier 1 |
| APTS-AR-007 | Risk Assessment Documentation Before Action Execution | MUST \| Tier 2 |
| APTS-AR-008 | Context-Aware Decision Logging | MUST \| Tier 2 |
| APTS-AR-009 | Transparency Report Requirements | MUST \| Tier 2 |
| APTS-AR-010 | Cryptographic Hashing of All Evidence | MUST \| Tier 1 |
| APTS-AR-011 | Chain of Custody for Evidence | MUST \| Tier 2 |
| APTS-AR-012 | Tamper-Evident Logging with Hash Chains | MUST \| Tier 1 |
| APTS-AR-013 | RFC 3161 Trusted Timestamp Integration | SHOULD \| Tier 3 |
| APTS-AR-014 | Screenshot and Packet Capture Evidence Standards | MUST \| Tier 2 |
| APTS-AR-015 | Evidence Classification and Sensitive Data Handling | MUST \| Tier 1 |
| APTS-AR-016 | Platform Integrity and Supply Chain Attestation | MUST \| Tier 2 |
| APTS-AR-017 | Safety Control Regression Testing After Platform Updates | MUST \| Tier 2 |
| APTS-AR-018 | Customer Notification for Behavior-Affecting Updates | MUST \| Tier 2 |
| APTS-AR-019 | AI/ML Model Change Tracking and Drift Detection | MUST \| Tier 2 |
| APTS-AR-020 | Audit Trail Isolation from the Agent Runtime | MUST \| Tier 2 |

### Conformance

A platform claims conformance with this domain by satisfying all MUST requirements at the tier it targets. APTS defines three cumulative tiers (Tier 1 Foundation, Tier 2 Verified, Tier 3 Comprehensive) in the [Introduction](../Introduction.md); a Tier 2 platform satisfies every Tier 1 AR requirement plus every Tier 2 AR requirement, and a Tier 3 platform satisfies all three tiers. SHOULD-level requirements are interpreted per RFC 2119.

Four advisory practices relevant to this domain (APTS-AR-A01 State Capture and Replay Support, APTS-AR-A02 Replay Variance Analysis, APTS-AR-A03 Real-Time External Log Streaming, APTS-AR-A04 Continuous Runtime Integrity Monitoring) are documented in the [Advisory Requirements appendix](../appendix/Advisory_Requirements.md). They are not required for conformance at any tier.

Every requirement in this domain includes a Verification subsection listing the verification procedures used to confirm implementation.

---

## APTS-AR-001: Structured Event Logging with Schema Validation

**Classification:** MUST | Tier 1

### Requirement

All network requests, responses, and system events MUST be logged in a structured, schema-validated format with timestamps precise to a level sufficient for unambiguous event ordering (millisecond or better).

Every log entry MUST include the following common fields regardless of event type:

- **Timestamp**: Standardized timestamp format with timezone
- **Event Type**: Classification of the event (request, response, decision, state_transition, error, finding)
- **Source**: Module or component generating the event
- **Correlation ID**: Unique identifier linking related events

In addition, the schema MUST enforce conditional fields by event type:

- **Network events**: `target`, `method`, `status_code`, `duration_ms`
- **Decision events**: `decision_type`, `confidence_score`, `alternatives_evaluated`, `selected_action`, `rationale`
- **Finding events**: `vulnerability_type`, `severity`, `evidence_hashes`, `cve_references`
- **Error events**: `error_code`, `error_message`, `stack_trace_hash`, `recovery_action`
- **State transition events**: `previous_state`, `new_state`, `triggering_condition` (per APTS-AR-002)

> **See also:** APTS-AR-002 (state transitions written to this log), APTS-AR-012 (hash chain over these entries), APTS-RP-001 (engagement reports reconcile against this log).

### Verification

1. All timestamps have ≤1ms precision
2. Every network interaction generates corresponding request AND response log entries
3. Log entries are immutable once written
4. Trace a sample multi-event transaction end-to-end using correlation IDs and confirm all related events are linked
5. 100% of logs validate against schema
6. No arbitrary field names (whitelist enforced)
7. All timestamps parseable and consistent
8. All arrays have consistent element types

---

## APTS-AR-002: State Transition Logging

**Classification:** MUST | Tier 1

### Requirement

Every transition between test phases MUST be logged with:
- Previous state
- New state
- Triggering condition
- Transition timestamp
- Explicit authorization (if applicable)

**Required Phase Transitions** (using the canonical APTS phase model):
1. Initialization → Reconnaissance
2. Reconnaissance → Enumeration
3. Enumeration → Identification
4. Identification → Exploitation
5. Exploitation → Post-Exploitation
6. Post-Exploitation → Reporting
7. Any phase → Error/Abort (with reason)

### Verification

1. Every phase change generates a transition log entry
2. The transition entry is written before any action in the new phase executes
3. Each transition records all required fields (previous state, new state, triggering condition, transition timestamp, and explicit authorization where applicable)
4. All transitions traceable to specific findings or conditions

> **See also:** APTS-AL-010 (L2 phase transitions with operator decision context).

---

## APTS-AR-003: Resource Utilization Metrics Logging

**Classification:** MUST | Tier 2

### Requirement

Every extended operation (>1 second duration) MUST log resource utilization metrics appropriate to the engagement context:

**Example Network Metrics:**
- Bytes sent / received
- Packet count
- Connection count (open/closed/failed)
- Average request latency
- Percentile latency (for example, 95th percentile)
- Error rate (failed requests / total requests)

**Example System Metrics:**
- CPU utilization (%)
- Memory usage (bytes, peak)
- Disk I/O (operations/second)
- Thread count

**Example Test Impact Metrics:**
- Requests sent to target
- Response codes received (distribution)
- Timeouts / connection resets
- Any detected target slowdown

Specific metrics and alert thresholds MUST be documented per engagement.

### Verification

1. **Metric capture**: Execute 5 extended operations (>1 second); verify each generates resource utilization log entries containing the metric categories declared in the engagement configuration
2. **Metric completeness**: For 10 logged operations, verify the captured metrics cover every metric declared in the engagement configuration's documented metric set
3. **Threshold documentation**: Verify specific metrics and alert thresholds are documented per engagement
4. **Alert triggering**: Simulate resource threshold breach (for example, high error rate); verify alert is generated
5. **Metric accuracy**: Cross-reference 5 logged metrics against independent measurement (for example, packet capture, system monitoring); verify values are consistent
6. **Per-engagement documentation**: Verify the engagement configuration documents which metrics are tracked and their alert thresholds

---

## APTS-AR-004: Decision Point Logging and Confidence Scoring

**Classification:** MUST | Tier 1

### Requirement

All automated decisions MUST be logged with:
- Decision timestamp
- Decision type (binary choice, multi-option selection, threshold crossing)
- Confidence score (0.0-1.0 scale, representing probability that the selected action will achieve intended outcome)
- Alternatives evaluated (at least 2 alternatives)
- Selected action with justification
- Risk assessment performed
- Fallback action if selected action fails

Confidence scores MUST be traceable to specific contributing factors, with individual factors weighted. Action execution MUST only proceed if confidence exceeds configured thresholds per action type. Minimum confidence thresholds by action type: Reconnaissance/Enumeration 0.30 (low threshold, low risk), Identification 0.60 (medium threshold), Exploitation 0.70 (high threshold, significant impact), Post-Exploitation 0.65 (medium threshold, depends on objective). Privilege escalation actions, which may occur within Exploitation or Post-Exploitation, SHOULD use a higher threshold (minimum 0.75) given their elevated impact. Organizations MUST document their confidence score methodology, including how scores are calculated, what inputs contribute to the score, and validate the methodology periodically against benchmark environments. Validation MUST include testing in representative environments to verify that confidence score distributions are appropriate for the platform's operational context.

> **See also:** APTS-RP-003 (application of the confidence scoring methodology in engagement reports). AR-004 defines the authoritative confidence scoring methodology and thresholds used by all requirements across the standard; RP-003 governs how these scores are presented and validated in customer deliverables.

### Verification

1. Every autonomous decision generates a decision log entry containing all required fields
2. Confidence scores range 0.0-1.0, are not constant across decisions, and vary in accordance with decision conditions (sample 20 decisions; verify scores are not all identical)
3. At least 2 alternatives evaluated and documented for each decision
4. Risk assessment performed and recorded before action selection
5. Fallback action defined for all non-trivial decisions
6. Factors underlying confidence identified with assigned weights documented per the platform's confidence methodology
7. Confidence above threshold triggers action; confidence at or below threshold prevents action or requires approval
8. Confidence methodology documented and reviewed
9. Periodic validation performed against benchmark environments with results documented

---

## APTS-AR-005: Log Retention and Archival Requirements

**Classification:** MUST | Tier 2

### Requirement

Logs MUST be retained according to the following minimum requirements:

**Retention Periods:**
- **Active Engagement**: Full retention (all logs accessible)
- **Post-Engagement**: Minimum 1 year from engagement end date
- **Regulatory minimums (where applicable to the engagement):**
  - PCI DSS: 1 year
  - HIPAA: 6 years (minimum)
  - SOX: 7 years (minimum)

**Note on GDPR:** GDPR does not impose a minimum retention period on pentest logs; instead it imposes a *minimization* requirement (personal data must not be retained longer than necessary for the documented processing purpose). For engagements covered by GDPR, the retention period for any logs containing personal data MUST be justified against a documented lawful basis and reviewed at the engagement's defined retention boundary.

**Storage Requirements:**
- Primary: Encrypted at-rest (AES-256)
- Backup: Geographically distributed (≥2 locations)
- Integrity: Regular cryptographic verification
- Format: Immutable (append-only, no modification/deletion)

**Access Control:**
- Logs restricted to authorized personnel only
- Access logging for all log access
- Audit trail of archival operations
- Read-only access after engagement closure

> **See also:** APTS-AR-001 (logs retained under this requirement are the ones produced by structured event logging), APTS-AR-011 (chain-of-custody records inherit these retention minimums), APTS-AR-012 (hash chain integrity applies to retained logs), APTS-TP-016 (data lifecycle / deletion cannot occur before these retention periods expire).

### Verification

1. 100% of logs successfully archived within the documented retention window, with no losses or corruption
2. Archival timestamps recorded and the archive is encrypted at rest (AES-256)
3. Backups exist in at least two geographically distributed locations and pass regular cryptographic integrity verification
4. Immutability enforced: no modification or deletion of archived entries is possible, and any attempt is logged
5. Access to archived logs is restricted to authorized personnel, every access event is itself logged, and post-engagement access is read-only
6. For engagements covered by GDPR, the retention period for personal-data-containing logs is justified against a documented lawful basis and reviewed at the defined retention boundary
7. Recovery procedures tested annually with documented results

---

## APTS-AR-006: Decision Chain of Reasoning and Alternative Evaluation

**Classification:** MUST | Tier 1

### Requirement

Every multi-step attack sequence MUST document the complete chain of reasoning, including:
- **Initial discovery**: What vulnerability or weakness was identified
- **Decision points**: Where the attack strategy could have branched
- **Alternative paths considered**: Why each was accepted or rejected
- **Action executed**: What was actually attempted
- **Observed outcome**: How the target responded
- **Impact assessment**: What was learned or compromised

**Required for all:**
- Multi-stage exploits (>1 attack step)
- Privilege escalation chains
- Lateral movement sequences
- Post-exploitation activities

**Alternative Action Documentation:** When a decision point involves two or more alternative actions, each rejected alternative MUST document: action description, feasibility assessment, resource requirements (time, computational resources, risk exposure), expected outcome, rejection rationale, and comparison to selected action.

**Rejection Categories:**
- `low_confidence`: Unlikely to succeed (confidence below threshold)
- `resource_intensive`: Excessive time/resource requirements
- `high_risk`: Detection risk, target damage, or engagement risk
- `out_of_scope`: Violates engagement scope or Rules of Engagement
- `lower_priority`: Lower impact or information value
- `dependency_missing`: Requires prior vulnerability exploitation that failed
- `not_applicable`: Feasibility depends on prior step outcome

### Verification

Sample 10 multi-step attack chains from the engagement audit trail (or all chains if fewer than 10 exist) and, for each sampled chain, verify every one of the following end-to-end:

1. Every stage is present in the audit trail with no gaps, traced from initial discovery to final impact. Missing stages fail.
2. Every decision point in the chain records the alternatives considered. Decisions without recorded alternatives fail.
3. Each step records an outcome (success, failure, partial, abandoned). Missing outcomes fail.
4. Every rejected alternative records a rationale and a rejection category from the defined taxonomy. Rejections without a category fail.
5. Each rejection rationale cites at least one concrete feasibility, risk, or scope factor (confidence score, resource cost, detection risk, Rules of Engagement (RoE) clause, or dependency status). Rationales that reduce to subjective preference fail.
6. A comparison to the selected action is recorded for every rejected alternative. Missing comparisons fail.
7. Feasibility data (confidence score, resource estimate, or dependency reference) supports the rejection decision for each rejected alternative. Unsupported rejections fail.

---

## APTS-AR-007: Risk Assessment Documentation Before Action Execution

**Classification:** MUST | Tier 2

### Requirement

Before executing any action rated "medium" or above risk, a formal risk assessment MUST be documented including:

**Risk Dimensions:**
1. **Target Impact Risk**: Potential damage to target system/data
   - Service disruption (DoS, crash)
   - Data loss or corruption
   - System instability or misconfiguration
   - Unintended lateral movement

2. **Detection Risk**: Likelihood of triggering defensive measures
   - Firewall/IDS alert probability
   - WAF trigger likelihood
   - EDR/Security Information and Event Management (SIEM) detection likelihood
   - Rate limiting / account lockout

3. **Engagement Risk**: Impact on engagement objectives/scope
   - Violates Rules of Engagement
   - Exceeds authorized scope
   - Jeopardizes future testing phases
   - Triggers incident response prematurely

4. **Organizational Risk**: Business impact of testing activity
   - Revenue impact (downtime)
   - Compliance/regulatory impact
   - Reputation impact
   - Legal/contractual implications

**Assessment Documentation:**

For each of the four risk dimensions, the assessment MUST record a likelihood estimate, an impact estimate, and any mitigations applied, all computed using a documented risk scoring methodology that the platform publishes and versions. The overall risk calculation MUST be transparent and traceable to the per-dimension inputs. Actions MUST NOT be executed when the resulting risk exceeds the platform's published risk thresholds for the action category.

> **See also:** APTS-AR-004 (this assessment populates AR-004's "Risk assessment performed" field).

### Verification

1. Risk assessment completed and recorded before each medium+ risk action
2. All four risk dimensions (target impact, detection, engagement, organizational) are evaluated
3. Each risk dimension has a documented likelihood and impact estimate using the platform's published scoring methodology
4. Mitigations documented for each identified risk
5. Overall risk calculation is transparent and traceable to per-dimension inputs
6. Actions are not executed when the documented risk assessment exceeds the platform's published risk thresholds for the action category

---

## APTS-AR-008: Context-Aware Decision Logging

**Classification:** MUST | Tier 2

### Requirement

All decision logs MUST include context information that influenced the decision:

**Required Context Elements:**
1. **Prior findings**: What has been discovered so far (enumeration results)
2. **Scope constraints**: What is/isn't in scope for this engagement
3. **Target state**: What has changed on the target since testing started
4. **Environmental factors**: Network conditions, observable defenses
5. **Time factors**: How much time remains in engagement
6. **Resource state**: System resources available for testing
7. **Regulatory/contractual**: Any relevant compliance or contractual constraints

> **See also:** APTS-AR-015 (classification framework for sensitive context data).

### Verification

Sample 20 decision log records at random from the engagement audit trail (or all decision records if fewer than 20 exist) and, for each sampled record, verify every one of the following:

1. All seven Required Context Elements are populated. Any null, empty, or placeholder field fails.
2. The context narrative explicitly names at least one constraint and at least one opportunity that the recorded decision considered. Missing either fails.
3. Every context field traces to an identifiable source log entry (enumeration result ID, scope document version, and health-check snapshot). Fields without a traceable source fail.
4. The context timestamp is within the documented decision-capture window of the recorded decision timestamp. Stale or missing timestamps fail.
5. Sensitive context data (targets, findings, credentials) carries the classification labels required by APTS-AR-015. Unlabeled sensitive data fails.

---

## APTS-AR-009: Transparency Report Requirements

**Classification:** MUST | Tier 2

### Requirement

At regular intervals (minimum daily for engagements >3 days), generate transparency reports documenting autonomous platform activity. Each report MUST include, at minimum, the following sections:

1. **Summary Statistics**: Total actions executed, autonomous decisions made, findings discovered, and detections triggered
2. **Decision Quality Metrics**: Average confidence scores, percentage of decisions requiring human approval, and decision override rate
3. **Evidence Summary**: Number of findings by severity, evidence integrity verification status (pass/fail per APTS-AR-010), and chain of custody compliance status
4. **Reproducibility Status**: If APTS-AR-A01 (advisory state capture and replay support) is implemented, state snapshot count, replay test results (if performed), and documented sources of non-determinism. If APTS-AR-A01 is not implemented, the section MUST state that reproducibility tracking is not implemented.
5. **Audit Compliance**: Log completeness percentage, timestamp accuracy verification, and retention policy compliance status

The specific metrics within each section are platform-determined, but all five sections MUST be present. Additional platform-specific sections are permitted.

Transparency reports MUST be made available to the engagement customer. The platform MUST provide customers access to: (a) the complete audit log for their engagement (redacted of other customers' data in multi-tenant environments), (b) all decision chain records for actions taken against their systems, (c) evidence integrity verification results, and (d) any anomalies or incidents detected during the engagement. Access MUST be provided within 5 business days of engagement completion or upon customer request during the engagement.

### Verification

1. **Cadence**: For an engagement longer than 3 days, verify that a transparency report was generated at least once per day. For shorter engagements, verify the engagement-final transparency report exists.
2. **Section completeness**: Inspect 3 transparency reports; verify all five mandatory sections are present (Summary Statistics, Decision Quality Metrics, Evidence Summary, Reproducibility Status, Audit Compliance) and that each section contains the platform-determined metrics it claims to cover.
3. **Summary statistics accuracy**: Cross-reference the report's "total actions executed" and "autonomous decisions made" counts against the underlying APTS-AR-001 event log; verify the numbers reconcile.
4. **Decision quality metrics**: Verify the report's average confidence score, human-approval percentage, and decision override rate are computed from the same APTS-AR-004 decision log entries that exist for the reporting period.
5. **Evidence integrity status**: Verify the report's evidence integrity field reflects the actual APTS-AR-010 hash verification results for the reporting period (no missing failures, no spurious passes).
6. **Reproducibility section**: If APTS-AR-A01 is implemented, verify the report's state snapshot count and non-determinism documentation reflect the APTS-AR-A01 records for the reporting period. Otherwise, verify the section explicitly states that reproducibility tracking is not implemented.
7. **Audit compliance section**: Verify the log completeness percentage and retention compliance status reflect actual APTS-AR-005 archival results.
8. **Customer access**: Confirm the engagement customer was provided access to the complete audit log, decision chain records, evidence integrity verification results, and incident records for their engagement within 5 business days of engagement completion (or earlier upon request).
9. **Multi-tenancy redaction**: For a multi-tenant platform, verify the customer-accessible audit log contains only the customer's own engagement data and is redacted of other customers' data.

---

## APTS-AR-010: Cryptographic Hashing of All Evidence

**Classification:** MUST | Tier 1

### Requirement

All evidence MUST be cryptographically hashed using SHA-256 (minimum) to verify integrity. Every piece of evidence MUST have:

**Hash Requirements:**
- **Algorithm**: SHA-256 minimum (NIST FIPS 180-4 compliant). SHA-384, SHA-512, and the SHA-3 family (SHA3-256, SHA3-384, SHA3-512) are acceptable stronger alternatives. Algorithms weaker than SHA-256 (MD5, SHA-1) MUST NOT be used for evidence integrity.
- **Hash coverage**: All raw evidence data
- **Storage**: Hash stored alongside evidence with tamper protection
- **Verification**: Cryptographic verification before use or archival
- **Format**: Hexadecimal string, lower-case
- **Algorithm identification**: The algorithm used MUST be recorded alongside the hash value to support future verification across algorithm migrations

**Evidence Types Requiring Hashing:**
1. **Request/Response Data**
   - HTTP requests (headers + body)
   - TCP connections (byte streams)
   - DNS queries and responses
   - SSL/TLS handshakes

2. **Files and Artifacts**
   - Uploaded payloads
   - Downloaded files from target
   - Screenshots and screen captures
   - Log files and transcripts

3. **Vulnerability Evidence**
   - Proof-of-concept payloads that triggered vulnerability
   - Error messages containing sensitive data
   - Response data showing vulnerability impact
   - System output proving access

4. **Forensic Data**
   - Memory dumps
   - Disk images or partitions
   - Database exports
   - Configuration files

> **See also:** APTS-AR-011 (chain of custody hash verification at every transfer), APTS-RP-001 (engagement report evidence integrity), APTS-RP-005 (binding hashes to individual findings in the deliverable report).

### Verification

Sample at least 20 evidence items from the engagement evidence store (or all items if fewer than 20 exist) and, for each sampled item, verify every one of the following:

1. A SHA-256 (or stronger, per the approved algorithm list in this requirement) hash is recorded with the item, and the algorithm identifier is stored alongside the hash. Missing algorithm identifier fails.
2. The hash value is stored in the structured audit log, not only on the evidence filesystem. Missing log entry fails.
3. The reviewer MUST independently recompute the hash from the stored evidence bytes and confirm it matches the recorded value. Mismatches or recomputation failures fail.
4. The hash travels with the evidence across storage, archival, and export operations (verified by comparing recorded hashes at each lifecycle checkpoint present in the chain-of-custody log). Gaps fail.
5. No audit trail entry references an evidence item without a valid hash verification record for that use. References without verification fail.

---

## APTS-AR-011: Chain of Custody for Evidence

**Classification:** MUST | Tier 2

### Requirement

A complete chain of custody MUST be maintained for all evidence showing:

**Chain of Custody Elements:**
1. **Evidence Creation**: When and how evidence was acquired
2. **Handling**: Every person/process that touched evidence
3. **Storage**: Where evidence was stored and protection method
4. **Access**: Who accessed evidence and when
5. **Transfer**: Movement of evidence between systems/locations
6. **Archival**: When evidence was archived and verification
7. **Disposal**: How evidence was securely deleted (if applicable)

**Chain of Custody Principles:**
- **Unbroken chain**: No gaps in custody documentation
- **Minimal access**: Only authorized personnel handle evidence
- **Documented transfers**: Every movement recorded and verified
- **Hash verification**: Hash checked at each transfer point
- **Accountability**: Person/system identified for each action
- **Secure storage**: Evidence protected when not in use
- **Access control**: Read-only access in secure facilities

> **See also:** APTS-AR-010 (hash verification at every custody transfer point), APTS-AR-015 (classification determines custody handling and access constraints), APTS-TP-015 (secure disposal procedures referenced by the custody chain's disposition step).

### Verification

Sample at least 20 evidence items from the engagement evidence store (or all items if fewer than 20 exist) and, for each sampled item, trace the full chain of custody and verify every one of the following:

1. A custody chain record exists that runs from evidence creation to its final disposition (retained, archived, or securely deleted). Missing endpoints fail.
2. Every entry in the chain identifies the responsible person or system (named operator, service account, or automated process identifier). Anonymous or unattributed entries fail.
3. For every custody transfer recorded in the chain, a hash verification record exists at the transfer timestamp. Missing verifications fail.
4. Time gaps between consecutive custody entries MUST be explained by a recorded storage or archival state. Unexplained gaps fail.
5. For disposed items, a disposal record exists with method, timestamp, and authorizing party. Missing disposal records fail.

---

## APTS-AR-012: Tamper-Evident Logging with Hash Chains

**Classification:** MUST | Tier 1

### Requirement

Logs MUST be stored in append-only format with cryptographic hash chains preventing undetected modification:

**Hash Chain Requirements:**
- **Structure**: Each log entry includes a monotonically increasing entry sequence number AND the hash of the previous entry
- **Format**: Chain of SHA-256 (or stronger, per APTS-AR-010) hashes linking entries
- **Integrity check**: Verifying chain detects any modification
- **Prevention**: Modifications would break chain (immediately detectable)
- **Immutability**: No deletion or modification of existing entries
- **Sequence integrity**: Sequence numbers MUST be continuous; gaps in the sequence indicate deletion and MUST be treated as tampering

**Chain Verification Algorithm:**
1. Read all entries in order of sequence number
2. For each entry, recompute hash: SHA256(content + previous_hash)
3. Compare computed hash to stored current_hash
4. Verify sequence numbers are continuous (no gaps)
5. If any mismatch or gap, log has been tampered with
6. Break point indicates where modification occurred

> **See also:** APTS-AR-010 (approved hash algorithms used in the chain).

### Verification

Run the Chain Verification Algorithm independently over a defined sample set and verify every one of the following:

1. **Sample set:** Run the algorithm over the complete log set for at least one full engagement, or over a random sample of at least 10,000 consecutive log entries if the engagement is very large. Samples smaller than this fail.
2. Every sampled entry MUST include a sequence number and the hash of the previous entry. Any missing field fails.
3. The reviewer MUST recompute SHA256(content + previous_hash) for every entry in the sample and compare it against the stored current_hash. Any mismatch fails and the break point MUST be reported.
4. Sequence numbers MUST be continuous across the sample. Any gap fails and is treated as tampering.
5. Attempt to delete or modify an entry through the platform's normal log interface in a staging environment. The attempt MUST fail (append-only enforcement). If the attempt succeeds, the requirement fails.
6. The reviewer MUST confirm the verification also runs successfully through the platform's own chain-verification tooling and that both independent and platform-run verifications agree.

---

## APTS-AR-013: RFC 3161 Trusted Timestamp Integration

**Classification:** SHOULD | Tier 3

### Requirement

The platform SHOULD integrate trusted timestamps from RFC 3161-compliant timestamp authorities (TSA) for critical evidence and findings. When implemented, timestamps MUST meet the following requirements:

**Timestamp Requirements:**
- **Authority**: Third-party RFC 3161-compliant Time Stamp Authority
- **Coverage**: Critical findings, exploitation steps, final reports
- **Accuracy**: ±1 second, verified with TSA certificate chain
- **Inclusion**: Timestamp token embedded with evidence
- **Verification**: TSA signature validates timestamp authenticity

**RFC 3161 Components:**
1. **Timestamp Request**: Cryptographic request to TSA
2. **Timestamp Token**: Cryptographic proof from TSA including:
   - Timestamp value
   - TSA digital signature
   - TSA certificate chain
3. **Verification**: Validate TSA signature and certificate chain

**TSA Selection:**
- Use NIST-approved TSAs (where regulatory requirement applies)
- Verify TSA certificate chain against root CAs
- Multiple TSAs for critical evidence (improved resilience)
- Record TSA identity in all timestamps

### Verification

1. All items within the documented coverage scope (critical findings, exploitation steps, and final reports) have RFC 3161 timestamps
2. Timestamp tokens stored alongside the corresponding evidence
3. TSA certificate chains included and verifiable against the trusted root CA set
4. Token verification passes for all timestamps in a sampled evidence set
5. Timestamp time aligns with system time within the ±1 second tolerance
6. TSA identity is recorded in every timestamp to support later provider disputes or revocations

---

## APTS-AR-014: Screenshot and Packet Capture Evidence Standards

**Classification:** MUST | Tier 2

### Requirement

Screenshots and packet captures have unique integrity and provenance challenges and MUST meet the following handling requirements:

**Screenshot Requirements:**
- **Metadata preservation**: Screenshot timestamp, resolution, source system
- **Content integrity**: Full screenshot content included (not truncated)
- **Anonymization**: Sensitive data redacted unless explicitly authorized
- **Format**: Lossless PNG (no JPEG compression artifacts)
- **Hash**: Cryptographic hash of screenshot file computed per APTS-AR-010
- **Provenance**: Identification of tool and settings used to capture

**Packet Capture Requirements:**
- **Capture completeness**: Full packets including headers and payload
- **Timestamp precision**: Microsecond-level packet timestamps
- **Packet count**: Total packets and bytes captured
- **Filter specification**: Any capture filters applied
- **Hardware timestamp**: If available (GPS time sync)
- **Decryption**: Encrypted traffic noted but not forcibly decrypted
- **Format**: PCAP or PCAPNG standard format
- **Hash**: Cryptographic hash of entire PCAP file computed per APTS-AR-010

> **See also:** APTS-AR-010 (hashing for screenshot and PCAP files), APTS-AR-011 (chain of custody for these files), APTS-AR-015 (classification governing redaction).

### Verification

Sample at least 10 screenshot artifacts and at least 10 packet capture artifacts from the engagement evidence store (or all artifacts of a given type if fewer than 10 exist) and run the type-specific procedures below.

**Screenshot procedure:** For every sampled screenshot, verify all of the following:

1. File format is lossless PNG. JPEG or lossy formats fail.
2. Image is complete and not truncated (image decoder opens the file without error and the full declared dimensions are present). Truncated files fail.
3. Metadata records the screenshot timestamp, resolution, source system, capturing tool identifier, and tool settings. Any missing field fails.
4. Sensitive regions are either redacted in place or the file is marked with a restricted classification under APTS-AR-015. Unmarked sensitive content fails.
5. Cryptographic hash is recorded per APTS-AR-010 and can be recomputed by the reviewer to the same value. Mismatches fail.
6. A chain-of-custody record exists under APTS-AR-011 covering the file. Missing chain fails.

**Packet capture procedure:** For every sampled PCAP/PCAPNG, verify all of the following:

1. File is valid PCAP or PCAPNG (reviewer MUST open it with an independent parser and confirm it loads cleanly). Invalid or corrupt files fail.
2. Every packet carries a microsecond-precision (or finer) timestamp. Millisecond-only or missing timestamps fail.
3. If hardware or GPS-synchronized time is available, the source is recorded in the capture metadata. Missing source when available fails.
4. Packet count and byte count recorded in metadata match the counts produced by the independent parser. Mismatches fail.
5. The capture filter used at collection time is recorded alongside the file. Missing filter specification fails.
6. Full packets are captured including headers and payload (no snap-length truncation beyond what the documented filter specifies). Unexplained truncation fails.
7. Encrypted traffic is noted in the metadata but not forcibly decrypted.
8. Cryptographic hash of the entire PCAP file is recorded per APTS-AR-010 and can be recomputed by the reviewer. Mismatches fail.
9. A chain-of-custody record exists under APTS-AR-011 covering the file. Missing chain fails.
10. Sensitive payload content is either selectively redacted in a derivative file or the file is marked with a restricted classification under APTS-AR-015. Unmarked sensitive content fails.

---

## APTS-AR-015: Evidence Classification and Sensitive Data Handling

**Classification:** MUST | Tier 1

### Requirement

All evidence MUST be classified based on sensitivity level and handled accordingly:

**Classification Levels:**
1. **PUBLIC**: Non-sensitive findings (general vulnerability types, counts)
2. **STANDARD**: Normal evidence (vulnerability details, impact assessment)
3. **CONFIDENTIAL**: Sensitive business data under customer non-disclosure agreement (NDA) (proprietary source code, internal architecture, non-regulated internal documents)
4. **RESTRICTED**: Regulated or highly sensitive data (credentials, personally identifiable information (PII), payment card data, health information, encryption keys)

**Classification Rules:**
- Evidence containing credentials → RESTRICTED minimum
- Evidence containing PII → RESTRICTED minimum
- Evidence containing payment card data → RESTRICTED minimum
- Evidence containing health information → RESTRICTED minimum
- Evidence containing encryption keys → RESTRICTED minimum
- Evidence containing proprietary source code or internal architecture under NDA → CONFIDENTIAL minimum
- Vulnerability details → STANDARD
- Non-sensitive findings → PUBLIC

**Handling Requirements by Classification:**

| Level | Storage | Access | Encryption | Retention |
|-------|---------|--------|-----------|-----------|
| PUBLIC | Standard | Unrestricted | No | As per policy |
| STANDARD | Secure | Authorized only | Optional | Engagement + 1 year |
| CONFIDENTIAL | Locked | Multi-person access control | Required (AES-256) | Engagement + 1 year (minimum; extend only with documented business need) |
| RESTRICTED | Highly secure | Multi-person access control + Multi-Factor Authentication (MFA) | Required + MFA | Engagement + 3 years (or longer where regulatory minimums such as HIPAA or SOX apply) |

Note: CONFIDENTIAL and RESTRICTED retention MUST be at least the minimum set in APTS-AR-005. Retention beyond these minimums is governed by the documented lawful basis per APTS-AR-005's GDPR note.

> **See also:** APTS-TP-012 (client data classification framework).

### Verification

1. All evidence classified at capture time with rationale documented
2. Classification rule enforcement: sample evidence containing credentials, PII, payment card data, health information, or encryption keys and verify each is classified RESTRICTED (minimum); sample evidence containing NDA-protected business data and verify classification is CONFIDENTIAL (minimum)
3. CONFIDENTIAL and RESTRICTED evidence is encrypted at rest using AES-256
4. Access controls enforced by classification, including multi-person access control for CONFIDENTIAL and RESTRICTED, and MFA enforcement for RESTRICTED access
5. Retention policies enforced by classification and meet the minimums set in APTS-AR-005
6. Deletion procedures documented and followed at the end of each classification's retention period

---

## APTS-AR-016: Platform Integrity and Supply Chain Attestation

**Classification:** MUST | Tier 2

### Requirement

The platform MUST maintain integrity verification, configuration stability monitoring, and supply chain transparency. This requirement covers three related concerns: binary integrity verification, configuration drift detection, and supply chain attestation. Platforms MAY document compliance for each concern separately.

**Platform Binary Integrity:**

The platform MUST generate and publish cryptographic hashes (SHA-256 minimum) of all executable components. The published hash list MUST be hosted in a customer-accessible repository and MUST be digitally signed by the operator's release key (for example, GPG-signed) so that customers can independently verify authenticity. Before each engagement, the platform MUST verify its own binary integrity against published hashes and include integrity verification results in the engagement pre-flight report: the structured record produced by the platform immediately before engagement execution that captures platform version, configuration baseline, integrity check results, and scope confirmation. If binary integrity verification fails (any hash mismatch), the platform MUST NOT proceed with the engagement and MUST record the failure in the final engagement report.

**Configuration Drift Detection:**

The platform MUST detect changes to its configuration between audited state and current state. Configuration drift reports MUST be produced for customers within 24 hours of request. Material configuration changes (scope enforcement rules, safety thresholds, AI model versions) MUST trigger re-verification against the relevant APTS requirements.

Baseline configuration includes: scope rules, safety thresholds, AI model versions, logging settings, autonomy constraints. Drift detection identifies: added settings, removed settings, modified values, changed timestamps. Immaterial changes (for example, log file paths) are flagged but do not trigger re-testing.

**Supply Chain Attestation:**

The platform MUST maintain a software bill of materials (SBOM) in Software Package Data Exchange (SPDX) or CycloneDX format. The SBOM MUST be updated within 48 hours of any dependency change. Customers MUST be able to request the current SBOM. Known vulnerabilities in dependencies (CVE with Common Vulnerability Scoring System (CVSS) >= 7.0) MUST be disclosed to customers within 72 hours of operator awareness.

The SBOM MUST include: component names, versions, licenses, copyright holders. Vulnerability disclosure includes: CVE ID, affected component, CVSS score, remediation status.

> **See also:** APTS-TP-006 (complementary supply chain controls: dependency inventory, risk assessment, and verification).

### Verification

**Binary integrity:**

1. Verify a published hash list exists for all platform executables, libraries, and dependencies, is hosted in a customer-accessible repository, and is digitally signed by the operator's release key so customers can independently verify authenticity.
2. For each engagement, confirm the pre-flight report includes integrity check results listing components checked, hashes verified, and any mismatches detected.
3. Validate that every platform component listed in the hash file is checked and that hash values match the published signatures.
4. Confirm that any hash mismatch halts the engagement immediately and that the halt is recorded in the final engagement report.

**Configuration drift detection:**

5. Verify a baseline configuration is documented at platform setup (covering scope rules, safety thresholds, AI model versions, logging settings, and autonomy constraints).
6. For each engagement, confirm configuration drift detection was performed and that any drift report can be produced for the customer within 24 hours of request.
7. Identify any material changes (for example, scope enforcement rules, safety thresholds, AI model versions) and verify that re-verification against the relevant APTS requirements was performed.
8. Confirm that material and immaterial classification is justified and consistent with the requirement (for example, log file paths flagged as immaterial; scope rules treated as material).

**Supply chain attestation:**

9. Verify the SBOM exists in a valid SPDX or CycloneDX format (XML or JSON) and includes required metadata (component names, versions, licenses, copyright holders).
10. For each platform version, verify the SBOM is dated, reflects the actual dependency set, and was updated within 48 hours of any dependency change.
11. Confirm the SBOM is provided to customers on request and that a documented vulnerability disclosure process is in place.
12. For known CVEs with CVSS >= 7.0, locate customer disclosure communication and verify the disclosure timestamp is within 72 hours of operator awareness and includes CVE ID, CVSS score, affected components, and remediation status.

---

## APTS-AR-017: Safety Control Regression Testing After Platform Updates

**Classification:** MUST | Tier 2

### Requirement

Platform operators MUST conduct regression testing of all safety-critical controls after any platform update that modifies decision-making logic, scope enforcement, safety mechanisms, or autonomy level behavior.

1. The operator MUST maintain a regression test suite covering all safety-critical controls defined in APTS: scope enforcement, kill switch, escalation triggers, rate limiting, data isolation, and manipulation resistance.
2. The regression suite MUST execute automatically as part of the platform's release pipeline. Updates MUST NOT ship to customers without passing the regression suite.
3. The regression suite MUST include test cases derived from previously identified failures (bugs, bypass discoveries, incident findings).
4. Regression test results MUST be documented and retained for at least 12 months.
5. If any regression test fails, the update MUST NOT be deployed until the failure is resolved and the suite passes completely.

> **See also:** APTS-MR-020 (adversarial validation of safety controls), APTS-AR-018 (customer notification of the updates tested here), APTS-AR-019 (model changes that trigger regression testing).

### Verification

1. Request the operator's regression test suite documentation.
2. Verify the suite covers all safety-critical controls defined in APTS.
3. Verify the suite runs automatically in the release pipeline (CI/CD integration evidence).
4. Review the most recent 3 release cycles and confirm regression tests passed before deployment.
5. Verify previously identified failures have corresponding regression test cases.
6. **Execution test:** Introduce or replay a known-failing safety-control test case in a staging pipeline run; verify the regression suite detects the failure and blocks the release from proceeding until the test passes

---

## APTS-AR-018: Customer Notification for Behavior-Affecting Updates

**Classification:** MUST | Tier 2

### Requirement

Platform operators MUST notify customers before deploying updates that change autonomous decision-making behavior, modify safety control parameters, or alter the platform's testing methodology.

1. The operator MUST classify updates into two categories: behavior-affecting (changes to decision logic, safety controls, testing methodology, AI/ML models) and non-behavior-affecting (UI changes, performance optimizations, documentation updates).
2. Behavior-affecting updates MUST be communicated to affected customers before deployment, with a description of what changed and how it may affect testing behavior.
3. The notification MUST include: summary of changes, affected components, potential impact on testing behavior, regression test results, and rollback procedure if issues arise.
4. Customers MUST have a documented option to defer behavior-affecting updates, unless the update addresses a critical security vulnerability in the platform itself.
5. All update notifications and customer acknowledgments MUST be logged and retained.

> **See also:** APTS-AR-017 (regression test results included in the notification), APTS-AR-019 (model changes requiring customer notification).

### Verification

1. Review the operator's update classification criteria. Verify they cover all safety-critical components.
2. Request notification history for the last 3 behavior-affecting updates.
3. Verify notifications were sent before deployment.
4. Verify notifications include change summary, impact description, regression results, and rollback procedure.
5. Verify the deferral mechanism is functional (for example, via test exercise or documented evidence).
6. **Staged update test:** In a staging environment, initiate a behavior-affecting update; verify the update pipeline blocks deployment until customer notification has been sent (or the documented notification window has elapsed)
7. **Deferral test:** Submit a customer deferral request for the staged update; verify the deferral is honored (deployment delayed) or explicitly rejected under the documented exception path with a recorded rationale

---

## APTS-AR-019: AI/ML Model Change Tracking and Drift Detection

**Classification:** MUST | Tier 2

**Applicability:** Platforms using AI/ML models for decision-making.

### Requirement

When the platform uses AI or ML models for decision-making, the operator MUST track model versions, validate model behavior after changes, maintain a model change log, and detect behavioral drift.

**AI/ML Model Change Tracking and Validation:**

1. Each AI/ML model used by the platform MUST have a unique version identifier, training date, and behavioral fingerprint (a summary of expected behavior on a standardized test set).
2. When a model is updated (retrained, fine-tuned, or replaced), the operator MUST run a behavioral comparison between the old and new model using a standardized test set relevant to safety-critical decisions.
3. If the new model's behavior deviates from the previous model on any safety-critical test case (scope decisions, escalation decisions, impact classification), the update MUST be reviewed by a human before deployment.
4. The model change log MUST record: model identifier, version, change date, change type (retrain, fine-tune, replacement), behavioral comparison results, and human review status.
5. The model change log MUST be available to customers upon request.

**AI/ML Model Behavioral Drift Detection:**

When the platform depends on external AI/ML models (for example, third-party LLM APIs), the platform MUST detect behavioral drift (changes in model output that occur without any code or configuration change on the platform side).

6. The platform MUST maintain a behavioral baseline: a set of reference inputs with expected outputs that exercise safety-critical decision paths (scope validation, escalation triggers, finding classification).
7. The platform MUST periodically run the baseline test set against the active model and compare results to expected outputs. Frequency MUST be at minimum before each engagement and after any detected API version change.
8. If baseline test results deviate beyond a defined tolerance on any safety-critical decision, the platform MUST alert the operator and MUST NOT proceed with affected decision paths until the drift is reviewed and acknowledged.
9. Drift detection results MUST be logged and available to customers.

> **See also:** APTS-TP-002 (model version pinning), APTS-TP-019 (model provenance and training data governance), APTS-TP-022 (re-attestation on material model change), APTS-AR-017 (regression testing triggered by model updates), APTS-AR-018 (customer notification for behavior-affecting model updates).

### Verification

**Model change tracking and validation:**

1. Request the operator's model registry and verify every AI/ML model has a unique version identifier, training date, and behavioral fingerprint.
2. Request the standardized test set used for behavioral comparison and verify it covers safety-critical decision paths (scope, escalation, impact classification).
3. Request the model change log for the last 12 months and verify each entry records model identifier, version, change date, change type, behavioral comparison results, and human review status.
4. For every change where behavior deviated on a safety-critical test case, verify a human review was performed and recorded before deployment.
5. Confirm the model change log is provided to customers on request.

**Behavioral drift detection:**

6. Request the operator's behavioral baseline test set and verify it covers safety-critical decision paths (scope validation, escalation triggers, finding classification).
7. Verify the baseline test set is executed against the active model at least before each engagement and after any detected API version change.
8. Simulate model drift (alter model responses on a test endpoint) and verify the platform detects the deviation, alerts the operator, and blocks affected decision paths until acknowledged.
9. Verify drift detection results are logged and made available to customers.

---

## APTS-AR-020: Audit Trail Isolation from the Agent Runtime

**Classification:** MUST | Tier 2

### Requirement

The agent runtime MUST NOT have permission to write, modify, or delete entries in the platform's authoritative audit trail. Audit records MUST be written to a store the agent cannot reach from within its execution environment, through a write-path that does not accept input originating from within the agent runtime. The audit store MUST enforce append-only semantics for the retention period defined by the platform's audit policy. Any attempt from within the agent runtime to modify or delete audit records MUST be denied at the storage layer and logged as a tamper event. The platform MUST be able to reconstruct the full sequence of agent actions for any engagement from audit records alone, without relying on data written by the agent runtime.

### Rationale

An audit trail the agent can modify is not an audit trail. As agent capabilities grow, any record the agent can reach becomes part of the agent's influence surface and can no longer be trusted as ground truth for investigating a containment failure. Enforcing isolation at the storage layer is the architectural property that preserves the audit trail's evidentiary value regardless of what the agent does or does not do. This requirement complements APTS-AR-012 (hash-chained tamper-evident logs) by addressing the write-path rather than the detection-after-the-fact.

### Verification

1. **Permission model review**: Retrieve the identity or role used by the agent runtime; confirm it has no write, modify, or delete permission on the audit store and no permission on the audit store's backing data (storage bucket, database rows, or filesystem path).
2. **Write-path test**: From within the agent runtime context, attempt to write a record to the audit store directly; confirm the write is refused at the storage boundary and a tamper event is recorded.
3. **Modification test**: From within the agent runtime context, attempt to modify or delete an existing audit record; confirm the modification is refused and the attempt is logged as a tamper event.
4. **Append-only verification**: Retrieve audit records from a completed engagement; confirm append-only semantics by attempting a modification from an administrative context and verifying the append-only property holds through the documented retention period.
5. **Reconstruction test**: For a completed engagement, reconstruct the full sequence of agent actions from audit records alone; confirm the reconstruction is complete without relying on any artifact written by the agent runtime itself.

---
