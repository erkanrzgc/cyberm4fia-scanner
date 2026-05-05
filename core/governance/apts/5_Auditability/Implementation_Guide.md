# Auditability & Reproducibility: Implementation Guide

Practical guidance for implementing APTS Auditability requirements. Each section provides a brief implementation approach, key considerations, and common pitfalls.

> **Note:** This guide is informative, not normative. Recommended defaults and example values are suggested starting points; the [Auditability README](README.md) contains the authoritative requirements. Where this guide and the README differ, the README governs.

---

## APTS-AR-001: Structured Event Logging with Schema Validation

**Implementation:** Implement JSON-based event logging with ISO 8601 timestamps (millisecond precision minimum) and unique correlation IDs for request tracing.

**Key Considerations:**
- Use UTC for all timestamps to avoid timezone conversion errors
- Include correlation IDs in all related log entries for end-to-end tracing

**Common Pitfalls:**
- Millisecond precision loss due to system clock limitations
- Missing correlation IDs leading to fragmented audit trails

**Recommended Log Schema (JSON):**

```json
{
  "timestamp": "2026-03-15T14:32:07.123Z",
  "event_id": "uuid-v4",
  "correlation_id": "engagement-uuid",
  "event_type": "ACTION_EXECUTED",
  "severity": "INFO",
  "source_component": "exploitation-engine",
  "target": {
    "ip": "10.0.1.50",
    "port": 443,
    "hostname": "app.target.com",
    "asset_criticality": "Production"
  },
  "action": {
    "technique": "SQL_INJECTION",
    "parameters": {"payload_type": "union_based", "parameter": "id"},
    "scope_validation": "PASS",
    "risk_score": 6.2
  },
  "decision": {
    "confidence": 0.87,
    "alternatives_evaluated": ["XSS", "CSRF"],
    "selected_rationale": "Highest confidence for target parameter type"
  },
  "result": {
    "status": "SUCCESS",
    "duration_ms": 245,
    "evidence_hash": "sha256:abc123..."
  }
}
```

All fields shown are REQUIRED for Tier 2 compliance. Tier 1 requires at minimum: timestamp, event_id, event_type, source_component, target.ip, action.technique, action.scope_validation, and result.status.

---


## APTS-AR-002: State Transition Logging

**Implementation:** Log every phase transition along the canonical phase model (Reconnaissance → Enumeration → Identification → Exploitation → Post-Exploitation → Reporting) with state, timestamp, and context. Include entry/exit conditions and state parameters.

**Key Considerations:**
- Define finite state machines explicitly before logging
- Capture state-specific metadata (for example, target info, configuration)

**Common Pitfalls:**
- Skipping intermediate state transitions
- Insufficient context about why transitions occurred

---

## APTS-AR-003: Resource Utilization Metrics Logging

**Implementation:** Extend operational logs to include network I/O, CPU/memory utilization, system calls, and attack impact metrics (traffic generated, targets scanned, findings count).

**Key Considerations:**
- Collect metrics at regular intervals (for example, 10-second samples)
- Correlate resource spikes with specific attack actions

**Common Pitfalls:**
- Metric collection overhead exceeding 5% CPU utilization
- Missing baseline metrics for comparison analysis

---

## APTS-AR-004: Decision Point Logging and Confidence Scoring

**Implementation:** Log all significant decisions with confidence level (0.0-1.0), evaluated alternatives, justification, and decision timestamp. Include decision_id for cross-referencing.

**Key Considerations:**
- Establish decision threshold criteria consistently
- Document confidence basis (empirical data, heuristics, ML model)

**Common Pitfalls:**
- Logging decisions without rationale or confidence scores
- Inconsistent thresholds across different decision types

---

## APTS-AR-005: Log Retention and Archival Requirements

**Implementation:** Retain logs for minimum 1 year with encrypted storage. Implement append-only archive with immutable timestamps and SHA-256 hash chains for integrity verification.

**Key Considerations:**
- Use HSM or KMS for encryption key management
- Implement tiered storage (hot/warm/cold) for cost optimization

**Common Pitfalls:**
- Retention policies without deletion verification
- Encryption key loss preventing archive recovery

---

## APTS-AR-006: Decision Chain of Reasoning and Alternative Evaluation

**Implementation:** For multi-step attack sequences, document the complete decision chain: initial hypothesis → reconnaissance findings → intermediate decisions → final action. Link decisions with decision_id chains.

**Key Considerations:**
- Create decision graphs showing relationships between decisions
- Include failed hypotheses and why they were rejected

**Common Pitfalls:**
- Only documenting successful decision paths
- Missing intermediate decision context

---


## APTS-AR-007: Risk Assessment Documentation Before Action Execution

**Implementation:** For medium/high-risk actions, perform formal risk assessments: identify hazards, estimate probability/impact, assign severity (CVSS compatible), document mitigation controls before execution.

**Key Considerations:**
- Use a consistent risk scoring framework across all assessments (for example, CVSS v3.1/v4.0 for vulnerability severity, or the cumulative risk scoring algorithm defined in APTS-SC-007 for engagement-level risk). Document the chosen framework and ensure all operators use the same methodology.
- Separate pre-action assessment from post-action findings

**Common Pitfalls:**
- Risk assessments after actions already executed
- Using different severity scales across assessments

---

## APTS-AR-008: Context-Aware Decision Logging

**Implementation:** Include environmental context in decision logs: target OS/version, network topology, active defenses detected, time-of-day, prior findings. Tag with context_id for grouping.

**Key Considerations:**
- Capture snapshot of target state at decision time
- Include relevant configuration parameters

**Common Pitfalls:**
- Context captured after environment changes
- Missing defensive tool/IDS detection data

---


## APTS-AR-009: Transparency Report Requirements

**Implementation:** Generate transparency reports at regular intervals (minimum daily for engagements exceeding three days) covering: attack phases executed, decisions made, confidence statistics, findings count and severity, resource metrics, and compliance status.

**Key Considerations:**
- Use consistent metrics across all reports
- Include trend analysis (compared to previous days)

**Common Pitfalls:**
- Reports lacking actionable insights
- Delayed distribution reducing timely decision-making

---

## APTS-AR-010: Cryptographic Hashing of All Evidence

**Implementation:** SHA-256 minimum (or stronger) hash all evidence: screenshots, logs, captures, findings. Include hash in evidence metadata. Verify hashes at ingest and before archive storage.

**Key Considerations:**
- Use cryptographically secure hash functions only
- Document hash algorithm version in metadata

**Common Pitfalls:**
- Using weak hashes (MD5, SHA1) for compliance
- Hash verification gaps during storage transitions

**Implementation Aid:** See the [Evidence Package Manifest appendix](../appendix/Evidence_Package_Manifest.md) for a practical example of how artifact identifiers, paths, hashes, timestamps, and sensitivity labels can be recorded together.

---

## APTS-AR-011: Chain of Custody for Evidence

**Implementation:** Document complete custody trail: collector identity, timestamp, transfer recipient, timestamp, transfer reason, hash verification. Maintain immutable custody log with signatures.

**Key Considerations:**
- Include digital signatures (PKI) for custody transfers
- Establish custody log retention equal to evidence retention

**Common Pitfalls:**
- Missing custody log entries between transfers
- Unsigned custody transfers

---

## APTS-AR-012: Tamper-Evident Logging with Hash Chains

**Implementation:** Implement append-only logs with cryptographic hash chains: each entry includes SHA-256 hash of previous entry. Verify chain integrity weekly and on archive.

**Key Considerations:**
- Use blockchain-style hash linking for tamper evidence
- Publish hash chain roots externally

**Common Pitfalls:**
- Hash chain gaps from log rotation
- Verification tools not catching chain breaks

---

## APTS-AR-013: RFC 3161 Trusted Timestamp Integration

**Implementation:** Integrate RFC 3161 time-stamping authority for critical events (decisions, key findings, phase transitions). Include TSA response proof in evidence archive.

**Key Considerations:**
- Use accredited TSA providers (ISO 27001 certified)
- Handle TSA certificate revocation scenarios

**Common Pitfalls:**
- TSA outage handling not implemented (no fallback or queue-and-retry)
- Missing TSA certificate chain validation, allowing forged tokens to pass

---

## APTS-AR-014: Screenshot and Packet Capture Evidence Standards

**Implementation:** Capture screenshots in lossless PNG format with metadata (timestamp, application window state). Record packet captures in PCAP format with link-layer headers. Hash both formats, store in evidence archive.

**Key Considerations:**
- Include screen resolution and refresh rate in metadata
- Capture full packet payloads for replay capability

**Common Pitfalls:**
- Lossy compression (JPEG) breaking artifact analysis
- Truncated packet captures losing payload data

---

## APTS-AR-015: Evidence Classification and Sensitive Data Handling

**Implementation:** Classify evidence into four levels: public, internal, confidential, restricted. Apply controls: redaction, encryption, access logs, destruction timelines. Separate sensitive data from general findings.

**Key Considerations:**
- Implement automated PII/credential detection and redaction
- Define audience for each classification level

**Common Pitfalls:**
- Sensitive data mixed with public findings
- Insufficient destruction documentation

---

## APTS-AR-016: Platform Integrity and Supply Chain Attestation

**Implementation:** Generate SHA-256 hashes for all platform components. Maintain Software Bill of Materials (SBOM) in SPDX format. Include CVE disclosures for dependencies. Publish attestations weekly.

**Key Considerations:**
- Automate SBOM generation during builds
- Include transitive dependency CVEs

**Common Pitfalls:**
- Outdated SBOMs missing recent changes
- Missing CVE remediation evidence

---

## APTS-AR-017: Safety Control Regression Testing After Platform Updates

**Implementation:** Include regression tests for all safety controls in CI/CD pipeline. Test before production deployment: decision validation, log integrity, evidence handling, notification systems.

**Key Considerations:**
- Automate test execution on every build
- Include end-to-end scenario testing

**Common Pitfalls:**
- Unit tests only (missing integration coverage)
- Manual testing delaying deployments

---

## APTS-AR-018: Customer Notification for Behavior-Affecting Updates

**Implementation:** Identify behavior-affecting updates (decision logic, safety thresholds, reporting changes). Notify customers 14 days before deployment with change summary and impact analysis.

**Key Considerations:**
- Define "behavior-affecting" criteria consistently
- Provide rollback procedures to previous version

**Common Pitfalls:**
- Notification lacking technical change details
- Insufficient notice window for customer planning

---

## APTS-AR-019: AI/ML Model Change Tracking and Drift Detection

**Implementation:** Assign version IDs to all ML models. Generate behavioral fingerprints (test result signatures) for each version. Monitor production inference drift: compare output distributions to baseline. Alert on >5% drift.

**Key Considerations:**
- Version models at semantic level (major.minor.patch)
- Include training data provenance in metadata

**Common Pitfalls:**
- Missing behavioral fingerprint generation
- Drift detection thresholds too loose/tight

---

## APTS-AR-020: Audit Trail Isolation from the Agent Runtime

**Implementation:** Deploy the audit store on infrastructure the agent runtime cannot reach from within its execution environment. Options include a managed append-only log service (for example, a write-only SQS/Pub-Sub queue feeding a WORM-configured bucket), an external SIEM with an ingest endpoint authenticated by the platform control plane, or an append-only database with row-level deny-modify policies. The agent runtime communicates with the control plane through a narrow interface that the control plane writes to the audit store on behalf of the agent; the agent runtime has no direct credentials for the audit store and no network route to it. Configure the audit store to reject modifications and deletions for the retention period defined in the platform's audit policy. Verify reconstruction works end-to-end by replaying audit records through a dedicated reconstruction tool that does not run inside the agent runtime.

**Key Considerations:**
- This requirement pairs with SC-019 (sandbox boundary) and MR-023 (agent runtime as untrusted component); all three must hold for the architecture to be coherent
- The control plane's audit-write credentials are as sensitive as any other platform secret and MUST NOT be reachable from the agent runtime
- Append-only semantics and retention policy are enforced at the storage layer, not by the writer, because the writer's identity may change over the retention period

**Common Pitfalls:**
- Writing audit records from the agent runtime directly "for simplicity" and relying on hash chains to detect tampering after the fact
- Granting the agent runtime read access to the audit store "for debugging", which creates a side channel the agent can use to learn what the control plane sees
- Using the same credential set for agent runtime and audit writer and calling that "least privilege"

---

## Implementation Roadmap

**Phase 1 (implement before any autonomous pentesting begins):**
APTS-AR-001 and APTS-AR-002 (structured event logging with schema validation, state transitions), APTS-AR-004 (decision point logging), APTS-AR-006 (decision chain reasoning and alternative evaluation), APTS-AR-010 (cryptographic evidence hashing), APTS-AR-012 (tamper-evident hash chains), APTS-AR-015 (evidence classification and sensitive data handling).

Start with APTS-AR-001 (structured logging infrastructure with schema validation) as the foundation. All other auditability controls depend on this. Add APTS-AR-010 and APTS-AR-012 (evidence integrity) next, then APTS-AR-004 and APTS-AR-006 (decision trail transparency).

**Phase 2 (implement within first 3 engagements):**
APTS-AR-003 (resource utilization metrics), APTS-AR-005 (log retention and archival), APTS-AR-007 and APTS-AR-008 (risk assessment, context-aware logging), APTS-AR-009 (transparency reports), APTS-AR-011 (evidence chain of custody), APTS-AR-014 (screenshot/PCAP standards), APTS-AR-016 (platform integrity and supply chain attestation), APTS-AR-017 (regression testing after updates), APTS-AR-018 (customer notification for behavior-affecting updates), APTS-AR-019 (AI/ML model change tracking and drift detection), APTS-AR-020 (audit trail isolation from the agent runtime).

Prioritize APTS-AR-005 (retention) and APTS-AR-020 (audit trail isolation) first. APTS-AR-020 is the architectural foundation that makes the rest of the audit stack trustworthy as the agent's capabilities grow. Then add APTS-AR-011 (chain of custody) and APTS-AR-009 (transparency reports) so customers see audit results from day one, followed by APTS-AR-016 through APTS-AR-019 (platform integrity and update governance).

**Phase 3 (implement within 6 months):**
APTS-AR-013 (RFC 3161 trusted timestamps, SHOULD). Consider the advisory practices documented in the [Advisory Requirements appendix](../appendix/Advisory_Requirements.md): APTS-AR-A01 and APTS-AR-A02 (state capture and replay variance analysis), APTS-AR-A03 (real-time external log streaming), and APTS-AR-A04 (continuous runtime integrity monitoring).

Phase 3 controls strengthen evidentiary defensibility and tamper resistance. Implement APTS-AR-019 first if logs already flow through a SIEM, then APTS-AR-016 and APTS-AR-017 to enable replay and dispute resolution, then APTS-AR-020 and APTS-AR-013.
