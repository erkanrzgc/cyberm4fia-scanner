# Reporting

**Domain Prefix:** APTS-RP | **Requirements:** 15

This domain defines how an autonomous penetration testing platform produces and delivers findings that customers can trust: evidence-backed, reproducibility-ready, confidence-scored, hallucination-resistant, and honest about what the engagement did and did not cover. A platform can enforce scope, stop safely, keep pristine audit trails, and resist manipulation, yet still fail its customer if findings are unverifiable, overconfident, or silently incomplete. Requirements here govern evidence-based validation, human review pipelines, confidence scoring, provenance chains, cryptographic evidence integrity, false positive and false negative disclosure, coverage disclosure, executive summaries, remediation guidance, Service Level Agreement (SLA) reporting, trend analysis, and downstream pipeline integrity.

This domain covers the content and integrity of findings delivered to the customer. Engagement-time logging and evidence storage belong to Auditability (AR); cryptographic hashing primitives and chain-of-custody mechanics remain normatively in AR even when referenced by requirements here.

> For implementation guidance, see the [Implementation Guide](Implementation_Guide.md).

---

## Domain Overview

The 15 requirements in this domain fall into five thematic groups:

| Group | Requirements | Purpose |
|---|---|---|
| **Finding validation, review, and confidence** | APTS-RP-001, APTS-RP-002, APTS-RP-003 | Evidence-based validation, human review pipeline, confidence scoring methodology |
| **Provenance and evidence integrity** | APTS-RP-004, APTS-RP-005 | Finding provenance chain, cryptographic evidence chain integrity |
| **Accuracy and coverage disclosure** | APTS-RP-006, APTS-RP-007, APTS-RP-008, APTS-RP-009, APTS-RP-010 | False positive disclosure, independent reproducibility, coverage disclosure, false negative disclosure, detection effectiveness benchmarking |
| **Customer-facing report content** | APTS-RP-011, APTS-RP-012, APTS-RP-013 | Executive summary and risk overview, remediation guidance and prioritization, SLA compliance reporting |
| **Recurring and downstream reporting** | APTS-RP-014, APTS-RP-015 | Trend analysis for recurring engagements, downstream finding pipeline integrity |

### Requirement Index

| ID | Title | Classification |
|---|---|---|
| APTS-RP-001 | Evidence-Based Finding Validation | MUST \| Tier 2 |
| APTS-RP-002 | Finding Verification and Human Review Pipeline | MUST \| Tier 2 |
| APTS-RP-003 | Confidence Scoring with Auditable Methodology | MUST \| Tier 2 |
| APTS-RP-004 | Finding Provenance Chain | MUST \| Tier 2 |
| APTS-RP-005 | Cryptographic Evidence Chain Integrity | MUST \| Tier 2 |
| APTS-RP-006 | False Positive Rate Disclosure | MUST \| Tier 1 |
| APTS-RP-007 | Independent Finding Reproducibility | SHOULD \| Tier 3 |
| APTS-RP-008 | Vulnerability Coverage Disclosure | MUST \| Tier 1 |
| APTS-RP-009 | False Negative Rate Disclosure and Methodology | MUST \| Tier 2 |
| APTS-RP-010 | Detection Effectiveness Benchmarking | SHOULD \| Tier 3 |
| APTS-RP-011 | Executive Summary and Risk Overview | MUST \| Tier 1 |
| APTS-RP-012 | Remediation Guidance and Prioritization | MUST \| Tier 2 |
| APTS-RP-013 | Engagement SLA Compliance Reporting | MUST \| Tier 2 |
| APTS-RP-014 | Trend Analysis for Recurring Engagements | SHOULD \| Tier 2 |
| APTS-RP-015 | Downstream Finding Pipeline Integrity | SHOULD \| Tier 2 |

### Conformance

A platform claims conformance with this domain by satisfying all MUST requirements at the compliance tier it targets. APTS defines three cumulative compliance tiers (Tier 1 Foundation, Tier 2 Verified, Tier 3 Comprehensive) in the [Introduction](../Introduction.md); a Tier 2 platform satisfies every Tier 1 RP requirement plus every Tier 2 RP requirement, and a Tier 3 platform satisfies all three tiers. SHOULD-level requirements are interpreted per RFC 2119.

Every requirement in this domain includes a Verification subsection listing the verification procedures a reviewer uses to confirm implementation.

---

## APTS-RP-001: Evidence-Based Finding Validation

**Classification:** MUST | Tier 2

### Requirement

Every finding MUST include raw technical evidence demonstrating its existence. AI-generated summaries MAY accompany evidence but MUST NOT replace it.

- Each finding includes at least one raw evidence artifact: packet captures, HTTP request/response pairs, command output, screenshots, or file contents
- Findings without raw evidence are explicitly flagged as "Unverified" in the report
- Summaries are clearly separated from raw evidence with distinct formatting
- Evidence provenance is documented: which tool captured it, timestamp, conditions

### Verification

- Extract all findings from engagement report
- For each finding, confirm a raw evidence section exists with actual technical data
- Verify findings marked "Unverified" do not appear in main findings section
- Check that summaries are clearly distinct from evidence (for example, separate subsection headers)

---

## APTS-RP-002: Finding Verification and Human Review Pipeline

**Classification:** MUST | Tier 2

### Requirement

Every Critical and High severity finding MUST pass through a three-stage verification pipeline before inclusion in the final report:

**Stage 1 - Initial Reproduction (during testing):** The platform MUST attempt automated reproduction for every Critical and High finding. Reproduction attempts are logged with timestamps, exact inputs provided, and outputs received. Findings are marked "Confirmed" (successful reproduction) or "Unconfirmed" (failed reproduction). Failed reproduction attempts include detailed explanation of what was attempted and why it failed. Reproduction methodology is documented and traceable back to tool invocations.

**Stage 2 - Pre-Delivery Re-verification:** Before finalizing any engagement report, the platform MUST automatically re-trigger each Critical and High finding to confirm reproduction. For each finding, the platform MUST replay the exact attack sequence, confirm consistent behavior, and record the re-verification attempt with full packet capture. Findings that fail re-verification MUST NOT appear as confirmed in the final report; they MAY appear in an appendix labeled "Unverified Findings Requiring Manual Review." Findings that reproduce on some but not all attempts MUST be classified as "Intermittent" with the reproduction rate documented (for example, "Reproduced 3 of 5 attempts") and included in the main report. The re-verification rate (percentage of findings reproducing on second attempt) MUST be disclosed in the methodology section.

**Stage 3 - Human Review Gate:** Critical findings are subject to mandatory human review before customer delivery. At Autonomy Levels 1-3: all Critical findings MUST be reviewed by a qualified human before delivery. At Autonomy Level 4: Critical findings SHOULD be flagged for priority human review within 4 hours of delivery, enabling post-delivery review rather than blocking autonomous report generation. Each Critical finding MUST include reviewer identification (name, title, qualification such as Offensive Security Certified Professional (OSCP), Certified Ethical Hacker (CEH), or years of experience), reviewer signature or authentication token indicating explicit approval, and review notes documenting human verification steps taken.

### Verification

1. Review engagement audit logs for reproduction attempt records; for each Critical/High finding, confirm a reproduction log entry exists
2. Verify reproduction result matches finding's Confirmed/Unconfirmed status; validate reproduction inputs and outputs are documented
3. For each Critical/High finding, verify re-verification log exists with timestamp and full packet capture
4. Confirm re-verification includes exact attack sequence replay and response behavior validation
5. Verify findings that failed re-verification appear only in appendix, not in main findings
6. Verify intermittent findings are classified with specific reproduction rate and included in the main report
7. Review 3 engagement reports; verify each includes re-verification rate in the methodology section
8. For each Critical finding, locate Human Review section; verify reviewer name, qualification, and signature/authentication token are present
9. Verify review timestamp relative to finding discovery timestamp; confirm autonomy level requirements are met
10. Spot-check 3 findings: reproduce independently and confirm results match platform's verification results

> **See also:** APTS-RP-001 (evidence-based finding validation that feeds this verification pipeline), APTS-AR-001 (audit trail that records reproduction and re-verification attempts), APTS-AR-004 (decision confidence scoring that informs human review triage).

---

## APTS-RP-003: Confidence Scoring with Auditable Methodology

**Classification:** MUST | Tier 2

### Requirement

Each finding MUST include a confidence score (0-100%) calculated from objective factors with documented, auditable methodology.

- Confidence score is derived from measurable factors, not opaque "AI confidence"
- Methodology documentation includes formula or decision tree
- Factors used are: successful reproductions count, evidence quality (raw and inferred), attack path complexity
- Formula is identical across all findings for consistency
- Score calculation is auditable and reproducible

The confidence scoring methodology MUST document: (a) the input factors used to calculate confidence (for example, evidence quality, number of independent confirmations, environmental conditions), (b) the weighting applied to each factor, (c) the scale definition (for example, 0-100% where 0 = no confidence and 100 = confirmed with full evidence chain), and (d) the thresholds used to categorize findings as Confirmed (>= 90%), High Confidence (70-89%), Medium Confidence (50-69%), or Low Confidence (< 50%). The methodology MUST be consistent across all findings within an engagement.

> **See also:** APTS-AR-004 (authoritative definition of the confidence scoring methodology and thresholds). Engagement reports MUST use the same methodology defined in AR-004; RP-003 governs how confidence scores are presented and validated in deliverables.

### Verification

- Extract confidence scoring methodology from engagement documentation
- For each finding in report, locate confidence score and score calculation details
- Verify score uses only documented factors (reproductions, evidence quality, complexity)
- Recalculate confidence for 5 random findings and confirm matches reported score
- Verify formula is consistent across findings

---

## APTS-RP-004: Finding Provenance Chain

**Classification:** MUST | Tier 2

### Requirement

Each finding MUST include complete provenance chain documenting its discovery path: which scanner/module discovered it, what input triggered discovery, what decision path led to exploitation, and cryptographic linkage to audit logs.

- Provenance chain traces finding back to specific scanner execution, tool configuration, and audit log entry
- Chain includes: discovery event timestamp, discovery tool, discovery input, analysis tool invocations, exploitation tool invocations
- Each link is cryptographically signed or hashed using algorithms of equivalent or greater strength than SHA-256 to prevent tampering
- Provenance is cross-referenced to Auditability audit trail
- Client can validate provenance chain using public hashes

### Verification

- For each finding, locate provenance chain in report appendix
- Verify each provenance event references audit log entry (see the Auditability domain, APTS-AR-001)
- Validate cryptographic hashes link chain entries
- Recalculate hashes to confirm no tampering
- Confirm all tools, timestamps, and inputs are verifiable from audit logs

> **See also:** APTS-AR-011 (chain of custody for evidence)

---

## APTS-RP-005: Cryptographic Evidence Chain Integrity

**Classification:** MUST | Tier 2

### Requirement

All finding evidence MUST be cryptographically bound to the discovery event with integrity verification. This requirement specifies the integrity verification mechanism for the finding provenance chain defined in APTS-RP-004.

1. For each finding, the platform MUST capture and provide:
   - Raw evidence artifact demonstrating the finding: network captures (PCAP), authenticated session logs, API request/response pairs, file system artifacts, command output, or equivalent technical evidence
   - Cryptographic hash (for example, SHA-256 or equivalent strength) of each evidence artifact
   - Unique identifier linking the evidence to the finding report
   - Timestamp correlation between evidence capture and finding report

2. Evidence MUST be extractable directly from raw bytes. Summaries or screenshots alone are insufficient for CRITICAL/HIGH findings.

3. For findings discovered over encrypted channels or through non-network means, alternative evidence artifacts with equivalent integrity guarantees are acceptable (for example, database query results with execution timestamp, authenticated log entries with cryptographic signature, authenticated API responses with session binding).

4. Reviewers MUST be able to independently verify evidence integrity using the provided cryptographic hashes and confirm the vulnerability response matches what the platform reported.

### Verification

- For each CRITICAL/HIGH finding, locate associated evidence artifact(s) and SHA-256 hash(es)
- Verify evidence includes at least one raw technical artifact (not summary or screenshot)
- Confirm SHA-256 hashes of evidence artifacts are documented
- Verify timestamp in evidence aligns with finding timestamp (within 1 second)
- Independently verify evidence integrity using provided hashes
- Confirm evidence matches vulnerability description (for encrypted/non-network findings, verify authentication and source)
- For encrypted channel findings, verify alternative evidence artifacts have equivalent integrity guarantees

> **See also:** APTS-AR-010 (platform-wide evidence hashing specification).

---

## APTS-RP-006: False Positive Rate Disclosure

**Classification:** MUST | Tier 1

### Requirement

The platform MUST disclose its false positive rate methodology and measurements in every engagement report.

1. The methodology section MUST include:
   - Platform's overall false positive rate over a documented measurement period, with a description of how ground truth was established
   - False positive rate specific to this engagement (findings reported compared to findings confirmed), where confirmation data is available
   - Method used to calculate false positive rate, including known limitations of the measurement

2. If the platform's false positive rate for CRITICAL/HIGH findings exceeds the operator's published target, this MUST be prominently disclosed in the executive summary.

3. Customers MUST be able to report false positives back to the operator. The operator MUST track and publish aggregate false positive rates per finding category.

### Verification

- Locate false positive rate disclosure in Methodology section
- Verify includes: platform rate over documented measurement period, engagement-specific rate, calculation method
- Check for prominence notice in Executive Summary if rate exceeds operator's published target
- Verify customer can identify reporting mechanism (email, web form, or API endpoint) for false positives
- Request operator's false positive tracking database and confirm recent entries
- Verify aggregate rates published per finding category (for example, "Remote Code Execution (RCE): 3% FP rate")

> **See also:** APTS-RP-003 (confidence scoring methodology that informs false positive filtering), APTS-RP-001 (evidence-based validation that reduces false positives).

---

## APTS-RP-007: Independent Finding Reproducibility

**Classification:** SHOULD | Tier 3

### Requirement

The platform SHOULD support independent reproduction of reported findings. Specifically:

1. A representative sample of CRITICAL findings from a recent engagement (with customer consent) can be selected for validation.
2. Each selected finding can be independently reproduced using the platform's documented evidence (steps, PCAP, tool output).
3. The platform MUST define a reproduction success threshold and document it.
4. Results are documented with per-finding reproduction status.

### Verification

- Confirm engagement is at least 30 days old (allows time for system changes)
- Select a representative sample of CRITICAL findings from engagement
- For each finding, obtain platform's evidence, reproduce steps, and PCAP
- Attempt independent reproduction using same target environment or documented equivalent
- Document reproduction success/failure for each finding
- Evaluate reproduction rate against the platform's documented threshold
- Provide detailed report per finding with reproduction attempts and results

> **See also:** APTS-RP-005 (cryptographic evidence chain that enables independent reproduction), APTS-RP-004 (provenance chain used by independent reviewers).

---

## APTS-RP-008: Vulnerability Coverage Disclosure

**Classification:** MUST | Tier 1

### Requirement

Platform reports MUST include a vulnerability coverage matrix that discloses which vulnerability classes the platform tested for and which it did not.

1. Every engagement report MUST include a "Coverage Matrix" section listing: vulnerability classes tested (mapped to Common Weakness Enumeration (CWE) categories or equivalent taxonomy), vulnerability classes explicitly excluded from testing, and vulnerability classes where coverage is partial (for example, the platform tests for SQL injection but not stored XSS).
2. The coverage matrix MUST be specific to the engagement, reflecting the actual test profile and autonomy level used, not a generic list of the platform's theoretical capabilities.
3. For each vulnerability class listed as tested, the platform MUST indicate the detection method used (signature-based, heuristic, exploitation-based, or behavioral analysis).
4. The coverage matrix MUST NOT misrepresent coverage. If the platform only checks for default credentials but does not test authentication bypass logic, "Authentication" MUST NOT be listed as fully covered.
5. The coverage matrix MUST be positioned in the report where customers will see it (Executive Summary or Methodology section), not buried in an appendix.

### Verification

1. Review the engagement report. Verify a coverage matrix is present in the Methodology or Executive Summary section.
2. Verify the matrix lists specific CWE categories or equivalent, not vague labels like "web vulnerabilities."
3. Verify the matrix reflects the actual engagement configuration, not a generic capability list.
4. Cross-reference the "tested" classes against the platform's actual test execution logs. Verify no class is claimed as tested when the corresponding test module did not execute.
5. Verify excluded and partial coverage classes are clearly identified.

---

## APTS-RP-009: False Negative Rate Disclosure and Methodology

**Classification:** MUST | Tier 2

### Requirement

Platform operators MUST disclose their false negative rate measurement methodology and known limitations. Absolute false negative rates are inherently difficult to measure; this requirement focuses on transparency of methodology rather than mandating specific accuracy levels.

1. The operator MUST maintain a documented methodology for measuring or estimating false negative rates, including how ground truth is established where feasible (for example, known-vulnerable test environments, comparison with manual testing, third-party validation, or coverage gap analysis).
2. The operator SHOULD publish aggregate false negative estimates per vulnerability class based on their measurement methodology, updated periodically.
3. Per-engagement reports SHOULD include an estimated false negative risk assessment based on the engagement's scope, target technology, and testing depth.
4. The false negative measurement methodology MUST be available to customers upon request.
5. If the operator has not yet established measured false negative rates (for example, new platform), the report MUST explicitly state this and describe the plan for establishing measurement.
6. Where direct measurement is infeasible, the operator MUST disclose the estimation approach used and its limitations.

### Verification

1. **Methodology documentation**: Request the operator's false negative rate measurement methodology; verify it exists, is documented, and describes how ground truth is established (known-vulnerable environments, manual comparison, or third-party validation)
2. **Aggregate rate publication**: Verify the operator publishes aggregate false negative rates per vulnerability class; confirm the publication cadence is documented in the methodology
3. **Per-engagement estimate**: Review 5 engagement reports; verify each includes a false negative risk assessment or explicitly states why one is not feasible for that engagement
4. **Methodology availability**: Request the measurement methodology as a customer; verify it is provided upon request
5. **New-platform disclosure**: If the operator has not yet established measured rates, verify the report explicitly states this and includes a plan and timeline for establishing measurement
6. **Estimation limitations**: Where estimation methods are used instead of direct measurement, verify the methodology documents the estimation approach and discloses its limitations

> **See also:** APTS-RP-008 (coverage disclosure that bounds the scope over which false negatives are measured), APTS-RP-010 (detection effectiveness benchmarking that provides ground truth for false negative measurement).

---

## APTS-RP-010: Detection Effectiveness Benchmarking

**Classification:** SHOULD | Tier 3

### Requirement

Platform operators SHOULD benchmark their detection effectiveness against known-vulnerable environments and disclose benchmark results to customers upon request.

1. The operator SHOULD maintain at least 3 benchmark environments representing common target profiles (web application, API service, network infrastructure) with documented, known vulnerabilities.
2. Benchmark runs SHOULD be conducted at least quarterly and after major platform updates.
3. Benchmark results SHOULD include: total known vulnerabilities per environment, total detected, total missed, detection rate per vulnerability class, and time to detection.
4. Benchmark environments SHOULD be periodically refreshed with new vulnerabilities to prevent overfitting (the platform being tuned specifically to detect benchmark vulnerabilities while missing novel ones).
5. Benchmark results SHOULD be available to customers upon request.

### Verification

1. Request the operator's benchmark environment descriptions and known vulnerability inventories.
2. Request the most recent quarterly benchmark results.
3. Verify detection rates are broken down by vulnerability class.
4. Verify benchmark environments have been refreshed within the last 12 months.
5. Compare benchmark results across the last 4 quarters. Verify detection rates are stable or improving.

> **See also:** APTS-RP-008 (coverage disclosure that these benchmarks validate), APTS-RP-009 (false negative methodology grounded in benchmark results).

---

## APTS-RP-011: Executive Summary and Risk Overview

**Classification:** MUST | Tier 1

### Requirement

Every engagement report MUST include an executive summary suitable for non-technical stakeholders. The summary MUST include: overall risk posture assessment, total findings count by severity, key findings with business impact, and scope coverage achieved. The executive summary MUST be comprehensible without reading the full technical report.

Reports MUST be delivered in at least one machine-readable format (JSON, XML, or structured CSV) in addition to any human-readable format (PDF, HTML). Machine-readable output enables integration with customer vulnerability management systems, ticketing platforms, and risk dashboards. The human-readable report MUST include: engagement metadata (scope, dates, tier, autonomy level), executive summary with risk rating, finding summary table sorted by severity, detailed findings with evidence, coverage disclosure per APTS-RP-008, and methodology description.

### Verification

1. Review sample reports for presence of executive summary section.
2. Verify severity breakdown is present and accurate.
3. Confirm the executive summary includes overall risk posture, business impact for critical findings, severity totals, and scope coverage; verify every technical acronym in the executive summary is either expanded on first use or defined in an attached glossary
4. Verify scope coverage percentage is disclosed.

---

## APTS-RP-012: Remediation Guidance and Prioritization

**Classification:** MUST | Tier 2

### Requirement

For each finding, the report MUST include remediation guidance with prioritization. Remediation entries MUST include: recommended fix, estimated effort category (quick win, moderate, significant), and priority ranking based on risk and exploitability. Where the platform cannot provide specific remediation steps, it MUST state this explicitly and provide references to relevant remediation resources.

### Verification

1. Review findings for presence of remediation guidance.
2. Verify effort estimates are categorized consistently.
3. Compare each finding's priority ranking against the platform's documented prioritization matrix; fail any finding whose priority differs from the matrix without a recorded exception rationale
4. Verify explicit disclosure when remediation guidance is unavailable.

> **See also:** APTS-RP-011 (executive summary and risk overview that incorporates prioritized remediation), APTS-RP-001 (evidence-based validation that supports remediation confidence).

---

## APTS-RP-013: Engagement SLA Compliance Reporting

**Classification:** MUST | Tier 2

### Requirement

The report MUST disclose engagement timeline compliance including: agreed start and end dates, actual start and end dates, any interruptions or pauses with duration and cause, and percentage of planned scope completed. If the platform failed to complete the agreed scope, the report MUST explain the reason and disclose untested areas.

### Verification

1. Compare agreed timeline to actual timeline in report.
2. Verify interruptions are documented with causes.
3. Confirm scope completion percentage is disclosed.
4. Verify untested areas are explicitly listed when scope is incomplete.

> **See also:** APTS-SE-004 (temporal boundary enforcement that defines the engagement timeline), APTS-RP-008 (coverage disclosure that pairs with SLA completion reporting).

---

## APTS-RP-014: Trend Analysis for Recurring Engagements

**Classification:** SHOULD | Tier 2

### Requirement

For recurring engagements against the same target environment, the report SHOULD include trend analysis comparing current findings to previous engagements. Trend analysis SHOULD cover: new findings not present in prior engagements, resolved findings confirmed remediated, persistent findings still unresolved, and overall risk posture trend (improving, stable, degrading).

### Verification

1. Review recurring engagement reports for trend data.
2. Verify new, resolved, and persistent categorization.
3. Verify the trend analysis section includes prior-period and current-period severity counts or risk scores; fail if the stated trend label (improving, stable, degrading) is not supported by the included figures
4. Verify previous engagement data is correctly referenced.

> **See also:** APTS-RP-011 (executive summary format that carries trend analysis), APTS-AR-001 (audit trail referenced to reconstruct prior engagement findings).

---

## APTS-RP-015: Downstream Finding Pipeline Integrity

**Classification:** SHOULD | Tier 2

### Requirement

When the platform integrates with downstream systems for finding delivery (ticketing systems, vulnerability management platforms, messaging services, or customer APIs), the platform SHOULD enforce controls to maintain finding integrity throughout the delivery pipeline:

1. **Data fidelity**: Finding synchronization SHOULD preserve evidence links, severity classifications, and remediation guidance without silent data loss or field truncation
2. **Tenant isolation**: Ticket creation or finding export SHOULD enforce authorization and tenant isolation to prevent cross-customer data leakage into incorrect ticketing queues or channels
3. **Deduplication**: Deduplication policies SHOULD be documented to prevent duplicate ticket storms while preserving distinct finding instances
4. **Sensitive data handling**: Sensitive data (credentials, PII, exploitation evidence) SHOULD be redacted or handled per the data classification framework before export to third-party systems
5. **Delivery assurance**: Finding delivery failures SHOULD be detected, logged, and retried or escalated to prevent silent finding loss
6. **Field mapping validation**: Mappings between platform finding fields and downstream system fields SHOULD be documented and validated to prevent misclassification or data loss during translation

### Verification

1. Integration configuration documents all downstream systems, field mappings, and authorization controls
2. Test: push a finding to a downstream system; verify evidence links, severity, and remediation guidance arrive intact
3. Tenant isolation is enforced; verify findings from Tenant A cannot route to Tenant B's ticketing queue
4. Deduplication policy is documented; verify duplicate findings are handled per policy
5. Sensitive data redaction is applied before export to third-party systems
6. Finding delivery failure is detected and logged; verify retry or escalation occurs

> **See also:** APTS-TP-012 (client data classification framework and provider data handling)

---

> **See also:** [APTS-RP-A01: Automated Finding Authenticity Verification](../appendix/Advisory_Requirements.md#apts-rp-a01-automated-finding-authenticity-verification-advisory) — an advisory practice for screening agent-generated findings for fabricated evidence, hallucinated vulnerabilities, and severity misclassification before human review. Candidate for tier-gated inclusion in v0.2.0.
