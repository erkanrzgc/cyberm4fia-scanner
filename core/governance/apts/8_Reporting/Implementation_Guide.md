# Reporting: Implementation Guide

Practical guidance for implementing APTS Reporting requirements. Each section provides a brief implementation approach, key considerations, and common pitfalls.

> **Note:** This guide is informative, not normative. Recommended defaults and example values are suggested starting points; the [Reporting README](README.md) contains the authoritative requirements. Where this guide and the README differ, the README governs.

---

## APTS-RP-001: Evidence-Based Finding Validation

**Implementation:** Attach raw technical evidence (logs, screenshots, payloads, network traces) to every finding. Clearly demarcate any AI-generated summaries or analysis as distinct from raw evidence.

**Key Considerations:**
- Evidence must be reproducible by the client and independent reviewers
- Storage should support secure chain-of-custody for forensic purposes

**Common Pitfalls:**
- Including only AI summaries without raw technical data
- Mixing evidence with unsubstantiated interpretations

---

## APTS-RP-002: Finding Verification and Human Review Pipeline

**Implementation:** Re-execute all Critical and High findings before report finalization using automated workflows. Tag each finding as "Confirmed" or "Unconfirmed" with reproduction timestamp and methodology.

**Key Considerations:**
- Automation must simulate human exploitation paths, not just tool-based detection
- Unconfirmed findings require escalation for manual review

**Common Pitfalls:**
- Assuming initial detection is sufficient without re-verification
- Automating reproduction without documenting the specific steps used

---

## APTS-RP-003: Confidence Scoring with Auditable Methodology

**Implementation:** Assign 0-100% confidence scores based on measurable factors (evidence completeness, reproduction success, tool consistency, manual verification). Document the scoring model used in the assessment methodology.

**Key Considerations:**
- Confidence scoring must be independent from severity/impact ratings
- Scoring methodology should be transparently disclosed to clients

**Common Pitfalls:**
- Conflating confidence with severity or criticality
- Using subjective confidence scores without documented factors

**Confidence Scoring Methodology:**

A recommended confidence scoring approach uses weighted factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| Evidence quality | 30% | Direct evidence (exploit success) scores 100%; indirect evidence (version banner match) scores 50%; inference only scores 20% |
| Independent confirmation | 25% | Confirmed by 2+ independent methods scores 100%; single method scores 50% |
| Environmental factors | 20% | Default configuration scores 100%; custom/hardened environment scores 60% |
| Historical accuracy | 15% | Platform's historical true positive rate for this vulnerability class |
| Recency | 10% | Evidence gathered within 1 hour scores 100%; decays to 50% after 24 hours |

**Confidence = Sum(factor_score * weight)**

Thresholds: Confirmed (>= 90%), High Confidence (70-89%), Medium Confidence (50-69%), Low Confidence (< 50%).

Findings below 50% confidence SHOULD be flagged as "Unconfirmed" and excluded from the executive summary unless the customer requests full disclosure.

---

## APTS-RP-004: Finding Provenance Chain

**Implementation:** Maintain a cryptographically-signed chain linking each finding to its discovery method, tool output, and operator actions. Use timestamped logs with digital signatures for forensic accountability.

**Key Considerations:**
- Provenance data must be immutable and timestamped
- Chain should include tool version, configuration, and execution parameters

**Common Pitfalls:**
- Losing tool output or discovery artifacts mid-assessment
- Failing to document who verified each finding and when

**Implementation Aid:** See the [Evidence Package Manifest appendix](../appendix/Evidence_Package_Manifest.md) for an illustrative machine-readable structure that links one finding to its raw artifacts, provenance events, and review state.

---



## APTS-RP-005: Cryptographic Evidence Chain Integrity

**Implementation:** Bind all evidence to the discovery chain using SHA-256 hashing of raw artifacts. Provide hash values in the report with instructions for client-side verification against original evidence files.

**Key Considerations:**
- Hashing must cover complete artifacts (logs, captures, transcripts)
- Include hash computation methodology in technical appendix

**Common Pitfalls:**
- Hashing only summaries instead of raw data
- Failing to provide verification instructions for clients

---

## APTS-RP-006: False Positive Rate Disclosure

**Implementation:** Document and disclose the methodology for identifying and filtering false positives. Include per-severity false positive rates measured across the assessment (for example, "2 of 50 Medium findings verified as false positives").

**Key Considerations:**
- FP rates should be calculated and reported per severity level
- Methodology must explain how false positives were identified

**Common Pitfalls:**
- Omitting FP metrics from reports entirely
- Reporting inflated accuracy without disclosing how false positives were determined

---

## APTS-RP-007: Independent Finding Reproducibility

**Implementation:** Designate reviewers independent from the automated tool chain to manually reproduce a statistically significant sample of Critical findings (minimum 80% coverage).

**Key Considerations:**
- Sample size should be defensible (for example, 100% for <5 findings, 80% for larger sets)
- Validation should occur before report delivery to allow remediation

**Common Pitfalls:**
- Validating findings after initial report without time for remediation
- Using the same operator who ran tools for validation

---

## APTS-RP-008: Vulnerability Coverage Disclosure

**Implementation:** Provide a coverage matrix mapping tested vulnerability classes to CWE/OWASP, clearly marking tested/excluded/partially-tested areas. Explain scope limitations and why certain vectors were excluded.

**Key Considerations:**
- Coverage should account for architecture constraints (for example, "client-side testing excluded per scope")
- Matrix should enable clients to assess residual risk from untested areas

**Common Pitfalls:**
- Implying complete coverage when only a subset of vulnerability classes were tested
- Failing to explain why certain CWEs were out-of-scope

---

## APTS-RP-009: False Negative Rate Disclosure and Methodology

**Implementation:** Document the methodology used to assess false negative risk. Publish per-vulnerability-class FN rate estimates based on control gaps, tool detection limits, and known blind spots.

**Key Considerations:**
- FN rates should be disclosed for each major vulnerability class
- Methodology should explain benchmarking approach and limitations

**Common Pitfalls:**
- Omitting FN estimates or providing only a single aggregate figure
- Failing to explain which vulnerability classes have higher FN risk

---

## APTS-RP-010: Detection Effectiveness Benchmarking

**Implementation:** Conduct quarterly benchmarks against controlled vulnerable environments (for example, DVWA, WebGoat) to validate detection accuracy. Document and trend results across tool versions and assessment methodologies.

**Key Considerations:**
- Benchmarks must use consistent, reproducible vulnerable targets
- Results should inform improvements to detection rules and methodologies

**Common Pitfalls:**
- Running benchmarks inconsistently or with varying targets
- Failing to correlate benchmark results with real assessment performance

---

## APTS-RP-011: Executive Summary and Risk Overview

**Implementation:** Provide a non-technical executive summary covering risk posture, overall findings distribution, coverage achieved, and key remediation priorities. Include context for risk-based decision making without requiring technical expertise.

**Key Considerations:**
- Summary should be actionable for C-level stakeholders
- Include trend data and comparison to industry baselines where available

**Common Pitfalls:**
- Writing executive summaries that are too technical
- Omitting business-context framing of findings

---

## APTS-RP-012: Remediation Guidance and Prioritization

**Implementation:** For each finding, provide step-by-step remediation guidance mapped to effort categories (quick-fix, short-term, long-term). Prioritize findings by risk and implementability to guide resource allocation.

**Key Considerations:**
- Remediation steps should be specific to the assessed environment
- Effort estimates should account for organizational factors (for example, change control requirements)

**Common Pitfalls:**
- Generic remediation advice that doesn't address specific context
- Prioritization by severity alone without considering effort or business impact

---

## APTS-RP-013: Engagement SLA Compliance Reporting

**Implementation:** Document engagement timeline, any interruptions or scope changes, percentage of planned scope tested, and areas left untested or partially tested with reasons documented.

**Key Considerations:**
- Timeline should show actual compared to planned dates for phased assessments
- Scope changes must be documented with impact on coverage

**Common Pitfalls:**
- Omitting scope gaps from reports
- Failing to explain why certain areas were not completed

---

## APTS-RP-014: Trend Analysis for Recurring Engagements

**Implementation:** For repeat clients, compare findings across engagements to identify new vulnerabilities, resolved issues, and persistent findings. Include trend metrics (closure rate, mean time to remediation, recurrence rate).

**Key Considerations:**
- Trend analysis should enable clients to assess remediation effectiveness
- Persistent findings may indicate systemic control issues requiring deeper investigation

**Common Pitfalls:**
- Treating each engagement as independent without cross-engagement analysis
- Failing to investigate reasons why findings persist across multiple assessments

---

## APTS-RP-015: Downstream Finding Pipeline Integrity

**Implementation:** Maintain data fidelity through all post-assessment processes: deduplication logic, tenant isolation in multi-client environments, delivery tracking, and audit logs. Implement cryptographic signing for final deliverables.

**Key Considerations:**
- Deduplication must preserve original evidence and discovery context
- Delivery logs should provide proof of integrity to recipients

**Common Pitfalls:**
- Losing original discovery context during deduplication
- Failing to verify tenant isolation in multi-tenant assessment platforms
- Lack of tamper-evident controls on final report deliverables

---

## Advisory Practice Implementation Guidance

### APTS-RP-A01: Automated Finding Authenticity Verification

> This section provides implementation guidance for the advisory practice [APTS-RP-A01](../appendix/Advisory_Requirements.md#apts-rp-a01-automated-finding-authenticity-verification-advisory). It is not required for conformance at any tier.

**Implementation:** Deploy an independent verification step that screens every finding for fabricated evidence, hallucinated vulnerabilities, and severity misclassification before the finding enters the human review pipeline. The verification mechanism must not share context or state with the discovering agent.

**Architecture Pattern — Independent Finding Judge:**

A proven pattern is to implement the verifier as a separate "Finding Judge" that receives only the finding record, associated evidence artifacts (PoC scripts, HTTP request/response pairs, tool output), and the target context. The judge evaluates each finding against several checks:

1. **PoC authenticity check**: Static analysis of proof-of-concept scripts for hardcoded output, absence of network calls, and output strings that match the "evidence" verbatim without any actual target interaction.
2. **Evidence-claim consistency check**: Cross-reference the claimed vulnerability type against the raw evidence. SQL injection claims need SQL injection indicators; XSS claims need evidence of script execution.
3. **Severity calibration check**: Evaluate whether the evidence supports the assigned severity. A Critical finding backed only by an informational disclosure is a severity mismatch.
4. **Design-intent check**: Flag findings that describe intended application behavior (public API keys designed for client-side use, CORS headers intentionally set for broad access, documented public endpoints).

The judge classifies each finding as VERIFIED, FLAGGED, or REJECTED, with a structured log entry explaining the decision.

**Calibrated Confidence Thresholds:**

For finding types where evidence quality varies, implement calibrated confidence ceilings. For example, email injection findings without rendering verification (confirming the injected content is actually rendered by an email client) should be assigned a confidence ceiling below the "Confirmed" threshold, ensuring they are flagged for human review regardless of other evidence quality.

**Key Considerations:**
- The verifier must be architecturally independent of the discovering agent. If both are LLM-based, they must use separate inference calls with no shared state.
- The verifier should err toward FLAGGED (sending to human review) rather than REJECTED (dropping the finding), to avoid suppressing genuine findings.
- For multi-agent or swarm architectures, the verifier should process findings from all agents through a single pipeline to ensure consistent integrity standards.
- Verification adds latency to the finding pipeline. For time-sensitive engagements, consider running verification in parallel with other post-processing steps rather than as a sequential gate.

**Common Pitfalls:**
- Running the verifier in the same LLM context as the discovering agent, which allows the agent's reasoning to influence the verification outcome
- Implementing only a "does the PoC run" check without examining whether the PoC actually contacts the target
- Treating all REJECTED findings as false positives without logging — some may indicate a genuine vulnerability that the agent described poorly, and the rejection log helps identify patterns for agent improvement
- Over-reliance on the verifier as a replacement for human review; the verifier is a pre-filter, not a substitute for APTS-RP-002

---

## Implementation Roadmap

**Tier 1 (implement before any autonomous pentesting begins):**
RP-006 (false positive rate disclosure), RP-008 (vulnerability coverage disclosure), RP-011 (executive summary and risk overview).

Start with RP-011 (executive summary) and RP-008 (coverage disclosure). Customers need these in every report. Add RP-006 (false positive disclosure) to establish trust in findings.

**Tier 2 (implement within first 3 engagements):**
RP-001 (evidence-based finding validation), RP-002 (automated reproduction of critical findings), RP-003 (confidence scoring), RP-004 (finding provenance chain), RP-005 (cryptographic evidence integrity), RP-009 (false negative rate disclosure), RP-012 (remediation guidance), RP-013 (engagement SLA compliance), RP-014 (trend analysis, SHOULD), RP-015 (downstream pipeline integrity, SHOULD).

Prioritize RP-001 and RP-002 (evidence and reproduction) first. Findings without evidence are worthless. Then add RP-003 and RP-004 (confidence scoring, provenance) for auditability, and RP-005 (cryptographic integrity) for tamper-proof evidence chains.

**Tier 3 (implement based on assessment maturity):**
RP-007 (independent finding validation during assessment), RP-010 (detection effectiveness benchmarking, SHOULD).
