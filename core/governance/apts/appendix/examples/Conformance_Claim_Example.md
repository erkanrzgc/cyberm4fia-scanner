# Conformance Claim Example

Informative Appendix Example (non-normative)

This example shows how a platform operator might complete the [Conformance Claim Template](../Conformance_Claim_Template.md). The organization, platform, evidence identifiers, and dates are fictional. This example is intentionally partial: it illustrates one possible level of detail and traceability without implying that every operator must use the same wording, evidence structure, or publication format.

Use this example with the [Conformance Claim Template](../Conformance_Claim_Template.md), [Conformance Claim Schema](../Conformance_Claim_Schema.md), [Checklists](../Checklists.md), and [Evidence Package Manifest](../Evidence_Package_Manifest.md).

---

## Conformance Claim

| Field | Example Value |
|-------|---------------|
| **Organization Name** | ExampleCorp Security Services |
| **Platform Name** | Example Autonomous Testing Platform |
| **Operator Type** | Vendor-operated SaaS platform |
| **Platform Version** | 2026.04.1 |
| **APTS Version** | v0.1.0 |
| **Claimed Tier** | Tier 2 (Verified) |
| **Claim Date** | 2026-04-20 |
| **Assessment Method** | Internal review independent of the implementation team |
| **Contact** | security-assurance@example.invalid |

---

## Scope of Claim

This fictional claim covers the Example Autonomous Testing Platform when operated by ExampleCorp Security Services for customer-authorized web application and API testing engagements.

Included deployment modes:

- Vendor-hosted SaaS control plane
- Customer-approved cloud scanner workers
- L1 Assisted, L2 Supervised, and L3 Semi-Autonomous operation

Excluded from this claim:

- L4 Autonomous operation
- Customer self-hosted worker deployments
- Wireless, physical, social engineering, and destructive testing modules
- Any engagement without a machine-readable Rules of Engagement record

---

## Foundation Model Disclosure (APTS-TP-021)

| Field | Example Value |
|-------|---------------|
| **Provider** | ExampleAI Provider |
| **Model Family** | Example Reasoning Model |
| **Model Version or Identifier** | `example-reasoning-2026-03-15` |
| **Release Date** | 2026-03-15 |
| **Fine-Tunes or Adapters** | None |
| **Capability Baseline Reference** | `capability-baseline-2026-04-01.pdf` |
| **Last Re-attestation Date (APTS-TP-022)** | Initial claim |
| **Next Scheduled Review** | 2026-07-20 or earlier on model substitution |

ExampleCorp does not permit runtime model substitution outside the approved model allowlist. Emergency model changes require security review, audit logging, and customer notification when they affect active engagements.

---

## Domain Summary

The table below is illustrative. A real claim can use the current requirement counts for the claimed APTS version and attach the completed checklist used during assessment.

| Domain | Requirements at Claimed Tier | Met | Example Notes |
|--------|------------------------------|-----|---------------|
| Scope Enforcement (SE) | Tier 1 + Tier 2 applicable requirements | All applicable tier requirements met | RoE validation, deny lists, temporal enforcement, scope refresh, and credential lifecycle controls reviewed |
| Safety Controls (SC) | Tier 1 + Tier 2 applicable requirements | All applicable tier requirements met | Kill switch, rate limiting, cumulative impact thresholds, rollback, and platform health monitoring demonstrated in staging |
| Human Oversight (HO) | Tier 1 + Tier 2 applicable requirements | All applicable tier requirements met | Approval gates, escalation paths, stale approval expiry, and reviewer qualification records sampled |
| Graduated Autonomy (AL) | Tier 1 + Tier 2 applicable requirements | All applicable tier requirements met | L1-L3 operating modes documented; L4 excluded from this claim |
| Auditability (AR) | Tier 1 + Tier 2 applicable requirements | All applicable tier requirements met | Decision logs, evidence hashes, model version logs, and tamper-evident storage reviewed |
| Manipulation Resistance (MR) | Tier 1 + Tier 2 applicable requirements | All applicable tier requirements met | Prompt/data separation, scope anchor validation, adversarial input handling, and red-team test summaries reviewed |
| Supply Chain Trust (TP) | Tier 1 + Tier 2 applicable requirements | All applicable tier requirements met | Provider due diligence, dependency inventory, tenant isolation, retention, and deletion evidence reviewed |
| Reporting (RP) | Tier 1 + Tier 2 applicable requirements | All applicable tier requirements met | Finding validation, confidence scoring, evidence integrity, and downstream export controls sampled |
| **Total** | Tier 2 cumulative requirements | All applicable tier requirements met | Completed checklist reference: `apts-checklist-tier2-examplecorp-2026-04-20.xlsx` |

> **Reminder:** APTS requires 100% of requirements at the claimed tier to be met. Partial credit is not awarded.

---

## Advisory Requirements (Optional)

| Advisory Requirement | Implemented | Example Notes |
|---------------------|-------------|---------------|
| APTS-TP-A01 external tool connector trust boundaries | Yes | MCP-style connector configuration is isolated per customer engagement and reviewed before enablement |
| APTS-HO-A01 out-of-band kill switch authority | Partial | Documented for production engagements; not enabled for all non-production engagements |

Advisory practices are not counted toward the claimed tier. Clear labels for partial advisory implementation help customers distinguish advisory practices from tier-required controls.

---

## Evidence Availability

ExampleCorp states that the following evidence is available to customers under NDA or through the customer trust portal:

- Completed APTS Tier 2 checklist with per-requirement status
- Sample Rules of Engagement validation report
- Kill switch demonstration recording from staging
- Sample audit log excerpt with sensitive values redacted
- Evidence package manifest for one representative finding
- Human review record for one critical finding
- Model version and capability baseline record
- Data retention and deletion procedure summary
- Independent internal review sign-off memo

Evidence package references:

| Evidence ID | Description | Related APTS Areas |
|-------------|-------------|--------------------|
| `EVID-SE-001` | RoE schema validation and signed scope record | APTS-SE-001, APTS-SE-004, APTS-SE-015 |
| `EVID-SC-009` | Kill switch test recording and result log | APTS-SC-009, APTS-HO-008, APTS-AR-001 |
| `EVID-AR-010` | Tamper-evident audit log hash sample | APTS-AR-010, APTS-AR-012 |
| `EVID-RP-002` | Human review record for critical finding | APTS-RP-002, APTS-HO-010 |
| `EVID-TP-021` | Foundation model disclosure and capability baseline | APTS-TP-021, APTS-TP-022 |

---

## Declared Scope Boundaries

ExampleCorp declares the following boundaries for this fictional claim:

- The platform does not support L4 Autonomous operation under this claim
- Customer-hosted workers are excluded because deployment hardening is customer-controlled
- Production testing requires explicit RoE authorization and Tier 2 safety controls
- Scanner workers cannot initiate lateral movement outside the approved target inventory
- Credential collection is disabled by default and requires customer-approved handling rules

These boundaries describe the claim's scope. They do not remove requirements that remain applicable to the claimed deployment.

---

## Sample Requirement-Level Traceability

This abbreviated table shows one way to connect the high-level claim to requirement-level evidence. A real claim can replace these fictional evidence IDs with the operator's completed checklist outputs and evidence package references.

| Requirement | Example Status | Evidence Reference | Reviewer Note |
|-------------|----------------|--------------------|---------------|
| APTS-SE-001 | Met | `EVID-SE-001` | RoE schema validation and signature checks were sampled for one staging and one production engagement |
| APTS-SC-009 | Met | `EVID-SC-009` | Kill switch demonstration showed graceful termination followed by forced stop on timeout |
| APTS-RP-002 | Met | `EVID-RP-002` | Critical finding review record included reviewer identity, decision, timestamp, and evidence references |

---

## Example Customer Interpretation

A customer reviewing this claim should treat it as an operator-provided statement, not a certification. Reasonable follow-up steps include:

1. Compare the claim to the completed [Checklists](../Checklists.md) for the claimed tier
2. Request a small evidence pack using the [Evidence Request Checklist](../Evidence_Request_Checklist.md)
3. Review one representative [Evidence Package Manifest](../Evidence_Package_Manifest.md)
4. Ask for a vendor demonstration of behavioral controls such as kill switch and scope enforcement
5. Check whether the evidence shows that network actions were checked against the active RoE
6. Confirm that approval authorities, default-deny behavior, and escalation paths are documented
7. Verify that one reported finding can be traced from action to report with preserved evidence
8. Use [Customer Acceptance Testing](../Customer_Acceptance_Testing.md) for higher-assurance deployments

---

## Revision History

| Date | Version | Change |
|------|---------|--------|
| 2026-04-20 | 0.1 | Initial fictional example claim for APTS v0.1.0 |

---

> **Disclaimer:** This example is fictional and non-normative. It does not certify any real platform, create an APTS certification process, or modify APTS requirements. See the [Introduction](../../Introduction.md#compliance-tiers) for the APTS verification model.
