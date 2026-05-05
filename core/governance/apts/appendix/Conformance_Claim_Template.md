# Conformance Claim Template

Informative Appendix (non-normative)

For teams that also want to publish a structured companion artifact, see the [Conformance Claim Schema](Conformance_Claim_Schema.md) appendix.
For a completed fictional claim showing the expected level of detail and evidence traceability, see [Conformance Claim Example](examples/Conformance_Claim_Example.md).

This appendix provides an optional template for any platform operator who chooses to document their APTS conformance: vendors publishing claims to their customers, service providers standing behind a platform they operate for clients, and enterprise security teams running an internal autonomous pentest platform who want to surface their conformance in customer-facing trust documentation (trust center pages, security whitepapers, customer security questionnaires, or SOC 2 complementary user entity control narratives). Use of this template is entirely voluntary. There is no requirement to submit this claim to any organization, certification body, or third party. Platform operators may use this template as-is, adapt it to their own format, or choose not to publish a conformance claim at all.

---

## Conformance Claim

| Field | Value |
|-------|-------|
| **Organization Name** | _[Vendor, service provider, or enterprise operating the platform]_ |
| **Platform Name** | _[Product or platform name]_ |
| **Operator Type** | _[Vendor / Service provider / In-house enterprise platform]_ |
| **Platform Version** | _[Version evaluated]_ |
| **APTS Version** | v0.1.0 |
| **Claimed Tier** | _[Tier 1 / Tier 2 / Tier 3]_ |
| **Claim Date** | _[YYYY-MM-DD]_ |
| **Assessment Method** | _[Internal self-assessment / Independent internal review / Third-party assessment]_ |
| **Contact** | _[Name and email for inquiries]_ |

---

## Scope of Claim

_[Describe the platform configuration, deployment model (SaaS, on-premises, hybrid), and autonomy levels (L1-L4) covered by this claim. Note any modules, features, or deployment modes excluded from the assessment.]_

---

## Foundation Model Disclosure (APTS-TP-021)

This section is required for any tier claim. It captures the foundation model powering the agent runtime at the time of the claim and the capability baseline referenced by APTS-TP-021 and APTS-TP-022.

| Field | Value |
|-------|-------|
| **Provider** | _[for example, OpenAI, Anthropic, Google, Meta, self-hosted]_ |
| **Model Family** | _[for example, GPT-5, Claude Opus 4, Gemini 2]_ |
| **Model Version or Identifier** | _[Exact version string, not "latest"]_ |
| **Release Date** | _[YYYY-MM-DD]_ |
| **Fine-Tunes or Adapters** | _[List operator-applied fine-tunes or adapters, or "None"]_ |
| **Capability Baseline Reference** | _[Link or document ID for the documented capability baseline]_ |
| **Last Re-attestation Date (APTS-TP-022)** | _[YYYY-MM-DD, or "Initial claim"]_ |
| **Next Scheduled Review** | _[YYYY-MM-DD or trigger condition]_ |

_[If the platform supports model substitution at runtime, disclose each approved model in a separate row and identify which engagements use which model.]_

---

## Domain Summary

| Domain | Requirements at Claimed Tier | Met | Notes |
|--------|------------------------------|-----|-------|
| Scope Enforcement (SE) | _[count]_ | _[count]_ | |
| Safety Controls (SC) | _[count]_ | _[count]_ | |
| Human Oversight (HO) | _[count]_ | _[count]_ | |
| Graduated Autonomy (AL) | _[count]_ | _[count]_ | |
| Auditability (AR) | _[count]_ | _[count]_ | |
| Manipulation Resistance (MR) | _[count]_ | _[count]_ | |
| Supply Chain Trust (TP) | _[count]_ | _[count]_ | |
| Reporting (RP) | _[count]_ | _[count]_ | |
| **Total** | _[count]_ | _[count]_ | |

> **Reminder:** APTS requires 100% of requirements at the claimed tier to be met. Partial credit is not awarded.

---

## Advisory Requirements (Optional)

_[If the platform implements any advisory requirements (documented in the [Advisory Requirements](Advisory_Requirements.md) appendix), list them here. This is optional and provided as a differentiator for customers seeking additional assurance.]_

| Advisory Requirement | Implemented | Notes |
|---------------------|-------------|-------|
| _[ID and title]_ | _[Yes/No]_ | |

---

## Evidence Availability

_[Describe what evidence is available to customers upon request. Examples: completed APTS Checklists, kill switch demonstration recordings, sample audit logs, data destruction certificates, adversarial test reports. Platform operators are not required to share any evidence unless they choose to.]_

---

## Declared Scope Boundaries

_[Document any declared scope boundaries or architectural constraints where the platform's approach differs from the standard's recommended defaults. Examples: "Platform does not support L4 autonomous operation" or "Multi-tenant isolation uses namespace separation rather than dedicated infrastructure." This section describes deliberate design decisions, not implementation gaps.]_

---

## Supporting Evidence (Optional)

Platform operators may attach or append supporting evidence to this claim. Evidence pages are entirely optional and may be added, removed, or updated independently of the claim itself. Examples of evidence that platform operators may choose to include:

- Completed APTS Checklists with per-requirement status
- Kill switch demonstration recordings or test results
- Sample audit log excerpts (with sensitive data redacted)
- Data destruction certificates
- Adversarial test report summaries
- Architecture diagrams showing safety control integration
- Scope enforcement test results
- Incident response tabletop exercise records

Each evidence page should reference the requirement ID(s) it supports (for example, "Evidence for APTS-SC-009: Kill Switch") so that customers can trace evidence back to specific requirements.

_[Append evidence pages below this section as needed.]_

---

## Revision History

| Date | Version | Change |
|------|---------|--------|
| _[YYYY-MM-DD]_ | _[1.0]_ | _[Initial conformance claim]_ |

---

> **Disclaimer:** This conformance claim is an operator-provided assessment. See the [Introduction](../Introduction.md#compliance-tiers) for the APTS verification model. Customers may independently verify these claims using the [Vendor Evaluation Guide](Vendor_Evaluation_Guide.md) or the optional [Customer Acceptance Testing](Customer_Acceptance_Testing.md) appendix.
