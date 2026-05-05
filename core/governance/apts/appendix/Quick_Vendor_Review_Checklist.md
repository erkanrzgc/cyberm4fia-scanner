# Quick Vendor Review Checklist

Informative Appendix (non-normative)

This checklist gives customers, CISOs, procurement teams, and security reviewers a short path for screening autonomous pentesting platform operators before a deeper APTS review. It complements the [Vendor Evaluation Guide](Vendor_Evaluation_Guide.md), [Evidence Request Checklist](Evidence_Request_Checklist.md), [Checklists](Checklists.md), and [Customer Acceptance Testing](Customer_Acceptance_Testing.md). It does not replace the full APTS requirements or create a certification process.

Use it when you need to decide how much additional review is warranted:

- **30-minute screen:** identify obvious gaps and decide whether to continue
- **2-hour review:** inspect the minimum evidence needed for a procurement or risk decision
- **Full review:** perform a deeper APTS-aligned assessment for higher-risk deployments

---

## Before the Review

Collect these basics from the operator:

| Item | What to Ask For | Why It Matters |
|------|-----------------|----------------|
| Claimed APTS tier | Tier 1, Tier 2, Tier 3, or no claim | Sets the review depth and expected evidence |
| APTS version and claim date | Version of APTS used and date the claim was last reviewed | Helps identify stale or generic claims |
| Assessment method | Self-assessment, independent internal review, or third-party assessment | Clarifies who reviewed the claim and what assurance it provides |
| Platform version | Product, service, or worker version reviewed | Prevents evidence for one version from being applied to another |
| Deployment model | SaaS, managed service, on-premises, hybrid, customer-hosted workers | Determines scope, tenant isolation, and customer responsibility boundaries |
| Supported autonomy levels | L1 Assisted through L4 Autonomous | Determines human oversight and safety expectations |
| Intended targets | Non-production, production, critical systems, APIs, cloud, client-side agents | Determines safety, scope, and evidence expectations |
| Evidence availability | Completed checklist, conformance claim, sample logs, demos, reports | Determines whether claims can be verified |

---

## 30-Minute Screen

Use this screen to decide whether the operator is ready for deeper review.

| Question | Acceptable Signal | Red Flag |
|----------|-------------------|----------|
| Which APTS tier do you claim, if any? | Clear tier statement or clear statement that no APTS conformance is claimed | Vague "APTS-aligned" statement with no tier, scope, or evidence |
| Can you provide a completed APTS checklist? | Completed [Checklists](Checklists.md) for the claimed tier, or a mapped internal assessment for first-pass screening only | No per-requirement mapping |
| How do you ingest and enforce Rules of Engagement? | Machine-readable RoE, validation, pre-action checks, audit trail | Scope handled manually or only by operator policy |
| Can you demonstrate a kill switch? | Recorded or live demo showing stop behavior and audit record | No demo, no timing expectation, or unclear authority |
| How are findings validated before reporting? | Reproduction, confidence scoring, and human review for critical findings | Findings reported directly from model output without validation |
| What evidence is available for one sample finding? | Evidence package with hashes, provenance, redaction log, and report export link | Screenshots or summaries only, no raw artifacts or provenance |
| How are customer credentials and discovered secrets handled? | Lifecycle, rotation/revocation, retention, and redaction policy | Long-lived credentials, unclear ownership, or no disposal evidence |
| Which foundation models and providers are used? | Exact model identifiers, provider trust review, change tracking | "Latest model" with no versioning or change process |
| What happens if testing causes unintended impact? | Thresholds, escalation, rollback, incident response, customer notification | No impact thresholds or incident path |
| Are agents deployed in customer infrastructure? | Install/remove process, permissions, update path, and RoE coverage | Persistent agents without clear removal or boundary controls |

### 30-Minute Decision

| Result | Suggested Next Step |
|--------|---------------------|
| Multiple red flags | Pause procurement or request remediation before deeper review |
| Some incomplete answers | Continue only with targeted evidence requests |
| Clear answers with evidence | Move to the 2-hour review or full review based on risk |

---

## 2-Hour Review

Use this review when the 30-minute screen passes and the engagement has moderate risk. Treat the result as triage or conditional procurement input unless none of the full review triggers below apply.

### 2-Hour Evidence Pack

Ask for a small evidence pack before scheduling detailed demos. This pack is a prioritized subset of the broader [Evidence Request Checklist](Evidence_Request_Checklist.md):

| Evidence | Related APTS Areas | Review Focus |
|----------|--------------------|--------------|
| Completed checklist for claimed tier | All domains | Does every claimed requirement have status and evidence? |
| [Conformance Claim Template](Conformance_Claim_Template.md) or equivalent statement | Introduction, conformance model | Is claim scope, assessment method, APTS version, platform version, and claim date clear? |
| Sample Rules of Engagement record | Scope Enforcement | Is scope machine-readable and enforced before actions? |
| Kill switch test evidence | Safety Controls, Human Oversight, Auditability | Is stop behavior demonstrated and logged? |
| Sample audit log excerpt | Auditability | Can actions, decisions, actors, timestamps, and outcomes be traced? |
| Sample evidence package for one finding | Reporting, Auditability | Are raw artifacts, hashes, provenance, review, and redaction linked? |
| Human review record for a critical finding | Human Oversight, Reporting | Was the reviewer qualified and was the decision recorded? |
| Model/provider disclosure | Supply Chain Trust, Auditability | Are model identifiers, provider review, and change controls documented? |
| Data retention and deletion summary | Supply Chain Trust, Scope Enforcement | Are customer data and credentials retained and deleted according to policy? |
| Incident response and notification process | Safety Controls, Supply Chain Trust | Are customer notification triggers and timelines documented? |

### Evidence Quality Checks

For each artifact, verify that it is current, representative of the reviewed deployment mode and autonomy level, and cross-checkable against another artifact such as an audit log, checklist row, evidence manifest, or demonstration recording. Sanitized demos and marketing summaries are useful for orientation, but they are not substitutes for reviewable evidence when the deployment is high risk.

Confirm exclusions and shared-responsibility boundaries explicitly, especially for SaaS, on-premises, hybrid, and customer-hosted worker deployments. Customer responsibilities can materially affect the risk decision.

### Suggested 2-Hour Agenda

| Time | Activity |
|------|----------|
| 0-15 minutes | Confirm claimed tier, deployment model, autonomy level, and excluded modes |
| 15-35 minutes | Review Rules of Engagement handling and pre-action scope enforcement |
| 35-55 minutes | Review kill switch, thresholds, rollback, and escalation evidence |
| 55-75 minutes | Trace one sample finding from discovery to evidence package to report export |
| 75-95 minutes | Review human approval, reviewer qualification, and critical-finding validation |
| 95-110 minutes | Review model/provider disclosure, data retention, and tenant isolation |
| 110-120 minutes | Record decision, open questions, and required follow-up evidence |

---

## Full Review Triggers

Move beyond the quick review when any of these conditions apply:

- The platform will test production or critical systems
- The operator claims Tier 2 or Tier 3 conformance for regulated environments
- The deployment uses L3 Semi-Autonomous or L4 Autonomous operation
- The platform deploys agents or workers inside customer infrastructure
- The engagement may encounter sensitive data, credentials, or multi-tenant systems
- The customer needs audit evidence for regulators, insurers, or internal governance
- The 30-minute or 2-hour review identifies unresolved red flags

For full review, use the [Vendor Evaluation Guide](Vendor_Evaluation_Guide.md), per-tier [Checklists](Checklists.md), and optional [Customer Acceptance Testing](Customer_Acceptance_Testing.md).

---

## Decision Record Template

| Field | Notes |
|-------|-------|
| Operator reviewed | _[Name]_ |
| Platform/version | _[Name and version]_ |
| APTS version reviewed | _[Version, for example v0.1.0]_ |
| Claim date | _[YYYY-MM-DD]_ |
| Assessment method | _[Self-assessment / independent internal review / third-party assessment]_ |
| Claimed APTS tier | _[Tier or no claim]_ |
| Deployment model reviewed | _[SaaS / managed service / on-premises / hybrid]_ |
| Autonomy levels reviewed | _[L1-L4]_ |
| Evidence received | _[List artifact IDs or links]_ |
| Red flags identified | _[List or "None"]_ |
| Conditions or exceptions | _[Required remediations or limitations]_ |
| Review decision | _[Proceed / proceed with conditions / pause / reject]_ |
| Next review trigger | _[Date, major platform change, incident, autonomy level change]_ |

---

## Common Red Flags

- The operator cannot state the claimed APTS tier or claim scope
- Scope is enforced by policy or operator judgment only, not by pre-action checks
- The kill switch cannot be demonstrated in a controlled environment
- Critical findings are reported without human review or reproducible evidence
- Evidence packages contain summaries but no raw artifacts, hashes, or provenance
- Model versions and provider dependencies are described as "latest" or "proprietary" with no change log
- Customer credentials have unclear ownership, retention, rotation, or revocation procedures
- Customer-hosted agents have broad permissions or no documented removal path
- Incident notification timelines are undefined
- The operator treats APTS as a certification without explaining the assessment method

---

## Output of a Quick Review

A quick review typically produces one of four practical outcomes:

| Outcome | Meaning |
|---------|---------|
| Proceed | Evidence is sufficient for the current risk level |
| Proceed with conditions | The operator can proceed only after specific evidence or remediation is provided |
| Pause | Significant gaps require follow-up before procurement or deployment continues |
| Reject | The platform does not meet minimum safety, scope, or accountability expectations |

Document the decision, evidence reviewed, unresolved questions, and next review trigger. Revisit the decision when the operator changes deployment model, autonomy level, foundation model, safety controls, or incident response process.
