# Evidence Request Checklist

Informative Appendix (non-normative)

For a time-boxed 30-minute or 2-hour vendor screen, see the [Quick Vendor Review Checklist](Quick_Vendor_Review_Checklist.md).

This appendix gives customers, procurement teams, and security reviewers a simple checklist of evidence to request when evaluating an autonomous pentest platform against APTS.

It is intended to be practical and lightweight. It does not create new requirements.

## How to Use This Checklist

Use this appendix when you want a short list of concrete artifacts to request from a platform operator.

Recommended workflow:

1. pick the domains most relevant to your environment
2. ask for the sample artifacts listed below
3. review whether the artifacts are complete, current, and internally consistent
4. use the [Vendor Evaluation Guide](Vendor_Evaluation_Guide.md) and [Customer Acceptance Testing](Customer_Acceptance_Testing.md) appendices if you need deeper validation

## Minimum Evidence Pack

If you only want a short first-pass review, request these five artifacts first:

- one sample Rules of Engagement document or machine-readable RoE file
- one sample kill switch or safety-control demonstration record
- one sample audit log or evidence record tied to a finding
- one sample customer report with remediation guidance
- one statement of platform version, claimed tier, and model/provider disclosure

## Domain-by-Domain Checklist

### Scope Enforcement (SE)

Request:

- one sample Rules of Engagement artifact
- one example of scope validation or blocked out-of-scope action logging
- one example of deny-list or critical-asset protection configuration

Quick checks:

- are targets, time boundaries, and restrictions explicit
- can the operator show how scope is enforced before actions are executed
- are production or sensitive assets clearly protected

### Safety Controls (SC)

Request:

- one kill switch demonstration record or operator walkthrough
- one sample rate-limit or impact-control configuration
- one sample rollback or cleanup record for a reversible action

Quick checks:

- can the platform be stopped quickly and reliably
- are rate limits and safety thresholds documented
- is there evidence that cleanup or rollback is handled deliberately

### Human Oversight (HO)

Request:

- one sample approval record for a higher-risk action
- one sample escalation or alert record
- one example of the authority/approval workflow used in practice
- one sample human review record (see [Human Review Record Template](Human_Review_Record_Template.md)) for a critical finding that required explicit reviewer approval

Quick checks:

- is it clear who can approve which actions
- do approval-required actions pause rather than continue silently
- are escalation paths visible and reviewable
- can the operator show who approved a critical finding and what evidence they checked

### Graduated Autonomy (AL)

Request:

- one document or configuration showing the autonomy level in use
- one example of how boundaries or approval behavior change by autonomy level
- one sample assessment, review, or signoff record for the selected autonomy mode

Quick checks:

- is the autonomy level explicit rather than implied
- do controls become stricter as autonomy increases
- is there evidence that the operator reviewed the level selection

### Auditability & Reproducibility (AR)

Request:

- one sample structured audit log
- one sample evidence artifact with a cryptographic hash
- one sample chain-of-custody or provenance record

Quick checks:

- can a finding be traced back to raw evidence
- are timestamps and identifiers consistent
- is evidence integrity protected in a way a reviewer can inspect

### Manipulation Resistance (MR)

Request:

- one example of how target content is separated from trusted instructions
- one example of blocked scope widening, redirect, or unsafe follow-on action
- one summary of the platform's manipulation-resistance controls or tests

Quick checks:

- can the operator explain how hostile target content is treated as untrusted
- are unsafe redirects or target-suggested scope changes blocked
- is there evidence that these controls are tested, not just described

### Third-Party & Supply Chain Trust (TP)

Request:

- one current model/provider disclosure
- one dependency inventory or SBOM sample
- one short description of data retention or data isolation controls

Quick checks:

- does the operator know exactly which models and providers are in use
- is there a visible dependency review process
- can the operator explain how customer data is isolated and later deleted

### Reporting (RP)

Request:

- one sample report with findings and remediation guidance
- one sample finding with raw evidence or evidence references
- one explanation of confidence scoring or validation status

Quick checks:

- can the report be understood by both technical and non-technical readers
- does each finding tie back to evidence
- is confidence communicated separately from severity

## Simple Reviewer Questions

For each artifact you receive, ask:

- is this current and representative of real platform use
- does it match the platform tier and deployment the operator is claiming
- can this artifact be cross-checked against another artifact in the package
- does it show actual implementation, not just policy language

## Notes

This checklist is intentionally simple. It is meant to help reviewers ask for the right artifacts quickly before doing a deeper review.