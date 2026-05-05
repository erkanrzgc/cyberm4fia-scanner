# Third-Party & Supply Chain Trust

**Domain Prefix:** APTS-TP | **Requirements:** 22

This domain defines how an autonomous penetration testing platform selects, vets, and governs the third parties and supply-chain components it depends on: AI and LLM providers, cloud services, vulnerability intelligence feeds, SaaS tools, AI model provenance, and the handling, isolation, and eventual destruction of client data that flows through those dependencies. Supply Chain Trust exists because an autonomous pentest platform is almost never a self-contained artifact. Its decisions are shaped by upstream model updates, its evidence is often stored in third-party infrastructure, and its blast radius extends to whatever data those dependencies can see. A failure in an upstream provider (compromise, silent model change, retention violation, tenant bleed) can undo every other safety control the platform implements. Requirements in this domain govern provider vetting, model version pinning, API security, Service Level Agreement (SLA) and failover, breach notification, dependency inventory, residency and sovereignty, cloud hardening, vulnerability-feed governance, data classification and encryption, retention and certified destruction, multi-tenant isolation, tenant-breach notification, AI model provenance, and persistent memory and retrieval state.

This domain covers the trustworthiness and governance of the platform's upstream dependencies. Target-facing scope enforcement belongs to Scope Enforcement (SE), blast-radius classification to Safety Controls (SC), and the audit trail of provider events to Auditability (AR).

> For implementation guidance, see the [Implementation Guide](Implementation_Guide.md).

---

## Domain Overview

The 22 requirements in this domain fall into seven thematic groups:

| Group | Requirements | Purpose |
|---|---|---|
| **Provider vetting and governance** | APTS-TP-001, APTS-TP-002, APTS-TP-003, APTS-TP-004, APTS-TP-005 | Provider selection and vetting, model version pinning, API security, availability and SLA, provider incident response |
| **Dependency inventory and cloud security** | APTS-TP-006, APTS-TP-007, APTS-TP-008, APTS-TP-009 | Dependency inventory and supply-chain verification, data residency and sovereignty, cloud configuration and hardening, incident response and service continuity |
| **Vulnerability intelligence feeds** | APTS-TP-010, APTS-TP-011 | Feed selection and management, feed quality assurance and incident response |
| **Client data classification, encryption, and retention** | APTS-TP-012, APTS-TP-013, APTS-TP-014, APTS-TP-015, APTS-TP-016 | Client data classification, sensitive data discovery and handling, encryption and cryptographic controls, retention and secure deletion, destruction proof and certification |
| **Multi-tenant isolation and tenant-breach notification** | APTS-TP-017, APTS-TP-018 | Multi-tenant and engagement isolation, tenant breach notification |
| **AI model provenance and persistent state** | APTS-TP-019, APTS-TP-020 | Model provenance and training-data governance, persistent memory and retrieval-state governance |
| **Foundation model disclosure and re-attestation** | APTS-TP-021, APTS-TP-022 | Foundation model disclosure and capability baseline, re-attestation on material foundation model change |

### Requirement Index

| ID | Title | Classification |
|---|---|---|
| APTS-TP-001 | Third-Party Provider Selection and Vetting | MUST \| Tier 1 |
| APTS-TP-002 | Model Version Pinning and Change Management | MUST \| Tier 2 |
| APTS-TP-003 | API Security and Authentication | MUST \| Tier 1 |
| APTS-TP-004 | Provider Availability, SLA Management, and Failover | MUST \| Tier 2 |
| APTS-TP-005 | Provider Incident Response, Breach Notification, and Mid-Engagement Compromise | MUST \| Tier 1 |
| APTS-TP-006 | Dependency Inventory, Risk Assessment, and Supply Chain Verification | MUST \| Tier 1 |
| APTS-TP-007 | Data Residency and Sovereignty Requirements | SHOULD \| Tier 2 |
| APTS-TP-008 | Cloud Security Configuration and Hardening | MUST \| Tier 1 |
| APTS-TP-009 | Incident Response and Service Continuity Planning | MUST \| Tier 2 |
| APTS-TP-010 | Vulnerability Feed Selection and Management | MUST \| Tier 2 |
| APTS-TP-011 | Feed Quality Assurance and Incident Response | SHOULD \| Tier 2 |
| APTS-TP-012 | Client Data Classification Framework | MUST \| Tier 1 |
| APTS-TP-013 | Sensitive Data Discovery and Handling | MUST \| Tier 1 |
| APTS-TP-014 | Data Encryption and Cryptographic Controls | MUST \| Tier 1 |
| APTS-TP-015 | Data Retention and Secure Deletion | MUST \| Tier 2 |
| APTS-TP-016 | Data Destruction Proof and Certification | MUST \| Tier 3 |
| APTS-TP-017 | Multi-Tenant and Engagement Isolation | MUST \| Tier 2 |
| APTS-TP-018 | Tenant Breach Notification | MUST \| Tier 1 |
| APTS-TP-019 | AI Model Provenance and Training Data Governance | MUST \| Tier 2 |
| APTS-TP-020 | Persistent Memory and Retrieval State Governance | SHOULD \| Tier 2 |
| APTS-TP-021 | Foundation Model Disclosure and Capability Baseline | MUST \| Tier 1 |
| APTS-TP-022 | Re-attestation on Material Foundation Model Change | MUST \| Tier 2 |

### Conformance

A platform claims conformance with this domain by satisfying all MUST requirements at the compliance tier it targets. APTS defines three cumulative compliance tiers (Tier 1 Foundation, Tier 2 Verified, Tier 3 Comprehensive) in the [Introduction](../Introduction.md); a Tier 2 platform satisfies every Tier 1 TP requirement plus every Tier 2 TP requirement, and a Tier 3 platform satisfies all three tiers. SHOULD-level requirements are interpreted per RFC 2119.

Four appendix-only advisory requirements for this domain (APTS-TP-A01 Breach Notification and Regulatory Reporting, APTS-TP-A02 Privacy Regulation Compliance, APTS-TP-A03 Professional Liability and Engagement Agreements, APTS-TP-A04 External Tool Connector Trust Boundaries and Credential Isolation) are documented in the [Advisory Requirements appendix](../appendix/Advisory_Requirements.md). They are not required for conformance at any tier.

Every requirement in this domain includes a Verification subsection listing the verification procedures a reviewer uses to confirm implementation.

---

## APTS-TP-001: Third-Party Provider Selection and Vetting

**Classification:** MUST | Tier 1

**Applicability:** All platforms using external service providers (AI/LLM providers, SaaS platforms, infrastructure services).

### Requirement

Organizations MUST establish and document a vetting process for all external service providers before their use in autonomous pentest operations. The vetting process MUST assess security posture (SOC 2 Type II, recent penetration tests, incident history), data protection practices (encryption standards, retention policies, residency options, multi-tenancy controls), service reliability (Service Level Agreements (SLAs), disaster recovery, geographic redundancy), contractual terms (DPA, liability, breach notification per applicable regulatory timelines, audit rights, termination procedures), and compliance certifications (ISO 27001, SOC 2 Type II, GDPR, industry-specific). All deployed third-party services MUST have documented evaluation and approval.

**AI/LLM Provider-Specific Vetting:**

AI/LLM service providers MUST receive additional vetting covering model training data governance, data isolation between customers, prompt/response logging policies, and model versioning practices.

**Non-AI SaaS and Infrastructure Services:**

Non-AI SaaS platforms used in pentest operations (log storage, dashboards, analytics, collaboration tools) MUST be evaluated against the same core criteria. Compliance certifications MUST be verified for each platform, and data handling practices MUST be assessed before use.

### Verification

1. Sample provider review packs for at least 3 providers (or all providers if fewer than 3); verify each pack contains documented evaluation against the required vetting categories (security posture, data handling, contractual terms, incident response capability)
2. For each sampled provider, verify an explicit approval or denial decision is recorded with date, approver identity, and rationale
3. Verify each approved provider has a documented reevaluation date and that reevaluation has occurred within the documented cadence
4. Verify at least 10 security factors are evaluated per provider; fail any provider review missing a required vetting category
5. Verify denied providers are documented with denial rationale and that no platform component depends on a denied provider
6. Review the most recent reevaluation cycle for one provider; verify the reevaluation used current criteria and produced an updated approval decision

---


## APTS-TP-002: Model Version Pinning and Change Management

**Classification:** MUST | Tier 2

### Requirement

Organizations MUST implement version pinning for all AI models to enable change tracking, testing, and rollback. All models MUST have explicit version identifiers (semantic versioning). Specific versions MUST be specified in deployment requirements rather than using "latest." Model upgrades MUST follow a formal change management process with testing before production deployment. Rollback procedures MUST enable reversion to previous versions if issues are detected.

### Verification

- Find requirements file or lock file with model versions
- Verify specific versions specified (not "latest" or ranges)
- Check change log: model version changes documented
- Find rollback procedure documentation
- Verify testing before production deployment

> **See also:** APTS-AR-019 (AI/ML model change tracking and drift detection), APTS-TP-019 (AI model provenance and training data governance)

---

## APTS-TP-003: API Security and Authentication

**Classification:** MUST | Tier 1

### Requirement

All API calls to external providers MUST use strong authentication and encryption. Authentication MUST include secure credential storage (never in code or configuration), API key rotation on defined schedule, and monitoring for unusual API usage patterns. All communications MUST enforce TLS 1.2 minimum (TLS 1.3 preferred) with certificate validation and no downgrades. Mutual TLS MUST be used for service-to-service authentication where supported.

### Verification

- Audit provider API calls: verify authentication present
- Find API key storage: confirm secure (not in code)
- Check key rotation schedule: documented and executed?
- Verify TLS usage: test API calls with TLS inspection
- Check monitoring: API usage logs reviewed for anomalies?

> **See also:** APTS-TP-014 (secrets/credential management for provider API keys), APTS-SE-023 (credential and secret lifecycle governance for provider API keys).

---

## APTS-TP-004: Provider Availability, SLA Management, and Failover

**Classification:** MUST | Tier 2

### Requirement

Organizations MUST establish availability requirements for critical providers and implement SLA management with failover procedures to ensure operations continue during provider outages. Provider selection MUST include SLA verification (minimum 99.5% uptime). SLA requirements MUST be established and documented for cloud services, specifying uptime percentages, maximum latency, and response times for support. Service contracts MUST include explicit SLA clauses with penalties for breaches. Monitoring systems MUST continuously check provider availability with automated alerts for failures, with metrics tracked for uptime percentage and latency. SLA breaches MUST be recorded and remediation actions documented. Failover procedures MUST be documented and tested, with fallback providers identified for critical services.

### Verification

1. Locate the availability monitoring system; verify it checks provider health at the documented frequency
2. Review monitoring logs for the last 30 days; verify continuous monitoring with no gaps exceeding the documented check interval
3. Locate the failover procedure documentation; verify it names a fallback provider or degraded-mode behavior for each critical service
4. Simulate a provider outage in a staging environment; verify the platform detects the outage within the documented alert latency and transitions to the failover target
5. Verify the platform continues operating within the documented SLA during the simulated outage
6. Verify SLA breach records exist for any historical SLA violations; confirm remediation actions are documented
7. Verify failover procedures have been tested within the last 12 months with documented results

> **See also:** APTS-TP-009 (business continuity and provider exit strategy), APTS-SC-018 (incident containment and recovery procedures that activate during provider failover).

---

## APTS-TP-005: Provider Incident Response, Breach Notification, and Mid-Engagement Compromise

**Classification:** MUST | Tier 1

### Requirement

Organizations MUST establish incident response procedures for provider-related security incidents, including procedures specific to compromises discovered during active engagements. Provider contracts MUST specify breach notification obligations with timelines aligned to applicable regulatory requirements. Organizations MUST maintain incident response procedures documenting investigation steps, data impact assessment, recovery procedures, and communication protocols with affected customers. Procedures MUST enable rapid assessment of which organization data was accessed or compromised.

**During Active Engagements:** When a provider compromise is discovered during an active engagement, response procedures MUST enable rapid containment of customer data exposure, assessment of engagement continuation feasibility, and prompt customer notification per the platform's incident response plan. For each engagement, the organization MUST document whether it can continue with the compromised provider or MUST cease operations pending remediation. Procedures MUST include evidence preservation for forensic investigation.

### Verification

- Find incident response procedure
- Review contract: breach notification timeline specified?
- Simulate provider breach: confirm the procedure identifies affected data categories and impacted customers within the timeline documented in the incident response procedure
- Find investigation procedure: how is breach investigated?
- Find recovery procedure: documented steps to recover?
- Find containment procedure for mid-engagement provider compromise
- Check engagement continuation criteria: when must operations cease?
- Verify evidence preservation documented
- Audit procedure completeness: investigation, communication, remediation

> **See also:** APTS-TP-018 (tenant breach notification obligations triggered by provider compromise), APTS-TP-009 (business continuity planning for mid-engagement provider outage).

---

## APTS-TP-006: Dependency Inventory, Risk Assessment, and Supply Chain Verification

**Classification:** MUST | Tier 1

### Requirement

Organizations MUST maintain complete inventory of all software dependencies and third-party components used in autonomous pentest operations (Software Bill of Materials (SBOM)). Inventory MUST include version numbers, licensing information, and known vulnerabilities. Risk assessment MUST be performed for each dependency, evaluated against criticality of its use in operations. Vulnerability monitoring MUST be continuous, with processes to identify and track new vulnerabilities in dependencies as well as abandoned or unmaintained packages. Update strategies MUST balance security patching with testing requirements.

**Supply Chain Integrity Verification:**

The platform MUST verify the integrity of all software dependencies by verifying package signatures and checksums against known-good sources, and detecting potential typosquatting or dependency confusion attacks. Dependency updates MUST be validated in a non-production environment before deployment.

### Verification

- Find dependency inventory (SBOM)
- Verify completeness: all components listed?
- Review risk assessment: each entry has risk score?
- Check vulnerability monitoring: how are new vulns discovered? Are abandoned packages tracked?
- Verify update tracking: confirm a documented monitoring cadence exists and recent dependency version changes or vulnerability disclosures were captured within that cadence
- Verify signature validation is operational for all packages
- Test dependency update validation process (non-production staging)
- Verify typosquatting and dependency confusion detection is active

> **See also:** APTS-AR-016 (platform integrity and supply chain attestation)

---

## APTS-TP-007: Data Residency and Sovereignty Requirements

**Classification:** SHOULD | Tier 2

**Applicability:** Platforms deployed in cloud or multi-jurisdiction environments.

### Requirement

Platforms SHOULD document data residency requirements and verify that provider configurations enforce jurisdictional constraints. The specific technical controls for residency enforcement are platform-determined.

### Verification

1. Review documented data residency requirements; verify allowed and disallowed regions are explicitly named
2. Verify cloud service configuration enforces storage in allowed regions only
3. **Negative test:** In a staging environment, attempt to write or replicate data to a disallowed region; verify the write is blocked or fails
4. Verify transfer and replication settings restrict data movement to allowed regions
5. Review audit logs for any data movement events; verify no data was transferred to a disallowed region during the review period

> **See also:** APTS-TP-012 (data classification that determines residency obligations), APTS-AR-015 (evidence classification that drives jurisdictional handling).

---

## APTS-TP-008: Cloud Security Configuration and Hardening

**Classification:** MUST | Tier 1

**Applicability:** Platforms deployed on cloud infrastructure.

### Requirement

Organizations MUST implement cloud security hardening for all cloud infrastructure supporting autonomous pentest operations. Configuration MUST follow principle of least privilege for identity and access management (IAM) policies. All data MUST be encrypted at rest using strong algorithms (AES-256 minimum). Network configuration MUST enforce security groups and network ACLs to restrict traffic to necessary flows only. Regular compliance scanning MUST identify deviations from hardening standards and trigger remediation. When hosting LLM models using services provided by a selected cloud provider, organizations MUST ensure that billing alerts are in place to detect anomalous resource provisioning that may indicate cloud account compromise. Organizations SHOULD limit the allowed services and regions within the cloud accounts to prevent misuse and minimize potential risks.

### Verification

1. Identify the named hardening baseline the platform follows (CIS Benchmark, cloud provider's security guide, or equivalent); verify documentation references a specific version
2. Audit IAM policies: compare granted privileges against the documented least-privilege baseline; fail any policy granting permissions not in the baseline without a documented exception
3. Verify all data at rest is encrypted with AES-256 or equivalent; inspect storage metadata to confirm algorithm and key length
4. Verify network security groups and ACLs restrict traffic to documented necessary flows only; fail any rule permitting traffic not in the architecture baseline
5. Run the compliance scanner; require zero critical deviations and documented remediation plans for any high-severity deviations
6. Verify that billing alerts are in place to detect anomalous resource provisioning that may indicate cloud account compromise
7. Verify that there are limitations for the allowed services and regions across the used cloud accounts; fail if any deviations from the baseline detected
8. **Negative test:** Introduce an intentionally overbroad IAM policy (for example, wildcard permissions) in a staging environment; verify the compliance scanner or policy gate detects and flags it
9. **Negative test:** Try to create any cloud resources in the prohibited region; verify that this operation fails
10. **Negative test:** Try to create resources using the prohibited service; verify that this action is blocked by the configured policies

> **See also:** APTS-SE-024 (cloud-native scope governance that this hardening baseline supports), APTS-TP-014 (secrets management inside the hardened cloud environment).

---

## APTS-TP-009: Incident Response and Service Continuity Planning

**Classification:** MUST | Tier 2

### Requirement

Organizations MUST establish incident response procedures and service continuity plans for cloud infrastructure supporting pentest operations. Plans MUST define Recovery Time Objective (RTO) and Recovery Point Objective (RPO) targets. Regular backups MUST be performed with documented schedule and verification that backups can be restored. Disaster recovery procedures MUST be tested regularly with results documented.

### Verification

1. Review the incident response procedure; verify it covers investigation steps, data impact assessment, recovery procedures, and communication protocols
2. Verify documented RTO and RPO targets exist for each critical service
3. Verify backup logs show regular backups occurring at the documented cadence
4. Execute one backup restore exercise; measure actual recovery time and data loss against documented RTO/RPO targets; fail if either target is exceeded
5. Verify the restored dataset's integrity (row counts, checksums, or application-level consistency checks)
6. Verify disaster recovery procedures have been tested within the last 12 months with documented results including actual RTO/RPO achieved

> **See also:** APTS-TP-004 (provider availability/SLA planning that feeds RTO/RPO targets), APTS-TP-005 (provider incident response procedures integrated with continuity plans).

---

## APTS-TP-010: Vulnerability Feed Selection and Management

**Classification:** MUST | Tier 2

### Requirement

Organizations MUST establish criteria for selecting vulnerability feeds and manage feed updates to ensure vulnerability data is current, accurate, and applicable to active scanning operations. Feed selection MUST assess Common Vulnerabilities and Exposures (CVE) coverage, update frequency, data quality (Common Vulnerability Scoring System (CVSS) accuracy, Common Weakness Enumeration (CWE) mappings, version identification), vendor longevity, and availability/SLA commitments. Feeds MUST have cryptographic verification. Feed testing MUST validate data quality in test environments before production deployment. Update frequency MUST be proportional to severity, with critical vulnerabilities prioritized for fastest integration. Updates SHOULD be applied during maintenance windows and validated in a non-production environment before deployment. Change management MUST track significant feed modifications and assess impact on finding accuracy.

### Verification

1. **Feed selection criteria**: Review documented feed selection criteria; verify CVE coverage, update frequency, data quality, vendor longevity, and SLA are assessed
2. **Feed cryptographic verification**: Verify feeds include cryptographic signatures or checksums; confirm signature validation occurs before feed data is used
3. **Feed update frequency**: Review feed update logs; verify critical vulnerabilities are integrated faster than lower-severity items
4. **Pre-production validation**: Verify feed updates are tested in a non-production environment before deployment to production scanning operations
5. **Change management**: Review feed change log; verify significant feed modifications are tracked with impact assessment on finding accuracy
6. **Feed currency**: Verify active feeds contain CVE data no older than the documented maximum staleness threshold (for example, feed updated within last 24 hours for critical, 7 days for others)

> **See also:** APTS-TP-011 (feed quality assurance and correlation that validates feed integrity), APTS-TP-006 (dependency/SBOM verification that shares cryptographic-trust processes).

---

## APTS-TP-011: Feed Quality Assurance and Incident Response

**Classification:** SHOULD | Tier 2

### Requirement

Organizations SHOULD implement correlation processes to validate vulnerability feeds against discovered services and establish metrics to measure and improve feed accuracy. Correlation MUST query feed(s) for matching CVEs per discovered service, filter by applicability (version range, OS, architecture), assign confidence scores based on version exactness, and document applicable CVEs. Multi-feed correlation MUST compare results across sources and identify/resolve discrepancies in CVSS scoring and affected versions. Accuracy validation MUST maintain test datasets of known vulnerable systems with documented false negative measurement methodology with tracked improvement targets. Organizations SHOULD establish measurable quality targets (for example, false positive rate targets, version match accuracy targets, CVE coverage targets) and track them over time. Absolute false negative rates are difficult to measure with precision. The requirement is for establishing and documenting a measurement methodology, not for achieving a specific false negative rate. Organizations MUST document known limitations of their measurement approach. Incident procedures MUST include detection methods (manual review, automated quality checks, client feedback, comparative analysis, spot-checking, vendor advisories), issue classification with documented response timelines per severity level, investigation/remediation process with vendor coordination, and client communication for high-impact issues (notification per the platform's documented SLA for feed quality incidents).

### Verification

1. Review documented quality targets (false positive rate, false negative rate, version match accuracy, CVE coverage) and verify current performance metrics are tracked against them
2. Provide a known-vulnerable test dataset (minimum 20 known vulnerabilities across at least 3 vulnerability classes) to the feed correlation process; measure detection output
3. Compare measured false positive and false negative counts against the operator's declared quality targets; fail if either exceeds the declared threshold
4. Review root cause analyses for the last 3 accuracy incidents; verify each has a documented cause and remediation
5. Verify feedback loop to feed providers is documented and active (evidence of at least one submission in the last 12 months)

> **See also:** APTS-TP-010 (feed selection and management whose data this QA process validates), APTS-RP-006 (false positive rate disclosure fed by feed-quality metrics).

---

## APTS-TP-012: Client Data Classification Framework

**Classification:** MUST | Tier 1

### Requirement

Organizations MUST establish a data classification framework to categorize client data by sensitivity and apply protection controls based on classification level as defined below. Framework MUST define four levels: RESTRICTED (credentials, encryption keys, PII, payment card data, health information, trade secrets - never transmit externally, minimum AES-256-GCM encryption), CONFIDENTIAL (findings, diagrams, source code, contact information, financial records, policies - limit external transmission, require DPA, TLS 1.2+ encryption), INTERNAL (engagement scope, business context, infrastructure details, status information, methodology - limit to authorized personnel, encryption at rest recommended), PUBLIC (process information, de-identified descriptions, aggregate statistics, published guidance - no special protection required). Classification MUST occur before data creation or receipt, be documented in engagement files, and be reviewed at engagement closure. Handling rules MUST specify external transmission permissions, encryption requirements in transit and at rest, access control levels, retention periods, and deletion methods for each classification. Organizations MUST implement data minimization before transmitting data to external AI providers: strip unnecessary metadata, remove/redact discovered credentials and API keys, anonymize IP addresses and domain names where possible, exclude non-essential client context, and use hash values instead of full data when feasible. Client engagement letters MUST disclose specific AI providers used, data categories sent to each provider, and obtain explicit client consent before transmitting classified data.

**Clarification:** 'Never transmit externally' for RESTRICTED data refers to raw credentials, encryption keys, and unredacted PII. Processed and minimized data (with credentials redacted, PII anonymized, keys removed) may be transmitted to approved AI providers under a Data Processing Agreement.

### Verification

1. **Framework documentation exists:** Classification framework documentation exists and explicitly defines the four required levels (RESTRICTED, CONFIDENTIAL, INTERNAL, PUBLIC), the data types mapped to each level, and the handling rules (external transmission, encryption in transit and at rest, access control, retention, deletion) for each level. Missing any level or any handling dimension fails.
2. **Tagging coverage:** Sample 25 data objects at random from the engagement data store (findings, scan data, credentials, evidence artifacts, contact records). Every sampled object MUST carry a classification tag from the framework. Untagged or mis-tagged objects fail.
3. **Seeded data flow trace:** Inject a seeded RESTRICTED marker and a seeded CONFIDENTIAL marker into the engagement data store in a staging environment. Trace every outbound flow from the store for the duration of an engagement simulation. The RESTRICTED marker MUST never leave the store in raw form. The CONFIDENTIAL marker MAY leave only to destinations covered by a Data Processing Agreement. Any deviation fails.
4. **Control enforcement:** For each sampled object from step 2, verify the encryption, access control, and retention controls actually applied match the handling rules for the object's classification (encryption algorithm in storage metadata, ACL entries, retention expiry). Any mismatch fails.
5. **External AI provider minimization:** Capture a sample of 10 outbound requests to each external AI provider used during a staging engagement. Verify the requests were stripped of unnecessary metadata, discovered credentials and API keys removed, IPs and domains anonymized where feasible, and hash values substituted for raw data where the minimization rule requires it. Any leakage of raw RESTRICTED data fails.
6. **Data flow documentation:** A documented data flow diagram or table exists that names every external AI provider used and the data categories sent to each. Missing provider fails.
7. **Client consent:** Review client engagement letters for the last 5 engagements (or all engagements if fewer than 5). Each letter MUST disclose the specific AI providers used, the data categories sent to each provider, and obtain explicit client consent before transmitting classified data. Missing disclosure or consent fails.

> **See also:** APTS-AR-015 (data/evidence classification), APTS-TP-013 (sensitive data discovery and handling using this classification framework), APTS-RP-015 (downstream finding pipeline integrity and data redaction)

---

## APTS-TP-013: Sensitive Data Discovery and Handling

**Classification:** MUST | Tier 1

### Requirement

Organizations MUST implement procedures to identify, protect, and report discovered sensitive data (credentials, PII, financial data, health information) found during autonomous pentest operations. Sensitive data types include credentials (passwords, API keys, tokens, SSH keys), PII (SSN, passport numbers, driver's licenses, email addresses, phone numbers), payment card information (PAN, cardholder names, CVV, bank accounts), and health information (medical records, diagnoses). Discovery MUST use automated pattern matching for known formats (credit card numbers, SSNs) and manual analysis by security analysts. Upon discovery, sensitive data MUST be isolated, location documented, exposure risk assessed, and access controls reviewed. Storage MUST use secure vaults (encrypted, access-restricted) separate from general findings with audit logging of access. Reporting MUST create RESTRICTED findings without disclosing actual values (for example, "CC # ending in 4532" instead of full number), provide description of exposure impact, recommend remediation, assess risk level, and document reasoning. Client notification MUST occur immediately (phone call recommended) with guidance on secure deletion and verification of client remediation. Regulatory compliance MUST assess GDPR, CCPA, HIPAA, PIPEDA, PCI-DSS, and state law requirements, and MUST issue the notifications required by any applicable regulation within the timelines those regulations specify.

### Verification

Build a seeded corpus containing a known set of synthetic sensitive items and run the discovery procedure against it in a staging environment. The corpus MUST contain at minimum:

- 10 synthetic credentials (passwords, API keys, tokens, SSH private keys)
- 10 synthetic PII records (SSNs, passport numbers, driver's licenses, email addresses, phone numbers)
- 5 synthetic payment card records (PANs with valid Luhn checksum, CVVs)
- 5 synthetic health records (medical record numbers, diagnoses)

Verify every one of the following:

1. **Detection rules exist:** Documented detection rules (regex patterns, classifiers, or dictionaries) exist and cover every sensitive data category listed in the requirement. Missing category fails.
2. **Discovery recall:** The discovery procedure MUST detect at least 95% of the seeded items per category. Recall below 95% fails.
3. **Isolation:** Every detected item MUST be moved to a secure vault within the documented response window. Items that remain in the general findings store after detection fail.
4. **Encryption at rest:** Every item in the vault MUST be encrypted at rest per APTS-TP-014, and the encryption algorithm MUST be recorded. Unencrypted or unrecorded items fail.
5. **Redaction in logs and reports:** Sample the engagement logs and any draft report referencing the seeded items. Every reference MUST redact the raw value (for example, "CC # ending in 4532") and NOT contain the full value. Any full-value leak fails.
6. **Access audit log:** Every access to a seeded item in the vault MUST be recorded with operator identity, timestamp, and purpose. Missing entries fail.
7. **Retention and purge:** Seeded items MUST be purged from the vault at or before the retention boundary for their classification (credentials no later than 90 days per APTS-TP-015). Retained items past the boundary fail.
8. **Client notification:** For each seeded item category that the procedure treats as a discovery-worthy finding, a notification draft MUST be produced containing description, exposure impact, recommended remediation, and risk level, without disclosing raw values. Missing draft fails.
9. **Regulatory applicability:** A regulatory applicability record MUST identify which of GDPR, CCPA, HIPAA, PIPEDA, PCI-DSS, and applicable state laws apply to each seeded category. Missing record fails.

> **See also:** APTS-MR-019 (discovered credential protection with immediate encryption), APTS-TP-012 (client data classification framework defining the classification levels), APTS-TP-014 (encryption controls), APTS-TP-015 (retention boundaries)

---

## APTS-TP-014: Data Encryption and Cryptographic Controls

**Classification:** MUST | Tier 1

### Requirement

Organizations MUST implement cryptographic controls to protect client data in transit and at rest using modern encryption standards. Encryption in transit MUST enforce minimum TLS 1.2 (TLS 1.3 preferred) with strong cipher suites only (no weak/export ciphers), certificate validation (no self-signed in production), certificate pinning for critical systems (recommended), and mutual TLS for service-to-service authentication. All API calls, client-server communication, and internal service communication MUST use TLS 1.2+, VPN for cloud infrastructure access, and TLS encryption for email (STARTTLS or implicit). Encryption at rest MUST use minimum AES-256-GCM with centralized key vault (not embedded in code), key rotation annually minimum (90 days for highly sensitive data), and optional multi-layer encryption for ultra-sensitive data. Key management MUST never embed keys in code or configuration, implement key escrow for recovery scenarios, maintain key inventory, restrict access via role-based controls, and audit all key operations. Approved algorithms include symmetric AES (128-bit minimum, 256-bit preferred), asymmetric RSA-2048+ or ECDSA-256+, hashing SHA-256 minimum, and key derivation PBKDF2/bcrypt/scrypt. Deprecated algorithms (DES, 3DES, RC4, MD5, SHA-1, RSA-1024) MUST NOT be used.

### Verification

1. Inspect storage metadata for all data stores; verify encryption at rest uses AES-256 or equivalent with documented key lengths
2. Attempt a TLS downgrade to TLS 1.1 or below against each platform communication endpoint; verify the connection is rejected
3. Verify no deprecated cryptographic algorithms (MD5, SHA-1 for integrity, DES, 3DES, RC4) are in use for data protection
4. Inspect the key management system; verify keys are stored in a hardware security module (HSM), dedicated key vault, or equivalent isolated storage, not embedded in application code or configuration files
5. Verify key rotation has occurred within the documented rotation cadence; review rotation logs for the last cycle

---

## APTS-TP-015: Data Retention and Secure Deletion

**Classification:** MUST | Tier 2

### Requirement

Organizations MUST establish and document a data retention policy that specifies retention periods per data classification, with justification based on operational need, contractual obligation, and applicable regulatory requirements. Example baseline periods (findings: 12 months, raw scan data: 6 months, credentials: 90 days maximum) may serve as starting points but MUST be adjusted for engagement-specific and jurisdictional requirements. Retention policy MUST address: findings and reports (CONFIDENTIAL) with documented retention period and justification; raw scan data (CONFIDENTIAL) with documented retention period; credentials (RESTRICTED) with maximum retention of 90 days; logs and audit trails (INTERNAL) with documented retention reflecting compliance requirements; backup data retention matching source data; data subject deletion requests (GDPR/CCPA) with documented compliance procedures. Retention tracking MUST maintain inventory with expiration dates, automated reminders 30 days before deletion, regular compliance audits, documented exceptions, and client approval for extensions. Secure deletion MUST use the method specified for the storage medium: for magnetic media, multi-pass overwriting (at least three passes) or NIST SP 800-88 Rev. 1 Clear/Purge; for solid-state storage, cryptographic erasure of the encryption key or manufacturer-certified secure erase (NIST SP 800-88 Purge); for cloud storage, the provider's documented secure deletion API combined with key destruction for any customer-managed keys. The specific deletion method MUST be documented. Deletion verification MUST confirm primary storage deletion, backup deletion, archival deletion, test recovery (expected to fail), and document deletion with evidence.

### Verification

- Verify retention policy documentation exists and covers all data classification levels
- For each retention period, verify it is justified against documented operational need, contractual obligation, or applicable regulation
- Verify credentials are retained no longer than 90 days
- Test deletion: delete data past its retention period, then attempt recovery; verify recovery fails
- Verify deletion method is documented and appropriate to the storage medium
- Check audit logs: verify deletion events are recorded with timestamp and method

> **See also:** APTS-TP-016 (data destruction proof and certification)

---

## APTS-TP-016: Data Destruction Proof and Certification

**Classification:** MUST | Tier 3

### Requirement

Upon engagement completion, the platform MUST generate a data destruction certificate documenting all data destroyed, destruction methods used, timestamps, and cryptographic verification of destruction. Destruction schedule MUST specify retention periods per data classification level, documented in the platform's data retention policy. Example classifications include: engagement logs (retain per policy, secure wipe or crypto-shred), vulnerability findings (until customer confirms receipt and remediation, per contractual agreement), raw evidence (per engagement agreement, using cryptographic erasure), and customer credentials (destroyed promptly after engagement end, crypto-shred required). Destruction certificates MUST include, at minimum: data identifiers (record IDs or scope descriptors for each data set destroyed), deletion method used (for example, crypto-shred, secure wipe, physical destruction), timestamp of destruction, responsible party, and a cryptographic hash of the destruction log. The specific certificate format is platform-determined, but all listed elements MUST be present. Customer-initiated destruction MUST support a request mechanism (API or portal), acknowledgment within the timeframe defined in the platform's data retention policy, processing within the documented destruction SLA, and a verification certificate upon completion. Independent verification SHOULD be performed using a separate system from the destruction process, attempting retrieval for each category: file system access (expected to return "file not found"), database queries (expected to return zero rows), decryption attempts (expected to fail with cryptographic error). When performed, verification SHOULD document success/failure per category with timestamp, include recovery test (expected to fail), and append results to certificate. Where applicable data protection regulations provide data subject rights to erasure or deletion (for example, GDPR, CCPA, PIPEDA, HIPAA), the platform MUST support those rights within the timeframes required by each applicable regulation.

### Verification

- Request data for engagement past retention date (expected to be unavailable)
- Verify destruction certificate generated automatically for completed engagements
- Validate certificate structure: all required fields present
- Review destruction methods: crypto-shred, secure wipe, or physical destruction
- Verify independent verification process: separate system, retrieval attempts
- Test customer-initiated destruction: request, verify processing within documented destruction SLA and certificate delivery
- Audit certificate archive: verify retention meets the period defined in the platform's data retention policy
- Validate certificate signature (attestation key)
- Calculate SHA-256 of destruction log; verify against certificate

> **See also:** APTS-TP-015 (data retention and secure deletion procedures)

---

## APTS-TP-017: Multi-Tenant and Engagement Isolation

**Classification:** MUST | Tier 2

**Applicability:** Multi-tenant platforms or platforms serving multiple concurrent engagements.

### Requirement

Each customer engagement MUST run in an isolated execution environment with separation of memory, storage, network resources, and credentials. Data from different clients MUST be segregated with no cross-contamination possible through accidental access patterns. Client findings MUST never be visible to other clients, and credentials MUST NOT be accessible across engagements.

Isolation controls MUST include: (1) Execution environment isolation using separate containers, virtual machines, or namespaces per engagement. (2) Database-level isolation using separate schemas per client (not just tables) with row-level security policies. (3) Storage isolation using separate encrypted volumes or directories per engagement with unique encryption keys. (4) Network isolation using policies that prevent inter-engagement communication. (5) Credential segregation using per-engagement encrypted vaults with access control bound to engagement ID. (6) Access control enforcing role-based access by client with logging of all access attempts. (7) Log and evidence segregation in separate access-controlled repositories per engagement.

AI model context isolation (Tier 3): new session per engagement with cleared context window, separate conversation threads, and fine-tuning prohibited without explicit written consent.

Testing and verification MUST include periodic isolation testing (at minimum annually, or after significant infrastructure changes) covering cross-client access testing, cross-engagement access attempts, credential vault access tests, and data leak testing.

**Tiered Implementation:** Application-layer isolation (separate database schemas, row-level security, application-enforced access controls) is expected at Tier 2. Infrastructure-layer isolation (dedicated VMs/containers per engagement, separate KMS policies, network namespace isolation) is expected at Tier 3 maturity or when required by regulatory obligations.

### Verification

- Deploy test engagements with known test data
- From each engagement, attempt to access other engagements' resources
- All attempts must be denied by infrastructure (not application)
- Document denial logs (for example, Linux audit logs showing access denied)
- Run monthly isolation penetration tests (attempt cross-engagement access)
- Request credentials for non-assigned engagement (expected to fail)
- Verify KMS policy blocks cross-engagement access
- Review credential access audit logs (verify no cross-engagement access)

> **See also:** APTS-SE-011 (tenant isolation in the target environment), APTS-MR-021 (adversarial testing of these isolation controls).

---

## APTS-TP-018: Tenant Breach Notification

**Classification:** MUST | Tier 1

### Requirement

If the platform operator discovers that engagement isolation was breached (data leaked between tenants), all affected customers MUST be notified promptly per the platform's incident response plan and applicable regulatory requirements. Notification MUST include what data was exposed, the time window of exposure, and remediation steps taken. This requirement addresses cross-tenant data exposure specifically. For general breach notification and regulatory reporting, see APTS-TP-A01 (Advisory).

**Breach Definition:** Cross-engagement data leakage (Engagement A data accessed by Engagement B), isolation bypass (infrastructure penetration or misconfiguration), unintended operator access, or exposure window (from breach occurrence until detection).

**Detection:** Procedures MUST include automated monitoring for cross-engagement access attempts, periodic audit log analysis for suspicious patterns, network TAP analysis for isolation verification, periodic isolation penetration testing, and customer escalation.

**Breach Assessment:** The operator MUST promptly confirm breach occurrence and isolate affected systems, identify scope (engagements involved, data categories exposed, record/byte quantities, customer count), establish timeline (occurrence date/time, isolation mechanism deployment, exposure window duration), determine preliminary root cause (configuration error, software vulnerability, operator error, hardware failure), and assign severity classification:

- CRITICAL: credentials/PII exposed, multiple customers, wide window
- HIGH: findings/evidence exposed, limited customers, narrow window
- MEDIUM: logs exposed, single customer, brief window

**Immediate Containment:** The operator MUST isolate affected systems (disconnect if necessary), stop cross-engagement access, preserve evidence (logs, audit trail, configuration), and not delete evidence.

**Customer Notification:** The operator MUST identify all affected customers, notify using appropriate channels based on severity (for example, phone for CRITICAL, email for others), and include: brief description, data exposed, timeline, affected engagement IDs, impact assessment, remediation taken, recommended customer actions, point of contact, and next steps.

**Forensic Investigation:** The operator MUST conduct a full technical investigation, determine exactly what data was exposed and when, identify all involved parties and access method, document all evidence, and determine if other systems were affected.

**Post-Incident Actions:** The operator MUST conduct a post-mortem with engineering/leadership, implement preventive measures, re-architect isolation if necessary, audit past engagements for similar exposure, and plan customer compensation.

**Regulatory Reporting:** The operator MUST assess applicable regulations (for example, GDPR, CCPA) for applicability, notify data protection authorities if required, and document the notification timeline.

### Verification

Run a simulated cross-tenant exposure exercise in a staging environment and verify every one of the following artifacts is produced and satisfies the criteria listed:

1. **Seeded breach trigger:** Inject a controlled cross-engagement access event (seeded record in Engagement A readable from the Engagement B context). The detection path required under this requirement MUST fire within the response time documented in the platform's incident response plan. Missed detection fails.
2. **Breach classification record:** A severity classification (CRITICAL / HIGH / MEDIUM) MUST be recorded with timestamp, severity level, and the criteria that drove the classification. Missing or ambiguous classification fails.
3. **Affected-customer list:** A list of affected customers MUST be produced with per-customer engagement IDs, data categories exposed, record/byte counts, and exposure window. The list MUST be generated from the audit trail, not reconstructed manually. Lists generated from memory or manual inspection fail.
4. **Containment evidence:** Evidence MUST exist that the affected systems were isolated (timestamped disconnection log, configuration change, or firewall-rule diff) and that no evidence was deleted between detection and containment. Deleted evidence fails.
5. **Customer notification draft:** A notification draft MUST be produced containing all required fields (brief description, data exposed, timeline, affected engagement IDs, impact assessment, remediation taken, recommended customer actions, point of contact, next steps). Drafts missing any field fail.
6. **Forensic timeline:** A forensic timeline MUST be produced with occurrence, detection, containment, notification draft, and investigation-complete timestamps. Gaps exceeding the documented response-plan targets fail.
7. **Regulatory applicability decision:** An explicit written decision MUST be recorded stating which regulations (GDPR, CCPA, sector-specific) apply to the exposed data and whether notification to authorities is required, with timeline. Missing or undated decisions fail.
8. **Current contact information:** A spot check of 5 random customers MUST confirm the on-file notification contacts resolve to current and monitored channels. Stale contacts fail.
9. **Audit logging completeness:** The audit logs MUST contain every cross-engagement access attempt from the exercise. Any missing log entry fails.

> **See also:** APTS-TP-017 (multi-tenant isolation requirement whose failure triggers this notification duty), APTS-AR-018 (customer notification for behavior-affecting updates in the Auditability domain).

---

## APTS-TP-019: AI Model Provenance and Training Data Governance

**Classification:** MUST | Tier 2

**Applicability:** Platforms using AI/ML models for decision-making.

### Requirement

The platform MUST maintain documentation of AI model provenance including: model source and supplier, training data categories (not the data itself, but descriptions of data types and sources), and fine-tuning history including whether customer engagement data was used. For third-party AI providers, the platform MUST request and retain provider attestations regarding data handling practices, including whether customer data is used for model training. Platforms MUST NOT use findings or data from one customer's engagement to train or fine-tune models used in another customer's engagement without documented consent.

Where direct verification of training data provenance is infeasible (for example, third-party LLM providers), the platform MUST obtain and retain written attestations from the provider covering: (a) training data sources and filtering methodology, (b) whether customer data is used for training, (c) data retention and deletion policies, and (d) model update notification procedures. Attestations MUST be refreshed annually or upon model version change, whichever is sooner.

### Verification

1. Sample one current model used by the platform; verify provenance documentation includes model source, supplier, training data categories, and fine-tuning history
2. Sample one third-party AI provider; verify a written attestation is on file covering training data sources, customer data use, retention/deletion, and update notification; confirm the attestation is dated within the past 12 months or matches the current model version
3. Verify fine-tuning history documents whether customer engagement data was used; verify consent records exist for any customer data used in fine-tuning
4. **Negative test:** Verify that absent explicit customer consent, no customer engagement data appears in fine-tuning inputs or training data logs for models used in other customers' engagements
5. Verify cross-customer training data usage is either explicitly prohibited in policy or permitted only with documented consent per customer

> **See also:** APTS-AR-019 (AI/ML model change tracking and drift detection), APTS-TP-002 (model version pinning and change management)

---

## APTS-TP-020: Persistent Memory and Retrieval State Governance

**Classification:** SHOULD | Tier 2

### Requirement

Platforms that maintain persistent state across engagements (including but not limited to embedding stores, retrieval-augmented generation (RAG) indexes, learned heuristics, rejection memory, cached target context, or planner state) SHOULD enforce governance controls over this persistent state:

1. **State inventory**: All persistent state types SHOULD be inventoried with their purpose, sensitivity classification, and engagement origin
2. **Cross-engagement isolation**: Cross-engagement state reuse SHOULD require explicit policy authorization and SHOULD NOT leak data from one client's engagement into another client's engagement
3. **Operator visibility**: Operators SHOULD be able to inspect, export, and purge persistent state associated with their engagements
4. **Decision influence auditing**: Persistent state that influences autonomous decision-making SHOULD be logged and auditable, including which stored data contributed to which decisions
5. **State hygiene**: Persistent state SHOULD have documented retention periods and be subject to periodic review for staleness, relevance, and accuracy

### Verification

1. Review the persistent state inventory; verify all state types are documented with purpose, sensitivity classification, and engagement origin
2. Verify a cross-engagement state reuse policy exists and is documented
3. **Isolation test:** Run two staged engagements for different simulated clients; verify Client A's engagement data does not appear in Client B's persistent state (embedding store, RAG index, cached context, or planner state)
4. Verify the operator can inspect, export, and purge their engagement's persistent state through the documented interface
5. **Purge test:** Purge one engagement's persistent state; verify the purged data no longer influences platform decisions in a subsequent test run
6. Verify persistent state access and influence on decisions is captured in audit logs

> **See also:** APTS-TP-017 (multi-tenant isolation extended to persistent state stores), APTS-MR-019 (discovered credential protection applied to persistent memory that may contain secrets).

---

## APTS-TP-021: Foundation Model Disclosure and Capability Baseline

**Classification:** MUST | Tier 1

**Applicability:** All platforms whose autonomous decision-making is powered by one or more foundation models (LLMs, vision-language models, or other large pre-trained models), whether hosted by a third-party provider or run by the operator.

### Requirement

The platform operator MUST disclose, in the platform's conformance documentation and to customers on request, the foundation model or models powering the agent's decision-making. The disclosure MUST include at minimum: (1) the model provider, (2) the model family name, (3) the specific model version or identifier the platform is pinned to at the time of the disclosure, (4) the model's publication or release date as stated by the provider, and (5) any fine-tuning, post-training, adapter, system-prompt pre-load, or tool-use configuration the operator applies on top of the base model.

The operator MUST maintain documentation of the model's known offensive capability baseline at the time of adoption. This baseline MUST draw on at least one of: (a) publicly available cyber capability benchmarks published by the provider or an independent evaluator, (b) the provider's own safety or dangerous-capability evaluations where published, or (c) the operator's own evaluation conducted during vetting under APTS-TP-001. The baseline is not a guarantee of capability bounds; it is a reference point so that customers, reviewers, and the operator can reason about how the agent's capability compares to the platform's safety-control envelope.

Disclosure MUST be refreshed whenever any of the five disclosure elements above changes. Material changes trigger the re-attestation requirement in APTS-TP-022. The platform's conformance claim MUST include the foundation model disclosure.

### Rationale

Foundation model choice is the single largest determinant of an autonomous pentest platform's capability surface. Two platforms that score identically against APTS safety-control requirements but run on very different foundation models can produce very different outcomes in the field, because the safety-control envelope is sized relative to assumptions about what the agent will attempt. Customers cannot reason about residual risk without knowing what model is inside the platform. Providers update and deprecate models frequently, and a platform that was vetted against Model A may behave differently when silently migrated to Model B. Explicit disclosure and a pinned version make this visible.

### Verification

1. **Disclosure content review:** Locate the platform's foundation model disclosure. Verify that all five required elements (provider, family, version/identifier, release date, operator-applied customizations) are present and accurate against the platform's runtime configuration.
2. **Capability baseline review:** Locate the capability baseline documentation. Verify that it cites at least one of the three acceptable sources (published benchmarks, provider safety evaluations, operator evaluation) and that the cited source exists and covers the disclosed model version.
3. **Conformance claim integration:** Review the platform's conformance claim. Verify that the foundation model disclosure is included and matches the disclosure document.
4. **Refresh policy review:** Review the operator's documented policy for refreshing the disclosure. Verify that the policy covers all five disclosure elements and that the most recent refresh matches the runtime configuration observed in step 1.
5. **Customer access test:** Verify that a customer with an active engagement can obtain the current disclosure through the documented channel (portal, contract annex, or on request) within the timeframe stated in the operator's policy.

> **See also:** APTS-TP-001 (provider vetting), APTS-TP-002 (model version pinning), APTS-TP-019 (model provenance and training data governance), APTS-TP-022 (re-attestation on material foundation model change)

---

## APTS-TP-022: Re-attestation on Material Foundation Model Change

**Classification:** MUST | Tier 2

**Applicability:** All platforms subject to APTS-TP-021.

### Requirement

When the operator makes a material change to the foundation model powering the agent, the operator MUST re-run the APTS conformance assessment covering at minimum the Scope Enforcement (SE), Safety Controls (SC), Manipulation Resistance (MR), and Graduated Autonomy (AL) domains, and MUST update the conformance claim and the APTS-TP-021 disclosure, before the changed platform handles customer engagements.

A change is material if any of the following apply: (1) the provider is different, (2) the model family is different, (3) the version change crosses a generation boundary as defined by the provider (for example, from a 3.x family to a 4.x family), (4) fine-tuning, adapters, or post-training configuration change in a way that affects the agent's available action space, offensive capability, or refusal behavior, or (5) the operator's own evaluation, a provider advisory, or a published benchmark indicates a meaningful shift in the model's offensive capability relative to the previously documented baseline.

The re-assessment MUST document what was re-tested, what the results were, and which controls, thresholds, or allowlists (if any) were adjusted as a result. Operators MUST notify customers with active engagements of the material change and the outcome of the re-assessment within the timeframe documented in the operator's change notification policy, and MUST preserve the prior configuration and disclosure for rollback under APTS-TP-002.

### Rationale

Foundation model changes are not routine dependency updates. A model upgrade can widen or narrow the agent's effective action space, change the distribution of actions it chooses from a fixed allowlist, or shift its behavior under adversarial prompts in ways that APTS safety controls were not previously sized against. Treating a model upgrade as equivalent to a library bump is the failure mode this requirement exists to prevent. Re-attestation forces the operator to confirm that the controls still hold against the new capability surface before customers are exposed to it.

### Verification

1. **Policy review:** Review the operator's documented change management policy for foundation model changes. Verify that it defines "material change" in terms consistent with this requirement and that it requires re-assessment of at minimum SE, SC, MR, and AL domains.
2. **Historical review:** Select the most recent foundation model change (if any). Verify that a re-assessment record exists, that it covers the required domains, and that it documents any resulting control adjustments.
3. **Conformance claim update:** Verify that the conformance claim and APTS-TP-021 disclosure were updated to reflect the changed model before the changed platform handled any customer engagement.
4. **Customer notification review:** Verify that customers with active engagements at the time of the change were notified within the timeframe stated in the operator's policy, and that the notification included the outcome of the re-assessment.
5. **Rollback test:** Verify that the prior model configuration and disclosure are preserved and that the operator's runbook supports reverting to the prior configuration under APTS-TP-002.

> **See also:** APTS-TP-001 (provider vetting), APTS-TP-002 (model version pinning and change management), APTS-TP-021 (foundation model disclosure and capability baseline), APTS-AR-019 (continuous model change tracking and drift detection).

---

## Key Takeaways

1. **Infrastructure-Layer Isolation**: Implement separation at container/VM/namespace level, not just application layer
2. **Credential Segregation**: HSM/KMS enforces cross-engagement access denial at key management layer
3. **Context Clearing**: Clear AI model context between engagements; do not retain information across engagements
4. **Network Separation**: Unique public IP and Virtual Local Area Network (VLAN) per engagement prevents attribution confusion
5. **Technical Enforcement**: Enforce access controls at the storage, database, and network layer rather than relying on policy alone
6. **Prompt Notification**: Breach detection and customer notification per documented incident response timelines
7. **Defense-in-Depth**: All isolation mechanisms (execution, credential, AI, network, logs, breach notification) required for complete multi-tenant security
