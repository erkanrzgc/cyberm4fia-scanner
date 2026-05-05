# Supply Chain Trust: Implementation Guide

Practical guidance for implementing APTS Supply Chain Trust requirements. Each section provides a brief implementation approach, key considerations, and common pitfalls.

> **Note:** This guide is informative, not normative. Recommended defaults and example values are suggested starting points; the [Supply Chain Trust README](README.md) contains the authoritative requirements. Where this guide and the README differ, the README governs.

---

## APTS-TP-001: Third-Party Provider Selection and Vetting

**Implementation:** Establish a vendor assessment process that evaluates AI/LLM providers on security controls, track record, certifications, and compliance posture before any engagement begins.

**Key Considerations:**
- Document vetting criteria and maintain an approved vendor list
- Reassess providers annually or after significant security incidents
- Verify certifications independently (SOC 2 Type II, ISO 27001, penetration test reports)

**Common Pitfalls:**
- Relying on marketing claims without independent verification
- Insufficient due diligence on emerging or smaller providers

---


## APTS-TP-002: Model Version Pinning and Change Management

**Implementation:** MUST pin AI model versions explicitly in code and configuration files. Enforce formal change management for version updates with testing and approval before production deployment.

**Key Considerations:**
- Use semantic versioning; never reference "latest" in production configs
- Track model lineage and test updates in staging before production
- Document rollback procedures for every version change

**Common Pitfalls:**
- Auto-updating to latest models without regression testing
- No rollback procedure when a model update causes behavioral changes
- Missing version documentation in deployment artifacts

---

## APTS-TP-003: API Security and Authentication

**Implementation:** Use strong authentication (OAuth 2.0, mTLS) for all provider API calls. Store API keys in secure vaults, enforce TLS 1.2+ with certificate validation, rotate keys quarterly, and use short-lived tokens.

**Key Considerations:**
- Implement rate limiting on all API endpoints
- Log all API access and monitor for suspicious usage patterns
- Use mutual TLS for service-to-service authentication where supported

**Common Pitfalls:**
- Hardcoding credentials in source code or configuration files
- Storing API keys in version control
- Never rotating credentials after initial deployment

---

## APTS-TP-004: Provider Availability, SLA Management, and Failover

**Implementation:** Define availability requirements (for example, 99.9% uptime) and implement fallback providers for critical services. Test failover procedures monthly.

**Key Considerations:**
- Document Recovery Time Objective (RTO) and Recovery Point Objective (RPO)
- Maintain secondary provider relationships for critical AI services
- Automate failover detection and switching where possible

**Common Pitfalls:**
- No failover testing until an actual outage occurs
- Single-provider dependence for critical functionality
- Unclear recovery procedures leading to extended downtime

---

## APTS-TP-005: Provider Incident Response, Breach Notification, and Mid-Engagement Compromise

**Implementation:** Ensure provider contracts specify breach notification obligations with timelines aligned to applicable regulatory requirements. Define notification procedures and establish incident communication channels.

**Key Considerations:**
- Verify the provider has documented incident response procedures
- Test communication channels before they are needed
- Include breach notification SLAs in all provider contracts

**Common Pitfalls:**
- No contractual SLAs for breach notification timelines
- Poor provider communication during active incidents
- Incomplete incident disclosure leaving gaps in impact assessment

---


## APTS-TP-006: Dependency Inventory, Risk Assessment, and Supply Chain Verification

**Implementation:** Maintain a Software Bill of Materials (SBOM) for all tools and dependencies. Perform risk assessments quarterly and monitor continuously for known vulnerabilities.

**Key Considerations:**
- Use standardized SBOM formats (SPDX, CycloneDX)
- Integrate SBOM with automated vulnerability scanners
- Track transitive dependencies, not just direct ones

**Common Pitfalls:**
- Incomplete inventory missing transitive or runtime dependencies
- Outdated SBOMs that do not reflect current deployments
- No automated monitoring for newly disclosed vulnerabilities

---


## APTS-TP-007: Data Residency and Sovereignty Requirements

**Implementation:** Define geographic restrictions for data storage and processing. Verify provider compliance with contractual commitments and audit data locations regularly.

**Key Considerations:**
- Check compliance with GDPR, CCPA, and applicable regional regulations
- Include data residency clauses in all provider contracts
- Monitor for provider infrastructure changes that may affect data location

**Common Pitfalls:**
- No geographic requirements specified in contracts
- Poor provider transparency about where data is actually stored
- Data routed through unintended regions during failover

---

## APTS-TP-008: Cloud Security Configuration and Hardening

**Implementation:** Apply least-privilege IAM policies, encrypt data at rest (AES-256) and in transit (TLS 1.2+), configure security groups restrictively, enable MFA for all administrative access, set up billing alerts to detect anomalous resource provisioning, restrict allowed regions and services that can be used within cloud accounts.

**Key Considerations:**
- Use Infrastructure-as-Code for consistent, auditable hardening
- Audit cloud configurations quarterly against CIS benchmarks
- Monitor for configuration drift from baseline
- Monitor for anomalous resource provisioning
- Limit allowed regions and cloud services

**Common Pitfalls:**
- Overly permissive security groups left from initial development
- Unencrypted data stores or weak cipher suites in production
- Disabled MFA on administrative accounts
- Alerts for anomalous resource provisioning are missing
- No region restrictions configured, allowing resource creation outside approved regions
- Overly permissive IAM policies granting administrative access to regular users or service accounts

**Cloud Security Hardening Baseline:**

Minimum cloud configuration requirements for platforms deployed on public cloud:

**AWS:**
- Enable CloudTrail in all regions with log file validation
- Enable GuardDuty for threat detection
- Use IAM roles (not access keys) for service-to-service authentication
- Enable S3 bucket versioning and block public access on all buckets containing engagement data
- Use KMS customer-managed keys for encryption at rest
- Deploy in a dedicated VPC with no internet gateway unless required
- When using AWS Organizations, set up SCP policies
- Set up billing alarms in CloudWatch or via AWS Budgets

**Azure:**
- Enable Azure Defender for all resource types hosting engagement data
- Use Managed Identities for service authentication
- Enable diagnostic logging on all resources
- Use customer-managed keys in Azure Key Vault for encryption
- Deploy in a dedicated virtual network with Network Security Groups
- Configure Azure Budgets and Cost Alerts
- Configure allowed services and regions via Azure Policies

**GCP:**
- Enable Cloud Audit Logging for all services
- Use service accounts with minimal IAM roles (principle of least privilege)
- Enable VPC Service Controls for engagement data resources
- Use Cloud KMS customer-managed keys for encryption
- Enable Access Transparency logging
- Set up Organization Policies
- Configure budget alerts

**Common (all providers):**
- Enable multi-factor authentication for all administrative access
- Implement network segmentation between platform components and engagement data
- Rotate all credentials and API keys at least every 90 days
- Monitor for configuration drift using cloud-native or third-party tools
- Set up alerts and notifications for the team via different channels
- Implement periodic IAM resources review to enforce principle of least privilege and detect unused entities
- Automate response to the common incidents

---

## APTS-TP-009: Incident Response and Service Continuity Planning

**Implementation:** Define RTO/RPO targets per service tier. Implement automated backups, maintain recovery runbooks, and conduct disaster recovery drills biannually.

**Key Considerations:**
- Test recovery procedures under realistic conditions, not just documentation review
- Document lessons learned from each drill and update runbooks accordingly
- Verify backup integrity through regular restore testing

**Common Pitfalls:**
- RTO/RPO targets undefined or untested
- Backup schedules that do not match RPO commitments
- Outdated runbooks that reference decommissioned infrastructure

---

## APTS-TP-010: Vulnerability Feed Selection and Management

**Implementation:** Select vulnerability feeds with broad CVE coverage. Cryptographically verify feed integrity on every update. Stage all updates in a non-production environment before deploying to production.

**Key Considerations:**
- Use multiple feeds to cross-validate and reduce blind spots
- Test staged updates for false positives before production deployment
- Monitor feed latency (time from CVE publication to feed inclusion)

**Common Pitfalls:**
- Single-source vulnerability data creating coverage gaps
- No integrity verification on feed updates
- Deploying feed updates directly to production without staging

---

## APTS-TP-011: Feed Quality Assurance and Incident Response

**Implementation:** Validate feeds against known-vulnerable datasets to measure accuracy. Establish incident procedures for bad data (false positives, missing CVEs) and log all discrepancies.

**Key Considerations:**
- Maintain baseline accuracy metrics and track trends
- Automate QA checks on every feed update
- Define rapid response procedures for feed data incidents

**Common Pitfalls:**
- No QA process to catch inaccurate or incomplete feed data
- Delayed response when bad data reaches production
- Poor documentation of feed accuracy over time

---

## APTS-TP-012: Client Data Classification Framework

**Implementation:** Implement a four-level classification framework: RESTRICTED (PII, credentials, secrets), CONFIDENTIAL (engagement-specific data), INTERNAL (operational data), PUBLIC (non-sensitive). Apply consistent labeling at data creation.

**Key Considerations:**
- Train all staff on classification procedures and handling requirements
- Enforce classification labels in storage, transit, and processing systems
- Audit classification compliance regularly

**Common Pitfalls:**
- Inconsistent classification across teams or projects
- No staff training leading to misclassification
- Missing labels on data created during engagements

**Data Classification Framework:**

| Classification | Description | Handling Requirements | Examples |
|---------------|-------------|----------------------|----------|
| RESTRICTED | Data whose exposure would cause severe harm | Encrypt at rest and in transit. Access logged and alerted. Retain minimum period only. Destroy with certification. | Discovered credentials, authentication tokens, PII, PHI, payment card data |
| CONFIDENTIAL | Engagement-specific data not for public disclosure | Encrypt at rest and in transit. Access logged. Retain per engagement agreement. | Vulnerability findings, network maps, exploitation evidence, target configurations |
| INTERNAL | Platform operational data | Encrypt in transit. Standard access controls. Standard retention. | Platform logs, health metrics, operator activity records |
| PUBLIC | Information safe for public disclosure | No special handling required. | Published CVE references, public documentation, framework version information |

All data MUST be classified at the point of discovery or creation. Classification MUST NOT be downgraded without documented justification and approval.

---

## APTS-TP-013: Sensitive Data Discovery and Handling

**Implementation:** Deploy automated discovery tools (DLP, regex scanners) to identify sensitive data in engagement artifacts. Establish procedures to protect, report, and audit discovered sensitive data.

**Key Considerations:**
- Run discovery scans regularly, not just at engagement completion
- Maintain audit trail of all discoveries and resulting actions
- Notify data owners when their sensitive data is discovered

**Common Pitfalls:**
- Manual-only discovery missing embedded credentials or PII
- No audit trail connecting discoveries to protective actions
- Slow response to sensitive data findings

---

## APTS-TP-014: Data Encryption and Cryptographic Controls

**Implementation:** Enforce TLS 1.2+ (TLS 1.3 preferred) for all data in transit. Use AES-256-GCM for data at rest. Implement FIPS 140-2 validated key management. Rotate encryption keys annually.

**Key Considerations:**
- Use hardware security modules (HSMs) for critical key material
- Test key recovery procedures before they are needed
- Disable weak cipher suites and negotiate only approved algorithms

**Common Pitfalls:**
- Weak or legacy cipher suites left enabled in production
- Poor key management practices (keys stored alongside encrypted data)
- No key rotation schedule after initial deployment

---

## APTS-TP-015: Data Retention and Secure Deletion

**Implementation:** Define retention periods per data classification level. Implement automated deletion workflows. Use crypto-shredding or multi-pass overwrite for secure deletion. Document all deletion procedures and outcomes.

**Key Considerations:**
- Verify deletion completeness including replicas and backups
- Maintain audit logs of all deletion events
- Test that deleted data cannot be recovered from backups

**Common Pitfalls:**
- Indefinite retention because no policy exists
- No verification that deletion actually occurred
- Backup copies surviving past the retention period

---

## APTS-TP-016: Data Destruction Proof and Certification

**Implementation:** Obtain destruction certificates from all vendors handling sensitive data. Verify cryptographic proof (hashes, digital signatures) of destruction. Maintain chain-of-custody documentation.

**Key Considerations:**
- Prefer third-party verified destruction over vendor self-certification
- Test destruction procedures before relying on them for compliance
- Audit vendor destruction compliance annually

**Common Pitfalls:**
- Accepting unverified vendor claims of destruction
- Missing destruction certificates for decommissioned services
- No chain-of-custody documentation for sensitive data lifecycle

---

## APTS-TP-017: Multi-Tenant and Engagement Isolation

**Implementation:** Execute each engagement in isolated environments (containers, VMs, or dedicated infrastructure). Enforce resource quotas and prevent cross-engagement data leakage through network and storage isolation.

**Key Considerations:**
- Automate environment provisioning and teardown
- Test isolation boundaries with penetration testing
- Verify complete cleanup after engagement completion

**Common Pitfalls:**
- Shared execution environments across multiple engagements
- Inadequate resource limits allowing noisy-neighbor problems
- Incomplete cleanup leaving artifacts from previous engagements

---

## APTS-TP-018: Tenant Breach Notification

**Implementation:** Notify all affected customers upon tenant isolation breach. Provide breach details, exposed data scope, and mitigation steps. Recommended SLA: initial notification within 1 hour of confirmed isolation failure, detailed report within 24 hours.

**Key Considerations:**
- Maintain up-to-date notification templates and customer contact lists
- Pre-build queries to identify affected customers quickly
- Coordinate cross-team communication before external notification

**Common Pitfalls:**
- Incomplete customer contact lists causing missed notifications
- Delayed notification while investigating scope
- Vague breach descriptions that leave customers unable to assess impact

---

## APTS-TP-019: AI Model Provenance and Training Data Governance

**Implementation:** Document model source, training datasets, and fine-tuning history for all AI models used. Verify no PII in training data. Maintain model cards with capability and limitation documentation.

**Key Considerations:**
- Audit provider training data practices during vendor vetting
- Monitor for model drift that may indicate undisclosed retraining
- Require providers to disclose material changes to model training

**Common Pitfalls:**
- Unknown training data origins creating compliance risk
- No model documentation or capability disclosure
- Missing provenance records for fine-tuned or custom models

---


## APTS-TP-020: Persistent Memory and Retrieval State Governance

**Implementation:** Inventory all persistent state types (logs, caches, vector stores, conversation history). Enforce strict isolation by engagement. Audit whether persistent state influences model outputs across engagements.

**Key Considerations:**
- Conduct regular state audits to identify untracked persistence
- Define clear retention and purge policies for all state types
- Test that engagement isolation prevents cross-contamination

**Common Pitfalls:**
- Untracked persistent state leaking between engagements
- Cross-engagement data influencing model behavior or recommendations
- No audit trail for persistent state access and modification

---

## APTS-TP-021: Foundation Model Disclosure and Capability Baseline

**Implementation:** Treat the foundation model as a first-class supply-chain dependency and document it the same way you document any other critical upstream component. Maintain a single source of truth (for example, a `foundation-model.yaml` in the platform configuration repository) that captures provider, family, pinned version identifier, the provider's stated release date, and every operator-applied customization (fine-tune id, adapter hashes, system prompt version, tool-use configuration version). Attach a capability baseline document citing the specific benchmarks or evaluations you are relying on for the claim that the model's offensive capability is within the envelope your safety controls were sized against. Include the disclosure file in the conformance claim generation pipeline so the claim cannot be produced without it. Expose the current disclosure to customers through the same channel you use for other transparency artifacts.

**Key Considerations:**
- The disclosure is informative for customers and load-bearing for reviewers; make it easy to find, not buried in an appendix
- Capability baselines age. Re-cite the source each time the disclosure is refreshed and note if the cited evaluation has been superseded
- Operator customizations (post-training, adapters, tool-use wiring) can shift capability as much as a base-model change and MUST be included in the disclosure

**Common Pitfalls:**
- Listing only the model family ("GPT-4 class", "Claude class") without a pinned version
- Treating the system prompt as a confidential differentiator and omitting it from the disclosure, which hides a meaningful part of the capability envelope from reviewers
- Publishing the disclosure once at vetting time and never refreshing it after silent provider-side model updates

---

## APTS-TP-022: Re-attestation on Material Foundation Model Change

**Implementation:** Wire the re-attestation obligation into the same change-management pipeline that governs any other production change. When a proposed model change hits the pipeline, run an automated pre-check that classifies it as material or non-material against the criteria in the README. Material changes open a re-assessment workpaper that exercises the SE, SC, MR, and AL controls against the candidate model in a staging environment and records the results, any adjustments to thresholds or allowlists, and the reviewer sign-off. Block promotion to production on the workpaper's completion. Generate the customer notification from the workpaper so the notification content is always consistent with what was actually re-tested. Keep the prior model pin and disclosure in version control so APTS-TP-002 rollback remains a one-command operation.

**Key Considerations:**
- The "material change" classifier should fail closed: if the change cannot be automatically classified, treat it as material and require human review
- Re-assessment does not mean running the entire APTS conformance assessment from scratch every time; it means running the subset the README requires, with documented scope
- Customer notification timing should be defined in your change management policy and respected even when the change is benign; predictability is the value customers are paying for

**Common Pitfalls:**
- Treating a provider-announced "minor" upgrade as automatically non-material without running the classifier
- Running the re-assessment against the new model but forgetting to regenerate the conformance claim and APTS-TP-021 disclosure
- Notifying customers after the changed platform has already handled one or more engagements, which defeats the purpose of the requirement

---

## Implementation Roadmap

**Tier 1 (implement before any autonomous pentesting begins):**
TP-001 (AI provider vetting), TP-003 (API security), TP-005 (provider breach notification), TP-006 (dependency inventory), TP-008 (cloud hardening), TP-012 and TP-013 (client data classification and minimization, sensitive data handling), TP-014 (encryption controls), TP-018 (tenant breach notification), TP-021 (foundation model disclosure and capability baseline).

Start with TP-001 and TP-012 (provider vetting, data classification and minimization). Know who handles your data and what data you send. Add TP-003 (API security) and TP-014 (encryption) for transit/rest protection, then TP-018 (tenant breach notification) for incident readiness. Add TP-021 in the same pass so the foundation model disclosure is in place before the platform handles its first engagement. Also consider TP-A01 (breach notification/regulatory reporting, Advisory) for general breach preparedness.

**Tier 2 (implement within first 3 engagements):**
TP-002 (model version pinning), TP-004 (provider failover), TP-009 (service continuity), TP-010 and TP-011 (vulnerability feed management and QA), TP-015 (data retention/deletion), TP-017 (engagement and tenant isolation), TP-019 (AI model provenance), TP-020 (persistent memory governance, SHOULD), TP-022 (re-attestation on material foundation model change). Also consider Advisory practices: TP-A02 (privacy compliance) and TP-A03 (professional liability).

Prioritize TP-017 (engagement and tenant isolation) first. Cross-tenant data leakage is the highest-impact supply chain risk. Then add TP-015 (secure deletion) and TP-022 (re-attestation on material foundation model change) so that model upgrades after the first engagement do not silently widen the platform's capability surface.

**Tier 3 (implement based on regulatory requirements):**
TP-007 (data residency/sovereignty, SHOULD), TP-016 (data destruction proof/certification).

---

## Advisory Practice Implementation Guidance

The following practices are not required for any compliance tier but provide additional assurance for platforms operating in regulated industries or high-risk environments. See the [Advisory Requirements](../appendix/Advisory_Requirements.md) appendix for rationale and recommendations.

### APTS-TP-A01: Breach Notification and Regulatory Reporting

**Implementation:** Establish breach identification and impact assessment procedures. Notify affected parties within applicable regulatory timeframes (GDPR: 72 hours; HIPAA: 60 days; US state laws: varies). Consult legal counsel for jurisdiction-specific requirements.

**Key Considerations:**
- Coordinate with legal and compliance teams from the start
- Pre-draft notification templates per jurisdiction
- Maintain detailed records of all notifications sent

**Common Pitfalls:**
- Delayed breach identification extending response timelines
- Incomplete notification missing required regulatory details
- No pre-built templates causing delays during active incidents

### APTS-TP-A02: Privacy Regulation Compliance

**Implementation:** Conduct Data Protection Impact Assessments (DPIA) for all data processing activities. Establish lawful basis for processing and document data subject rights procedures.

**Key Considerations:**
- Consult with Data Protection Officer (DPO) on all new processing activities
- Conduct regular compliance audits against applicable regulations
- Maintain records of processing activities as required by GDPR Article 30

**Common Pitfalls:**
- Missing DPIA for high-risk processing activities
- Unclear or undocumented lawful basis for data processing
- Poor handling of data subject access requests

### APTS-TP-A03: Professional Liability and Engagement Agreements

**Implementation:** Use formal engagement agreements with liability clauses, indemnification terms, and limitation of liability. Obtain professional liability insurance with coverage appropriate to engagement scope.

**Key Considerations:**
- Have legal counsel review all engagement contracts
- Ensure insurance coverage matches the scope and risk of engagements
- Include clear scope boundaries and exclusions in agreements

**Common Pitfalls:**
- Informal agreements without defined liability boundaries
- Inadequate insurance limits relative to engagement risk
- Missing limitation of liability clauses
