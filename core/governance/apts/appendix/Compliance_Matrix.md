# Compliance Matrix

Informative Appendix (non-normative)

This appendix is part of the OWASP Autonomous Penetration Testing Standard (APTS) and provides a cross-reference mapping of APTS requirements to major regulatory frameworks and standards. Use this matrix to understand how APTS controls align with external compliance frameworks. It is intended for both external reviewers mapping a vendor or service-provider platform against known frameworks, and enterprise security teams running an internal autonomous pentest platform who need to position APTS conformance against their existing governance program (SOC 2, ISO 27001, NIST CSF, and so on). Note: This mapping identifies areas of overlap and does not constitute legal advice or guarantee compliance with any external regulation. APTS requirements are often more specific to autonomous pentesting than external frameworks; compliance with APTS does not automatically mean compliance with mapped frameworks, and vice versa.

> **Note:** Mappings in this matrix identify areas where APTS requirements address concerns within external frameworks. A mapping does NOT constitute full compliance with the external framework. Organizations should perform their own compliance assessments for each applicable framework independently of APTS.

---

## Overview

This appendix maps APTS requirements to nine external frameworks:
1. **NIST Cybersecurity Framework (CSF) 2.0** - Risk-based cybersecurity framework
2. **ISO/IEC 27001:2022** - International information security standard
3. **NIST AI RMF 1.0** - AI risk management framework
4. **SOC 2 Trust Services Criteria (2017, with 2022 revised points of focus)** - Trust services for service organizations
5. **PCI DSS 4.0.1** - Payment card industry data security standard
6. **GDPR** - EU General Data Protection Regulation
7. **NIST SP 800-53 Rev. 5** - Federal information security controls
8. **HIPAA Security Rule (45 CFR Part 164)** - Healthcare data security requirements
9. **CIS Critical Security Controls v8** - Foundational security practices

The first four frameworks are mapped comprehensively across all domains. PCI DSS 4.0.1, GDPR, and HIPAA mappings apply primarily to data-handling, privacy, and supply chain requirements. NIST SP 800-53, CIS Controls, and other frameworks address specific governance and technical control areas.

Each framework requires specific controls. The standard's requirements often address areas relevant to multiple framework controls simultaneously.

---

## 1. NIST Cybersecurity Framework 2.0 Mapping

NIST CSF 2.0 organizes controls into six Functions and multiple Categories. APTS addresses categories across all functions.

### GOVERN Function

**GV.PO-1: Organizational Context**
- Related: Scope Enforcement (Scope Definition), Safety Controls
- Requirements: Document formal governance structure for autonomous pentesting platform operations
- Controls:
  - Establish APTS charter defining organizational roles, responsibilities, and approval authorities (APTS-HO-004)
  - Perform impact classification for every pentest action before execution using multi-tier system (APTS-SC-001)
  - Document cumulative risk scoring algorithm with automated escalation thresholds (APTS-SC-007)

**GV.PO-2: Roles and Responsibilities**
- Related: Human Oversight (Governance), Safety Controls
- Requirements: Document Authority Delegation Matrix specifying approval authority by role and action type
- Controls:
  - Maintain written Authority Delegation Matrix specifying which personnel can approve actions at which autonomy levels (APTS-HO-004)
  - Require mandatory human approval gates for all medium and high-impact actions with defined SLA response windows (APTS-HO-003)
  - Log all approval decisions with immutable audit trail including timestamp, approver identity, and rationale (APTS-HO-005)

**GV.RM-1: Risk Management Strategy**
- Related: Human Oversight (Risk Assessment), Safety Controls
- Requirements: Implement formal risk scoring and escalation controls for autonomous pentesting actions
- Controls:
  - Score every pentest action against Confidentiality/Integrity/Availability dimensions with minimum dimension determining escalation level (APTS-SC-001)
  - Implement graduated responsibility escalation with automatic actions, approval requirements, and prohibited thresholds (APTS-SC-006)
  - Track cumulative risk score across entire engagement with configurable decay and reset windows (APTS-SC-007)

**GV.RM-2: Cybersecurity Supply Chain Risk**
- Related: Supply Chain Trust (Third-Party Dependencies)
- Requirements: Establish vetting process and maintain inventory of all third-party dependencies
- Controls:
  - Document AI provider selection and vetting process assessing security posture, data protection, reliability, and compliance (APTS-TP-001)
  - Maintain complete inventory of software dependencies and third-party components with version numbers and vulnerability tracking (APTS-TP-006)
  - Perform continuous vulnerability monitoring on all dependencies and implement update strategy balancing security with testing requirements (APTS-TP-006)

### IDENTIFY Function

**ID.AM-1: Asset Management**
- Related: Scope Enforcement (Scope Definition)
- Requirements: Ingest machine-parseable scope with complete target inventory and asset criticality classifications
- Controls:
  - Ingest and validate machine-parseable Rules of Engagement containing target lists, temporal boundaries, and action restrictions (APTS-SE-001)
  - Validate all IP ranges using CIDR notation, detecting overlaps and maintaining awareness of reserved IP space (APTS-SE-002)
  - Classify each asset by criticality level (Critical, Production, Non-Production) with corresponding action restrictions enforced at runtime (APTS-SE-005)

**ID.AM-4: External Information Systems**
- Related: Third-Party & Supply Chain Trust
- Requirements: Maintain comprehensive inventory of cloud dependencies and third-party services
- Controls:
  - Document all AI provider dependencies with vetting criteria including data protection and contractual terms (APTS-TP-001)
  - Maintain Software Bill of Materials (SBOM) including versions and vulnerability tracking for all dependencies (APTS-TP-006)
  - Perform risk assessment for each dependency evaluated against criticality of its use in operations (APTS-TP-006)

**ID.RA-1: Asset Vulnerabilities**
- Related: Graduated Autonomy, Auditability (Vulnerability Assessment & Exploitation)
- Requirements: Identify vulnerabilities through automated scanning with findings confidence scoring
- Controls:
  - Maintain authoritative mapping of pentest techniques with pre-classified impact levels, CIA scores, and reversibility status (APTS-SC-001)
  - Log all vulnerability assessment findings as decision events with confidence scores and alternative actions evaluated (APTS-AR-004)
  - Record vulnerability metadata including type, severity, evidence hashes, and CVE references in structured log format (APTS-AR-001)

**ID.RA-2: Threat Identification**
- Related: Scope Enforcement (Scope Definition and Approval)
- Requirements: Assess target system threats within scope boundaries with explicit approval
- Controls:
  - Document domain scope specifications with explicit wildcard policies distinguishing exact domains, all subdomains, and single-level wildcards (APTS-SE-003)
  - Perform continuous DNS monitoring and cloud boundary validation to detect scope drift before unauthorized testing (APTS-SE-007)
  - Maintain hard deny list of assets that cannot be tested regardless of scope (production databases, critical infrastructure, PII datastores) enforced before all scope checks (APTS-SE-009)

### PROTECT Function

**PR.AA-1: Identity Management, Authentication, and Access Control Policy**
- Related: Auditability (Data Protection) + Supply Chain Trust (Data Handling)
- Requirements: Implement role-based access control with multi-tenancy isolation
- Controls:
  - Define role-based access control for autonomous system operator functions with delegation of authority by action type (APTS-HO-004)
  - Implement multi-tenancy isolation controlling data access between engagements with row-level security and file system permissions (APTS-TP-017)
  - Restrict operator access to engagement-specific scope, findings, and data with mandatory access control enforcement (APTS-TP-017)

**PR.AA-2: Access Enforcement**
- Related: Supply Chain Trust (Multi-Tenancy Data Isolation)
- Requirements: Enforce access controls at database, file system, and network layers
- Controls:
  - Implement row-level security controls ensuring operators cannot access data outside assigned engagements (APTS-TP-017)
  - Enforce file system permissions with restricted access to engagement findings and evidence (APTS-TP-017)
  - Isolate testing network traffic per engagement with network segmentation and firewall rules (APTS-TP-017)

**PR.DS-1: Data Security Policy**
- Related: Auditability (Data Protection) + Supply Chain Trust (Data Handling)
- Requirements: Classify data by sensitivity level and minimize transmission to external providers
- Controls:
  - Establish data classification framework distinguishing Public, Sensitive, Confidential, and Restricted sensitivity levels (APTS-TP-012)
  - Implement data minimization by stripping unnecessary metadata, redacting credentials/API keys, and anonymizing IPs before transmission to providers (APTS-TP-012)
  - Obtain explicit client consent disclosing specific AI providers used, data categories sent, and data retention policies (APTS-TP-012)

**PR.DS-2: Data In Transit**
- Related: Supply Chain Trust (Encryption & Data Handling)
- Requirements: Enforce encryption for all data transmitted to external providers
- Controls:
  - Enforce TLS 1.2 minimum (TLS 1.3 preferred) with certificate validation for all API calls to external providers (APTS-TP-003)
  - Implement mutual TLS for service-to-service authentication where supported by providers (APTS-TP-003)
  - Monitor all API usage patterns for anomalies and enforce secure credential storage with rotation schedules (APTS-TP-003)

**PR.DS-3: Data At Rest**
- Related: Supply Chain Trust (Encryption & Data Handling)
- Requirements: Encrypt sensitive data at rest with documented key management and deletion procedures
- Controls:
  - Encrypt engagement data at rest including findings, evidence, and credentials using documented encryption standards (APTS-TP-014)
  - Implement key management controls with separate key storage from encrypted data and key rotation procedures (APTS-TP-014)
  - Define and test secure deletion procedures for sensitive data with verification that old data cannot be recovered (APTS-TP-014)

**PR.PS-1: Security Policy**
- Related: Scope Enforcement, Safety Controls, Human Oversight (Governance and Scope)
- Requirements: Document APTS security policies, Rules of Engagement, and approval workflows
- Controls:
  - Establish written APTS charter defining organizational context, roles, and decision authorities (APTS-HO-004)
  - Document Rules of Engagement in machine-parseable format specifying scope, temporal boundaries, and action restrictions (APTS-SE-001)
  - Implement scope approval workflows enforcing pre-action scope validation for all network actions before execution (APTS-SE-006)

**PR.PS-2: Third-Party Maintenance**
- Related: Supply Chain Trust (Third-Party Dependencies)
- Requirements: Monitor provider SLAs and establish incident response for provider failures
- Controls:
  - Continuously monitor provider availability against documented SLAs with automated alerts for failures (APTS-TP-004)
  - Establish documented failover procedures for critical providers with fallback providers identified and tested (APTS-TP-004)
  - Establish incident response procedures for provider breaches with breach notification obligations aligned to regulatory requirements (APTS-TP-005)

### DETECT Function

**DE.AE-1: Detection Processes**
- Related: Human Oversight + Supply Chain Trust (Risk Assessment & Monitoring)
- Requirements: Detect vulnerabilities and anomalies with confidence scoring and false positive procedures
- Controls:
  - Implement anomaly detection identifying deviations from baseline for testing patterns, decision-making patterns, and action patterns (APTS-SC-010)
  - Score all anomalies with confidence levels and route according to documented escalation policy (APTS-SC-010)
  - Generate decision event logs for all detection findings with evidence hashes and vulnerability metadata (APTS-AR-004)

**DE.CM-1: Network Monitoring**
- Related: Supply Chain Trust (Cloud Dependencies & Monitoring)
- Requirements: Monitor target system health and detect impacts during testing
- Controls:
  - Continuously monitor target system health with response time measurement and service availability verification (APTS-SC-010)
  - Establish baseline metrics within first 5 health check cycles and detect degradation exceeding 200% of baseline (APTS-SC-010)
  - Implement circuit breaker logic automatically suspending testing on sustained degradation with cooldown and probe-based recovery (APTS-SC-012)

**DE.CM-2: Data Monitoring**
- Related: Supply Chain Trust (Data Handling)
- Requirements: Monitor all data access and implement breach detection mechanisms
- Controls:
  - Log all data access with structured event logging including timestamp, source, target, and data accessed (APTS-AR-001)
  - Implement breach detection mechanisms monitoring for unauthorized data exfiltration patterns (APTS-TP-017)
  - Establish DLP monitoring rules specific to regulated data types (PHI, PCI, PII) with automatic escalation (APTS-SC-002)

### RESPOND Function

**RS.MA-1: Response Planning**
- Related: Manipulation Resistance (Incident Response) + Supply Chain Trust (Breach Notification)
- Requirements: Establish documented incident response plan with escalation procedures and team assignments
- Controls:
  - Document platform incident response plan specifying response timelines, communication channels, and recovery procedures (APTS-SC-018)
  - Define escalation procedures routing detected anomalies to human operators with defined SLA notification timelines (APTS-SC-017)
  - Assign incident response team members with documented responsibilities and communication protocols (APTS-SC-018)

**RS.MI-1: Incident Handling**
- Related: Manipulation Resistance (Incident Response)
- Requirements: Classify, investigate, and preserve evidence for all detected incidents
- Controls:
  - Classify incidents with confidence levels and route to appropriate response team per documented escalation policy (APTS-SC-010)
  - Preserve memory dumps, log snapshots, network captures, and process state before any containment procedures (APTS-SC-018)
  - Document incident timeline, root cause, affected systems, remediation steps, and lessons learned in post-incident report (APTS-SC-018)

**RS.CO-1: Response Communication**
- Related: Manipulation Resistance + Supply Chain Trust (Incident Response & Breach Notification)
- Requirements: Notify operators and customers of incidents within defined SLA timelines
- Controls:
  - Establish Watchdog infrastructure monitoring platform health with independent network and credentials (APTS-SC-017)
  - Notify operators within defined SLA timeframe via multiple channels (messaging, email, dashboard) upon anomaly detection (APTS-SC-017)
  - Notify customers within documented SLA of confirmed incidents including what happened, systems affected, and actions taken (APTS-SC-017)

### RECOVER Function

**RC.RP-1: Recovery Planning**
- Related: Supply Chain Trust (Business Continuity)
- Requirements: Establish disaster recovery procedures with documented RTO and RPO targets
- Controls:
  - Document recovery procedures for each incident containment scenario with defined Recovery Time Objective (RTO) (APTS-SC-018)
  - Execute complete safety control validation after recovery: kill switches, health monitoring, anomaly detection, and rollback procedures (APTS-SC-018)
  - Perform backup and restoration testing to verify recovery procedures function and within RTO targets (APTS-TP-009)

---

## 2. ISO/IEC 27001:2022 Mapping

ISO/IEC 27001:2022 contains 93 controls organized into four themes: A.5 Organizational (37 controls), A.6 People (8 controls), A.7 Physical (14 controls), and A.8 Technological (34 controls). Below are key controls addressed by APTS.

### A.5: Organizational Controls

**A.5.1: Policies for information security**
- Controls: Establish APTS charter defining organizational roles and decision authorities (APTS-HO-004); document Rules of Engagement specifying testing scope and boundaries (APTS-SE-001); implement scope approval workflows with pre-action validation (APTS-SE-006)
- Addresses:

**A.5.2: Information security roles and responsibilities**
- Controls: Document Authority Delegation Matrix specifying approval authority by role and action type (APTS-HO-004); implement mandatory approval gates for medium and high-impact actions (APTS-HO-001); maintain immutable decision audit trail (APTS-HO-005)
- Addresses:

**A.5.7: Threat intelligence**
- Controls: Maintain authoritative technique mapping with impact classifications, CIA scores, and reversibility status (APTS-SC-001); log all decision points with confidence scores and alternative actions evaluated (APTS-AR-004); establish baseline for anomaly detection from threat feeds (APTS-SC-010)
- Addresses:

**A.5.8: Information security in project management**
- Controls: Ingest and validate machine-parseable Rules of Engagement with target lists, temporal boundaries, and action restrictions (APTS-SE-001); perform pre-action scope validation for all network actions (APTS-SE-006); continuously monitor for DNS changes and scope drift (APTS-SE-007)
- Addresses:

**A.5.19: Information security in supplier relationships**
- Controls: Document AI provider vetting process assessing security posture, data protection, and compliance (APTS-TP-001); maintain complete inventory of software dependencies and third-party components (APTS-TP-006); perform risk assessment for each dependency (APTS-TP-006)
- Addresses:

**A.5.20: Addressing information security within supplier agreements**
- Controls: Establish SLA requirements for critical providers with minimum 99.5% uptime; include breach notification obligations aligned to regulatory requirements in provider contracts (APTS-TP-004, APTS-TP-005)
- Addresses:

**A.5.21: Managing information security in the ICT supply chain**
- Controls: Document all third-party service dependencies with version numbers and known vulnerabilities in SBOM (APTS-TP-006); maintain alternative providers for critical services (APTS-TP-004)
- Addresses:

**A.5.22: Monitoring, review and change management of supplier services**
- Controls: Continuously monitor provider availability against documented SLAs with automated alerts for failures (APTS-TP-004); establish incident response procedures for provider breaches (APTS-TP-005)
- Addresses:

**A.5.23: Information security for use of cloud services**
- Controls: Establish procedures to respond to provider compromises discovered during active engagements (APTS-TP-005); validate cloud resource boundaries for AWS, Azure, GCP in-scope actions (APTS-SE-007)
- Addresses:

**A.5.24: Information security incident management planning and preparation**
- Controls: Document platform incident response plan with response timelines and communication channels (APTS-SC-018); establish Watchdog infrastructure monitoring with independent network (APTS-SC-017); define explicit termination conditions with detailed logging (APTS-SC-011)
- Addresses:

**A.5.25: Assessment and decision on information security events**
- Controls: Score anomalies with confidence levels and route according to documented escalation policy (APTS-SC-010); classify incidents and perform independent audit log validation before confirming (APTS-SC-017)
- Addresses:

**A.5.26: Response to information security incidents**
- Controls: Execute automatic network isolation and credential rotation upon confirmed incident (APTS-SC-018); preserve evidence on separate secure system before containment (APTS-SC-018); escalate to customers within documented SLA (APTS-SC-017)
- Addresses:

**A.5.28: Collection of evidence**
- Controls: Capture screenshots, log output, and modified file contents before rollback in write-once, tamper-evident storage (APTS-SC-016); preserve memory dump and logs for forensic investigation (APTS-SC-018)
- Addresses:

**A.5.29: Information security during disruption**
- Controls: Establish documented failover procedures for critical providers with fallback providers identified (APTS-TP-004); implement kill switch for immediate halt of all testing with Phase 1 (5 seconds) and Phase 2 (60 seconds) sequencing (APTS-SC-009)
- Addresses:

**A.5.30: ICT readiness for business continuity**
- Controls: Document recovery procedures with defined Recovery Time Objective (RTO) for each incident scenario (APTS-SC-018); perform complete safety control validation after recovery verifying all controls pass (APTS-SC-018)
- Addresses:

**A.5.31: Legal, statutory, regulatory and contractual requirements**
- Controls: Adjust impact classifications for industry-specific regulatory requirements including healthcare (PHI access as Critical) and financial systems (PCI data access as Critical) (APTS-SC-002)
- Addresses:

**A.5.33: Protection of records**
- Controls: Log all events in structured format with cryptographic timestamps and immutability enforcement (APTS-AR-001, APTS-AR-001); maintain append-only log storage with minimum 12-month retention (APTS-AR-005); validate cryptographic signatures on audit log entries (APTS-AR-005)
- Addresses:

**A.5.34: Privacy and protection of PII**
- Controls: Classify data by sensitivity level (Public, Sensitive, Confidential, Restricted) with data minimization before external transmission (APTS-TP-012); detect and redact PII/PHI/PCI data before logging or transmission (APTS-TP-012)
- Addresses:

**A.5.36: Conformance with policies, rules and standards for information security**
- Controls: Enforce temporal scope boundaries with no testing before start_time or after end_time (APTS-SE-008); verify authorized contacts listed in RoE and reachable within 5 minutes (APTS-HO-002)
- Addresses:

**A.5.37: Documented operating procedures**
- Controls: Document all required APTS procedures including Rules of Engagement (APTS-SE-001), incident response (APTS-SC-018), and rollback procedures (APTS-SC-014); maintain operational documentation for scope validation and escalation (APTS-SE-006, APTS-HO-003)
- Addresses:

### A.6: People Controls

**A.6.3: Information security awareness, education and training**
- Controls: Provide security training for platform operators covering approval authority, decision delegation, and incident response procedures
- Addresses:

### A.7: Physical Controls

**A.7.1: Physical security perimeters**
- Controls: Data center security, facility access controls
- Addresses: (organizational responsibility)

### A.8: Technological Controls

**A.8.1: User endpoint devices**
- Controls: Enforce Rules of Engagement scope for all client-side agents with hard deny list enforcement (APTS-SE-009)
- Addresses:

**A.8.2: Privileged access rights**
- Controls: Implement multiple independent kill switch mechanisms with operator-initiated, remote, and automatic failsafe halts (APTS-SC-009); require multi-factor authentication for sensitive approval actions
- Addresses:

**A.8.3: Information access restriction**
- Controls: Implement multi-tenancy isolation with row-level security restricting operator access to assigned engagements (APTS-TP-017); enforce least privilege in Authority Delegation Matrix (APTS-HO-004)
- Addresses:

**A.8.4: Access to source code**
- Controls: Document code signing and verification processes for platform integrity; maintain secure source code repositories with access controls
- Addresses:

**A.8.5: Secure authentication**
- Controls: Enforce secure credential storage with never-in-code API keys and documented rotation schedules (APTS-TP-003); implement mutual TLS for service-to-service authentication (APTS-TP-003)
- Addresses:

**A.8.7: Protection against malware**
- Controls: Maintain SBOM with continuous vulnerability monitoring of all dependencies (APTS-TP-006); implement input sanitization preventing target-side content from modifying tool behavior (APTS-MR-002)
- Addresses: (organizational responsibility)

**A.8.8: Management of technical vulnerabilities**
- Controls: Maintain authoritative mapping of pentest techniques with pre-classified impact levels and reversibility status (APTS-SC-001); continuously monitor vulnerability feeds (APTS-TP-006)
- Addresses:

**A.8.9: Configuration management**
- Controls: Store threshold configurations in structured format with schema validation (APTS-SC-008); maintain baseline configurations for scanning tools and impact classification updates
- Addresses:

**A.8.10: Information deletion**
- Controls: Implement secure deletion procedures with verification that data cannot be recovered (APTS-TP-014); provide automated cleanup of all test artifacts with idempotent execution (APTS-SC-016)
- Addresses:

**A.8.11: Data masking**
- Controls: Implement data minimization by stripping metadata, redacting credentials, and anonymizing IPs before transmission (APTS-TP-012); sanitize responses removing instruction-like patterns before processing (APTS-MR-002)
- Addresses:

**A.8.12: Data leakage prevention**
- Controls: Classify data as Public, Sensitive, Confidential, or Restricted with access restrictions enforced by classification (APTS-TP-012); establish DLP monitoring rules for regulated data types (PHI, PCI, PII) (APTS-SC-002)
- Addresses:

**A.8.15: Logging**
- Controls: Log all events in structured format with mandatory fields including timestamp, event type, source, target, and status code (APTS-AR-001, APTS-AR-001); enforce immutable append-only storage with cryptographic signatures (APTS-AR-005)
- Addresses:

**A.8.16: Monitoring activities**
- Controls: Implement anomaly detection identifying deviations from baseline for testing patterns, decision-making patterns, and action patterns (APTS-SC-010); route anomalies by confidence level per documented escalation policy
- Addresses:

**A.8.20: Networks security**
- Controls: Validate all IP ranges using CIDR notation with overlap detection and reserved IP space awareness (APTS-SE-002); monitor for DNS changes and scope drift during engagement (APTS-SE-007)
- Addresses:

**A.8.21: Security of network services**
- Controls: Enforce TLS 1.2 minimum (TLS 1.3 preferred) for all API calls to external providers with certificate validation (APTS-TP-003)
- Addresses:

**A.8.22: Segregation of networks**
- Controls: Implement network isolation controls for multi-tenancy with file system permission enforcement and network segmentation (APTS-TP-017); isolate testing network traffic per engagement
- Addresses:

**A.8.24: Use of cryptography**
- Controls: Encrypt engagement data at rest with documented encryption standards (APTS-TP-014); enforce TLS for data in transit and implement key management with separate key storage (APTS-TP-014)
- Addresses:

**A.8.25: Secure development life cycle**
- Controls: Document secure platform development practices with regular security testing; implement defense-in-depth controls for prompt injection prevention (APTS-MR-001 through APTS-MR-012)
- Addresses:

**A.8.28: Secure coding**
- Controls: Enforce instruction boundary enforcement with cryptographic verification of operator-provided instructions (APTS-MR-001); prevent target-side content from influencing tool behavior
- Addresses:

**A.8.31: Separation of development, test and production environments**
- Controls: Segregate development, test, and production environments with controlled data flow between environments
- Addresses:

**A.8.32: Change management**
- Controls: Implement version pinning for AI models with formal change management and testing before deployment (APTS-TP-002); document configuration changes and deploy within defined windows
- Addresses:

**A.8.33: Test information**
- Controls: Handle test data without exposing production credentials; redact sensitive data from test logs and evidence
- Addresses:

**A.8.34: Protection of information systems during audit testing**
- Controls: Preserve evidence in write-once, tamper-evident storage before any rollback (APTS-SC-016); maintain cryptographically signed audit logs with immutability validation (APTS-AR-005)
- Addresses:

---

## 3. SOC 2 Trust Services Criteria Mapping (2017 TSC, 2022 revised Points of Focus)

SOC 2 defines five trust services categories with specific Trust Services Criteria. Mappings reference the AICPA 2017 Trust Services Criteria as revised with 2022 Points of Focus. The standard addresses all five categories.

### Principle 1: Security (CC - Common Criteria)

**CC1: The entity has defined security objectives.**
- Controls: Establish APTS charter documenting organizational roles, decision authorities, and security objectives (APTS-HO-004); define Rules of Engagement specifying scope and boundaries (APTS-SE-001)
- Addresses:

**CC2: The board of directors demonstrates independence from management.**
- Controls: Establish organizational governance with CISO oversight and documented Authority Delegation Matrix (APTS-HO-004)
- Addresses:

**CC3: Management establishes structures, reporting lines, and appropriate authorities.**
- Controls: Document Authority Delegation Matrix specifying approval authority by role and action type (APTS-HO-004); implement escalation procedures with defined SLA response windows (APTS-HO-003)
- Addresses:

**CC4: The entity holds people accountable for their responsibilities.**
- Controls: Maintain immutable decision audit trail for all approvals with timestamp, approver identity, and rationale (APTS-HO-005); log all operator activities with structured event format (APTS-AR-001)
- Addresses:

**CC6: The entity defines and implements logical access controls.**
- Controls: Define role-based access control for autonomous system operator functions (APTS-HO-004); enforce multi-tenancy isolation with row-level security restricting access per engagement (APTS-TP-017)
- Addresses:

**CC7: The entity restricts access to assets.**
- Controls: Classify data as Public, Sensitive, Confidential, or Restricted with access controls enforced by classification (APTS-TP-012); encrypt engagement data at rest with documented key management (APTS-TP-014)
- Addresses:

**CC9: The entity obtains or generates information to support operation.**
- Controls: Log all events in structured format with timestamps and required fields (APTS-AR-001, APTS-AR-001); maintain audit trails for 12 months minimum with immutability validation (APTS-AR-005)
- Addresses:

### Principle 2: Availability (A)

**A1.1: The entity obtains or generates, uses, and communicates relevant, quality information regarding the objectives and responsibilities for information and communication technology security to support the functioning of other principles.**
- Controls: Continuously monitor platform health with heartbeat, resource utilization, and behavioral baselines (APTS-SC-010); establish Watchdog infrastructure monitoring with independent network (APTS-SC-017)
- Addresses:

**A1.2: The entity authorizes, designs, develops, configures, documents, tests, approves, implements, maintains, monitors, evaluates, and disposes of changes to systems to achieve objectives.**
- Controls: Implement version pinning for AI models with formal change management and testing before deployment (APTS-TP-002); store configuration in structured format with schema validation (APTS-SC-008)
- Addresses:

**A1.3: The entity authorizes, designs, develops, configures, documents, tests, approves, implements, and maintains physical and logical access controls.**
- Controls: Enforce Authority Delegation Matrix with role-based access control (APTS-HO-004); implement multi-tenancy isolation with row-level security (APTS-TP-017)
- Addresses:

### Principle 3: Processing Integrity (PI)

**PI1.1: The entity obtains or generates, uses, and communicates relevant, quality information regarding the objectives and responsibilities for processing integrity to support the functioning of other principles.**
- Controls: Classify data as Public, Sensitive, Confidential, or Restricted with minimization before external transmission (APTS-TP-012); detect and redact PII/PHI/PCI data before logging (APTS-TP-012)
- Addresses:

**PI1.2: The entity authorizes, designs, configures, implements, maintains, and monitors technologies to achieve objectives related to processing integrity.**
- Controls: Validate all target-side responses and sanitize before processing by LLM (APTS-MR-002); implement defense-in-depth controls preventing prompt injection (APTS-MR-001 through APTS-MR-012)
- Addresses:

**PI1.3: The entity authorizes, designs, develops, configures, documents, tests, approves, implements, and maintains policies and procedures for processing integrity.**
- Controls: Document data handling procedures with explicit data minimization, redaction, and retention policies (APTS-TP-012); define validation procedures for all scope decisions (APTS-SE-006)
- Addresses:

**PI1.4: The entity authorizes, designs, develops, configures, documents, tests, approves, implements, and maintains monitoring of operations to achieve objectives.**
- Controls: Implement continuous vulnerability monitoring of dependencies (APTS-TP-006); monitor target system health with degradation detection (APTS-SC-010)
- Addresses:

**PI1.5: The entity authorizes, designs, develops, configures, documents, tests, approves, implements, and maintains the physical infrastructure.**
- Controls: Establish infrastructure segregation with separate storage for health monitoring data and audit logs (APTS-SC-010)
- Addresses:

### Principle 4: Confidentiality (C)

**C1.1: The entity obtains or generates, uses, and communicates relevant, quality information regarding the objectives and responsibilities for confidentiality to support the functioning of other principles.**
- Controls: Classify data by sensitivity level (Public, Sensitive, Confidential, Restricted) (APTS-TP-012); obtain explicit client consent disclosing AI providers and data categories (APTS-TP-012)
- Addresses:

**C1.2: The entity authorizes, designs, develops, configures, documents, tests, approves, implements, and maintains logical and physical access controls.**
- Controls:
  - Access controls (APTS-HO-004)
  - Encryption (APTS-TP-014)
  - Multi-tenancy isolation (APTS-TP-017)
- Addresses:

**C1.3: The entity authorizes, designs, develops, configures, documents, tests, approves, implements, and maintains technologies to achieve objectives.**
- Controls:
  - Encryption technologies
  - Secure deletion (APTS-TP-016)
  - Data protection mechanisms
- Addresses:

### Principle 5: Privacy (P)

**P2.1: The entity provides notice to data subjects about privacy practices.**
- Controls: Include data handling disclosures in engagement documents specifying AI provider usage and data categories (APTS-TP-012); obtain written consent before testing regulated data types (APTS-SC-002)
- Addresses:

**P2.2: The entity obtains and retains evidence of explicit consent prior to the collection, use, and sharing of personal information.**
- Controls: Document explicit client consent for data handling practices with specific AI providers and data categories (APTS-TP-012); obtain consent before transmitting classified data (APTS-TP-012)
- Addresses:

---

## 4. NIST AI RMF 1.0 Mapping

NIST AI RMF 1.0 defines four functions for managing AI system risks. APTS addresses controls across all four functions, with particular depth in GOVERN and MANAGE.

### GOVERN Function

**GOVERN 1: Policies and Procedures**
- Controls: Implement graduated autonomy governance with mandatory approval gates for all significant actions at L1 (APTS-HO-001); document human oversight policies specifying role responsibilities (APTS-HO-004)
- Addresses:

**GOVERN 2: Accountability Structures**
- Controls: Establish Authority Delegation Matrix specifying approval authority by role and action type (APTS-HO-004); implement escalation chains with documented SLA response windows (APTS-HO-003)
- Addresses:

### MAP Function

**MAP 1: AI System Context and Risk Framing**
- Controls: Ingest machine-parseable Rules of Engagement specifying scope, boundaries, and action restrictions (APTS-SE-001); implement multi-tier impact classification system for every action before execution (APTS-SC-001)
- Addresses:

**MAP 2: AI Impact Characterization**
- Controls: Continuously monitor target system health with degradation detection and automatic escalation (APTS-SC-010); implement circuit breaker logic suspending testing on sustained degradation (APTS-SC-012)
- Addresses:

### MEASURE Function

**MEASURE 1: AI System Performance and Risk Metrics**
- Controls: Log all decisions with confidence scores and auditable methodology (APTS-AR-004); document CIA impact scores for each pentest action (APTS-SC-001)
- Addresses:

**MEASURE 2: AI System Trustworthiness Characteristics**
- Controls: Log decision points with all alternatives evaluated and selected action justification (APTS-AR-004); maintain structured logs with confidence scores and risk assessment (APTS-AR-001)
- Addresses:

### MANAGE Function

**MANAGE 1: AI Risk Treatment and Response**
- Controls: Implement multiple independent kill switch mechanisms with Phase 1 (5 seconds) and Phase 2 (60 seconds) sequencing (APTS-SC-009); enforce instruction boundary enforcement with cryptographic verification of operator instructions (APTS-MR-001)
- Addresses:

**MANAGE 2: Continuous Monitoring**
- Controls: Implement platform health monitoring with anomaly detection for testing patterns and decision-making patterns (APTS-SC-010); establish external Watchdog on independent infrastructure monitoring platform health (APTS-SC-017)
- Addresses:

---

## 5. PCI DSS Mapping

PCI DSS 4.0.1 contains 12 requirements for payment card security. The standard addresses applicable controls (not all apply if the platform doesn't handle payment cards directly).

**Requirement 1: Firewall Configuration**
- Controls: Implement network isolation controls for multi-tenancy with network segmentation (APTS-TP-017)
- Applicable if: the platform processes cardholder data
- Addresses:

**Requirement 2: Default Passwords**
- Controls: Enforce strong authentication with API key rotation schedules and secure credential storage (APTS-TP-003)
- Applicable if: the platform systems exposed to external networks
- Addresses:

**Requirement 3: Stored Data Protection**
- Controls: Encrypt engagement data at rest with documented encryption standards and key management (APTS-TP-014)
- Applicable if: the platform stores card data
- Addresses:

**Requirement 4: Transmitted Data Protection**
- Controls: Enforce TLS 1.2 minimum (TLS 1.3 preferred) for all API calls to external providers (APTS-TP-003); implement data minimization redacting payment data before transmission (APTS-TP-012)
- Applicable if: the platform transmits card data
- Addresses:

**Requirement 6: Secure Development**
- Controls: Implement defense-in-depth controls preventing prompt injection (APTS-MR-001 through APTS-MR-012); enforce input sanitization removing instruction-like patterns (APTS-MR-002)
- Applicable if: the platform developed in-house
- Addresses:

**Requirement 7: Access Control**
- Controls: Define role-based access control for operators with Authority Delegation Matrix (APTS-HO-004); enforce least privilege through multi-tenancy isolation (APTS-TP-017)
- Applicable if: the platform processes card data
- Addresses:

**Requirement 8: User Identification**
- Controls: Enforce multi-factor authentication for approval actions; log all operator activities with structured event format (APTS-AR-001)
- Applicable if: the platform processes card data
- Addresses:

**Requirement 10: Logging and Monitoring**
- Controls: Log all events in structured format with timestamps, status codes, and mandatory fields (APTS-AR-001, APTS-AR-001); maintain audit trails for 12 months minimum (APTS-AR-005)
- Applicable if: the platform processes card data
- Addresses:

**Requirement 11: Vulnerability Management**
- Controls: Maintain SBOM with continuous vulnerability monitoring of dependencies (APTS-TP-006); implement version pinning with formal change management (APTS-TP-002)
- Applicable always
- Addresses:

**Requirement 12: Policies and Procedures**
- Controls: Document APTS charter with security policies and procedures (APTS-HO-004); establish Rules of Engagement with approval workflows (APTS-SE-001)
- Applicable always
- Addresses:

---

## 6. GDPR Mapping

GDPR (EU privacy regulation) contains key obligations for processing personal data. The standard addresses applicable articles.

**Article 4: Definitions**
- Controls: Classify data as Public, Sensitive, Confidential, or Restricted with explicit definitions (APTS-TP-012)
- Addresses: Defines what constitutes personal data, processing
- Addresses:

**Article 5: Principles**
- Controls: Obtain explicit client consent disclosing AI providers and data categories (APTS-TP-012); implement data minimization stripping metadata and redacting credentials (APTS-TP-012); maintain secure deletion procedures with verification (APTS-TP-014)
- Addresses:

**Article 6: Lawfulness of Processing**
- Controls: Document explicit client consent in engagement agreement disclosing specific data processing practices (APTS-TP-012)
- Addresses:

**Article 9: Processing Special Categories**
- Controls: Adjust impact classifications for special categories treating PHI/PCI access as Critical (APTS-SC-002); provide extra protections and documentation if applicable
- Addresses: (with additional safeguards if applicable)

**Article 12-14: Transparency**
- Controls: Include privacy notices in engagement documents explaining data handling (APTS-TP-012); provide audit trail of data processing activities (APTS-AR-001, APTS-AR-001)
- Addresses:

**Article 17: Right to Erasure**
- Controls: Implement secure deletion procedures with verification that data cannot be recovered (APTS-TP-014); provide automated cleanup of test artifacts (APTS-SC-016)
- Addresses:

**Article 18: Right to Restriction**
- Controls: Preserve evidence in write-once storage before cleanup enabling data retention flexibility (APTS-SC-016)
- Addresses:

**Article 28: Data Processing Agreements**
- Controls: Establish Data Processing Agreements with external providers including breach notification obligations (APTS-TP-005); document sub-processor agreements with AI providers and cloud services (APTS-TP-001)
- Addresses:

**Article 32: Security of Processing**
- Controls: Encrypt engagement data at rest and in transit with documented encryption standards (APTS-TP-014); implement data minimization as pseudonymization (APTS-TP-012); enforce multi-tenancy isolation controls (APTS-TP-017)
- Addresses:

**Article 33: Breach Notification**
- Controls: Establish incident response procedures for provider breaches with breach notification obligations aligned to regulatory timelines (APTS-TP-005); document breach assessment and notification timeline
- Addresses:

**Article 34: Individual Notification**
- Controls: Notify affected tenants or individuals upon confirmed breach in accordance with documented notification procedures and required notification contents (APTS-TP-018)
- Addresses:

---

## 7. Domain Compliance Mappings

This section maps all 8 APTS domains to external frameworks, organized by domain.

### 6.1 Scope Enforcement (APTS-SE)

| APTS Requirement | NIST CSF 2.0 | ISO/IEC 27001:2022 | NIST AI RMF 1.0 | SOC 2 TSC 2017 (2022 PoF) | Notes |
|---|---|---|---|---|---|
| APTS-SE-001: Rules of Engagement (RoE) Specification and Validation | GV.PO-1 | A.5.8 | GOVERN 1 | CC3.2 | Scope definition and validation process control |
| APTS-SE-002: IP Range Validation and RFC 1918 Awareness | ID.AM-1 | A.8.20, A.8.22 | GOVERN 1 | CC1.1 | Asset inventory validation, scope boundary enforcement |
| APTS-SE-003: Domain Scope Validation and Wildcard Handling | ID.AM-1 | A.8.20 | GOVERN 1 | CC1.1 | Domain ownership verification, third-party detection |
| APTS-SE-004: Temporal Boundary and Timezone Handling | GV.PO-1 | A.5.37, A.8.16 | GOVERN 1 | CC2.1 | Time-based operational controls, timezone handling |
| APTS-SE-005: Asset Criticality Classification and Integration | ID.AM-5 | A.5.12 | GOVERN 1 | CC4.1 | Risk-based testing restrictions per asset tier |
| APTS-SE-006: Pre-Action Scope Validation | PR.AA-1 | A.8.5 | GOVERN 1 | CC6.6 | Authorization boundary enforcement before action |
| APTS-SE-007: Dynamic Scope Monitoring and Drift Detection | DE.CM-1 | A.8.16 | MAP 1 | CC9.1 | Continuous drift detection, boundary violation alerts |
| APTS-SE-008: Temporal Scope Compliance Monitoring | DE.CM-1 | A.5.1 | GOVERN 1 | CC9.1 | Engagement window enforcement, deadline alerts |
| APTS-SE-009: Hard Deny Lists and Critical Asset Protection | PR.AA-1 | A.8.5 | GOVERN 1 | CC6.6 | Immutable asset protection, cryptographic enforcement |
| APTS-SE-010: Production Database Safeguards | PR.AA-1 | A.8.5 | GOVERN 1 | CC6.6 | MUST \| Tier 2 | Multi-layer database protection, read-only mode |
| APTS-SE-011: Multi-Tenant Environment Awareness | PR.AA-2 | A.8.5 | GOVERN 1 | CC7.2 | SHOULD \| Tier 2 | Cross-tenant isolation, shared infrastructure detection |
| APTS-SE-012: DNS Rebinding Attack Prevention | PR.AA-1 | A.8.9 | GOVERN 1 | CC6.6 | Network-level attack prevention, resolution validation |
| APTS-SE-013: Network Boundary and Lateral Movement Enforcement | ID.AM-1 | A.8.20 | GOVERN 1 | CC6.6 | VLAN/subnet/cloud security group boundaries |
| APTS-SE-014: Network Topology Discovery Limitations | DE.CM-1 | A.8.9 | GOVERN 1 | CC9.1 | Reconnaissance scope limitations, host/port count limits |
| APTS-SE-015: Scope Enforcement Audit and Compliance Verification | PR.PS-1 | A.5.36 | MAP 1 | CC9.1 | Complete audit trail of scope decisions |
| APTS-SE-016: Scope Refresh and Revalidation Cycle | DE.CM-1 | A.8.16 | MAP 1 | CC9.1 | MUST \| Tier 2 | Infrastructure change detection, delta reporting |
| APTS-SE-017: Engagement Boundary Definition for Recurring Tests | GV.PO-1 | A.5.1 | GOVERN 1 | CC2.1 | MUST \| Tier 2 | Recurring test cycle management, authorization renewal |
| APTS-SE-018: Cross-Cycle Finding Correlation and Regression Detection | DE.AE-1 | A.5.36 | MAP 1 | PI1.1 | SHOULD \| Tier 2 | Finding lifecycle tracking, regression detection |
| APTS-SE-019: Rate Limiting, Adaptive Backoff, and Production Impact Controls | DE.CM-1 | A.8.9 | GOVERN 1 | CC9.1 | MUST \| Tier 2 | Per-target and global rate limits, adaptive throttling, production impact prevention, response time monitoring |
| APTS-SE-020: Deployment-Triggered Testing Governance | GV.PO-1 | A.8.25 | GOVERN 1 | CC3.2 | CI/CD integration governance, scope validation for auto-triggers |
| APTS-SE-021: Scope Conflict Resolution for Overlapping Engagements | DE.CM-1 | A.8.9 | GOVERN 1 | CC6.6 | SHOULD \| Tier 3 | Multi-engagement overlap handling, restrictive constraint application |
| APTS-SE-022: Client-Side Agent Scope and Safety Boundaries | PR.AA-1 | A.8.5 | GOVERN 1 | CC6.6 | SHOULD \| Tier 2 | Agent boundary enforcement, kill switch integration |
| APTS-SE-023: Credential and Secret Lifecycle Governance | PR.DS-1, PR.AA-1 | A.8.3, A.5.33, A.8.24 | GOVERN 1 | C1.2 | MUST \| Tier 2 | Credential inventory, provenance classification, reuse policy, delegation control, and secure disposal |
| APTS-SE-024: Cloud-Native and Ephemeral Infrastructure Governance | PR.PS-1 | A.8.9, A.5.23 | GOVERN 1 | CC3.2 | Cloud control plane, serverless, and ephemeral infrastructure governance |
| APTS-SE-025: API-First and Business Logic Testing Governance | PR.PS-1 | A.5.23 | GOVERN 1 | CC3.2 | API business logic traversal, token propagation, and schema drift governance |
| APTS-SE-026: Out-of-Distribution Action Monitoring | DE.AE-2, DE.CM-1 | A.8.16 | MEASURE 2 | CC9.1 | SHOULD \| Tier 2 | Baseline-driven action-distribution monitoring with staffed review queue |

### 6.2 Safety Controls (APTS-SC)

| APTS Requirement | NIST CSF 2.0 | ISO/IEC 27001:2022 | NIST AI RMF 1.0 | SOC 2 TSC 2017 (2022 PoF) | Notes |
|---|---|---|---|---|---|
| APTS-SC-001: Impact Classification and CIA Scoring | ID.RA-4 | A.5.1 | GOVERN 1 | CC4.1 | Risk assessment framework with discrete tiers |
| APTS-SC-002: Industry-Specific Impact Considerations | ID.RA-4 | A.5.1 | GOVERN 1 | CC4.1 | Regulatory impact elevation (Healthcare/Finance/CI) |
| APTS-SC-003: Real-World Impact Classification Examples | PR.PS-1 | A.5.1 | GOVERN 1 | CC3.2 | Documented scenarios with classification rationale |
| APTS-SC-004: Rate Limiting, Bandwidth, and Payload Constraints | DE.CM-1 | A.8.9 | GOVERN 1 | CC9.1 | Target-specific rate enforcement by impact tier |
| APTS-SC-005: Cascading Failure Prevention in Interconnected Systems | DE.CM-1 | A.8.9 | GOVERN 1 | A1.1 | Dependency mapping, upstream impact detection |
| APTS-SC-006: Threshold Escalation Workflow (Automated → Approval → Prohibited) | GV.RR-2 | A.5.1 | GOVERN 1 | CC4.1 | Graduated approval gates with timeout defaults |
| APTS-SC-007: Cumulative Risk Scoring with Time-Based Decay | DE.CM-1, ID.RA-5 | A.5.1 | GOVERN 1 | CC4.1 | Cumulative impact tracking with multi-factor risk algorithm and audit trail |
| APTS-SC-008: Threshold Configuration with Schema Validation | PR.PS-1 | A.5.8 | GOVERN 1 | CC3.2 | Schema-validated threshold configuration |
| APTS-SC-009: Kill Switch | PR.PS-1, RS.MA-1 | A.5.26, A.5.29 | GOVERN 1 | CC4.1 | Independent halt mechanisms, Phase 1/2 sequencing |
| APTS-SC-010: Health Check Monitoring, Threshold Adjustment, and Automatic Halt | DE.CM-1 | A.8.9 | MEASURE 1 | A1.1 | Dynamic threshold adjustment and automatic halt on target degradation |
| APTS-SC-011: Condition-Based Automated Termination | DE.CM-1 | A.5.1 | MEASURE 1 | A1.1 | Automated service unavailability response |
| APTS-SC-012: Network-Level Circuit Breaker | DE.CM-1 | A.8.9 | MEASURE 1 | A1.1 | Degradation-triggered suspension with recovery probe |
| APTS-SC-013: Time-Based Automatic Termination with Operator Override | DE.CM-1 | A.5.1 | GOVERN 1 | CC2.1 | Engagement duration limits with advance warning |
| APTS-SC-014: Reversible Action Tracking and Rollback | PR.PS-1 | A.5.1 | MANAGE 1 | CC7.2 | State capture, rollback procedures, verification |
| APTS-SC-015: Post-Test System Integrity Validation | DE.CM-1 | A.8.9 | MANAGE 1 | CC7.2 | Baseline comparison, discrepancy escalation |
| APTS-SC-016: Evidence Preservation and Automated Cleanup | PR.PS-1 | A.5.28 | MANAGE 1 | CC7.2 | Immutable evidence storage, idempotent artifact removal |
| APTS-SC-017: External Watchdog and Operator Notification | DE.CM-1 | A.8.9 | MEASURE 1 | A1.1 | Independent health verification, operator SLA |
| APTS-SC-018: Incident Containment and Recovery | RS.MA-1 | A.5.24 | MANAGE 1 | A1.1 | Automatic isolation, credential rotation, recovery RTO |
| APTS-SC-019: Kernel-Enforced Execution Sandbox for Agent Runtime | PR.PS-1, PR.IR-1 | A.8.22, A.8.25 | GOVERN 1 | CC6.6 | MUST \| Tier 2 | Kernel-enforced sandbox (namespaces, seccomp, AppArmor/SELinux, hypervisor/gVisor/Kata); agent holds no credentials to move its own boundary |
| APTS-SC-020: External Enforcement of Tool and Action Allowlist | PR.PS-1, PR.AA-1 | A.8.5, A.8.25 | GOVERN 1 | CC6.6 | MUST \| Tier 1 | Allowlist enforced by external gateway or policy engine, not by the model system prompt |

### 6.3 Human Oversight (APTS-HO)

| APTS Requirement | NIST CSF 2.0 | ISO/IEC 27001:2022 | NIST AI RMF 1.0 | SOC 2 TSC 2017 (2022 PoF) | Notes |
|---|---|---|---|---|---|
| APTS-HO-001: Mandatory Pre-Approval Gates for Autonomy Levels L1 and L2 | GV.RR-2 | A.5.2 | GOVERN 1 | CC3.2 | Mandatory approval for autonomy levels L1 and L2 |
| APTS-HO-002: Real-Time Monitoring and Intervention Capability | DE.CM-1 | A.8.16 | MEASURE 2 | CC9.1 | Live activity visualization and monitoring of autonomous operations |
| APTS-HO-003: Decision Timeout and Default-Safe Behavior | GV.RR-1 | A.5.3 | GOVERN 1 | CC4.1 | SLA-based approval windows with safe fallback behavior |
| APTS-HO-004: Authority Delegation Matrix | GV.RR-2 | A.5.2 | GOVERN 1 | CC4.1 | Clear definition and enforcement of delegated authorities |
| APTS-HO-005: Delegation Chain-of-Custody and Decision Audit Trail | GV.RR-3 | A.5.3 | GOVERN 1 | CC3.2 | Complete chain of delegation with audit trail |
| APTS-HO-006: Graceful Pause Mechanism with State Preservation | PR.IR-1 | A.5.24 | MEASURE 1 | CC9.1 | Operator-initiated pause with full state recovery capability |
| APTS-HO-007: Mid-Engagement Redirect Capability | PR.IR-1 | A.5.37 | GOVERN 1 | CC3.2 | Ability to redirect engagement scope mid-test |
| APTS-HO-008: Immediate Kill Switch with State Dump | RS.MA-1 | A.5.24 | MANAGE 1 | CC4.1 | Immediate termination with complete state capture |
| APTS-HO-009: Multi-Operator Kill Switch Authority and Handoff | RS.MA-1 | A.5.26 | MAP 1 | CC9.1 | Multiple kill switch authorities with handoff procedures |
| APTS-HO-010: Mandatory Human Decision Points Before Irreversible Actions | GV.RR-2 | A.5.2 | GOVERN 1 | CC4.1 | Human approval required for permanent or irreversible actions |
| APTS-HO-011: Unexpected Findings Escalation Framework | DE.AE-2 | A.5.24 | GOVERN 1 | CC3.2 | Escalation procedures for unexpected or anomalous findings |
| APTS-HO-012: Impact Threshold Breach Escalation | DE.AE-2 | A.5.25 | MEASURE 1 | CC4.1 | Automatic escalation when impact thresholds exceeded |
| APTS-HO-013: Confidence-Based Escalation (Scope Uncertainty) | DE.AE-2 | A.5.24 | GOVERN 1 | CC4.1 | Escalation triggers based on confidence levels |
| APTS-HO-014: Legal and Compliance Escalation Triggers | RS.CO-2 | A.5.25 | GOVERN 1 | CC3.2 | Escalation for legal and compliance boundary concerns |
| APTS-HO-015: Real-Time Activity Monitoring and Multi-Channel Notification | DE.CM-1 | A.8.16 | MEASURE 1 | CC9.1 | Real-time monitoring with multi-channel alerts |
| APTS-HO-016: Alert Fatigue Mitigation and Smart Aggregation | DE.AE-3 | A.8.16 | MEASURE 1 | CC9.1 | Intelligent alert filtering and aggregation |
| APTS-HO-017: Stakeholder Notification and Engagement Closure | RS.CO-3 | A.5.37 | MANAGE 1 | CC3.2 | Notification procedures and engagement conclusion |
| APTS-HO-018: Operator Qualification, Training, and Competency Governance | GV.RR-2 | A.6.3 | GOVERN 1 | CC3.2 | Minimum competency and certification requirements, full training curriculum and incident response, continuous competency assessment and succession planning |
| APTS-HO-019: 24/7 Operational Continuity and Shift Handoff | GV.RR-2 | A.5.2, A.5.3 | MANAGE 2 | CC3.2 | Shift handoff, stale approval expiry, suppression drift, and operator desensitization monitoring |

### 6.4 Graduated Autonomy (APTS-AL)

| APTS Requirement | NIST CSF 2.0 | ISO/IEC 27001:2022 | NIST AI RMF 1.0 | SOC 2 TSC 2017 (2022 PoF) | Notes |
|---|---|---|---|---|---|
| APTS-AL-001: Single Technique Execution | PR.PS-1 | A.8.25 | GOVERN 1 | CC3.2 | Atomic action constraint at L1 |
| APTS-AL-002: Human-Directed Target and Technique Selection | GV.RR-2 | A.5.1 | GOVERN 1 | CC3.2 | Operator-driven targeting at L1 |
| APTS-AL-003: Parameter Configuration by Human Operator | PR.PS-1 | A.5.8 | GOVERN 1 | CC3.2 | No defaults without explicit confirmation |
| APTS-AL-004: No Automated Chaining or Sequential Decision-Making | PR.PS-1 | A.8.25 | GOVERN 1 | CC3.2 | Prohibition on autonomous workflow sequencing at L1 |
| APTS-AL-005: Mandatory Logging and Human-Reviewable Audit Trail | DE.CM-1 | A.8.15 | MAP 1 | CC9.1 | Complete audit trail with structured fields |
| APTS-AL-006: Basic Scope Validation and Policy Enforcement | PR.AA-1 | A.8.5 | GOVERN 1 | CC6.6 | Policy enforcement before technique execution |
| APTS-AL-007: Multi-Step Technique Chaining Within Single Phase | PR.PS-1 | A.8.25 | GOVERN 1 | CC3.2 | L2 multi-step chaining within phase boundaries |
| APTS-AL-008: Real-Time Human Monitoring and Approval Gates | DE.CM-1 | A.8.16 | GOVERN 1 | CC4.1 | L2 real-time monitoring with approval gates |
| APTS-AL-009: Tool-Proposed Actions with Operator Modification Capability | GV.RR-2 | A.5.2 | GOVERN 1 | CC4.1 | L2 tool proposes, operator modifies/approves |
| APTS-AL-010: Step-by-Step Audit Log with Phase Transitions | DE.CM-1 | A.8.15 | MAP 1 | CC9.1 | L2 detailed phase transition logging |
| APTS-AL-011: Escalation Triggers and Exception Handling | DE.AE-2 | A.5.24 | GOVERN 1 | CC4.1 | Automatic escalation on boundary conditions |
| APTS-AL-012: Kill Switch and Pause Capability | PR.IR-1 | A.5.24 | GOVERN 1 | CC4.1 | Immediate halt and pause at all levels |
| APTS-AL-013: Complete Attack Chain Execution Within Boundaries | PR.PS-1 | A.8.25 | GOVERN 1 | CC3.2 | L3 full attack chain within defined boundaries |
| APTS-AL-014: Boundary Definition and Enforcement Framework | PR.AA-1 | A.8.5 | GOVERN 1 | CC6.6 | L3 boundary definition and runtime enforcement |
| APTS-AL-015: Pre-Approved Action Categories and Decision Trees | PR.PS-1 | A.5.8 | GOVERN 1 | CC3.2 | L3 pre-approved action categories |
| APTS-AL-016: Continuous Boundary Monitoring and Breach Detection | DE.CM-1 | A.8.16 | MEASURE 1 | CC4.1 | L3 continuous monitoring for boundary violations |
| APTS-AL-017: Multi-Target Assessment Management | DE.CM-1 | A.8.25 | GOVERN 1 | CC9.1 | L3 concurrent multi-target management |
| APTS-AL-018: Incident Response During Autonomous Testing | RS.MA-1 | A.5.24 | MANAGE 1 | CC4.1 | Incident response procedures during autonomous ops |
| APTS-AL-019: Multi-Target Campaign Management Without Intervention | PR.PS-1 | A.8.25 | GOVERN 1 | CC3.2 | L4 fully autonomous campaign management |
| APTS-AL-020: Dynamic Scope Adjustment and Target Discovery | GV.PO-1 | A.8.16, A.5.37 | GOVERN 1 | CC4.1 | L4 dynamic scope within pre-approved boundaries |
| APTS-AL-021: Adaptive Testing Strategy and Resource Reallocation | PR.PS-1 | A.5.37 | GOVERN 1 | CC3.2 | L4 adaptive strategy with resource optimization |
| APTS-AL-022: Continuous Risk Assessment and Automated Escalation | DE.AE-2 | A.5.24 | MEASURE 1 | CC4.1 | L4 continuous risk assessment |
| APTS-AL-023: Complete Audit Trail and Forensic Reconstruction | DE.CM-1 | A.8.15 | MAP 1 | CC9.1 | SHOULD \| Tier 3 | L4 complete forensic-grade audit trail |
| APTS-AL-024: Periodic Autonomous Review Cycles | DE.CM-1 | A.5.36 | MEASURE 1 | CC9.1 | L4 periodic review cycles |
| APTS-AL-025: Autonomy Level Authorization, Transition, and Reauthorization | GV.RR-1 | A.5.2 | GOVERN 1 | CC3.2 | Level authorization and periodic reauthorization |
| APTS-AL-026: Incident Investigation and Autonomy Level Adjustment | RS.MA-1 | A.5.24 | MANAGE 1 | CC4.1 | Post-incident autonomy level review |
| APTS-AL-027: Evasion and Stealth Mode Governance | GV.PO-1 | A.5.2, A.5.31 | GOVERN 1 | CC3.2 | SHOULD \| Tier 3 | Default-off evasion, explicit authorization, disclosure, prohibited classes, impact reclassification |
| APTS-AL-028: Containment Verification for L3 and L4 Autonomy | DE.CM-1, ID.IM-2 | A.8.16, A.8.29 | MEASURE 1 | CC7.2 | MUST \| Tier 3 | Operator-run probes of sandbox and allowlist boundaries at quarterly (L3) or monthly (L4) cadence; verification MUST NOT be performed by the agent runtime |

### 6.5 Auditability (APTS-AR)

| APTS Requirement | NIST CSF 2.0 | ISO/IEC 27001:2022 | NIST AI RMF 1.0 | SOC 2 TSC 2017 (2022 PoF) | Notes |
|---|---|---|---|---|---|
| APTS-AR-001: Structured Event Logging with Schema Validation | DE.CM-1, PR.PS-1 | A.8.15 | MAP 1 | CC9.1 | Millisecond-precision timestamps, correlation IDs, schema-validated structured format |
| APTS-AR-002: State Transition Logging | DE.CM-1 | A.8.15 | MEASURE 1 | CC9.1 | Phase change documentation with authorization |
| APTS-AR-003: Resource Utilization Metrics Logging | DE.CM-1 | A.8.9 | MEASURE 1 | CC9.1 | Network/system metrics per operation |
| APTS-AR-004: Decision Point Logging and Confidence Scoring | DE.AE-1 | A.8.15 | MAP 1 | CC9.1 | Confidence scores, alternatives, rationale |
| APTS-AR-005: Log Retention and Archival Requirements | PR.PS-1 | A.5.33 | MANAGE 1 | A1.1 | Minimum retention per engagement, compliance alignment |
| APTS-AR-006: Decision Chain of Reasoning and Alternative Evaluation | DE.AE-1 | A.8.15 | MAP 1 | CC9.1 | Complete reasoning chain with alternative evaluation and rejection rationale |
| APTS-AR-007: Risk Assessment Documentation Before Action Execution | ID.RA-5 | A.5.1 | GOVERN 1 | CC4.1 | Pre-action risk assessment documentation |
| APTS-AR-008: Context-Aware Decision Logging | DE.AE-1 | A.8.15 | MAP 1 | CC9.1 | Environmental context captured with decisions |
| APTS-AR-009: Transparency Report Requirements | GV.OC-2 | A.5.37 | GOVERN 1 | CC2.1 | Public transparency reporting requirements |
| APTS-AR-010: Cryptographic Hashing of All Evidence | PR.DS-1 | A.8.24 | MANAGE 1 | C1.1 | SHA-256+ hashing of all evidence artifacts |
| APTS-AR-011: Chain of Custody for Evidence | PR.DS-1 | A.5.28 | MANAGE 1 | CC9.1 | Evidence provenance and custody tracking |
| APTS-AR-012: Tamper-Evident Logging with Hash Chains | PR.DS-1 | A.8.24 | MANAGE 1 | CC7.2 | Append-only hash chain integrity |
| APTS-AR-013: RFC 3161 Trusted Timestamp Integration | PR.DS-1 | A.8.24 | MANAGE 1 | CC9.1 | External trusted timestamping for evidence integrity |
| APTS-AR-014: Screenshot and Packet Capture Evidence Standards | PR.PS-1 | A.5.28 | MEASURE 1 | CC9.1 | Evidence capture format and integrity requirements |
| APTS-AR-015: Evidence Classification and Sensitive Data Handling | PR.DS-1 | A.5.12 | MANAGE 1 | C1.1 | Evidence classification and redaction procedures |
| APTS-AR-016: Platform Integrity and Supply Chain Attestation | PR.PS-1 | A.5.21 | GOVERN 1 | CC7.2 | Platform binary and supply chain verification |
| APTS-AR-017: Safety Control Regression Testing After Platform Updates | PR.PS-1 | A.8.25 | MEASURE 1 | CC9.1 | Post-update safety validation |
| APTS-AR-018: Customer Notification for Behavior-Affecting Updates | RS.CO-3 | A.8.32 | MANAGE 1 | C1.1 | Advance notification of behavior changes |
| APTS-AR-019: AI/ML Model Change Tracking and Drift Detection | DE.CM-1 | A.8.25 | MEASURE 1 | CC9.1 | Model version tracking and drift monitoring |
| APTS-AR-020: Audit Trail Isolation from Agent Runtime | PR.DS-1, PR.PS-1 | A.8.15, A.8.24 | MAP 1 | CC7.2 | MUST \| Tier 2 | Authoritative audit trail on append-only infrastructure the agent runtime cannot reach (WORM, external SIEM, dedicated log service) |

### 6.6 Manipulation Resistance (APTS-MR)

| APTS Requirement | NIST CSF 2.0 | ISO/IEC 27001:2022 | NIST AI RMF 1.0 | SOC 2 TSC 2017 (2022 PoF) | Notes |
|---|---|---|---|---|---|
| APTS-MR-001: Instruction Boundary Enforcement | PR.PS-1 | A.8.25 | GOVERN 1 | CC3.2 | Operator instruction isolation from target content |
| APTS-MR-002: Response Validation & Sanitization | DE.AE-1 | A.8.25 | MEASURE 1 | CC9.1 | Target content parsing in sandbox, injection detection |
| APTS-MR-003: Error Message Neutrality | DE.AE-1 | A.8.25 | MEASURE 1 | CC9.1 | Error data analysis without behavioral influence |
| APTS-MR-004: Configuration File Integrity Verification | PR.PS-1 | A.8.25 | GOVERN 1 | CC3.2 | Configuration content as data, not directives |
| APTS-MR-005: Authority Claim Detection & Rejection | PR.PS-1 | A.8.25 | GOVERN 1 | CC3.2 | Target-sourced authority claims rejected |
| APTS-MR-006: Decision Boundary Enforcement | PR.PS-1 | A.8.25 | GOVERN 1 | CC6.6 | SHOULD \| Tier 2 | Decision logic isolated from target influence |
| APTS-MR-007: Redirect Following Policy | PR.AA-1 | A.8.20 | GOVERN 1 | CC6.6 | HTTP redirect scope validation |
| APTS-MR-008: DNS and Network-Level Redirect Prevention | PR.AA-1 | A.8.20 | GOVERN 1 | CC6.6 | DNS rebinding and network redirect defense |
| APTS-MR-009: Server-Side Request Forgery (SSRF) Prevention in Testing | PR.AA-1 | A.8.25 | GOVERN 1 | CC6.6 | SSRF prevention in testing operations |
| APTS-MR-010: Scope Expansion Social Engineering Prevention | PR.PS-1 | A.5.2 | GOVERN 1 | CC3.2 | Social engineering scope expansion defense |
| APTS-MR-011: Out-of-Band Communication Prevention | PR.PS-1 | A.8.25 | GOVERN 1 | CC6.6 | No out-of-band communication channels |
| APTS-MR-012: Immutable Scope Enforcement Architecture | PR.AA-1 | A.8.5 | GOVERN 1 | CC6.6 | Scope cannot be modified by target interaction |
| APTS-MR-013: Adversarial Example Detection in Vulnerability Classification | DE.AE-1 | A.8.25 | MEASURE 1 | CC9.1 | Adversarial input detection in classification |
| APTS-MR-014: Resource Exhaustion and Tarpit Attack Prevention | DE.CM-1 | A.8.9 | MEASURE 1 | CC9.1 | Tarpit and resource exhaustion defense |
| APTS-MR-015: Deceptive Authentication Honeypots | DE.AE-1 | A.8.25 | MEASURE 1 | CC9.1 | Honeypot and deceptive credential detection |
| APTS-MR-016: Anti-Automation Defense Detection | DE.AE-1 | A.8.25 | MEASURE 1 | CC9.1 | CAPTCHA and anti-automation detection |
| APTS-MR-017: Anomaly Detection in Response Patterns | DE.AE-1 | A.8.25 | MEASURE 1 | CC9.1 | Response pattern anomaly detection |
| APTS-MR-018: AI Model Input/Output Architectural Boundary | PR.PS-1, PR.IR-1 | A.8.22, A.8.27 | GOVERN 1 | CC3.2 | AI model I/O isolation architecture |
| APTS-MR-019: Discovered Credential Protection | PR.DS-1 | A.8.3 | GOVERN 1 | C1.2 | Discovered credentials not auto-used cross-system |
| APTS-MR-020: Adversarial Validation and Resilience Testing of Safety Controls | DE.CM-1 | A.8.25 | MEASURE 1 | CC9.1 | Periodic red-team testing of safety controls, safety control resilience under adversarial conditions |
| APTS-MR-021: Data Isolation Adversarial Testing | DE.CM-1 | A.8.22 | MEASURE 1 | CC7.2 | Cross-tenant isolation adversarial testing |
| APTS-MR-022: Inter-Model Trust Boundaries and Output Validation | PR.DS-1 | A.8.25, A.8.26 | MANAGE 1 | CC7.2 | Inter-component sanitization, shared state integrity, pipeline documentation |
| APTS-MR-023: Agent Runtime as Untrusted Component in Threat Model | ID.RA-1, GV.RM-1 | A.5.7, A.8.27 | MAP 1 | CC3.2 | MUST \| Tier 2 | Threat model names agent runtime as untrusted; agent-originated threats traced to architectural containment controls (SC-019, SC-020, AR-020, MR-012) |

### 6.7 Supply Chain Trust (APTS-TP)

| APTS Requirement | NIST CSF 2.0 | ISO/IEC 27001:2022 | NIST AI RMF 1.0 | SOC 2 TSC 2017 (2022 PoF) | Notes |
|---|---|---|---|---|---|
| APTS-TP-001: Third-Party Provider Selection and Vetting | GV.SC-3, GV.SC-4 | A.5.19, A.5.21 | GOVERN 1 | CC3.2 | Vendor vetting, SOC 2 Type II review, SaaS vendor evaluation and contract review |
| APTS-TP-002: Model Version Pinning and Change Management | GV.SC-3, GV.SC-4 | A.5.23, A.8.32 | GOVERN 1 | CC3.2 | Explicit model versions, no "latest" tracking |
| APTS-TP-003: API Security and Authentication | PR.AA-1, PR.AA-3 | A.8.5 | GOVERN 1 | CC6.6 | Transport encryption, key rotation, mutual authentication |
| APTS-TP-004: Provider Availability, SLA Management, and Failover | GV.SC-7 | A.5.22 | GOVERN 1 | A1.2 | Documented uptime SLA, metrics tracking, failover procedures |
| APTS-TP-005: Provider Incident Response, Breach Notification, and Mid-Engagement Compromise | RS.MA-1, RS.CO-2 | A.5.24, A.5.26 | MANAGE 1 | C1.1 | Provider breach notification, mid-engagement compromise detection and response |
| APTS-TP-006: Dependency Inventory, Risk Assessment, and Supply Chain Verification | GV.SC-5, GV.SC-7 | A.5.19, A.5.21 | GOVERN 1 | CC3.2 | Annual or more frequent security review, dependency integrity verification and monitoring |
| APTS-TP-007: Data Residency and Sovereignty Requirements | GV.OC-3 | A.5.31 | GOVERN 1 | CC3.2 | Geographic data storage and sovereignty compliance |
| APTS-TP-008: Cloud Security Configuration and Hardening | PR.PS-1 | A.8.9 | GOVERN 1 | CC4.1 | AWS/Azure/GCP security baseline enforcement |
| APTS-TP-009: Incident Response and Service Continuity Planning | RS.MA-1, RS.CO-2 | A.5.24, A.5.26 | MANAGE 1 | CC4.1 | Vendor incident response procedures |
| APTS-TP-010: Vulnerability Feed Selection and Management | ID.RA-1, ID.RA-2 | A.8.8 | MEASURE 1 | PI1.1 | Vulnerability/threat feed accuracy verification |
| APTS-TP-011: Feed Quality Assurance and Incident Response | ID.RA-1, ID.RA-2 | A.8.8 | MEASURE 1 | PI1.1 | Cross-feed correlation, false positive identification |
| APTS-TP-012: Client Data Classification Framework | PR.DS-1, PR.DS-2 | A.5.12, A.5.13 | GOVERN 1 | C1.1 | Public/Sensitive/Confidential/Restricted taxonomy |
| APTS-TP-013: Sensitive Data Discovery and Handling | PR.DS-1, PR.DS-2 | A.5.12, A.5.13 | MEASURE 1 | C1.3 | Automatic PII/PHI/credentials identification |
| APTS-TP-014: Data Encryption and Cryptographic Controls | PR.DS-1, PR.DS-2 | A.8.24 | GOVERN 1 | C1.1 | Encryption at rest, encryption in transit, secure key management |
| APTS-TP-015: Data Retention and Secure Deletion | PR.DS-1 | A.8.10 | MANAGE 1 | C1.3 | Crypto-shred, disposal verification |
| APTS-TP-A01: Breach Notification and Regulatory Reporting (Advisory) | RS.CO-2, RS.CO-3 | A.5.24, A.5.5 | MANAGE 1 | CC7.4 | Client notification per applicable regulatory timelines |
| APTS-TP-016: Data Destruction Proof and Certification | PR.DS-1 | A.8.10 | MANAGE 1 | C1.3 | Certified data destruction and audit trail |
| APTS-TP-017: Multi-Tenant and Engagement Isolation | PR.DS-1, PR.AA-1 | A.8.22 | GOVERN 1 | CC7.2 | Engagement and tenant isolation verification |
| APTS-TP-018: Tenant Breach Notification | RS.CO-2, RS.CO-3 | A.5.24, A.5.26 | MANAGE 1 | CC7.4 | Timely breach notification to affected tenants per contractual terms |
| APTS-TP-A02: Privacy Regulation Compliance (Advisory) | GV.OC-3 | A.5.34 | GOVERN 1 | P2.1 | GDPR, CCPA, and regional privacy compliance |
| APTS-TP-A03: Professional Liability and Engagement Agreements (Advisory) | GV.OC-2 | A.5.31 | GOVERN 1 | CC9.2 | E&O insurance, service agreements, liability caps |
| APTS-TP-019: AI Model Provenance and Training Data Governance | GV.SC-3, GV.SC-4 | A.5.23, A.8.32 | GOVERN 1 | CC3.2 | Model training data documentation and verification |
| APTS-TP-020: Persistent Memory and Retrieval State Governance | PR.DS-1 | A.5.12, A.8.10 | GOVERN 1 | C1.1 | State inventory, cross-engagement isolation, operator visibility, decision influence auditing |
| APTS-TP-021: Foundation Model Disclosure and Capability Baseline | GV.SC-3, GV.SC-4 | A.5.23, A.8.32 | GOVERN 1 | CC3.2 | MUST \| Tier 1 | Disclose provider, family, version, release date, and operator customizations of the foundation model; publish a capability baseline in the conformance claim |
| APTS-TP-022: Re-attestation on Material Foundation Model Change | GV.SC-7, ID.IM-2 | A.8.32, A.5.23 | GOVERN 1 | CC7.2 | MUST \| Tier 2 | Re-assess SE, SC, MR, AL when the foundation model undergoes material change (provider/family/generation/fine-tune/capability shift); block promotion until workpaper is complete |

### 6.8 Reporting (APTS-RP)

| APTS Requirement | NIST CSF 2.0 | ISO/IEC 27001:2022 | NIST AI RMF 1.0 | SOC 2 TSC 2017 (2022 PoF) | Notes |
|---|---|---|---|---|---|
| APTS-RP-001: Evidence-Based Finding Validation | RS.AN-3, ID.IM-1 | A.5.28 | MEASURE 2 | CC9.1 | Raw artifacts separate from summaries |
| APTS-RP-002: Finding Verification and Human Review Pipeline | ID.IM-1 | A.5.28, A.8.29 | MEASURE 2 | CC9.1 | Critical/High findings re-verified before delivery |
| APTS-RP-003: Confidence Scoring with Auditable Methodology | DE.AE-1 | A.8.25 | MEASURE 1 | CC9.1 | Auditable, formula-based confidence methodology |
| APTS-RP-004: Finding Provenance Chain | PR.DS-1 | A.5.28 | MEASURE 1 | CC9.1 | Cryptographic linkage to audit logs |
| APTS-RP-005: Cryptographic Evidence Chain Integrity | PR.DS-1 | A.8.24 | MANAGE 1 | CC9.1 | Evidence cryptographically linked to findings |
| APTS-RP-006: False Positive Rate Disclosure | ID.IM-1 | A.5.37, A.8.29 | MEASURE 2 | CC9.1 | Methodology section includes accuracy statistics |
| APTS-RP-007: Independent Finding Reproducibility | ID.IM-2 | A.8.25 | MEASURE 1 | CC9.1 | Independent validation of findings mid-assessment |
| APTS-RP-008: Vulnerability Coverage Disclosure | ID.IM-1 | A.5.36, A.8.29 | MEASURE 2 | CC2.1 | Coverage scope and limitations disclosed |
| APTS-RP-009: False Negative Rate Disclosure and Methodology | ID.IM-1 | A.5.36, A.8.29 | MEASURE 2 | CC9.1 | Missed vulnerability rate methodology |
| APTS-RP-010: Detection Effectiveness Benchmarking | ID.IM-2 | A.5.37 | MEASURE 1 | PI1.1 | Detection rate benchmarking methodology |
| APTS-RP-011: Executive Summary and Risk Overview | GV.OC-2 | A.5.37 | MANAGE 1 | CC2.1 | Risk-focused narrative for decision-makers |
| APTS-RP-012: Remediation Guidance and Prioritization | ID.IM-1 | A.8.8 | MANAGE 1 | CC4.1 | Prioritized remediation with effort estimation |
| APTS-RP-013: Engagement SLA Compliance Reporting | ID.IM-1 | A.5.35 | MEASURE 2 | CC9.1 | SLA adherence documentation |
| APTS-RP-014: Trend Analysis for Recurring Engagements | DE.CM-1 | A.5.37 | MEASURE 1 | PI1.1 | Cross-engagement trend analysis |
| APTS-RP-015: Downstream Finding Pipeline Integrity | PR.DS-1, PR.DS-2 | A.5.12, A.5.14 | MANAGE 1 | CC7.2 | Finding sync fidelity, tenant isolation, deduplication, sensitive data redaction, delivery assurance |

## Compliance Matrix Reference Table

| Requirement | NIST CSF 2.0 | ISO/IEC 27001:2022 | NIST AI RMF 1.0 | SOC 2 TSC 2017 (2022 PoF) | PCI DSS 4.0.1 | GDPR |
|---|---|---|---|---|---|---|
| APTS-SE-001: Rules of Engagement (RoE) Specification and Validation | GV.PO-1 | A.5.8 | GOVERN 1 | CC3.2 | - | - |
| APTS-SE-002: IP Range Validation and RFC 1918 Awareness | ID.AM-1 | A.8.20, A.8.22 | GOVERN 1 | CC1.1 | - | - |
| APTS-SE-009: Hard Deny Lists and Critical Asset Protection | PR.AA-1 | A.8.5 | GOVERN 1 | CC6.6 | - | - |
| APTS-SC-009: Kill Switch | PR.PS-1, RS.MA-1 | A.5.26, A.5.29 | GOVERN 1 | CC4.1 | - | - |
| APTS-SC-017: External Watchdog and Operator Notification | DE.CM-1 | A.8.9 | MEASURE 1 | A1.1 | - | - |
| APTS-HO-001: Mandatory Pre-Approval Gates for Autonomy Levels L1 and L2 | GV.RR-2 | A.5.2 | GOVERN 1 | CC3.2 | - | - |
| APTS-HO-002: Real-Time Monitoring and Intervention Capability | DE.CM-1 | A.8.16 | MEASURE 2 | CC9.1 | - | - |
| APTS-AL-001: Single Technique Execution | PR.PS-1 | A.8.25 | GOVERN 1 | CC3.2 | - | - |
| APTS-AL-002: Human-Directed Target and Technique Selection | GV.RR-2 | A.5.1 | GOVERN 1 | CC3.2 | - | - |
| APTS-AR-001: Structured Event Logging with Schema Validation | DE.CM-1, PR.PS-1 | A.8.15 | MAP 1 | CC9.1 | Req 10 | - |
| APTS-AR-004: Decision Point Logging and Confidence Scoring | DE.AE-1 | A.8.15 | MAP 1 | CC9.1 | - | - |
| APTS-MR-001: Instruction Boundary Enforcement | PR.PS-1 | A.8.25 | GOVERN 1 | CC3.2 | - | - |
| APTS-MR-002: Response Validation & Sanitization | DE.AE-1 | A.8.25 | MEASURE 1 | CC9.1 | - | - |
| APTS-TP-001: Third-Party Provider Selection and Vetting | GV.SC-3, GV.SC-4 | A.5.19, A.5.21 | GOVERN 1 | CC3.2 | - | - |
| APTS-TP-003: API Security and Authentication | PR.AA-1, PR.AA-3 | A.8.5 | GOVERN 1 | CC6.6 | Req 7-8 | Art 32 |
| APTS-TP-014: Data Encryption and Cryptographic Controls | PR.DS-1, PR.DS-2 | A.8.24 | GOVERN 1 | C1.1 | Req 3-4 | Art 32 |
| APTS-TP-018: Tenant Breach Notification | RS.CO-2, RS.CO-3 | A.5.24, A.5.26 | MANAGE 1 | CC7.4 | Req 12 | Art 33-34 |
| APTS-RP-001: Evidence-Based Finding Validation | RS.AN-3, ID.IM-1 | A.5.28 | MEASURE 2 | CC9.1 | - | - |
| APTS-RP-002: Finding Verification and Human Review Pipeline | ID.IM-1 | A.5.28, A.8.29 | MEASURE 2 | CC9.1 | - | - |

---

## Using This Matrix

1. **For Audits**: Use matrix to show compliance with standards
2. **For Vendor Reviews**: Map vendor requirements to APTS controls
3. **For Gap Analysis**: Identify which APTS controls address which framework requirements
4. **For Client Assurance**: Demonstrate how APTS controls align with client compliance requirements

---

## Key Observations

1. **NIST CSF 2.0 Coverage**: The standard addresses all six functions (Govern, Identify, Protect, Detect, Respond, Recover)
2. **ISO/IEC 27001:2022 Coverage**: Controls A.5 through A.8 have corresponding mappings
3. **SOC 2 Coverage**: All five trust principles addressed with proper Trust Service Criteria codes
4. **NIST AI RMF 1.0 Coverage**: All four functions (Govern, Map, Measure, Manage) addressed, with particular depth in autonomy governance and AI risk treatment
5. **PCI DSS Coverage**: Applicable controls for card data security
6. **GDPR Coverage**: All key articles (5, 17, 28, 32-34) addressed

---

## NIST SP 800-53 Rev. 5

APTS requirements map to the following NIST SP 800-53 control families relevant to autonomous testing governance:

| NIST SP 800-53 Control | Description | APTS Requirements |
|------------------------|-------------|-------------------|
| AC-4 Information Flow Enforcement | Control information flows between systems | APTS-SE-006, APTS-SE-013, APTS-MR-012 |
| AC-6 Least Privilege | Restrict system access to authorized functions | APTS-HO-004, APTS-AL-025, APTS-SE-023 |
| AU-2 Event Logging | Define auditable events | APTS-AR-001, APTS-AR-002, APTS-AR-004 |
| AU-3 Content of Audit Records | Ensure audit records contain required information | APTS-AR-001, APTS-AR-006, APTS-AR-008 |
| AU-6 Audit Record Review | Review and analyze audit records | APTS-AR-009, APTS-AR-012, APTS-HO-002 |
| AU-9 Protection of Audit Information | Protect audit information from unauthorized access | APTS-AR-010, APTS-AR-011, APTS-AR-012 |
| AU-10 Non-Repudiation | Protect against individual falsely denying actions | APTS-AR-010, APTS-AR-011, APTS-AR-013 |
| CA-7 Continuous Monitoring | Implement continuous monitoring | APTS-SC-010, APTS-SC-017, APTS-AR-020 |
| CM-3 Configuration Change Control | Control changes to systems | APTS-TP-002, APTS-AR-017, APTS-AR-019 |
| CP-2 Contingency Plan | Establish contingency plans | APTS-TP-004, APTS-TP-009, APTS-SC-018 |
| IA-2 Identification and Authentication | Authenticate users and devices | APTS-TP-003, APTS-SE-023 |
| IR-4 Incident Handling | Implement incident handling capability | APTS-SC-018, APTS-TP-005, APTS-AL-018 |
| IR-5 Incident Monitoring | Track and document incidents | APTS-HO-011, APTS-HO-012, APTS-SC-017 |
| IR-6 Incident Reporting | Report incidents to appropriate authorities | APTS-TP-A01 (Advisory), APTS-TP-018, APTS-HO-017 |
| PE-3 Physical Access Control | Enforce physical access authorizations | Not directly addressed (APTS is a logical governance standard) |
| RA-5 Vulnerability Monitoring and Scanning | Monitor and scan for vulnerabilities | APTS-TP-010, APTS-RP-008, APTS-RP-009 |
| SA-9 External System Services | Require external service providers to comply | APTS-TP-001, APTS-TP-006, APTS-TP-019 |
| SC-7 Boundary Protection | Monitor and control communications at boundaries | APTS-SE-006, APTS-SE-009, APTS-SC-012 |
| SC-8 Transmission Confidentiality | Protect transmitted information | APTS-TP-014, APTS-TP-003 |
| SC-28 Protection of Information at Rest | Protect information at rest | APTS-TP-014, APTS-AR-015, APTS-MR-019 |
| SI-4 System Monitoring | Monitor systems for attacks and indicators | APTS-SC-010, APTS-MR-017, APTS-HO-015 |
| SR-3 Supply Chain Controls | Implement supply chain risk management | APTS-TP-001, APTS-TP-006, APTS-TP-019 |

---

## HIPAA Security Rule (45 CFR Part 164)

For autonomous testing platforms operating in healthcare environments or handling protected health information (PHI):

| HIPAA Requirement | Description | APTS Requirements |
|-------------------|-------------|-------------------|
| 164.312(a) Access Control | Implement access controls for ePHI | APTS-SE-009, APTS-SE-023, APTS-HO-004 |
| 164.312(b) Audit Controls | Record and examine system activity | APTS-AR-001, APTS-AR-004, APTS-AR-012 |
| 164.312(c) Integrity | Protect ePHI from improper alteration | APTS-AR-010, APTS-AR-011, APTS-TP-014 |
| 164.312(d) Authentication | Verify identity of persons seeking access | APTS-TP-003, APTS-SE-023 |
| 164.312(e) Transmission Security | Guard against unauthorized access during transmission | APTS-TP-014, APTS-TP-003 |
| 164.308(a)(1) Security Management | Implement policies to prevent security violations | APTS-SC-001, APTS-HO-004, APTS-AL-025 |
| 164.308(a)(5) Security Awareness | Implement security awareness and training | APTS-HO-018 |
| 164.308(a)(6) Security Incident Procedures | Implement incident response procedures | APTS-SC-018, APTS-TP-005, APTS-TP-A01 (Advisory) |
| 164.308(a)(7) Contingency Plan | Establish contingency plans | APTS-TP-004, APTS-TP-009 |
| 164.310(d) Device and Media Controls | Govern receipt and removal of hardware and media | APTS-TP-015, APTS-TP-016 |
| 164.314(a) Business Associate Contracts | Require BAAs with business associates | APTS-TP-A03 (Advisory) |
| 164.404-410 Breach Notification | Notify following breach of unsecured PHI | APTS-TP-A01 (Advisory), APTS-TP-018 |

---

## CIS Critical Security Controls v8

| CIS Control | Description | APTS Requirements |
|-------------|-------------|-------------------|
| 1 Inventory and Control of Enterprise Assets | Maintain asset inventory | APTS-SE-001, APTS-SE-005, APTS-SE-024 |
| 2 Inventory and Control of Software Assets | Maintain software inventory | APTS-TP-006, APTS-AR-018 |
| 3 Data Protection | Develop processes to identify, classify, and protect data | APTS-TP-012, APTS-TP-013, APTS-TP-014 |
| 4 Secure Configuration | Establish secure configurations | APTS-TP-008, APTS-SC-008 |
| 6 Access Management | Control access based on need-to-know | APTS-HO-004, APTS-SE-023, APTS-AL-025 |
| 8 Audit Log Management | Collect, manage, and analyze audit logs | APTS-AR-001, APTS-AR-005, APTS-AR-012 |
| 9 Email and Web Browser Protections | Not directly addressed (APTS governs testing platforms) | |
| 11 Data Recovery | Establish data recovery practices | APTS-SC-014, APTS-SC-016, APTS-TP-009 |
| 13 Network Monitoring and Defense | Monitor and defend network infrastructure | APTS-SC-010, APTS-SC-012, APTS-SC-017 |
| 15 Service Provider Management | Develop processes to evaluate service providers | APTS-TP-001, APTS-TP-004, APTS-TP-006 |
| 16 Application Software Security | Manage security lifecycle of software | APTS-AR-017, APTS-AR-019, APTS-MR-020 |
| 17 Incident Response Management | Establish incident response program | APTS-SC-018, APTS-AL-018, APTS-TP-005 |

---

## Customization

Adapt this matrix to your:
- Additional frameworks (HIPAA, FedRAMP, NIST CSF specific sectors)
- Customer requirements
- Regional regulations
- Industry-specific standards

Review annually as frameworks and APTS evolve.
