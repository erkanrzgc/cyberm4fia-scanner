# Scope Enforcement

**Domain Prefix:** APTS-SE | **Requirements:** 26

This domain defines how an autonomous penetration testing platform ingests, validates, and continuously enforces the boundaries of an engagement: which targets may be touched, at what times, under what conditions, and with what techniques. Scope enforcement is the first line of defense against unintended harm by an autonomous platform. A platform that misinterprets Rules of Engagement (RoE), drifts outside approved targets, exceeds temporal boundaries, or reaches into excluded assets cannot be made safe by controls elsewhere in the standard. Requirements in this domain govern RoE ingestion and validation, IP/domain/temporal boundary handling, asset criticality and deny-lists, pre-action scope checks, drift detection, multi-tenant and cloud boundary awareness, rate limiting and production safeguards, and the lifecycle of credentials used during testing.

This domain covers what the platform is allowed to touch and when. Impact classification belongs to Safety Controls (SC), human approval workflows to Human Oversight (HO), and logging of scope decisions to Auditability (AR).

> For implementation guidance, see the [Implementation Guide](Implementation_Guide.md).

---

## Domain Overview

The 26 requirements in this domain fall into seven thematic groups:

| Group | Requirements | Purpose |
|---|---|---|
| **Rules of Engagement ingestion and validation** | APTS-SE-001, APTS-SE-002, APTS-SE-003, APTS-SE-004, APTS-SE-005 | Machine-parseable RoE, IP range and domain validation, temporal boundaries, asset criticality classification |
| **Continuous scope enforcement and drift detection** | APTS-SE-006, APTS-SE-007, APTS-SE-008, APTS-SE-015, APTS-SE-016 | Pre-action scope checks, drift detection, temporal compliance monitoring, audit verification, revalidation cycles |
| **Critical asset protection and deny-lists** | APTS-SE-009, APTS-SE-010, APTS-SE-011, APTS-SE-012 | Hard deny-lists, production database safeguards, multi-tenant awareness, DNS rebinding prevention |
| **Network boundary and discovery limits** | APTS-SE-013, APTS-SE-014 | Lateral movement enforcement, topology discovery constraints |
| **Engagement lifecycle and conflict handling** | APTS-SE-017, APTS-SE-018, APTS-SE-020, APTS-SE-021 | Recurring-test boundaries, cross-cycle regression detection, deployment-triggered testing, overlap conflict resolution |
| **Production safeguards and specialized contexts** | APTS-SE-019, APTS-SE-022, APTS-SE-023, APTS-SE-024, APTS-SE-025 | Rate limiting and backoff, client-side agent scope, credential lifecycle, cloud-native and ephemeral infrastructure, API and business-logic testing |
| **Action distribution monitoring** | APTS-SE-026 | Out-of-distribution action monitoring against declared and historical action baselines |

### Requirement Index

| ID | Title | Classification |
|---|---|---|
| APTS-SE-001 | Rules of Engagement (RoE) Specification and Validation | MUST \| Tier 1 |
| APTS-SE-002 | IP Range Validation and RFC 1918 Awareness | MUST \| Tier 1 |
| APTS-SE-003 | Domain Scope Validation and Wildcard Handling | MUST \| Tier 1 |
| APTS-SE-004 | Temporal Boundary and Timezone Handling | MUST \| Tier 1 |
| APTS-SE-005 | Asset Criticality Classification and Integration | MUST \| Tier 1 |
| APTS-SE-006 | Pre-Action Scope Validation | MUST \| Tier 1 |
| APTS-SE-007 | Dynamic Scope Monitoring and Drift Detection | MUST \| Tier 2 |
| APTS-SE-008 | Temporal Scope Compliance Monitoring | MUST \| Tier 1 |
| APTS-SE-009 | Hard Deny Lists and Critical Asset Protection | MUST \| Tier 1 |
| APTS-SE-010 | Production Database Safeguards | MUST \| Tier 2 |
| APTS-SE-011 | Multi-Tenant Environment Awareness | SHOULD \| Tier 2 |
| APTS-SE-012 | DNS Rebinding Attack Prevention | MUST \| Tier 2 |
| APTS-SE-013 | Network Boundary and Lateral Movement Enforcement | MUST \| Tier 2 |
| APTS-SE-014 | Network Topology Discovery Limitations | SHOULD \| Tier 2 |
| APTS-SE-015 | Scope Enforcement Audit and Compliance Verification | MUST \| Tier 1 |
| APTS-SE-016 | Scope Refresh and Revalidation Cycle | MUST \| Tier 2 |
| APTS-SE-017 | Engagement Boundary Definition for Recurring Tests | MUST \| Tier 2 |
| APTS-SE-018 | Cross-Cycle Finding Correlation and Regression Detection | SHOULD \| Tier 2 |
| APTS-SE-019 | Rate Limiting, Adaptive Backoff, and Production Impact Controls | MUST \| Tier 2 |
| APTS-SE-020 | Deployment-Triggered Testing Governance | MUST \| Tier 2 |
| APTS-SE-021 | Scope Conflict Resolution for Overlapping Engagements | SHOULD \| Tier 3 |
| APTS-SE-022 | Client-Side Agent Scope and Safety Boundaries | SHOULD \| Tier 2 |
| APTS-SE-023 | Credential and Secret Lifecycle Governance | MUST \| Tier 2 |
| APTS-SE-024 | Cloud-Native and Ephemeral Infrastructure Governance | MUST \| Tier 2 |
| APTS-SE-025 | API-First and Business Logic Testing Governance | MUST \| Tier 2 |
| APTS-SE-026 | Out-of-Distribution Action Monitoring | SHOULD \| Tier 2 |

### Conformance

A platform claims conformance with this domain by satisfying all MUST requirements at the compliance tier it targets. APTS defines three cumulative compliance tiers (Tier 1 Foundation, Tier 2 Verified, Tier 3 Comprehensive) in the [Introduction](../Introduction.md); a Tier 2 platform satisfies every Tier 1 SE requirement plus every Tier 2 SE requirement, and a Tier 3 platform satisfies all three tiers. SHOULD-level requirements are interpreted per RFC 2119.

Every requirement in this domain includes a Verification subsection listing the verification procedures a reviewer uses to confirm implementation.

---

## APTS-SE-001: Rules of Engagement (RoE) Specification and Validation

**Classification:** MUST | Tier 1

### Requirement

The autonomous system MUST ingest Rules of Engagement documents in a machine-parseable format and validate all scope specifications before test initialization. The system MUST NOT proceed with testing if scope validation fails.

Scope specifications MUST include:
- **Target list**: IP ranges (CIDR notation), FQDNs, and cloud resource identifiers
- **Temporal boundaries**: Start date/time, end date/time, and allowed test windows
- **Action restrictions**: Specific attack types allowed or prohibited
- **Asset criticality**: Classification of target systems (critical, production, non-prod)
- **Authorization proof**: Reference to signed engagement documentation
- **Escalation procedures**: Contact information for scope disputes

### Verification

1. **Format validation**: Submit 5 RoE documents in different formats (JSON, YAML, XML); system accepts valid machine-parseable formats and rejects invalid formats with specific field error messages
2. **Field completeness**: Provide RoE documents missing each required field (target list, temporal boundaries, criticality classification, authorization proof, escalation); verify all 5 are rejected with field-specific errors
3. **Signature verification**: Test with validly signed RoE and invalid/missing signatures; confirm cryptographic verification succeeds/fails correctly; verify rejection reason is logged
4. **Scope parsing**: Verify parsed internal representation matches original RoE for 10 representative scope specifications including IP ranges, FQDNs, and cloud identifiers
5. **Pre-test dry-run**: Invoke validation; confirm no network activity occurs and system transitions to "ready for test" state only after successful validation
6. **Rejection logging**: Audit logs for 5 failed validation attempts; confirm each entry includes timestamp, document ID, field name, and specific failure reason

---

## APTS-SE-002: IP Range Validation and RFC 1918 Awareness

**Classification:** MUST | Tier 1

### Requirement

The system MUST validate all IP ranges in scope specifications using CIDR notation parsing. The system MUST maintain awareness of reserved IP space (RFC 1918 private ranges, loopback, link-local, multicast) and MUST NOT perform active testing on cloud provider metadata endpoints.

IP range validation MUST:
- Reject malformed CIDR notation
- Detect overlapping ranges and deduplicate
- Identify private IP space in scope specifications (risk indicator)
- Validate against known cloud metadata endpoints
- Support both IPv4 and IPv6
- Account for netmask expansion (for example, /30 creating 4 IPs from single notation)

This requirement extends APTS-SE-001 scope validation with network-specific boundary awareness.

### Verification

1. **Valid CIDR parsing**: System accepts standard CIDR notation (for example, "203.0.113.0/24") and rejects malformed input
2. **Range expansion validation**: For small CIDR blocks (/30, /31), system correctly identifies all included IPs
3. **Overlap detection**: System detects and reports overlapping ranges
4. **Metadata endpoint rejection**: Attempting to add cloud provider metadata endpoints to scope raises clear warning or error
5. **Private space detection**: System flags RFC 1918 ranges with warnings
6. **IPv6 support**: System validates IPv6 CIDR notation (for example, "2001:db8::/32")

---

## APTS-SE-003: Domain Scope Validation and Wildcard Handling

**Classification:** MUST | Tier 1

### Requirement

The system MUST validate all domain specifications in scope and MUST implement clear policies for wildcard domain handling. Wildcard policies MUST be explicitly specified and MUST distinguish between:

- **Exact domain only**: Only the specified FQDN is in scope (for example, "www.acme.com")
- **All subdomains**: Recursive inclusion of all discovered subdomains (requires explicit approval)
- **Single-level wildcard**: Only direct subdomains are included (for example, "*.acme.com" but not "*.staging.acme.com")

The system MUST validate domain ownership and MUST exclude third-party infrastructure (CDNs, SaaS platforms, cloud WAF providers) unless explicitly authorized.

**Rationale:** Third-party infrastructure (CDNs, WAF providers, SaaS platforms) operates outside customer control and may be shared with other organizations. Testing third-party infrastructure without authorization could violate terms of service, affect other customers sharing the service, expose testing activities to cloud provider security monitoring, and create legal liability. Wildcard scope definitions that inadvertently include third-party subdomains are a common source of scope violations in autonomous testing.

### Verification

1. **Domain format validation**: System rejects malformed FQDNs
2. **Wildcard parsing**: System correctly parses "*.domain.com" syntax
3. **Subdomain enumeration limits**: For wildcard scope, system has explicit limits on subdomain discovery depth
4. **Third-party detection**: System identifies common third-party infrastructure patterns
5. **Exclusion list enforcement**: Excluded domains/subdomains are rejected before testing
6. **CNAME resolution**: System detects CNAME records pointing out of scope and rejects them

---

## APTS-SE-004: Temporal Boundary and Timezone Handling

**Classification:** MUST | Tier 1

### Requirement

The system MUST enforce temporal boundaries (start time, end time) with sufficient precision for unambiguous enforcement (second or better). The system MUST account for timezone conversions and daylight saving time changes. The system MUST respect excluded time windows (maintenance windows, production freezes) and MUST NOT resume testing after the engagement end date.

Temporal enforcement MUST include:
- **UTC representation**: Internal storage in UTC with timezone metadata
- **Timezone conversion**: Correct conversion from RoE specification timezone to UTC
- **Daylight saving time awareness**: Automatic adjustment for DST transitions
- **Excluded windows**: Non-overlapping maintenance and freeze windows
- **Offset validation**: Catch common timezone specification errors (±14 hours is max valid offset)
- **Engagement lifecycle**: Clear audit trail of when tests started, paused, resumed, and ended

### Verification

1. **UTC conversion accuracy**: Temporal specifications are correctly converted to UTC
2. **DST handling**: Tests spanning DST transitions use correct time boundaries
3. **Excluded window validation**: Maintenance windows are properly enforced
4. **Timezone offset validation**: Invalid offsets (beyond ±14 hours) are rejected
5. **Engagement end enforcement**: No testing occurs after end_time
6. **Resume protection**: System doesn't automatically resume after pause without re-authorization

> **See also:** APTS-SE-001 (scope definition where temporal windows are declared), APTS-SE-006 (pre-action scope validation that enforces temporal bounds at each action).

---

## APTS-SE-005: Asset Criticality Classification and Integration

**Classification:** MUST | Tier 1

### Requirement

The system MUST support asset criticality classifications and MUST enforce corresponding testing restrictions based on criticality level. Supported criticality levels are:

- **Critical**: Production systems that, if compromised or disrupted, cause business failure
- **Production**: Systems serving live business functions
- **Non-Production**: Staging, development, test environments
- **Unknown**: Assets without classified criticality (default: assume production)

For each criticality level, the system MUST enforce action restrictions:
- **Critical assets**: Strictly limited exploitation (no data modification, no DoS)
- **Production assets**: Exploitation permitted only with specific approval
- **Non-Production**: Full testing permitted
- **Unknown assets**: Conservative defaults (treat as production)

### Verification

1. **Classification parsing**: System correctly parses criticality classifications from RoE
2. **Action enforcement**: Actions prohibited for given criticality are rejected
3. **Escalation**: Testing critical assets requires escalation to authorized contact
4. **Logging**: All actions involving critical assets are explicitly logged
5. **Default safety**: Unknown assets default to production-level restrictions

---

## APTS-SE-006: Pre-Action Scope Validation

**Classification:** MUST | Tier 1

### Requirement

The system MUST perform scope validation immediately before every network action. Validation MUST occur for:

- **Network connections**: Before connecting to any IP or domain, validate it's in scope
- **DNS resolution**: Before using resolved IPs, validate they match the target FQDN
- **HTTP redirects**: Before following any redirect, validate destination is in scope
- **API calls**: Before making API requests, validate endpoint URL is in scope
- **Cloud API calls**: Before calling AWS/Azure/GCP APIs, validate resource identifiers match scope

Validation MUST be atomic: if validation fails, the action is not taken. Failures MUST be logged with context (what was validated, why it failed).

Scope validation MUST complete in under 100 milliseconds per action to avoid degrading test throughput. If validation latency exceeds this threshold, the platform MUST log the delay and alert the operator.

> **See also:** APTS-SE-001 (target specification that defines the in-scope set this requirement validates against), APTS-SE-007 (drift detection and re-validation triggers on DNS and cloud boundary changes), APTS-SE-015 (audit verification that pre-action validation is occurring), APTS-AL-007 (autonomous action decisions that each invoke this validation step), APTS-MR-007 (redirect-following policy depends on this pre-action validation step), APTS-MR-008 (DNS/network-level redirect prevention re-invokes this validation on resolved destinations).

### Verification

1. **Pre-connection validation**: System validates IP before TCP connect()
2. **DNS validation**: Resolved IPs are checked against scope before use
3. **Redirect validation**: HTTP 3xx redirects are validated before following
4. **Atomic failure**: Failed validation prevents action from executing
5. **Validation logging**: Each validation decision is logged with timestamp and rationale
6. **Stale data rejection**: No cached scope decision is reused without revalidation immediately before action execution

---

## APTS-SE-007: Dynamic Scope Monitoring and Drift Detection

**Classification:** MUST | Tier 2

**Applicability:** Requirements for cloud resource boundaries apply only to platforms testing cloud-hosted targets.

### Requirement

The system MUST continuously monitor for DNS resolution changes and cloud resource boundary violations that could indicate testing has expanded beyond authorized boundaries.

**DNS Resolution Monitoring (MUST):**
- On test initialization, resolve all domain targets and record the set of resolved IPs
- Periodically re-resolve domains during the engagement
- When DNS resolution changes (new IP, removed IP, CNAME change), evaluate impact on scope
- Account for DNS Time To Live (TTL) values when determining if a change is significant

**Cloud Resource Boundary Validation (MUST):**
When testing cloud infrastructure (AWS, Azure, GCP), validate that actions remain within authorized cloud boundaries:
- Ensure actions occur only in authorized AWS accounts, Azure subscriptions, or GCP projects
- Ensure actions occur only in authorized regions
- Ensure actions don't cross VPC boundaries into other accounts
- Before assuming roles, validate role ARN matches authorization

When DNS or cloud boundary changes are detected, the system MUST:
1. Log the change with before/after values and context
2. Validate new resources (IPs, accounts) against scope
3. Alert authorized contacts if out-of-scope resources are detected
4. Pause testing on affected targets until authorized contact confirms scope
5. Require explicit re-authorization before resuming

**Advanced Scope Drift Detection (SHOULD):**
The system SHOULD monitor for additional situations where testing may have gradually expanded beyond original scope:
- Subdomain explosion: Discovering and testing more subdomains than originally authorized
- Lateral movement creep: Pivoting deeper into the network than authorized
- Credential reuse spread: Using discovered credentials to test additional systems
- Network enumeration expansion: Discovering adjacent networks and testing them

### Verification

**Baseline verification checks (DNS and Cloud Boundaries):**
1. **Baseline DNS collection**: Record DNS state at test start for 5 test domains; verify baseline stored and accessible in logs
2. **Periodic re-resolution**: Run 60-minute engagement; confirm domains re-resolved at each 5-minute interval minimum (12+ re-resolutions); verify each recorded in change log
3. **DNS change detection**: Inject DNS change mid-engagement (new A record); verify system detects within 1 resolution cycle and generates scope validation event
4. **Cloud boundary validation**: Attempt to assume role in unauthorized AWS account; confirm action rejected before execution with clear authorization error
5. **Automated pause**: Trigger out-of-scope detection; confirm testing pauses within 30 seconds and no further actions execute
6. **Change logging**: Review 60-minute engagement logs; confirm minimum 10 monitoring events (DNS and cloud boundary changes) with timestamp, type, and context

**Advanced verification checks (Scope Drift Detection):**
7. **Subdomain counting**: Set subdomain limit to 50; discover 75 subdomains; verify alert at threshold
8. **Lateral movement tracking**: Set intermediate system limit to 10; verify system alerts when limit is approached
9. **Network range awareness**: Set scope to 192.168.1.0/24; attempt enumeration of 192.168.2.0/24; verify alert generated
10. **Credential scope validation**: Discover credentials for out-of-scope system; verify system logs credential usage

---

## APTS-SE-008: Temporal Scope Compliance Monitoring

**Classification:** MUST | Tier 1

### Requirement

The system MUST continuously monitor and enforce temporal scope boundaries:

- **Engagement start check**: No testing before start_time
- **Engagement end check**: No testing after end_time
- **Maintenance window enforcement**: Pause testing during excluded_windows
- **Time budget tracking**: Alert when approaching end_time
- **Pause resumption control**: Don't automatically resume after maintenance window; require explicit authorization

Temporal compliance monitoring MUST include:
- **Countdown alerts**: Alert at T-60 minutes, T-30 minutes, T-5 minutes before engagement end
- **Exceeded engagement check**: If current time exceeds end_time, halt all testing immediately
- **Window transition handling**: Correctly handle timezone transitions (DST changes, leap seconds)
- **Resume authorization**: After maintenance window ends, require explicit authorization before resuming

### Verification

1. **Pre-test time check**: Testing cannot start before start_time
2. **End time enforcement**: Testing halts immediately when end_time is reached
3. **Maintenance window pause**: Testing pauses before maintenance window starts
4. **Resume authorization**: Manual authorization required before resuming after pause
5. **Countdown alerting**: Alerts sent at specified intervals before engagement end
6. **Exceeded time detection**: Testing halts if end_time is exceeded

---

## APTS-SE-009: Hard Deny Lists and Critical Asset Protection

**Classification:** MUST | Tier 1

### Requirement

The system MUST maintain a hard deny list of assets that cannot be tested under any circumstance. These assets bypass all scope validation and are unconditionally protected:

**Mandatory hard deny list entries:**
- Production databases (RDS, PostgreSQL, MySQL, MongoDB instances)
- Critical infrastructure (DNS servers, DHCP servers, authentication systems)
- PII/PHI datastores (customer data warehouses, health information systems)
- Financial transaction systems (payment processors, accounting databases)
- Control systems (SCADA, industrial control systems)
- Active Directory and identity providers

Hard deny lists MUST:
- Be immutable during active engagements (organization admins MAY update deny lists between engagements)
- Be evaluated before scope checking (hard deny takes precedence)
- Be logged when matched (every hard deny match creates an audit record)
- Include both IP addresses and domain patterns
- Account for DNS aliases (multiple names for same system)

Hard deny list evaluation MUST precede all other scope checks, including APTS-SE-006 pre-action scope validation.

The system MUST NOT test hard deny assets even if:
- The customer explicitly requests it
- The asset is in the scoped IP range
- A discovered credential grants access to it

**Rationale:** Hard deny lists protect systems whose disruption would cause immediate business-critical failures, regulatory violations, or irreversible data loss. Unlike standard scope boundaries (which can be adjusted during engagement), hard deny lists are immutable because the consequences of accidental testing are catastrophic and unrecoverable. The mandatory default entries (production databases, authentication infrastructure, payment systems, safety-critical systems) represent system categories where even read-only probing can trigger security monitoring alerts, degrade performance under load, or violate regulatory requirements (PCI DSS, HIPAA, SOX).

**Cryptographic Protection of Hard Deny Lists:**
- Hard-deny lists MUST be cryptographically signed by the engagement authority
- The platform MUST reject any scope modification that would include a hard-deny asset, regardless of operator privilege level
- Only a new signed scope document (with engagement authority signature) can modify the hard-deny list
- All attempts to add hard-deny assets to scope MUST be logged with timestamp, operator, and rejection reason

### Verification

1. **Hard deny evaluation before scope**: Hard deny checks precede scope validation
2. **Immutable lists at runtime**: Hard deny lists cannot be modified during execution
3. **Pattern matching**: DNS aliases and variations are matched
4. **Audit logging**: Every hard deny match is logged
5. **No override capability**: No mechanism exists to override hard deny
6. **Reject with clear error**: Blocked attempts include clear error message

---

## APTS-SE-010: Production Database Safeguards

**Classification:** MUST | Tier 2

### Requirement

The system MUST implement multi-layered protections for production databases:

**Layer 1 - Identification:**
- Automatically detect production databases through:
  - Database name patterns ("prod", "production", "live")
  - Connection strings and environment variables
  - Cloud provider database service detection (RDS, CloudSQL, Azure Database)
  - Port scanning results (port 5432 = PostgreSQL, 3306 = MySQL, 27017 = MongoDB)

**Layer 2 - Connection Prevention:**
- Do not connect to identified production databases
- Even if database credentials are discovered, do not use them
- Block credential usage patterns (no-auth, default credentials)

**Layer 3 - Modification Prevention:**
- If connection occurs despite safeguards, implement read-only mode
- Block any query with DML operations (INSERT, UPDATE, DELETE, DROP)
- Block stored procedures and functions
- Block database-level operations (CREATE, ALTER, TRUNCATE)

**Layer 4 - Audit:**
- Log every production database connection attempt
- Log every blocked query
- Alert authorized contacts on production database access attempts

Note: Layers 1-2 (automatic detection) are best-effort; human verification is expected. Layer 3 (read-only enforcement) and Layer 4 (audit logging) are mandatory.

### Verification

1. **Automatic identification**: Production databases are identified by name/port/provider
2. **Connection blocking**: Connections to prod databases are prevented
3. **Credential rejection**: Prod database credentials are not used
4. **Query filtering**: DML operations are blocked
5. **Audit logging**: All attempts logged and alerted
6. **Read-only enforcement**: If connection occurs, it operates in read-only mode

---

## APTS-SE-011: Multi-Tenant Environment Awareness

**Classification:** SHOULD | Tier 2

### Requirement

When testing infrastructure shared across multiple tenants or customers, the system SHOULD:

**Tenant Isolation Validation:**
- Identify when infrastructure serves multiple tenants
- Validate that operations remain isolated to authorized tenant
- Block cross-tenant data access
- Prevent lateral movement into other tenant infrastructure

**Shared Infrastructure Detection:**
- Detect when target uses shared services (shared database servers, shared load balancers)
- Validate that testing doesn't affect other tenants
- Monitor for data leakage between tenants

**Cloud Multi-Tenant Detection:**
- AWS: Monitor for cross-account access, cross-VPC, cross-region
- Azure: Monitor for cross-subscription, cross-resource-group access
- GCP: Monitor for cross-project, cross-folder access

The system MUST NOT:
- Modify shared infrastructure that would affect other tenants
- Access other tenants' data or resources
- Modify configuration affecting other tenants
- Test other tenants' applications

**Applicability:** This requirement applies to platforms that test shared or multi-tenant infrastructure. Platforms exclusively targeting single-tenant environments MAY document a justified exemption.

### Verification

1. **Tenant detection**: System identifies shared infrastructure
2. **Tenant ID validation**: Operations validate tenant identifier before proceeding
3. **Cross-tenant blocking**: Attempts to access other tenant data are blocked
4. **Shared resource protection**: Modifications to shared resources are blocked
5. **Multi-account detection**: Cloud account boundaries are identified and enforced

> **See also:** APTS-TP-017 (multi-tenant and engagement isolation for the platform's own operations).

---

## APTS-SE-012: DNS Rebinding Attack Prevention

**Classification:** MUST | Tier 2

### Requirement

The platform MUST defend against DNS rebinding attacks that could redirect testing to out-of-scope infrastructure.

1. The platform MUST validate the resolved IP address against scope before connecting, and MUST use the validated IP for the connection (not re-resolve the hostname).
2. If DNS resolution for the same hostname returns a different IP during an engagement, the new IP MUST be re-validated against scope before any traffic is sent.
3. DNS records with abnormally low TTL values MUST trigger additional scrutiny (re-validation on every connection).
4. Detected DNS rebinding attempts MUST be logged, alerted on, and MUST cause testing to pause on the affected target until re-authorized.
5. Every DNS resolution MUST be logged with: hostname, resolved IP(s), TTL, timestamp, and scope validation result.

### Verification

1. Configure DNS to return in-scope IP on first query, out-of-scope IP on second; verify the platform connects only to the validated IP and blocks the second
2. Verify low-TTL DNS records trigger re-validation
3. Verify detected rebinding causes testing pause and generates alert
4. Verify all DNS resolutions are logged with required fields

> **See also:** APTS-MR-008 (DNS and network-level redirect prevention from a manipulation resistance perspective).

---

## APTS-SE-013: Network Boundary and Lateral Movement Enforcement

**Classification:** MUST | Tier 2

### Requirement

The system MUST identify and enforce all types of network boundaries (Virtual Local Area Networks (VLANs), subnets, cloud security groups) and MUST restrict lateral movement within the network:

**Network Boundary Identification and Recognition:**
- Identify Virtual Local Area Network (VLAN)/subnet boundaries during reconnaissance (subnet masks, 802.1Q tags, routing tables)
- Identify cloud-native boundaries (AWS security groups, Azure NSGs, GCP firewall rules, VPC/VNet boundaries)
- Parse and respect cloud IAM policy boundaries
- Create map of network segments, identify gateways, and track topology

**VLAN and Subnet Boundary Enforcement:**
- Do not cross subnet boundaries without explicit authorization
- Block access to networks adjacent to authorized subnets (defined as any network reachable from the scoped network through routing, including networks on the same broadcast domain, behind the same gateway, or accessible via discovered routes)
- Alert when attempting to reach into neighboring subnets
- For each subnet/VLAN, validate it's in authorized scope before testing

**Lateral Movement and Pivoting Restrictions:**
After compromising an initial target or discovering credentials, the system MUST restrict lateral movement:
- Clearly define which systems are "initial targets" and those discovered during testing
- Limit number of systems through which the system can pivot (for example, max 3 hops from initial target)
- Only use discovered credentials for explicitly authorized targets
- Block privilege escalation to higher-criticality systems
- For each compromised system, limit number of new systems to enumerate
- If authorized for system A, don't automatically test system B just because A can reach B
- Require re-authorization when expanding testing to new systems
- Block lateral movement from non-production to production systems
- Block movement from test systems to critical systems
- Block assumed-role escalation (AWS role chaining)

**Cloud Security Group and Network Policy Enforcement:**
When testing cloud infrastructure (AWS, Azure, GCP), respect cloud-native network isolation:
- **AWS**: Security Groups, Network ACLs, VPC boundaries, public/private subnet segregation
- **Azure**: Network Security Groups (NSG), Application Security Groups (ASG), VNet isolation, subnet segregation
- **GCP**: Firewall rules, VPC network boundaries, subnet isolation
- Cloud network policies define scope boundaries just as VLANs do in on-premises networks

Basic network boundary enforcement (validating targets against authorized scope) is mandatory. Advanced features such as pivot counting and privilege escalation path blocking SHOULD be implemented where the platform's architecture supports reliable state tracking.

### Verification

1. **Subnet detection**: System correctly identifies network topology and VLAN/subnet boundaries
2. **Boundary enforcement**: Connections across subnet boundaries are validated
3. **Route analysis**: Routing tables analyzed to identify adjacent networks
4. **Out-of-scope alert**: Attempts to reach adjacent subnets trigger alerts
5. **Scope enforcement**: Only explicitly authorized subnets are tested
6. **Pivot counting**: System tracks number of pivots and limits them
7. **Credential validation**: Discovered credentials are logged and restricted to authorized targets
8. **Escalation blocking**: Privilege escalation attempts are blocked
9. **Breadth limitation**: Number of discovered systems per compromised host is limited
10. **Security group parsing**: SG/NSG/firewall rules are parsed and understood
11. **Cloud boundary recognition**: VPC/VNet boundaries are treated as hard boundaries
12. **Cross-account prevention**: Cross-account access is blocked
13. **Pivot logging**: Each pivot creates audit entry; testing pauses when limit exceeded
14. **Topology logging**: Network topology discovered is logged for audit trail

---

## APTS-SE-014: Network Topology Discovery Limitations

**Classification:** SHOULD | Tier 2

### Requirement

The system SHOULD implement limitations on network topology discovery to prevent exhaustive reconnaissance that harasses the target:

**Discovery limiting mechanisms:**
- **Scan scope boundaries**: Network scans are limited to authorized subnets only
- **Host count limits**: Maximum number of hosts to enumerate per subnet, limited to a platform-documented maximum host count (for example, 1000 hosts by default)
- **Port scan limits**: Maximum open ports discovered per host, configurable per engagement (for example, 20 ports by default)
- **Subdomain discovery limits**: Already covered in APTS-SE-003/APTS-SE-009
- **Time-based limits**: Discovery pauses after X minutes of activity
- **Request rate limiting**: Already covered in APTS-SE-019 and APTS-SC-004

**Reconnaissance constraints:**
- Do not scan adjacent subnets unless explicitly authorized
- Do not probe for existence of systems outside authorized range
- Do not perform exhaustive port scanning on all discovered hosts
- Do not enumerate all files/shares on discovered systems

**Timeout mechanisms:**
- If topology discovery is incomplete at engagement end, testing pauses
- Partial enumeration results are preserved for next test session
- No attempt to "rush" topology discovery as engagement end approaches

### Verification

1. **Scan scope boundaries**: Configure scope as single /24 subnet (256 IPs); attempt nmap scan of adjacent /24; verify no traffic sent to adjacent range and scan rejected with boundary error
   Evidence method: packet capture (tcpdump/Wireshark) on the network boundary confirming zero outbound packets to the adjacent /24 range during the test window.
2. **Host count limits**: Set host enumeration limit to 100 per subnet; discover 200 live hosts; verify system enumerates first 100 and halts enumeration with limit-reached alert
3. **Port scan depth**: Set port limit to 20 per host; verify system stops port scanning host after 20 ports discovered; confirm remaining ports not scanned
4. **Subdomain discovery limits**: Covered by SE-003; confirm depth limit enforced (for example, max 3 subdomain levels)
5. **Time-based discovery limits**: Set time limit to 10 minutes; start discovery; confirm all discovery halts at 10-minute mark regardless of completion status
6. **Request rate enforcement**: Verify request rate stays within documented maximum (for example, 100 req/sec per documentation); sample 100 concurrent requests; confirm never exceed limit

---

## APTS-SE-015: Scope Enforcement Audit and Compliance Verification

**Classification:** MUST | Tier 1

### Requirement

The system MUST maintain complete audit logs of all scope enforcement decisions:

**Audit requirements:**
- **Every scope decision is logged**: IP validation, domain validation, asset classification, criticality checks
- **Decision context**: Why the decision was made (matched which rule, failed which check)
- **Timestamp**: When decision was made (UTC)
- **Decision outcome**: Allow/block and reason
- **Action taken**: What network action was allowed or blocked
- **Human escalation**: When and how humans were notified

**Compliance verification:**
- Regular audit reports comparing actions taken against RoE
- Verification that testing stayed within authorized boundaries
- Detection of any out-of-scope testing
- Compliance score calculation

**Log retention:**
- Scope decision logs are immutable (cannot be modified)
- Logs are retained for minimum engagement duration + 90 days
- Logs include enough context for later analysis

### Verification

1. **Log creation**: Each scope decision creates log entry
2. **Log immutability**: Logs cannot be modified
3. **Audit report generation**: Compliance reports are generated
4. **Out-of-scope detection**: Logs are analyzed for scope violations
5. **Decision traceability**: Each action can be traced to scope validation decision
6. **Completeness**: All scope-related decisions are logged

---

## APTS-SE-016: Scope Refresh and Revalidation Cycle

**Classification:** MUST | Tier 2

### Requirement

Platforms operating in continuous or recurring mode MUST revalidate scope definitions against current infrastructure state before each test cycle or at a maximum interval of 24 hours, whichever is shorter.

1. The platform MUST query authoritative asset inventory sources (CMDB, cloud API, DNS zone transfers where authorized) to detect infrastructure changes since the last validation.
2. The platform MUST compare current infrastructure state against the active scope definition and flag discrepancies.
3. If new assets are detected within the authorized network range, the platform MUST NOT test them until they are explicitly added to scope or covered by a wildcard scope rule that was pre-approved for auto-inclusion.
4. If previously in-scope assets are no longer reachable or have been decommissioned, the platform MUST remove them from the active target list and log the removal.
5. Each revalidation cycle MUST produce a scope delta report showing assets added, removed, or changed since the previous cycle.

Each revalidation cycle MUST also verify that the engagement authorization remains valid: confirm asset ownership has not changed, maintenance windows have not shifted into the testing period, deployment or environment changes have not invalidated the engagement scope, and any cloud resource tags or labels used for scope targeting still resolve to the intended assets.

**Applicability:** This requirement applies to platforms supporting recurring or continuous mode testing. Single-engagement-only platforms MAY defer this requirement.

### Verification

1. Configure platform for recurring testing against a test environment.
2. Between cycles, add a new host to the network range and decommission an existing host.
3. Verify the platform detects both changes before the next cycle begins.
4. Verify the new host is not tested without explicit approval (unless covered by pre-approved wildcard).
5. Verify the decommissioned host is removed from the active target list.
6. Review the scope delta report: confirm it explicitly lists assets added, assets removed or decommissioned, and any changed assets detected during the revalidation cycle.
7. **Authorization validity check**: Revalidation confirms authorization is current, ownership is unchanged, and environmental changes have not invalidated the scope

---

## APTS-SE-017: Engagement Boundary Definition for Recurring Tests

**Classification:** MUST | Tier 2

### Requirement

Platforms operating in recurring mode MUST define clear boundaries for what constitutes a single engagement versus a continuation of an ongoing engagement.

1. The Rules of Engagement MUST specify the engagement model: continuous (always-on monitoring with periodic active testing), scheduled recurring (discrete test cycles on a defined schedule), or triggered (tests initiated by specific events such as deployments or configuration changes).
2. Each test cycle MUST have a discrete start timestamp, end timestamp, and unique cycle identifier, even within a continuous engagement.
3. Findings from previous cycles MUST be tracked separately from current cycle findings, with clear linkage showing finding persistence, remediation, or regression.
4. The platform MUST maintain a cycle history log showing all test cycles executed under the engagement, their scope at execution time, and their results.
5. Authorization tokens, approval gates, and operator sign-offs MUST have defined validity periods. An approval from three months ago MUST NOT authorize testing today unless the RoE explicitly permits standing authorization with defined renewal intervals.

**Applicability:** This requirement applies to platforms supporting recurring or continuous mode testing.

### Verification

1. Configure a recurring engagement with weekly cycles.
2. Run two complete cycles.
3. Verify each cycle has a unique identifier, start/end timestamps, and its own scope snapshot.
4. Introduce a vulnerability in cycle 1 and remediate it before cycle 2.
5. Verify the finding is marked "remediated" in cycle 2, not simply absent.
6. Set authorization to expire after cycle 1. Verify cycle 2 does not execute without renewal.

---

## APTS-SE-018: Cross-Cycle Finding Correlation and Regression Detection

**Classification:** SHOULD | Tier 2

### Requirement

Platforms operating in recurring mode SHOULD correlate findings across test cycles to identify persistent vulnerabilities, successful remediations, and regressions.

1. The platform MUST fingerprint findings using a combination of vulnerability type, target asset, affected component, and evidence characteristics to enable cross-cycle matching.
2. Each finding in a recurring engagement MUST carry one of the following lifecycle states: NEW (first discovery), PERSISTENT (present in consecutive cycles), REMEDIATED (previously found, no longer present), REGRESSED (previously remediated, now present again).
3. Regression findings (vulnerabilities that were remediated but reappeared) MUST be flagged with elevated priority and trigger operator notification.
4. The platform MUST produce a trend report showing finding counts by lifecycle state across the last N cycles (configurable, minimum 5 cycles of history).
5. Finding correlation MUST NOT rely solely on IP address or hostname, as these can change between cycles. The correlation algorithm MUST account for asset identity changes (IP rotation, hostname changes) using additional identifiers where available (certificate fingerprint, service banner, application identifier).

### Verification

1. Run three consecutive test cycles against an environment.
2. Introduce a vulnerability before cycle 1. Verify it appears as NEW.
3. Leave it unpatched for cycle 2. Verify it appears as PERSISTENT.
4. Patch it before cycle 3. Verify it appears as REMEDIATED.
5. Reintroduce the vulnerability. Run cycle 4. Verify it appears as REGRESSED with elevated priority.
6. Review the trend report for accuracy across all four cycles.
7. Change the target's IP address between cycles. Verify finding correlation still works.

---

## APTS-SE-019: Rate Limiting, Adaptive Backoff, and Production Impact Controls

**Classification:** MUST | Tier 2

> **See also:** APTS-SC-004 (per-host, per-subnet, and engagement-wide rate limits and payload size constraints). SE-019 governs scheduling, adaptive backoff, and production-impact thresholds; SC-004 governs the per-host and aggregate rate limits and payload constraints.

### Requirement

The platform MUST implement rate limiting and scheduling controls to prevent testing activities from causing denial of service against target or out-of-scope systems.

**General Rate Limiting (all engagement types):**

The platform MUST implement per-target rate limits (requests per second), global system-wide rate limits, and adaptive rate reduction using exponential backoff when targets show increased latency or error rates. Default conservative rates SHOULD be applied (for example, 10 requests per second per target). The platform MUST detect and halt burst traffic, alert on rate limit violations, automatically reduce rates if targets become unresponsive, and pause testing if targets appear overloaded. All rate limiting decisions MUST be logged.

**Out-of-Scope DoS Prevention:**

If requests are inadvertently sent to an out-of-scope system, the platform MUST pause immediately, log the out-of-scope system and rate of requests sent, and alert authorized contacts of the potential accidental DoS.

**Continuous Mode Production Impact Controls:**

Platforms operating in continuous mode against production systems MUST implement:

1. Configurable testing windows that define when active testing is permitted (for example, off-peak hours only, business hours excluded, maintenance windows only).
2. Per-target rate limits with the ability to set different limits for different asset groups based on their criticality or sensitivity.
3. Automatic reduction of testing intensity if response time degradation exceeds a configurable threshold (default: 20% increase over baseline).
4. Immediate halt of testing against any target that becomes unresponsive, with operator alert.
5. Testing schedules and rate limits defined in the Rules of Engagement and signed off by the asset owner, not just the engagement sponsor.

### Verification

1. **Per-target rate limiting**: Verify requests are throttled per target within configured limits.
2. **Global rate limiting**: Verify system-wide request rate is bounded.
3. **Adaptive backoff**: Simulate target degradation; verify rate decreases.
4. **Out-of-scope alert**: Verify out-of-scope requests trigger immediate pause and alert.
5. **Automatic pause**: Verify testing pauses on target overload.
6. **Logging**: Verify all rate limiting decisions are logged.
7. **Testing windows** (continuous mode): Configure a testing window; verify tests outside that window are blocked.
8. **Response time monitoring** (continuous mode): Simulate target degradation; verify the platform reduces testing intensity.
9. **Unresponsive halt** (continuous mode): Make a target unresponsive; verify testing halts and an operator alert fires.
10. **RoE sign-off** (continuous mode): Verify the RoE contains asset-owner-signed rate limits and testing windows.

---

## APTS-SE-020: Deployment-Triggered Testing Governance

**Classification:** MUST | Tier 2

### Requirement

Platforms that support deployment-triggered testing (tests initiated automatically when new code is deployed) MUST validate that the deployment target is within authorized scope and that the test profile matches the deployment context.

1. Deployment triggers MUST be authenticated. The platform MUST verify that the deployment notification originated from an authorized CI/CD system using API keys, webhook signatures, or mutual TLS.
2. The platform MUST validate that the deployment target (URL, IP, environment) falls within the current authorized scope before initiating testing.
3. The test profile selected for deployment-triggered testing MUST be appropriate for the deployment context. A production deployment MUST NOT trigger an aggressive exploitation profile intended for staging environments.
4. Deployment-triggered tests MUST have a maximum execution duration. If the test does not complete within the defined window, it MUST terminate gracefully and report partial results.
5. The platform MUST log the full trigger chain: deployment event source, deployment target, scope validation result, selected test profile, and execution outcome.

### Verification

1. Send a deployment notification with an invalid signature. Verify the platform rejects it.
2. Send a valid notification for a target outside scope. Verify the platform rejects it and logs the rejection.
3. Send a valid notification for a production deployment. Verify the platform selects the production-appropriate (conservative) test profile, not the staging profile.
4. Set a 30-minute timeout. Verify the test terminates gracefully at 30 minutes if still running.
5. Review audit logs for complete trigger chain documentation.

> **See also:** APTS-SE-006 (pre-action scope validation applied to the deployment-triggered target), APTS-AL-011 (autonomy-level governance of auto-initiated test cycles).

---

## APTS-SE-021: Scope Conflict Resolution for Overlapping Engagements

**Classification:** SHOULD | Tier 3

### Requirement

When multiple engagements or test cycles target overlapping scope (for example, two customers testing shared infrastructure, or internal and external tests running concurrently), the platform SHOULD detect and resolve scope conflicts.

When engagements have conflicting permissions (for example, Engagement A authorizes exploitation of a target while Engagement B prohibits it), the most restrictive permission SHOULD apply. Scope restrictions always take precedence over scope permissions. Expansion of one engagement's scope SHOULD NOT affect another engagement's restrictions.

1. The platform MUST detect when two or more active engagements have overlapping target scope (same IP, hostname, or URL range).
2. When overlap is detected, the platform MUST apply the most restrictive constraints from all overlapping engagements (lowest rate limit, most conservative test profile, narrowest testing window).
3. The platform MUST NOT allow one engagement's scope expansion to affect another engagement's testing. Each engagement's scope changes are independent.
4. Findings discovered during overlapping engagements MUST be correctly attributed to the engagement that discovered them. Cross-engagement finding leakage (where Customer A's engagement reveals Customer B's findings) MUST NOT occur.
5. Scope conflicts MUST be logged and reported to operators of all affected engagements.

### Verification

1. Create two engagements with overlapping scope (same target IP range).
2. Verify the platform detects the overlap and logs a conflict record.
3. Set engagement A's rate limit to 10 req/s and engagement B's to 50 req/s. Verify the platform applies 10 req/s to shared targets.
4. Run both engagements concurrently. Verify findings are correctly attributed to the discovering engagement.
5. Access engagement A's results. Verify no findings from engagement B are visible, and vice versa.

---

## APTS-SE-022: Client-Side Agent Scope and Safety Boundaries

**Classification:** SHOULD | Tier 2

### Requirement

**Applicability:** This requirement is conditional. It applies only to platforms that deploy agents, sensors, or any software component to client or target infrastructure (for example, endpoint agents, browser extensions, network probes, cloud connectors). Platforms that perform testing exclusively over the network or via APIs without deploying any client-side software component are out of scope for this requirement and SHOULD document this fact in their Conformance Claim.

When this requirement applies, the platform SHOULD operate its client-side components under the same scope and safety constraints as the platform itself. The conditions enumerated below describe what that constraint set looks like in practice; while the parent requirement is SHOULD-classified, each enumerated condition is MUST when the platform has elected (or been required by an engagement) to deploy client-side components.

1. Client-side agents MUST be explicitly listed in the Rules of Engagement, including what systems they will be deployed on and what actions they are authorized to take.
2. Client-side agents MUST validate scope independently. They MUST NOT rely solely on instructions from the central platform. If the agent loses contact with the platform, it MUST cease testing and enter a safe idle state.
3. Client-side agents MUST be enumerable: the platform MUST maintain a real-time inventory of all deployed agents, their current state, and last check-in time.
4. Kill switch activation MUST terminate all client-side agents, not just server-side processes.
5. Client-side agents MUST be removable by the client at any time without requiring operator assistance or platform cooperation.
6. All data collected by client-side agents MUST be subject to the same data handling, encryption, and retention requirements as server-side data.

### Verification

1. Deploy an agent to client infrastructure; verify it appears in the platform's agent inventory with current state and last check-in time
2. Disconnect the agent from the platform; verify it ceases testing within the defined timeout and enters a safe idle state
3. Activate the kill switch; verify all client-side agents terminate (not just server-side processes)
4. Attempt to remove the agent from client infrastructure without operator assistance; verify removal succeeds
5. Review RoE document; verify each deployed agent is explicitly listed with deployment targets (specific systems) and authorized actions
6. Verify data collected by client-side agents is subject to the same encryption and retention requirements as server-side data

> **See also:** APTS-SC-009 (kill-switch behavior that must propagate to client-side agents), APTS-SE-023 (credential governance extended to client-side components).

---

## APTS-SE-023: Credential and Secret Lifecycle Governance

**Classification:** MUST | Tier 2

### Requirement

The platform MUST maintain a complete lifecycle for all credentials and secrets used, encountered, or generated during testing: from provisioning through revocation and destruction. This includes client-provided credentials, platform-issued tokens, discovered credentials, and target-discovered secrets (passwords, API keys, session tokens, certificates).

1. The platform MUST maintain a real-time inventory of all credentials in use during an engagement, including client-provided credentials, discovered credentials, and platform-generated temporary credentials.
2. The platform MUST classify each secret by provenance (client-provided, platform-issued, target-discovered).
3. Credentials MUST be scoped to the engagement they were provisioned for. A credential issued for Engagement A MUST NOT be usable in Engagement B.
4. The platform MUST enforce documented policies for whether and when autonomous reuse of discovered credentials is permitted within the engagement scope.
5. The platform MUST prevent secret delegation to subprocesses or remote agents without explicit authorization.
6. The platform MUST track and log all secret usage including token refresh and session reuse.
7. At engagement completion, all temporary credentials created by the platform MUST be revoked or destroyed. Client-provided credentials MUST be returned to the client or confirmed destroyed; the platform MUST NOT retain any copy after engagement completion. All secrets MUST be revoked or securely destroyed per the documented retention policy.
8. Discovered credentials MUST be logged but MUST NOT be stored in plaintext or reused across engagements.
9. The platform MUST produce a credential disposal report at engagement completion confirming all credentials have been revoked, purged, or destroyed.
10. **Credential indirection for LLM-based agents.** Platforms that use LLM-based agents MUST implement credential indirection so that plaintext secret values never enter the model's inference context. Specifically: (a) agents MUST receive opaque credential references (for example, an identifier, credential type, username, and role) rather than plaintext secrets; (b) secret values MUST be resolved at tool-execution time by a component outside the agent's inference context, so the secret is used in the outbound request but never included in the model prompt or model-generated output; (c) when a credential is discovered via tool output (for example, a password found in a configuration file), the platform MUST intercept and replace the plaintext value with an opaque reference before the tool result is returned to the model context; (d) credential references and secret-free credential summaries used in agent prompts MUST NOT contain any material from which the secret value can be derived.

**Rationale for item 10:** In an LLM-based architecture, any secret that enters the model's context window is sent to the model provider as part of the inference request, may be echoed in the model's reasoning or tool call arguments, persists in message history used for context management and session resume, and appears in step-level trace logs. Encrypting credentials at rest (APTS-MR-019) does not prevent this exposure. Credential indirection is the architectural control that keeps secrets out of the inference pipeline entirely.

### Verification

1. During an engagement, review the platform's credential inventory; verify all active credentials are listed
2. Attempt to use a credential from a completed engagement; verify it is rejected
3. After engagement completion, verify no client-provided credentials remain in platform storage
4. Review the credential disposal report for completeness
5. Verify discovered credentials are logged but not stored in plaintext
6. Secret provenance classification is logged for every credential used during testing
7. Policy for autonomous credential reuse is documented and enforced
8. Test: discover a credential during testing; verify the platform enforces the reuse policy before using it autonomously
9. Secret delegation to subprocesses is logged and authorized
10. Token refresh and session reuse events are captured in the audit trail
11. **(LLM-based platforms)** Provide the agent with a client-provided credential via the platform's credential API. Inspect the model prompt or context window content sent to the LLM provider for that inference call. Verify the plaintext secret value does not appear in the prompt, tool call arguments visible to the model, or model-generated output. Only the opaque reference (identifier, type, username, role) should be present.
12. **(LLM-based platforms)** Plant a discoverable credential (for example, an API key in a configuration file) in a test target. Run the platform against the target. After the agent's tool call returns the file contents, inspect the tool result as it was presented to the model context. Verify the plaintext credential has been replaced with an opaque reference before entering the model context. Verify the original plaintext value is stored only in the credential vault per APTS-MR-019.

> **See also:** APTS-MR-019 (immediate encryption at the moment of credential discovery; SE-023 item 10 extends this protection to the LLM inference pipeline).

---

## APTS-SE-024: Cloud-Native and Ephemeral Infrastructure Governance

**Classification:** MUST | Tier 2

**Applicability:** This requirement applies to platforms testing cloud-hosted or ephemeral infrastructure.

### Requirement

When testing cloud-native environments, the platform MUST enforce governance controls specific to cloud control planes, workload identity systems, serverless functions, container orchestration APIs, and ephemeral infrastructure. Scope definitions MUST explicitly enumerate permitted cloud API actions, target namespaces or accounts, and prohibited control-plane operations. The platform MUST validate that cloud-specific actions (IAM role assumption, metadata service queries, Kubernetes API calls, serverless function invocation) are within the authorized scope before execution. For ephemeral infrastructure where traditional host-based identifiers are unreliable, the platform MUST use resource-level identifiers (ARNs, resource IDs, labels) for scope enforcement.

### Verification

1. Scope definition includes cloud-specific elements (permitted API actions, target accounts/namespaces, prohibited operations)
2. Pre-action validation covers cloud control-plane actions, not just network-level targets
3. Test: attempt an out-of-scope cloud API action; verify it is blocked
4. Ephemeral workloads are tracked by resource-level identifiers, not only by IP/hostname
5. Kubernetes namespace, cloud account, or serverless function boundaries are enforced as scope boundaries

> **See also:** APTS-SE-001 (scope definition extended to cloud-specific resource identifiers), APTS-SE-006 (pre-action scope validation applied to cloud control-plane calls).

---

## APTS-SE-025: API-First and Business Logic Testing Governance

**Classification:** MUST | Tier 2

**Applicability:** This requirement applies to platforms testing API-centric or business-logic-heavy applications.

### Requirement

When testing API-centric environments, the platform MUST enforce governance controls specific to API business logic traversal, token propagation, and schema validation.

**Rules of Engagement (MUST):**
The operator MUST define and document the following in the Rules of Engagement before testing begins:
- **Authorized API endpoints**: Complete list of API endpoints the platform is permitted to test
- **Allowed HTTP methods**: Which HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS, and HEAD) are permitted per endpoint
- **Authorized authentication contexts**: Which user roles, authentication tokens, or authentication types may be used for testing
- **Prohibited business logic workflows**: Explicit list of business logic workflows or operations that are off-limits

**Platform Enforcement (MUST):**
The platform MUST enforce all boundaries defined in the Rules of Engagement:
- Restrict autonomous API traversal to only authorized endpoints listed in the Rules of Engagement
- Reject requests to unauthorized API endpoints before execution
- Enforce allowed HTTP methods per endpoint; reject other methods
- Use only authorized authentication contexts; reject attempts to escalate or use unauthorized credentials
- Block execution of prohibited business logic workflows
- Track and log all API requests with endpoint, method, authentication context, and scope validation result
- Detect and flag API schema changes (changes in API contracts during the engagement) for operator review
- Track and log token propagation across services with provenance

### Verification

1. **Rules of Engagement documentation**: Verify Rules of Engagement includes all four required elements (authorized endpoints, allowed HTTP methods, authorized authentication contexts, prohibited workflows) before testing starts
2. **Endpoint whitelist enforcement**: Attempt to call an API endpoint not on the authorized list; verify the platform rejects the request before execution with clear authorization error
3. **HTTP method enforcement**: Define endpoint /api/users as GET-only in Rules of Engagement; attempt POST to /api/users; verify request rejected
4. **Authentication context enforcement**: Authorize only admin role for /api/admin/* endpoints; attempt access with user role; verify rejected before execution
5. **Prohibited workflow blocking**: List specific business logic workflows as off-limits in Rules of Engagement; verify platform blocks attempts to execute them
6. **API request logging**: Review logs; confirm all API requests include endpoint, method, authentication context, and scope validation result
7. **Schema change detection**: Introduce an API schema change mid-engagement; verify the platform detects and flags it
8. **Token propagation tracking**: Execute multi-service workflow; verify token usage is tracked across service boundaries with provenance

> **See also:** APTS-SE-006 (pre-action scope validation applied to API endpoints and methods), APTS-SE-023 (credential/token governance extended to API authentication contexts).

---

## APTS-SE-026: Out-of-Distribution Action Monitoring

**Classification:** SHOULD | Tier 2

### Requirement

The platform SHOULD monitor the agent's action stream during an engagement for patterns that deviate meaningfully from the action distribution the operator declared for the engagement class, or from the distribution the platform has historically observed for engagements of that class. The monitor's purpose is to surface behavior that is in scope and inside the APTS-SC-020 allowlist but still unusual enough to warrant a second look by a human.

At minimum, the operator SHOULD:

1. **Define metrics**: Define a small set of action-distribution metrics appropriate to the engagement class. Candidate metrics include tool invocation rate, the balance between reconnaissance and exploitation actions, target diversity, error-path frequency, and time distribution of actions. The chosen metrics MUST be documented.
2. **Establish baselines**: Establish a baseline per engagement class, either from a declared expected distribution or from historical data. Baselines SHOULD be versioned and refreshed on a documented cadence.
3. **Detect deviations**: Detect deviations that exceed operator-defined thresholds. Thresholds MUST be documented and MUST be grounded in something the operator can explain, not a default constant.
4. **Route detections for review**: Route detections to a human review queue rather than to automatic engagement termination. The point of this control is to raise questions, not to pull the plug; termination decisions remain governed by APTS-SC-011 and APTS-AL-026.
5. **Audit the loop**: Write detections, operator decisions (investigate, dismiss, escalate), and baseline updates to the audit trail under APTS-AR-020 so that a reviewer can reconstruct how unusual behavior was handled.

### Rationale

An autonomous pentest agent can stay entirely inside declared scope and inside the action allowlist while still behaving in ways its operator would want to know about: a sudden shift in the ratio of reconnaissance to exploitation, a sharp drop in target diversity, a burst of error-path invocations, or an action cadence that looks nothing like prior engagements of the same class. None of those on its own is a scope violation or a control breach, and none of them is reliably caught by the other scope enforcement requirements. This control gives the operator a lightweight way to notice that something has changed before it becomes a scope violation, without turning every unusual decision into an automatic halt. It is a SHOULD because the right metrics and thresholds depend heavily on engagement class and platform maturity, and a premature MUST would push operators toward brittle defaults.

### Verification

1. **Metric definition review**: Verify that the operator's engagement configuration documents the action-distribution metrics being monitored and that each metric has a defined measurement procedure.
2. **Baseline review**: Verify that a baseline exists for each engagement class the platform supports, that the baseline has a documented source (declared distribution or historical data), and that it has been refreshed within the operator's documented cadence.
3. **Detection test**: Inject a synthetic deviation into a test engagement that exceeds the documented threshold for at least one metric, and verify that the monitor flags the deviation and routes it to the review queue.
4. **Operator workflow review**: Select three detections from the last twelve months (or note if none exist) and verify that each has an operator decision recorded with a brief rationale, and that escalated detections reached the autonomy level adjustment review under APTS-AL-026 where appropriate.
5. **Audit trail review**: Verify that detections, operator decisions, and baseline updates are recorded in the audit trail under APTS-AR-020.

> **See also:** APTS-SC-011 (condition-based automated termination), APTS-SC-020 (action allowlist enforcement external to the model), APTS-AL-026 (incident investigation and autonomy level adjustment), APTS-AR-020 (audit trail isolation from the agent runtime), APTS-MR-023 (agent runtime as an untrusted component)

---
