# cyberm4fia-scanner APTS Conformance Overview

## What is APTS?

OWASP Autonomous Penetration Testing Standard — a governance standard for
autonomous pentest platforms. 173 requirements across 8 domains, 3 tiers.

Reference: https://github.com/OWASP/APTS

## Scanner Current State (Tier 1 Readiness)

### Domain 1: Scope Enforcement (SE) — 26 requirements
Status: PARTIALLY MET
- core/scope.py: Domain wildcard scope with include/exclude patterns, glob matching
- Scope boundary checking via stats tracking
- proxy_interceptor.py enforces target_scope on MITM traffic
- TODO: Formal scope validation before every action (APTS-SE-005)

### Domain 2: Safety Controls (SC) — 20 requirements
Status: PARTIALLY MET
- utils/code_executor.py: Docker-sandboxed PoC execution
- utils/docker_executor.py: Containerized exploitation
- TODO: Formal impact classification per action (APTS-SC-001)
- TODO: Hard kill switch mechanism (APTS-SC-010)

### Domain 3: Human Oversight (HO) — 19 requirements
Status: PARTIALLY MET
- AutonomyLevel enum in agent_framework.py (L1-L4)
- requires_approval() gate for destructive actions
- TODO: Operator qualification requirements (APTS-HO-018)

### Domain 4: Graduated Autonomy (AL) — 28 requirements
Status: IMPLEMENTED
- AutonomyLevel: L1 Assisted → L4 Autonomous
- requires_approval() per action type per level
- Default: L3 Supervised Autonomous

### Domain 5: Auditability (AR) — 20 requirements
Status: PARTIALLY MET
- Scan session logging via JSON files
- utils/scan_intelligence.py: Cross-scan knowledge store
- TODO: Append-only tamper-proof audit trail (APTS-AR-020)

### Domain 6: Manipulation Resistance (MR) — 23 requirements
Status: PARTIALLY MET
- utils/validation_pipeline.py: 4-gate hallucination prevention
- Anti-hallucination pipeline in ai_exploit_agent.py
- TODO: Formal prompt injection defense (APTS-MR-001)

### Domain 7: Supply Chain Trust (TP) — 22 requirements
Status: NOT STARTED
- TODO: AI provider documentation (NVIDIA NIM, Llama 3.3)
- TODO: Model change impact assessment

### Domain 8: Reporting (RP) — 15 requirements
Status: PARTIALLY MET
- Confidence scores on AI-generated findings (70% threshold)
- CVSS/CWE/EPSS scoring in utils/finding.py
- TODO: False-positive rate disclosure per finding

## Autonomy Level Configuration

| Level | Name | Scan | Exploit | Destructive | Scope Exit |
|-------|------|------|---------|-------------|------------|
| L1 | Assisted | APPROVAL | APPROVAL | APPROVAL | APPROVAL |
| L2 | Semi-Autonomous | AUTO | APPROVAL | APPROVAL | APPROVAL |
| L3 | Supervised (default) | AUTO | AUTO | APPROVAL | APPROVAL |
| L4 | Autonomous | AUTO | AUTO | AUTO | MONITOR |
