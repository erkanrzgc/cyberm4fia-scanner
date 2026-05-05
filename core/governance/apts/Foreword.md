# Foreword

Autonomous penetration testing tools make real-time decisions, chain exploits, and operate without human intervention. Unlike manual and automated testing, where a human tester is always in control, these systems operate independently and can exhibit behaviors their creators did not anticipate.

Existing standards (the Penetration Testing Execution Standard [PTES], the OWASP Web Security Testing Guide [WSTG], and the Open Source Security Testing Methodology Manual [OSSTMM]) were designed for human-driven testing workflows and do not address the governance challenges unique to autonomous operation: scope enforcement without human judgment, safe autonomous exploitation, manipulation resistance, and algorithmic accountability. These systems operate with varying degrees of independence and traverse attack surfaces dynamically.

These capabilities create governance gaps that existing frameworks do not address. This standard answers these challenges with 173 tier-required requirements across eight governance domains: scope enforcement, safety controls, human oversight, graduated autonomy, auditability, manipulation resistance, supply chain trust, and reporting.

The standard applies across different platform architectures without prescribing specific AI architectures, scanning techniques, or implementation languages. Several domains (particularly Manipulation Resistance, Supply Chain Trust, and Graduated Autonomy) address AI/ML-specific risks; non-AI autonomous systems should evaluate which requirements apply to their architecture. Requirements specific to certain architectures (AI/ML, cloud, multi-tenant) are marked with applicability statements.

APTS applies to any autonomous pentesting system operating against production or production-like environments where the system makes autonomous decisions about targeting, methodology, or exploitation.

Feedback and implementation experience reports are welcome through the OWASP project page.

---

**Jinson Varghese Behanan**<br>
**Project Lead, OWASP Autonomous Penetration Testing Standard**<br>
**2026**
