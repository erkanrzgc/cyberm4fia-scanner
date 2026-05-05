# SKILL: Common Mistakes Log

## Metadata
- **Skill Name**: common-mistakes
- **Folder**: offensive-common-mistakes
- **Source**: pentest-agents rules/mistakes.md

## Description
"Do not repeat" register of lessons from real engagements. Covers agent behavior mistakes, methodology mistakes, tooling mistakes, reporting mistakes, and scope/policy mistakes. Read at the start of every hunt to avoid wasting time, inflating reports, or missing bugs.

## Trigger Phrases
Use this skill when the conversation involves any of:
`mistake, lesson learned, best practice, don't repeat, avoid, methodology, reporting, validation, agent behavior`

## Instructions for Claude

When this skill is active:
1. Read the relevant mistake category when facing a decision
2. Apply the "Apply: when/where" condition before acting
3. If the user corrects you, audit next 3 actions against the correction

---

## Top 10 Most Common Mistakes

1. **Write artifacts to disk.** Terminal output is not evidence. If it's not on disk, it doesn't exist.
2. **Never hallucinate file paths.** `ls` every path before it lands in a report or message.
3. **Run /validate BEFORE writing the report.** The 7-Question Gate kills weak findings in 30 seconds; reports take 30 minutes.
4. **Use a real browser for WAF/JS/CAPTCHA/UI-mediated bugs.** `curl` 403 from a CDN is not "not vulnerable" — it's "you never reached the app."
5. **Demonstrate impact with real data, not theoretical language.** "Could result in..." is N/A bait. "Here is the data I accessed" is a finding.
6. **Sibling Rule: test every adjacent endpoint, method, field, and alias.** 30%+ of paid IDOR/BAC bugs are sibling bugs.
7. **Match CVSS version to platform.** HackerOne = 3.1. Bugcrowd/Intigriti/Immunefi = 4.0. Mismatch = triage rework.
8. **Read `policy.md` BEFORE the first probe.** Required headers, rate limits, OOS labels, banned techniques all live there.
9. **"CONFIRMED" means working PoC against the live target.** Fingerprints and status-code differentials are `POTENTIAL` at best.
10. **When corrected once, recalibrate.** If the user flags the same mistake twice, halt and audit — don't repeat.

## AGENT-BEHAVIOR Rules

- Write files to disk — terminal output is not a deliverable
- Never hallucinate file paths — `ls` every path before citing
- Don't call it "CONFIRMED" unless you have a working PoC against the live target
- Read program memory / `.env` / brain files before asking the user
- When the user corrects you, audit the next 3 actions against the correction
- Rank findings when asked, don't list
- Never use placeholder values when the real value is one file away
- Don't pollute identity/credential memory files with ephemeral session status
- Parallel subagents must write to unique output paths
- Agent-local memory files must be indexed back into the main brain
- Quota-hit subagents are UNRUN — don't promote their empty verdict
- Honor autonomy flags — only checkpoint for carved-out decisions
- Don't read a subagent's full transcript file
- Don't re-attack surfaces marked EXHAUSTED without new capability
- Record EVERY exhausted vector with its specific blocker

## METHODOLOGY Rules

- Run /validate (7-Question Gate) BEFORE writing any report
- Run /chain on every confirmed capability before writing the primary report
- Apply the Sibling Rule — method, field, verb, alias, route, GraphQL op
- Mine rejection text — it IS the spec for the resubmission
- Demonstrate impact with actual data — never theoretical phrasing
- Run the never-submit check at the IDEA stage, not after a 30-minute draft
- Differential server responses on placeholder IDs are not proof of unauth access
- A CORS wildcard without a credential delivery path is not exploitable
- Spec violations alone aren't vulnerabilities
- Verify framework / tech stack BEFORE running framework-specific exploits
- WAF 403 on a path means the path exists — but don't submit from that alone
- Error-message divergence is a signal, not a finding
- IDOR requires a cross-user test — not a placeholder-ID response check
- Cross-account testing needs a second account from day one
- Pre-hijack / account-collision testing needs 3 accounts and a real IdP return
- Auth-required impact path ≠ `Scope:Changed`
- Staging-parity checks rarely produce bugs — time-box hard
- Probabilistic exploits need reliability measurement before claiming them
- Use timing oracles to classify "blind" SSRF quantitatively

## TOOLING Rules

- Use a real browser (browser-agent / Camoufox / Playwright) for WAF/JS/CAPTCHA/UI-mediated bugs
- Before concluding "not vulnerable" on a WAF-gated endpoint, confirm the app layer was reached
- "WAF blocks <payload>" is NEVER a valid dead-end verdict — run the 7-level bypass ladder first
- Major IdP OAuth flows (Google GIS, Apple) can't be completed with a stealth browser
- Residential proxy for datacenter-IP + interactive CAPTCHA
- Saved bearer tokens expire — assume stale at session start

## REPORTING Rules

- Match CVSS version to platform policy
- When you change severity, change EVERY copy of it
- Don't submit "HTTP 200" as proof — demonstrate downstream impact
- Structure state-change reports as BEFORE / EXPLOIT / AFTER / CONTROL
- Include admin-view / detection evidence for stealth findings
- Verify exploit preconditions exist on YOUR instance before submitting
- Unverified escalations go in an "Untested Escalation" section, not the severity score
- Never use CWE-200 as the primary CWE
- Keep HackerOne titles short (≤80 chars)
- Place follow-up impact in `COMMENT-<slug>.md` files — don't edit submitted drafts

## SCOPE-POLICY Rules

- Read `policy.md` BEFORE the first active probe
- Inject program rate limits + required headers + banned tool categories into EVERY agent preamble
- Screen program economics BEFORE hunting — don't chase Lows on a VDP
- Verify EVERY wildcard before calling recon "exhausted"
- Policy-banned delivery mechanisms kill the chain — not the report
