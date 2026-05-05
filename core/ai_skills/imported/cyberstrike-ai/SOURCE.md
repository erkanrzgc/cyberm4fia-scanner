# Source — CyberStrikeAI

- **Upstream:** https://github.com/Ed1s0nZ/CyberStrikeAI
- **Imported on:** 2026-05-04
- **Files imported:** 37 (15 agent prompts + roles YAML + docs + READMEs)
- **Note:** Content is mixed Chinese/English. Useful as reference even if
  not translated.

## Why this was imported

The CyberStrikeAI binary itself is Go and would not integrate with our
Python stack — that part stays out. But the repo ships a portable layer
of **agent prompts and role configurations** that map directly to our
`utils/agent_orchestrator.py` and `core/ai_skills/` patterns.

### `agents/` (15+ markdown agent prompts)

Each file is a structured persona for one phase of an offensive engagement:

```
attack-surface-enumeration   intel-collection           penetration
cleanup-rollback             lateral-movement           persistence-maintenance
engagement-planning          opsec-evasion              privilege-escalation
impact-exfiltration          orchestrator(-plan-…)      recon
                             orchestrator-supervisor    reporting-remediation
                                                        vulnerability-triage
```

These cover stages our native skills don't cleanly express
(opsec-evasion, persistence, lateral-movement, cleanup-rollback) and offer
a second opinion on stages we do cover (recon, vulnerability-triage,
reporting).

### `roles/` (YAML role configs)

Lightweight role declarations (CTF, API security, …). Could be loaded by
`agent_orchestrator.py` to spin up a focused subagent.

## How to use in cyberm4fia-scanner

Reference imports — load any agent markdown as a system prompt when
delegating a task. The orchestrator-supervisor pattern in particular is
worth studying as our `agent_orchestrator.py` evolves.

## License

See upstream repository for license terms.
