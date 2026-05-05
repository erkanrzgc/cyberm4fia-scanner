# Source — VICE (Webba Creative Technologies)

- **Upstream:** https://github.com/Webba-Creative-Technologies/vice
- **Imported on:** 2026-05-04
- **Files imported:** 12 (regex DB + 10 white-box audit modules + README)
- **License:** See upstream

## Why this was imported

VICE is a Node.js scanner with **15 specialized white-box / local audit
modules**. Most overlap with our existing scanner, BUT three categories
genuinely extend our coverage:

1. **Git history secret scanning** (`git-history.js`) — scans the last 500
   commits' diff for previously-leaked secrets that are recoverable from
   `.git/` even after removal from working tree. Our `secrets_scanner.py`
   only inspects the live HTML/JS of a target — it does **not** clone or
   walk git history. This is a real gap.

2. **White-box code-vulnerability audit** (`code-vulnerabilities.js`) — runs
   regex/AST patterns against `.js/.ts/.jsx/.tsx/.vue/.svelte` source for
   SQLi, XSS, hardcoded secrets, dangerous APIs. Our scanner is purely
   black-box — this is a brand-new capability class.

3. **Confidence-scored secret pattern DB** (`patterns.js`) — 14 hand-tuned
   regexes with placeholder/env-reference filtering. Strong reference for
   improving our `utils/secrets_scanner.py` precision.

Other modules (`auth.js`, `dependencies.js`, `supabase-rls.js`,
`headers-config.js`, `ci-security.js`, `env.js`, `container.js`) are kept
as **methodology references** — they overlap with our existing modules but
take different angles worth comparing.

## How to use in cyberm4fia-scanner

This is a **reference import**, not a runtime dependency. Concrete next
steps to extract value:

- Port `git-history.js` → `modules/git_history_scan.py` (new white-box
  capability: clone target git repo if accessible, scan history)
- Compare `patterns.js` SECRET_PATTERNS regex DB against
  `utils/secrets_scanner.py` and add missing patterns
- Port `code-vulnerabilities.js` → `modules/whitebox_code_audit.py` for
  cases where source code is supplied (e.g., on-prem CISO use)

These follow-ups are **not done yet** — they're ranked todo work.

## License

See upstream repository for license terms.
