---
name: offensive-secrets-exposure
description: "Secrets exposure hunting across source code, git history, client bundles, and public repos. Covers high-entropy/known-pattern detection (API keys, tokens, private keys), git-history mining of deleted secrets, .git/.env exposure, and validating/scoping leaked credentials. Use when reviewing repos, JS bundles, or exposed VCS metadata."
---

# Secrets Exposure — Offensive Testing Methodology

## Quick Workflow

1. Collect sources: client JS, exposed `.git`/`.env`, public repos, history
2. Scan for known key patterns and high-entropy strings
3. Mine git history for secrets deleted from HEAD
4. Validate scope/liveness of any credential (carefully, in scope)

---

## Where Secrets Hide

- Front-end JS bundles & sourcemaps (API keys, endpoints, tokens)
- Exposed `/.git/` (reconstruct repo) and `/.env`, `/config.json`
- Public/forked repos, Gists, CI logs, Docker image layers
- Commit history & branches (secret removed from HEAD but present in history)
- Backup files: `.bak`, `~`, `.swp`, `.DS_Store`

---

## Detection Patterns

```
AKIA[0-9A-Z]{16}                  # AWS Access Key ID
ASIA[0-9A-Z]{16}                  # AWS temp key
gh[pousr]_[A-Za-z0-9]{36,}        # GitHub tokens
xox[baprs]-[0-9A-Za-z-]+          # Slack tokens
-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----
AIza[0-9A-Za-z\-_]{35}            # Google API key
sk_live_[0-9a-zA-Z]{24,}          # Stripe live secret
eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.  # JWT
```

Also flag high Shannon-entropy strings near keywords: `secret`, `token`, `apikey`,
`password`, `private_key`, `aws_secret`.

---

## Git History Mining

```
git log -p --all | grep -iE 'api[_-]?key|secret|token|password'
# reconstruct exposed .git:
wget -r http://target/.git/    # then `git checkout .`
```

Secrets removed in a later commit still live in the object store and pack files.

---

## Validation (in scope)

- AWS key → `aws sts get-caller-identity` to confirm validity + identity
- GitHub token → `GET /user` and scope check (`X-OAuth-Scopes`)
- Treat live keys as CRITICAL; never exfiltrate beyond proof; recommend rotation

---

## Remediation

- Never commit secrets; use env vars / secret managers
- Rotate any exposed secret immediately; assume compromise
- Pre-commit secret scanning (gitleaks) + CI gate; purge history (BFG/filter-repo)
- Block `.git`/`.env`/backup files at the web server; strip secrets from bundles
