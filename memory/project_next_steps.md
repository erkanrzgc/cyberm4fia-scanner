---
name: project-next-steps
description: Agreed roadmap items for cyberm4fia-scanner — test coverage, CI/CD, async, rate limiting, scan resume
type: project
---

Agreed roadmap (2026-03-25) in priority order:

1. Test coverage — unit tests for ssrf, ssti, xxe, lfi, cmdi, deserialization modules
2. CI/CD — GitHub Actions pipeline with pytest + ruff lint on every push
3. Async architecture — convert sync modules to real async HTTP for 3-5x perf
4. Rate limiting per-host — currently global, should be per-target
5. Scan resume hardening — more robust session persistence for large scans

**Why:** All major bugs and AI integration are done. These are the remaining gaps to make the scanner production-grade.
**How to apply:** When Erkan returns, start from item 1 unless he says otherwise. Plugin system was explicitly rejected as unnecessary.
