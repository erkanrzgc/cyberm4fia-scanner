# Source — Bug-Bounty-Agents

- **Upstream:** https://github.com/matty69v/Bug-Bounty-Agents
- **Commit imported:** `5f8b8301b1bfbbe3aece4f38337cef69d52af0dc`
- **Imported on:** 2026-05-04
- **Files imported:** 45 markdown agent prompts
- **Skipped:** `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md` (project-meta, not skill content)

## What this is

A curated set of 43+ specialized **AI agent prompts** for bug bounty work,
designed to run on Claude Code, Cursor, GitHub Copilot Chat, and ChatGPT/Gemini.
Each `*.md` file is a standalone agent persona covering one phase of the
offensive lifecycle (recon, web/API testing, infra, exploitation, reporting).

These are **prompts, not scanners** — they guide LLM reasoning rather than
provide standalone tooling.

## How to use in cyberm4fia-scanner

The scanner's `ai_intent_agent`, `ai_exploit_agent`, and `agent_orchestrator`
can load any of these prompts as a system message when delegating a task to
the LLM. They complement the native `core/ai_skills/offensive-*` skills.

## License

See upstream repository for license terms. All copied content remains under
the upstream project's license.
