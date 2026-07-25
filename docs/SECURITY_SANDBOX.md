# Sandbox Security Review

**Scope:** the execution layer used by `utils.ai_intent_agent` to run
LLM-generated Python exploit code.

**Files:** `utils/code_executor.py` (subprocess mode), `utils/docker_executor.py`
(Docker mode), `utils/ai_intent_agent.py` (caller).

**Audited:** 2026-05-23. This document is the source of truth for what the
sandbox protects against and what it does NOT.

---

## 1. What the sandbox does well

| Control | Subprocess mode | Docker mode |
|---|---|---|
| Process isolation from parent | ✅ separate Python process | ✅ container |
| Import allow-list (`__import__` hook) | ✅ ~25 stdlib + requests/httpx | ✅ same list |
| CPU / memory / file-size limits (RLIMIT) | ✅ | ✅ |
| Process-count limit (RLIMIT_NPROC) | ✅ 64 | ✅ + `--pids-limit 128` |
| Read-only rootfs | ❌ host FS readable as parent UID | ✅ `--read-only` |
| Capability drop | ❌ | ✅ `--cap-drop ALL` |
| No-new-privileges | ❌ | ✅ |
| Non-root user | runs as parent user | ✅ `--user 65534:65534` |
| Ephemeral filesystem | ❌ | ✅ `--rm`, tmpfs `/tmp` noexec/nosuid |
| Timeout enforcement | ✅ `subprocess.run(timeout=)` | ✅ + container stop |

**Conclusion for that table:** Docker mode is materially stronger and is what
should be used for any non-trivial threat model.

---

## 2. Real weaknesses (call them what they are)

### 2.1 `__builtins__` exposes dangerous primitives — CRITICAL (subprocess mode)

The harness sets `_g = {"__name__": "__sandbox__", "__builtins__": builtins}`,
so user code inherits the **entire** `builtins` namespace:

- `open()` — read or write any file accessible to the parent UID.
  Import allow-list is irrelevant because `open` is a *builtin*, not a module.
- `eval`, `exec`, `compile` — execute arbitrary strings, sidestep the AST.
- `__import__` is replaced with the guarded version, but user code can read it
  off `builtins` and call it through other paths.

In Docker mode this is mitigated by the read-only rootfs + non-root user, but
in **subprocess mode the host filesystem is fully readable as the user running
the scanner** — `/etc/passwd`, `~/.aws/credentials`, project source, etc.

**Fix shipped in this commit:** subprocess sandbox now constructs a curated
`__builtins__` dict that strips `open`, `eval`, `exec`, `compile`, `input`,
`breakpoint`. A regression test confirms `open(...)` raises `NameError` in
sandboxed code.

### 2.2 Outbound network is unrestricted — HIGH

`requests` and `httpx` are allowed (exploits need to talk to the target). The
sandbox does **not** restrict destination hosts. Malicious LLM output, prompt
injection through a target response, or a compromised model could exfiltrate
findings, env vars, or even file contents (now blocked by 2.1) to an
attacker-controlled URL.

**Mitigation:**
- Docker mode: set `SCANNER_SANDBOX_NETWORK=none` for tasks that don't need
  network, or use a network policy that only allows the target host.
- Caller side: the adaptive orchestrator already enforces a target-host scope
  on planner-proposed intents (see `_resolve_default_scope`), but this does
  not stop the exploit code itself from connecting elsewhere.
- Future hardening (not in scope of this PR): pass the target host into the
  Docker container as the only allowed egress (`iptables`/`netavark` ACL).

### 2.3 Docker default network is `bridge` — MEDIUM

`DEFAULT_NETWORK = os.environ.get("SCANNER_SANDBOX_NETWORK", "bridge")`.
Full internet by default is convenient for testing but couples 2.2's risk to
"works out of the box." Operators should set the env var explicitly.

### 2.4 No seccomp profile — LOW (Docker mode)

`docker run` is launched without `--security-opt seccomp=…`. Default Docker
seccomp profile is applied (which is reasonable), but a custom restrictive
profile would reduce the syscall surface further.

### 2.5 Subprocess group not killed on timeout — LOW

`subprocess.run(timeout=…)` terminates the immediate child. If the user code
spawned grandchildren before RLIMIT_NPROC caught up, those processes are not
killed. RLIMIT_NPROC=64 limits the blast radius but does not eliminate it.

### 2.6 Resource limits are Linux-only — INFO

The `resource` module is unavailable on Windows; the harness gracefully no-ops
those limits. Document this so operators know subprocess mode on Windows has
weaker enforcement.

---

## 3. Threat model — when is this sandbox enough?

| Scenario | Sandbox sufficient? |
|---|---|
| Authorized pentest, operator runs Docker mode, `--network` restricted, no sensitive secrets on host | ✅ |
| Authorized pentest, subprocess mode on a clean throw-away VM | ✅ (subject to 2.1 fix in this commit) |
| CI/CD running the agent against arbitrary targets on shared hardware | ⚠ Use Docker mode, isolate per-job |
| Operator's primary workstation with cloud creds, SSH keys, source code | ❌ Use Docker mode; never subprocess mode |

The scanner is **not** designed to defend against an adversarial LLM provider
or a model that has been prompt-injected into actively exfiltrating data.
Network restriction (2.2) is the only complete mitigation for that class.

---

## 4. Recommended operator configuration

```bash
# Strongest stance: Docker mode, no egress unless explicitly needed.
export SCANNER_SANDBOX_NETWORK=none

# When an exploit needs to reach the target only, use a per-job custom network
# with iptables egress restricted to the target's resolved IP(s).
```

If the scanner runs Docker mode, ensure the Docker daemon socket is **not**
mounted into containers (it is not, by design — but custom integrations
should be reviewed).

---

## 5. What this review did NOT cover

- Container-escape primitives in the host kernel (out of scope of this code)
- LLM provider auth-token theft (NVIDIA NIM credentials live in env vars on
  the parent process, not in the sandbox)
- Side-channel attacks (timing, cache) on co-tenanted Docker
- Supply-chain integrity of `requests`/`httpx`/`python` images (lock these
  via image digest in production)

---

## 6. Open follow-ups (tracked in this repo)

- [ ] Default `SCANNER_SANDBOX_NETWORK=none` in production configs once a
      per-target egress policy is shipped.
- [ ] Per-target egress allow-list in Docker mode.
- [ ] Custom seccomp profile.
- [ ] Process-group SIGKILL on subprocess timeout.
- [ ] Document Windows subprocess limitations in the user guide.
