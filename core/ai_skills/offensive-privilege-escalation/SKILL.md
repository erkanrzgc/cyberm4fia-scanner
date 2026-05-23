---
name: offensive-privilege-escalation
description: "Privilege escalation testing across web (vertical/horizontal authz) and host (Linux/Windows) contexts. Covers role/IDOR-based vertical escalation, parameter tampering, mass assignment, SUID/sudo/capabilities, cron, writable services, and post-exploitation enumeration. Use after gaining initial access or a low-privilege account."
---

# Privilege Escalation — Offensive Testing Methodology

## Quick Workflow

1. Establish current privilege (role, user id, group)
2. Web: attempt vertical (low→admin) and horizontal (user→user) escalation
3. Host: enumerate misconfigurations giving root/SYSTEM
4. Validate impact; capture evidence

---

## Web Privilege Escalation

### Vertical (role) escalation

- Access admin endpoints directly while authenticated as a normal user
- Tamper role in request: `role=admin`, `isAdmin=true`, `"role":"superuser"`
- **Mass assignment**: add privileged fields the UI never sends
  ```json
  {"username":"x","email":"x@y","role":"admin","verified":true}
  ```
- JWT claim tampering (`role`, `groups`, `scope`) — see offensive-jwt

### Horizontal escalation (IDOR)

- Swap object identifiers to act on other users' resources (see offensive-idor)
- Force-browse to `/users/{otherId}/settings`

---

## Linux Privilege Escalation

```
id; sudo -l                       # sudo rights, NOPASSWD entries
find / -perm -4000 -type f 2>/dev/null   # SUID binaries (GTFOBins)
getcap -r / 2>/dev/null           # capabilities (cap_setuid, etc.)
cat /etc/crontab; ls -la /etc/cron.*     # writable cron jobs
find / -writable -type d 2>/dev/null
```

Escalation vectors: GTFOBins via SUID/sudo, writable `PATH` for cron/root scripts,
LD_PRELOAD with `env_keep`, kernel exploits (check `uname -a`), Docker socket / group,
writable `/etc/passwd`, misconfigured systemd services.

---

## Windows Privilege Escalation

- Unquoted service paths; weak service permissions (`accesschk`)
- `AlwaysInstallElevated` registry keys
- Token impersonation (Potato family) with `SeImpersonatePrivilege`
- DLL hijacking on writable paths; scheduled tasks; stored creds (`cmdkey`)
- Check `whoami /priv`, `whoami /groups`

---

## Remediation

- Enforce server-side authorization checks on every object and action
- Bind privileges to server-side session/role, never client-supplied fields
- Whitelist bindable fields (guard against mass assignment)
- Host: drop SUID where unneeded, patch kernels, restrict sudo, audit cron/services
