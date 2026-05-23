---
name: offensive-http-method-tampering
description: "HTTP method/verb tampering and access-control bypass testing. Covers verb-based authz bypass (GET vs POST vs arbitrary), method override headers, dangerous methods (PUT/DELETE/TRACE/CONNECT), and WebDAV exposure. Use when testing endpoints whose authorization may depend on the HTTP method."
---

# HTTP Method Tampering — Offensive Testing Methodology

## Quick Workflow

1. Enumerate allowed methods (`OPTIONS`, observe `Allow:` header)
2. Replay protected requests with alternate verbs (GET↔POST, HEAD, arbitrary)
3. Test method-override headers and dangerous methods (PUT/DELETE/TRACE)
4. Confirm authz bypass or unintended write/read

---

## Detection

### Enumerate Methods

```
OPTIONS /path HTTP/1.1        → Allow: GET, POST, PUT, DELETE
```

### Verb-Based Authz Bypass

Many filters protect only specific verbs. If `POST /admin` is blocked, try:

```
GET /admin
HEAD /admin
PUT /admin
FOO  /admin           # arbitrary verb — some servers default to GET handler
```

A `403` on POST but `200` on GET/HEAD/arbitrary verb is a bypass.

### Method Override Headers

When the framework honors overrides, smuggle a privileged method past a verb filter:

```
X-HTTP-Method-Override: PUT
X-HTTP-Method: DELETE
X-Method-Override: PUT
POST /resource?_method=DELETE
```

---

## Exploitation

### Dangerous Methods

- **PUT** — upload a file/webshell if the server writes the body to the path
- **DELETE** — remove resources without authz
- **TRACE** — Cross-Site Tracing (XST) to read headers/cookies in old stacks
- **CONNECT** — proxy abuse / SSRF pivot

### WebDAV

`PROPFIND`, `MKCOL`, `MOVE`, `COPY` exposed → directory listing and file write.

```
PUT /shell.jsp HTTP/1.1
Content-Length: ...

<%-- webshell --%>
```

---

## Remediation

- Enforce authorization independent of HTTP method
- Disable unused/dangerous methods (PUT, DELETE, TRACE, CONNECT) at the server
- Ignore method-override headers unless explicitly required
- Disable WebDAV where not needed; restrict write methods by auth + path
