---
name: offensive-cloud-attacks
description: "Cloud and Backend-as-a-Service attack testing for AWS/GCP/Azure resources and BaaS platforms (Firebase, Supabase). Covers public storage buckets, exposed metadata (IMDS) via SSRF, over-permissive IAM, open Firebase/Supabase rules, and cloud resource enumeration. Use when assessing cloud-hosted apps, object storage, and BaaS-backed mobile/web apps."
---

# Cloud & BaaS Attacks — Offensive Testing Methodology

## Quick Workflow

1. Enumerate cloud assets (buckets, functions, BaaS endpoints) from app + DNS
2. Test public/anonymous access to storage and databases
3. Look for credential/metadata exposure (IMDS via SSRF)
4. Assess IAM / security-rule misconfiguration impact

---

## Object Storage (S3 / GCS / Azure Blob)

```
https://<bucket>.s3.amazonaws.com/
https://storage.googleapis.com/<bucket>/
https://<account>.blob.core.windows.net/<container>?restype=container&comp=list
```

Test: anonymous LIST, READ, and WRITE. Public write = content injection/defacement.
Enumerate bucket names from app source, CNAMEs, and permutations of the org name.

---

## Metadata Service (IMDS) via SSRF

When an SSRF exists on a cloud host, pivot to credentials:

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS IMDSv1
http://metadata.google.internal/computeMetadata/v1/   (Metadata-Flavor: Google)
http://169.254.169.254/metadata/instance?api-version=2021-02-01     (Metadata: true)  # Azure
```

IMDSv2 requires a PUT token first — chain only if the SSRF allows method/headers.
Stolen role credentials → enumerate with `aws sts get-caller-identity`, then scoped actions.

---

## Firebase / BaaS

### Firebase Realtime DB / Firestore

```
https://<project>.firebaseio.com/.json        # open RTDB read
https://<project>.firebaseio.com/.json?print=pretty
```

Open `.json` returning data = world-readable rules. Test write with a PUT of a
benign key. Firestore: test unauthenticated SDK reads when rules are `allow read`.

### Supabase

- Anon key is public by design — the risk is **Row Level Security disabled**
- Test REST: `GET /rest/v1/<table>?select=*` with the anon key → full table = no RLS
- Exposed `service_role` key in client = full DB compromise (CRITICAL)

---

## IAM / Permissions

- Over-permissive roles (`*:*`), wildcard resource policies
- Public Lambda function URLs / API Gateway without auth
- Privilege escalation via `iam:PassRole`, `sts:AssumeRole` chains

---

## Remediation

- Block public access on buckets; least-privilege bucket policies
- Enforce IMDSv2 (hop limit + token); fix the underlying SSRF
- Lock Firebase rules (`auth != null` + per-record checks); enable Supabase RLS
- Never ship `service_role`/admin keys to clients; scope IAM tightly
