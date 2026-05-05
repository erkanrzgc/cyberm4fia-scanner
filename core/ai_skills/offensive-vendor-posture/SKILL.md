# SKILL: Vendor Posture

## Metadata
- **Skill Name**: vendor-posture
- **Folder**: offensive-vendor-posture
- **Source**: pentest-agents rules/vendor-status.md

## Description
Kill-list of patched attack classes, fingerprint signatures for framework detection, and cooldown tables for takeover bugs. Prevents re-probing patched vectors across engagements. Consult when recon points at a vendor surface (cloud, IdP, CDN, managed DB) or when a chain relies on framework behavior.

## Trigger Phrases
Use this skill when the conversation involves any of:
`vendor, patched, fingerprint, framework detection, Keycloak, AWS, Azure, GCP, managed DB, cooldown, takeover, subdomain, CSP drift`

## Instructions for Claude

When this skill is active:
1. Check the Patched table before probing known-fixed vectors
2. Use Framework Fingerprints before running framework-specific CVEs
3. Consult cooldown tables for takeover-style bugs
4. Run managed DB queries against catalog views

---

## Patched — do not test

| Vector | Patched by | Since |
|---|---|---|
| `*.azurewebsites.net` subdomain takeover | Microsoft reserves deprovisioned hostnames | 2022-11 |
| AWS S3 "public bucket default" on new buckets | Block Public Access on by default | 2023-04 |
| GCS uniform bucket-level access on new buckets | Google default | 2020 |
| GitHub Pages `*.github.io` takeover on deleted repos | 24h reservation + explicit CNAME check | 2018 |

## Cloud Subdomain-Takeover Cooldowns

| Service | Cooldown | Notes |
|---|---|---|
| `*.azurewebsites.net` (App Service) | Indefinite reservation | Skip — patched |
| `*.trafficmanager.net` | ~2 hours | Testable |
| `*.cloudapp.net` (classic VM DNS) | ~7 days | Testable |
| `*.blob.core.windows.net` | Immediate | Testable |
| `*.herokuapp.com` | Immediate after deletion | Program scope must permit |
| `*.fastly.net` | Immediate | Requires service-config collision |
| `*.github.io` | 24h then immediate | Test only when dangling CNAME confirmed |
| `s3://<bucket>` | Immediate | Region-scoped |

## Framework Fingerprint Signatures

### Keycloak vs Spring Authorization Server

| Signal | Keycloak | Spring Authorization Server |
|---|---|---|
| OIDC discovery path | `/realms/<realm>/.well-known/openid-configuration` | `/.well-known/openid-configuration` at root |
| `issuer` in discovery | `https://.../realms/<realm>` | Equal to server base URL |
| Session cookie | `KEYCLOAK_SESSION`, `KEYCLOAK_IDENTITY` | `JSESSIONID` only |
| Admin surface | `/auth/admin/` | No built-in admin UI |
| Error body shape | Keycloak JSON envelope with `error`/`error_description` | Spring `OAuth2Error` shape |

### Azure App Service vs S3 Static Hosting

| Signal | Azure App Service | S3 static site |
|---|---|---|
| Headers | `x-powered-by: ASP.NET`, `Server: Microsoft-IIS/...` | `Server: AmazonS3`, `x-amz-request-id` |
| 404 body | HTML "The resource you are looking for has been removed" | `<Error><Code>NoSuchKey</Code>...` XML |

### Next.js vs Nuxt

| Signal | Next.js | Nuxt |
|---|---|---|
| Hydration root | `__NEXT_DATA__` `<script>` tag | `__NUXT__` `<script>` tag |
| Asset path | `/_next/static/...` | `/_nuxt/...` |
| API conventions | `/api/*` collocated with pages | `/api/*` via Nitro server routes |

## Chrome CSP Drift (re-verify every ~6 months)

| Feature | Current behavior (≥ Chrome 124) |
|---|---|
| `'unsafe-inline'` with `nonce-...` | Nonce wins; unsafe-inline ignored for that source |
| `'strict-dynamic'` + legacy `'unsafe-inline'` | `strict-dynamic` takes precedence |
| `script-src-attr 'unsafe-inline'` | Required for inline event handlers |
| `trusted-types` enforced | Blocks DOM sinks receiving plain string |

## Managed-DB Internal Surface (Postgres catalogs)

Authenticated DB users can read per-tenant config via `pg_settings`:

```sql
SELECT name, setting FROM pg_settings
WHERE name NOT IN ('application_name','TimeZone','search_path');
SELECT * FROM pg_shadow;
SELECT * FROM pg_user;
SELECT * FROM pg_roles;
```

Do NOT attempt `SET ROLE`, `ALTER ROLE`, `SECURITY DEFINER`, extension escalation, or FDW outbound; managed platforms block these.
