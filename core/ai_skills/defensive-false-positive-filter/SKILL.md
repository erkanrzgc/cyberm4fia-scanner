---
name: defensive-false-positive-filter
description: "Filter out SPA fallback, soft-404, generic error page, and template-mirror false positives from scanner findings. Use when triaging endpoint-discovery hits, sensitive-info-exposure findings, and any '200 OK on a suspicious path' result. Includes a deterministic decision tree (title → length-band → simhash → DOM skeleton) and confidence calibration."
---

# Defensive False-Positive Filter — SPA / Catch-All Triage Methodology

## When to Use

A finding looks suspicious but the response body is identical (or near-identical)
to the site's homepage. Symptoms:

* HTTP 200 on `/admin`, `/wp-admin`, `/.env`, `/api-docs`, `/swagger.json`, etc.
* Response size clusters tightly (within 0.5%) around the homepage size.
* Multiple unrelated paths return bodies with the same `<title>` and the same
  navigation HTML.

These are almost always:

* **SPA history routing** (React/Vue/Next.js/Angular returning `index.html`
  for any unmatched route)
* **Apache/Nginx custom 404** mapped to 200 + the marketing homepage
* **WordPress catch-all** redirecting unknown slugs to the front page
* **Laravel/Rails route fallback** returning the brand landing
* **SSO wall** rewriting every URL to the login page

---

## Decision Tree

Run these checks in order. The first match wins.

```
1. Hash exact match (sha256 of body) with any calibration probe   → spa_fallback
2. DOM skeleton hash exact match (tag sequence identical)          → spa_fallback
3. <title> tag identical to homepage AND |Δlength| / len ≤ 5%      → continue (4)
   else                                                            → real_vuln
4. simhash Hamming distance ≤ 3  vs homepage                       → spa_fallback
   simhash distance 4-10                                           → unclear
   simhash distance > 10                                           → real_vuln
```

The engine has already applied steps 1-2 via `utils.response_fingerprint`. AI is
called when the engine could not decide (e.g. step 3 hit `continue` but the
fingerprint baseline was incomplete, or the finding came from a path that
wasn't probed during calibration).

---

## Sites Patterns to Recognise

* **Next.js / Vercel:** path returns 200, body contains `__NEXT_DATA__` script
  with `"page":"/<unrelated route>"`. The `<title>` is the brand title for
  every path.
* **WordPress:** path returns 200 with `<meta name="generator" content="WordPress">`
  and the body is the front-page theme template.
* **Laravel route fallback:** body contains a generic CSRF token meta tag plus
  the homepage `<main>` element. URL is preserved in the `<base href>`.
* **SPA history routing (React Router / Vue Router):** path returns 200 with
  the same SPA shell; the only mutation is the `<base href>` or `<link
  rel="canonical">` URL.
* **Custom 404 returning 200:** Apache/Nginx with `ErrorDocument 404 /index.html`
  + `RewriteRule` chains. Body is the homepage but might have a small "page
  not found" string embedded — search for `not found|sayfa bulunamadı|404` in
  the body if length matches the homepage closely.

---

## Known FP Heuristics

| Signal | Decision |
|---|---|
| Body > 30KB AND title matches homepage AND DOM skeleton matches | `spa_fallback` (confidence ≥ 95) |
| Body < 2KB AND identical body across every "found" path | `dynamic_error_page` (confidence ≥ 90) |
| Every path redirects to `/login` or `/sso` with the same body | `benign_path` (auth wall) |
| Same simhash bucket as homepage AND content-type is `text/html` AND no leaked secrets matched the body | `spa_fallback` |
| Path matched a sensitive keyword (`.env`, `wp-admin`) BUT body is the homepage | `spa_fallback` (high confidence) |
| Path is `.env`/`.git` BUT body is **plain text** with `KEY=value` pairs or `[core]` ini blocks | `real_vuln` — NEVER mark as FP |
| Path is `info.php` BUT body contains `phpinfo()` table markers | `real_vuln` — NEVER mark as FP |

The last two rows are the rules that catch genuine leaks even when most of the
batch is a SPA template.

---

## Confidence Calibration

* simhash distance **0**: identical body — `confidence: 100` (FP)
* simhash distance **1-3**: same template, different URL fragment — `confidence: 95`
* simhash distance **4-10**: shares boilerplate header/footer only — `confidence: 60`, mark `unclear`
* simhash distance **> 10**: different page — `confidence: 5` for FP claim

When body is missing entirely (only headers captured), fall back to title-only
matching and downgrade confidence by 30.

---

## What NOT to Filter

* **Missing security headers** — these are valid for the homepage itself. They
  are intentionally excluded from FP filtering and emitted with content-aware
  payloads via `modules/header_exploit_map.py`.
* **Secret leaks where the body is plain text** (no HTML tags) — never an SPA
  fallback by definition; almost certainly a real `.env`, `.git/config`, or
  config dump.
* **`info.php` / `phpinfo()` output** — body contains `<title>phpinfo()</title>`
  and the characteristic ImageMagick-style PHP logo. Real, every time.

---

## Output Schema

```json
{
  "real": true,
  "confidence": 0,
  "reason": "...",
  "evidence_type": "real_vuln | spa_fallback | dynamic_error_page | benign_path | unclear"
}
```

* `real=true, evidence_type=real_vuln` → keep finding
* `real=false, evidence_type=spa_fallback` → drop finding, log reason
* `evidence_type=unclear` → keep finding but downgrade severity by one tier
