# Source — Claude-OSINT

- **Upstream:** https://github.com/elementalsouls/Claude-OSINT
- **Commit imported:** `ea42241d068e8112da0e4e28006207125c835c2e`
- **Imported on:** 2026-05-04
- **Files imported:** 15 (skills + docs + examples + README)
- **Skipped:** `.github/`, `tests/`, `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, `CHANGELOG.md`

## What this is

Paired Claude skills that turn Claude into an external reconnaissance
operator for authorized engagements:

- **offensive-osint** — tactical arsenal (90+ recon modules across 12
  domains)
- **osint-methodology** — strategic methodology and engagement planning

Sources covered: DNS/WHOIS/RDAP, SEC EDGAR, OpenCorporates, Wayback CDX,
breach intel (HudsonRock, HIBP, IntelX), cloud bucket scanning, vendor
fingerprinting, GitHub code-search dorks, LinkedIn/job-board enumeration,
read-only credential validators (Postman, AWS, GitHub, Slack, …),
secret-pattern catalogs, email-security audits (SPF/DMARC/DKIM),
infrastructure probes (Kubernetes, CI/CD, cloud-native).

## How to use in cyberm4fia-scanner

The scanner already has its own `core/ai_skills/offensive-osint/` and
`core/ai_skills/osint-methodology/` skills. This import is a parallel
reference — useful when the native methodology needs a second opinion or
when delegating an OSINT task to Claude directly.

## License

See upstream repository for license terms.
