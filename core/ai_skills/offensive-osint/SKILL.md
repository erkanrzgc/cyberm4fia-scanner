---
name: offensive-osint
description: "Operational arsenal for external red-team and bug-bounty reconnaissance. Wordlists, 48-pattern secret-regex catalog, 80+ dork corpus, vendor product fingerprints, identity-fabric endpoints, CI/CD exposure paths, container registry leak detection, and sector-specific recon."
version: 2.1.1
triggers:
  - external recon
  - bug bounty recon
  - secret scanning
  - google dorking
  - subdomain enumeration
  - cloud bucket enumeration
  - identity fabric
  - SSO discovery
  - vendor product fingerprints
  - container registry leak
  - CI/CD exposure
  - package registry leak
  - sector specific recon
  - breach lookup
---

# Offensive OSINT — External Red-Team Arsenal

> Companion skill: `osint-methodology`. This skill is the "what to reach for."

## When to Use

When you need concrete probe paths, wordlists, regexes, payloads, or tool URLs for reconnaissance execution.

## Secret-Pattern Catalog — 48 Patterns

Used in the integrated `secrets_scanner.py` module. Covers: AWS, GCP, GitHub, Stripe, Slack, SendGrid, Mailgun, Twilio, Heroku, Firebase, JWT, Private Keys, Anthropic, OpenAI, HuggingFace, Cloudflare, DigitalOcean, npm, PyPI, Docker Hub, Atlassian, Linear, New Relic, DataDog, Sentry, ngrok, Discord, Telegram.

## Dork Corpus — 80+ Templates, 9 Categories

Substitute `{domain}` with target. Categories: Files, Admin/Login, Secrets/Credential Leakage, Cloud/CI/Shadow-IT, Docs/Intel Mining, Vuln Indicators, Internal Tool Exposure, Backup/Dump Files, Sector-Specific.

## Vendor Product Fingerprints

- **Citrix Netscaler**: `/vpn/index.html`, `/logon/LogonPoint/tmindex.html`
- **F5 BIG-IP**: `/tmui/login.jsp`, `/mgmt/tm/sys/`
- **Cisco ASA/AnyConnect**: `/+CSCOE+/`, `/webvpn.html`
- **Pulse Secure/Ivanti**: `/dana-na/`, `/dana-na/auth/url_default/welcome.cgi`
- **FortiGate/FortiOS**: `/remote/login`, `/remote/info`
- **PaloAlto GlobalProtect**: `/global-protect/`, `/global-protect/portal/css/login.css`
- **VMware Horizon**: `/portal/info.jsp`, `/broker/xml`
- **VMware vCenter**: `/sdk`, `/ui/`, `/vsphere-client/`
- **VMware ESXi**: `/sdk`, `/ui/`, `/folder`
- **Microsoft Exchange OWA**: `/owa/`, `/ews/exchange.asmx`, `/ecp/`
- **WatchGuard**: `/auth/`, `/wgcgi.cgi`
- **SonicWall SMA**: `/cgi-bin/welcome`, `/__api__/v1/`
- **Sophos UTM/XG**: `/userportal/`, `/webconsole/`
- **Check Point R80/R81**: `/sslvpn/portal/`, `/clients/`
- **Zoho ManageEngine**: `/RestAPI/Login`
- **Atlassian Confluence**: `/confluence/`, `/login.action`
- **Atlassian Jira**: `/secure/Dashboard.jspa`, `/rest/api/2/serverInfo`
- **GitLab self-hosted**: `/users/sign_in`, `/help`
- **SolarWinds Orion**: `/Orion/Login.aspx`

## Container Registry Leak Detection

| Registry | Search Pattern |
|---|---|
| Docker Hub | `https://hub.docker.com/search?q=<keyword>&type=image` |
| Quay (Red Hat) | `https://quay.io/search?q=<keyword>` |
| GitHub Container Registry | `https://api.github.com/orgs/<org>/packages?package_type=container` |
| Amazon ECR Public | `https://gallery.ecr.aws/?searchTerm=<keyword>` |
| Azure Container Registry | `*.azurecr.io` |
| Google Container Registry | `https://console.cloud.google.com/gcr/images/<project>` |

## CI/CD Platform Exposure

| Platform | Key Paths |
|---|---|
| Jenkins | `/script` (Groovy console), `/asynchPeople/`, `/computer/` |
| GitLab self-hosted | `/users/sign_in`, `/api/v4/version`, `/explore` |
| TeamCity | `/login.html`, `/agent.html` |
| Argo CD | `/api/version`, `/applications` |
| Drone CI | `/api/info`, `/login` |
| Spinnaker | `/gate/info`, `/applications` |
| Buildkite | Per-org dashboards |

## Identity Fabric Endpoints

- **Entra/ADFS**: `getuserrealm.srf`, `GetCredentialType`, `autodiscover`
- **Okta**: `/api/v1/authn`, `/.well-known/openid-configuration`
- **Google Workspace**: OIDC discovery, MX correlation
- **M365 Deep**: Teams federation, SharePoint subdomains, OneDrive, OAuth clients
- **SAML metadata**: 5 paths for metadata XML extraction

## Sector-Specific Recon

### Healthcare
- DICOM (port 11112), HL7 v2 (2575), FHIR REST APIs
- EHR systems: Epic, Cerner, Meditech
- Searches: HIPAA, PHI, patient records

### Finance
- SWIFT terminals, FIX protocol (port 9876)
- Banking middleware: Temenos T24, Finacle
- Searches: PCI, SOX, GLBA, MAS

### ICS/SCADA
- Modbus (502), BACnet (47808), Siemens S7 (102)
- DNP3 (20000), EtherNet/IP (44818)
- Never actively probe ICS without explicit RoE coverage

### IoT/Consumer
- MQTT (1883/8883), CoAP (5683)
- UPnP/SSDP (1900), camera DVRs

## Hard Rules (companion to methodology)

- Don't paste creds into cloud LLMs
- Don't run destructive probes outside DEEP/`--aggressive`
- Don't use validated credentials for anything except read-only verification
- Don't single-source attribute
