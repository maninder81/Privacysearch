# Serus.ai feature review

Reviewed 2026-10-25 from serus.ai (home, `/protection/`, `/intelligence/`,
`/business/`, `/ai-info/`) and the public API reference at docs.serus.ai.
Serus is operated by Anon AI Labs, Inc. and describes itself as an "agentic AI
privacy and intelligence platform".

## 1. Product pillars

| Pillar | Serus sub-features |
| --- | --- |
| **Protection** | Surveillance (find and monitor exposure) · Data Removal ("erase your data on Autopilot") · Intelligence (surface + dark web search) · Reputation ("how the internet sees you", sentiment score) |
| **Intelligence** | Agentic OSINT (surface, deep and dark web) · Deployed Agents (your own monitored-source feed) · Developer API · Serus MCP toolkit for AI agents (coming soon) |
| **Business** | Team workspace · executive protection · per-protected-person / per-investigator-seat pricing · DPA · whitelabel / partnerships |
| **Serus Agent** (waitlist) | "An AI that watches for scams and leaks, and tells you first" |

## 2. Detailed capabilities

### Discovery
- **Universal search box** keyed on: email, phone (country-code picker), username, name, crypto wallet, domain.
- **Footprint discovery** across data brokers, people-search sites, public records, social platforms, other public sources.
- **Source search with provenance** – every finding attributed to the source it came from.
- **Dark web lookups** – breach dumps, credential collections, paste sites, forums, market listings. Sensitive values (passwords) are redacted until explicitly revealed.
- **Single exposure list ranked by risk** (addresses, phone numbers, leaked credentials, aliases).
- Input can be "an email, a username, a screenshot, or a question in plain language"; Serus picks the investigation path.

### Removal and remediation
- **Automated opt-out requests** filed with the source's data controller under **GDPR Art. 17** and **CCPA** where they apply.
- **Autopilot**: new exposures are queued and removed without user action.
- **Follow-up / re-filing** until data comes down; automatic re-submission when data **reappears** (relists).
- **Removal tracking** – every request visible through a pipeline from submission to confirmation.
- Free tier: 5 removal requests/day; Protection tier: unlimited.

### Monitoring and alerting
- 24/7 open-internet monitoring for new exposures.
- Dark web and breach monitoring (emails, passwords, other sensitive data).
- Real-time alerts when data appears in a new source or a new breach surfaces.
- "Daily digest" (quoted by a brand-team customer).
- Deployed agents watching names, domains and keywords around the clock.

### Risk and scoring
- **Risk assessment** weighted by data type and source (home address/phone weighted above public professional info).
- **Coverage Score** – current exposure level, tracked over time.
- "Digital health" map / footprint-reduction view.
- **Reputation sentiment** score.

### Conversational assistant ("Serus AI")
- Chat UI: "Ask, find and remove on the go." Example flow: the agent notices a home address listing and asks "Would you like me to request a removal?", then files a GDPR Art. 17 request.
- Free: 2 dark-web AI lookups/day, 50 free credits.

### Intelligence tools (public pages)
- Reverse email lookup (breaches, accounts and sources tied to an email, lookalike sender-domain detection).
- OSINT investigation from email / username / phone / domain / wallet.
- Vendor due diligence (real footprint, people/entities behind a supplier, flagged payment details).
- 56 marketed use cases, e.g. fake invoices, crypto scams, smishing, contractor/landlord vetting, vendor KYB, leaked credentials, typosquat & lookalike domains, phishing infrastructure mapping, doxxing prevention, executive protection.

### Developer API (docs.serus.ai, OpenAPI 3.1, `https://api.serus.ai/v1`)
- Bearer API keys `ak_…`, created in dashboard, secret shown once, editable / rotatable / revocable, with expiration.
- **Scoped permissions**: `account:read`, `darkweb:scan`, `darkweb:read`, `darkweb:reveal`.
- `GET /v1/hello` – verify key, returns `subject` (`user_…`/`org_…`), `scopes`, `credits_remaining`.
- `POST /v1/darkweb/scans` – identifier types `email, phone, username, domain, keyword, origin, password`; returns `{id, status: processing}`; recent duplicate scans are reused instead of re-charged.
- `GET /v1/darkweb/scans/{id}` – masked by default; `?reveal=true` needs `darkweb:reveal` and **reveals are audit-logged**.
- `POST /v1/darkweb/scans/stream` – Server-Sent Events: `breach`, `paste`, `done`, `error`; 15 s heartbeat, 5 min max.
- Results: `breaches[]` (`breachedData`, `isMasked`, `breachAuthority`), `pastes[]`, `extractedData` (`emails, usernames, phones, names, cryptoAddresses`).
- Credits (0.25 per dark web scan), `402 insufficient_balance`.
- Tiered per-second rate limits (60/7/3 req/s) with `X-RateLimit-*` and `Retry-After` headers.
- Consistent error envelope `{error:{type, code, message, request_id, details}}`.
- Additive-only stability policy within a major version.
- API spend dashboard per key / feature / time range.

### Teams / business
- Onboard many people into one workspace; map each person's exposure; manage removals, monitoring and investigations from one dashboard.
- Bulk operations through a single integration.
- Role-based access control and audit logging.

### Security, privacy and trust
- Encryption in transit and at rest, backups, MFA enforced, pen-tested, EU data residency.
- GDPR compliant; SOC 2 and ISO 27001 in progress; EU representative (Prighter).
- Data export and account deletion at any time; no AI training on user data; data never sold.
- Honours Global Privacy Control for cookies.

### Free resources (content/SEO)
- Data broker opt-out guides, general opt-out guides, data-breach list (13,000+), "what to do after a breach", scam alerts, glossary, privacy-law pages.

### Pricing (Oct 2026)
- Free $0 · Intelligence $12.99/mo · Protection $14.99/mo ($8.25/mo annual) · 30-day money-back guarantee.

## 3. What PrivacySearch implements

| Serus feature | PrivacySearch | Module |
| --- | --- | --- |
| Protected profile (names, emails, phones, addresses, usernames) | yes, encrypted at rest | `profiles.py`, `storage.py`, `crypto.py` |
| Data broker / people-search discovery | yes, pluggable broker registry and search provider | `brokers.py`, `data/brokers.json`, `providers/brokers.py` |
| Breach + paste lookup | yes, Have I Been Pwned (API key) | `providers/hibp.py` |
| Password breach check that never sends the password | yes, k-anonymity Pwned Passwords | `providers/hibp.py` |
| Risk-ranked exposure list | yes | `risk.py` |
| Coverage Score + exposure level | yes | `risk.py` |
| GDPR Art. 17 / CCPA / PIPEDA / UK GDPR removal letters | yes | `removal.py` |
| Autopilot removal queue, follow-up, re-filing on reappearance | yes | `removal.py`, `monitor.py` |
| Removal pipeline tracking | yes | `removal.py`, CLI `removals` |
| Continuous monitoring + diff alerts | yes (`monitor --interval`) | `monitor.py` |
| Alerts: console / webhook / email, plus daily digest | yes | `notify.py` |
| Deployed agents (watch keywords/domains) | yes, watchlists of keywords and domains | `monitor.py` |
| Typosquat / lookalike domain detection | yes | `intel.py` |
| Lookalike sender-domain check (reverse email) | yes | `intel.py` |
| Developer API with scoped keys, masking, audit-logged reveal, SSE streaming, rate limits, error envelope | yes, the Serus-compatible `/v1` shape | `api.py`, `apikeys.py` |
| Teams / bulk onboarding | yes, bulk JSON import + org-owned keys | CLI `profile import` |
| Export / delete everything | yes | CLI `profile export` / `profile delete` |
| Audit logging | yes | `storage.py` |

### Deliberately out of scope
- **Investigating third parties** (skip tracing, locating people, "find someone to serve papers",
  "understand who your kid is talking to", romance-scam person lookups). These are dual-use
  and invite stalking/doxxing abuse. PrivacySearch only scans identifiers that belong to a
  profile the operator registered as a protected person. Domain-level checks (typosquats,
  lookalike senders) are kept because they look at infrastructure, not individuals.
- Proprietary dark web crawling, forum or market scraping: replaced by reputable breach data (HIBP).
- Hosted billing/credits, LLM chat assistant, reputation sentiment, MCP server. These are possible future work; the
  API is designed so an MCP wrapper can sit on top of it.
