# PrivacySearch

A self-hosted, open alternative to [Serus.ai](https://www.serus.ai)'s protection features. It finds where
your personal data is exposed (people-search sites, data brokers, breaches, pastes), files legal removal
requests on Autopilot, monitors continuously and alerts you, and exposes a Serus-style developer API.

See [docs/SERUS_FEATURE_REVIEW.md](docs/SERUS_FEATURE_REVIEW.md) for the full review of Serus features and
how each one maps to this project.

## Features

- **Protected profiles**: names and aliases, emails, phones, addresses, usernames, birth year and jurisdiction.
  All personal data is encrypted at rest (Fernet) with a key you control.
- **Footprint discovery**: a registry of 23 US/global brokers (`privacysearch brokers`). It checks each
  broker's public search page and scores the match on name, city, street, phone, age and email. Brokers that
  block bots, or have no public search, come back as manual checks. With `--assume-listed`, they get a
  proactive opt-out instead.
- **Breach and paste monitoring** through Have I Been Pwned, with remediation steps for each breach.
- **Password check** using k-anonymity: only 5 characters of the SHA-1 hash leave your machine.
- **Risk-ranked exposures** and a **Coverage Score** (0-100), which is the share of discovered risk that has
  been removed or remediated. Exposures also get a level from none to severe.
- **Removal engine**: data-minimised erasure letters under GDPR Art. 17, UK GDPR, CCPA/CPRA §1798.105,
  US state privacy laws, PIPEDA, the Australian Privacy Act and the NZ Privacy Act. Brokers that take opt-outs
  by email get them automatically over SMTP (Autopilot). Web-form brokers produce a task with step-by-step
  instructions.
- **Removal pipeline**: `queued → submitted → confirmed`, plus `action_required`, `failed` and `cancelled`.
  After each broker's expected processing time it re-checks the listing, files again up to 3 times, then
  alerts you to escalate. Data that reappears is detected and re-filed automatically.
- **Continuous monitoring** (`monitor`) with alerts to the console, a webhook and email, plus a daily digest.
- **Deployed agents (watches)**: get alerted when a lookalike of your domain goes live in DNS, or when a
  keyword such as your name appears on a page.
- **Infrastructure intel**: typosquat/lookalike domain generation, and a sender check that flags invoice and
  phishing senders imitating a domain you trust (homoglyphs, punycode, edit distance, TLD swaps).
- **Developer API**, shaped like Serus `/v1`: scoped `ak_` keys shown once and stored hashed, with expiry,
  rotation and revocation. Breach scans are masked by default; `?reveal=true` is audit-logged. Results can
  stream as SSE (`breach`/`paste`/`done`/`error`, 15 s heartbeat, 5 min cap). It also has per-second rate
  limits with `X-RateLimit-*` headers, a consistent error envelope, scan reuse within 24 h, and endpoints for
  bulk team onboarding and profiles.
- **Dashboard** at `/` when the API server is running.
- **Data rights**: export everything about a profile as JSON, or delete it along with all of its records.

## Install

```bash
pip install .            # Python 3.10+, depends only on `cryptography`
privacysearch init
```

## Quick start

```bash
export HIBP_API_KEY=...                       # https://haveibeenpwned.com/API/Key (breach monitoring)

PID=$(privacysearch profile add --label "Me" \
        --name "Jane Q Doe" --name "Jane Smith" \
        --email jane@example.com --phone "+1 512 555 0142" \
        --address "42 Elm Street;Austin;TX;78701;US" \
        --birth-year 1985 --jurisdiction US-CA)

privacysearch scan $PID --show-manual         # discover exposures
privacysearch exposures $PID -v               # ranked by risk, with remediation steps
privacysearch score $PID                      # Coverage Score
privacysearch removals -v                     # removal pipeline + web-form instructions
privacysearch removal letter <removal-id>     # read the legal request
privacysearch removal mark <removal-id> --status submitted
privacysearch monitor --interval 21600        # rescan, re-file and alert every 6 h
```

Other tools:

```bash
privacysearch password-check
privacysearch lookalikes mycompany.com --resolve
privacysearch check-sender billing@mycornpany.com --trusted mycompany.com
privacysearch watch add --kind lookalike_domain --value mycompany.com
privacysearch watch add --kind page_keyword --value "https://forum.example/thread Jane Doe"
privacysearch digest --hours 24
privacysearch profile export $PID -o me.json
privacysearch profile delete $PID --yes
```

Team onboarding: `privacysearch profile import team.json`, where the file holds a list of
`{"label", "full_names", "emails", "phones", "addresses", "usernames", "jurisdiction"}` objects. You can also
send the same list to `POST /v1/profiles`.

## API

```bash
privacysearch apikey create --name ci --scope account:read --scope darkweb:scan --scope profiles:read
privacysearch serve --port 8787
curl localhost:8787/v1/hello -H "Authorization: Bearer ak_..."
curl localhost:8787/v1/darkweb/scans -H "Authorization: Bearer ak_..." -H "Content-Type: application/json" \
     -d '{"identifierType":"email","identifierValue":"jane@example.com"}'
```

| Method | Path | Scope |
| --- | --- | --- |
| GET | `/v1/hello` | `account:read` |
| POST | `/v1/darkweb/scans` | `darkweb:scan` |
| GET | `/v1/darkweb/scans/{id}[?reveal=true]` | `darkweb:read` / `darkweb:scan` (own scans); reveal needs `darkweb:reveal` |
| POST | `/v1/darkweb/scans/stream` | `darkweb:scan` |
| GET / POST | `/v1/profiles` | `profiles:read` / `profiles:write` |
| GET | `/v1/profiles/{id}`, `/exposures`, `/removals` | `profiles:read` |
| POST | `/v1/profiles/{id}/scan` | `profiles:write` |

Supported scan identifier types: `email`, `password`, `domain`. Any other Serus type returns
`422 identifier_type_not_supported` until a provider for it is added. By default the API only scans emails
that belong to a protected profile. Pass `--allow-any-identifier` to lift that restriction.

## Configuration

| Variable | Purpose |
| --- | --- |
| `PRIVACYSEARCH_HOME` | data directory (default `~/.privacysearch`) |
| `PRIVACYSEARCH_KEY` | Fernet key; otherwise `secret.key` in the home directory is used (back it up) |
| `HIBP_API_KEY` | breach and paste lookups |
| `PRIVACYSEARCH_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_FROM` / `_STARTTLS` | Autopilot email removals and email alerts |
| `PRIVACYSEARCH_ALERT_EMAIL` | where alert emails go |
| `PRIVACYSEARCH_WEBHOOK_URL` | POST alerts as JSON |
| `PRIVACYSEARCH_ALERT_MIN_SEVERITY` | `low` / `medium` / `high` / `critical` |
| `PRIVACYSEARCH_ASSUME_LISTED=1` | file proactive opt-outs where a broker can't be checked |

Add or override brokers in `$PRIVACYSEARCH_HOME/brokers.json` (same format as
`privacysearch/data/brokers.json`). Broker URLs change often, and the bundled entries are marked
`verified: false`. Check them before relying on them.

## Scope and ethics

PrivacySearch is built to protect people from exposure, not to investigate them. It only scans identifiers
that belong to a registered protected profile. It deliberately leaves out the people-lookup side of Serus
Intelligence (locating individuals, skip tracing, profiling third parties). The domain and sender checks
stay in because they look at infrastructure, not people.

## Development

```bash
python3 -m unittest discover -s tests
```

The tests use a fake network, so they run offline.
