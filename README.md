# Cyber Intelligence Platform

A unified cybersecurity intelligence platform for small and medium businesses. The product is designed as one analyst workspace backed by specialized, independently developed security capabilities and shared identity, findings, investigations, audit, and reporting contracts.

> **Status:** Local prototype. All ten capability workspaces are present. Email, unidirectional IP traffic, and Bitcoin have bounded offline analyzer workflows; the other seven profiles below accept analyst-supplied files and run limited local checks or calculations. These profiles are not production detectors, do not connect to live telemetry or paid APIs, and do not perform automated response. The API's local authentication examples are not production authentication or authorization.

## Stack

- API: Python 3.12, FastAPI, Pydantic Settings, pytest, Ruff, mypy
- Web: Node.js 22, React, TypeScript, Vite, Vitest, Testing Library, ESLint
- CI: GitHub Actions

## Prerequisites

- Python 3.12 (3.12.x recommended for CI parity)
- `uv` (Python dependency manager)
- Node.js 22 and npm
- Git

## Quick start

Clone the repository and enter its root directory. Copy the example configuration only if you need to override defaults. The API currently reads the root `.env` when launched from `services/api`, as shown below:

```bash
cp .env.example .env
```

Do not put production credentials or customer data in `.env`; it is ignored by Git.

### API

```bash
cd services/api
uv sync --locked --all-groups
uv run --locked uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Verify the API:

```bash
curl --fail http://127.0.0.1:8000/health/live
```

Expected response:

```json
{"status":"ok"}
```

Interactive API docs are available at `http://127.0.0.1:8000/docs` in development only.

Run API checks from `services/api`:

```bash
uv run --locked ruff check app tests
uv run --locked ruff format --check app tests
uv run --locked mypy app
uv run --locked pytest --cov=app --cov-report=term-missing --cov-fail-under=80
```

### Web

In a second terminal, from the repository root:

```bash
cd apps/web
npm ci
npm run dev
```

Open `http://127.0.0.1:5173`.

Run frontend checks from `apps/web`:

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

## Generate and commit lockfiles (first setup)

Lockfiles must be generated and committed before the first CI run. In this build environment, package registry access was unavailable, so the lockfiles could not be resolved here. On a network-enabled machine with `uv`, Python 3.12, Node.js 22, and npm installed, run:

```bash
cd services/api
uv lock
uv sync --locked --all-groups
cd ../../apps/web
npm install
npm ci
cd ../..
```

Commit `services/api/uv.lock` and `apps/web/package-lock.json`. Then run `scripts/verify.sh`. CI intentionally uses locked installation and should not be weakened to generate lockfiles automatically.

## Dependency updates

- Python: update `services/api/pyproject.toml`, then run `uv lock` and review `services/api/uv.lock`.
- Web: update `apps/web/package.json`, then run `npm install` and review `apps/web/package-lock.json`.
- Run all local checks before committing dependency changes.
- Prefer small, reviewed updates. Do not install unreviewed packages directly in CI.

## Repository map

```text
apps/web/                  React + TypeScript frontend
services/api/              FastAPI application and tests
services/api/uv.lock       Locked Python dependency graph
.github/workflows/ci.yml   Pull-request and push checks
docs/architecture/         Architecture decision records
```

## Security baseline

- Never commit `.env`, credentials, API tokens, certificates, or real customer data.
- Development servers bind to localhost by default.
- CORS uses an explicit local origin; it is not an authentication or authorization mechanism.
- Health responses must not disclose configuration or secrets.
- Treat uploaded files, email content, URLs, and imported traffic records as untrusted input.
- Before processing real customer data, implement authentication, server-side authorization, tenant isolation, safe file handling, audit events, retention policies, backups, and a security review.
- Do not enable automated blocking or other destructive response actions without explicit authorization, approval, and auditability.
- Keep detections explainable and distinguish severity, confidence, and business impact.
- Treat voice, identity-document, financial-transaction, and video analytics as sensitive domains requiring explicit authorization, data minimization, retention limits, and human review. Never treat an automated indicator as proof of identity or wrongdoing.

## CI

GitHub Actions checks the Python API and web application independently. Python dependencies are installed with `uv sync --locked`; frontend dependencies use `npm ci`. CI runs linting, type checks, tests, coverage, and a production frontend build.

## Local infrastructure (CIP-002)

The repository now includes a local PostgreSQL and API container setup for the next sprint.

Start the environment from the repository root:

```bash
cp .env.example .env

docker compose up --build
```

Verify the API:

```bash
curl --fail http://127.0.0.1:8000/health/live
```

Stop and reset the environment:

```bash
docker compose down -v
```

The API container uses the same local loopback binding and explicit environment configuration pattern as the web app. PostgreSQL credentials are supplied via environment variables and never hardcoded in the source tree.

## Findings API foundation

The API now provides authenticated, tenant-scoped finding creation, listing, and detail retrieval. All queries derive the tenant from the bearer token and verify that the token subject is an existing user in that tenant. The API does not accept a client-selected tenant ID for findings. Finding records keep severity, confidence, and business impact separate, and new findings emit an audit event.

After PostgreSQL is available, apply migrations from `services/api`:

```bash
uv run --locked alembic upgrade head
```

Local HMAC JWT verification and the token helper used in tests are limited to `APP_ENV=development`; there is no public token-issuance endpoint. Outside development, the API verifies RS256 OIDC access tokens against the configured HTTPS JWKS endpoint, enforcing exact issuer and audience claims. Each external `(issuer, subject)` must be explicitly mapped to an existing tenant member; authorization roles are read only from the database. Unmapped identities are denied. This is an API resource-server integration, not a hosted login flow; configure the identity provider and provision member mappings before deployment.

Set `OIDC_ISSUER`, `OIDC_AUDIENCE`, and `OIDC_JWKS_URL` in the deployment environment (never commit real settings or credentials). Apply the identity-mapping migration with `uv run --locked alembic upgrade head`. Provision each allowed account with the provider's exact issuer and immutable subject in `users.identity_issuer` and `users.identity_subject`, then assign its tenant and role through the managed database/admin process. Do not use email as the OIDC identity key.

## Incident workflow API

Authenticated tenant members can create, list, and retrieve incidents, attach findings from the same tenant, and request controlled status transitions:

- `POST /incidents`, `GET /incidents`, and `GET /incidents/{incident_id}`
- `POST /incidents/{incident_id}/findings` to link an existing finding
- `PATCH /incidents/{incident_id}/status` with a `status` field

Allowed transitions are `new -> investigating`, `investigating -> contained|resolved`, `contained -> investigating|resolved`, and `resolved -> investigating|closed`. Closed incidents are terminal. Invalid transitions return `409 Conflict`, and create, link, and status-change actions create tenant-scoped audit events.

The API returns `404` when an incident or finding is unavailable in the caller's tenant, including cross-tenant link attempts, so resource existence is not disclosed. Finding links are unique per incident. Incident endpoints use the same development-only authentication as the findings API; they are not suitable for protecting customer data.

## Shared findings workspace

The web app uses separate hash-routed pages rather than placing every workflow on the overview. The sidebar separates the overview and capability library, individual analysis workspaces, connector readiness, and shared findings/incident operations. Each workspace can be opened directly at `/#/<workspace>` and browser back/forward navigation is supported. On narrow screens, navigation becomes a horizontally scrollable bar. The Integrations page lists the current state and prerequisites for production data sources; it is a readiness checklist, not a connector manager, and accurately reports that no live integrations are connected.

The web app's **Findings** section calls the authenticated `GET /findings?limit=100` endpoint and displays the latest tenant-scoped records from all active analyzers. It is read-only, caps the response at 100 findings, and keeps the bearer token in component memory only until the request completes. Finding evidence is collapsed by default and shown only when explicitly expanded. Use the local development token only with synthetic demo data.

The **Incidents** section loads up to 100 tenant incidents and findings, creates incidents with optional linked findings, links further same-tenant findings, and exposes only API-supported status transitions. The token remains in component memory to support multiple analyst actions and can be cleared explicitly; it is never written to browser storage. Create/link/status actions emit the backend's tenant-scoped audit events. This prototype does not assign incident owners or expose incident editing/deletion.

## Email analysis API (CIP-006 foundation)

`POST /email/analyze` accepts raw RFC 5322 message bytes (for example, an `.eml` file sent as the request body). The endpoint authenticates the tenant member, streams at most 1 MiB into memory, ignores attachment content, and never executes files or fetches URLs. It reports sender-related domains, up to 100 deduplicated URL scheme/host pairs (with `urls_truncated` when more exist), and parsed authentication-result claims. URL paths, query strings, message body, and full addresses are not returned or stored.

The versioned offline rules identify reported SPF/DKIM/DMARC failures, From/Reply-To domain mismatches, and IP-literal links. `Authentication-Results` is user-supplied and explicitly treated as an unverified claim; the rules produce suspicious indicators, not confirmation of malicious activity. Suspicious analysis creates a tenant-scoped finding and audit events; clean analysis creates only an `email.analyzed` audit event. Neither path stores raw message content.

Local example:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @sample.eml \
  http://127.0.0.1:8000/email/analyze
```

### Run the no-paid-API synthetic demo

This uses only the local rule-based analyzer, local PostgreSQL, and synthetic fixtures. It does not call an external analysis service.

From the repository root, after Docker is available:

```bash
cp .env.example .env
docker compose up -d --build
cd services/api
uv sync --locked --all-groups
uv run --locked alembic upgrade head
uv run --locked python -m app.dev_demo
```

The last command seeds only a clearly named synthetic tenant and analyst, then prints a short-lived development token. This helper refuses to run unless `APP_ENV=development`; it is not a login mechanism and must never be used for production. Copy the printed token into the workspace’s **API access token** field (this is a local development token, not an OIDC token), choose a synthetic `.eml` or the `services/api/tests/fixtures/traffic/synthetic_port_scan.csv` sample in its corresponding analysis panel, and submit it. Open `http://127.0.0.1:5173` after starting the web app in another terminal:

```bash
cd apps/web
npm ci
npm run dev
```

The synthetic samples use reserved `.test` domains and documentation-only IP ranges. Do not replace them with real email for demonstrations.

The analyst workspace upload/results flow posts the selected `.eml` bytes and bearer token directly to the API. The token is held only in component memory and cleared after the request; it is not stored in browser storage. Configure `VITE_API_BASE_URL` at web build time to use a different API URL. Production requires configured OIDC and issuer/subject membership mappings. Avoid sending real customer messages until privacy/retention review and security review are complete.

## Unidirectional IP traffic analysis (CIP-004 foundation)

`POST /traffic/analyze` accepts a UTF-8 CSV of one-way flow records. Required headers are `source_ip,destination_ip,destination_port,protocol,bytes,packets`; each row is one direction, not a bidirectional connection. Uploads are limited to 1 MiB and 10,000 rows. The offline `unidirectional-ip-rules-v1` rules report a source contacting at least 20 distinct destination ports for one protocol, or at least 50 distinct destination IPs. These thresholds are heuristic review signals, not attack confirmation. Findings retain aggregate counts and source IP evidence, never the uploaded rows; each analysis emits an audit event.

The web workspace includes a CSV upload panel. A small synthetic fixture is available at `services/api/tests/fixtures/traffic/synthetic_port_scan.csv`; it uses documentation-only address ranges. Use only traffic data you are authorized to analyze. This initial capability does not ingest live telemetry, establish baselines, forecast attacks, or apply automated response.

## Bitcoin transaction analysis (CIP-005 foundation)

`POST /bitcoin/analyze` accepts a UTF-8 CSV with one sender-to-recipient transfer edge per row and required headers `transaction_id,sender_address,recipient_address,amount_btc`. Amounts must be positive BTC values with up to eight decimal places. Uploads are limited to 1 MiB and 10,000 rows. The offline `bitcoin-transfer-rules-v1` rules flag sender fan-out and recipient fan-in of at least ten distinct counterparties, and transfer amounts exceeding five times the sample median when at least five records exist.

These are contextual heuristics, not address attribution, sanctions screening, money-laundering detection, or proof of wrongdoing. Transfer CSVs are supplied by the analyst; this does not connect to a blockchain node or provide live monitoring. Raw addresses and transaction IDs are used only in request memory to calculate distinct-counterparty counts; findings retain aggregate counts and amounts, never addresses, fingerprints, or transaction IDs. Analysis audit events retain the ruleset version, row count, and upload size. A synthetic placeholder fixture is available at `services/api/tests/fixtures/bitcoin/synthetic_transfers.csv`. Use only data you are authorized to analyze.

## Additional local capability profiles

The seven additional workspaces use authenticated `POST /capabilities/{capability_id}/analyze` requests. Uploads are streamed with a 1 MiB cap; CSV profiles are limited to 10,000 rows. The analyzers run locally without external services, save findings for review, and emit tenant-scoped audit events. Only bounded summaries and indicator evidence are persisted, not uploaded files. Use synthetic or otherwise authorized data.

- **Voice (`voice`)**: uncompressed mono/stereo 8-bit or 16-bit PCM WAV, 8–96 kHz, up to 120 seconds. Reports audio format, signal level, silence, and clipping only. It does not detect voice cloning, impersonation, or speaker identity.
- **Cyber risk & investment (`risk`)**: CSV columns `asset,asset_value_usd,annual_event_probability,impact_fraction,control,annual_control_cost_usd,risk_reduction_fraction`. Ranks control scenarios using expected annual loss, avoided loss, net benefit, and ROI where cost permits. Rows for one asset must agree on the underlying annual loss assumptions. Add optional `budget_usd` to the analysis request to select a portfolio maximizing modeled annual loss avoided with a bounded 0/1 knapsack optimizer (up to 100 options, with costs rounded upward to $10 increments). The portfolio assumes modeled control reductions are additive and independent. This is not an actuarial forecast or a recommendation to accept residual risk.
- **Network trend (`forecasting`)**: CSV columns `timestamp,event_count`, with at least eight strictly increasing timestamps and non-negative event counts. Produces a one-step linear event-count projection from supplied observations; it does not predict attacks or use live telemetry.
- **Cisco IOS baseline (`compliance`)**: supplied text configuration; checks AAA, enable secret, SSH-only VTY transport, VTY timeout, remote logging/timestamps, and default SNMP communities. It is a small configuration checklist, not complete compliance coverage or certification.
- **Document structure (`identity`)**: PDF, PNG, or JPEG structural markers and a short list of PDF active-content/revision indicators. There is no OCR, identity verification, face analysis, or reliable counterfeit detection.
- **CCTV event export (`video`)**: CSV columns `timestamp,camera_id,event_type,confidence`; summarizes supplied metadata and flags low reported confidence or events outside 06:00–22:00 local time. It does not process video streams or frames, identify people, or enforce actions.
- **strongSwan IPsec (`ipsec`)**: supplied `ipsec.conf` text; checks IKEv2, explicit IKE/ESP proposals, known weak algorithms, and inline pre-shared-secret patterns. It does not cover all syntax, assess live negotiation, or probe VPN endpoints.

The generic web panel accepts one file and a development/API access token per workspace, displays explicit API validation errors, and clears the token after a completed request. Risk analysis also accepts an optional planning budget. Results link to shared tenant findings; input files and raw configuration/audio/document contents are not saved by these analyzers. Sensitive data should not be uploaded until authorization, privacy, retention, and security reviews are complete.

## Current limitations

- The seven additional capability profiles are intentionally limited local MVPs, not general-purpose detection. In particular, there is no voice-cloning detector, document authenticity verifier, direct CCTV video analytics, attack predictor, complete vendor compliance audit, or live IPsec assessment.
- Findings and incidents have tenant-scoped APIs with audit events; incident status changes and finding associations are covered by the shared workflow API.
- The shared findings section is a read-only latest-100 view; finding status management and pagination are not yet available in the web UI. Incident owners, editing, deletion, and pagination are also unavailable in the web UI.
- Findings, incidents, and `/auth/me` require persisted membership; business API access allows persisted `analyst` and `admin` roles, and admin-only checks use the database role rather than a token claim. There is no membership/role administration API yet.
- OIDC integration validates API access tokens but does not implement interactive login, account provisioning, refresh tokens, or logout. The UI therefore requires a provider-issued API access token to be pasted for the request; those responsibilities remain with the selected identity provider and a future controlled membership administration workflow.
- The local synthetic demo bootstrap is for development workflow testing only; the dashboard is not a production-authenticated application.
- Email analysis is a small heuristic foundation, not an evaluated production detector; messages and `Authentication-Results` headers can be forged, and the rules can produce false positives or miss threats.
- Unidirectional IP traffic analysis is an initial heuristic foundation; authorized network discovery can trigger its thresholds, and it does not establish attack intent or forecast future activity.
- Bitcoin transaction analysis is an initial CSV-based heuristic foundation; it does not resolve address ownership, identify people, screen against external intelligence, or monitor a live chain.
- Docker Compose runtime validation has not been completed in environments without Docker.
- No production authentication provider, detection evaluation datasets, operational alerting, or customer-data retention controls have been configured.

## Product capability scope

The long-term product is one platform containing these ten integrated capabilities:

1. Voice-cloning impersonation detection.
2. Cyber risk quantification and investment prioritization.
3. Email threat detection, geolocation, and forensic intelligence.
4. Unidirectional IP traffic threat detection.
5. Bitcoin transaction traffic monitoring.
6. Network attack forecasting from network traffic data.
7. Multi-vendor network security compliance auditing.
8. Fake identity and document screening.
9. Authorized CCTV video analytics.
10. IPsec VPN protocol analysis and security assessment.

Each module will emit versioned, evidence-backed findings into common workflows. Capabilities involving people, finances, or surveillance require explicit authorization, privacy protections, careful evaluation, and human review. Detection will precede any separately authorized response automation.
