# Backend operations

Running the BlackShield API in production: deployment, monitoring, limits, database and backups.

## Deployment

`backend/docker-compose.prod.yml` runs:

| Service | Network | Purpose |
| --- | --- | --- |
| `nginx` | public, app | TLS termination, per-IP limits, security headers; the only published ports (80, 443) |
| `api` | app, data | FastAPI (uvicorn, one process; scale with more containers behind Nginx) |
| `db` | data | PostgreSQL 18 |
| `worker`, `domains-worker` (profile `workers`) | data, egress | Feed ingestion; run exactly one of each |
| `maintenance` | data | Daily `crashes-prune` (90-day crash report retention) |
| `backup` | data | Nightly `pg_dump` into the `backups` volume |

`app` and `data` are internal networks: the API and the database cannot reach the internet and cannot be reached
from it. Containers run read-only, with all capabilities dropped and `no-new-privileges`.

```bash
cd backend
cp .env.prod.example .env          # fill in every value; keep it out of git
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml --profile workers up -d
```

Before the first start:

1. Point DNS for the API host name at the server and get a certificate (for example certbot with the webroot
   `acme-webroot` volume or DNS validation). Set `TLS_CERT_DIR` and replace `api.example.com` in
   `deploy/nginx/conf.d/blackshield.conf`. Renew outside the container and run `docker compose exec nginx nginx -s reload`.
2. Create the app's API key: `docker compose run --rm api blackshield-signatures generate-api-key --id android-v1`.
   Put the printed `API_KEYS` entry in `.env` and the key itself in the release CI secrets
   (`BLACKSHIELD_API_KEY`).
3. Pin the certificate in the app: the SPKI SHA-256 of the current key **and** a backup key
   (`blackshield.certificatePins`, see [release.md](release.md)).

Upgrades: `docker compose -f docker-compose.prod.yml up -d --build api`. The API container runs `alembic upgrade head`
on start; migrations are additive, so the previous version keeps working during a rolling update. Take a backup first.

## Probes

| Endpoint | Meaning | Used by |
| --- | --- | --- |
| `GET /health` | Liveness: the process serves requests. Never touches the database. | Docker `HEALTHCHECK` in the image; external uptime checks |
| `GET /health/ready` | Readiness: PostgreSQL is reachable (503 otherwise). | Compose health check of `api`, so Nginx waits for it; load balancers |
| `GET /nginx-health` (port 80, localhost only) | Nginx is up | Compose health check of `nginx` |

## Metrics

`GET /metrics` on the API (Prometheus text format). Nginx never serves it publicly (`location /` returns 404);
scrape `api:8000/metrics` from a Prometheus on the internal network, optionally with `METRICS_TOKEN` as a bearer
token. `METRICS_ENABLED=false` turns it off.

| Metric | Type | Labels | Watch for |
| --- | --- | --- | --- |
| `blackshield_http_requests_total` | counter | route template, method, status | 5xx rate > 1 %; sudden drops (app releases broken) |
| `blackshield_http_request_duration_seconds` | histogram | route template, method | p95 of `/v1/signatures/delta` > 1 s |
| `blackshield_rate_limited_total` | counter | reason (`rate`, `auth`) | `rate` rising: limits too tight or scraping; `auth`: key stuffing |
| `blackshield_auth_failures_total` | counter | — | Spikes after a key rotation (old builds) or abuse |
| `blackshield_crash_reports_total` | counter | — | A jump after a release |
| `blackshield_published_version` | gauge | dataset (`signatures`, `domains`, `yara_rules`) | Not increasing for > 24 h: ingestion is stuck |
| `blackshield_active_signatures` | gauge | — | Large unexpected drops (bad feed, mass removal) |

Plus the client library's process metrics (CPU, memory, open file descriptors). Labels never contain keys, IPs,
hashes or raw paths: unmatched requests are counted under `route="unmatched"`.

Suggested alerts: `/health/ready` failing for 2 min; 5xx ratio > 5 % for 5 min; `published_version{dataset="signatures"}`
unchanged for 24 h while the worker runs; backup log line `backup FAILED`.

## Logs

JSON lines on stderr (`LOG_JSON=true`), one access line per request: request id, method, path (no query string),
status, duration, API key id. Never logged: client IP, headers, bodies, hashes. Nginx's access log has the same policy
(custom `privacy` format). Ship container logs with the host's log driver and keep them 30 days. `X-Request-ID` ties an
Nginx line to the API line.

## Rate limits

Two layers, both answering 429 (the API adds `Retry-After` and `RateLimit-*` headers):

| Layer | Key | Default | Why |
| --- | --- | --- | --- |
| Nginx `limit_req` | client IP | 20 r/s, burst 60; 50 connections | Cheap protection before Python runs |
| API token bucket | API key + client IP | 600/min, burst 120 | One key is shared by every install, so it is combined with the IP |
| API auth failures | client IP | 10/min | Slows key guessing |

Sizing: a phone syncs every 6 hours with 3–6 requests (version checks, then delta pages of up to 5,000 rows), plus
the rules and domain checks. Mobile carriers put thousands of phones behind one address (CGNAT), and a quarter of a
6-hour window's syncs landing in the same minute is unlikely but possible after an outage. 600/min per IP covers about
100 phones syncing in the same minute from one address; Nginx's 20 r/s (1,200/min) sits above it. Tune with
`blackshield_rate_limited_total{reason="rate"}`: it should stay near zero for real traffic. The API's buckets are
per process; with N API containers the effective limit is N times higher, which Nginx's limit still bounds.

## Database

### Indexes (reviewed for 1.0)

| Query | Index used |
| --- | --- |
| Reputation lookup `WHERE hash IN (...) AND NOT removed` | `pk_signatures` (hash) |
| Delta page `WHERE version > ? AND version <= ? [AND (version, hash) > cursor] ORDER BY version, hash LIMIT n` | `ix_signatures_version_hash`: a range scan in index order, no sort |
| Snapshot `WHERE NOT removed ORDER BY hash` | `pk_signatures`, read in order (streamed) |
| Domain delta and lookups | `ix_blocked_domains_version_domain`, `pk_blocked_domains` |
| Domains of one feed (`--replace` imports) `WHERE source = ?` | `ix_blocked_domains_source` |
| Latest version `ORDER BY version DESC LIMIT 1`, `max(version)` | primary keys of the `*_versions` tables |
| Crash prune `WHERE received_at < ?`, grouping by crash | `ix_crash_reports_received_at`, `ix_crash_reports_fingerprint` |

The only full scan is `count(*) WHERE NOT removed`, once per published version (about 0.1 s at 1M rows); a partial
index is not worth the write cost. Check plans after schema changes with `EXPLAIN (ANALYZE, BUFFERS)` on a copy of
production data. Tombstones (`removed = true`) are kept so deltas can delete rows on clients; they are a few percent of
rows and need no cleanup before tens of millions.

Run `VACUUM (ANALYZE)` after large imports (autovacuum handles normal operation).

### Backups

The `backup` service writes `pg_dump --format=custom` to the `backups` volume every 24 hours and keeps
`BACKUP_KEEP_DAYS` (14) days. A dump is written to `*.partial` and renamed when complete, so a file without the suffix
is always whole.

- **Off-site copy (required):** sync the volume to object storage with server-side encryption and versioning, for
  example nightly `rclone sync /var/lib/docker/volumes/blackshield_backups/_data remote:blackshield-backups`. A backup
  on the same disk as the database protects against mistakes, not against losing the server.
- **What is lost without backups:** signature and domain versions can be rebuilt from the feeds, but version numbers
  would restart, forcing every client into a full snapshot; the published YARA rulesets (signed offline) must be
  republished; crash reports are lost.
- **Point-in-time recovery:** for an RPO below 24 hours, add WAL archiving (`archive_mode=on` with `pgBackRest` or
  `wal-g` to object storage). Not needed for 1.0: the data is reproducible and changes hourly at most.

Restore (test it every quarter on a scratch host):

```bash
docker compose -f docker-compose.prod.yml stop api worker domains-worker maintenance
docker compose -f docker-compose.prod.yml exec -T db \
  pg_restore --clean --if-exists --no-owner -U "$POSTGRES_USER" -d "$POSTGRES_DB" < blackshield-20261114T000000Z.dump
docker compose -f docker-compose.prod.yml start api worker domains-worker maintenance
curl -fsS https://api.example.com/health/ready
```

Then check `blackshield_published_version` matches what the dump contained, and run one sync from a test phone.

## Dependency audit

`pip-audit` (in the `dev` extra) checks the backend's dependencies against the PyPA advisory database; CI runs it on
every change. Locally: `pip install -e '.[dev]' && pip-audit --local --skip-editable`. 1.0.0: no known
vulnerabilities (2026-11-14). The Android side is covered by Dependabot/Renovate on `gradle/libs.versions.toml`.

## Secrets

| Secret | Where |
| --- | --- |
| `POSTGRES_PASSWORD`, `API_KEYS` (hashes only), `MALWAREBAZAAR_API_KEY`, `PHISHTANK_APP_KEY`, `METRICS_TOKEN` | Host `.env` from the secrets manager |
| YARA rules signing key | Offline (release machine / HSM), never on the server ([architecture.md](architecture.md)) |
| TLS private key | Host certificate directory, readable by root only |
