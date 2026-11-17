# Signature data model and sync protocol

How the backend stores malware signatures and how the app keeps its local copy current.
The OpenAPI document is [openapi.json](openapi.json) (served live at `/docs` and `/openapi.json`);
[`backend/examples/sync_client.py`](../backend/examples/sync_client.py) is a complete reference client.

## 1. Data model

### `signatures`

| Column | Type | Notes |
| --- | --- | --- |
| `hash` | `varchar(64)` PK | Lower-case hex digest. The primary-key index serves lookups and the snapshot's `ORDER BY`. |
| `algorithm` | `varchar(8)` | `md5`, `sha1` or `sha256` (check constraint). The length always matches the algorithm. |
| `family` | `varchar(128)` null | Malware family, e.g. `Hydra`. Control characters stripped, whitespace collapsed. |
| `source` | `varchar(64)` | Where the row came from: `malwarebazaar`, `local:<feed>`. Not sent to clients. |
| `severity` | `varchar(16)` | `low`, `medium`, `high` or `critical` (check constraint). |
| `first_seen` | `timestamptz` | Earliest sighting reported by any feed. |
| `version` | `bigint` | The signature version in which this row **last changed**: added, re-added or removed. |
| `removed` | `boolean` | Tombstone. Removed rows are kept so deltas can tell clients to delete them. |

Index `ix_signatures_version_hash (version, hash)` serves delta pages.

### `signature_versions`

| Column | Type | Notes |
| --- | --- | --- |
| `version` | `bigint` PK | 1, 2, 3, … with no gaps. 0 means "no signatures yet". |
| `created_at` | `timestamptz` | When the version was published. |
| `count` | `bigint` | Active (non-removed) signatures after this version. Clients can compare it with their local count. |

### Writes

Every import (MalwareBazaar run, local feed, `remove` command) is one database transaction:

1. Take the writer lock (`pg_advisory_xact_lock`). Writers queue, so versions commit in order and a reader can
   never see version N+1 while N is still uncommitted.
2. Allocate `version = max(version) + 1`.
3. For each incoming hash (normalized and deduplicated first):
   - new: insert with `version`;
   - tombstoned: re-activate, set `version`, keep the earliest `first_seen`;
   - already active: leave unchanged (the first source wins) and do not publish anything.
4. Removals of active hashes set `removed = true` and `version`. Removing an unknown hash does nothing.
   When one import both adds and removes the same hash, the last change in feed order wins.
5. If nothing changed, roll back: **no version is published for a no-op import**. Otherwise record the active
   count in `signature_versions` and commit.

Because each row stores only its latest state and the version of that state, `WHERE version > since` gives the
**net** change from any older version to now, however many versions the client skipped. A hash added in v3 and
removed in v5 appears once, as a removal, for any client at v2 to v4. For a client at v2 that removal deletes
nothing, which is harmless.

### Ingestion

| Command | What it does |
| --- | --- |
| `blackshield-signatures ingest-malwarebazaar` | One run: `get_file_type` for each `MALWAREBAZAAR_FILE_TYPES` (default `apk`) and `get_taginfo` for each `MALWAREBAZAAR_TAGS`. Tag results are filtered to those file types. Imports SHA-256 only, with severity `high`, family = MalwareBazaar `signature`. |
| `blackshield-signatures schedule` | The same every `INGEST_INTERVAL_SECONDS` (default 3600, ±10 % jitter). `docker compose --profile worker up` runs it as the `worker` service. |
| `blackshield-signatures import-feed FILE` | CSV (header row), JSON array or NDJSON. Fields: `hash` (required), `algorithm`, `family`, `severity`, `first_seen`, `action` (`add`/`remove`). CSV and NDJSON stream in constant memory. |
| `blackshield-signatures remove HASH…` | Retract false positives. Publishes a version with tombstones. |
| `blackshield-signatures status` | Latest version and count. |

Normalization (all sources): whitespace trimmed, lower-cased, hex only, and the length must be 32/40/64 for
md5/sha1/sha256. The algorithm is inferred from the length when absent. Invalid rows are counted and reported
with their line number, never imported.

MalwareBazaar requests carry the `Auth-Key` header (`MALWAREBAZAAR_API_KEY`, never logged) and are throttled
to one every `MALWAREBAZAAR_MIN_INTERVAL_SECONDS` (default 2 s). Transport errors, 429 and 5xx are retried up to
`MALWAREBAZAAR_MAX_RETRIES` times with exponential backoff and jitter, honoring `Retry-After`. Backoff is capped
at 120 s. A rejected key (401/403, `unknown_auth_key`) aborts the run immediately. A query that still fails is
skipped; the other queries' samples are imported, and the CLI exits with 2. `get_file_type` returns at most the
1,000 most recent samples, so the interval must be short enough that fewer arrive between runs (hourly is ample
for APKs today).

> MalwareBazaar's API is free under abuse.ch's fair-use terms; commercial use may require their paid
> subscription. Check the terms before shipping.

## 2. API

All `/v1` endpoints require an API key: `X-API-Key: <key>` or `Authorization: Bearer <key>`.

### `GET /v1/signatures/version`

```json
{"version": 42, "created_at": "2026-11-13T09:00:00Z", "count": 512345}
```

### `GET /v1/signatures/full`

The full set of active signatures as NDJSON (`application/x-ndjson`), gzip-encoded when the client sends
`Accept-Encoding: gzip`, streamed from a single REPEATABLE READ snapshot through a server-side cursor. Server
memory does not depend on the table size: a 500k-row snapshot peaks at about 2 MiB of Python heap in the tests.

```
{"type":"header","format":1,"version":42,"count":3,"created_at":"2026-11-13T09:00:00+00:00"}
{"hash":"0a1b…","algorithm":"sha256","family":"Hydra","severity":"high"}
{"hash":"0c2d…","algorithm":"sha256","family":null,"severity":"high"}
{"hash":"9f00…","algorithm":"md5","family":"Joker","severity":"critical"}
{"type":"end","version":42,"count":3}
```

- Lines between header and end are signatures, ordered by hash.
- **The `end` line is the integrity check.** If it is missing (connection dropped) or its `count` differs from
  the number of lines received, discard everything and retry. Never commit a partial snapshot.
- A write that commits during the download is not included; the next delta picks it up.

### `GET /v1/signatures/delta?since=<v>[&limit=<n>][&cursor=<c>]`

The net changes in versions `(since, until]`, gzip-compressed JSON:

```json
{
  "since": 40,
  "until": 42,
  "latest_version": 42,
  "additions": [{"hash": "…", "algorithm": "sha256", "family": "Hydra", "severity": "high", "version": 41}],
  "removals":  [{"hash": "…", "algorithm": "sha256", "version": 42}],
  "next_cursor": "eyJzIjo0MCwidSI6NDIsInYiOjQxLCJoIjoiMGExYiJ9"
}
```

- `limit` defaults to 5,000 and is capped at 20,000 (`DELTA_DEFAULT_LIMIT`, `DELTA_MAX_LIMIT`). A page holds at
  most `limit` additions and removals combined.
- **Pagination.** The first request fixes `until` to the latest version. Pass `next_cursor` back as `cursor`,
  with the same `since`, until `next_cursor` is `null`. Pages are keyset scans over `(version, hash)`: no
  offsets, and no row is returned twice. The cursor is opaque. A malformed cursor, or one issued for a
  different `since`, gets 400.
- **Every hash appears at most once** across all pages, so additions and removals can be applied in any
  order. Additions are upserts.
- **409 `version_ahead`**: `since` (or a cursor's `until`) is newer than the server's latest version, e.g. the
  server database was rebuilt. Do a full sync.

### `POST /v1/reputation/lookup`

```json
{"hashes": ["<sha256>", "..."]}
```

At most 100 SHA-256 digests (any case). No other fields are accepted, so file contents cannot be sent.
Duplicates are folded. Results come back in request order:

```json
{"version": 42, "results": [
  {"hash": "…", "verdict": "malicious", "family": "Hydra", "severity": "high"},
  {"hash": "…", "verdict": "unknown", "family": null, "severity": null}
]}
```

`unknown` means "not a known signature", not "safe". Submitted hashes are neither stored nor logged.

## 3. Client algorithm

```
remote = GET /v1/signatures/version
if remote.version == local.version:            done
if local.version == 0:                          full sync
else:
    BEGIN local transaction
    cursor = null
    loop:
        page = GET /v1/signatures/delta?since=local.version[&cursor=cursor]
        upsert page.additions; delete page.removals
        cursor = page.next_cursor
        until cursor == null
    local.version = page.until
    COMMIT
    on HTTP 409: ROLLBACK, full sync

full sync:
    BEGIN; DELETE local signatures
    stream GET /v1/signatures/full, insert in batches
    if the end line is missing or its count differs: ROLLBACK, retry later
    local.version = header.version; COMMIT
```

Rules:

- **Store `until` only after the last page.** It is the version the whole delta brings the client to. If a
  sync is interrupted, roll back and restart from the old version; re-applying pages is idempotent anyway.
- **Concurrent publishes are safe.** A version published while the client is paging is not part of this sync,
  because `until` was fixed on the first page. If it modifies a hash the client has not reached yet, that hash
  moves past `until` and is skipped now. The next sync (`since = until`) delivers its newest state. The client
  converges one sync later and never ends up with a wrong final state.
- **When to use a full sync:** first install, local version 0, HTTP 409, or a corrupt local store. A delta from
  version 0 works but also carries every tombstone ever written.
- **Polling:** check `/version` every few hours (WorkManager, unmetered network). Back off on 429 using
  `Retry-After`.
- Severity and algorithm are lower-case in the API. The app's `Severity` and `SignatureAlgorithm` enums map
  them by name (`high` → `HIGH`, `sha256` → `SHA256`). `family` may be null.

## 4. Security

| Control | Implementation |
| --- | --- |
| Authentication | API keys (`bs_` + 256 random bits). The server stores only `key_id:sha256(key)` in `API_KEYS`, comma-separated for rotation. No keys configured means every `/v1` request is refused. `blackshield-signatures generate-api-key --id android-v1` prints a key and its entry. |
| Rate limiting | Token bucket per (key id, client IP): `RATE_LIMIT_PER_MINUTE` (120) sustained, `RATE_LIMIT_BURST` (30). Failed authentications: `AUTH_FAILURE_LIMIT_PER_MINUTE` (10) per IP. 429 carries `Retry-After`. Limits are in-process: with several replicas, enforce them at the gateway too. |
| Request size | `MAX_REQUEST_BODY_BYTES` (16 KiB) by `Content-Length` and while streaming chunked bodies → 413. |
| Input validation | Pydantic models with `extra="forbid"`, hex/length checks, bounded query parameters and cursor length. |
| CORS | Off unless `CORS_ALLOWED_ORIGINS` lists origins; then only those, GET/POST, no credentials. Entries must be explicit `scheme://host[:port]` origins: `*`, wildcards and paths fail at startup. |
| Logging | JSON lines: method, path without query string, status, duration, request id, key id. Never logged: keys, bodies, submitted hashes, client IPs. Uvicorn's access log is disabled for the same reason. |
| Headers | `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `X-Request-ID`. |

An API key compiled into the app can be extracted, so it identifies the app build, not a user. It is there for
rate limiting, key rotation and blocking abusive builds. Per-install signed tokens (e.g. after a Play Integrity
check) would be the next step if per-device identity is needed.

## 5. Operations

- Tombstones are never deleted. They cost one row per removed signature. If they ever matter, add a compaction
  floor: delete tombstones older than version F and answer `since < F` with 409 (full sync).
- Tests run on SQLite by default and on PostgreSQL when `TEST_DATABASE_URL` is set (CI does both). The writer
  lock, server-side cursor and snapshot isolation are verified only on PostgreSQL.
