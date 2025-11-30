# RPC Interface Contracts

## API Versioning and Compatibility

RPP node and wallet RPC endpoints follow a semantic versioning policy that
mirrors the workspace release tags (`MAJOR.MINOR.PATCH`). Each RPC handler is
considered stable once it first ships in a minor release. Subsequent patch
releases may extend responses with new optional fields but never remove existing
keys, change value semantics, or reorder enumerations. Breaking a serialized
contract—such as removing a field or altering its type—requires a new major
version of the workspace and an explicit migration note.

We guarantee that clients compiled against a given `MAJOR.MINOR` release can
communicate with any server running the same `MAJOR` version for at least two
minor releases. For example, applications built against `1.8.x` continue to work
with servers up to and including `1.10.y`. After that window the API is still
expected to function, but previously deprecated fields may be removed in the
next minor bump.

## Deprecation Timeline

Every deprecation is announced one minor release in advance. The release notes
call out the affected field or endpoint, the intended removal version, and any
recommended migration steps. During the deprecation window the server continues
to populate the legacy payloads while emitting structured warnings via metrics
and logs so operators can monitor usage. Once the grace period expires (minimum
of two minor releases) the endpoint is either removed or the field becomes a no-
op entry, depending on the migration plan. Breaking removals only ship alongside
minor version bumps within the same major series.

### Enforced deprecation windows

The RPC contract tests enforce the deprecation window so that removals never land
accidentally. When deprecating a field, add an entry to
`tests/rpc/deprecated_fields.toml` with the schema name, dotted property path,
the first workspace version that permits removal, and the expiry date of the
grace period. CI runs `deprecated_fields_require_version_bump_or_expiry` to
verify three rules:

1. Deprecated fields must stay in the JSON Schema until either the configured
   removal version ships or the expiry date is reached.
2. Allowlist entries with past-due expiry dates fail the build, prompting
   contributors to remove the field (and the allowlist entry) or extend the
   window with a new date.
3. Schema removals before the allowed version cause a failure unless the
   deprecation window has expired.

Document the new allowlist entry in release notes so client teams can plan the
migration and keep the `rationale` string up to date for reviewers.

## Semantic Version Mapping

* **Patch release (`MAJOR.MINOR.PATCH`)** – bug fixes only. Payload shapes and
  field semantics do not change.
* **Minor release (`MAJOR.MINOR`)** – may introduce new endpoints or add optional
  response fields. Deprecated fields announced previously may be dropped.
* **Major release (`MAJOR`)** – reserved for protocol overhauls that require
  coordinated client updates. All incompatible schema changes are bundled here.

Contract tests in `tests/rpc/` validate that representative request and response
examples remain compatible with the published JSON Schemas. CI executes these
checks on every PR so any incompatible change is caught before landing.

## Schema snapshots and update workflow

OpenAPI/JSON Schema snapshots live in `docs/interfaces/snapshots` and are
generated from the curated contracts in this directory. Run
`python scripts/generate_api_schemas.py` after touching any
`docs/interfaces/rpc/*.jsonschema` file or adding a new contract; commit the
refreshed snapshots alongside your change. The job `api-schema-guard` exercises
`python scripts/generate_api_schemas.py --check` in CI and fails when the
committed snapshots fall behind the source schemas.

Incompatible payload changes must also bump `docs/interfaces/schema_versions.toml`.
Use the `node` version when altering operator/node-facing endpoints and the
`wallet` version for wallet JSON-RPC contracts. Regenerate the snapshots after
the bump so the new version is captured in the generated metadata. CI will
refuse schema diffs that are missing a corresponding version increment to keep
breaking changes auditable.

## Rate Limiting Semantics

The public RPC is protected by per-IP token buckets split into **read**
(`GET`/`HEAD`) and **write** (mutating) classes. Configure independent bursts
and replenish rates via `[network.limits.per_ip_token_bucket.read]` and
`[network.limits.per_ip_token_bucket.write]` in the node configuration; legacy
single-bucket configs map to both classes automatically.【F:config/node.toml†L37-L55】【F:rpp/runtime/config.rs†L1767-L1909】
When a request depletes the relevant bucket and is throttled, the server
responds with `429 Too Many Requests` and the following headers:

* `X-RateLimit-Limit` – Maximum tokens in the bucket (the burst size).
* `X-RateLimit-Remaining` – Tokens still available for the current bucket.
* `X-RateLimit-Reset` – Seconds until a token is replenished and the bucket is
  usable again.
* `X-RateLimit-Class` – The request class (`read` or `write`) that triggered the
  throttle.

The response body spells out the class as well (for example, `write rate limit
exceeded`). Clients should treat a `429` as a temporary condition. Retry only
after waiting for at least the advertised reset window and prefer exponential
backoff to avoid immediate re-throttling.

SDK-oriented helpers that parse the headers and clamp backoff are documented in
[`rpp/chain-cli/SDK.md`](../../../rpp/chain-cli/SDK.md); the code samples are
doctested so they stay aligned with the server’s token-bucket semantics.

## Subscription-Recovery

Event-stream clients must treat long-lived connections as lossy and implement
replay-friendly recovery. RPC servers expose consistent signals across SSE and
WebSocket transports so wallet pipelines, indexers, and monitoring agents react
the same way regardless of transport.

### Heartbeats and disconnect expectations

* **SSE** – Idle connections emit comment heartbeats every 15 s (`:\n` or
  `: <ts>`). Missing two consecutive heartbeats indicates either gateway
  buffering or a dead connection; clients should reconnect with backoff and
  resume using the last seen cursor/token.
* **WebSocket** – Servers send `ping` frames at the same 15 s cadence and expect
  a `pong` reply within 10 s. Two missed pings will be logged and the server may
  close the socket with `1008` (policy violation) or `1002` (protocol error).
  Clients should pro-actively reconnect after a single missed ping to avoid
  being culled by intermediaries.

### Error codes and reorg indicators

* **`410 Gone` (`sse.reorg`)** – Emitted on SSE streams when the advertised
  cursor falls outside the retained window because of pruning or a deep reorg.
  The response body includes the latest stable cursor; clients must restart from
  that cursor and reapply idempotent handlers.
* **`409 Conflict` (`stream.reorg_in_progress`)** – WebSocket servers send this
  close frame when a reorg rewinds past the active subscription. Clients should
  reconnect after a short backoff and request history from the provided
  `rollback_to` height in the close reason payload.
* **`429` with `X-RateLimit-*` headers** – Treat as transient congestion; wait
  for the `Reset` window then retry with exponential backoff. The stream should
  reuse the previous cursor/token.

### Reconnect and backoff guidance

* Use **exponential backoff with jitter** for both SSE and WebSocket reconnects
  (for example, `1s, 2s, 4s, capped at 30s`), resetting the backoff after five
  minutes of stability.
* **Replay on reconnect** by sending the last durable cursor (SSE `Last-Event-ID`
  or WebSocket subscribe request payload). If the server replies with a reorg
  hint, restart from the provided checkpoint rather than the stale cursor.
* **Surface churn** – After three reconnects in five minutes, emit a user-facing
  banner and write structured logs so operators can correlate with uptime
  probes. The probes treat reconnect+resume as healthy; loops that restart
  without progressing the cursor are considered degraded.
* **Operator restarts** – Node processes may restart during backends switchover
  or rollouts. Wallet and indexer SDKs should treat `ECONNRESET`, `ECONNREFUSED`,
  and HTTP `503` responses as transient for up to five minutes while the leader
  elections settle. Clients must continue replaying from the last durable cursor
  or cached response instead of rebuilding history from scratch.

### Detecting prunes and replay gaps

Reorg-aware streams include a `pruned=true` or `rollback_height=<n>` metadata
field when emitting rollbacks. Clients should persist the highest finalized
height processed and compare it to these signals to trigger a rescan. Wallet
pipelines must re-request historical batches if a gap larger than their in-memory
buffer is detected, preferring bounded range queries over full history to reduce
load after pruning.

### Wallet history pagination and rate limits

Wallet history endpoints (`/wallet/history` and the `history.page` JSON-RPC
shim used by the GUI) expose cursor tokens to page through cached entries. The
server stamps each page with `page_token`, `next_page_token`, and
`prev_page_token` values that can be echoed back to resume pagination even if a
previous call was throttled. Rate-limited responses still include the retry
headers above; once the `429` window elapses, clients should reuse the prior
token rather than restarting from the beginning. Backends (for example,
`rpp-stark` vs `plonky3`) and reorg-aware filters may adjust which entries are
returned, but stale tokens remain valid and simply yield an empty page if the
underlying history was truncated.

## Snapshot and state sync RPC errors

Snapshot operations expose structured error payloads. When a request fails the
response body always includes an `error` string and may also carry a
machine-readable `code` to simplify automation and runbook lookups. The
snapshot-related codes and their typical triggers are:

| Code | HTTP status | Typical message | Description |
| --- | --- | --- | --- |
| `state_sync_plan_invalid` | `400`/`404` | `chunk index <N> out of range (total <T>)`, `chunk <N> missing`, `invalid manifest` | The published snapshot plan or manifest does not match the requested chunk window. |
| `state_sync_metadata_mismatch` | `500` | `snapshot root mismatch: expected <expected>, found <actual>` | The local snapshot metadata (root or receipts) diverges from the advertised plan. |
| `state_sync_proof_encoding_invalid` | `503` | `failed to decode proof chunk` | Snapshot verification failed because the proof stream could not be decoded. |
| `state_sync_verification_incomplete` | `503` | `state sync verification failed` | The verifier stopped before producing a complete proof. |
| `state_sync_verifier_io` | `500` | `disk unavailable`, `ProofError::IO(...)` | I/O errors while reading snapshot chunks or verification inputs. |
| `state_sync_pipeline_error` | `500` | `snapshot store error: ...` | Internal orchestration errors while serving or verifying snapshot chunks. |
| `state_sync_pruner_state_error` | `500` | `pruner state unavailable` | Snapshot verification failed because pruning metadata was missing or inconsistent. |

The `/p2p/snapshots*` and `/state-sync/*` handlers surface these codes so
operators can map RPC responses directly to the remediation steps in the
troubleshooting guide.

### Consensus RPC errors

Consensus endpoints expose structured error payloads when finality or proof
verification fails. The `/consensus/proof/status` handler sets a `code` field in
addition to the human-readable `error` string:

| Code | HTTP status | Typical message | Description |
| --- | --- | --- | --- |
| `consensus_verifier_failed` | `503` | `invalid VRF proof`, `consensus certificate contains non-prevote in prevote set` | Consensus proof or binding verification failed. The runtime increments `rpp.runtime.consensus.rpc.failures{reason="verifier_failed"}` for observability. |
| `consensus_finality_unavailable` | `503` | `no consensus certificate recorded` | No finalized consensus certificate is currently available. The metric label `reason="finality_gap"` is emitted alongside the failure counter. |

Operators can alert on `rpp.runtime.consensus.rpc.failures` to detect repeated
verification errors or stalled finality and then reference the troubleshooting
guide for remediation steps.

## RPC subscription probes

Long-lived RPC streams (for example, `/wallet/pipeline/stream` SSE updates) are
covered by synthetic probes that run during consensus load generators and
operator maintenance windows. Each probe exports two metrics to the metrics
stack:

- `rpc_subscription_probe_success_ratio{phase}` – keep-alive success ratio per
  phase (`consensus_load` or `maintenance`). Values should stay at `1.0` while
  the probes are connected.
- `rpc_subscription_probe_disconnects_total{phase,stream}` – counter incremented
  whenever the probe reconnects a stream.

Alerts fire when keep-alives drop below 0.98 during load or stay below 0.90
beyond a maintenance window, or when disconnects accrue unexpectedly. Expect the
metrics to return to `1.0` / `0` after rolling restarts, and review ingress
timeouts or gateway buffering if the alerts remain active.【F:ops/alerts/rpc/streams.yaml†L1-L35】【F:tools/alerts/validation.py†L903-L977】【F:docs/operations/uptime.md†L80-L112】

### SDK error mapping helpers

The Rust (`rpp/chain-cli`), Go (`ffi` module), and TypeScript (`validator-ui`)
SDK layers expose typed error helpers that translate the snapshot `code` field
into structured enums. Each helper also derives retry delays from
`X-RateLimit-Reset`/`Retry-After` headers so client backoff matches the server’s
token-bucket policy. See the language-specific docs below for examples:

* Rust: `SnapshotError` and `classify_snapshot_error` in
  `rpp/chain-cli/src/snapshot_errors.rs`.
* Go: `SnapshotError` and `ClassifySnapshotResponse` in
  `ffi/snapshotclient.go`.
* TypeScript: `SnapshotError` and `snapshotRequest` in
  `validator-ui/src/lib/snapshotClient.ts`.

### Pruning progress endpoints

Operators and monitoring agents can now query pruning progress directly from
RPC. Both endpoints require the RPC token when authentication is enabled and
are throttled by the snapshot token bucket (rate-limit headers are included in
the response):

- `GET /snapshots/pruning/status` – returns the latest
  `PruningStatusResponse` with the current job payload plus calculated
  `progress` (`0.0-1.0`) and `eta_ms` when the worker has enough samples.
- `GET /snapshots/pruning/status/stream` – Server-Sent Event stream that emits
  the same payload on the `pruning` event name and keeps the connection alive
  with a 15-second heartbeat comment. Monitoring tools should prefer the
  stream to avoid burst-polling during pruning windows.

## Live API key rotation

RPC authentication secrets are only loaded during process startup; there is no
`SIGHUP`/on-the-fly reload path. Rotate bearer tokens or wallet API keys by
shipping updated configuration and rolling the fleet so each instance clears its
in-memory limiters and rejects the retired credential. The steps below avoid
interrupting traffic and ensure caches are refreshed as soon as a node adopts
the new secret.

### Rotation checklist

- **Prepare a new token and publish it to clients.** Distribute the credential
  via your secret store and update any reverse proxies that inject
  `Authorization`/`X-Api-Key` headers.
- **Stage configuration with the replacement secret.** Edit the active
  `network.rpc.auth_token` (or wallet `requests_per_minute` API key map) in the
  config profile or supply the new value via `--rpc-auth-token` at startup.
- **Roll nodes one at a time.** Drain each instance, start it with the updated
  token, and wait for `/health/ready` before moving to the next host. The reboot
  clears the per-tenant token-bucket cache so only the new key accrues quota.
- **Validate both paths during the overlap.** Use canary clients to confirm the
  new token returns `200` responses and the retired token immediately receives
  `401` or `429` responses once its host restarts.
- **Flush dependent caches.** If you front RPC with a proxy/CDN that caches
  `401`/`429` decisions, purge entries for RPC paths after the first host rolls
  so stale authorisation results do not linger.
- **Tear down the old secret.** After every node has restarted, revoke the prior
  token in the secret manager and remove any emergency overrides or temporary
  CORS origins added for the rotation.

### Example rotation timeline (rolling, zero-downtime)

- **T‑30 m** – Announce rotation window, push new token to clients, and lower
  proxy cache TTLs for RPC responses to ≤30 seconds.
- **T‑15 m** – Apply configuration with the new token to the first node and
  restart it with `--rpc-auth-token <new>` (or the updated config file); verify
  `/health/ready` and successful RPC requests with the new credential.
- **T‑10 m** – Restart remaining nodes sequentially. Monitor `401`/`429`
  counters to confirm the old token is rejected as each instance comes back.
- **T+5 m** – Purge any residual proxy/CDN caches for RPC paths and validate that
  quota/limit metrics reference only the new key.
- **T+30 m** – Revoke the old token in the secret store and delete temporary
  client allow lists or observability silences created for the rotation.

## Snapshot Regression Fixtures

Critical request/response shapes for the public RPC are captured as JSON fixtures
under `tests/rpc_snapshots/fixtures/`. The `rpc_snapshots` integration test sends
representative requests through the in-process router and compares the
serialization output against those snapshots.

* Run `cargo test -p rpp-chain --test rpc_snapshots` (or `make test:stable`) to
  confirm that local changes do not alter any canonical payloads.
* When an intentional contract change is required, bump the appropriate version
  constant in `tests/rpc_snapshots/mod.rs` and add a new `vN.json` fixture beside
  the prior version. Leave earlier fixtures in place so downstream clients can
  diff historical changes.
* Regenerate the fixtures by copying the `Actual snapshot` block printed by the
  failing test into the new `vN.json` file.

Document the version bump in the release notes alongside any schema updates so
consumers know to upgrade.

