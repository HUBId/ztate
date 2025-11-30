# Firewood lifecycle API

The Firewood storage backend exposes a dedicated lifecycle helper that moves
snapshot artifacts between nodes while preserving the Merkle commitment
contracts that Firewood publishes. The [`FirewoodLifecycle` helper](../../storage-firewood/src/lifecycle.rs)
wraps a [`FirewoodState`](../../storage-firewood/src/state.rs) handle and
orchestrates how pruning manifests and proofs land in the on-disk column
families. Its API surfaces the following guarantees:

- `ingest_snapshot` verifies the exported manifest and proof bundle before
  persisting it. The integration test exercises a sequence of three snapshots
  produced by Firewood itself and checks that every manifest ends up in the
  target storage directory. 【F:tests/firewood_lifecycle/mod.rs†L91-L120】
- `rollback_to_snapshot` truncates state to a previously verified height by
  deleting newer manifests and proofs before reloading the target block. The
  regression test confirms that only the intended snapshots remain after a
  rollback. 【F:tests/firewood_lifecycle/mod.rs†L122-L152】
- Layout upgrades are gated through the storage layout marker enforced by
  `STORAGE_LAYOUT_VERSION`. Any snapshot manifest with a different layout is
  rejected, preserving compatibility guarantees. 【F:storage-firewood/src/lifecycle.rs†L63-L95】【F:tests/firewood_lifecycle/mod.rs†L154-L178】

Firewood snapshots also carry schema and parameter digests whose prefixes map
back to the canonical key spaces defined in the storage schema module. The
[`schema` constants](../../storage-firewood/src/schema.rs) document those
prefixes and serve as the source of truth for how account, reputation, and block
metadata keys are encoded on disk. Snapshot ingestion therefore validates both
Merkle proofs and schema versioning before the runtime exposes the updated
state.

## Trie node layout and allocation

Firewood represents trie nodes with the `firewood_storage::Node` enum, which
stores branch nodes behind a `Box` but keeps leaves inline. That split keeps the
enum's footprint manageable: a `BranchNode` is 1,752 bytes with the default
branching factor because it owns the full `[Option<Child>; 16]` fan-out plus the
embedded value slot, while a `LeafNode` is only 88 bytes (a `Path` wrapper around
`SmallVec<[u8; 64]>` and the boxed value). Boxing the branch variant holds the
`Node` enum at 96 bytes so cloning or swapping nodes only copies a pointer-sized
handle and the discriminant; storing branches inline would force every `Node` and
`Option<Node>` allocation to reserve ≈1.7 KiB even when the variant contains a
leaf. The serialization routines therefore match the in-memory layout—branch
payloads live in heap allocations that mirror the persisted area entries, while
leaves remain compact for fast hashing and persistence (see
`storage/src/node/mod.rs`).

## Pruning automation and operational hooks

The runtime now ships a pruning worker alongside the lifecycle helper so nodes
continuously produce and hydrate Firewood snapshots without manual triggers. At
startup the pruning service publishes its cadence, retention depth, and pause
state, then streams `PruningJobStatus` updates through a watch channel that both
internal components and RPC handlers can subscribe to.【F:rpp/node/src/services/pruning.rs†L120-L200】
Each cycle persists pruning proofs, records missing heights, and broadcasts the
status over the snapshots gossip topic so downstream recovery tools observe the
latest plan immediately.【F:rpp/runtime/node.rs†L3580-L3639】

Operators interact with the automation via the `/snapshots/rebuild` and
`/snapshots/snapshot` RPCs, which return structured receipts describing whether
the request was accepted and why.【F:rpp/rpc/src/routes/state.rs†L1-L26】【F:rpp/storage/pruner/receipt.rs†L1-L58】
The pruning runbooks document how to adjust cadence, inspect receipts, and
monitor the status stream, rounding out the operational story for the automated
worker.【F:docs/runbooks/pruning.md†L1-L120】【F:docs/runbooks/pruning_operations.md†L1-L120】

## WAL sizing and sync policy guidance

Firewood retains the three most recent commit boundaries in the WAL, trimming
older sequences after every fsync to keep the log bounded even on long-running
validators.【F:storage-firewood/src/kv.rs†L26-L45】【F:storage-firewood/src/kv.rs†L236-L248】
Each append is flushed immediately and the `FileWal::sync` path issues
`sync_data` calls so committed transactions survive power loss.【F:storage-firewood/src/wal.rs†L100-L129】
Operators therefore size the WAL by multiplying the expected per-block write
footprint with the retention window (≈3× the commit payload) and allocating head
room for compactions.

Production deployments should keep the metadata sync policy at `always`, which
mirrors the `StorageOptions` default and instructs Firewood to flush manifest,
telemetry, and pruning updates durably on every commit.【F:storage-firewood/src/state.rs†L391-L420】
The node configuration exposes the same default through
`storage.sync_policy = "always"`, with commit and compaction budgets publishing
the expected WAL and pruning write volume to telemetry.【F:rpp/runtime/config.rs†L1625-L1670】【F:config/storage.toml†L1-L20】
Sticking to the shipped budgets (64 MiB for commits, 128 MiB for compactions)
keeps alerts calibrated against the IO headroom provisioned for production
hardware.【F:config/storage.toml†L1-L20】 The budgets do not hard-cap writes, but
they document intended throughput and feed dashboards via the
`firewood.storage.io_budget` gauges.【F:storage-firewood/src/state.rs†L202-L220】

### Troubleshooting WAL pressure or latency

- **Large WAL growth or constant truncations.** Check whether the actual commit
  size (e.g. `firewood.wal.transactions` payloads) consistently overshoots the
  documented budget. If so, raise `storage.commit_io_budget_bytes` in
  `config/storage.toml` so alert thresholds reflect the higher steady-state load
  and investigate upstream components that started emitting larger batches.【F:storage-firewood/src/kv.rs†L286-L305】【F:config/storage.toml†L1-L20】
- **Sustained fsync latency spikes.** Inspect
  `rpp.runtime.storage.wal_flush.*{outcome="failed"|"retry"}` to confirm flush
  pressure and temporarily switch `storage.sync_policy` to `"deferred"` during
  catch-up windows. The deferred mode skips immediate metadata fsyncs and can
  shave milliseconds off each commit, but operators must revert to `"always"`
  once the backlog clears so pruning manifests stay crash-safe.【F:rpp/runtime/telemetry/metrics.rs†L125-L142】【F:config/storage.toml†L1-L20】
- **Slow compactions after pruning.** Compare the compaction budget recorded in
  `cf_meta/telemetry.json` with observed wall-clock time. Raising
  `storage.compaction_io_budget_bytes` increases the documented throughput and
  aligns dashboards with the larger I/O envelope required for new retention
  policies.【F:storage-firewood/src/state.rs†L202-L220】【F:tests/compaction_budget.rs†L1-L34】【F:config/storage.toml†L1-L20】

When changes to sync policy or budgets are required, update the values, restart
the node (configuration reloads only happen on startup), and document the new
targets alongside telemetry dashboards so on-call staff understand the revised
expectations.【F:rpp/runtime/config.rs†L1625-L1674】【F:config/storage.toml†L1-L20】

### IO-Budget und Pruning-Throttling {#io-budget-und-pruning-throttling}

Pruning-Zyklen schreiben die erzeugten Beweise und Manifeste unter
`cf_pruning_*` und exportieren das Volumen über
`rpp.node.pruning.io_bytes_written`, während `io_duration_ms` und
`io_throughput_bytes_per_sec` die beobachtete Schreibdauer bzw. den Durchsatz
pro Zyklus erfassen.【F:rpp/node/src/telemetry/pruning.rs†L21-L125】 Korreliere die
Werte mit `missing_heights` und `time_remaining_ms`, um IO-Engpässe von leerlauf
bedingten Stalls zu unterscheiden.

- **Durchsatz dauerhaft < 4 MiB/s:** Stelle sicher, dass `snapshot_dir` und
  `proof_dir` auf einer lokalen SSD/NVMe liegen, und erhöhe
  `storage.commit_io_budget_bytes` sowie `storage.compaction_io_budget_bytes`,
  damit die Hintergrundleistung mit der per-Metrik dokumentierten Erwartung
  übereinstimmt.【F:storage-firewood/src/state.rs†L202-L220】【F:config/storage.toml†L1-L20】
- **Backlog fällt trotz Budget nicht:** Pausiere Pruning mit `rppctl pruning pause`,
  entzerre den IO-Pfad (z. B. dediziertes Volume für Pruning-Artefakte) und
  setze den Dienst erst fort, wenn der 10‑Minuten-Durchschnitt von
  `io_throughput_bytes_per_sec` über die kritische Schwelle steigt.

## Root integrity and failure handling

NodeStore accessors now differentiate between an intentionally empty trie and a
root that could not be fetched from disk. `NodeStore<Committed>::root_node`
returns `Ok(None)` when the revision is empty and propagates any `FileIoError`
from the underlying storage backend instead of silently returning
`None`.【F:storage/src/nodestore/mod.rs†L642-L701】 The mutable and immutable
variants retain the same behaviour, with immutable readers re-emitting storage
errors so callers can react accordingly.【F:storage/src/nodestore/mod.rs†L669-L701】

The trie utilities rely on this guarantee to surface corruption during proofs or
Merkle traversals. Helper functions such as `Merkle::try_root` bubble the
`FileIoError` rather than masking it, ensuring that snapshot ingestion or proof
verification halts when the committed root is unreadable.【F:firewood/src/merkle.rs†L127-L138】

State-sync consumers extend the behaviour by mapping any `ProofError::IO`
messages from the pipeline into explicit `IoProof` responses and incrementing the
`rpp_node_pipeline_root_io_errors_total` counter so operators can correlate API
failures with Firewood storage symptoms. The light-client verifier records the
counter whenever snapshot verification, validation, or persistence surfaces the
marker, and the runtime replays the message in the `/state-sync/chunk/:id`
payload.【F:rpp/node/src/state_sync/light_client.rs†L360-L401】【F:rpp/node/src/telemetry/pipeline.rs†L1-L88】【F:rpp/runtime/node.rs†L4029-L4075】
The observability runbook points auditors to the corresponding Prometheus
queries and log markers, while dedicated regression tests confirm the API
response, telemetry increments, and safeguards against corrupted snapshot
payloads.【F:docs/runbooks/observability.md†L1-L38】【F:tests/state_sync/proof_error_io.rs†L1-L111】【F:tests/state_sync/root_corruption.rs†L1-L53】
The `root_corruption` safeguard now runs in the standard CI integration matrix,
mirroring release gating so regressions are surfaced before packaging.

Two new metrics aid incident response:

- `firewood.nodestore.root.read_errors` counts committed or immutable root reads
  that failed with I/O errors.【F:storage/src/nodestore/mod.rs†L661-L701】
- `firewood.snapshot.ingest.failures{reason="…"}` records missing proofs,
  checksum mismatches, or verification failures observed during snapshot
  ingestion.【F:storage-firewood/src/lifecycle.rs†L18-L37】【F:storage-firewood/src/lifecycle.rs†L238-L276】

Operators should treat any increment of these counters as a hard failure. The
observability runbook documents how to correlate the metrics with WAL recovery
attempts (`firewood.recovery.runs` / `firewood.recovery.active`) and which
manual checks to perform before resuming ingestion.【F:docs/runbooks/observability.md†L9-L38】【F:storage-firewood/src/bin/firewood_recovery.rs†L36-L105】
