# Pruning checkpoints and recovery drills

The pruning flows exercised in CI mirror the operator steps for validating
state-sync checkpoints and mempool replay after a crash. The integration test
harness builds a short chain, prunes payloads down to proofs, and records a
state-sync checkpoint before simulating a WAL crash. The recovered node reloads
both the pruning plan and any transactions staged in the mempool WAL to ensure
state hashes and proof verification remain consistent across backends.

During recovery and steady-state pruning runs, storage captures
`io_bytes_written`, `io_duration_ms`, and `io_throughput_bytes_per_sec` so on-call
staff can correlate backlog reductions with observed disk throughput. Alerts fire
when throughput lags while `missing_heights` and the ETA stay non-zero; consult
the pruning IO runbook before raising budgets or moving the pruning artifacts to
faster disks.【F:rpp/node/src/telemetry/pruning.rs†L21-L125】【F:ops/alerts/storage/firewood.yaml†L70-L120】【F:docs/runbooks/observability.md†L115-L148】

Before any pruning artifacts are rotated, the storage layer now rehydrates the
latest manifest from disk and compares its height, digests, and checksum with
the just-committed state root. A mismatch (including missing proof files) aborts
the prune with a `PruningInvariantViolation` so operators can reconcile the WAL
and snapshot directories before losing retention depth. This check runs for both
prover backends and for each branch factor exercised by the Firewood tree tests.

Each checkpoint JSON now embeds a `metadata` block that records the snapshot
height, the Unix timestamp when the plan was persisted, and the proof backend
used to generate it. The checkpoint and its metadata are written atomically to
`snapshot-<height>.json`, so recovery routines can ignore truncated files and
select the newest valid checkpoint by inspecting the metadata.

When `pruning.checkpoint_signatures.signing_key_path` is configured, the node
signs the JSON payload and writes `snapshot-<height>.json.sig` alongside it. The
signature encodes the signing key version and an ed25519 signature of the full
checkpoint bytes, so tampering either the plan or the companion signature file
causes recovery to bail with a signature error. Operators can opt into strict
verification by setting `pruning.checkpoint_signatures.require_signatures=true`;
the key is generated automatically if the configured path is empty and the
derived verifying key is used to validate checkpoints on restart.

## Running the cross-backend drill locally

```shell
# Default backend (includes STWO proof replay)
cargo test -p rpp-chain --locked --features prover-stwo --test pruning_cross_backend -- \
  pruning_checkpoint_round_trip_default_backend wallet_snapshot_round_trip_default_backend

# RPP-STARK backend (replays golden vector verification)
cargo test -p rpp-chain --locked --features backend-rpp-stark --test pruning_cross_backend \
  -- pruning_checkpoint_round_trip_rpp_stark_backend wallet_snapshot_round_trip_rpp_stark_backend
```

The scenarios:

1. Create deterministic dummy blocks and prune them down to proofs.
2. Capture the pruning checkpoint plan to `checkpoint-<height>.json`.
3. Reconstruct pruned payloads from an in-memory provider and verify their
   pruning proofs and hashes match the originals.
4. Advance consensus by appending a new block after the pruning cycle and
   assert the refreshed checkpoint tip height/hash/state-root equals the
   finalized head.
5. Reload the persisted pruning proof for the finalized head and validate it
   with `ValidatedPruningEnvelope` so zk commitments match the header digests.
6. Append a handful of synthetic transactions to a dedicated mempool WAL,
   inject a partial record to mimic a crash, and replay the intact entries.
7. Restart the node, rehydrate the mempool from the recovered WAL contents, and
   confirm the checkpoint still lines up with the reconstructed tip height.
8. After replay, verify zk proofs against deterministic inputs: the default
   backend synthesizes and verifies a STWO transaction proof, while the
   `backend-rpp-stark` lane replays the bundled golden vector to ensure
   verifier state stays aligned with snapshot contents.

## Signals to watch

* The pruning plan tip height/hash/state-root should match the finalized head
  even if consensus advanced mid-prune.
* Reconstructed blocks must hash to the same value they held before pruning and
  pass `verify_pruning` against their predecessor. The persisted pruning proof
  for the finalized head must validate via `ValidatedPruningEnvelope`.
* The runtime now scrubs mempool metadata during pruning. Expect
  `rpp.runtime.mempool.metadata.rehydrated` to tick up when missing witness
  payloads are rebuilt, and `rpp.runtime.mempool.metadata.orphans` plus a
  `mempool_metadata_reconciled` warning when stale metadata is dropped. Wallet
  submissions queued during the prune should retain their proof payloads in
  `/status/mempool` after reconciliation.【F:rpp/runtime/node.rs†L735-L762】【F:rpp/runtime/telemetry/metrics.rs†L153-L208】【F:tests/mempool/pruning_orphans.rs†L1-L82】
* WAL replay should resurrect the queued transactions so the mempool count after
  restart equals the recovered WAL length.
* The STWO and RPP-STARK verifiers must accept their respective reference
  proofs after snapshot replay, proving that pruning did not desync witness
  inputs across backends.

These steps now run in the integration matrix (default and `backend-rpp-stark`)
so regressions in pruning, proof verification, or WAL handling are surfaced
before release.

## Operator runbook for manifest/WAL divergence

1. **Detect the failure.** A prune will now fail fast with a
   `PruningInvariantViolation` that calls out which snapshot height diverged
   from the committed root or missing proof bytes. The node leaves all files in
   place so operators can inspect the mismatch.
2. **Cross-check WAL vs. snapshots.** Use the latest committed block height in
   logs to compare against `cf_pruning_snapshots/<height>.json` and confirm the
   manifest `state_root` and checksum match what the WAL would rebuild. If they
   differ, regenerate the manifest/proof pair from the WAL contents or replay
   the affected block.
3. **Repair and retry.** Once the manifest and proof checksum line up with the
   rebuilt state root, rerun the pruning job. The validation step will pass and
   retention will resume without silently deleting inconsistent artifacts.

## Rotating pruning and consensus checkpoint signing keys

1. **Generate a fresh signing keypair.** Point
   `pruning.checkpoint_signatures.signing_key_path` at a new file and bump
   `signature_version` so consumers can distinguish the rollover. The runtime
   creates the path on startup when it does not exist, storing both the secret
   and derived public key for distribution.【F:rpp/runtime/config.rs†L2699-L2847】
2. **Extract and distribute the verifying key.** After the node writes the new
   key file, export the `public_key` field and share it with downstream
   validators and consensus checkpoint verifiers:

   ```bash
   python - <<'PY'
import tomllib
from pathlib import Path

key = tomllib.loads(Path("/var/lib/rpp/keys/pruning-checkpoint.toml").read_text())
print(key["public_key"])
PY
   ```

   Set `pruning.checkpoint_signatures.verifying_key` (and the matching
   consensus checkpoint verifier entry) to the exported value so both pruning
   recovery and consensus snapshot validation refuse unsigned or stale
   signatures.【F:rpp/runtime/config.rs†L2793-L2842】
3. **Update configs and restart validators.** Roll the new signing key path and
   verifying key through the deployment’s `config/node.toml` (or templated
   equivalent) and restart nodes. Environments requiring strict enforcement
   should keep `require_signatures=true` so startup fails if a rotated key is
   missing.【F:rpp/runtime/config.rs†L2793-L2842】
4. **Verify signatures after rotation.** Run the mixed-backend signature tests
   locally or in CI to prove the new key signs checkpoints and that tampering is
   rejected across both prover stacks:

   ```bash
   # Default backend (STWO)
   RPP_PROVER_DETERMINISTIC=1 cargo test -p rpp-chain --locked --features prover-stwo --test recovery_pruning -- \
     pruning_checkpoint_signature_rejects_tampered_payload pruning_checkpoint_signature_rejects_tampered_signature

   # RPP-STARK backend
   RPP_PROVER_DETERMINISTIC=1 cargo test -p rpp-chain --locked --features backend-rpp-stark --test recovery_pruning -- \
     pruning_checkpoint_signature_rejects_tampered_payload pruning_checkpoint_signature_rejects_tampered_signature
   ```

   The `pruning-checkpoints` CI job records per-backend logs under
   `artifacts/pruning-checkpoints/<backend>/` so operators can confirm mixed-
   backend coverage after each rotation.
