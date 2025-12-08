# Migration Guide

## Node Configuration Schema Versioning

Use the following checklist when the `NodeConfig` schema changes:

- [ ] Bump `NODE_CONFIG_VERSION` in `rpp/runtime/config.rs` and update the
      `config_version` field in sample configs (e.g. `config/node.toml`).
- [ ] Document operator-facing changes and migration steps in `docs/` and the
      release notes.
- [ ] Provide an upgrade procedure that includes backing up the previous
      configuration and running validation via `cargo run -p rpp-chain -- <mode> --dry-run --config <path>`
      (or the equivalent CLI entry point) before restarting.
      Reference the [`rpp-node` operator guide](docs/rpp_node_operator_guide.md) and the
      [validator quickstart](docs/validator_quickstart.md) for CLI usage details.
- [ ] Communicate the new version to validators and ensure automation or
      orchestration scripts fail-fast on mismatches.

### Hot-reload evaluation

`NodeConfig` is loaded during start-up and its values are wired into subsystems
such as networking, storage, and consensus before the main runtime begins. The
current runtime does not support re-initialising those components on the fly,
so hot-reloading configuration files would not apply the updated values safely
and could leave the process in an inconsistent state. Operators should restart
the node after editing configuration files to pick up changes.

## Maintaining the Stable Toolchain

Use the following checklist to keep the `1.79.0` workflow healthy:

- [ ] **Toolchain**
  - [ ] Run the full validation suite on the pinned stable compiler (`1.79.0`) whenever a release candidate is cut.
  - [ ] Re-run the suite after upstream `1.79.x` patch releases and capture any deltas in [`docs/STABLE_MIGRATION_REPORT.md`](docs/STABLE_MIGRATION_REPORT.md).
  - [ ] Update `rust-toolchain.toml` if the minimum supported Rust version changes and communicate the date of enforcement.
- [ ] **Feature flags & crates**
  - [ ] Audit `Cargo.toml` and workspace members for `#![feature(...)]` attributes or nightly-only dependencies before accepting upgrades.
  - [ ] Gate unstable functionality behind cfg flags or replace it with stable equivalents.
  - [ ] Refresh documentation snippets and examples to reflect stable-compatible syntax.
- [ ] **CI configuration**
  - [ ] Keep CI jobs (build, test, lint, docs) on the stable toolchain matrix and ensure caches are refreshed when the compiler is bumped.
  - [ ] Ensure formatting and linting steps pull `rustfmt`/`clippy` from the pinned stable channel.
  - [ ] Update cached toolchain layers or containers to include the stable version before the release branch is cut.
- [ ] **Benchmarks & performance tracking**
  - [ ] Re-run benchmark suites after toolchain bumps to compare regressions.
  - [ ] Update baseline metrics stored in `bench/` artefacts or observability dashboards.
  - [ ] Communicate any performance deltas to stakeholders and capture follow-up tasks.

Once every item is checked, announce the toolchain status in the release communication channel and monitor post-merge CI for regressions.

## Wallet database schema v3 upgrade

Phase 4 ships the third major revision of the wallet store. The upgrade adds
tables for deterministic backups, mTLS/RBAC registries, and watch-only account
metadata, so operators must plan the migration before rolling out the new
binary.

## Nova V2 folding bootstrap from a cut tip

The Nova folding path now boots from a signed cut rather than the original
genesis header. The helper `Storage::bootstrap_global_folding_from_cut` accepts
the cut tip reference, state/pruning commitments, and the Nova proof payload
(`π_boot`). It derives `I_boot`, signs it with `ProofVersion::NovaV2`, and
persists both artifacts without touching legacy aggregation records.

Recovery steps:

1. **Record the cutover**: configure the consensus layer with
   `ConsensusConfig::with_folding_cutover(<height>, <epoch>)` so every node
   enforces the Nova switch at the same block/epoch.
2. **Prepare inputs**: capture the state roots and pruning digest of the cut
   block and export the Nova bootstrap proof and verification key ID.
3. **Persist bootstrap artifacts**: call
   `Storage::bootstrap_global_folding_from_cut` with the collected inputs. The
   method leaves existing aggregated proofs intact and writes `I_boot` and
   `π_boot` as the source for subsequent folding steps.
4. **Restart validation**: restart the node to pick up the new cutover values
   and continue folding from the persisted bootstrap pair.

### Prerequisites

1. **Backups first.** Take an encrypted snapshot with the Phase 4 backup tool
   before touching the on-disk database:
   ```sh
   rpp-wallet backup export --path /var/backups/wallet/pre-v3.rppb \
       --profile argon2id --tag pre-v3
   ```
   Confirm the archive lives in `wallet.backup.export_dir` and replicate it to
   offline media. Automatic exports (`wallet.backup.auto_export_enabled`) should
   stay disabled until the manual backup is verified.
2. **Schema discovery.** Run `rpp-wallet doctor schema` (or
   `rpp-wallet info --json | jq '.wallet.schema_version'`) to confirm the
   current version is `2`. Abort and investigate if the store already reports a
   higher version; the migration is not reversible in-place.
3. **Maintenance window.** Stop the wallet runtime and ensure no external tools
   are writing to the store. The schema migration is not safe to run while the
   wallet is online.

### Upgrade workflow

1. Deploy the Phase 4 wallet binary compiled with the required feature flags
   (e.g. `wallet_rpc_mtls`, `wallet_multisig_hooks`).
2. Apply the schema upgrade:
   ```sh
   rpp-wallet migrate --schema-target 3
   ```
   The command creates the backup buckets, security registries, and watch-only
   projections introduced in `docs/wallet_phase4_advanced.md`.
3. Validate success by re-running `rpp-wallet doctor schema` and confirming the
   stored version is `3`. Start the wallet process only after the check passes.

### Rollback

If application smoke tests fail after the upgrade, keep the wallet runtime
stopped and restore the pre-v3 backup:

```sh
rpp-wallet backup restore --path /var/backups/wallet/pre-v3.rppb --force
```

The restore drops the new schema and reinstates the previous store. Repeat the
`rpp-wallet migrate --schema-target 3` command only after investigating the
failure and capturing fresh backups. Never attempt to downgrade a live database
without restoring from a clean backup archive.

## Fixture compatibility checkpoints

The CI matrix keeps a small catalogue of historical proof+VK pairs so that
migration tooling can assert we do not regress on backwards compatibility. The
following tags are referenced by the fixtures and validated in CI:

| Version | Migration tag      | Notes                               |
|---------|-------------------|--------------------------------------|
| v1      | 2024-06-hotfix    | Legacy rollout with cached witnesses |
| v2      | 2024-08-rollup    | Rollup release with rotation tweaks  |
