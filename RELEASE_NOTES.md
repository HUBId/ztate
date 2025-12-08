# Release Notes

For the secure release process, see the updated [RELEASES.md](RELEASES.md)
runbook and [SECURITY.md](SECURITY.md) policy that describe the CI gates,
signing requirements, and advisory flow enforced by the latest pipelines.

## Stable Toolchain Workflow

The project is standardised on the Rust `1.79.0` toolchain. Each release must confirm that this stable pin continues to compile, format, and lint cleanly before the artefact is tagged. Toolchain health is summarised in [`docs/STABLE_MIGRATION_REPORT.md`](docs/STABLE_MIGRATION_REPORT.md), and migration criteria are tracked in `MIGRATION.md`. The repository’s `rust-toolchain.toml` still names the `nightly` channel for developer utilities; keep the pinned nightly toolchain updated in lockstep with the stable validation plan.

## Prover Backend Wiring

- `rpp/node`, `rpp/wallet`, and `rpp/consensus` now enable the `prover/prover_stwo_backend` crate whenever the `prover-stwo` feature is active, replacing their previous interface-only relationship. The `prover-mock` feature continues to keep the backend disabled.
- `scripts/build_release.sh` blocks release artefacts that request the experimental
  Plonky3 backend (including aliases such as `plonky3-backend`) or the
  `prover-mock` feature, emitting an explicit error so production builds cannot
  link the deterministic stub.【F:scripts/build_release.sh†L105-L145】
- Release/CI now treats the vendored STWO stack as proof-affecting by default:
  any change under `vendor/rpp-stark/` (including Golden Vectors and verifier
  code) must carry a `PROOF_VERSION` bump. The `proof-version-policy` pipeline
  enforces this via `cargo xtask proof-version-guard` and fails otherwise.
- Reopened the Plonky3 backend milestone: the blueprint now tracks
  `proofs.plonky3_vendor_backend` and `proofs.plonky3_ci_matrix` as
  `InProgress` until the vendor prover/verifier is integrated, mirroring the
  roadmap in [`docs/testing/plonky3_experimental_testplan.md`](docs/testing/plonky3_experimental_testplan.md).

## Storage

- Committed and immutable nodestore readers now surface `FileIoError` on root
  reads instead of treating them as empty tries. Snapshot ingestion reports the
  exact failure reason via `firewood.snapshot.ingest.failures`, and recovery
  cycles advertise their lifecycle using the new `firewood.recovery.*`
  telemetry, backed by regression tests that reject missing proofs or checksum
  mismatches.【F:storage/src/nodestore/mod.rs†L642-L701】【F:storage-firewood/src/lifecycle.rs†L238-L276】【F:storage-firewood/src/bin/firewood_recovery.rs†L62-L110】【F:storage-firewood/src/lifecycle.rs†L310-L352】【F:storage/src/nodestore/mod.rs†L909-L942】

## Documentation

- Added [Validator Quickstart](docs/validator_quickstart.md) and
  [Validator Troubleshooting](docs/validator_troubleshooting.md) guides covering
  installation, configuration with `config/node.toml`, rollout feature gates,
  telemetry options, and recovery procedures for VRF mismatches and missing
  snapshots.
- Dokumentiert die [Nova-Folding-Demo](docs/nova_folding_demo.md) inklusive
  Repro-Skript [`scripts/demo_nova_folding.sh`](scripts/demo_nova_folding.sh),
  die `I_boot` + `π_boot` initialisiert, drei Mock-Folds durchläuft und den
  Handle/Validation-Flow für Tester sichtbar macht.
- Published the [Wallet Support Policy](docs/wallet_support_policy.md), which
  enumerates long-term wallet configurations, minimum system requirements,
  support tiers (LTS, maintenance, experimental), and explicit deprecation
  timelines for CLI-only, mock-prover, bearer-token-only RPC, and other legacy
  modes. Release announcements must link this policy so stakeholders can track
  commitments over time.
- Updated the Poseidon VRF notes to highlight the `/status/node` telemetry
  payload and the `target_validator_count` / `rollout.telemetry.*` knobs in
  `config/node.toml`, giving operators concrete endpoints and toggles for the
  new metrics.【F:docs/poseidon_vrf.md†L55-L104】【F:config/node.toml†L8-L76】
- Documented den vollständigen Pipeline-Lifecycle inklusive Orchestrator-Hooks,
  Telemetrie-Metriken und dem Smoke-Test `tests/pipeline/end_to_end.rs`, damit
  Releases die Produktionstauglichkeit der Wallet→Firewood-Kette hervorheben.
  Die zugehörigen Dashboards (`docs/observability/pipeline.md`) und das
  Lifecycle-Dossier (`docs/lifecycle/pipeline.md`) sind als Referenz verlinkt
  und verweisen auf die Blueprint-Abdeckung.【F:docs/lifecycle/pipeline.md†L1-L86】【F:tests/pipeline/end_to_end.rs†L1-L122】【F:docs/observability/pipeline.md†L1-L74】【F:docs/blueprint_coverage.md†L73-L121】
- Published the [wallet monitoring guide](docs/wallet_monitoring.md), mapping
  the runtime metrics (`rpp.runtime.wallet.*`) to the Grafana exports listed in
  `docs/performance_dashboards.json` plus sample PromQL alerts. Release tickets
  now link this guide so operators keep sync/prover/RBAC alerts in view during
  rollout.【F:docs/wallet_monitoring.md†L1-L70】
- Added the [wallet platform support matrix](docs/wallet_platform_support.md)
  so Linux, macOS, and Windows builds share reproducible instructions, smoke
  tests, and cross-compilation notes for both CLI and GUI bundles.【F:docs/wallet_platform_support.md†L1-L120】
- Captured the post-Phase 4 backlog in the
  [wallet future roadmap](docs/wallet_future_roadmap.md), linking each initiative
  to tracking labels/RFCs so contributors can pick up work beyond the current
  release scope.【F:docs/wallet_future_roadmap.md†L1-L60】

## Wallet Phase 4

- Added [Wallet Phase 4 – Advanced Operations](docs/wallet_phase4_advanced.md),
  detailing deterministic backup archives, watch-only projections, multisig
  hooks, Zero State Import (ZSI) workflows, hardened RPC (mTLS + RBAC), and
  hardware signing bridges for the wallet runtime.【F:docs/wallet_phase4_advanced.md†L1-L165】
- Phase 4 features rely on explicit cargo feature flags:
  `wallet_multisig_hooks`, `wallet_zsi`, `wallet_rpc_mtls`, `wallet_hw`, and the
  default `runtime`/`backup` toggles. Operators must build artefacts with the
  required flags before enabling the corresponding `[wallet.*]` configuration
  sections.【F:docs/wallet_phase4_advanced.md†L131-L176】
- Watch-only mode stays configuration-driven (`wallet.watch_only.*`) and never
  exposes private keys. RPC projections remain hidden unless
  `wallet.watch_only.expose_rpc = true`, so monitoring deployments should wire
  downstream services accordingly.【F:docs/wallet_phase4_advanced.md†L45-L66】
- RPC hardening now supports mutual TLS and RBAC bindings. Enabling it requires
  both configuration (`[wallet.rpc.security]`) and the `wallet_rpc_mtls` cargo
  feature; legacy clients that do not present client certificates are rejected
  once `wallet.rpc.security.mtls_required = true` is set.【F:docs/wallet_phase4_advanced.md†L103-L150】
- Backup archives must be seeded manually before turning on automatic export and
  rotation, and restores can enforce passphrase policies for rollback events.
  Operators should take a manual export with `rpp-wallet backup export` prior to
  schema upgrades or config changes to ensure a known-good recovery point.
  【F:docs/wallet_phase4_advanced.md†L8-L43】

### Risks

- Stable patch releases can change lint or formatting behaviour. Cache toolchains in CI to avoid mid-release drift and re-validate when a new 1.79.x patch lands.
- Dependencies may add nightly-only features in minor updates. Track upstream release notes and stabilisation proposals to plan the upgrade path.
- Contributors using older stable compilers may encounter build failures. Communicate the minimum required version prominently in README and onboarding docs.

### Update Process

1. Run the full validation suite (`scripts/build.sh`, `scripts/test.sh --all --integration`, `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`).
2. Execute the suite with `RUSTUP_TOOLCHAIN=1.79.0` explicitly to ensure CI and local behaviour match.
3. Capture any deviations in [`docs/STABLE_MIGRATION_REPORT.md`](docs/STABLE_MIGRATION_REPORT.md) and update documentation (README, CONTRIBUTING, MIGRATION) if toolchain requirements change.
4. Announce the outcome in the release communication channel and update the tracking issues.

### Manual Checks per Release

- [ ] Confirm `rust-toolchain.toml` pins the intended stable release.
- [ ] Verify CI pipelines completed against the stable toolchain matrix.
- [ ] Review benchmarking dashboards for regressions versus the previous release.
- [ ] Ensure new backend feature flags are documented and gated appropriately.
- [ ] Validate release artefacts (binaries, Docker images, manifests) were built with the pinned toolchain.
- [ ] Annotate each SemVer tag with its support tier (`lts/MAJOR.MINOR` or
      `exp/MAJOR.MINOR.PATCH`) so `.github/workflows/release.yml` and the release
      body can surface the guarantees captured in
      [`docs/wallet_support_policy.md`](docs/wallet_support_policy.md).
