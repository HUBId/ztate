# Operator documentation

Welcome to the operator guidebook. Start with the runtime [modes overview](modes.md), then dive into
configuration specifics, checklists, and runbooks as needed. The sections below group the most
frequently consulted references.

## Backlog status

- **Phasenübersicht:** Die abgeschlossenen Backlog-Tranchen und offenen
  Aufgaben sind im [Roadmap Implementation Plan](roadmap_implementation_plan.md)
  dokumentiert; dort sind Phase 1–4 mitsamt Nachweisen und verbleibenden
  Nacharbeiten verlinkt.
- **Offene Punkte:** Alle aufgeschobenen oder eingeschränkten Funktionen sind im
  Abschnitt „Deferred items“ der [Wallet Release Status](wallet_release_status.md)
  sowie in den Acceptance-Checklisten (z. B.
  [Phase‑3](runbooks/phase3_acceptance.md)) aufgeführt. Neue Arbeiten landen ab
  sofort ausschließlich in regulären Issues oder den jeweiligen Checklisten.

## Core guides

- [`rpp-node` operator guide](rpp_node_operator_guide.md)
- [Nova-Folding-Demo: I_boot/π_boot + Mock-Backend](nova_folding_demo.md)
- [Wallet integration feature reference](wallet_integration.md)
- [Configuration guide](configuration.md)
- [Snapshot streaming protocol](network/snapshots.md)
- [Validator quickstart](validator_quickstart.md)

## Checklists

- [Operator checklist](checklists/operator.md)
- [Checklist: Phase-1 Guard Verification](runbooks/startup.md#phase-1-guard-verification)
- [Deployment staged rollout playbook](deployment/staged_rollout.md)
- [Wallet release checklist](release_checklist.md)
- [Consensus/verifier/pruning quick triage](operator-guide.md#consensus-verifier-and-pruning-quick-triage)

## Runbooks

- [Runbook: startup](runbooks/startup.md)
- [Runbook: observability](runbooks/observability.md)
- [Runbook: network snapshot failover](runbooks/network_snapshot_failover.md)
- [Runbook: upgrade](runbooks/upgrade.md)
- [Runbook: pruning](runbooks/pruning.md)
- [Runbook: pruning operations](runbooks/pruning_operations.md)
- [Runbook: Plonky3 production validation](runbooks/plonky3.md)

## Observability

- [Observability overview](observability.md)
- [Deployment observability checklist](deployment_observability.md)
- [Telemetry reference](telemetry.md)
- [Alert validation drill](runbooks/observability.md#alert-validation-drills)
- [Alert promotion workflow](operations/alert_promotion.md)

## Zero-knowledge backend procedures

- [Zero-knowledge backend procedures](zk_backends.md)
- [Vendor routine checklist](vendor_routine.md)
- [Third-party compliance: Plonky3](third_party/plonky3.md)

## Security references

- [Security policy & vulnerability reporting](../SECURITY.md)
- [Threat model](THREAT_MODEL.md)
- [Key management](KEY_MANAGEMENT.md)
- [API security](API_SECURITY.md)
- [Governance](GOVERNANCE.md)
- [Wallet advisory template](security/wallet_advisory_template.md)

## Wallet documentation index

These references cover every wallet deployment phase along with the supporting
runbooks and migration checklists. Follow the phase order below when enabling
new capabilities.

| Document | Summary |
| --- | --- |
| [Wallet Phase 1 – minimal runtime configuration](wallet_phase1_minimal.md) | Baseline configuration knobs, JSON-RPC reference, telemetry opt-in defaults, and CLI quickstart that early operators use to stage the runtime. |
| [Wallet Phase 2 – policies & prover guide](wallet_phase2_policies_prover.md) | Policy tunables, fee estimator behaviour, pending lock lifecycle, rescans, prover setup, and troubleshooting workflows for spend readiness. |
| [Wallet Phase 3 – GUI guide](wallet_phase3_gui.md) | MVU architecture overview, tab flows, telemetry, UX security affordances, and GUI-specific build/test steps layered atop the Phase 2 runtime. |
| [Wallet Phase 4 – advanced operations](wallet_phase4_advanced.md) | Backup rotation, watch-only projections, multisig hooks, ZSI workflows, mTLS/RBAC security, hardware integrations, and migration guidance for enterprise rollouts. |
| [Wallet operator runbook](wallet_operator_runbook.md) | Step-by-step acceptance checklist that validates prerequisites, feature flags, backup/restores, security envelopes, and regression automation for wallet releases. |
| [Wallet installation guides (Linux / macOS / Windows)](install) | Platform-specific instructions covering signature verification, installer hooks, RPC/GUI configuration, screenshots, and uninstall flows. |
| [Wallet operations guide](operations/wallet.md) | RPC hosting models, mTLS/RBAC hardening, logging, backup rotation, telemetry, crash reporting, and drill expectations for on-call teams. |
| [Wallet troubleshooting catalog](troubleshooting/wallet.md) | Error-code lookup tables, health checks, and self-diagnostic workflows that responders can run before escalating incidents. |
| [Wallet release status](wallet_release_status.md) | Executive summary of Phase 1–4 completion, delivered capabilities, deferred items, dependencies, and verification checklist links for release readiness. |
| [Wallet policies](wallet/policies.md) & [operations](wallet/operations.md) | Tiered UTXO policy reference plus operational guidance for monitoring policy enforcement and coordinating validator-grade sweeps. |
| [Wallet documentation in `MIGRATION.md`](../MIGRATION.md#wallet-database-schema-v3-upgrade) | Database schema v3 upgrade path, including backup prerequisites, migration commands, and rollback steps tied to the Phase 4 rollout. |
| [Wallet monitoring guide](wallet_monitoring.md) | Maps runtime metrics (`rpp.runtime.wallet.*`), Grafana dashboards, and sample alert rules so operators can tie incidents back to the correct Prometheus/OTLP signals. |
| [Wallet platform support matrix](wallet_platform_support.md) | Documents Linux/macOS/Windows build steps, cross-compilation commands, smoke tests, and per-OS quirks for the CLI and GUI bundles. |
| [Wallet roadmap beyond Phase 4](wallet_future_roadmap.md) | Highlights short-, mid-, and long-term initiatives (hardware vendors, HSMs, mobile UI, multisig automation) and links each one to the relevant issue tracker labels. |

For additional topics, explore the documentation tree (e.g. `docs/telemetry.md` and
`docs/validator_quickstart.md`).

