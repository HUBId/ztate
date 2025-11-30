# Observability runbook

> **Breadcrumbs:** [Operator documentation index](../README.md) › [Runbooks](../README.md#runbooks) › Observability runbook
>
> **See also:** [Observability overview](../observability.md),
> [Node lifecycle expectations](../operator-guide.md),
> [Security policy & reporting](../../SECURITY.md),
> [Zero-knowledge backend procedures](../zk_backends.md)

Use this runbook to diagnose gaps in telemetry, metrics, and health reporting. Pair it with the
[startup](startup.md) and [configuration](../configuration.md) guides when remediation requires
configuration changes.

## Snapshot-CLI-Diagnose

Die Snapshot-Steuerung läuft vollständig über `cargo run -p rpp-chain -- validator snapshot`. Verwende die Subcommands,
um Session-Status strukturiert zu erfassen und die Belege für Phase 3 zu sichern:

1. **Start oder Resume dokumentieren.** `cargo run -p rpp-chain -- validator snapshot start --peer <peer>` bzw.
   `cargo run -p rpp-chain -- validator snapshot resume --session <id> --peer <peer> --plan-id <plan>` legt einen
   neuen oder wiederaufgenommenen Stream an und druckt Session-ID, Root und Plan-ID für das Incident-Log.【F:rpp/node/src/main.rs†L118-L310】
2. **Status prüfen.** `cargo run -p rpp-chain -- validator snapshot status --session <id>` zeigt Fortschritt,
   Chunk-Index, letzte Höhe und Fehlerzustände. Kopiere den Output in das
   [On-Call-Handbuch](./oncall.md#snapshot-recovery), damit Rotationsteams die gleiche Sicht teilen und die
   Snapshots im Incident-Log nachvollziehen können.【F:docs/runbooks/oncall.md†L21-L34】
3. **Artefakte sichern.** Exportiere parallel die Panels aus `pipeline_overview.json`,
   `pipeline_proof_validation.json` und `vrf_overview.json`, um die CLI-Ausgabe mit Dashboard-Screenshots
   zu belegen; beide Quellen werden in der [Phase‑3-Akzeptanzliste](phase3_acceptance.md#snapshot-slis--replay-evidenz)
   abgelegt.【F:docs/dashboards/pipeline_overview.json†L200-L260】【F:docs/dashboards/pipeline_proof_validation.json†L1-L60】【F:docs/dashboards/vrf_overview.json†L1-L60】【F:docs/runbooks/phase3_acceptance.md†L8-L62】
4. **Cancel als Abschluss.** Schliesse fehlgeschlagene Sessions mit
   `cargo run -p rpp-chain -- validator snapshot cancel --session <id>` und notiere den Zeitpunkt im Incident-Log; das On-Call-Handbuch
   beschreibt die Eskalation für mehrfach fehlschlagende Streams.【F:docs/runbooks/oncall.md†L21-L34】

## Phase-1 Guard Verification

Re-run these guard checks whenever telemetry gaps or snapshot alerts occur to ensure the compile-time
and runtime protections remain enforced alongside the CI gates.

- [ ] **Compile guard blocks Plonky3 + mock combinations.** Run
      `cargo check --features backend-plonky3,prover-mock` from the repository root. Compilation must
      abort with `The Plonky3 backend cannot be combined with the mock prover feature.`, confirming the
      guard in `rpp-node` still fires and the feature-matrix tests continue to cover it.【F:rpp/node/src/feature_guard.rs†L1-L7】【F:rpp/node/tests/feature_matrix.rs†L6-L60】
- [ ] **Runtime guard raises root-integrity signals.** Temporarily corrupt a snapshot payload (see the
      Python helper in the [startup checklist](startup.md#phase-1-guard-verification)) and request a
      state-sync chunk before polling `curl -i http://localhost:26600/health/ready`. The readiness probe
      should drop to `503` while the chunk endpoint returns a `snapshot root mismatch` error and the
      pipeline counter `rpp_node_pipeline_root_io_errors_total` increments, matching the Firewood
      telemetry contract and the regression tests.【F:rpp/runtime/node.rs†L4007-L4043】【F:rpp/rpc/api.rs†L3027-L3070】【F:tests/state_sync/root_corruption.rs†L1-L53】【F:docs/storage/firewood.md†L58-L76】
- [ ] **CI dashboards and guardrails pass.** Confirm the GitHub `CI` workflow (fmt, clippy, full
      `scripts/test.sh` matrix, and dashboard/alert validation) is green via
      `gh run watch --exit-status --workflow ci.yml` or the pull-request status view before declaring
      telemetry healthy.【F:.github/workflows/ci.yml†L1-L80】【F:docs/test_validation_strategy.md†L41-L83】

## Alert validation drills

The nightly workflow runs the **Alert validation drill** immediately after the metric-export smoke
tests to prove that Prometheus rules fire and reach the configured webhooks.【F:.github/workflows/nightly.yml†L1-L140】
The job executes `python tools/alerts/validate_alerts.py` to replay consensus and snapshot
anomalies, then runs the companion pytest suite to guarantee that missing or unexpected alerts fail
the build.【F:tools/alerts/validate_alerts.py†L1-L48】【F:tools/alerts/tests/test_alert_validation.py†L1-L63】

When the step fails it produces an `AlertValidationError` describing which alert names were missing or
unexpected and whether the webhook payload differed from expectations. Use the following checklist
before paging the on-call rotation:

1. **Inspect the nightly log.** Open the `alert-validation` job in the
   [`nightly-simnet` workflow](https://github.com/chainbound/chain/actions/workflows/nightly.yml) to
   read the failure summary and confirm whether the HTTP webhook ran at all. The payload dump is
   recorded in the step log if the simulated Alertmanager responded.【F:.github/workflows/nightly.yml†L1-L160】
2. **Reproduce locally.** Run `python tools/alerts/validate_alerts.py` followed by
   `python -m pytest tools/alerts/tests` from the repository root. The harness spins up a local
   webhook server and stores the payloads under `ValidationResult.webhook_payloads` so you can inspect
   the JSON directly.【F:tools/alerts/validation.py†L1-L522】 Update the anomaly fixtures or expected
   alert names in `default_validation_cases()` if the Prometheus rules changed legitimately.【F:tools/alerts/validation.py†L524-L580】
3. **Confirm runbook coverage.** If a real regression surfaced (for example the alert stopped firing),
   follow the relevant playbook (`Consensus VRF-/Quorum` or `Snapshot failover`) and attach the
   validation output to the incident log before re-enabling the nightly gate.【F:docs/runbooks/observability.md†L69-L123】【F:docs/runbooks/network_snapshot_failover.md†L1-L176】

## Phase-2 consensus proof audits

- Orientiere dich an der [Plonky3 Production Validation Checklist](../testing/plonky3_experimental_testplan.md#4-production-sign-off-checklist),
  wenn du Phase‑2-Nachweise sammelst; die folgenden Schritte spiegeln die dort
  verlangten Artefakte für Observability und Tamper-Belege wider.【F:docs/testing/plonky3_experimental_testplan.md†L1-L121】

- [ ] **Tamper-Rejections lokal nachweisen.** Führe `cargo xtask test-consensus-manipulation`
      aus, um gültige sowie manipulierte VRF-/Quorum-Zeugen gegen beide Backends zu prüfen.
      Verwende `XTASK_FEATURES="prod,backend-plonky3"` bzw. `XTASK_FEATURES="prod,prover-stwo"`.
      Der Lauf muss mit Exit-Code `0` enden, andernfalls ist der Proof-Pfad regressiv.【F:xtask/src/main.rs†L1-L120】
- [ ] **Simnet-Logs protokollieren.** Starte `cargo run -p simnet -- --scenario
      tools/simnet/scenarios/consensus_quorum_stress.ron --artifacts-dir target/simnet/consensus-quorum`
      und archiviere die Einträge `invalid VRF proof`, `duplicate precommit detected` usw. aus
      `target/simnet/consensus-quorum/node.log`. Diese stammen aus
      `Block::verify_consensus_certificate` und beweisen, dass manipulierte Daten abgelehnt werden.【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】【F:rpp/runtime/types/block.rs†L2002-L2245】
- [ ] **RPC- und Dashboard-Nachweise sammeln.** Während eines erfolgreichen Laufs muss
      `cargo run -p rpp-chain -- validator telemetry --rpc-url http://127.0.0.1:7070 --auth-token "$RPP_RPC_TOKEN" --pretty | jq '.consensus | {round, quorum_reached}'`
      `quorum_reached=true` liefern. Nach einer manipulierten Probe bleibt der Wert `false` und der
      Log-Eintrag dokumentiert den Abbruch. Erfasse zusätzlich einen Screenshot der Panels
      `consensus_vrf_verification_time_ms` und `consensus_quorum_verifications_total` aus
`docs/dashboards/consensus_grafana.json`, inklusive des `result="failure"`-Slices.【F:rpp/node/src/main.rs†L60-L208】【F:docs/dashboards/consensus_grafana.json†L1-L200】【F:rpp/runtime/node.rs†L358-L390】

## Consensus VRF-/Quorum-Alert-Playbook

Die Prometheus-Regeln unter `docs/observability/alerts/consensus_vrf.yaml` schlagen bei erhöhten VRF-Latenzen,
Failure-Bursts oder Quorum-Rejections an.【F:docs/observability/alerts/consensus_vrf.yaml†L1-L47】 Die folgenden Schritte sind
mit dem [On-Call-Handbuch](./oncall.md#alert-reaction-quick-reference) synchronisiert und sichern die Artefakte für die
[Phase‑3 Acceptance Checklist](phase3_acceptance.md#observability-dashboards--alerts).【F:docs/runbooks/oncall.md†L47-L56】

1. **Alert `ConsensusVRFSlow` (warning).** Prüfe das Histogramm
   `consensus_vrf_verification_time_ms` nach `result="success"` und verifiziere, dass der p95-Wert
   über 50 ms bleibt. Korrelierte Ursachen sind CPU- oder GPU-Sättigung – kontrolliere die Node-Hardware
   via `top`/`nvidia-smi` und vergleiche den `prove_ms`-Trend aus dem letzten Regression-Lauf
   (`regression.json`).【F:docs/observability/consensus.md†L1-L70】【F:tools/simnet/src/bin/regression.rs†L1-L240】 Drossele Testlasten
   oder starte die GPU-Runtime neu, bevor das Latency-Budget dauerhaft überschritten wird.
2. **Alert `ConsensusVRFFailureBurst` (page).** Wurde in den letzten fünf Minuten mehr als zweimal
   `result="failure"` gezählt, ermittele die `reason`-Labels und suche in `node.log` nach `invalid VRF proof`.
   Bestätige über das Regressionstool (`cargo run -p simnet --bin regression`), dass Manipulationen weiterhin
   abgelehnt werden, bevor du die Runde erneut startest.【F:tools/simnet/src/bin/regression.rs†L96-L214】 Fehlende Ablehnungen
   deuten auf Konfigurations- oder Schlüsselprobleme hin.
3. **Alert `ConsensusQuorumVerificationFailure` (page).** Notiere den `reason`-Tag des Counters
   `consensus_quorum_verifications_total`, vergleiche ihn mit den Tamper-Fällen der Regression und
   auditier die betroffenen Validatoren. Ein Quorum-Failure deutet auf manipulierte Zertifikate hin –
   stoppe Blockproduktion, analysiere Logs und eskaliere an das Consensus-Team, falls der Fehler nach
   erneuter Validierung bestehen bleibt.【F:docs/observability/alerts/consensus_vrf.yaml†L27-L47】

> 📌 Dokumentiere jeden Alert im Incident-Log (Zeit, Labels, Gegenmaßnahmen) und verlinke Regression-
>  bzw. Dashboard-Artefakte. Der Playbook-Eintrag dient Auditor:innen als Nachweis, dass Phase‑2-Alarme
>  reproduzierbar und mit klaren Eskalationspfaden hinterlegt sind.

| Symptom | Check | Action |
| --- | --- | --- |
| Alert `root_io_error_rate` fires | Confirm the trigger by querying `sum(increase(rpp_node_pipeline_root_io_errors_total[5m]))` in Prometheus or inspecting the dedicated Grafana stat panel for spikes. Validate that related dashboards still receive pipeline updates and correlate with recent Firewood lifecycle logs containing `root read failed` markers.【F:rpp/node/src/telemetry/pipeline.rs†L12-L73】【F:storage/src/nodestore/mod.rs†L661-L701】 | Treat the incident as a Firewood storage fault: pause snapshot ingestion, audit the underlying object store or block device for I/O errors, then run `firewood_recovery` to rebuild or validate the affected roots before re-enabling peers. Escalate if the counter keeps climbing after recovery or if the WAL drill reports persistent corruption.【F:storage-firewood/src/bin/firewood_recovery.rs†L36-L105】【F:storage-firewood/src/lifecycle.rs†L18-L37】 |
| `/state-sync/chunk/:id` returns 5xx with `ProofError::IO` in the body | Inspect the labelled Prometheus counters/histograms `rpp.runtime.rpc.request.total` and `rpp.runtime.rpc.request.latency` for spikes tagged `method="other"`, `result="server_error"`, then confirm the Firewood pipeline recorded the failure by checking `sum(increase(rpp_node_pipeline_root_io_errors_total[5m])) > 0` on the Prometheus endpoint or the dedicated Grafana stat panel.【F:rpp/runtime/telemetry/metrics.rs†L111-L139】【F:rpp/rpc/api.rs†L1147-L1168】【F:rpp/runtime/node.rs†L4031-L4056】【F:rpp/node/src/telemetry/pipeline.rs†L12-L73】 Correlate the spike with logs containing the `ProofError::IO` marker emitted by state-sync chunk handlers.【F:rpp/runtime/node.rs†L4031-L4056】 | Audit the Firewood snapshot store backing state sync for I/O faults, then rerun the `firewood_recovery` tooling to rebuild or validate the affected chunks before re-enabling peers; escalate if repeated `ProofError::IO` markers appear after recovery.【F:rpp/runtime/node.rs†L4031-L4056】【F:storage-firewood/src/bin/firewood_recovery.rs†L36-L105】 |
| OTLP backend shows no traces or metrics | Inspect startup logs for `telemetry disabled` or `telemetry enabled without explicit endpoint` to confirm whether telemetry was activated.【F:rpp/node/src/lib.rs†L442-L481】 | Enable `rollout.telemetry.endpoint` (and optional HTTP mirror) in the active config or pass `--telemetry-endpoint` on the CLI; hybrid/validator templates ship with telemetry enabled for convenience.【F:rpp/runtime/config.rs†L894-L907】【F:config/hybrid.toml†L41-L46】【F:config/validator.toml†L41-L45】【F:rpp/node/src/lib.rs†L143-L208】 |
| `/observability` dashboards lack pipeline data | Call `/wallet/pipeline/telemetry` or `/p2p/peers` on the RPC service to confirm the orchestrator is publishing snapshots (include the Authorization header when RPC auth is enabled[^rpc-auth]).【F:rpp/rpc/api.rs†L984-L1067】【F:rpp/runtime/orchestration.rs†L611-L615】 | If the summary is empty, ensure the node runtime is running (see startup runbook) and that the pipeline orchestrator logged `pipeline orchestrator started`. Restart after resolving config or network issues and review the [pipeline telemetry dashboards](../observability/pipeline.md) for stalled phases.【F:rpp/node/src/lib.rs†L494-L552】 |
| Admission telemetry flags unknown peers or auditors request a policy dump | Run `curl -H "Authorization: Bearer ${RPP_RPC_TOKEN}" https://rpc.example.org/p2p/admission/policies` to inspect the persisted allowlist tiers and sorted blocklist snapshot.【F:rpp/rpc/src/routes/p2p.rs†L126-L157】 | Issue `POST /p2p/admission/policies` with an `actor` (and optional `reason`) to add or remove entries; duplicates or allowlist/blocklist conflicts return a `400` so failed attempts land in the incident log before retrying.【F:rpp/rpc/src/routes/p2p.rs†L158-L209】 Query `GET /p2p/admission/audit?offset=0&limit=50` (bearer token required) to review the append-only audit log and confirm who requested the change, the timestamp, and the previous/current state. Rotate the JSONL log in line with `network.admission.audit_retention_days` to keep the evidence trail manageable.【F:rpp/rpc/src/routes/p2p.rs†L110-L153】【F:rpp/p2p/src/policy_log.rs†L1-L112】【F:rpp/runtime/config.rs†L942-L1004】 |
| Need to diff or restore previous admission policies | `cargo run -p rpp-chain -- validator admission backups list` lists the archived snapshots and `download` fetches the selected archive to disk with the correct RPC URL/token from the validator profile.【F:rpp/node/src/main.rs†L151-L408】 | Use `cargo run -p rpp-chain -- validator admission restore` (or `POST /p2p/admission/backups`) with the backup name, actor, optional reason, and approvals to roll back to a known-good snapshot; the peerstore prunes backups according to `network.admission.backup_retention_days` so copy out relevant archives before restoring.【F:rpp/rpc/src/routes/p2p.rs†L90-L225】【F:rpp/p2p/src/peerstore.rs†L1090-L1157】 |
| Grafana shows `firewood.nodestore.root.read_errors` or `firewood.snapshot.ingest.failures` climbing | Confirm the spike is real by querying the labelled counters in Prometheus (`sum by (state)(increase(firewood_nodestore_root_read_errors_total[5m]))`, `sum by (reason)(increase(firewood_snapshot_ingest_failures_total[5m]))`). Inspect the Firewood lifecycle logs for `root read failed` or `snapshot manifest` errors and check the WAL recovery drill output.【F:storage/src/nodestore/mod.rs†L661-L701】【F:storage-firewood/src/lifecycle.rs†L14-L248】【F:storage-firewood/src/bin/firewood_recovery.rs†L36-L171】 | Treat the incident as data loss: pause snapshot ingestion, run the `firewood_recovery` utility to rebuild state, and only resume once the counters flatten. Escalate if the recovery gauge `firewood.recovery.active` stays non-zero after the workflow finishes.【F:storage-firewood/src/bin/firewood_recovery.rs†L62-L171】 |
| `pipeline_submissions_total` metrics report many `reason="tier_requirement"` rejections | Review the labelled counter from the metrics backend; the orchestrator records tier and gossip errors when rejecting workflows.【F:rpp/runtime/orchestration.rs†L623-L704】 | Investigate the submitting account’s reputation tier via `/wallet/reputation/:address` (include the Authorization header when RPC auth is enabled[^rpc-auth]) or adjust the workflow policy; see [modes](../modes.md) for role-specific submission expectations.【F:rpp/rpc/api.rs†L984-L1059】 |
| Slashing dashboards show `kind=censorship` oder `kind=inactivity` Ausschläge | Prüfe `rpp.node.slashing.events_total` und `queue_segments` nach Validator-IDs mit gehäuften Meldungen; korreliere mit `consensus`-Logs für `registered censorship trigger` bzw. `registered inactivity trigger`.【F:rpp/node/src/telemetry/slashing.rs†L59-L93】【F:rpp/consensus/src/state.rs†L1000-L1199】 | Abgleich mit den in `consensus.config` gesetzten Grenzwerten (`censorship_vote_threshold`, `censorship_proof_threshold`, `inactivity_threshold`) und Validator-Runbooks; wiederholte Treffer deuten auf blockierte Votes/Proofs oder dauerhaftes Fernbleiben hin. Fordere betroffene Operatoren zur Netzwerkanalyse auf und evaluiere Slashing-/Ersatzmaßnahmen anhand der Testfälle.【F:tests/consensus/censorship_inactivity.rs†L1-L260】 |

## Firewood-Pruning-IO-Bottleneck {#firewood-pruning-io-bottleneck}

Sowohl `FirewoodPruningIoBottleneckWarning` als auch `FirewoodPruningIoBottleneckCritical` feuern,
wenn die Durchsatz-Histogramme `rpp.node.pruning.io_throughput_bytes_per_sec` länger als den
Schwellwert unter Last bleiben und gleichzeitig `missing_heights` bzw. `time_remaining_ms` größer
als null sind.【F:rpp/node/src/telemetry/pruning.rs†L21-L125】【F:ops/alerts/storage/firewood.yaml†L70-L120】 Beobachte die
gleiche Label-Kombination (`shard`, `partition`, `reason`) auf den korrespondierenden Backlog- und
ETA-Metriken, um Stalls einzukreisen.

1. **Pruning pausieren.** Stoppe laufende Zyklen mit `rppctl pruning pause`, damit weitere
   Checkpoints die langsame Platte nicht füllen.【F:rpp/node/src/services/pruning.rs†L740-L800】
2. **IO-Pfade prüfen.** Vergleiche `io_bytes_written` und `io_duration_ms` aus dem aktuellen
   `/snapshots/pruning/status` Response, um zu bestätigen, dass der Durchsatz knapp über `1 MiB/s`
   liegt. Wechsle falls möglich auf einen lokalen NVMe-Mount für `snapshot_dir`/`proof_dir`.
3. **Budgets anheben.** Erhöhe `storage.firewood.commit_io_budget_bytes` und
   `storage.firewood.compaction_io_budget_bytes` gemäß der [Firewood-Storage-Anleitung](../storage/firewood.md#io-budget-und-pruning-throttling),
   damit die Hintergrund-Writer die fehlenden Höhen schneller abtragen.
4. **Wieder aufnehmen.** Sobald die 10‑Minuten-Durchschnittswerte über dem Warnschwellenwert
   liegen und `missing_heights` fällt, setze `rppctl pruning resume` und beobachte, ob das
   Zeitbudget `time_remaining_ms` wieder sinkt. Missglückt der Versuch, migriere die Pruning-
   Verzeichnisse auf ein schnelleres Volume.


### Firewood storage alert reference

Import the storage-focused Prometheus rules in [`ops/alerts/storage/firewood.yaml`](../../ops/alerts/storage/firewood.yaml)
to match the thresholds summarised in [Firewood storage monitoring](../storage/monitoring.md).【F:ops/alerts/storage/firewood.yaml†L1-L139】【F:docs/storage/monitoring.md†L1-L21】 The
subsections below expand on the linked runbook URLs referenced by the alert annotations.

#### Firewood WAL queue depth

1. **Confirm backlog.** Graph `max(firewood_nodestore_unwritten_nodes)` over the last 15 minutes to verify the
   warning (>1 000) or critical (>5 000) threshold that fired.【F:docs/storage/monitoring.md†L9-L11】 The
   gauge reflects staged nodes waiting for persistence, so large values indicate WAL pressure.【F:storage/src/nodestore/mod.rs†L468-L498】【F:storage/src/nodestore/persist.rs†L348-L470】
2. **Correlate with IO budgets.** Compare `firewood.storage.io_budget{stage="commit"|"compaction"}` with the
   provisioned budgets to determine whether workloads outgrew the documented envelope.【F:storage-firewood/src/state.rs†L201-L210】【F:docs/storage/firewood.md†L60-L88】 Adjust `storage.commit_io_budget_bytes` only after identifying upstream causes for larger batches.
3. **Mitigate sustained back-pressure.** Throttle intake (pause new submissions or snapshots) and review
   disk latency. If the queue only drains after switching to `storage.sync_policy="deferred"`, plan to return
   to `"always"` once the backlog clears and document the temporary change in the incident log.【F:docs/storage/firewood.md†L71-L93】

#### Firewood WAL flush failures

1. **Inspect failure counters.** Check `increase(rpp_runtime_storage_wal_flush_total{outcome="failed"}[5m])` and the retry
   variant to confirm whether the alert was triggered by hard failures or repeated retries.【F:docs/storage/monitoring.md†L12-L12】
2. **Audit the filesystem.** Review kernel logs and disk SMART data for IO errors, then evaluate whether temporarily relaxing
   `storage.sync_policy` is required to flush pending writes while keeping crash consistency documented.【F:docs/storage/firewood.md†L78-L83】
3. **Run the recovery drill.** Execute `firewood_recovery` to rebuild the WAL, verifying that the counter
   `firewood.recovery_runs_total{phase="complete"}` increments when the workflow finishes.【F:storage-firewood/src/bin/firewood_recovery.rs†L62-L171】 Only resume new commits once flushes succeed without retries.

#### Firewood WAL corruption

1. **Validate rolled-back transactions.** Query `increase(firewood_wal_transactions_total{result="rolled_back"}[15m])` to
   quantify how many incomplete transactions were discarded during replay.【F:docs/storage/monitoring.md†L13-L13】 Values > 0 imply a truncated WAL or abrupt shutdown.【F:storage-firewood/src/kv.rs†L120-L165】
2. **Inspect recent shutdowns.** Review system logs for power loss or OOM kills that might have interrupted commits before
   the matching `Commit` record was written. Document findings alongside the incident report.
3. **Restore from known-good state.** Run the recovery workflow and, if repeated rollbacks occur, rebuild from the latest
   snapshot bundle before re-enabling peer ingestion.【F:storage-firewood/src/bin/firewood_recovery.rs†L62-L171】

#### Firewood snapshot ingest failures

1. **Check labelled reasons.** Inspect `sum by (reason)(increase(firewood_snapshot_ingest_failures_total[15m]))` to pinpoint
   whether manifests were missing, checksum mismatches occurred, or proofs were rejected.【F:docs/storage/monitoring.md†L14-L14】【F:storage-firewood/src/lifecycle.rs†L14-L248】
2. **Validate artefacts.** Re-fetch the offending manifest and proof from the object store, verifying checksums before retrying
   ingestion. If proofs repeatedly fail, escalate to engineering with the captured artefacts.
3. **Coordinate with snapshot consumers.** Pause downstream replay while the bundle is rebuilt to prevent inconsistent state from propagating.

#### Firewood root read errors

1. **Quantify failures.** Use `sum by (state)(increase(firewood_nodestore_root_read_errors_total[5m]))` to determine whether
   the committed or immutable trie is failing to load.【F:docs/storage/monitoring.md†L15-L15】【F:storage/src/nodestore/mod.rs†L687-L719】 Persistent growth points to on-disk corruption or hardware faults.
2. **Triaging storage.** Audit the backing volume for IO errors and run `firewood_recovery` to verify roots before resuming
   ingestion.【F:storage-firewood/src/bin/firewood_recovery.rs†L62-L171】 Document remediation steps in the incident record.

#### Firewood recovery stuck

1. **Confirm the stall.** Verify that `firewood_recovery_active` has remained > 0 and that starts exceed completes within the
   alert window, matching the rule definitions.【F:docs/storage/monitoring.md†L16-L16】【F:ops/alerts/storage/firewood.yaml†L92-L115】
2. **Review logs and output.** Inspect the recovery drill logs and generated report to understand the current phase; restart
   the workflow with fresh directories if the process is wedged.【F:storage-firewood/src/bin/firewood_recovery.rs†L62-L171】
3. **Escalate if unable to complete.** Engage the storage on-call after one failed restart or if corruption prevents replaying the WAL.

#### Firewood snapshot lag

1. **Validate lag trends.** Plot `snapshot_stream_lag_seconds` to confirm the > 30 s (warning) or > 120 s (critical)
   threshold sustained over the alert duration.【F:docs/storage/monitoring.md†L17-L17】 The metric is exported by the snapshot
   behaviour and captures end-to-end delay across sessions.【F:rpp/p2p/src/behaviour/snapshots.rs†L462-L499】
2. **Correlate with pipeline metrics.** Check `snapshot_bytes_sent_total` and pipeline stage counters to determine whether
   producers are stalled or consumers are slow.【F:docs/observability/pipeline.md†L32-L44】 Compare against network health and peer logs before failing over.
3. **Follow snapshot failover procedures.** Use the [network snapshot failover runbook](network_snapshot_failover.md) to reroute
   lagging consumers or restart stuck sessions, recording actions in the incident log.

## Admission-Audit-Abfragen

Nutze die Audit-Endpunkte, um Policy-Änderungen nachvollziehbar zu dokumentieren:

1. **Policysnapshot ziehen.** `curl -sS -H "Authorization: Bearer ${RPP_RPC_TOKEN}" ${RPP_RPC_URL}/p2p/admission/policies | jq .`
   legt den aktuellen Allow-/Blocklist-Stand offen und wird gemeinsam mit der CLI-Ausgabe im Incident-Log abgelegt.【F:rpp/rpc/src/routes/p2p.rs†L126-L209】
2. **Audit-Log paginieren.** `curl -sS -H "Authorization: Bearer ${RPP_RPC_TOKEN}" "${RPP_RPC_URL}/p2p/admission/audit?offset=0&limit=50" | jq .`
   liefert die jüngsten Änderungen inklusive `actor`, `reason` und `approvals`. Exportiere die JSONL-Datei oder Screenshot in das
   [On-Call-Handbuch](./oncall.md#admission-audit) und verlinke den Export in der [Phase‑3 Acceptance Checklist](phase3_acceptance.md#tier-admission-persistenz--audit).【F:rpp/rpc/src/routes/p2p.rs†L110-L209】【F:docs/runbooks/phase3_acceptance.md†L13-L42】【F:docs/runbooks/oncall.md†L35-L45】
3. **Retention bestätigen.** Prüfe, dass `network.admission.audit_retention_days` im Konfig-Dump zur Größe der JSONL-Dateien passt;
   Abweichungen deuten auf fehlende Rotation oder zu kurze Retention hin.【F:rpp/runtime/config.rs†L942-L1004】 Dokumentiere Korrekturen im Incident-Log, damit das Audit-Trail konsistent bleibt.

[^rpc-auth]: RPC endpoints require an `Authorization` header when authentication is enabled; review the [API security hardening guide](../API_SECURITY.md) for token lifecycle management.

## Telemetry exporter checklist

1. Confirm `rollout.telemetry` is enabled and points to a valid HTTP/OTLP endpoint; validation rejects
   empty, scheme-less, or unauthenticated URIs.【F:rpp/runtime/config.rs†L1729-L1779】
2. Verify CLI overrides (`--telemetry-endpoint`, `--telemetry-auth-token`, `--telemetry-sample-interval`)
   are correct; these flags replace file-based settings when present.【F:rpp/node/src/lib.rs†L143-L208】【F:rpp/node/src/lib.rs†L1045-L1080】
3. If metrics still fail to export, increase `trace_max_queue_size` or
   `trace_max_export_batch_size` to reduce drop pressure on the OpenTelemetry batcher before restarting.
   Validation enforces sane, non-zero limits.【F:rpp/runtime/config.rs†L1729-L1779】

## Pipeline dashboards

* The orchestrator publishes telemetry summaries and dashboard streams that back `/wallet/pipeline/*`
  endpoints; lack of updates usually indicates the node runtime never started or shut down unexpectedly.
  Look for `node runtime started` and `pipeline orchestrator started` markers, then inspect shutdown
  logs for cancellations.【F:rpp/runtime/orchestration.rs†L611-L615】【F:rpp/node/src/lib.rs†L442-L557】
* Metrics counters such as `pipeline_submissions_total` emit reasons (`tier_requirement`,
  `gossip_publish`, etc.) when workflows are rejected, making it easier to correlate RPC clients with
  policy failures.【F:rpp/runtime/orchestration.rs†L623-L704】
* Stage-level latency, throughput, and Firewood commit heights are documented in
  [pipeline telemetry dashboards](../observability/pipeline.md); consult them when diagnosing gaps
  between wallet intake, proof validation, BFT finality, and storage commits.
* Validiert Abweichungen mit dem Smoke-Test `tests/pipeline/end_to_end.rs` oder den in
  [Pipeline Lifecycle](../lifecycle/pipeline.md) beschriebenen Hooks, um sicherzustellen, dass
  Instrumentierung und Dashboards synchron zur Orchestrator-Pipeline laufen.【F:tests/pipeline/end_to_end.rs†L1-L122】【F:docs/lifecycle/pipeline.md†L1-L86】

If health probes fail, jump to the [startup runbook](startup.md); persistent issues should be logged
for follow-up in the [operator checklist](../checklists/operator.md).

Regression coverage: [`tests/state_sync/proof_error_io.rs`](../../tests/state_sync/proof_error_io.rs)
asserts that `/state-sync/chunk/:id` surfaces a 500 with a `ProofError::IO(...)` payload and records
`rpp.runtime.rpc.request.{total,latency}` samples labelled `method="other"`,
`result="server_error"`, ensuring observability signals remain wired.【F:tests/state_sync/proof_error_io.rs†L1-L96】

