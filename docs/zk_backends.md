# ZK-Backends

> **Breadcrumbs:** [Operator documentation index](./README.md) › [Zero-knowledge backend procedures](./README.md#zero-knowledge-backend-procedures) › ZK-backends
>
> **Complementary guides:** [Observability runbook](./runbooks/observability.md),
> [Security policy & reporting](../SECURITY.md),
> [RPP vendor refresh procedure](./operations/rpp_vendor_update.md),
> [Incident response runbook](./operations/incidents.md)

## Dependency pinning and review

- The STWO backend snapshot is distributed as `prover/prover_stwo_backend/stwo-dev.zip`
  and unpacked into `vendor/stwo-dev/0.1.1/staging` with recorded hashes under
  `vendor/stwo-dev/0.1.1/manifest/`. CI validates the archive digest and every
  staged file against `manifest/final_file_list.txt` and the integrity summary
  before builds proceed.【F:scripts/ci/validate_prover_deps.py†L9-L105】【F:vendor/stwo-dev/0.1.1/manifest/integrity_summary.json†L1-L27】
- The Plonky3 offline mirror is pinned via `third_party/plonky3/manifest/checksums.json`;
  the same CI check recomputes the SHA256 for each mirrored crate and fixture to
  catch drift.【F:scripts/ci/validate_prover_deps.py†L107-L123】【F:third_party/plonky3/manifest/checksums.json†L1-L119】
- Release builds refuse to continue when either manifest changes between tags
  without an explicit `prover_dep_reviewer` acknowledgement in the dispatch
  inputs, ensuring vendor refreshes receive manual sign-off.【F:.github/workflows/release.yml†L18-L44】【F:.github/workflows/release.yml†L46-L79】
- When intentionally refreshing STWO, replace `prover/prover_stwo_backend/stwo-dev.zip`,
  regenerate `vendor/stwo-dev/0.1.1/manifest/final_file_list.txt` via
  `scripts/vendor_stwo/update_manifest.py`, and rerun the integrity check so the
  manifest and recorded hash stay aligned.【F:scripts/vendor_stwo/update_manifest.py†L1-L140】【F:scripts/ci/validate_prover_deps.py†L9-L105】

## Backend-Interoperabilität im Simnet

- Das Simnet-Profil `mixed-backend-interop` kombiniert STWO-, Plonky3- und
  Groth16-Labelsets in einer Small-World-Topologie, erzwingt Finalitäts- und
  Mempool-Kohärenz trotz Partition, Churn und byzantinischem Spam und schreibt
  JSON/CSV-Summaries mit Backend-Attribution (`SIMNET_BACKEND_ATTRIBUTION`).【F:scenarios/mixed_backend_interop.toml†L1-L78】【F:tools/simnet/scenarios/mixed_backend_interop.ron†L1-L32】
- Nightly-CI führt das Profil im Job `simnet-mixed-backend` mit dem
  Produktions-Prover und aktivierter Plonky3-Verifier-Implementierung aus,
  bündelt Logs/Summaries unter
  `target/simnet/mixed-backend-interop-nightly/` und lädt das Archiv als
  `simnet-mixed-backend-interop` hoch.【F:.github/workflows/nightly.yml†L120-L155】
- GPU-Proving und Multi-Prover-Failover sind im Profil bewusst deaktiviert; für
  GPU/L2-Skalierungsfragen gelten weiterhin die separaten `zk-load-harness`-
  und `uptime`-Drills.

- Das zusätzliche Profil `prover-acceleration-mix` fährt zwei Plonky3-Proof-
  Läufe hintereinander: einmal mit explizit deaktiviertem GPU-Path
  (`PLONKY3_GPU_DISABLE=1`, `use_gpu_acceleration=false`) und einmal mit
  angefordertem GPU-Path (`use_gpu_acceleration=true`). Die Tests schreiben die
  Latenzen, Proof-Größen und Cache-/Queue-Health unter
  `cpu_gpu_prover_mix.json` und brechen ab, sobald CPU-Beweise GPU-Metadaten
  tragen oder Proof-Größen fehlen.【F:tools/simnet/scenarios/prover_acceleration_mix.ron†L1-L37】【F:rpp/proofs/plonky3/tests.rs†L105-L207】【F:.github/workflows/nightly.yml†L1338-L1397】

- Nightly-CI startet das Profil im Job `simnet-prover-acceleration` mit den
  Features `backend-plonky3-gpu`, sammelt die Summaries unter
  `target/simnet/prover-acceleration-mix-nightly/summaries/` und verifiziert
  CPU/GPU-Interop über den Python-Validator im Workflow. Artefakte werden als
  `simnet-prover-acceleration-mix-…` hochgeladen.【F:.github/workflows/nightly.yml†L1338-L1397】

## Kompatibilität & Rollout-Fallen

- Der Umschaltpunkt auf Nova V2 folgt den in `ProofVersion::configure_cutover`
  hinterlegten Grenzwerten. Upgegradete Knoten akzeptieren sowohl Aggregated V1
  (vor dem Grenzwert) als auch Nova V2 (ab dem Grenzwert). Legacy-Knoten, die
  den Cutover nicht kennen, lehnen Nova-Payloads konsequent ab; sie müssen vor
  dem Grenzwert aktualisiert oder offline genommen werden, um Forks zu
  vermeiden.【F:rpp/runtime/types/block.rs†L2977-L3044】
- Proof-Downloads verwenden die serialisierte `GlobalProofHandleSummary` aus dem
  Header. Die JSON-Repräsentation bleibt stabil über beide Versionen hinweg und
  reicht aus, um Commitment, VK-ID und Versionslabel korrekt aufzulösen; Fetcher
  dürfen deshalb nur den Handle-Content prüfen und anschließend das Payload
  erneut verifizieren, um inkonsistente Transportpfade zu erkennen.【F:rpp/runtime/types/block.rs†L3046-L3093】
- Operativer Workaround für inkompatible Alt-Nodes: Cutover-Schwellen per
  `ProofVersion::configure_cutover` temporär zurücksetzen, damit die Knoten
  Aggregated V1 weiter prüfen können, und sie dann mit aktualisierter Binärdatei
  oder konfiguriertem Nova-Cutover neu starten. Dauerhafter Betrieb jenseits des
  offiziellen Grenzwerts ist nicht unterstützt und sollte nur zur Incident-
  Eindämmung genutzt werden.【F:rpp/runtime/types/block.rs†L2987-L3044】

## Beschleunigte Prover-Läufe

- Der Nightly-Workflow enthält einen optionalen Accelerator-Lauf
  (`prover-accelerator`), der die Plonky3-GPU-Features mit
  `PLONKY3_GPU_DISABLE=0` ausführt und Laufzeitmetriken im Step-Summary sowie
  das Log als Artefakt `prover-accelerator-log` ablegt.
- Läufer ohne dedizierte Hardware werden automatisch erkannt: schlägt sowohl
  `nvidia-smi -L` als auch `rocminfo` fehl, markiert die Pipeline den Schritt als
  „skipped“ und lässt die übrigen Nightly-Jobs normal weiterlaufen. Das Summary
  dokumentiert die Auslassung explizit, damit Operator:innen fehlende GPU-
  Kapazität sofort sehen.【F:.github/workflows/nightly.yml†L951-L1020】
- Lokale Reproduktion: baue die Tests mit `cargo test -p plonky3-backend
  --no-default-features --features plonky3-gpu -- --nocapture` und stelle sicher,
  dass eine GPU über `nvidia-smi -L` oder `rocminfo` sichtbar ist. Setze
  `PLONKY3_GPU_DISABLE=1`, falls der Fallback auf CPU-Pfade geprüft werden soll;
  die Tests schlagen dann deterministisch fehl, wenn der GPU-Code fälschlich
  weiter genutzt würde.【F:prover/plonky3_backend/README.md†L6-L19】【F:prover/plonky3_backend/src/gpu.rs†L3-L78】
- Performance-Erwartung: Das Nightly-Log enthält die gemessene Laufzeit in
  Sekunden, sodass Abweichungen zwischen GPU-Typen oder Treiber-Versionen
  sichtbar werden. Hinterlegte Dashboards sollten dieselben Artefakte
  referenzieren, wenn GPU-Kapazität in Clustern bereitgestellt wird.

### Gemischte Hardware-Deployments (CPU + GPU)

- Für Validator-/Prover-Fleets mit heterogener Hardware sollte
  `plonky3.use_gpu_acceleration` pro Node gemäß Hardware-Inventar gesetzt
  werden; GPU-Hosts verwenden `true`, CPU-Only-Hosts `false` oder
  `PLONKY3_GPU_DISABLE=1` als env-Override. Beide Pfade bleiben interoperabel,
  solange `proof_version` konsistent bleibt.【F:rpp/proofs/plonky3/tests.rs†L105-L207】
- Queue- und Latenzmetriken lassen sich pro Pfad getrennt beobachten: die
  Summaries aus `prover-acceleration-mix` liefern Prove/Verify-Zeiten und
  Proof-Größen pro Modus (`cpu`/`gpu`), während die produktiven Queue-Metriken
  (`wallet.prover.queue.*`, `wallet.prover.priority_slots`) weiterhin nach
  Backend/Classe labeln. Bei GPU-Drain sollte `PLONKY3_GPU_DISABLE=1` gesetzt
  und die Priority-Slots erhöht werden, bis die P95-Wartezeiten wieder unter
  10 s fallen.【F:rpp/proofs/plonky3/tests.rs†L105-L207】【F:telemetry/prometheus/runtime-rules.yaml†L335-L360】
- Rollouts im Mischbetrieb: zuerst GPU-fähige Validatoren aktualisieren, dann
  CPU-Knoten. Bleiben GPU-Knoten leer oder melden niedrige `proofs_generated`
  im `cpu_gpu_prover_mix.json`, Logs auf `GPU_DISABLE_ENV` und fehlende Treiber
  prüfen, bevor die GPU-Features wieder aktiviert werden.【F:rpp/proofs/plonky3/tests.rs†L105-L207】【F:.github/workflows/nightly.yml†L1338-L1397】

## Warmup-Dauer und Kaltstarts

- Wallet-Prover messen seit dem Start die Warmup-Dauer pro Backend: das Laden
  der Circuit-Artefakte (Stage `stage="circuit_load"`) und den ersten
  Keygen-Lauf (`stage="keygen"`). Die Histogramme liegen unter
  `wallet.prover.warmup_ms{backend,stage}`, Alerts zählen unter
  `wallet.prover.warmup.alerts{backend,stage}`. Schwellen: ≥5 s für Circuit-Load
  und ≥30 s für Keygen triggern einen Alert sowie einen Warn-Logeintrag mit
  Dauer/Threshold.【F:rpp/wallet/src/engine/signing/prover.rs†L41-L47】【F:rpp/wallet/src/engine/signing/prover.rs†L86-L117】
- Kaltstarts (z. B. frische Container oder Nodes ohne Cache) sollten die
  Warmup-Histogramme kurzzeitig füllen, aber keine wiederholten Alerts auslösen.
  Wenn `wallet.prover.warmup.alerts` kontinuierlich wächst, Backend-Logs auf
  Hardware-Engpässe (GPU disabled, IO-Limits) prüfen und ggf. die Warmup-Phase
  durch Preloading-Skripte oder längere Liveness-Grace-Periods abfedern.
- Für zweistufige Setups mit Fallback-Prover (Primary STWO, Secondary Mock)
  erscheinen beide Backends im Warmup-Monitoring. Alerts auf dem Fallback
  deuten meist auf CPU-Drossel oder fehlende Ressourcen im Primary hin; die
  Warnung wird zusammen mit `primary`/`fallback` im Prover-Log ausgegeben und
  sollte in der On-Call-Doku verlinkt werden.

## rpp-stark (stable)

### Aktivierung

- Optionales Feature `backend-rpp-stark` aktivieren, z. B. `cargo build --features backend-rpp-stark`.
- Die Node-Konfiguration muss `max_proof_size_bytes` setzen (Standard: 4 MiB). Der Wert wird beim Bootstrapping an den Verifier weitergereicht.
- `ProofVerifierRegistry::with_max_proof_size_bytes` (siehe `rpp/proofs/proof_system/mod.rs`) initialisiert den `RppStarkVerifier` mit der konfigurierten Grenze und blockiert Starts mit übergroßen Limits (> `u32::MAX`).

### Interop-Test

- Golden Vectors liegen unter `vendor/rpp-stark/vectors/stwo/mini/`.
- Testaufruf: `cargo test --features backend-rpp-stark --test interop_rpp_stark`.
- CI-Absicherung: Der GitHub-Actions-Workflow `nightly-simnet` (Job `simnet`) führt den Test als Teil seiner Matrix-Läufe bei jedem nächtlichen Durchlauf aus.
- Prüft Digest, Stage-Flags (`params`, `public`, `merkle`, `fri`, `composition`), Proof-Länge und Trace-Indizes.
- Die Backend-Unit-Suite schreibt die Checksummen der Golden-Vector-Artefakte sowie die verifizierte Proof-Länge, Stage-Flags und Telemetrie (falls vorhanden) nach `logs/rpp_golden_vector_checksums.log` und vergleicht sie in CI gegen die Basislinie `tests/baselines/rpp_golden_vector_checksums.log`. Drift blockiert den Lauf; legitime Updates werden über `tools/update_rpp_golden_vector_baseline.sh` übernommen.
- Die Pruning-Snapshot-Replays unter `wallet_snapshot_round_trip_*` (siehe `tests/pruning_cross_backend.rs`) hängen eine zk-Validierung an: der Default-Backend-Lauf erzeugt eine STWO-Transaktionsprobe, während der `backend-rpp-stark`-Zweig den Golden Vector verifiziert, nachdem WAL-Inhalte und Snapshots wiederhergestellt wurden. Beide Pfade laufen im CI-Job `pruning-checkpoints` mit `--features prover-stwo` bzw. `--features backend-rpp-stark`.

### Public-Inputs-Encoding

- Byte-Layout ist in `vendor/rpp-stark/docs/PUBLIC_INPUTS_ENCODING.md` dokumentiert.
- Der Adapter `rpp/chain/src/zk/rpp_adapter/public_inputs.rs` nutzt dieselbe Little-Endian-Kodierung und Hashing-Strategie.

### Proof-ABI-Versionierung & Guardrails

- `PROOF_VERSION` ist in `vendor/rpp-stark/src/proof/types.rs` hinterlegt und steuert den Serialisierungsvertrag für Header,
  Transcript-Labels und Merkle-Bundles. Jede Änderung an `rpp/chain/src/zk/`, `rpp/proofs/`, den Prover-Backends unter
  `prover/` (inklusive `params/`-Artefakten) oder den Golden-Vectors in `vendor/rpp-stark/` erfordert einen Versionssprung.
- Auch testgetriebene Layout-Änderungen – z. B. angepasste Snapshots (`tests/snapshots/proof_*`), Fail-Matrix-Fakes oder neue
  Interop-Vektoren – müssen mit einem `PROOF_VERSION`-Bump und dokumentiertem Proof-Metadata-Update gekoppelt werden.
- Änderungen an Circuit-Artefakten (`prover/plonky3_backend/params/`, `prover/prover_stwo_backend/params/`) verlangen neben dem
  Versionssprung auch einen CHANGELOG-Eintrag mit explizitem PROOF_VERSION-Hinweis; der Guard schlägt fehl, sobald Circuit-Diffs
  ohne Versionserhöhung oder Changelog-Anker auftreten.
- Mixed-rollout-Absicherung: `mixed_circuit_versions_reject_incompatible_proofs` zwingt in Tests, dass Nodes mit alten und neuen
  Circuits Proofs mit abweichendem `PROOF_VERSION` explizit ablehnen. Der CI-Job `proof-version-policy` führt den Check unter
  `cargo test --test rpp_circuit_rollback --features backend-rpp-stark` bei jedem PR aus, sodass Rollbacks/Future-Proofs keine
  stillen Fallbacks mehr triggern.【F:tests/rpp_circuit_rollback.rs†L36-L110】【F:.github/workflows/ci.yml†L309-L337】
- Der Befehl `cargo xtask proof-version-guard --base origin/main` prüft diese Pfade und bricht ab, wenn die Konstanten nicht
  angepasst wurden. Nutze `--base <ref>`, wenn der Release-/Feature-Branch von einem anderen Stand als `origin/main` abzweigt.
  Der Guard liest beide Stände aus Git und gleicht die Werte aus `vendor/rpp-stark/src/proof/types.rs` und `firewood/src/proofs.rs`
  miteinander ab. Jeder Vendor-Refresh unter `vendor/rpp-stark/` (inklusive `vectors/` und Verifier-Code) gilt als proof-affecting
  und erfordert zwingend einen Bump; der CI-Job `proof-version-policy` bricht andernfalls ab.【F:xtask/src/release.rs†L1-L209】
- `cargo xtask proof-version-metadata` validiert zusätzlich, dass die Circuit-Metadaten für beide Backends die aktuelle
  `PROOF_VERSION` widerspiegeln: STWO liest `version` aus `prover/prover_stwo_backend/params/vk.json`, Plonky3 erwartet
  `metadata.proof_version` in den Setup-Dateien. Der CI-Job `proof-version-policy` führt den Check automatisch aus und
  blockiert Merges bei Drift.【F:xtask/src/release.rs†L1-L217】【F:xtask/src/main.rs†L3589-L3634】【F:xtask/src/main.rs†L5932-L6020】
- Pull-Requests, die Proof- oder ZK-Module anfassen, laufen automatisch durch den CI-Job `proof-version-policy`, der denselben
  Guard via `cargo xtask proof-version-guard` ausführt und bei Verstößen das Review blockiert.【F:.github/workflows/ci.yml†L1-L80】
- Dokumentiere jeden Bump in den Release Notes (`docs/release_notes.md`) und aktualisiere bei Bedarf zusätzliche Artefakte wie
  Telemetrie-Mappings oder Operator-Guides, damit Auditor:innen den ABI-Wechsel nachvollziehen können.

### Lasttests & Durchsatzgrenzen

- `cargo test -p rpp-chain --features "prover-stwo backend-rpp-stark" --test zk_load -- --nocapture` erzeugt parallelisierte
  Proof-Batches über STWO- und RPP-STARK-Artefakte, misst Latenzen/Throughput und erzwingt die erwarteten Size-Gate-Fehler bei
  übergroßen Beweisen (`RppStarkVerifyFailure::ProofTooLarge`). Die Suite nutzt einen STWO-Prover-Semaphor mit zwei gleichzeitig
en
  Jobs sowie drei parallele RPP-Verifier-Läufe; der minimale Durchsatz-Floor liegt bei 0,1 Proofs/Sekunde und wird als Test-Asse
rt
  geprüft.【F:tests/zk_load.rs†L1-L47】【F:tests/zk_load_common.rs†L1-L127】
- Nightly-CI führt die Suite automatisch im Job `zk-load-harness` aus, damit Größe- und Parallelitäts-Grenzen regressionssicher
  bleiben.【F:.github/workflows/nightly.yml†L273-L303】
- Der ergänzende Memory-Drift-Check `zk_load_memory` hält dieselben Lastprofile über vier Runden aufrecht, zeichnet einen DHAT-
  Heap-Trace unter `logs/zk-heap/zk-load-heap.json` auf und bricht bei RSS-Wachstum über 50 MiB ab. Der Test verwendet den
  globalen DHAT-Allocator für das Profiling, prüft weiterhin Throughput- und Oversize-Gates und stellt den Heap-Dump für spätere
  Regression-Analysen bereit.【F:tests/zk_load_memory.rs†L1-L83】
- Der Nightly-Job lädt die erzeugten Heap-Profile als Artefakt `zk-heap-profiles` hoch; schlägt die Drift-Grenze fehl, ist die
  CI-Pipeline rot und die Datei im Artefakt-Archiv dient als RCA-Einstieg. Für lokale Reproduktion einfach `cargo test -p
  rpp-chain --features "prover-stwo backend-rpp-stark" --test zk_load_memory -- --nocapture` ausführen und den DHAT-Dump mit
  `dhview` oder dem JSON-Viewer der Wahl untersuchen.【F:.github/workflows/nightly.yml†L273-L303】【F:tests/zk_load_memory.rs†L6-L83】
- Wallet-Prover-Failover: Setze optional `wallet.prover.fallback_backend = "mock"` (oder einen anderen aktivierten Backendnamen)
  in der Wallet-Konfiguration, um Überlastungen des Primärbackends transparent auf einen sekundären Pfad umzulenken. Fallbacks
  werden nur bei Überlast-Signalen (`busy`, `timeout`) aktiviert und lassen Witness-Size-Grenzen unangetastet; Telemetrie
  (`wallet.prover.fallback{primary=…,fallback=…,stage=…,reason=…}`) und Warn-Logs markieren jeden Umschaltvorgang. Die neuen
  Fallback-Tests unter `rpp/wallet/src/engine/signing/prover.rs` simulieren Überlast auf `prepare`- und `prove`-Pfaden und
  verifizieren, dass die Sekundär-Backends greifen, während Size-Gates weiter enforced bleiben
  (`cargo test -p rpp-wallet --features prover-mock fallback_router_ -- --nocapture`).【F:rpp/wallet/src/engine/signing/prover.rs†L996-L1060】
- Prover-Queue-Prioritäten: `wallet.prover.priority_slots` reserviert einen Anteil der `max_concurrency`-Permits für konsenskritische Jobs; Hintergrundproving wird verworfen, sobald diese Reserven benötigt werden. Die Queue-Metriken `wallet.prover.queue.{enqueued,pending,dropped}` und `wallet.prover.queue.backpressure` tragen das Label `{backend,class}` (z. B. `class="consensus"`) und signalisieren Backpressure, sobald alle High-Priority-Slots belegt sind. Die neuen Lasttests im Prover-Modul decken die Reservierung und Backpressure-Signale ab und verhindern Regressionen im Prioritätsmodell (`cargo test -p rpp-wallet background_jobs_respect_reserved_capacity -- --nocapture`).【F:rpp/wallet/src/config/wallet.rs†L267-L380】【F:rpp/wallet/src/engine/signing/prover.rs†L574-L1520】
- Queue-Latenzen werden zusätzlich als Histogramm `wallet.prover.queue.latency_ms{backend,circuit,class}` erfasst. Das Dashboard **Prover Queue Latency by Circuit** zeigt P50/P95/P99 pro Backend und Circuit; Zielwerte liegen bei < 1 s (P50), < 10 s (P95) und < 30 s (P99). Das neue Alert `ZkStwoProverQueueTailCritical` feuert ab 30 s P99 über zehn Minuten und verweist auf diese Tuning-Hinweise.【F:telemetry/grafana/dashboards/uptime_finality_correlation.json†L73-L124】【F:telemetry/prometheus/runtime-rules.yaml†L335-L360】【F:ops/alerts/zk/stwo.yaml†L27-L53】 Zur Entschärfung zuerst `wallet.prover.priority_slots` erhöhen oder Hintergrundjobs drosseln, dann `wallet.prover.max_concurrency` und `wallet.prover.timeout_secs` auf das dokumentierte Lastprofil abstimmen; Backlogs > 30 s sollten nach Queue-Drain unter die Schwelle fallen, andernfalls Backend wechseln oder eskalieren.
- Die Drill `zk-penalty-guardrails` lässt sowohl RPP-STARK- als auch STWO-Backends eine verpasste Slot- und Double-Sign-Sequenz
   durchlaufen, verifiziert die Proofs und prüft, dass die Konsensus-Logs `applied slashing penalty` mit dem aktiven Backend labeln.
   Alarme müssen nach dem nächsten Blockabschluss wieder auf Grün springen; schlagen sie fehl, folge den unterstehenden
   Incident-Schritten zur Backend-Isolation oder starte das Simnet-Profil `tools/simnet/scenarios/consensus_slashing_backends.ron`
   wie im Slashing-Runbook beschrieben.【F:tests/consensus/censorship_inactivity.rs†L422-L520】【F:tools/simnet/scenarios/consensus_slashing_backends.ron†L1-L27】【F:docs/runbooks/slashing_incidents.md†L1-L36】【F:.github/workflows/nightly.yml†L1013-L1066】

### Size-Gate-Mapping

- Proof-Header speichern die Obergrenze in KiB; der Node überträgt `max_proof_size_bytes` an den Verifier, der das Mapping mittels `ensure_proof_size_consistency` verifiziert.【F:tests/rpp_verifier_smoke.rs†L35-L66】【F:tests/rpp_verifier_smoke.rs†L107-L152】
- `ProofVerifierRegistry` konvertiert das Node-Limit in Bytes → KiB und lehnt Werte ab, die nicht in `u32` passen.【F:tests/rpp_verifier_smoke.rs†L35-L66】【F:tests/rpp_verifier_smoke.rs†L154-L183】
- Die Byte-Histogramme werden in fünf Buckets eingeteilt: `≤512 KiB`, `≤1 MiB`, `≤2 MiB`, `≤4 MiB`, `>4 MiB`. Sowohl erfolgreiche Prüfungen als auch Fehlversuche (inkl. Size-Gate-Fehler) aktualisieren `rpp_stark_proof_total_bytes{,_by_result}`, `rpp_stark_params_bytes`, `rpp_stark_public_inputs_bytes` und `rpp_stark_payload_bytes`, sodass Oversize-Versuche messbar bleiben.【F:rpp/runtime/node.rs†L5614-L5672】【F:rpp/runtime/node.rs†L5790-L5855】
- Überlange Artefakte liefern `RppStarkVerifyFailure::ProofTooLarge{max_kib,got_kib}`; Logs/Telemetrie enthalten `proof_bytes`, `size_bucket`, Parameter- und Payload-Größen. Beobachte `rpp_stark_proof_total_bytes_by_result{result="fail",proof_kind="consensus",le=…}` für Ausreißer oberhalb von 4 MiB.【F:rpp/runtime/node.rs†L5850-L5892】【F:rpp/runtime/node.rs†L5790-L5855】
- Per-Circuit Fehlercodes und Meldungen:
  - `ProofSizeGateError::LimitMismatch` (z. B. `proof size gate failed for RppStark/consensus: parameter limit mismatch: params=4096 KiB, node=3072 KiB`) markiert einen Widerspruch zwischen Param-Datei und Node-Limit; die Meldung enthält stets den Circuit (`transaction`, `identity`, `state`, `pruning`, `recursive`, `uptime`, `consensus`).【F:rpp/runtime/errors.rs†L10-L50】【F:rpp/proofs/proof_system/mod.rs†L663-L741】
  - `ProofSizeGateError::LimitOverflow` (`…parameter limit overflow…`) signalisiert, dass der in den Parametern kodierte Wert nicht nach Bytes konvertiert werden kann (u32-Overflow) und blockiert den Circuit vor der Verifikation.【F:rpp/runtime/errors.rs†L10-L18】【F:rpp/proofs/proof_system/mod.rs†L686-L704】
  - `ProofSizeGateError::ProofTooLarge` (`…proof too large: limit <X> KiB, got <Y> KiB`) tritt auf, sobald die gemessene Serialisierung eines Circuit-Beweises das Limit übersteigt; Logs/Telemetrie führen `size_bucket` und die Byte-Felder, sodass pro Circuit nachvollziehbar ist, ob einzelne Zeugen oder Aggregationsbeweise ausschlagen.【F:rpp/runtime/errors.rs†L10-L18】【F:rpp/proofs/proof_system/mod.rs†L686-L704】【F:rpp/runtime/node.rs†L5850-L5892】
- Interpretation: Der Präfix `proof size gate failed for <backend>/<circuit>` stammt aus dem Runtime-Error, die nachfolgende Message zeigt den exakten Mismatch-Typ. Trage den Circuit in das Incident-Log ein, damit Operator:innen erkennen, ob nur ein Teilpfad (z. B. `uptime` oder `consensus`) betroffen ist.【F:rpp/runtime/errors.rs†L20-L51】【F:rpp/proofs/proof_system/mod.rs†L663-L741】
- Troubleshooting Oversize-Proofs:
  - **Limit anpassen:** Erhöhe bei Bedarf `max_proof_size_bytes` in `config/node.toml` (Standard 4 MiB) und stelle sicher, dass der Wert > 0 bleibt; das Config-Validierungs-Guardrail lehnt Nullwerte ab. Der Registry-Builder propagiert den neuen Wert beim Neustart in den Verifier und bricht ab, falls er `u32::MAX` überschreitet.【F:config/node.toml†L1-L38】【F:rpp/runtime/config.rs†L2153-L2186】【F:rpp/runtime/config.rs†L2508-L2525】【F:rpp/proofs/proof_system/mod.rs†L744-L756】
  - **Logs & Metriken prüfen:** Oversize-Fälle erscheinen als `proof_backend="rpp-stark" valid=false … size_bucket=…` in den Proof-/Telemetry-Logs und aktualisieren `rpp_stark_proof_total_bytes{,_by_result}` sowie `rpp_stark_stage_checks_total` pro Circuit. Nutze die Labels `{proof_backend,proof_kind,proof_circuit}` für Drilldowns pro Backend/Circuit und korreliere mit `rpp.runtime.proof.verification.outcomes` in Prometheus.【F:rpp/runtime/node.rs†L5614-L5672】【F:rpp/runtime/node.rs†L5790-L5855】【F:rpp/runtime/node.rs†L5850-L5892】【F:telemetry/schema.yaml†L246-L314】
  - **Backend-/Circuit-Gesundheit:** Die Warn- und Proof-Logs aus `emit_rpp_stark_failure_metrics` liefern `proof_bytes`, `params_bytes`, `payload_bytes` sowie `incompatible_proof`, sodass sich Param-Drift von echten Oversize-Fällen unterscheiden lässt. Bei mehrfachen Failures pro Circuit prüfen, ob die Param-Dateien zum aktuell erwarteten Limit passen und ob der Prover größere Zeugen produziert als vorgesehen.【F:rpp/runtime/node.rs†L5790-L5855】【F:rpp/runtime/node.rs†L5850-L5892】
  - **Alerts erwarten:** `ZkRppStarkLargeFailingProofs` feuert, sobald die p90 der fehlschlagenden Proof-Größen > 5 MiB liegt; stage-bezogene Alerts (`ZkRppStarkVerificationFailuresWarning/Critical`) schlagen ebenfalls an, da Size-Gate-Verstöße die Stage-Histogramme aktualisieren. On-Call sollte entsprechend der Runbook-URL die Limits dokumentieren, Cluster-Logs nach `size_bucket` durchsuchen und Backends neu starten, falls das Limit angepasst wurde.【F:ops/alerts/zk/rpp_stark.yaml†L5-L44】【F:rpp/runtime/node.rs†L5790-L5855】
  - **Backend-Metriken im CLI:** `cargo run -p rpp-node -- validator backend-status …` zeigt `verifier_metrics.per_backend` inkl. Cache- und Error-Rates pro Backend/Circuit; ein anhaltender Anstieg der Failures für einen Circuit deutet auf ein Size-Gate-Problem hin und sollte zusammen mit den obigen Metriken validiert werden.【F:rpp/chain-cli/src/lib.rs†L720-L828】【F:rpp/chain-cli/src/lib.rs†L1838-L1876】

### Fehlerbehandlung & Telemetrie

> **Alerting shortcut:** Der dedizierte Operations-Guide bündelt empfohlene
> Prometheus-Queries, Alertmanager-Regeln und Grafana-Panels für das
> `backend-rpp-stark`-Monitoring. Siehe
> [RPP-STARK Verifier Alert Operations](operations/zk_backends.md).

- `NodeInner::verify_rpp_stark_with_metrics` (implementiert in `rpp/runtime/node.rs`) ruft den Registry-Helper auf und emittiert strukturierte Logs (`valid`, `proof_bytes`, `verify_duration_ms`, Stage-Flags) mit Label `proof_backend="rpp-stark"` und `proof_kind` (z. B. `"transaction"`).
- Zusätzlich landen die Kennzahlen auf dem `telemetry`-Target. Erfolgreiche Prüfungen loggen `params_ok`, `public_ok`, `merkle_ok`, `fri_ok`, `composition_ok` sowie `params_bytes`, `public_inputs_bytes` und `payload_bytes`.
- Fehlerpfade nutzen `emit_rpp_stark_failure_metrics` (`rpp/runtime/node.rs`), das Byte-Größen sowie den Fehlertext protokolliert und `valid=false` setzt. Oversize- und Limit-Mismatch-Fälle tragen dieselben Byte-Felder und Buckets, wodurch Alerting-Regeln auf `result="fail"` aufsetzen können.【F:rpp/runtime/node.rs†L5583-L5863】
- Inkompatible Proofs (Version-/Digest-Diskrepanzen) werden zusätzlich mit `incompatible_proof=true` und `incompatibility_reason` geloggt; der Counter `rpp.runtime.proof.incompatible` zählt dieselben Ereignisse für Prometheus und dokumentiert missglückte Mixed-Rollouts ohne Fallback auf eine andere Circuit-Version.【F:rpp/runtime/node.rs†L5583-L5863】【F:rpp/runtime/telemetry/metrics.rs†L1108-L1165】
- Beispielausgaben:

  ```text
  INFO telemetry proof_backend="rpp-stark" proof_kind="transaction" valid=true params_ok=true public_ok=true merkle_ok=true fri_ok=true composition_ok=true proof_bytes=1234 params_bytes=256 public_inputs_bytes=64 payload_bytes=914 verify_duration_ms=42 "rpp-stark proof verification"
  WARN telemetry proof_backend="rpp-stark" proof_kind="transaction" valid=false proof_bytes=1234 params_bytes=256 public_inputs_bytes=64 payload_bytes=914 verify_duration_ms=42 error="cryptography error: verification failed" "rpp-stark proof verification failed"
  ```
- Zusätzlich zu den Logs werden Prometheus-kompatible Metriken über das `metrics`-Crate gemeldet:
  - Histogramme `rpp_stark_verify_duration_seconds`, `rpp_stark_proof_total_bytes`, `rpp_stark_params_bytes`, `rpp_stark_public_inputs_bytes` und `rpp_stark_payload_bytes` (Labels: `proof_backend`, `proof_kind`).
  - Counter `rpp_stark_stage_checks_total` mit Labels `proof_backend`, `proof_kind`, `stage` (`params`, `public`, `merkle`, `fri`, `composition`) und `result` (`ok`/`fail`).
  - Fehlerpfade aktualisieren dieselben Byte-Histogramme, sodass Ausreißer sichtbar bleiben.
- Gossip-Proof-Caches werden per Backend-Fingerprint namespacet; sobald ein Node mit einem anderen aktiven Backend startet, loggt er `p2p.proof.cache` mit `expected`/`previous` und leert die persistierten Digests, damit eingehende Proofs erneut gegen das frische Backend verifiziert werden.【F:rpp/p2p/src/pipeline.rs†L356-L425】【F:rpp/runtime/node_runtime/tests/gossip_bridge.rs†L100-L161】
  - `TelemetrySnapshot` (`rpp/runtime/node_runtime/node.rs`) trägt die `verifier_metrics.per_backend`-Aggregationen weiter, womit Exporter den aktuellen Stand der Backend-Verifikationen ohne zusätzlichen RPC abrufen können.
  - Beispiel-`scrape_config` für Prometheus (wenn `rollout.telemetry.metrics.listen = "127.0.0.1:9797"` konfiguriert ist):

  ```yaml
  scrape_configs:
    - job_name: rpp-node
      honor_labels: true
      static_configs:
        - targets: ["rpp-node:9797"]
      metrics_path: /metrics
      # Optional, falls rollout.telemetry.metrics.auth_token gesetzt ist
      authorization:
        credentials: Bearer change-me
      relabel_configs:
        - source_labels: [__address__]
          target_label: instance
  ```

#### CLI: Backend-Status der Verifier

- `cargo run -p rpp-node -- validator backend-status --rpc-url http://<host>:7070` fasst die Verifier-Metriken für STWO und
  RPP-STARK zusammen. Die Ausgabe kombiniert Cache-Hits/-Misses, Evictions, aktuelle/Maximal-Queue-Tiefe sowie die Error-Rate pro
  Backend. Mit `--json` lassen sich dieselben Felder automatisiert abgreifen (z. B. für On-Call-Probes). Die Werte stammen aus
  `/validator/telemetry` und spiegeln sowohl das Cache-Backend als auch `verifier_metrics.per_backend` wider.【F:rpp/chain-cli/src/lib.rs†L720-L828】【F:rpp/chain-cli/src/lib.rs†L1838-L1876】

### Crash-Reports & RCA-Schritte

- Prover- und Verifier-Prozesse installieren einen Panic-Hook, sobald `RPP_ZK_CRASH_REPORTS=true` gesetzt ist. Die Reports landen standardmäßig unter `logs/zk-crash-reports/*.json`; `RPP_ZK_CRASH_REPORT_DIR` überschreibt das Zielverzeichnis.【F:rpp/zk/backend-interface/src/crash_reports.rs†L14-L118】【F:.github/workflows/nightly.yml†L210-L273】
- Jeder Report enthält Prozessrolle, Backend, Circuit, Panic-Message, Location und einen forcierten Backtrace, sodass Operator:innen auch bei abrupten Abbrüchen den Auslöser nachschlagen können. Der aktuelle Circuit-Kontext wird pro Proving- bzw. Verifier-Aufruf gesetzt.【F:prover/prover_stwo_backend/src/backend.rs†L21-L117】【F:rpp/proofs/proof_system/mod.rs†L1018-L1082】
- CI lädt die JSON-Reports automatisch als Artefakt in den ZK-Nightly-Jobs (`zk-alert-probes`, `zk-penalty-guardrails`, `zk-load-harness`). Bei Prod-Incidents den Hook per Env-Flag aktivieren, den betroffenen Circuit aus dem Report abgleichen, die Backtrace-Fragmente gegen die Pipeline-Logs mappen und bei Bedarf die zugehörigen Witness-/Param-Artefakte erneut verifizieren, bevor der Prozess neu gestartet wird.【F:.github/workflows/nightly.yml†L210-L273】
- Bei blockbezogenen Prüfungen werden Berichte ausgewertet, Size-Gates geprüft und ungültige Proofs sanktioniert (`punish_invalid_proof`).
- `RppStarkProofVerifier` mappt Backend-Fehler (`VerificationFailed`, Size-Mismatch) auf `ChainError::Crypto` und hängt den strukturierten Report an die Log-Nachricht an.

### Prover-/Verifier-Audit-Chains

- Sowohl Wallet-Prover als auch Runtime-Verifier schreiben nun hash-verkettete Audit-Records als JSONL unter `logs/zk-prover-audit.jsonl` bzw. `logs/zk-verifier-audit.jsonl`. `RPP_ZK_AUDIT_LOG` kann den Pfad pro Prozess überschreiben oder mit dem Wert `off` deaktivieren.【F:prover-backend-interface/src/audit.rs†L15-L215】【F:rpp/wallet/src/engine/signing/prover.rs†L28-L120】【F:rpp/proofs/proof_system/mod.rs†L564-L841】
- Jeder Eintrag enthält Backend, Operation (`prove` oder Verifier-Stage), Witness/Proof-Größen bzw. Proof-Fingerprint sowie `prev_hash`/`entry_hash`, sodass Manipulationen beim Export oder nach der Rotation erkennbar bleiben.【F:prover-backend-interface/src/audit.rs†L17-L123】【F:rpp/wallet/src/engine/signing/prover.rs†L89-L136】【F:rpp/proofs/proof_system/mod.rs†L691-L785】
- Rotation erfolgt durch Umbenennen/Archivieren des aktuellen Files; der nächste Start legt eine frische Chain an. Verifiziere die archivierten Logs vor der Ablage mit `AuditLog::verify_chain(<path>)` oder dem CI-Test `cargo test -p prover-backend-interface -- audit::chain_rejects_tampering`, der Tampering und Hash-Drift ablehnt.【F:prover-backend-interface/src/audit.rs†L94-L215】【F:prover-backend-interface/src/audit.rs†L152-L209】

### Proof-Cache-Sizing & Telemetrie

- Die Gossip-Proof-Persistenz ist auf 1 024 Einträge pro Backend limitiert (`PersistentProofStorage::with_capacity`), das älteste Element wird bei Überlauf im FIFO-Modus entfernt.【F:rpp/p2p/src/pipeline.rs†L831-L846】 Der Pfad bleibt über `config.proof_cache_dir` konfigurierbar, sodass Betreiber den Cache auf ein separates Volume legen können, falls größere Retentionswerte gebaut werden.
- Die Runtime exportiert `rpp.runtime.proof.cache.{hits,misses,evictions}` mit Label `cache=gossip-proof-cache`, womit Dashboards (Cache-Efficiency) und Alerts (`ProofCacheThrash` in `ops/alerts/zk/rpp_stark.yaml`) einen Thrash-Alarm auslösen, sobald die Hit-Rate unter 50 % sinkt und Evictions anziehen.【F:telemetry/schema.yaml†L21-L32】【F:telemetry/prometheus/cache-rules.yaml†L16-L37】【F:ops/alerts/zk/rpp_stark.yaml†L46-L71】
- Neue Telemetrie `rpp.runtime.proof.cache.{queue_depth,max_queue_depth,persist_latency,load_latency}` trennt Warteschlangenlänge und DB-/I/O-Wartezeit pro Backend auf; Prometheus-Alerts `ProofCacheQueueSaturation` (lange Queues) und `ProofCacheIoStall` (Persist/Load‑P95 > 250 ms) schlagen bei back pressure oder saturierten Volumes an.【F:telemetry/schema.yaml†L21-L38】【F:telemetry/prometheus/cache-rules.yaml†L18-L76】 Bei lokalen Engpässen Cache-Retention (`proof_cache_retain`) drosseln oder Persistenz-Volume auf schnelle SSD/NVMe legen, bis die Queue-P95 stabil unter 500 bleibt.
- Die Proof-Cache-Metriksuite enthält jetzt Stresstests gegen langsame Persistenz (`cargo test -p rpp-p2p --test proof_cache_metrics -- --nocapture`), die gezielt Queue-Aufstau und >20 ms Persist-/Load-Latenzen erzwingen. Die Tests brechen, sobald die Warteschlangen-Telemetrie oder DB-Wartezeiten nicht erfasst werden und geben so frühe Warnungen vor regressionsbedingter Alert-Stille.【F:rpp/p2p/tests/proof_cache_metrics.rs†L173-L246】

### Circuit-spezifische Verifikationsmetriken

- Alle Proof-Metriken tragen jetzt das Label `proof_circuit`, inklusive Size-, Stage-Check- und Latenzmetriken (`rpp_stark_{params_bytes,payload_bytes,proof_total_bytes,public_inputs_bytes,stage_checks_total,verify_duration_seconds}`), sodass Operator:innen Regressionen pro Backend und Circuit segmentieren können.【F:telemetry/schema.yaml†L246-L303】 Verifier-Aufrufer übergeben den Circuit für RPP-STARK und STWO, womit auch Stage-Dauer- und Größensignale im Dashboard nach Circuit getrennt werden.【F:rpp/runtime/node.rs†L2085-L2181】【F:rpp/runtime/node.rs†L5327-L5438】【F:rpp/runtime/telemetry/metrics.rs†L21-L203】
- Neue Metriken `rpp.runtime.proof.verification.outcomes{proof_backend,proof_kind,proof_circuit,result}` (Counter) und `rpp.runtime.proof.verification.success_ratio{proof_backend,proof_kind,proof_circuit}` (Histogram, Einheit `1`) erfassen Erfolgs-/Fehlerraten pro Backend und Circuit. Der Node zählt jede Verifier-Antwort für STWO- und RPP-STARK-Pfade und berechnet pro Event ein 0/1-Ergebnis, das im Success-Ratio-Histogramm landet.【F:rpp/runtime/telemetry/metrics.rs†L57-L203】【F:rpp/runtime/node.rs†L3193-L3359】【F:telemetry/schema.yaml†L303-L314】
- Das Dashboard **Pipeline Proof Validation** enthält ein Panel „Verification Success Ratio by Circuit“, das die Erfolgsrate pro Backend und Circuit aus `rpp_runtime_proof_verification_outcomes_total` ableitet und gezielte Drops sichtbar macht.【F:docs/dashboards/pipeline_proof_validation.json†L84-L104】 Die neue Alert-Regel **ProofVerificationCircuitRegression** feuert, sobald der 10-Minuten-Fail-Anteil pro Circuit/Backend über 2 % steigt, und verweist auf das Dashboard zur Eingrenzung.【F:docs/observability/alerts/telemetry.yaml†L55-L70】

### Verifier-Stage-Flags & Gegenmaßnahmen

| Stage-Flag | Bedeutung | Typische Fehlersignale | Priorisierte Gegenmaßnahmen |
| --- | --- | --- | --- |
| `params_ok` | Hashvergleich zwischen Proof-Header und erwarteter Backend-Konfiguration (Parameter-Digest). | Log- bzw. Telemetrie-Einträge mit `error="...ParamsHashMismatch"` oder `params_ok=false`. | Prüfe Release-Artefakte (`scripts/build_release.sh` + `RPP_RELEASE_BASE_FEATURES`) und stelle sicher, dass die Binary mit den richtigen Features (`backend-rpp-stark`/`backend-plonky3`) gebaut wurde. Vergleiche `proof_version` und Parameter-Hashes mit `cargo xtask proof-metadata --format json`; der Test `cargo test --features backend-rpp-stark --test rpp_verifier_smoke -- --nocapture error_mapping_is_stable_display` reproduziert den Fehlerfall.【F:tests/rpp_verifier_smoke.rs†L73-L105】 |
| `public_ok` | Bindet kanonische Public Inputs an den Transcript-/Digest-Check. | `PublicInputMismatch`/`PublicDigestMismatch` im Fehlertext oder `public_ok=false`. | Extrahiere den Payload-Abschnitt aus dem Log (Hex/Base64) und spiele `cargo test --features backend-rpp-stark --test rpp_fail_matrix -- --nocapture public_digest_mismatch_maps_to_public_failure`, um Layout-Regressionen mit den Fail-Matrix-Fakes zu überprüfen. Validierte Public-Inputs-JSON (`vendor/rpp-stark/docs/PUBLIC_INPUTS_ENCODING.md`) gegen die betreffende Proof-Klasse.【F:tests/rpp_fail_matrix.rs†L100-L122】 |
| `merkle_ok` | Prüft Trace- und Composition-Merkle-Pfade gegen die im Header gemeldeten Wurzeln. | `MerkleVerifyFailed`/`TraceLeafMismatch` im Report, `merkle_ok=false`, oder Trace-Indizes (`trace_query_indices`) in der Telemetrie. | Sichere den Proof aus `/status/mempool` (`payload_bytes`) und führe `cargo test --features backend-rpp-stark --test rpp_fail_matrix -- --nocapture merkle_path_tampering_maps_to_trace_commit_failure` aus, um Merkle-Path-Tampering lokal zu vergleichen. Verifiziere, dass `proof_cache_dir` intakt ist und kein Dritt-Tool Pfade überschreibt.【F:tests/rpp_fail_matrix.rs†L70-L98】 |
| `fri_ok` | Ergebnis des FRI-Verifiers inkl. Query- & Layer-Budgets. | `FriVerifyFailed{issue=...}` im Report oder `fri_ok=false`. | Prüfe `max_proof_size_bytes` und FRI-Parameter via `ProofVerifierRegistry::with_max_proof_size_bytes`. Führe `cargo test --features backend-rpp-stark --test rpp_fail_matrix -- --nocapture fri_payload_offset_mismatch_maps_to_serialization_error` oder `scripts/test.sh --backend rpp-stark --integration` aus, um Query-Budgets gegen Golden Vectors zu vergleichen. Bei Vendor-Backends GPU-Override (`PLONKY3_GPU_DISABLE=1`) testen, um Hardware-Probleme auszuschließen.【F:tests/rpp_fail_matrix.rs†L124-L151】【F:scripts/test.sh†L44-L120】 |
| `composition_ok` | Vergleicht Composition-Polynome gegen deklarierte Commitments/Degrees. | `CompositionLeafMismatch`/`CompositionInconsistent` bzw. `composition_ok=false`. | Bewahre das Incident-Proof-Bundle, validiere die Witness-Dateien aus `vendor/rpp-stark/vectors/` mit `cargo test --features backend-rpp-stark --test interop_rpp_stark -- --nocapture interop_verify_golden_vector_ok` und fordere gegebenenfalls aktualisierte Circuit-Vektoren beim Release-Team an.【F:tests/interop_rpp_stark.rs†L1-L80】 |

*Hinweis:* Die Stage-Flags stammen aus dem strukturierten `VerifyReport` und werden unverändert an Log- und Telemetrieschichten weitergereicht. Bei Teilausfällen liefert `trace_query_indices` die FRI-Abfragepositionen, sodass Wiederholungen gezielt nachvollzogen werden können.【F:rpp/chain/src/zk/rpp_verifier/report.rs†L1-L86】【F:vendor/rpp-stark/src/proof/types.rs†L1138-L1224】 

### Proof-Replay & Backend-Umschaltung

- **Proof erneut ausführen:** Sichere den Proof-Blob (`payload_bytes`) aus den Incident-Logs und führe `cargo test --features backend-rpp-stark --test interop_rpp_stark -- --nocapture interop_verify_golden_vector_ok` aus, um denselben Beweis gegen die eingebetteten Golden Vectors zu prüfen. Die Test-Harness lädt `vendor/rpp-stark/vectors/stwo/mini/` und repliziert Stage-Checks lokal.【F:tests/interop_rpp_stark.rs†L1-L80】【F:vendor/rpp-stark/src/proof/mod.rs†L40-L160】【F:vendor/rpp-stark/tests/proof_lifecycle.rs†L16-L140】
- **Golden-Vectors und Regressionen:** `scripts/test.sh --backend rpp-stark --unit --integration` verifiziert alle Circuit-Familien inkl. Negativpfade. Verwende `--backend plonky3` analog für den Vendor-Pfad, falls ein Backend-Wechsel evaluiert wird.【F:scripts/test.sh†L44-L120】【F:scripts/test.sh†L286-L352】
- **Backend-Switch vorbereiten:** Baue alternative Artefakte mit `RPP_RELEASE_BASE_FEATURES="prod,backend-plonky3" scripts/build_release.sh` oder `cargo build --features backend-plonky3`. Deployments übernehmen den Wechsel nach einem kontrollierten Neustart; dokumentiere den Feature-Flip im Incident-Log.【F:scripts/build_release.sh†L10-L118】【F:scripts/build_release.sh†L204-L214】
- **Runtime-Parameter anpassen:** Passe `max_proof_size_bytes` oder `rollout.feature_gates.consensus_enforcement` in `config/node.toml` an und starte den Dienst neu, um neue Limits bzw. temporäre Enforcement-Ausnahmen zu übernehmen. Setze Schalter nach der Störung zurück und bestätige die Wirkung über `/status/node` (`backend_health.*`).【F:config/node.toml†L5-L71】【F:rpp/runtime/node.rs†L5043-L5164】【F:rpp/runtime/node.rs†L5416-L5460】

### Zero-data-loss backend switch procedure

**Prerequisites**

- Stelle sicher, dass der alternative Backend-Build mit den richtigen Feature-Flags vorliegt (z. B. `backend-plonky3` oder `backend-rpp-stark`) und ein Integrationslauf (`scripts/test.sh --backend <target> --unit --integration`) ohne Fehlermeldungen durchläuft.
- Prüfe, dass die aktiven Limits (`max_proof_size_bytes`, `rollout.feature_gates.consensus_enforcement`) in `config/node.toml` mit den Ziel-Artefakten kompatibel sind und dokumentiere den aktuellen Wert im Incident-Log, um spätere Rollbacks nachvollziehen zu können.【F:config/node.toml†L5-L71】
- Stelle sicher, dass Validatoren finalisiert haben und keine ungeprüften Proofs im Mempool hängen, indem du `/status/mempool` und `backend_health.*` prüfst. So vermeidest du, dass unbestätigte Artefakte während des Wechsels verworfen werden.【F:rpp/rpc/api.rs†L1440-L2406】【F:rpp/runtime/node.rs†L5416-L5460】

**Schritte für kontrollierten Neustart**

1. **Konfigurationsänderung vorbereiten:** Passe den Backend-Feature-Flip in der Build- oder Deployment-Pipeline an (z. B. `RPP_RELEASE_BASE_FEATURES="prod,backend-plonky3"`) und lege eine Kopie der aktuellen `config/node.toml` mit Versions-Hash im Change-/Incident-Log ab.【F:scripts/build_release.sh†L10-L118】
2. **Node sauber stoppen:** Stoppe den Validator nach Abschluss des aktuellen Slots/Heights (z. B. via Service-Manager), damit gepufferte Proofs persistiert sind.
3. **Binary/Container austauschen:** Rolle das neue Artefakt aus und stelle sicher, dass der Dienst mit den aktualisierten Feature-Flags startet.
4. **Konfiguration anwenden:** Lade die angepasste `config/node.toml` (inkl. aktualisiertem `max_proof_size_bytes` falls nötig) und führe einen Neustart durch. Verifiziere unmittelbar nach dem Start, dass `backend_health.<target>.verifier.accepted` ansteigt und `valid=true`-Logs für neue Proofs erscheinen.【F:rpp/runtime/node.rs†L5416-L5460】
5. **Post-Checks & Dokumentation:** Erfasse `GET /status/node` und relevante Telemetrie-Panels als Artefakte, notiere die Slot-/Height-Marke des Wechsels und aktualisiere das Incident-Log mit dem erfolgreichen Flip. Führe unmittelbar nach dem Neustart `tools/backend_switch_check.sh --url http://<host>:<port> --backend <ziel>` aus, um sicherzustellen, dass `backend_health.<ziel>.verifier` steigt und neue Proofs tatsächlich auf dem frischen Backend landen. Alternativ lässt sich derselbe Check automatisiert über `cargo test --features integration --test node_lifecycle -- backend_switch_routes_proofs_to_active_backend` ausführen, falls eine lokale Simnet-Umgebung zur Verfügung steht.

**Rolling Deploy ohne Datenverlust**

1. **Canary-Knoten aktualisieren:** Wähle einen Validator oder ein kleines Shard-Subset, deploye das neue Backend und verifiziere Proof-Akzeptanz (`backend_health.<target>.verifier.accepted` steigt, keine `valid=false`-Spitzen).
2. **Staggered rollout:** Aktualisiere die übrigen Nodes in kleinen Batches; zwischen den Batches sicherstellen, dass Finality-Gaps stabil bleiben und keine Mempool-Drops auftreten (Monitor `finality_lag_slots` und `backend_health.*`).
3. **Cluster-weite Bestätigung:** Nach Abschluss bestätigen, dass alle Nodes denselben Backend-Status melden und die Telemetrie-Histogramme (`*_proof_total_bytes`, `*_verify_duration_seconds`) keine Regressionen zeigen.

**Rollback**

- Halte den vorherigen Build und die gesicherte `config/node.toml` bereit. Wenn Proof-Rejections oder Finality-Gaps nach dem Flip auftreten, stelle den vorherigen Binary-Stand wieder her, setze die Konfiguration zurück und starte den Dienst neu. Validere, dass `backend_health.<previous>.verifier.accepted` erneut steigt und dokumentiere den Zeitpunkt des Rollbacks im Incident-Log.
- Bei Rolling Deployments sofort zum letzten stabilen Backend zurückkehren, falls der Canary Fehler zeigt; stoppe weitere Batches und verwirf nur den canary-spezifischen Proof-Cache, um Datenverlust zu vermeiden.
- Circuit-Rollbacks ohne `PROOF_VERSION`-Bump müssen im `CHANGELOG.md` explizit als „Circuit-Rollback“ oder „Downgrade“ vermerkt werden, damit der Guardrail-Lauf (`cargo xtask proof-version-guard`) die Änderung akzeptiert. Ein fehlender Eintrag führt trotz unverändertem `PROOF_VERSION` zu einem Merge-Blocker.【F:xtask/src/release.rs†L78-L118】【F:xtask/src/release.rs†L392-L430】
- Die neue Integration-Suite `rpp_circuit_rollback` simuliert Proofs, die mit einem neueren Circuit gebaut wurden, und verifiziert, dass ein zurückgerollter Verifier sie mit klaren Fehlern (`VersionMismatch`, `ParamsHashMismatch`) ablehnt. Sie läuft automatisch im Integration-Matrix-Job für `backend-rpp-stark` und dient als Regressionstest für Downgrade-Pfade.【F:tests/rpp_circuit_rollback.rs†L1-L93】【F:xtask/src/main.rs†L563-L607】

### Incident Runbook: rpp-stark verification failures

#### Detection

- Warnungen mit `proof_backend="rpp-stark"` und `valid=false` markieren fehlgeschlagene Prüfungen direkt im Logstream sowie im Telemetrie-Target und enthalten Stage-Flags bzw. Fehlermeldung für das On-Call-Playbook.【F:docs/zk_backends.md†L29-L43】
- `/status/node` zeigt unter `backend_health.rpp-stark.verifier.rejected` den Zähler für verworfene Beweise; die Werte stammen aus dem `VerifierMetricsSnapshot` und steigen bei jedem Fehlversuch.【F:rpp/runtime/node.rs†L5416-L5460】【F:rpp/proofs/proof_system/mod.rs†L328-L392】
- Die Prometheus-Metriken `rpp_stark_stage_checks_total{result="fail"}` und `rpp_stark_verify_duration_seconds` liefern Stage-spezifische Fehler- und Latenzsignale, die auch für Alerting-Regeln genutzt werden können.【F:rpp/runtime/telemetry/metrics.rs†L476-L520】

#### Manual mitigation

1. Hole das aktuelle Proof-Backlog über `GET /status/mempool`, ermittle Hash, Backend und Payload-Größe des betroffenen Artefakts und vergleiche sie mit den Logeinträgen – so lässt sich feststellen, ob der Fehler reproduzierbar ist oder bereits aus dem Mempool verschwunden ist.【F:rpp/rpc/api.rs†L1440-L2406】【F:rpp/runtime/node.rs†L5461-L5537】
2. Prüfe die lokale Konfiguration auf ein zu niedriges `max_proof_size_bytes`. Der Parameter wird beim Start in den Verifier übertragen; sobald Beweise die Grenze überschreiten, blockiert `ensure_proof_size_consistency` den Start oder markiert eingehende Artefakte als zu groß. Passe den Wert in der Node-Konfiguration an (z. B. `config/node.toml`) und starte den Dienst neu, damit der Verifier das neue Limit übernimmt.【F:config/node.toml†L5-L25】【F:rpp/runtime/config.rs†L1529-L1964】【F:rpp/proofs/proof_system/mod.rs†L360-L412】【F:tests/node_lifecycle.rs†L120-L192】
3. Dokumentiere den Vorfall im Incident-Log und beobachte `backend_health.rpp-stark.verifier.accepted` sowie die Stage-Counter, um zu bestätigen, dass nach der Anpassung wieder erfolgreiche Verifikationen eintreffen.【F:rpp/runtime/node.rs†L5416-L5460】【F:rpp/proofs/proof_system/mod.rs†L328-L392】【F:rpp/runtime/telemetry/metrics.rs†L476-L520】

#### Fallback paths

- **Switch to the vendor backend:** Baue oder deploye eine Binary mit `--features prod,backend-plonky3` (bzw. setze `RPP_RELEASE_BASE_FEATURES="prod,backend-plonky3"` für das Release-Skript), stoppe den Dienst und starte ihn mit dem neuen Artefakt. Der Operator-Guide beschreibt die Build-Schritte; dokumentiere den Wechsel im Change-Log und überwache anschließend `backend_health.plonky3.*` für die Erfolgsquoten.【F:docs/rpp_node_operator_guide.md†L1-L68】
- **Temporarily disable proof enforcement:** Setze `rollout.feature_gates.consensus_enforcement = false` in der aktiven Konfiguration, speichere die Datei und führe einen kontrollierten Neustart durch. Dadurch überspringt die Runtime Sanktionen und Validierungen, bis der Fix bereitsteht. Nach Abschluss der Nacharbeiten muss der Schalter wieder auf `true` stehen, gefolgt von einem erneuten Neustart, um die Verifikation zu reaktivieren.【F:config/node.toml†L57-L71】【F:rpp/runtime/node.rs†L5043-L5164】【F:tests/node_lifecycle.rs†L120-L192】
- **Escalate to release engineering:** Wenn weder Parameter-Anpassungen noch Backend-Wechsel helfen, eskaliere an das Release-Team und lass Hotfix-Builds mit aktualisierten Circuit-Vektoren signieren. Halte das Playbook gemeinsam mit `RELEASE.md` synchron, damit neue Proof-Versionen inklusive Artefakt-Hashes und Checksummen ausgerollt werden können.

## plonky3 (vendor backend)

### Aktivierung

- Optionales Feature `backend-plonky3` aktivieren, z. B. `cargo build --features backend-plonky3` oder `scripts/build_release.sh` mit `RPP_RELEASE_BASE_FEATURES="prod,backend-plonky3"`. Das Feature schaltet den vendorisierten Prover/Verifier frei und kann parallel zu STWO eingesetzt werden; der Guard blockiert weiterhin Kombinationen mit `prover-mock`.【F:scripts/build_release.sh†L1-L118】【F:rpp/node/src/feature_guard.rs†L1-L5】
- Der Prover lädt vendorisierte Parameter, generiert echte Proofs für alle Circuit-Familien und persistiert die Schlüssel im Cache (`backend_health.plonky3.*`).【F:rpp/proofs/plonky3/prover/mod.rs†L19-L520】
- Keine zusätzlichen CLI-Schalter notwendig; Laufzeit und Wallet greifen automatisch auf das Plonky3-Backend zu, sobald das Feature aktiv ist.【F:rpp/node/src/lib.rs†L240-L360】【F:rpp/runtime/node.rs†L161-L220】

### Test- und Interop-Abdeckung

- `scripts/test.sh --backend plonky3 --unit --integration` erzeugt und verifiziert Vendor-Proofs für alle Circuit-Familien.【F:scripts/test.sh†L1-L220】
- Regressionstests (`plonky3_transaction_roundtrip`, `plonky3_recursion`) prüfen Witness-Kodierung, Rekursion und Tamper-Rejection gegen das echte Backend.【F:tests/plonky3_transaction_roundtrip.rs†L1-L200】【F:tests/plonky3_recursion.rs†L1-L360】
- Das Simnet-Szenario `consensus-quorum-stress` misst Prover/Verifier-Latenzen, Tamper-Rejections und Proof-Größen; Nightly CI bricht bei Grenzwertüberschreitungen ab.【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】【F:scripts/analyze_simnet.py†L1-L200】

### Telemetrie & API-Oberfläche

- `Plonky3Prover` aktualisiert Telemetrie (`cached_circuits`, `proofs_generated`, `failed_proofs`, Zeitstempel) auf Basis realer Läufe.【F:rpp/proofs/plonky3/prover/mod.rs†L19-L520】
- `/status/node` liefert produktive Prover-/Verifier-Snapshots unter `backend_health.plonky3.*`; die Validator-UI rendert die Werte direkt aus diesen Feldern.【F:rpp/runtime/node.rs†L161-L220】【F:validator-ui/src/types.ts†L140-L220】
- Grafana-Panels in `docs/dashboards/consensus_proof_validation.json` zeigen p50/p95-Latenzen, Proof-Größen und Tamper-Rejections, unterstützt durch Nightly-Stresstests.【F:docs/dashboards/consensus_proof_validation.json†L1-L200】【F:docs/performance/consensus_proofs.md†L1-L200】
- Die Wallet-Prover-Queues emittieren das Gauge `wallet.prover.queue.depth{backend}` (inklusive `backend="mock"`/`"stwo"`) und blockieren neue Jobs bei ausgeschöpften Semaphoren (`wallet.prover.max_concurrency`). Alerts feuern bei einer Tiefe > 2 über 10 Minuten, p95-Latenz > 3 Minuten oder Fehlerraten > 20 % pro Backend; sobald das Backlog abgearbeitet ist, fällt das Gauge wieder auf 0.【F:rpp/wallet/src/engine/signing/prover.rs†L271-L338】【F:tests/zk_alert_probe.rs†L32-L73】【F:ops/alerts/zk/stwo.yaml†L31-L83】
- Ressourcengrenzen lassen sich per `wallet.prover.cpu_quota_percent` (CPU-Kontingent in %) und `wallet.prover.memory_quota_bytes` (Bytes; `0` nutzt den aktiven cgroup-Limit-Wert) erzwingen. `wallet.prover.limit_warn_percent`, `.limit_backoff_ms` und `.limit_retries` steuern Warnschwellen, Backoff und maximale Drosselversuche; Warnungen und Throttles landen als `wallet.prover.resource.warning`/`wallet.prover.resource.throttled` im Metrics-Endpunkt, bevor neue Jobs mit `Busy` abbrechen.【F:rpp/wallet/src/engine/signing/prover.rs†L19-L188】【F:rpp/wallet/src/config/wallet.rs†L262-L334】【F:rpp/wallet/src/config/wallet.rs†L480-L555】
- Runbook-Hinweis: Bei Queue- oder Latenz-Alerts blockierte Drafts prüfen, Backend-Logs auf Dauercodes sichten, `wallet.prover.max_concurrency` temporär senken bzw. `wallet.prover.timeout_secs` erhöhen und die Wallet mit geleertem Entwurfs-Cache neu starten. Hält der Alarm länger als 15 Minuten an, Backend wechseln oder an das Release-Team eskalieren.【F:ops/alerts/zk/stwo.yaml†L31-L83】【F:rpp/wallet/src/engine/signing/prover.rs†L271-L338】

### Offene Aufgaben

- GPU-Benchmarks ausrollen und zusätzliche Nightly-Profile aufnehmen.
- Key-Distribution-Automatisierung für Multi-Region-Deployments ausarbeiten (siehe Runbook-Follow-ups).【F:docs/runbooks/plonky3.md†L1-L200】
