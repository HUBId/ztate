# Folding- und Global-Proof-Monitoring

Die neuen Metriken für Folding-Pipeline, Global-Proof-Validierung und Pruning-Updates sind
so definiert, dass sie direkt via OTLP/Prometheus in die bestehenden Dashboards einlaufen.

## Relevante Metriken

* `rpp.folding.fold_duration_ms` (Histogramm): Dauer eines Fold-Schritts pro Blockhöhe/VK/Version.
* `rpp.folding.verify_duration_ms` (Histogramm): Dauer der optionalen Post-Fold-Verification.
* `rpp.folding.proof_bytes` (Histogramm): Größe der gefalteten Proof-Payload.
* `rpp.folding.failures_total` (Counter): Fehlgeschlagene Fold-Schritte, nach Fehlercode gelabelt.
* `rpp.runtime.global_proof.verify_ms` (Histogramm): Dauer der Global-Proof-Prüfung (ms).
* `rpp.runtime.global_proof.bytes` (Histogramm): Größe des geprüften Global-Proofs.
* `rpp.runtime.global_proof.failures` (Counter): Fehlgeschlagene Global-Proof-Prüfungen.

## Alerting-Richtlinien (Beispiele für Prometheus)

```yaml
- alert: FoldingStepSlow
  expr: histogram_quantile(0.95, sum(rate(rpp_folding_fold_duration_ms_bucket[5m])) by (le)) > 5000
  labels:
    severity: warning
  annotations:
    summary: Langsame Fold-Schritte
    description: <=95%-Quantil> der Fold-Dauer liegt seit 5m über 5s.

- alert: FoldingFailuresBurst
  expr: sum(rate(rpp_folding_failures_total[5m])) by (code) > 0
  labels:
    severity: critical
  annotations:
    summary: Fold-Pipeline verwirft Blöcke
    description: Fehlercode {{ $labels.code }} häuft sich ({{ $value }} Fehler/5m).

- alert: GlobalProofTimeouts
  expr: histogram_quantile(0.90, sum(rate(rpp_runtime_global_proof_verify_ms_bucket[5m])) by (le)) > 15000
  labels:
    severity: warning
  annotations:
    summary: Verifikation von Global-Proofs dauert zu lange
    description: 90%-Quantil der Verifikationsdauer liegt über 15s.

- alert: GlobalProofFailures
  expr: sum(rate(rpp_runtime_global_proof_failures[10m])) by (vk_id,version) > 0
  labels:
    severity: critical
  annotations:
    summary: Global-Proof-Validierung schlägt fehl
    description: Mindestens eine Prüfung für VK {{ $labels.vk_id }} ({{ $labels.version }}) scheitert.
```

## Troubleshooting-Checkliste

1. **Logs prüfen**
   * Folding: `folding.pipeline` und `folding.validator` liefern Fehlercodes (`FOLD-STEP-*`, `FOLD-V-*`), Blockhöhe, `vk_id` und Version.
   * Pruning: `pruning.firewood` zeigt, wann Snapshots aktualisiert werden und welche Versionen dabei genutzt wurden.
   * Block-Witness: `proofs.block_witness` meldet Blockhöhe und Anzahl der gebündelten Transaktionen.
2. **Metriken korrelieren**
   * Steigt `rpp.folding.failures_total`, gleichzeitig aber nicht `rpp.runtime.global_proof.failures`, liegt das Problem meist im Backend-Folding (z. B. Payload-Format).
   * Hohe `rpp.runtime.global_proof.verify_ms`-Quantile ohne Fehler lassen auf Auslastung des Verifiers schließen.
3. **VK/Version abgleichen**
   * Logs enthalten `vk_id` und Version; prüfen, ob sie mit der aktuellen Rollout-Matrix übereinstimmen.
4. **Payload-Größen prüfen**
   * `rpp.folding.proof_bytes` und `rpp.runtime.global_proof.bytes` helfen, Ausreißer zu identifizieren; große Ausreißer oft Hinweis auf falsch komprimierte Artefakte.
5. **Upstream-Daten verifizieren**
   * Bei Pruning-Fehlern prüfen, ob die zuletzt persistierten Snapshots die erwarteten `schema_version`/`parameter_version` tragen und ob Cross-Shard-Referenzen vollständig sind.
