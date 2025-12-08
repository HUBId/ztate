# Testinventar und Lücken (Proof-/Circuit-Module)

Dieses Dokument fasst die über `rg` gefundenen Tests für die Proof- und Circuit-Module zusammen und zeigt die wichtigsten Lücken für die priorisierten Hochrisiko-Themen.

## Testinventar (Circuit/Proof-Module)
- **Plonky3 (rpp/proofs/plonky3)** – zentrale Regressionstests prüfen deterministische Commitment-Berechnung, Backend-Roundtrips sowie Verifikations-Fehlerbilder (u. a. Keys, Witnesses, Payload-Größe) im kombinierten `tests.rs`.【F:rpp/proofs/plonky3/tests.rs†L131-L207】【F:rpp/proofs/plonky3/tests.rs†L701-L814】【F:rpp/proofs/plonky3/tests.rs†L1048-L1124】
- **STWO (rpp/proofs/stwo/tests)** – Integrations- und Roundtrip-Tests validieren deterministische Wallet-State-Persistenz und die wiederholbare Generierung/Verifikation aufgezeichneter Transaktions-Proofs.【F:rpp/proofs/stwo/tests/official_integration.rs†L137-L179】 Weitere Tests liegen in `tests/consensus_metadata.rs`, `tests/adapter.rs`, `tests/valid_proof.rs` und `tests/mock_state_view.rs` (siehe `rg`).
- **Proof-System-Kern (rpp/proofs/proof_system)** – SLA-/Metrik-Tests sichern Budget-Berechnung und Beobachtbarkeit des Verifiers ab.【F:rpp/proofs/proof_system/mod.rs†L1212-L1265】
- **Blueprint (rpp/proofs/blueprint)** – stellt Aufgabenplan-Regressionstests für Section-Vollständigkeit, Status-Updates und Fehlerpfade bereit.【F:rpp/proofs/blueprint/mod.rs†L409-L458】
- **Firewood Proof Codec** – Header-/Payload-Fuzzing-Tests stellen robustes Parsen von Range-Proofs sicher.【F:firewood/src/proof/codec/tests.rs†L1-L120】
- **Storage-Migration** – Migrationstests validieren Upgrade/Dry-Run von Legacy-Block-Datenbanken.【F:rpp/storage/migration.rs†L608-L652】

## Hochrisiko-Themen: Flow vs. Testabdeckung

### 1) VK-Rotation
| Flow | Test vorhanden? | Hinweis |
| --- | --- | --- |
| Plonky3 verweigert Proofs mit manipuliertem Verifying-Key/Metadata | Ja – `transaction_proof_rejects_tampered_verifying_key` deckt Manipulation der baked VK-Metadaten ab.【F:rpp/proofs/plonky3/tests.rs†L701-L730】 | Stellt fest, dass Verifier und Backend einen VK-Mismatch erkennen. |
| Rollierende/rotierende VK-Artefakte (neue Keys ausrollen, alte übergültig) | **Fehlt** | Kein Test, der die Rotation von VK-Files oder die Koexistenz mehrerer Generationen in Artefakt-Layern prüft. |

### 2) Migration
| Flow | Test vorhanden? | Hinweis |
| --- | --- | --- |
| Migration von Legacy-Block-Records auf aktuelles Schema | Ja – `migrates_legacy_block_records` validiert Upgrade und Resultat-Lesen.【F:rpp/storage/migration.rs†L608-L630】 | Deckt End-to-End-Upgrade für Blockspeicher ab. |
| Dry-Run ohne Persistenz | Ja – `dry_run_does_not_persist_changes` erzwingt unveränderte Schema-Marker im Dry-Run.【F:rpp/storage/migration.rs†L632-L652】 | Testet Schutz vor unbeabsichtigtem Schreiben. |
| Wallet-/Runtime-spezifische Schema-Migrationen (z. B. RBAC/Backup-Buckets) | **Fehlt** | Keine expliziten Tests für die Wallet-Migrationspfade oder Konsistenz der neuen Buckets nach Versionserhöhung gefunden. |

### 3) Proof-Größe
| Flow | Test vorhanden? | Hinweis |
| --- | --- | --- |
| Verifizierung lehnt übergroße/verkürzte Transaction-Payloads ab | Ja – `transaction_proof_rejects_oversized_payload` und verwandte Tests decken Truncation/Padding ab.【F:rpp/proofs/plonky3/tests.rs†L793-L814】 | Stellt Grenzprüfungen für Payload-Größe sicher. |
| Rekursive Aggregation limitiert Batch-Größe und protokolliert Latenz | Ja – `recursive_batch_enforces_size_gate_and_reports_latency` prüft Batch-Limit und Metrik-Updates.【F:rpp/proofs/plonky3/tests.rs†L1048-L1124】 | Belegt, dass Batch-Limits greifen und Telemetrie aktualisiert wird. |
| STWO-Proofs: Größen- oder Payload-Limits | **Fehlt** | Kein Test gefunden, der STWO-Proof- oder Fixture-Größe validiert. |

### 4) Determinismus
| Flow | Test vorhanden? | Hinweis |
| --- | --- | --- |
| Commitment-Berechnung invariant gegen Map-Ordering | Ja – `compute_commitment_is_stable_for_map_ordering` vergleicht permutierte JSON-Bäume.【F:rpp/proofs/plonky3/tests.rs†L131-L176】 | Sichert deterministische Commitments ab. |
| STWO-Wallet-State Roundtrip deterministisch | Ja – `wallet_state_round_trip_is_deterministic` belegt wiederholbare Persistenz/Reload.【F:rpp/proofs/stwo/tests/official_integration.rs†L137-L143】 | Deckt deterministische Speicherung ab. |
| Deterministische Proof-Generierung mit neuen VK-/Parameter-Generationen | **Fehlt** | Kein Test, der deterministische Outputs nach Parameter-/VK-Wechsel oder im Multi-Proof-Pipeline-Verbund prüft. |

## Beobachtete Lücken (Priorität)
1. **VK-Rotation**: Tests für Mehr-Generationen-Betrieb/Rotation fehlen komplett.
2. **Migration**: Wallet-/Runtime-Migrationspfade sind ungetestet; nur Storage-Blocks sind abgedeckt.
3. **Proof-Größe**: STWO-Payload-/Größengrenzen nicht abgesichert.
4. **Determinismus**: Keine Regressionstests für deterministische Outputs nach Artefakt-/Parameterwechsel.
