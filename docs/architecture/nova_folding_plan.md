# Nova-style Folding Plan for RPP/ztate

## 0. Ist-Analyse: Aktuelle Aggregation

- **Beweisbündel-Struktur:** `BlockProofBundle` hält pro Block alle Transaktions-, State-, Pruning- und rekursiven Beweise als eigenständige Artefakte. Die rekursive Komponente ist ein weiterer `ChainProof`, so dass das Bündel linear mit der Blockanzahl wächst, solange alte Bündel erhalten bleiben.【F:rpp/runtime/types/proofs.rs†L330-L351】
- **Rekursive Verdichtung:** `RecursiveAggregator::build_witness` faltet Commitments aus Identitäts-, Transaktions-, Uptime-, Konsensus- und State-Proofs plus dem vorherigen rekursiven Commitment. Der Aggregationshash bindet außerdem Pruning-Digests und den Blockhöhenzähler; Batchgröße bis 64 Einzelbeweise.【F:rpp/proofs/stwo/aggregation/mod.rs†L10-L127】【F:rpp/proofs/stwo/aggregation/mod.rs†L200-L279】
- **Header-Bindung:** Das Blueprint beschreibt eine Aggregations-Stufe, die Modul-Commitments, das Witness-Bundle-Commitment und das vorherige Proof-Commitment als Zeugen nutzt und den rekursiven Akkumulator in den Proof-Registry-State schreibt. Der Header verbindet sich über den Proof-Registry-Root mit diesem Akkumulator.【F:rpp/proofs/rpp.rs†L1260-L1354】
- **Verifikationsfluss:** `ProofSystem::verify_block_bundle` erwartet vollständige Bündel und prüft, dass alle Einzelbeweise denselben Backend-Typ besitzen, bevor der rekursive Beweis verifiziert wird. Somit müssen Validatoren aktuell die gesamte Bündelstruktur laden und verifizieren.【F:rpp/proofs/proof_system/mod.rs†L905-L1054】

### Mapping: Aktueller Zustand → Geplante Nova-Instanz (I_i)

| Heute | Nova-Instanzfeld |
| --- | --- |
| `GlobalStateCommitments` (global/utxo/reputation/timetoke/zsi/proof Roots) | `C_state_i` |
| Rekursives Commitment aus `RecursiveWitness.aggregated_commitment` | `C_rpp_i` (bzw. Teil des RPP-Commitments) |
| Pruning Envelope Binding + Segment-Commitments | `C_history_i` / `C_pruned_i` |
| Blockhöhe in Aggregationshash | `h_i` als öffentliches Eingabefeld |

## 1. Nova-Style State-Transition-Relation (AIR/Circuit)

- **Relation R:** `R(C_state_old, C_rpp_old, B_i, pruning_meta) -> (C_state_new, C_rpp_new)` mit konstantem Circuit pro Block. Öffentliche Inputs: laufende Instanz `I_i = {C_state_i, C_rpp_i, params, h_i}` plus Headerfelder. Witness: Block-Transaktionen, Merkle-Pfade, UTXO-/Account-Zeugnisse, Pruning-Segmente.
- **Relaxed / Running Instance:** `I_i` wird als öffentliches Eingabe-Commitment im Beweis geführt; die Verkettung erfolgt ausschließlich über `I_{i-1}` und den Blockzeugen, nicht über eine wachsende Proof-Liste.
- **Restore-Relation:** Separates AIR `Restore(I_tip, aux) -> Block_j` validiert Rekonstruktion älterer Blöcke/States aus `I_tip` und Pruning-Hilfsdaten. Wichtig: `I_i` muss alle RPP-Commitments enthalten, die hierfür nötig sind.

## 2. Folding-/Aggregation-Schicht (Nova-analog)

- **GlobalInstance:** `struct GlobalInstance { C_state: CommitmentDigest, C_rpp: CommitmentDigest, height: u64, params_id: ParamsVersion }` mit Serialisierung für Header-Felder.
- **GlobalProof:** `{ instance_commitment, proof_bytes, vk_id }`, konstante Größe; keine eingebettete Liste historischer Subproofs.
- **Folding-Operator:** `fold(I_prev, π_prev, block_witness) -> (I_next, π_next)` mit garantiert fixer Beweisgröße. Der Operator ersetzt die bisherige `RecursiveAggregator`-Verkettung.
- **Backend-Trait:** `trait FoldingBackend { fn fold(&self, prev: &GlobalInstance, proof: &GlobalProof, w: &BlockWitness) -> (GlobalInstance, GlobalProof); fn verify(&self, inst: &GlobalInstance, proof: &GlobalProof) -> bool; }` mit Fake-Backend für Tests.

## 3. RPP/Pruning-Integration

- **Instanzfelder:** `I_i` enthält `C_pruned_i`/`C_history_i` (z.B. aus Pruning-Envelopes). Faltung prüft, dass Pruning-Segmente konsistent zu `C_pruned_i` sind und dass `C_rpp_new` das aktuelle Pruning-Binding einkettet.
- **Rekonstruktion:** Aus `{I_tip, π_tip}` und Off-Chain-Pruning-Segmenten lässt sich deterministisch `Block_j` rekonstruieren; das erfordert festgelegte Bindungen der Segmente in `I_i` und eine definierte `restore`-Relation.

## 4. Schnittstellen für Node / Wallet / Konsens

- **Header-Felder:** ergänze `global_instance_commitment` + `global_proof_handle`. State-/RPP-Roots bleiben separat für Wallets.
- **Verifikation:** `verify_global_proof(header, global_proof) -> bool` prüft `global_proof.instance_commitment == header.global_instance_commitment` und verifiziert `π`. Light Clients laden nur Header + `GlobalProof`.
- **Proposer/Validator Flow:**
  - Proposer lädt `(I_prev, π_prev)`, baut `block_witness`, ruft `fold`, hängt `I_next`-Commitment und `π_next` an.
  - Validatoren rufen `verify_global_proof` und prüfen, dass `I_next`-Felder mit Header-Roots übereinstimmen.

## 5. Migration & Versionierung

- **ProofVersion:** `AggregatedV1` (aktuelles Bündel), `NovaV2` (Folding). Konsens-Schalter: ab Blockhöhe/Epoche `H_upgrade` ist `NovaV2` Pflicht.
- **Bootstrap:** Einmalige Generierung von `(I_boot, π_boot)` aus Genesis oder einem Cut der V1-Kette; ab dort nur noch `fold`-Schritte.
- **Koexistenz:** Während Übergang können Blöcke optional beide Felder tragen; Validatoren akzeptieren V1 bis `H_upgrade`, danach nur V2.

## 6. Umbauplan (inkrementell)

1. **Modul anlegen:** `rpp/ztate/folding` mit `GlobalInstance`, `GlobalProof`, `FoldingBackend`. Fake-Backend für Tests.
2. **Mapping-Funktionen:** `from_state_and_rpp(commitments, pruning_digest) -> GlobalInstance`; `GlobalInstance::to_header_fields()`.
3. **Block-Format:** Header um `global_instance_commitment`, optional `global_proof_handle` erweitern; Storage-Tables für `GlobalInstance`/`GlobalProof` ergänzen.
4. **Prover-Pipeline:** `produce_block_witness` und `fold_global` einführen; alte Aggregations-Verkettung zugunsten eines einzelnen Faltungsaufrufs pro Block ersetzen.
5. **Consensus-Flow:** Proposer/Validator Pfade auf `verify_global_proof` umstellen; Übergangslogik für `ProofVersion` implementieren.
6. **RPP-Rekonstruktion:** RPP-Commitment-Schema finalisieren und `restore`-API entwerfen; sicherstellen, dass `I_i` alle nötigen Bindungen trägt.
7. **Tests:** Long-chain Tests (10k+ Blöcke) auf konstante Beweisgröße; Migrationsszenario V1→V2 simulieren.

### ASCII-Übersicht

```
+-----------+      +--------------+      +-----------------+
|  Block i  | ---> | fold(I_{i-1},| ---> |  I_i, π_i (const)|
| witness   |      |  π_{i-1})    |      |  stored in hdr  |
+-----------+      +--------------+      +-----------------+
       ^                    |                     |
       |                    v                     v
  Pruning meta ----> RPP commitments -----> Restore(Relation)
```
