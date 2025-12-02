# Ztate-State, RPP/Pruning-Commitments und Folding-Eingänge

Das Sequenzdiagramm unter [`docs/architecture/ztate_state_folding_interaction.md`](architecture/ztate_state_folding_interaction.md) visualisiert die Schnittstellen zwischen Prover, `ztate/state`, Consensus und Storage, markiert die bestehenden Aggregationsstufen und zeigt, wo der neue Folding-Schritt (`GlobalProof`) eingehängt wird.

## 1. Aktuelle Commitments und State-Roots
- **Globale Ztate-State-Commitments:** Das Ledger emittiert einen Satz aus sechs Commitment-Wurzeln (Global-Accounts, UTXO, Reputation, Timetoke, ZSI-Registry, Proof-Registry). Sie werden im Block-Header gespiegelt und bilden den Stand der "ztate"-Substates ab (`global_state_root`, `utxo_root`, `reputation_root`, `timetoke_root`, `zsi_root`, `proof_root`).【F:rpp/proofs/rpp.rs†L377-L406】【F:rpp/runtime/node.rs†L9488-L9510】【F:rpp/storage/ledger.rs†L1180-L1190】
- **Pruning/Recovery-Roots (RPP):** Jede Pruning-Checkpoint-Datei speichert den gerade committed State-Root und bricht die Rotation ab, falls die manifestierte Wurzel nicht zum Commit passt. Recovery- und Cross-Backend-Drills prüfen zudem, dass der Pruning-Proof für den finalisierten Head gegen den erwarteten State-Root validiert werden kann.【F:docs/storage/pruning.md†L15-L36】【F:docs/storage/pruning.md†L71-L95】
- **State-Sync/Light-Client-Roots:** Snapshot-Manifeste und Light-Client-Updates tragen den Firewood-State-Root und eine zusammengeführte Root-Commitment-Kette. Die Verifikation stoppt, wenn Wurzeln in Plan, Pruning-Receipts oder Chunk-Proofs voneinander abweichen.【F:docs/state_sync.md†L10-L38】【F:docs/state_sync.md†L30-L37】

## 2. Vorläufiges Schema für `GlobalInstance I_i`
Ein Instanzobjekt aggregiert die öffentlichen Inputs eines Folding-Schritts für Block *i*:

| Feld | Beschreibung |
| ---- | ------------ |
| `height_i` | Blockhöhe des Instanzschritts (offen verfügbar über Light-Client-Update). |
| `C_state_i` | Bündel aller sechs Substate-Commitments aus dem Header (`global_state_root`, `utxo_root`, `reputation_root`, `timetoke_root`, `zsi_root`, `proof_root`).【F:rpp/runtime/node.rs†L9488-L9510】 |
| `C_rpp_i` | Commitment der Pruning-Witness (z. B. letzter `snapshot-<height>.json`) inkl. Referenz auf den verifizierten State-Root; dient als Boundary-Bedingung für den Folding-Übergang.【F:docs/storage/pruning.md†L15-L36】 |
| `C_rpp_history_i` | Sequenz/Historie der zuletzt bestätigten Pruning-Proofs und zugehörigen State-Roots, damit der Faltungsschritt nur monotone/append-only Updates akzeptiert.【F:docs/storage/pruning.md†L71-L95】 |
| `C_rec_i` | Commitment der rekursiven Aggregation des vorherigen Blocks (`recursive_commitment`), falls vorhanden; leer bei Genesis.【F:docs/state_sync.md†L30-L37】 |
| `pp_public` | Öffentliche Parameter des verwendeten Proof-Systems (z. B. RPP-STARK/Plonky3), versioniert über Parameter-Hashes im Snapshot-Metadatenpfad.【F:docs/state_sync.md†L10-L24】 |

## 3. Nutzung bestehender Block-Proofs im Folding-Schritt
- **Prover-Inputs bündeln:** Der Prover konstruiert für Block *i* die Modul-Witnesses (`build_state_witness`, `build_pruning_witness`) und reicht sie zusammen mit den Header-Commitments an `build_recursive_witness` weiter. Dadurch fließen State- und Pruning-Commitments als öffentliche Inputs in die rekursive Aggregation ein.【F:rpp/proofs/proof_system/mod.rs†L262-L310】
- **Header-Commitments dekodieren:** Der Runtime-Knoten liest die Commitments aus dem finalisierten Header (`commitments_from_header`) und übergibt sie an den Prover. Diese Werte entsprechen exakt den öffentlichen Wurzeln, die im Folding-Schritt erneut verknüpft werden.【F:rpp/runtime/node.rs†L9488-L9510】
- **Vorherige Aggregation referenzieren:** `build_recursive_witness` akzeptiert den vorherigen rekursiven Proof (`previous_recursive`) und die aktuellen Block-Proofs. Damit entsteht eine Kette aus Block-Beweisen, deren Commitment (`recursive_commitment`) als öffentlicher Input der nächsten Instanz `I_{i+1}` dient.【F:rpp/proofs/proof_system/mod.rs†L293-L310】
- **Pruning- und State-Proofs koppeln:** Der rekursive Witness beinhaltet sowohl den Pruning-Beweis (`pruning_envelope`, `pruning_proof`) als auch die globalen State-Commitments, wodurch der Folding-Schritt garantiert, dass die neue Root (`C_state_i`) nur akzeptiert wird, wenn der zugehörige Pruning-Proof verifiziert wurde.【F:rpp/proofs/proof_system/mod.rs†L293-L310】【F:docs/storage/pruning.md†L71-L95】
