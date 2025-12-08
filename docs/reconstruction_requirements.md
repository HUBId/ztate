# Rekonstruktions-Anforderungen

Dieses Dokument konkretisiert, welche Commitments und APIs erforderlich sind, um
Pruning-fähige Intervalle deterministisch aus einem aktuellen Tipp `I_tip`
rekonstruieren zu können. Die Vorgaben orientieren sich an den
`ReconstructionEngine`-Primitiven im Runtime-Code, formulieren jedoch die
vollständigen Anforderungen an die zugrunde liegenden RPP-/History-Commitments
und deren Verifizierungsschritte.

## 1. Commitments, die in jedem Intervall `I_i` vorliegen müssen
- **Block-/Header-Commitment**: Ein Hash/Commitment über Header und Parent-Hash
  auf `I_{i-1}`, damit die Kette eindeutig verankert ist.
- **RPP- bzw. History-Commitment**: Verkettete Commitments über alle
  transaktionsrelevanten Ereignisse des Intervalls, inklusive Forward-Link auf
  das Commitment von `I_{i+1}` oder einen kumulierten Prüfsummenanker, so dass
  fehlende Segmente zwischen `I_i` und `I_tip` nachprüfbar sind.
- **State-Commitment**: Zustands-Root nach Verarbeitung von `I_i` (z. B. trie
  root / global state root), plus Referenz auf den Startzustand von `I_{i+1}`.
- **Proof-/Transcript-Commitment**: Commitment über alle Prüfbarkeits-Beweise
  oder Protokoll-Transkripte des Intervalls (z. B. zk/STARK-Proofs) für
  Drittverifikation.
- **Checkpoint-Link**: Optionaler Snapshot-/Checkpoint-Hinweis, damit
  Rekonstruktion über große Strecken auf vorliegende Teilzustände springen kann.

Die Menge stellt sicher, dass sowohl der Ausführungsverlauf (History) als auch
Start- und Endzustand jedes Intervalls aus `I_tip` heraus eindeutig ableitbar
sind.

## 2. API-Signaturen für Rekonstruktion
Die folgenden Signaturen beschreiben, welche Zusatzdaten (`aux_data`) neben
`I_tip` benötigt werden und welche Ergebnisse erwartet werden. Sie können in
Rust/TypeScript analog ausgestaltet werden.

```rust
/// Rekonstruiert Block i inkl. Ereignishistorie und Verifikationsstatus.
fn reconstruct_block(
    i: u64,
    tip: CommitmentView,           // abgeleitet aus I_tip
    aux_data: AuxData,
) -> ChainResult<ReconstructedBlock>;
```

```rust
/// Rekonstruiert den Zustand unmittelbar nach Block i.
fn reconstruct_state_at(
    i: u64,
    tip: CommitmentView,           // abgeleitet aus I_tip
    aux_data: AuxData,
) -> ChainResult<StateView>;
```

### Benötigte Zusatzdaten (`AuxData`)
- `commitment_chain`: Sequenz aller History-/RPP-Commitments von `i` bis
  einschließlich `I_tip`, inkl. Parent-Referenzen.
- `parent_state_commitment`: Zustands-Commitment für `i-1` (falls nicht bereits
  in der Kette kodiert) zur Initialisierung der Replay-VM.
- `execution_rules`: Parameter und Protokoll-/Fork-Regeln, die bestimmen, welche
  State-Transition-Funktionen für Höhe `i` gelten.
- `proof_artifacts`: Prüfbarkeitsbeweise oder Transkript-Hashes für das
  Intervall (z. B. STARK-/ZK-Proofs, Merkle-Pfade), damit Ergebnisse verifiziert
  werden können.
- `chain_spec`: Format/Version der Blöcke, Konsensus-Constraints und Limits, die
  zur Validierung der Rekonstruktion benötigt werden.
- `checkpoints`: Optionale Checkpoint- oder Snapshot-Hinweise, um lange
  Rekonstruktionspfade zu segmentieren.

## 3. Verifikation der Pruning-Schritte im Circuit/AIR
Damit `I_{i+1}` garantiert rekonstruierbar bleibt, erzwingt das Circuit/AIR
folgende Checks:

- **Link-Constraint**: `I_{i+1}` referenziert das History-/RPP-Commitment von
  `I_i` (z. B. verkettetes Merkle-/Hash-Commitment).
- **State-Update-Constraint**: Der berechnete State-Root nach Ausführung von
  `I_{i+1}` muss exakt dem im Commitment abgelegten State-Commitment entsprechen.
- **Inclusion-Constraint**: Alle für Rekonstruktion relevanten Ereignisse
  (Logs, Inputs, Receipt-Hashes) besitzen gültige Merkle-Pfade in den
  RPP-/History-Commitments; Stichproben/Öffnungen werden im AIR geprüft.
- **Completeness-Constraint**: Sequenznummern/Längenprüfungen stellen sicher,
  dass kein Ereignis ausgelassen wurde und der Replay-Pfad deterministisch ist.
- **Boundary-Constraint**: Startzustand von `I_{i+1}` == Endzustand von `I_i`;
  Hash-/Commitment-Gleichheit wird im Circuit erzwungen.

Bestehen alle Constraints, können Light Clients oder rekonstruierende Knoten die
Pruning-Schritte prüfen und aus `I_tip` rückwärts deterministisch rekonstruieren.
