# Ztate-State, Prover und GlobalProof-Interaktion

Dieses Diagramm zeigt, wie Prover, `ztate/state`, Consensus und Storage im Kontext der bestehenden Aggregationsschritte interagieren und wo der neue Folding-Schritt samt `GlobalProof` eingehängt wird.

```mermaid
graph TD
    C[Consensus] -->|finalisierte Header + Commitments| P[Prover]
    C -->|finalisierte Blöcke| S[ztate/state]

    S -->|State-Writes<br/>Substate-Roots| ST[Storage]
    ST -->|State-Roots + Merkle/Pruning-Proofs| P
    S -->|State/Pruning-Witness<br/>(build_state_witness,<br/>build_pruning_witness)| P

    subgraph Bestehende Aggregation
        P -->|Block-Proofs| A1[Modul-/Block-Aggregation]
        A1 -->|rekursiver Block-Proof<br/>(recursive_commitment)| A2[Rekursive Aggregation<br/>(build_recursive_witness)]
    end

    subgraph Neuer Schritt
        A2 -->|`recursive_commitment` +<br/>`GlobalInstance I_i`| F[Folding-Step<br/>(GlobalProof)]
        F -->|neues `proof_root`/Commitment| ST
        ST -->|Header-Update (`proof_root`)| C
    end
```

**Legende**
- **Bestehende Aggregation:** aktueller Pfad der Block-Proofs, der in `recursive_commitment` mündet.
- **Neuer Schritt:** Folding nimmt den rekursiven Block-Proof und die `GlobalInstance`-Inputs auf, erzeugt den `GlobalProof` und aktualisiert das `proof_root`, das über Storage in den Header zurückgespiegelt wird.
- **GlobalProof-Einhängepunkt:** direkt hinter dem bestehenden rekursiven Aggregationsschritt (`build_recursive_witness`), bevor das Commitment in Storage/Consensus landet.

## Validierungsablauf für Fold-Outputs
- **`verify_global_proof(I_next, π_next)`:** Nach jedem Folding-Schritt ruft der Validator den Backend-`verify`-Pfad mit `I_next` und `π_next` auf. Der Schritt ist Pflicht – nur wenn der Backend-Report positiv ist, darf der Block weiterverarbeitet werden.
- **Header-Konsistenz prüfen:** Der Validator leitet `C_state_h` (gebündelte State-Roots) und `C_rpp_h` (Pruning-/Recovery-Commitment) aus dem finalisierten Header ab und vergleicht sie mit dem im Proof gelieferten `I_next`. Zusätzlich muss `global_instance_commitment` im Header genau dem Commitment aus `I_next` entsprechen; bei Abweichungen wird der Block abgelehnt.
- **Fehlpfad/Reject-Gründe:**
  - Nicht-monotone Indexe oder fehlende Commitments (bereits in `fold_pipeline_step` abgesichert) führen zu einem unmittelbaren Fehler mit `warn!`-Logeintrag.
  - `verify_global_proof` liefert `false` oder ein Backend-Error → Block-Validation schlägt fehl und der Proof wird mit einem strukturierten Fehler (inkl. Backend-Message) geloggt.
  - Header-Commitments (`C_state_h`, `C_rpp_h`, `global_instance_commitment`) stimmen nicht mit `I_next`/`π_next` überein → Block wird rejected, Log-Level `warn`, mit Kontext `height`, `instance.index` und dem abweichenden Feldnamen.

### Light-Client-Pfad
- **Header-only Check:** `verify_global_proof(header, global_proof)` prüft Commitment, Handle (Commitment + VK-ID) und Versionslabel allein anhand von Header und Proof-Payload. Es werden keine Ledger-Daten oder vorherige Blöcke benötigt.
- **Serialisierung:** `global_instance_commitment` und `global_proof_handle` werden als lowercase Hex-Strings transportiert; der Handle enthält Commitment, `vk_id` und das semantische Label (`aggregated-v1` oder `nova-v2`). Ein End-to-End-Beispiel befindet sich unter `docs/interfaces/runtime/examples/light_client_global_proof.json`.

## Übergangsphase: alte Aggregations-Beweise vs. GlobalProofs
- **Akzeptanzmatrix:** Während der Migration akzeptiert der Validator sowohl legacy Aggregations-Proofs (Poseidon-basierte `recursive_commitment`) als auch neue `GlobalProofHandle`/`GlobalProof`-Paare. Ein Feature-Flag (z. B. `folding-verify`) steuert, ob `verify_global_proof` verpflichtend ist oder optional.
- **Priorisierung:** Falls beide Artefakte vorliegen, wird zuerst der GlobalProof validiert; schlägt dieser fehl, fällt der Pfad deterministisch auf die bisherige Aggregations-Validierung zurück, um Reorg-Risiken zu minimieren. Erfolgreiche GlobalProof-Validierung überschreibt das `proof_root`/`global_instance_commitment` im Header.
- **Rollout-Checks:** Telemetrie-Metriken sollten getrennte Counter für „legacy verified“ und „global verified“ ausweisen; sobald alle Peers GlobalProofs signalisieren, kann die Fallback-Validierung entfernt werden. Bis dahin müssen Storage und Gossip beide Handles vorhalten, damit Light-Clients konsistent bleiben.
