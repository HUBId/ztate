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
