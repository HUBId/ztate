# Light-Client-Validierung für `global_proof`

Die Header-Felder `global_instance_commitment` und `global_proof_handle` werden
als lowercase Hex-Strings serialisiert, so dass Light Clients sie direkt aus
Gossip- oder RPC-Headern lesen können. `global_instance_commitment` spiegelt den
Blake2s-Hash (32 Bytes) über `(index || state_commitment || rpp_commitment)`
wider; `global_proof_handle` enthält den Proof-Commitment-Hash (32 Bytes), die
hex-kodierte Verifikationsschlüssel-ID (`vk_id`) und ein semantisches
Versionslabel (`aggregated-v1` oder `nova-v2`). Das Label wird über eine
**zentrale VK-Registry** auf konkrete `vk_id`-Einträge gemappt (siehe
`docs/architecture/global_proof_vk_registry.md`) und erlaubt so, dass Clients
rotierende Verifikationsschlüssel sicher auflösen.

Ein komplettes Beispiel liegt unter
`docs/interfaces/runtime/examples/light_client_global_proof.json` und zeigt die
JSON-Repräsentation eines Headers plus dazugehörigem Proof-Blob.

## Validierung ohne History

Light Clients benötigen weder Ledger-History noch State-Snapshots, um einen Tip
gegen den Folding-Proof zu prüfen. Der neue Helper
`verify_global_proof(header, global_proof)` erledigt den Abgleich ausschließlich
auf Basis der übertragenen Artefakte:

1. Header aus Gossip/RPC laden und `global_proof_handle`/`global_instance_commitment`
dekodieren.
2. Proof-Payload (`GlobalProof`) via Handle/Commitment vom Netz beziehen.
3. `verify_global_proof(&header, &global_proof)` aufrufen. Der Helfer verifiziert
   Commitment- und VK-Konsistenz, prüft das erwartete Proof-Version-Label basierend
   auf der Header-Höhe gegen die Registry-Abbildung und hasht die Proof-Bytes
   erneut gegen das Commitment.

```rust
use rpp_chain::runtime::types::{BlockHeader, verify_global_proof};
use rpp_chain::proof_backend::folding::GlobalProof;

fn validate_tip(header: &BlockHeader, proof: &GlobalProof) -> bool {
    verify_global_proof(header, proof)
}
```

Bei Erfolg liefert der Helper `true`; alle Fehlerpfade (fehlendes Commitment,
Versionsmismatch, invalide Hex) ergeben `false` und benötigen keine zusätzlichen
Datenquellen.

## Optionale Sampling-/Fetch-Strategien

* **Handle-Only Preflight:** Das Version-Label im Header erlaubt es, vor dem
  Download einen Cutover-Check (z. B. `nova-v2` verpflichtend) zu erzwingen. Falls
  das Label nicht akzeptabel ist, kann der Client den Download komplett
  überspringen.
* **Chunk-/Streaming-Download:** Proofs können über das Commitment aus dem
  Handle adressiert werden. Ein Client kann die Bytes gestreamt laden, den
  Blake2s-Commitment während des Downloads inkrementell aktualisieren und den
  Stream verwerfen, falls der finale Hash nicht dem Header-Commitment entspricht.
* **Caching nach Commitment:** Da sowohl Header als auch Proof-Handle den gleichen
  Commitment-Schlüssel nutzen, können Downloader deduplizieren oder gecachte
  Proof-Blobs wiederverwenden, ohne weitere State-Informationen vorzuhalten.

Diese Flows reichen aus, um einen Tip-Block zu akzeptieren oder abzulehnen,
selbst wenn der Client nur Header-Gossip, das Handle und das geladene Proof-Blob
kennt.
