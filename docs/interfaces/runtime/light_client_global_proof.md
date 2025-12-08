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

## Proof-Bezug über Handles

Der `global_proof_handle` dient als content-addressable Zeiger auf den
tatsächlichen Proof-Blob:

* **Addressierung via Commitment:** `proof_commitment` ist der 32-Byte-Blake2s
  über die Proof-Bytes. Downloader können den Blob unter
  `cas://global-proof/<proof_commitment>` oder einem äquivalenten HTTP/P2P-Key
  ablegen und identifizieren, ohne zusätzliche Metadaten zu benötigen.
* **Gossip-Propagation:** Block-Gossip (`gossip_block.jsonschema`) transportiert
  den Handle vollständig, sodass Light Clients ihn frühzeitig empfangen und
  den Proof parallel zum Header-Download anfordern können.
* **Deduplication & Caching:** Da der Key nur aus dem Commitment besteht, können
  mehrere Peers denselben Blob bereitstellen. Clients cachen Proofs
  commitment-basiert, um Wiederholungsdownloads zu vermeiden.

## Validierung ohne History

Light Clients benötigen weder Ledger-History noch State-Snapshots, um einen Tip
gegen den Folding-Proof zu prüfen. Der neue Helper
`verify_global_proof(header, global_proof)` erledigt den Abgleich ausschließlich
auf Basis der übertragenen Artefakte:

1. Header aus Gossip/RPC laden und `global_proof_handle`/`global_instance_commitment`
dekodieren.
2. Proof-Payload (`GlobalProof`) via Handle/Commitment vom Netz beziehen.
3. `fetch_and_verify_global_proof(&header, fetch_by_handle)` oder
   `verify_global_proof(&header, &global_proof)` aufrufen. Der neue Helper zieht
   den Proof aus einem content-addressable Speicher, liefert bei fehlendem Blob
   eine aussagekräftige `InvalidProof`-Fehlermeldung und verifiziert anschließend
   Commitment, VK-ID und Version gegen Header und Registry.

```rust
use rpp_chain::runtime::types::{BlockHeader, verify_global_proof};
use rpp_chain::proof_backend::folding::GlobalProof;

fn validate_tip(header: &BlockHeader, cas: &ProofStore) -> ChainResult<bool> {
    let proof = fetch_and_verify_global_proof(header, |handle| cas.get(handle));
    Ok(proof.map(|_| true)?)
}
```

Bei Erfolg liefert der Helper `true`; alle Fehlerpfade (fehlendes Commitment,
Versionsmismatch, invalide Hex oder nicht auffindbarer Proof) ergeben einen
`ChainError` mit klarer Ursache und benötigen keine zusätzlichen
Datenquellen.

## Anforderungen an Header- und Netzwerk-Propagation

* **Header-Mindestfelder:** `global_instance_commitment` und
  `global_proof_handle` müssen als lowercase Hex im Gossip-/RPC-Header stehen,
  damit Light Clients den CAS-Key und den erwarteten VK sofort kennen.
* **Handle-Stabilität im Gossip:** P2P-Gossip darf den Handle nicht kürzen oder
  neu serialisieren; `proof_commitment`, `vk_id` und `version` müssen exakt wie
  im Block erzeugt propagiert werden. Nodes sollen den Handle bereits in der
  Header-Preview mitsenden, sodass Downloader den Proof anfordern können, bevor
  der gesamte Block/Body übertragen ist.
* **Proof-Transport:** Proof-Blobs werden über `proof_commitment` adressiert
  (HTTP Range Request, Bitswap/Libp2p, o. ä.). Clients sollten Streaming-Hashing
  verwenden, um den Commitment während des Downloads zu verifizieren und große
  Blobs früh verwerfen zu können, falls der Hash nicht passt.

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
