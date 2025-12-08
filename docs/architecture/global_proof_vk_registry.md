# Verifikationsschlüssel-Registry und Versionierung für `GlobalProof`

Dieses Dokument beschreibt, wie Verifikationsschlüssel (VKs) für `GlobalProof`-Beweise
verwaltet werden, wie `ProofVersion`-Labels auf konkrete VK-IDs abgebildet werden und
welche Migrationsschritte Nodes befolgen müssen.

## Zentrale Registry für VKs

* **Quell-Of-Truth:** Eine kanonische `vk_registry.json` im Repository (unter
  `docs/interfaces/runtime/`) enthält alle aktiven und historischen VK-IDs
  einschließlich Metadaten (`version`, `curve`, `backend`, `activated_at`,
  `superseded_by`).
* **Distribution:** Nodes laden die Registry über denselben Release-/Config-Pfad wie
  andere runtime-spezifische Artefakte (z. B. via packaged assets oder gesicherte
  HTTP-Bundles). Die Datei wird mit einer Checksumme (z. B. SHA-256) ausgeliefert,
  die gegen die Release-Metadaten geprüft wird.
* **Lookup-API:** Loader-Funktionen reichen die Registry als Mapping
  `vk_id -> {version, metadata}` in die Verifier-Schicht weiter. Die Registry dient
  als einzige Quelle, aus der `GlobalProofHandle::vk_id` aufgelöst wird; Hardcoding
  in Codepfaden ist zu vermeiden.

## Versionierungsregeln

* **Eindeutige Zuordnung:** Jedes `ProofVersion`-Label mappt auf genau eine
  `vk_id`. Beispiel: `ProofVersion::NovaV2 -> "nova-v2-vk"`. Die Zuordnung wird in
  der Registry gepflegt und in den Runtime-Checks referenziert.
* **Rückwärtskompatibilität:** Alte Labels bleiben in der Registry bestehen, selbst
  wenn sie superseded sind, damit historische Blöcke weiterhin verifiziert werden
  können.
* **Rotation/Ablauf:**
  * Eine neue VK-Version wird hinzugefügt, das Vorgänger-VK erhält das Feld
    `superseded_by` und optional `expires_at_block`.
  * Validatoren akzeptieren beide Versionen während einer definierten
    Grace-Periode; danach erzwingt der Cutover-Check, dass das Header-Label auf die
    neue `vk_id` zeigt.
  * Die Registry vermerkt den **aktivierten Block** und optional den
    **abgeschalteten Block**, um Height-basierte Checks zu ermöglichen.

## Migration für Nodes

1. **Registry laden und cachen:**
   * Beim Start lädt der Node `vk_registry.json`, validiert die Signatur/Checksumme
     und cached das Mapping im Speichersnapshot (z. B. über `Arc<RwLock<_>>`).
   * Hot-Reload: Bei neuen Releases kann die Datei im laufenden Betrieb neu geladen
     werden; die Registry-Version (z. B. SemVer + Hash) verhindert Stale-Caches.
2. **GlobalProof-Validierung:**
   * Der Verifier löst `global_proof.handle.vk_id` gegen die Registry auf und
     prüft, ob das Label im Header (`global_proof_handle.version`) mit dem Registry
     Eintrag (`ProofVersion` → `vk_id`) übereinstimmt.
   * Ist eine `expires_at_block` gesetzt, schlägt die Validierung fehl, sobald der
     Header über dem Ablaufblock liegt.
   * Proofs werden nur akzeptiert, wenn Commitment, VK und Version konsistent sind
     **und** die Registry das VK als aktiv markiert.
3. **Cache-Strategie für VK-Blobs:**
   * VK-Bytes werden anhand der `vk_id` gecached (z. B. unter
     `${data_dir}/vk_cache/<vk_id>.bin`). Der Fetch-Pfad nutzt die Registry-URLs
     oder eingebettete Assets.
   * Cache-Invalidierung erfolgt, wenn die Registry-Version wechselt oder der
     Ablaufblock erreicht ist.
4. **Rollout/Upgrade-Pfade:**
   * Während der Grace-Periode akzeptiert der Node sowohl den alten als auch den
     neuen `vk_id`, vergleicht aber das Header-Label gegen den Registry-Eintrag, um
     Fehlkonfigurationen zu erkennen.
   * Telemetrie sollte getrennte Counter für „legacy vk accepted“ und
     „current vk accepted“ erfassen, um den Cutover zu beobachten.
   * Nach Ende der Grace-Periode wird die Legacy-ID aus der akzeptierten Menge
     entfernt; historische Blöcke bleiben verifizierbar, weil die Registry den
     alten Eintrag beibehält.

## Validierungschecks beim Wechsel

* **Header-VK-Check:** `header.global_proof_handle.vk_id` muss exakt der Registry
  Zuordnung für das Version-Label entsprechen.
* **Height-Gates:** Wenn die Registry `activated_at`/`expires_at_block` angibt,
  prüft der Verifier die Header-Höhe gegen diese Grenzen.
* **Proof-Commitment:** Der Hash aus dem Handle muss mit dem neu heruntergeladenen
  Proof-Blob übereinstimmen; ansonsten gilt der Beweis als manipuliert und wird
  verworfen.
* **Cache-Fallback:** Falls der Cache ein abgelaufenes VK enthält, muss der Loader
  den Download forcieren und die Registry-Version aktualisieren, bevor erneut
  validiert wird.
