# Nova-Folding-Demo (I_boot + π_boot)

Dieses Playbook demonstriert den Nova-Folding-Flow mit dem Mock-Backend. Das
Skript initialisiert eine deterministische Startinstanz (`I_boot` + `π_boot`),
faltet drei Blöcke nacheinander und prüft nach jedem Schritt den Handle und die
Verifikation. Alle Artefakte werden lokal erzeugt; es ist kein Backend-Cluster
oder Snapshot-Download nötig.

## Demo ausführen

```sh
RUST_LOG=info,folding.pipeline=debug scripts/demo_nova_folding.sh
```

Die Ausgabe zeigt die Initialisierung und drei Faltungs-Schritte mit Handle und
Verifikation:

```
I_boot index=0 commitment=6810c0c1b37c876659ce28f813d55aa76d9a07bf0fd45cf92264ac7b5e379280 (state=73746174652d30, rpp=7270702d30)
π_boot handle: commitment=a50bb56d71949189eeeac187507b19144ed552ea68f676e1fcef5c0a939e5ad0 vk_id=mock-folding-vk version=AggregatedV1
2025-12-08T15:15:52.992447Z  INFO prover_backend_interface::folding: folding step completed previous_index=0 next_index=1 witness_block=1 fold_ms=0
Folded block 1: I_1 commitment=688e3305d912d92cec7ff2a040fd4ed88872ddba4733a5637de8d153154ef3cc / proof=ea55025013d4a30593fca6675fd14691ed21b5a388e68e9bfb3bcb1deec1d5a0 / vk_id=mock-folding-vk / verified=true
2025-12-08T15:15:52.992980Z  INFO prover_backend_interface::folding: folding step completed previous_index=2 next_index=3 witness_block=3 fold_ms=0
Folded block 3: I_3 commitment=72ec192d73c1f15f1b0e4dde5eef20d33617d3baf9d14cc3c7027e58b7d83887 / proof=3d07c79bc064a7ee549bbcbe7d1a16afaa5525ab866bc4250823ee5a64ed2719 / vk_id=mock-folding-vk / verified=true
```
【5aa476†L1-L22】【5aa476†L23-L28】

## Erwartete Artefakte

- **Initialer Zustand:** `I_boot` entsteht deterministisch aus State- und
  Pruning-Commitments über `from_state_and_rpp`, sodass Validatoren denselben
  Combined-Hash berechnen können.【F:rpp/zk/backend-interface/src/folding.rs†L206-L279】
- **Handle für π_boot:** `GlobalProof::new` erzeugt einen Handle mit
  Proof-Commitment (Blake2s über die Proof-Bytes), VK-ID und `ProofVersion`.
  Diese Werte erscheinen im Header und im Demo-Output, der Proof-Blob bleibt
  lokal.【F:rpp/zk/backend-interface/src/folding.rs†L375-L423】
- **Faltungs-Schritte:** Jeder `fold_pipeline_step` baut `I_i`/`π_i` mit dem
  Mock-Backend neu auf; die Commitments und Handles sind deterministisch aus
  Blocknummer und Witness abgeleitet, sodass die Demo-Ausgabe reproduzierbar
  bleibt.【F:rpp/zk/backend-interface/src/folding.rs†L783-L827】

## Fehlersuche und Validierung

- `fold_pipeline_step` validiert Monotonie und Payload-Bounds und versieht
  Ablehnungen mit `FOLD-STEP-*` Codes (`folding.pipeline`-Logs), z. B. bei
  wiederverwendeten Blocknummern oder leeren Witness-Payloads.【F:rpp/zk/backend-interface/src/folding.rs†L520-L604】
- Erfolgreiche Schritte protokollieren das neue Commitment, schreiben Telemetrie
  und (optional) verifizieren den Proof direkt nach dem Fold. Die Demo ruft
  zusätzlich `verify` des Mock-Backends auf und meldet `verified=true`, damit
  Tester die vollständige Kette sehen.【F:rpp/zk/backend-interface/src/folding.rs†L608-L639】【F:rpp/zk/backend-interface/src/folding.rs†L822-L826】
- Schlägt ein Schritt fehl, liefert der Prozess einen non-zero Exit-Code. Mit
  `RUST_LOG=warn,folding.pipeline=debug` erscheinen die Fehlermeldungen inkl.
  Reject-Code im Terminal, sodass Operatoren die Ursache sofort erkennen.
