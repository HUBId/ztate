# Folding-CI und Performance-Grenzwerte

Die Folding-spezifischen Pipelines bestehen aus zwei Bausteinen:

1. **CI-Tests** (`.github/workflows/folding.yml`)
   - Führt `cargo test -p rpp-chain global_proof` und die Mock-Pipeline (`block_witness_flows_into_mock_fold_pipeline`) aus.
   - Prüft die Storage-Sequenzen rund um `GlobalProof` (`cargo test -p rpp-chain bootstraps_fold_pipeline_from_cut_tip`).
   - Erzwingt die Migration `AggregatedV1 → NovaV2` über den Test `nova_cutover_requires_bootstrap_version_shift`.
2. **Performance-Gates** (`folding`-Job in `.github/workflows/perf.yml`)
   - Nutzt `cargo run -p rpp-chain --bin folding_perf --release`, um eine Kette synthetischer GlobalProofs aufzubauen und `verify_global_proof` in Serie zu messen.
   - Schreibt die Messwerte nach `folding-perf.json` und fasst sie in `folding-perf-summary.tsv` zusammen (Artefakte des Jobs).

## Schwellenwerte

Die Failure-Gates im Perf-Job schlagen fehl, wenn eine der folgenden Bedingungen verletzt wird:

- **AggregatedV1**
  - Maximale Proof-Größe: `FOLDING_MAX_AGGREGATED_KIB = 12` KiB
  - Verifikationszeit pro Proof: `FOLDING_MAX_AGGREGATED_VERIFY_MS = 1.5` ms
- **NovaV2**
  - Maximale Proof-Größe: `FOLDING_MAX_NOVA_KIB = 16` KiB
  - Verifikationszeit pro Proof: `FOLDING_MAX_NOVA_VERIFY_MS = 2.5` ms

Die Kettenlänge (`FOLDING_PERF_CHAIN_LENGTH`, Standard `256`) und die synthetische Payload-Größe (`FOLDING_PERF_PROOF_BYTES`, Standard `4096`) können im Workflow überschrieben werden. Die Benchmarks laufen mit stabilem Toolchain-Stand und werden bei täglichen Perf-Runs als Artefakte veröffentlicht.
