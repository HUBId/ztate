# fold_global integration notes

## Legacy aggregation touchpoints
- **STWO prover batch wiring** (`rpp/proofs/stwo/prover/mod.rs`): `derive_recursive_witness` builds the recursive witness after all batch proofs and pruning metadata are available. The call is currently routed through `RecursiveAggregator::new(...).build_witness(...)` and is tagged with a TODO for swapping in `fold_global` once the folding pipeline owns the batch output.
- **Plonky3 prover recursion** (`rpp/proofs/plonky3/prover/mod.rs`): `prove_recursive` finalizes the recursive batch via the backend-specific `RecursiveAggregator`. A TODO marks this as the handoff point where `fold_global` should accept the Plonky3 recursion artifact instead of the legacy aggregator path.
- **STWO verifier commitment check** (`prover/prover_stwo_backend/src/official/verifier/mod.rs`): `compute_recursive_commitment` recomputes the recursive hash inside the verifier. A TODO documents that this should be replaced with a `fold_global` verification hook so the accumulator operates on folded instances.

## Interface deltas to cover
- Current aggregation expects **hex-encoded commitments and `StateCommitmentSnapshot` structs** plus pruning digests, whereas `fold_global` operates on `GlobalInstance`/`GlobalProof` pairs (`rpp/zk/backend-interface/src/folding.rs`). Parameter conversion from hex strings to the fixed-length byte payloads used by `GlobalInstance::from_state_and_rpp` and `GlobalProof::new` will be required.
- The existing recursive helpers return **`RecursiveWitness` structs or raw `FieldElement` commitments**; `fold_global` emits **`GlobalProofHandle` metadata** and proof bytes instead, so callers will need to persist the folding handle instead of hex commitments.
- Aggregator constructors currently rely on **`StarkParameters`/`Plonky3Parameters`** and backend-specific verifiers. `fold_global` expects a **`FoldingBackend`** implementation, so re-exports and trait object wiring in the prover crates must be adjusted to surface that backend to the orchestration layer.

## Verifier/accumulator dependencies
- The node verifier currently recomputes recursive commitments to validate the proof payload. Moving to `fold_global` means the accumulator needs access to the **`GlobalInstance` commitment chain** and should verify against `GlobalProofHandle::proof_commitment` instead of the Poseidon-based recursive hash.
- Final ledger checks that depend on `StateCommitmentSnapshot` (e.g., pruning/state roots) will need to pull the same fields from the folded instance headers (`GlobalInstance::to_header_fields`) to avoid duplicating validation logic.

## Open items for the refactor
- Define the **byte/hex normalization** between existing `TaggedDigestHex` fields and the byte vectors expected by `GlobalInstance`/`GlobalProof` constructors.
- Confirm **batch size and constraint limits** (`MAX_BATCHED_PROOFS`) remain enforceable once folding subsumes recursive aggregation.
- Identify how **previous recursive commitments** map to the `GlobalProofHandle` chain so block height/index offsets remain monotonic.
- Determine whether **telemetry and metrics** that currently record aggregation latency need to be moved to the folding backend interfaces.
