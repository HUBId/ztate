use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use std::time::Instant;
use tracing::{debug, info, warn};

use crate::{BackendError, BackendResult, Blake2sHasher, ProofVersion};

const INSTANCE_COMMITMENT_MAX_LEN: usize = 64;
const GLOBAL_PROOF_BYTES_MAX_LEN: usize = 4096;
const VERIFICATION_KEY_ID_MAX_LEN: usize = 64;
const PROOF_COMMITMENT_LEN: usize = 32;
const BLOCK_WITNESS_PAYLOAD_MAX_LEN: usize = 4096;

/// Fixed-capacity byte container to keep proof artifacts bounded and allocation-free.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedBytes<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> FixedBytes<N> {
    pub fn new(bytes: impl AsRef<[u8]>) -> BackendResult<Self> {
        let bytes = bytes.as_ref();

        if bytes.len() > N {
            return Err(BackendError::Failure(format!(
                "byte payload exceeds fixed capacity ({} > {})",
                bytes.len(),
                N
            )));
        }

        let mut buffer = [0u8; N];
        buffer[..bytes.len()].copy_from_slice(bytes);

        Ok(Self {
            bytes: buffer,
            len: bytes.len(),
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl<const N: usize> Serialize for FixedBytes<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_slice())
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedBytes<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        FixedBytes::new(bytes).map_err(DeError::custom)
    }
}

/// Represents the running folding instance (Iᵢ) that evolves as blocks are folded.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobalInstance {
    pub index: u64,
    pub commitment: Vec<u8>,
    pub state_commitment: Vec<u8>,
    pub rpp_commitment: Vec<u8>,
    pub pruned_commitment: Vec<u8>,
    pub history_commitment: Vec<u8>,
}

impl GlobalInstance {
    pub fn new(index: u64, commitment: impl Into<Vec<u8>>) -> Self {
        Self {
            index,
            commitment: commitment.into(),
            state_commitment: Vec::new(),
            rpp_commitment: Vec::new(),
            pruned_commitment: Vec::new(),
            history_commitment: Vec::new(),
        }
    }

    /// Build a global instance deterministically from state and pruning commitments.
    ///
    /// The combined commitment is derived by hashing the index, state commitment,
    /// and pruning commitment in a fixed order. No external state is read or
    /// mutated, making the helper safe for both prover and validator flows.
    pub fn from_commitments(
        index: u64,
        state_commitment: impl Into<Vec<u8>>,
        rpp_commitment: impl Into<Vec<u8>>,
        pruned_commitment: impl Into<Vec<u8>>,
        history_commitment: impl Into<Vec<u8>>,
    ) -> Self {
        let state_commitment = state_commitment.into();
        let rpp_commitment = rpp_commitment.into();
        let pruned_commitment = pruned_commitment.into();
        let history_commitment = history_commitment.into();

        let commitment = derive_combined_commitment(
            index,
            &state_commitment,
            &rpp_commitment,
            &pruned_commitment,
            &history_commitment,
        );

        Self {
            index,
            commitment,
            state_commitment,
            rpp_commitment,
            pruned_commitment,
            history_commitment,
        }
    }

    pub fn from_state_and_rpp(
        index: u64,
        state_commitment: impl Into<Vec<u8>>,
        rpp_commitment: impl Into<Vec<u8>>,
    ) -> Self {
        let rpp_commitment = rpp_commitment.into();
        let history_commitment = rpp_commitment.clone();

        Self::from_commitments(
            index,
            state_commitment,
            rpp_commitment.clone(),
            rpp_commitment,
            history_commitment,
        )
    }

    /// Return the header fields carried by the instance for downstream
    /// integrations.
    pub fn to_header_fields(&self) -> CommitmentView<'_> {
        CommitmentView {
            state_commitment: &self.state_commitment,
            rpp_commitment: &self.rpp_commitment,
            pruned_commitment: &self.pruned_commitment,
            history_commitment: &self.history_commitment,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentView<'a> {
    pub state_commitment: &'a [u8],
    pub rpp_commitment: &'a [u8],
    pub pruned_commitment: &'a [u8],
    pub history_commitment: &'a [u8],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitmentSnapshot {
    pub index: u64,
    pub state_commitment: Vec<u8>,
    pub rpp_commitment: Vec<u8>,
    pub pruned_commitment: Vec<u8>,
    pub history_commitment: Vec<u8>,
    pub combined_commitment: Vec<u8>,
}

impl CommitmentSnapshot {
    pub fn new(
        index: u64,
        state_commitment: impl Into<Vec<u8>>,
        rpp_commitment: impl Into<Vec<u8>>,
        pruned_commitment: impl Into<Vec<u8>>,
        history_commitment: impl Into<Vec<u8>>,
    ) -> Self {
        let state_commitment = state_commitment.into();
        let rpp_commitment = rpp_commitment.into();
        let pruned_commitment = pruned_commitment.into();
        let history_commitment = history_commitment.into();

        let combined_commitment = derive_combined_commitment(
            index,
            &state_commitment,
            &rpp_commitment,
            &pruned_commitment,
            &history_commitment,
        );

        Self {
            index,
            state_commitment,
            rpp_commitment,
            pruned_commitment,
            history_commitment,
            combined_commitment,
        }
    }

    pub fn ensure_consistent(&self) -> BackendResult<()> {
        let expected_commitment = derive_combined_commitment(
            self.index,
            &self.state_commitment,
            &self.rpp_commitment,
            &self.pruned_commitment,
            &self.history_commitment,
        );

        if expected_commitment == self.combined_commitment {
            Ok(())
        } else {
            Err(BackendError::Failure(
                "combined commitment does not match constituent commitments".into(),
            ))
        }
    }
}

impl From<&GlobalInstance> for CommitmentSnapshot {
    fn from(instance: &GlobalInstance) -> Self {
        let combined_commitment = if instance.commitment.is_empty() {
            derive_combined_commitment(
                instance.index,
                &instance.state_commitment,
                &instance.rpp_commitment,
                &instance.pruned_commitment,
                &instance.history_commitment,
            )
        } else {
            instance.commitment.clone()
        };

        Self {
            index: instance.index,
            state_commitment: instance.state_commitment.clone(),
            rpp_commitment: instance.rpp_commitment.clone(),
            pruned_commitment: instance.pruned_commitment.clone(),
            history_commitment: instance.history_commitment.clone(),
            combined_commitment,
        }
    }
}

/// Proof artifact tied to a specific global instance.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobalProof {
    pub instance_commitment: FixedBytes<INSTANCE_COMMITMENT_MAX_LEN>,
    pub proof_bytes: FixedBytes<GLOBAL_PROOF_BYTES_MAX_LEN>,
    pub handle: GlobalProofHandle,
}

impl GlobalProof {
    pub fn new(
        instance_commitment: impl AsRef<[u8]>,
        proof_bytes: impl AsRef<[u8]>,
        vk_id: impl AsRef<[u8]>,
        version: ProofVersion,
    ) -> BackendResult<Self> {
        let instance_commitment = FixedBytes::new(instance_commitment)?;
        let proof_bytes = FixedBytes::new(proof_bytes)?;
        let vk_id = FixedBytes::new(vk_id)?;
        let handle = GlobalProofHandle::from_proof_bytes(&proof_bytes, vk_id, version);

        Ok(Self {
            instance_commitment,
            proof_bytes,
            handle,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobalProofHandle {
    pub proof_commitment: [u8; PROOF_COMMITMENT_LEN],
    pub vk_id: FixedBytes<VERIFICATION_KEY_ID_MAX_LEN>,
    pub version: ProofVersion,
}

impl GlobalProofHandle {
    pub fn from_proof_bytes(
        proof_bytes: &FixedBytes<GLOBAL_PROOF_BYTES_MAX_LEN>,
        vk_id: FixedBytes<VERIFICATION_KEY_ID_MAX_LEN>,
        version: ProofVersion,
    ) -> Self {
        let proof_commitment = Blake2sHasher::hash(proof_bytes.as_slice()).0;

        Self {
            proof_commitment,
            vk_id,
            version,
        }
    }
}

/// Public witness material for the next fold step.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockWitness {
    pub block_number: u64,
    pub payload: Vec<u8>,
}

impl BlockWitness {
    pub fn new(block_number: u64, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            block_number,
            payload: payload.into(),
        }
    }
}

/// Interface implemented by backends capable of recursively folding proofs.
pub trait FoldingBackend {
    /// Fold the current instance/proof pair with a block witness to produce the next state.
    fn fold(
        &self,
        instance_prev: &GlobalInstance,
        proof_prev: &GlobalProof,
        block_witness: &BlockWitness,
    ) -> BackendResult<(GlobalInstance, GlobalProof)>;

    /// Verify that a proof is valid for the provided global instance.
    fn verify(&self, instance: &GlobalInstance, proof: &GlobalProof) -> BackendResult<bool>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PruningAirPublicInputs {
    pub previous: CommitmentSnapshot,
    pub next: CommitmentSnapshot,
    pub start_state_commitment: Vec<u8>,
    pub end_state_commitment: Vec<u8>,
    pub inclusion_proofs_ok: bool,
    pub completeness_checks_ok: bool,
}

impl PruningAirPublicInputs {
    pub fn enforce(&self) -> BackendResult<()> {
        self.previous.ensure_consistent()?;
        self.next.ensure_consistent()?;

        if self.previous.index + 1 != self.next.index {
            return Err(BackendError::Failure(
                "pruning fold must advance instance index by exactly one".into(),
            ));
        }

        if self.previous.history_commitment != self.next.pruned_commitment {
            return Err(BackendError::Failure(
                "history commitment link between intervals is invalid".into(),
            ));
        }

        if self.start_state_commitment != self.previous.state_commitment {
            return Err(BackendError::Failure(
                "start state of next interval does not match previous end state".into(),
            ));
        }

        if self.end_state_commitment != self.next.state_commitment {
            return Err(BackendError::Failure(
                "computed end state does not match committed next state".into(),
            ));
        }

        if !self.inclusion_proofs_ok {
            return Err(BackendError::Failure(
                "inclusion proofs for pruning-critical events failed".into(),
            ));
        }

        if !self.completeness_checks_ok {
            return Err(BackendError::Failure(
                "completeness checks for pruning transcript failed".into(),
            ));
        }

        Ok(())
    }
}

/// Execute a single folding step with validation, tracing, and optional verification.
///
/// The helper enforces monotonic block indices, bounds the witness payload, and ensures
/// the provided proof commits to the supplied global instance. When the instance lacks a
/// combined commitment but exposes state and pruning commitments, the commitment is
/// derived deterministically via [`derive_combined_commitment`]. Backend execution is
/// timed and traced, and (under the `folding-verify` feature) a post-fold verification
/// check is issued to guard correctness in debug flows.
pub fn fold_pipeline_step(
    mut instance_prev: GlobalInstance,
    proof_prev: GlobalProof,
    block_witness: BlockWitness,
    backend: &impl FoldingBackend,
) -> BackendResult<(GlobalInstance, GlobalProof)> {
    let start = Instant::now();

    if block_witness.block_number <= instance_prev.index {
        return Err(BackendError::Failure(format!(
            "block number {} must exceed current instance index {}",
            block_witness.block_number, instance_prev.index
        )));
    }

    if block_witness.payload.is_empty() {
        return Err(BackendError::Failure(
            "block witness payload cannot be empty".into(),
        ));
    }

    if block_witness.payload.len() > BLOCK_WITNESS_PAYLOAD_MAX_LEN {
        return Err(BackendError::Failure(format!(
            "block witness payload exceeds limit ({} > {})",
            block_witness.payload.len(),
            BLOCK_WITNESS_PAYLOAD_MAX_LEN
        )));
    }

    if instance_prev.commitment.is_empty()
        && !instance_prev.state_commitment.is_empty()
        && !instance_prev.rpp_commitment.is_empty()
    {
        debug!(
            index = instance_prev.index,
            "deriving missing instance commitment from state and pruning commitments"
        );
        instance_prev.commitment = derive_combined_commitment(
            instance_prev.index,
            &instance_prev.state_commitment,
            &instance_prev.rpp_commitment,
            &instance_prev.pruned_commitment,
            &instance_prev.history_commitment,
        );
    }

    if instance_prev.commitment.is_empty() {
        return Err(BackendError::Failure(
            "global instance is missing a commitment and combination inputs".into(),
        ));
    }

    if proof_prev.instance_commitment.as_slice() != instance_prev.commitment.as_slice() {
        return Err(BackendError::Failure(
            "previous proof commitment does not match global instance".into(),
        ));
    }

    let fold_start = Instant::now();
    let fold_result = backend.fold(&instance_prev, &proof_prev, &block_witness);
    let fold_elapsed = fold_start.elapsed();

    match fold_result {
        Ok((instance_next, proof_next)) => {
            info!(
                previous_index = instance_prev.index,
                next_index = instance_next.index,
                witness_block = block_witness.block_number,
                fold_ms = fold_elapsed.as_millis(),
                "folding step completed"
            );

            #[cfg(feature = "folding-verify")]
            {
                let verify_start = Instant::now();
                let verified = backend.verify(&instance_next, &proof_next)?;
                let verify_elapsed = verify_start.elapsed();

                if !verified {
                    warn!(
                        next_index = instance_next.index,
                        "post-fold verification failed"
                    );
                    return Err(BackendError::Failure(
                        "post-fold verification failed".into(),
                    ));
                }

                info!(
                    next_index = instance_next.index,
                    verify_ms = verify_elapsed.as_millis(),
                    "post-fold verification succeeded"
                );
            }

            let total_elapsed = start.elapsed();
            debug!(
                previous_index = instance_prev.index,
                next_index = instance_next.index,
                total_ms = total_elapsed.as_millis(),
                "fold pipeline step finished"
            );

            Ok((instance_next, proof_next))
        }
        Err(err) => {
            warn!(
                previous_index = instance_prev.index,
                witness_block = block_witness.block_number,
                error = %err,
                "folding step failed"
            );
            Err(err)
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreAuxData {
    pub commitment_chain: Vec<CommitmentSnapshot>,
    pub parent_state_commitment: Vec<u8>,
    pub execution_rules: Vec<u8>,
    pub proof_artifacts: Vec<Vec<u8>>,
    pub chain_spec: Vec<u8>,
    pub checkpoints: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconstructionResult {
    pub reconstructed_state_commitment: Vec<u8>,
    pub history_anchor: Vec<u8>,
}

pub fn reconstruct_block(
    height: u64,
    tip: &CommitmentSnapshot,
    aux: &RestoreAuxData,
) -> BackendResult<ReconstructionResult> {
    if aux.commitment_chain.is_empty() {
        return Err(BackendError::Failure(
            "commitment chain for reconstruction cannot be empty".into(),
        ));
    }

    for snapshot in &aux.commitment_chain {
        snapshot.ensure_consistent()?;
    }

    if aux
        .commitment_chain
        .iter()
        .all(|snapshot| snapshot.index != tip.index)
    {
        return Err(BackendError::Failure(
            "tip commitment is missing from reconstruction chain".into(),
        ));
    }

    let mut preimage = Vec::new();
    preimage.extend_from_slice(&height.to_le_bytes());
    preimage.extend_from_slice(&tip.combined_commitment);
    preimage.extend_from_slice(&aux.parent_state_commitment);
    preimage.extend_from_slice(&aux.execution_rules);
    preimage.extend_from_slice(&aux.chain_spec);

    for snapshot in &aux.commitment_chain {
        preimage.extend_from_slice(&snapshot.combined_commitment);
    }

    for artifact in &aux.proof_artifacts {
        preimage.extend_from_slice(artifact);
    }

    for checkpoint in &aux.checkpoints {
        preimage.extend_from_slice(checkpoint);
    }

    let reconstructed_state_commitment = Blake2sHasher::hash(&preimage).0.to_vec();

    Ok(ReconstructionResult {
        reconstructed_state_commitment,
        history_anchor: tip.history_commitment.clone(),
    })
}

pub fn reconstruct_state_at(
    height: u64,
    tip: &CommitmentSnapshot,
    aux: &RestoreAuxData,
) -> BackendResult<ReconstructionResult> {
    reconstruct_block(height, tip, aux)
}

#[cfg(any(test, feature = "prover-mock"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct MockFoldingBackend;

#[cfg(any(test, feature = "prover-mock"))]
impl MockFoldingBackend {
    const VK_ID: &'static str = "mock-folding-vk";
    const VERSION: ProofVersion = ProofVersion::AggregatedV1;
}

#[cfg(any(test, feature = "prover-mock"))]
impl FoldingBackend for MockFoldingBackend {
    fn fold(
        &self,
        instance_prev: &GlobalInstance,
        _proof_prev: &GlobalProof,
        block_witness: &BlockWitness,
    ) -> BackendResult<(GlobalInstance, GlobalProof)> {
        let next_index = instance_prev.index.saturating_add(1);
        let state_commitment = format!("state-{}", block_witness.block_number).into_bytes();
        let rpp_commitment = format!("rpp-{}", next_index).into_bytes();
        let pruned_commitment = format!("pruned-{}", next_index).into_bytes();
        let history_commitment = format!("history-{}", next_index).into_bytes();
        let instance_commitment = derive_combined_commitment(
            next_index,
            &state_commitment,
            &rpp_commitment,
            &pruned_commitment,
            &history_commitment,
        );
        let proof_bytes = format!("proof-{}", block_witness.block_number).into_bytes();

        let instance_next = GlobalInstance {
            index: next_index,
            commitment: instance_commitment.clone(),
            state_commitment,
            rpp_commitment,
            pruned_commitment,
            history_commitment,
        };
        let proof_next = GlobalProof::new(
            instance_commitment,
            proof_bytes,
            Self::VK_ID.as_bytes(),
            Self::VERSION,
        )?;

        Ok((instance_next, proof_next))
    }

    fn verify(&self, instance: &GlobalInstance, proof: &GlobalProof) -> BackendResult<bool> {
        Ok(proof.instance_commitment.as_slice() == instance.commitment
            && proof.handle.vk_id.as_slice() == Self::VK_ID.as_bytes()
            && proof.handle.version == Self::VERSION)
    }
}

fn derive_combined_commitment(
    index: u64,
    state_commitment: &[u8],
    rpp_commitment: &[u8],
    pruned_commitment: &[u8],
    history_commitment: &[u8],
) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(
        std::mem::size_of::<u64>()
            + state_commitment.len()
            + rpp_commitment.len()
            + pruned_commitment.len()
            + history_commitment.len(),
    );
    preimage.extend_from_slice(&index.to_le_bytes());
    preimage.extend_from_slice(state_commitment);
    preimage.extend_from_slice(rpp_commitment);
    preimage.extend_from_slice(pruned_commitment);
    preimage.extend_from_slice(history_commitment);

    Blake2sHasher::hash(&preimage).0.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Blake2sHasher;

    #[test]
    fn mock_backend_folds_with_deterministic_outputs() {
        let backend = MockFoldingBackend;
        let instance = GlobalInstance::new(0, b"instance-0".to_vec());
        let proof = GlobalProof::new(
            b"instance-0",
            b"proof-0",
            "mock-folding-vk",
            ProofVersion::AggregatedV1,
        )
        .expect("mock proof creation succeeds");
        let witness = BlockWitness::new(42, b"payload".to_vec());

        let (next_instance, next_proof) = backend
            .fold(&instance, &proof, &witness)
            .expect("mock fold succeeds");

        let expected_commitment =
            derive_combined_commitment(1, b"state-42", b"rpp-1", b"pruned-1", b"history-1");

        assert_eq!(next_instance.index, 1);
        assert_eq!(next_instance.commitment, expected_commitment);
        assert_eq!(
            next_proof.instance_commitment.as_slice(),
            next_instance.commitment.as_slice()
        );
        assert_eq!(next_proof.proof_bytes.as_slice(), b"proof-42");
        assert_eq!(next_proof.handle.vk_id.as_slice(), b"mock-folding-vk");
        assert_eq!(next_proof.handle.version, ProofVersion::AggregatedV1);
    }

    #[test]
    fn mock_backend_verifies_matching_commitment() {
        let backend = MockFoldingBackend;
        let instance = GlobalInstance::new(5, b"instance-5".to_vec());
        let proof = GlobalProof::new(
            b"instance-5",
            b"proof-5",
            "mock-folding-vk",
            ProofVersion::AggregatedV1,
        )
        .expect("mock proof creation succeeds");

        assert!(backend
            .verify(&instance, &proof)
            .expect("mock verification succeeds"));
    }

    #[test]
    fn mock_backend_rejects_mismatched_commitment() {
        let backend = MockFoldingBackend;
        let instance = GlobalInstance::new(7, b"instance-7".to_vec());
        let proof = GlobalProof::new(
            b"instance-8",
            b"proof-8",
            "mock-folding-vk",
            ProofVersion::AggregatedV1,
        )
        .expect("mock proof creation succeeds");

        assert!(!backend
            .verify(&instance, &proof)
            .expect("mock verification succeeds"));
    }

    #[test]
    fn reconstruct_block_restores_expected_commitments() {
        let tip_snapshot =
            CommitmentSnapshot::new(12, b"tip-state", b"tip-rpp", b"tip-pruned", b"tip-history");

        let aux = RestoreAuxData {
            commitment_chain: vec![
                CommitmentSnapshot::new(10, b"state-10", b"rpp-10", b"pruned-10", b"history-10"),
                CommitmentSnapshot::new(11, b"state-11", b"rpp-11", b"pruned-11", b"history-11"),
                tip_snapshot.clone(),
            ],
            parent_state_commitment: b"parent-state".to_vec(),
            execution_rules: b"execution-rules".to_vec(),
            proof_artifacts: vec![b"proof-a".to_vec(), b"proof-b".to_vec()],
            chain_spec: b"chain-spec".to_vec(),
            checkpoints: vec![b"checkpoint-1".to_vec(), b"checkpoint-2".to_vec()],
        };

        let reconstructed = reconstruct_block(9, &tip_snapshot, &aux)
            .expect("reconstruction should succeed with consistent inputs");

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&9u64.to_le_bytes());
        preimage.extend_from_slice(&tip_snapshot.combined_commitment);
        preimage.extend_from_slice(&aux.parent_state_commitment);
        preimage.extend_from_slice(&aux.execution_rules);
        preimage.extend_from_slice(&aux.chain_spec);

        for snapshot in &aux.commitment_chain {
            preimage.extend_from_slice(&snapshot.combined_commitment);
        }

        for artifact in &aux.proof_artifacts {
            preimage.extend_from_slice(artifact);
        }

        for checkpoint in &aux.checkpoints {
            preimage.extend_from_slice(checkpoint);
        }

        let expected_commitment = Blake2sHasher::hash(&preimage).0.to_vec();

        assert_eq!(
            reconstructed.reconstructed_state_commitment,
            expected_commitment
        );
        assert_eq!(
            reconstructed.history_anchor,
            tip_snapshot.history_commitment
        );
    }

    #[cfg(feature = "prover-mock")]
    #[test]
    fn mock_pipeline_entrypoint_is_deterministic() {
        let backend = MockFoldingBackend;

        let starting_index = 11u64;
        let previous_commitment = format!("instance-{}", starting_index);
        let previous_proof_bytes = format!("proof-{}", starting_index);

        let instance_prev = GlobalInstance::new(starting_index, previous_commitment.as_bytes());
        let proof_prev = GlobalProof::new(
            previous_commitment.as_bytes(),
            previous_proof_bytes.as_bytes(),
            MockFoldingBackend::VK_ID,
            MockFoldingBackend::VERSION,
        )
        .expect("mock proof creation succeeds");

        let witness_block = starting_index + 1;
        let block_witness = BlockWitness::new(witness_block, b"fold-payload".to_vec());

        let (instance_next, proof_next) =
            fold_pipeline_step(instance_prev, proof_prev, block_witness, &backend)
                .expect("pipeline fold succeeds");

        let expected_index = starting_index + 1;
        let expected_commitment = derive_combined_commitment(
            expected_index,
            &instance_next.state_commitment,
            &instance_next.rpp_commitment,
            &instance_next.pruned_commitment,
            &instance_next.history_commitment,
        );
        let expected_proof_bytes = format!("proof-{}", witness_block);

        assert_eq!(instance_next.index, expected_index);
        assert_eq!(instance_next.commitment, expected_commitment);
        assert!(!instance_next.state_commitment.is_empty());
        assert!(!instance_next.pruned_commitment.is_empty());
        assert!(!instance_next.history_commitment.is_empty());
        assert_eq!(
            proof_next.instance_commitment.as_slice(),
            expected_commitment.as_slice()
        );
        assert_eq!(
            proof_next.proof_bytes.as_slice(),
            expected_proof_bytes.as_bytes()
        );
        assert_eq!(
            proof_next.handle.vk_id.as_slice(),
            MockFoldingBackend::VK_ID.as_bytes()
        );
        assert_eq!(proof_next.handle.version, MockFoldingBackend::VERSION);
    }

    #[test]
    fn constructs_instance_from_state_and_rpp() {
        let index = 10u64;
        let state_commitment = b"state-root".to_vec();
        let rpp_commitment = b"rpp-root".to_vec();

        let instance = GlobalInstance::from_state_and_rpp(
            index,
            state_commitment.clone(),
            rpp_commitment.clone(),
        );

        assert_eq!(instance.index, index);
        assert_eq!(instance.state_commitment, state_commitment);
        assert_eq!(instance.rpp_commitment, rpp_commitment);
        assert_eq!(instance.pruned_commitment, instance.rpp_commitment);
        assert_eq!(instance.history_commitment, instance.rpp_commitment);

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&index.to_le_bytes());
        preimage.extend_from_slice(b"state-root");
        preimage.extend_from_slice(b"rpp-root");
        preimage.extend_from_slice(b"rpp-root");
        preimage.extend_from_slice(b"rpp-root");

        let expected_commitment = Blake2sHasher::hash(&preimage).0.to_vec();
        assert_eq!(instance.commitment, expected_commitment);
    }

    #[test]
    fn from_state_and_rpp_is_deterministic() {
        let base = GlobalInstance::from_state_and_rpp(3, b"state-a", b"rpp-a");
        let same = GlobalInstance::from_state_and_rpp(3, b"state-a", b"rpp-a");
        let different = GlobalInstance::from_state_and_rpp(4, b"state-a", b"rpp-a");

        assert_eq!(base.commitment, same.commitment);
        assert_ne!(base.commitment, different.commitment);
    }

    #[test]
    fn pruning_air_inputs_enforce_links() {
        let previous = CommitmentSnapshot::new(1, b"state-1", b"rpp-1", b"pruned-1", b"history-1");
        let next = CommitmentSnapshot::new(2, b"state-2", b"rpp-2", b"history-1", b"history-2");

        let inputs = PruningAirPublicInputs {
            previous: previous.clone(),
            next: next.clone(),
            start_state_commitment: previous.state_commitment.clone(),
            end_state_commitment: next.state_commitment.clone(),
            inclusion_proofs_ok: true,
            completeness_checks_ok: true,
        };

        assert!(inputs.enforce().is_ok());

        let mut broken = inputs.clone();
        broken.completeness_checks_ok = false;

        assert!(broken.enforce().is_err());
    }

    #[test]
    fn reconstruct_block_hashes_inputs_into_state_anchor() {
        let tip =
            CommitmentSnapshot::new(5, b"state-tip", b"rpp-tip", b"pruned-tip", b"history-tip");
        let aux = RestoreAuxData {
            commitment_chain: vec![
                CommitmentSnapshot::new(4, b"state-4", b"rpp-4", b"pruned-4", b"history-4"),
                tip.clone(),
            ],
            parent_state_commitment: b"parent-state".to_vec(),
            execution_rules: b"rules".to_vec(),
            proof_artifacts: vec![b"proof-a".to_vec(), b"proof-b".to_vec()],
            chain_spec: b"chain-spec".to_vec(),
            checkpoints: vec![b"checkpoint".to_vec()],
        };

        let reconstructed = reconstruct_block(4, &tip, &aux).expect("reconstruction succeeds");
        assert_eq!(reconstructed.history_anchor, tip.history_commitment);

        let reproduced =
            reconstruct_state_at(4, &tip, &aux).expect("state reconstruction succeeds");
        assert_eq!(reconstructed, reproduced);
    }

    #[test]
    fn header_fields_expose_state_and_rpp_commitments() {
        let instance = GlobalInstance::from_state_and_rpp(99, b"state-h", b"rpp-h");
        let header = instance.to_header_fields();

        assert_eq!(
            header.state_commitment,
            instance.state_commitment.as_slice()
        );
        assert_eq!(header.rpp_commitment, instance.rpp_commitment.as_slice());
        assert_eq!(
            header.pruned_commitment,
            instance.pruned_commitment.as_slice()
        );
        assert_eq!(
            header.history_commitment,
            instance.history_commitment.as_slice()
        );
    }

    #[test]
    fn fold_pipeline_validates_and_derives_commitments() {
        let backend = MockFoldingBackend;
        let index = 3u64;
        let instance = GlobalInstance {
            index,
            commitment: Vec::new(),
            state_commitment: b"state-fold".to_vec(),
            rpp_commitment: b"rpp-fold".to_vec(),
            pruned_commitment: b"pruned-fold".to_vec(),
            history_commitment: b"history-fold".to_vec(),
        };

        let derived_commitment = derive_combined_commitment(
            index,
            &instance.state_commitment,
            &instance.rpp_commitment,
            &instance.pruned_commitment,
            &instance.history_commitment,
        );
        let proof = GlobalProof::new(
            &derived_commitment,
            b"proof-fold",
            MockFoldingBackend::VK_ID,
            MockFoldingBackend::VERSION,
        )
        .expect("mock proof creation succeeds");
        let witness = BlockWitness::new(index + 1, vec![1, 2, 3, 4]);

        let (next_instance, next_proof) =
            fold_pipeline_step(instance.clone(), proof, witness, &backend)
                .expect("pipeline fold succeeds");

        assert_eq!(next_instance.index, instance.index + 1);
        let expected_commitment = derive_combined_commitment(
            next_instance.index,
            &next_instance.state_commitment,
            &next_instance.rpp_commitment,
            &next_instance.pruned_commitment,
            &next_instance.history_commitment,
        );
        assert_eq!(
            next_proof.instance_commitment.as_slice(),
            expected_commitment
        );
        assert_eq!(next_instance.commitment, expected_commitment);
    }

    #[test]
    fn fold_pipeline_rejects_non_monotonic_indices() {
        let backend = MockFoldingBackend;
        let instance = GlobalInstance::new(5, b"instance-5".to_vec());
        let proof = GlobalProof::new(
            b"instance-5",
            b"proof-5",
            MockFoldingBackend::VK_ID,
            MockFoldingBackend::VERSION,
        )
        .expect("mock proof creation succeeds");
        let witness = BlockWitness::new(5, vec![1]);

        let err = fold_pipeline_step(instance, proof, witness, &backend)
            .expect_err("fold should fail for non-monotonic indices");

        assert!(matches!(err, BackendError::Failure(message) if message.contains("exceed")));
    }

    #[test]
    fn fold_pipeline_rejects_oversized_payloads() {
        let backend = MockFoldingBackend;
        let instance = GlobalInstance::new(8, b"instance-8".to_vec());
        let proof = GlobalProof::new(
            b"instance-8",
            b"proof-8",
            MockFoldingBackend::VK_ID,
            MockFoldingBackend::VERSION,
        )
        .expect("mock proof creation succeeds");
        let witness = BlockWitness::new(9, vec![0u8; BLOCK_WITNESS_PAYLOAD_MAX_LEN + 1]);

        let err = fold_pipeline_step(instance, proof, witness, &backend)
            .expect_err("fold should fail for oversized payloads");

        assert!(matches!(err, BackendError::Failure(message) if message.contains("exceeds")));
    }
}
