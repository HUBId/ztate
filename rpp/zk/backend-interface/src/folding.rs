use serde::{Deserialize, Serialize};

use crate::{BackendResult, Blake2sHasher};

/// Represents the running folding instance (Iᵢ) that evolves as blocks are folded.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobalInstance {
    pub index: u64,
    pub commitment: Vec<u8>,
    pub state_commitment: Vec<u8>,
    pub rpp_commitment: Vec<u8>,
}

impl GlobalInstance {
    pub fn new(index: u64, commitment: impl Into<Vec<u8>>) -> Self {
        Self {
            index,
            commitment: commitment.into(),
            state_commitment: Vec::new(),
            rpp_commitment: Vec::new(),
        }
    }

    /// Build a global instance deterministically from state and pruning commitments.
    ///
    /// The combined commitment is derived by hashing the index, state commitment,
    /// and pruning commitment in a fixed order. No external state is read or
    /// mutated, making the helper safe for both prover and validator flows.
    pub fn from_state_and_rpp(
        index: u64,
        state_commitment: impl Into<Vec<u8>>,
        rpp_commitment: impl Into<Vec<u8>>,
    ) -> Self {
        let state_commitment = state_commitment.into();
        let rpp_commitment = rpp_commitment.into();

        let commitment = derive_combined_commitment(index, &state_commitment, &rpp_commitment);

        Self {
            index,
            commitment,
            state_commitment,
            rpp_commitment,
        }
    }

    /// Return the header fields carried by the instance for downstream
    /// integrations.
    pub fn to_header_fields(&self) -> (&[u8], &[u8]) {
        (&self.state_commitment, &self.rpp_commitment)
    }
}

/// Proof artifact tied to a specific global instance.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobalProof {
    pub instance_commitment: Vec<u8>,
    pub proof_bytes: Vec<u8>,
    pub vk_id: String,
}

impl GlobalProof {
    pub fn new(
        instance_commitment: impl Into<Vec<u8>>,
        proof_bytes: impl Into<Vec<u8>>,
        vk_id: impl Into<String>,
    ) -> Self {
        Self {
            instance_commitment: instance_commitment.into(),
            proof_bytes: proof_bytes.into(),
            vk_id: vk_id.into(),
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

#[cfg(any(test, feature = "prover-mock"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct MockFoldingBackend;

#[cfg(any(test, feature = "prover-mock"))]
impl MockFoldingBackend {
    const VK_ID: &'static str = "mock-folding-vk";
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
        let instance_commitment = derive_mock_instance_commitment(instance_prev, block_witness);
        let proof_bytes = derive_mock_proof_bytes(&instance_commitment, block_witness);

        let instance_next = GlobalInstance::new(next_index, instance_commitment.clone());
        let proof_next = GlobalProof::new(instance_commitment, proof_bytes, Self::VK_ID);

        Ok((instance_next, proof_next))
    }

    fn verify(&self, instance: &GlobalInstance, proof: &GlobalProof) -> BackendResult<bool> {
        Ok(proof.instance_commitment == instance.commitment && proof.vk_id == Self::VK_ID)
    }
}

#[cfg(any(test, feature = "prover-mock"))]
fn derive_mock_instance_commitment(
    instance_prev: &GlobalInstance,
    block_witness: &BlockWitness,
) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(
        std::mem::size_of::<u64>()
            + instance_prev.commitment.len()
            + std::mem::size_of::<u64>()
            + block_witness.payload.len(),
    );
    preimage.extend_from_slice(&instance_prev.index.to_le_bytes());
    preimage.extend_from_slice(&instance_prev.commitment);
    preimage.extend_from_slice(&block_witness.block_number.to_le_bytes());
    preimage.extend_from_slice(&block_witness.payload);

    Blake2sHasher::hash(&preimage).0.to_vec()
}

#[cfg(any(test, feature = "prover-mock"))]
fn derive_mock_proof_bytes(instance_commitment: &[u8], block_witness: &BlockWitness) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(
        instance_commitment.len()
            + std::mem::size_of::<u64>()
            + block_witness.payload.len(),
    );
    preimage.extend_from_slice(instance_commitment);
    preimage.extend_from_slice(&block_witness.block_number.to_le_bytes());
    preimage.extend_from_slice(&block_witness.payload);

    Blake2sHasher::hash(&preimage).0.to_vec()
}

fn derive_combined_commitment(
    index: u64,
    state_commitment: &[u8],
    rpp_commitment: &[u8],
) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(
        std::mem::size_of::<u64>() + state_commitment.len() + rpp_commitment.len(),
    );
    preimage.extend_from_slice(&index.to_le_bytes());
    preimage.extend_from_slice(state_commitment);
    preimage.extend_from_slice(rpp_commitment);

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
        let proof = GlobalProof::new(b"instance-0", b"proof-0", "mock-folding-vk");
        let witness = BlockWitness::new(42, b"payload".to_vec());

        let (next_instance, next_proof) = backend
            .fold(&instance, &proof, &witness)
            .expect("mock fold succeeds");

        let expected_commitment = derive_mock_instance_commitment(&instance, &witness);
        let expected_proof = derive_mock_proof_bytes(&expected_commitment, &witness);

        assert_eq!(next_instance.index, 1);
        assert_eq!(next_instance.commitment, expected_commitment);
        assert_eq!(next_proof.instance_commitment, next_instance.commitment);
        assert_eq!(next_proof.proof_bytes, expected_proof);
        assert_eq!(next_proof.vk_id, "mock-folding-vk");

        assert_eq!(next_proof.proof_bytes.len(), Blake2sHasher::hash(&[]).0.len());
        assert_eq!(next_proof.instance_commitment.len(), Blake2sHasher::hash(&[]).0.len());
    }

    #[test]
    fn mock_backend_verifies_matching_commitment() {
        let backend = MockFoldingBackend;
        let witness = BlockWitness::new(5, b"payload".to_vec());
        let instance_prev = GlobalInstance::new(4, b"instance-4".to_vec());
        let commitment = derive_mock_instance_commitment(&instance_prev, &witness);
        let proof_bytes = derive_mock_proof_bytes(&commitment, &witness);
        let instance = GlobalInstance::new(5, commitment.clone());
        let proof = GlobalProof::new(commitment, proof_bytes, "mock-folding-vk");

        assert!(backend
            .verify(&instance, &proof)
            .expect("mock verification succeeds"));
    }

    #[test]
    fn mock_backend_rejects_mismatched_commitment() {
        let backend = MockFoldingBackend;
        let instance = GlobalInstance::new(7, b"instance-7".to_vec());
        let proof = GlobalProof::new(b"instance-8", b"proof-8", "mock-folding-vk");

        assert!(!backend
            .verify(&instance, &proof)
            .expect("mock verification succeeds"));
    }

    #[test]
    fn mock_backend_roundtrip_fold_and_verify() {
        let backend = MockFoldingBackend;
        let instance = GlobalInstance::new(2, b"instance-2".to_vec());
        let proof = GlobalProof::new(b"instance-2", b"proof-2", "mock-folding-vk");
        let witness = BlockWitness::new(11, b"roundtrip".to_vec());

        let (next_instance, next_proof) = backend
            .fold(&instance, &proof, &witness)
            .expect("fold should succeed");

        assert!(backend
            .verify(&next_instance, &next_proof)
            .expect("verification should succeed"));
    }

    #[test]
    fn mock_backend_produces_fixed_size_proofs() {
        let backend = MockFoldingBackend;
        let instance = GlobalInstance::new(0, b"instance-0".to_vec());
        let proof = GlobalProof::new(b"instance-0", b"proof-0", "mock-folding-vk");
        let witness = BlockWitness::new(1, b"size-check".to_vec());

        let (_, proof_one) = backend
            .fold(&instance, &proof, &witness)
            .expect("first fold succeeds");

        let (_, proof_two) = backend
            .fold(&instance, &proof, &witness)
            .expect("second fold succeeds deterministically");

        assert_eq!(proof_one.proof_bytes.len(), Blake2sHasher::hash(&[]).0.len());
        assert_eq!(proof_two.proof_bytes.len(), Blake2sHasher::hash(&[]).0.len());
        assert_eq!(proof_one.proof_bytes, proof_two.proof_bytes);
        assert_eq!(proof_one.instance_commitment, proof_two.instance_commitment);
    }

    #[test]
    fn deterministic_commitments_depend_on_inputs() {
        let backend = MockFoldingBackend;
        let instance = GlobalInstance::new(1, b"instance-1".to_vec());
        let proof = GlobalProof::new(b"instance-1", b"proof-1", "mock-folding-vk");
        let witness_a = BlockWitness::new(3, b"payload-a".to_vec());
        let witness_b = BlockWitness::new(3, b"payload-b".to_vec());

        let (next_instance_a, _) = backend
            .fold(&instance, &proof, &witness_a)
            .expect("fold a succeeds");
        let (next_instance_a_repeat, _) = backend
            .fold(&instance, &proof, &witness_a)
            .expect("fold a repeat succeeds");
        let (next_instance_b, _) = backend
            .fold(&instance, &proof, &witness_b)
            .expect("fold b succeeds");

        assert_eq!(next_instance_a.commitment, next_instance_a_repeat.commitment);
        assert_ne!(next_instance_a.commitment, next_instance_b.commitment);
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

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&index.to_le_bytes());
        preimage.extend_from_slice(b"state-root");
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
    fn header_fields_expose_state_and_rpp_commitments() {
        let instance = GlobalInstance::from_state_and_rpp(99, b"state-h", b"rpp-h");
        let (state_header, rpp_header) = instance.to_header_fields();

        assert_eq!(state_header, instance.state_commitment.as_slice());
        assert_eq!(rpp_header, instance.rpp_commitment.as_slice());
    }
}
