use serde::{Deserialize, Serialize};

use crate::BackendResult;

/// Represents the running folding instance (Iᵢ) that evolves as blocks are folded.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobalInstance {
    pub index: u64,
    pub commitment: Vec<u8>,
}

impl GlobalInstance {
    pub fn new(index: u64, commitment: impl Into<Vec<u8>>) -> Self {
        Self {
            index,
            commitment: commitment.into(),
        }
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
        let instance_commitment = format!("instance-{}", next_index).into_bytes();
        let proof_bytes = format!("proof-{}", block_witness.block_number).into_bytes();

        let instance_next = GlobalInstance::new(next_index, instance_commitment.clone());
        let proof_next = GlobalProof::new(instance_commitment, proof_bytes, Self::VK_ID);

        Ok((instance_next, proof_next))
    }

    fn verify(&self, instance: &GlobalInstance, proof: &GlobalProof) -> BackendResult<bool> {
        Ok(proof.instance_commitment == instance.commitment && proof.vk_id == Self::VK_ID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_backend_folds_with_deterministic_outputs() {
        let backend = MockFoldingBackend;
        let instance = GlobalInstance::new(0, b"instance-0".to_vec());
        let proof = GlobalProof::new(b"instance-0", b"proof-0", "mock-folding-vk");
        let witness = BlockWitness::new(42, b"payload".to_vec());

        let (next_instance, next_proof) = backend
            .fold(&instance, &proof, &witness)
            .expect("mock fold succeeds");

        assert_eq!(next_instance.index, 1);
        assert_eq!(next_instance.commitment, b"instance-1".to_vec());
        assert_eq!(next_proof.instance_commitment, b"instance-1".to_vec());
        assert_eq!(next_proof.proof_bytes, b"proof-42".to_vec());
        assert_eq!(next_proof.vk_id, "mock-folding-vk");
    }

    #[test]
    fn mock_backend_verifies_matching_commitment() {
        let backend = MockFoldingBackend;
        let instance = GlobalInstance::new(5, b"instance-5".to_vec());
        let proof = GlobalProof::new(b"instance-5", b"proof-5", "mock-folding-vk");

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
}
