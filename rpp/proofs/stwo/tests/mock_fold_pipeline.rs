#![cfg(feature = "prover-mock")]

use std::sync::Arc;

use prover_backend_interface::folding::{
    fold_pipeline_step, BlockWitness as FoldingBlockWitness, GlobalInstance, GlobalProof,
    MockFoldingBackend, ProofVersion,
};
use rpp_pruning::{Envelope, DIGEST_LENGTH};
use tracing_test::traced_test;

use crate::errors::{ChainError, ChainResult};
use crate::rpp::{produce_block_witness, MerklePathWitness, StateView, TransactionWitness};
use crate::runtime::types::SignedTransaction;

use super::mock_state_view::{
    dummy_block, dummy_pruning_proof, dummy_transaction, CountingStateView,
};

#[traced_test]
#[cfg_attr(not(feature = "prover-mock"), ignore)]
fn block_witness_flows_into_mock_fold_pipeline() {
    let pruning_proof = dummy_pruning_proof();
    let state_view = CountingStateView::new(2, vec![pruning_proof.clone()]);

    let tx_a = dummy_transaction("alice", "bob", 10, 1, 0, 1);
    let tx_b = dummy_transaction("carol", "dave", 20, 2, 1, 2);
    let mut block = dummy_block(vec![tx_a, tx_b], pruning_proof);
    block.header.height = 1;

    let witness = produce_block_witness(block.clone(), &state_view).expect("witness should build");
    let payload = bincode::serialize(&witness).expect("witness serialization should succeed");
    let folding_witness = FoldingBlockWitness::new(block.header.height, payload);

    let instance_prev = GlobalInstance::new(0, b"instance-0".to_vec());
    let proof_prev = GlobalProof::new(
        b"instance-0",
        b"proof-0",
        b"mock-folding-vk",
        ProofVersion::AggregatedV1,
    )
    .expect("mock proof creation succeeds");

    let (instance_next, proof_next) = fold_pipeline_step(
        instance_prev,
        proof_prev,
        folding_witness,
        &MockFoldingBackend,
    )
    .expect("fold pipeline should succeed");

    assert_eq!(instance_next.index, 1);
    assert_eq!(instance_next.commitment, b"instance-1".to_vec());
    assert_eq!(proof_next.instance_commitment.as_slice(), b"instance-1");
    assert_eq!(proof_next.proof_bytes.as_slice(), b"proof-1");
    assert!(!logs_contain("ERROR"));
    assert!(logs_contain("cache miss recorded"));
    assert!(logs_contain("fold pipeline step finished"));
}

#[traced_test]
#[cfg_attr(not(feature = "prover-mock"), ignore)]
fn missing_transaction_path_aborts_pipeline() {
    let mut block = dummy_block(
        vec![dummy_transaction("eve", "frank", 5, 1, 0, 3)],
        dummy_pruning_proof(),
    );
    block.header.height = 1;

    let failing_state_view = FailingStateView::new(2, true, false);
    let err = produce_block_witness(block, &failing_state_view)
        .expect_err("missing path should fail witness construction");

    assert!(format!("{err}").contains("transaction merkle path unavailable"));
    assert!(logs_contain("transaction merkle path unavailable"));
    assert!(!logs_contain("fold pipeline step finished"));
}

#[traced_test]
#[cfg_attr(not(feature = "prover-mock"), ignore)]
fn missing_pruning_proof_aborts_pipeline() {
    let mut block = dummy_block(
        vec![dummy_transaction("grace", "heidi", 7, 1, 0, 4)],
        dummy_pruning_proof(),
    );
    block.header.height = 1;

    let failing_state_view = FailingStateView::new(2, false, true);
    let err = produce_block_witness(block, &failing_state_view)
        .expect_err("missing pruning proof should fail witness construction");

    assert!(format!("{err}").contains("pruning proof unavailable"));
    assert!(logs_contain("pruning proof unavailable"));
    assert!(!logs_contain("fold pipeline step finished"));
}

struct FailingStateView {
    path_depth: u32,
    fail_path: bool,
    fail_pruning: bool,
}

impl FailingStateView {
    fn new(path_depth: u32, fail_path: bool, fail_pruning: bool) -> Self {
        Self {
            path_depth,
            fail_path,
            fail_pruning,
        }
    }
}

impl StateView for FailingStateView {
    fn merkle_path_depth(&self) -> ChainResult<u32> {
        Ok(self.path_depth)
    }

    fn cached_transaction_path(&self, _tx: &SignedTransaction) -> Option<MerklePathWitness> {
        None
    }

    fn load_transaction_path(&self, _tx: &SignedTransaction) -> ChainResult<MerklePathWitness> {
        if self.fail_path {
            let message = "transaction merkle path unavailable";
            tracing::error!(message);
            return Err(ChainError::Config(message.into()));
        }

        let siblings = vec![[0u8; DIGEST_LENGTH]; self.path_depth as usize];
        MerklePathWitness::new(self.path_depth, siblings)
    }

    fn cached_pruning_proofs(&self) -> Option<Vec<Arc<Envelope>>> {
        None
    }

    fn load_pruning_proofs(&self) -> ChainResult<Vec<Arc<Envelope>>> {
        if self.fail_pruning {
            let message = "pruning proof unavailable";
            tracing::error!(message);
            return Err(ChainError::Config(message.into()));
        }

        Ok(vec![dummy_pruning_proof()])
    }

    fn transaction_witness(&self, tx: &SignedTransaction) -> ChainResult<TransactionWitness> {
        Ok(CountingStateView::build_transaction_witness(tx))
    }

    fn log_cache_miss(&self, kind: &str) {
        tracing::debug!(cache = kind, "cache miss recorded");
    }
}
