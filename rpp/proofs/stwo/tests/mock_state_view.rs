#![cfg(feature = "prover-mock")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use uuid::Uuid;

use crate::consensus::messages::{
    ConsensusCertificate, ConsensusProofMetadata, ConsensusProofMetadataVrf,
};
use crate::consensus::ConsensusWitnessBindings;
use crate::errors::ChainResult;
use crate::rpp::{
    produce_block_witness, AccountBalanceWitness, MerklePathWitness, ModuleWitnessBundle,
    TransactionUtxoSnapshot, TransactionWitness, UtxoOutpoint,
};
use crate::runtime::types::{
    block::{Block, ProofSystem, RecursiveProof},
    proofs::{BlockProofBundle, ChainProof},
    ReputationUpdate, SignedTransaction, TimetokeUpdate, Transaction, UptimeProof,
};
use crate::state::StoredUtxo;
use rpp_pruning::{
    BlockHeight, Commitment, Envelope, ParameterVersion, SchemaVersion, Snapshot, TaggedDigest,
    COMMITMENT_TAG, DIGEST_LENGTH, ENVELOPE_TAG, SNAPSHOT_STATE_TAG,
};

struct CountingStateView {
    path_depth: u32,
    pruning_proofs: Vec<Arc<Envelope>>,
    cache_misses: Mutex<HashMap<String, usize>>,
    pruning_loads: AtomicUsize,
    path_loads: AtomicUsize,
    witness_builds: AtomicUsize,
}

impl CountingStateView {
    fn new(path_depth: u32, pruning_proofs: Vec<Arc<Envelope>>) -> Self {
        Self {
            path_depth,
            pruning_proofs,
            cache_misses: Mutex::new(HashMap::new()),
            pruning_loads: AtomicUsize::new(0),
            path_loads: AtomicUsize::new(0),
            witness_builds: AtomicUsize::new(0),
        }
    }

    fn cache_miss(&self, kind: &str) -> usize {
        *self.cache_misses.lock().unwrap().get(kind).unwrap_or(&0)
    }

    fn build_transaction_witness(tx: &SignedTransaction) -> TransactionWitness {
        let tx_id = tx.hash();
        let sender_before =
            AccountBalanceWitness::new(tx.payload.from.clone(), 1_000, tx.payload.nonce);
        let sender_after = AccountBalanceWitness::new(
            tx.payload.from.clone(),
            1_000 - tx.payload.amount - tx.payload.fee as u128,
            tx.payload.nonce + 1,
        );
        let recipient_before = AccountBalanceWitness::new(tx.payload.to.clone(), 0, 0);
        let recipient_after =
            AccountBalanceWitness::new(tx.payload.to.clone(), tx.payload.amount, 0);
        let outpoint = UtxoOutpoint { tx_id, index: 0 };
        let stored_utxo = StoredUtxo::new(tx.payload.to.clone(), tx.payload.amount);
        let snapshot = TransactionUtxoSnapshot::new(outpoint.clone(), stored_utxo);
        TransactionWitness::new(
            tx_id,
            tx.payload.fee,
            sender_before,
            sender_after,
            Some(recipient_before),
            recipient_after,
            vec![snapshot.clone()],
            vec![snapshot],
            vec![],
            vec![],
        )
    }
}

impl crate::rpp::StateView for CountingStateView {
    fn merkle_path_depth(&self) -> ChainResult<u32> {
        Ok(self.path_depth)
    }

    fn cached_transaction_path(&self, _tx: &SignedTransaction) -> Option<MerklePathWitness> {
        None
    }

    fn load_transaction_path(&self, tx: &SignedTransaction) -> ChainResult<MerklePathWitness> {
        self.path_loads.fetch_add(1, Ordering::SeqCst);
        let siblings = vec![[tx.id.as_fields().0 as u8; DIGEST_LENGTH]; self.path_depth as usize];
        MerklePathWitness::new(self.path_depth, siblings)
    }

    fn cached_pruning_proofs(&self) -> Option<Vec<Arc<Envelope>>> {
        None
    }

    fn load_pruning_proofs(&self) -> ChainResult<Vec<Arc<Envelope>>> {
        self.pruning_loads.fetch_add(1, Ordering::SeqCst);
        Ok(self.pruning_proofs.clone())
    }

    fn transaction_witness(&self, tx: &SignedTransaction) -> ChainResult<TransactionWitness> {
        self.witness_builds.fetch_add(1, Ordering::SeqCst);
        Ok(Self::build_transaction_witness(tx))
    }

    fn log_cache_miss(&self, kind: &str) {
        let mut guard = self.cache_misses.lock().unwrap();
        *guard.entry(kind.to_string()).or_default() += 1;
    }
}

fn dummy_block(transactions: Vec<SignedTransaction>, pruning_proof: Arc<Envelope>) -> Block {
    let header = crate::runtime::types::block::BlockHeader {
        height: 0,
        previous_hash: String::new(),
        tx_root: String::new(),
        state_root: String::new(),
        utxo_root: String::new(),
        reputation_root: String::new(),
        timetoke_root: String::new(),
        zsi_root: String::new(),
        proof_root: String::new(),
        total_stake: String::new(),
        randomness: String::new(),
        vrf_public_key: String::new(),
        vrf_preoutput: String::new(),
        vrf_proof: String::new(),
        timestamp: 0,
        proposer: String::from("proposer"),
        leader_tier: String::new(),
        leader_timetoke: 0,
        global_instance_commitment: None,
        global_proof_handle: None,
    };

    let recursive_proof = RecursiveProof {
        system: ProofSystem::Stwo,
        commitment: String::new(),
        previous_commitment: None,
        pruning_binding_digest: [0u8; 48],
        pruning_segment_commitments: vec![],
        proof: ChainProof::Stwo(Default::default()),
    };

    let consensus = ConsensusCertificate {
        block_hash: String::new(),
        height: 0,
        round: 0,
        total_power: 0,
        quorum_threshold: 0,
        prevote_power: 0,
        precommit_power: 0,
        commit_power: 0,
        prevotes: vec![],
        precommits: vec![],
        metadata: ConsensusProofMetadata {
            vrf: ConsensusProofMetadataVrf { entries: vec![] },
            witness_commitments: vec![],
            reputation_roots: vec![],
            epoch: 0,
            slot: 0,
            quorum_bitmap_root: String::new(),
            quorum_signature_root: String::new(),
            bindings: ConsensusWitnessBindings::default(),
        },
    };

    let proof_bundle = BlockProofBundle {
        transaction_proofs: vec![],
        state_proof: ChainProof::Stwo(Default::default()),
        pruning_proof: ChainProof::Stwo(Default::default()),
        recursive_proof: ChainProof::Stwo(Default::default()),
    };

    Block {
        header,
        identities: vec![],
        transactions,
        uptime_proofs: Vec::<UptimeProof>::new(),
        timetoke_updates: Vec::<TimetokeUpdate>::new(),
        reputation_updates: Vec::<ReputationUpdate>::new(),
        bft_votes: vec![],
        module_witnesses: ModuleWitnessBundle::default(),
        proof_artifacts: vec![],
        pruning_proof,
        recursive_proof,
        stark: proof_bundle,
        signature: String::new(),
        consensus,
        consensus_proof: None,
        hash: String::new(),
        pruned: false,
    }
}

fn dummy_pruning_proof() -> Arc<Envelope> {
    let schema_version = SchemaVersion::new(0);
    let parameter_version = ParameterVersion::new(0);
    let state_commitment = TaggedDigest::new(SNAPSHOT_STATE_TAG, [1u8; DIGEST_LENGTH]);
    let snapshot = Snapshot::new(
        schema_version,
        parameter_version,
        BlockHeight::new(0),
        state_commitment,
    )
    .expect("snapshot is valid");
    let aggregate_commitment = TaggedDigest::new(COMMITMENT_TAG, [2u8; DIGEST_LENGTH]);
    let commitment = Commitment::new(schema_version, parameter_version, aggregate_commitment)
        .expect("commitment is valid");
    let binding = TaggedDigest::new(ENVELOPE_TAG, [3u8; DIGEST_LENGTH]);
    Arc::new(
        Envelope::new(
            schema_version,
            parameter_version,
            snapshot,
            vec![],
            commitment,
            binding,
        )
        .expect("envelope is valid"),
    )
}

fn dummy_transaction(
    from: &str,
    to: &str,
    amount: u128,
    fee: u64,
    nonce: u64,
    id_seed: u128,
) -> SignedTransaction {
    let payload = Transaction {
        from: from.to_string(),
        to: to.to_string(),
        amount,
        fee,
        nonce,
        memo: None,
        timestamp: 0,
    };
    SignedTransaction {
        id: Uuid::from_u128(id_seed),
        payload,
        signature: String::new(),
        public_key: String::new(),
    }
}

#[test]
fn produces_block_witness_with_cache_miss_logging() {
    let pruning_proof = dummy_pruning_proof();
    let state_view = CountingStateView::new(2, vec![pruning_proof.clone()]);

    let tx_a = dummy_transaction("alice", "bob", 10, 1, 0, 1);
    let tx_b = dummy_transaction("carol", "dave", 20, 2, 1, 2);
    let block = dummy_block(vec![tx_a.clone(), tx_b.clone()], pruning_proof);

    let witness = produce_block_witness(block.clone(), &state_view).expect("witness should build");
    witness
        .validate(block.transactions.len(), state_view.path_depth)
        .expect("witness validation should succeed");

    assert_eq!(state_view.cache_miss("pruning_proofs"), 1);
    assert_eq!(
        state_view.cache_miss("transaction_merkle_path"),
        block.transactions.len()
    );
    assert_eq!(state_view.pruning_loads.load(Ordering::SeqCst), 1);
    assert_eq!(
        state_view.path_loads.load(Ordering::SeqCst),
        block.transactions.len()
    );
    assert_eq!(
        state_view.witness_builds.load(Ordering::SeqCst),
        block.transactions.len()
    );
}
