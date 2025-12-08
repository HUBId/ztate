//! Prover-side integration for STWO/STARK proofs.

use std::collections::{HashMap, HashSet};
use std::num::IntErrorKind;

use crate::consensus::ConsensusCertificate;
use crate::errors::{ChainError, ChainResult};
use crate::proof_system::ProofProver;
use crate::reputation::{ReputationWeights, Tier};
use crate::rpp::{
    produce_block_witness, BlockWitness, GlobalStateCommitments, ProofSystemKind, StateView,
};
use crate::runtime::types::block::Block;
use crate::state::merkle::compute_merkle_root;
use crate::storage::Storage;
use crate::types::{
    Account, AttestedIdentityRequest, ChainProof, IdentityGenesis, SignedTransaction, Stake,
    UptimeClaim,
};
use rpp_crypto_vrf::{VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH};
use rpp_pruning::Envelope;

use super::aggregation::{RecursiveAggregator, StateCommitmentSnapshot};
use crate::stwo::circuit::{
    consensus::{
        ConsensusCircuit, ConsensusVrfPoseidonInput, ConsensusVrfWitnessEntry, ConsensusWitness,
        VotePower,
    },
    identity::{IdentityCircuit, IdentityWitness},
    pruning::{PruningCircuit, PruningWitness},
    recursive::{RecursiveCircuit, RecursiveWitness},
    state::{StateCircuit, StateWitness},
    transaction::{TransactionCircuit, TransactionWitness},
    uptime::{UptimeCircuit, UptimeWitness},
    CircuitError, StarkCircuit,
};
use crate::stwo::fri::FriProver;
use crate::stwo::params::{FieldElement, StarkParameters};
use crate::stwo::proof::{ProofKind, ProofPayload, StarkProof};

fn map_circuit_error(err: CircuitError) -> ChainError {
    ChainError::Crypto(err.to_string())
}

fn string_to_field(parameters: &StarkParameters, value: &str) -> FieldElement {
    let bytes = hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec());
    parameters.element_from_bytes(&bytes)
}

/// Wallet-integrated prover that derives witnesses from local state.
pub struct WalletProver<'a> {
    pub storage: &'a Storage,
    parameters: StarkParameters,
    reputation_weights: ReputationWeights,
    minimum_tier: Tier,
}

impl<'a> WalletProver<'a> {
    pub fn new(storage: &'a Storage) -> Self {
        Self {
            storage,
            parameters: StarkParameters::blueprint_default(),
            reputation_weights: ReputationWeights::default(),
            minimum_tier: Tier::Tl1,
        }
    }

    pub fn with_minimum_tier(mut self, tier: Tier) -> Self {
        self.minimum_tier = tier;
        self
    }

    pub fn with_parameters(mut self, parameters: StarkParameters) -> Self {
        self.parameters = parameters;
        self
    }

    fn hasher(&self) -> crate::stwo::params::PoseidonHasher {
        self.parameters.poseidon_hasher()
    }

    pub fn derive_identity_witness(
        &self,
        genesis: &crate::types::IdentityGenesis,
    ) -> ChainResult<IdentityWitness> {
        let commitment = genesis.expected_commitment()?;
        Ok(IdentityWitness {
            wallet_pk: genesis.wallet_pk.clone(),
            wallet_addr: genesis.wallet_addr.clone(),
            vrf_tag: genesis.vrf_tag().to_string(),
            epoch_nonce: genesis.epoch_nonce.clone(),
            state_root: genesis.state_root.clone(),
            identity_root: genesis.identity_root.clone(),
            initial_reputation: genesis.initial_reputation,
            commitment,
            identity_leaf: genesis.commitment_proof.leaf.clone(),
            identity_path: genesis.commitment_proof.siblings.clone(),
        })
    }

    pub fn derive_transaction_witness(
        &self,
        tx: &SignedTransaction,
    ) -> ChainResult<TransactionWitness> {
        let sender_account = self
            .storage
            .read_account(&tx.payload.from)?
            .ok_or_else(|| ChainError::Transaction("sender account not found".into()))?;
        let receiver_account = self.storage.read_account(&tx.payload.to)?;
        Ok(TransactionWitness {
            signed_tx: tx.clone(),
            sender_account,
            receiver_account,
            required_tier: self.minimum_tier.clone(),
            reputation_weights: self.reputation_weights.clone(),
        })
    }

    pub fn derive_state_witness(
        &self,
        prev_state_root: &str,
        new_state_root: &str,
        identities: &[AttestedIdentityRequest],
        transactions: &[SignedTransaction],
    ) -> ChainResult<StateWitness> {
        let accounts_before = self.storage.load_accounts()?;
        let mut state: HashMap<_, _> = accounts_before
            .iter()
            .cloned()
            .map(|account| (account.address.clone(), account))
            .collect();
        let now = crate::reputation::current_timestamp();

        for request in identities {
            let declaration = &request.declaration;
            let genesis = &declaration.genesis;
            if state.contains_key(&genesis.wallet_addr) {
                return Err(ChainError::Transaction(
                    "identity wallet already exists in state".into(),
                ));
            }
            let mut account = Account::new(genesis.wallet_addr.clone(), 0, Stake::default());
            account.reputation = crate::reputation::ReputationProfile::new(&genesis.wallet_pk);
            account.ensure_wallet_binding(&genesis.wallet_pk)?;
            account
                .reputation
                .zsi
                .validate(&declaration.proof.commitment);
            account
                .reputation
                .recompute_score(&self.reputation_weights, now);
            account.reputation.update_decay_reference(now);
            state.insert(genesis.wallet_addr.clone(), account);
        }
        for tx in transactions {
            let sender = state
                .get_mut(&tx.payload.from)
                .ok_or_else(|| ChainError::Transaction("sender missing from state".into()))?;
            let total = tx
                .payload
                .amount
                .checked_add(tx.payload.fee as u128)
                .ok_or_else(|| ChainError::Transaction("transaction amount overflow".into()))?;
            if sender.balance < total {
                return Err(ChainError::Transaction("insufficient balance".into()));
            }
            sender.balance -= total;
            sender.nonce += 1;
            let recipient = state
                .entry(tx.payload.to.clone())
                .or_insert_with(|| Account::new(tx.payload.to.clone(), 0, Stake::default()));
            recipient.balance = recipient.balance.saturating_add(tx.payload.amount);
            recipient
                .reputation
                .recompute_score(&self.reputation_weights, now);
        }
        let accounts_after = state.into_values().collect();
        Ok(StateWitness {
            prev_state_root: prev_state_root.to_string(),
            new_state_root: new_state_root.to_string(),
            identities: identities.to_vec(),
            transactions: transactions.to_vec(),
            accounts_before,
            accounts_after,
            required_tier: self.minimum_tier.clone(),
            reputation_weights: self.reputation_weights.clone(),
        })
    }

    pub fn derive_pruning_witness(
        &self,
        expected_previous_state_root: Option<&str>,
        previous_identities: &[AttestedIdentityRequest],
        previous_txs: &[SignedTransaction],
        pruning: &Envelope,
        removed: Vec<String>,
    ) -> ChainResult<PruningWitness> {
        let snapshot_state_root = hex::encode(pruning.snapshot().state_commitment().digest());
        if let Some(expected) = expected_previous_state_root {
            if expected != snapshot_state_root {
                return Err(ChainError::Crypto(format!(
                    "pruning envelope snapshot root mismatch: expected {expected}, envelope {snapshot_state_root}",
                )));
            }
        }
        let pruned_segment = pruning.segments().first().ok_or_else(|| {
            ChainError::Crypto("pruning envelope missing transaction segment".into())
        })?;
        let pruned_tx_root = hex::encode(pruned_segment.segment_commitment().digest());
        let capacity = previous_identities.len() + previous_txs.len();
        let mut original_hashes = Vec::with_capacity(capacity);
        let mut original_transactions = Vec::with_capacity(capacity);
        for request in previous_identities {
            let hash = request.declaration.hash()?;
            original_hashes.push(hash);
            original_transactions.push(hex::encode(hash));
        }
        for tx in previous_txs {
            let hash = tx.hash();
            original_hashes.push(hash);
            original_transactions.push(hex::encode(hash));
        }

        let mut previous_leaves = original_hashes.clone();
        let previous_tx_root = hex::encode(compute_merkle_root(&mut previous_leaves));

        let removed_set: HashSet<&str> = removed.iter().map(|value| value.as_str()).collect();
        if removed.len() != removed_set.len() {
            return Err(ChainError::Crypto(
                "pruning witness contains duplicate removed transactions".into(),
            ));
        }

        let original_set: HashSet<&str> = original_transactions
            .iter()
            .map(|value| value.as_str())
            .collect();
        if let Some(missing) = removed
            .iter()
            .find(|value| !original_set.contains(value.as_str()))
        {
            return Err(ChainError::Crypto(format!(
                "pruning witness references unknown transaction: {missing}",
            )));
        }

        let mut remaining_hashes =
            Vec::with_capacity(original_hashes.len().saturating_sub(removed.len()));
        for (hash, encoded) in original_hashes.iter().zip(original_transactions.iter()) {
            if !removed_set.contains(encoded.as_str()) {
                remaining_hashes.push(*hash);
            }
        }
        let computed_pruned_root = hex::encode(compute_merkle_root(&mut remaining_hashes));
        if computed_pruned_root != pruned_tx_root {
            return Err(ChainError::Crypto(format!(
                "pruning witness pruned root mismatch: envelope {pruned_tx_root}, computed {computed_pruned_root}",
            )));
        }
        let pruning_binding_digest = pruning.binding_digest().prefixed_bytes();
        let pruning_segment_commitments: Vec<_> = pruning
            .segments()
            .iter()
            .map(|segment| segment.segment_commitment().prefixed_bytes())
            .collect();
        let hasher = self.parameters.poseidon_hasher();
        let pruning_fold = RecursiveCircuit::fold_pruning_digests(
            &hasher,
            &self.parameters,
            &pruning_binding_digest,
            &pruning_segment_commitments,
        )
        .map_err(map_circuit_error)?
        .to_hex();
        Ok(PruningWitness {
            previous_tx_root,
            pruned_tx_root,
            original_transactions,
            removed_transactions: removed,
            pruning_binding_digest,
            pruning_segment_commitments,
            pruning_fold,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn derive_recursive_witness(
        &self,
        previous_recursive: Option<&ChainProof>,
        identity_proofs: &[ChainProof],
        tx_proofs: &[ChainProof],
        uptime_proofs: &[ChainProof],
        consensus_proofs: &[ChainProof],
        state_commitments: &GlobalStateCommitments,
        state_proof: &ChainProof,
        pruning_proof: &ChainProof,
        pruning_envelope: &Envelope,
        block_height: u64,
    ) -> ChainResult<RecursiveWitness> {
        let previous_recursive_owned = previous_recursive
            .map(|proof| proof.expect_stwo().map(|inner| inner.clone()))
            .transpose()?;
        let identity_owned: Vec<StarkProof> = identity_proofs
            .iter()
            .map(|proof| proof.expect_stwo().map(|inner| inner.clone()))
            .collect::<ChainResult<Vec<_>>>()?;
        let tx_owned: Vec<StarkProof> = tx_proofs
            .iter()
            .map(|proof| proof.expect_stwo().map(|inner| inner.clone()))
            .collect::<ChainResult<Vec<_>>>()?;
        let uptime_owned: Vec<StarkProof> = uptime_proofs
            .iter()
            .map(|proof| proof.expect_stwo().map(|inner| inner.clone()))
            .collect::<ChainResult<Vec<_>>>()?;
        let consensus_owned: Vec<StarkProof> = consensus_proofs
            .iter()
            .map(|proof| proof.expect_stwo().map(|inner| inner.clone()))
            .collect::<ChainResult<Vec<_>>>()?;
        let state_owned = state_proof.expect_stwo()?.clone();
        let pruning_owned = pruning_proof.expect_stwo()?;
        if pruning_owned.kind != ProofKind::Pruning {
            return Err(ChainError::Crypto(format!(
                "expected pruning proof but received {:?}",
                pruning_owned.kind
            )));
        }
        let aggregator = RecursiveAggregator::new(self.parameters.clone());
        let state_roots = StateCommitmentSnapshot::from_commitments(state_commitments);
        aggregator.build_witness(
            previous_recursive_owned.as_ref(),
            &identity_owned,
            &tx_owned,
            &uptime_owned,
            &consensus_owned,
            &state_owned,
            pruning_envelope,
            &state_roots,
            block_height,
        )
    }

    pub fn produce_block_witness(
        &self,
        block: Block,
        state_view: &dyn StateView,
    ) -> ChainResult<BlockWitness> {
        produce_block_witness(block, state_view)
    }

    pub fn derive_uptime_witness(&self, claim: &UptimeClaim) -> ChainResult<UptimeWitness> {
        let commitment = claim.commitment();
        Ok(UptimeWitness {
            wallet_address: claim.wallet_address.clone(),
            node_clock: claim.node_clock,
            epoch: claim.epoch,
            head_hash: claim.head_hash.clone(),
            window_start: claim.window_start,
            window_end: claim.window_end,
            commitment,
        })
    }

    fn parse_weight(label: &str, weight: &str) -> ChainResult<u64> {
        weight.parse::<u64>().map_err(|err| {
            let message = match err.kind() {
                IntErrorKind::InvalidDigit => {
                    format!("failed to parse {label} voting weight '{weight}'")
                }
                _ => format!("{label} voting weight '{weight}' exceeds supported range"),
            };
            ChainError::Crypto(message)
        })
    }

    pub fn derive_consensus_witness(
        &self,
        block_hash: &str,
        certificate: &ConsensusCertificate,
    ) -> ChainResult<ConsensusWitness> {
        let quorum_threshold =
            certificate
                .quorum_threshold
                .parse::<u64>()
                .map_err(|err| match err.kind() {
                    IntErrorKind::InvalidDigit => ChainError::Crypto(format!(
                        "invalid quorum threshold encoding '{}'",
                        certificate.quorum_threshold
                    )),
                    _ => ChainError::Crypto("quorum threshold exceeds 64-bit range".into()),
                })?;

        let to_vote_power =
            |record: &crate::consensus::VoteRecord, stage: &str| -> ChainResult<VotePower> {
                let voter = record.vote.vote.voter.clone();
                let weight = Self::parse_weight(stage, &record.weight)?;
                Ok(VotePower { voter, weight })
            };

        let decode_digest = |label: &str, value: &str| -> ChainResult<Vec<u8>> {
            let bytes = hex::decode(value).map_err(|err| {
                ChainError::Crypto(format!("invalid {label} encoding '{value}': {err}"))
            })?;
            if bytes.len() != 32 {
                return Err(ChainError::Crypto(format!("{label} must encode 32 bytes")));
            }
            Ok(bytes)
        };

        decode_digest(
            "quorum bitmap root",
            &certificate.metadata.quorum_bitmap_root,
        )?;
        decode_digest(
            "quorum signature root",
            &certificate.metadata.quorum_signature_root,
        )?;

        let block_hash_bytes = decode_digest("block hash", block_hash)?;
        let normalized_block_hash = hex::encode(&block_hash_bytes);

        if certificate.metadata.vrf.entries.is_empty() {
            return Err(ChainError::Crypto(
                "consensus certificate missing VRF entries".into(),
            ));
        }
        if certificate.metadata.witness_commitments.is_empty() {
            return Err(ChainError::Crypto(
                "consensus certificate missing witness commitments".into(),
            ));
        }
        if certificate.metadata.reputation_roots.is_empty() {
            return Err(ChainError::Crypto(
                "consensus certificate missing reputation roots".into(),
            ));
        }

        let mut vrf_entries = Vec::with_capacity(certificate.metadata.vrf.entries.len());

        for (index, entry) in certificate.metadata.vrf.entries.iter().enumerate() {
            let sanitize_entry_hex =
                |value: &str, label: &str, expected_len: usize| -> ChainResult<Vec<u8>> {
                    let trimmed = value.trim();
                    if trimmed.is_empty() {
                        return Err(ChainError::Crypto(format!(
                            "consensus certificate vrf entry #{index} missing {label}",
                        )));
                    }
                    let bytes = hex::decode(trimmed).map_err(|err| {
                        ChainError::Crypto(format!(
                            "invalid vrf entry #{index} {label} encoding: {err}",
                        ))
                    })?;
                    if bytes.len() != expected_len {
                        return Err(ChainError::Crypto(format!(
                            "vrf entry #{index} {label} must encode {expected_len} bytes",
                        )));
                    }
                    Ok(bytes)
                };

            let randomness = sanitize_entry_hex(&entry.randomness, "randomness", 32)?;
            let pre_output =
                sanitize_entry_hex(&entry.pre_output, "pre-output", VRF_PREOUTPUT_LENGTH)?;
            let proof_bytes = sanitize_entry_hex(&entry.proof, "proof", VRF_PROOF_LENGTH)?;
            let public_key = sanitize_entry_hex(&entry.public_key, "public key", 32)?;
            let _poseidon_digest =
                sanitize_entry_hex(&entry.poseidon.digest, "poseidon digest", 32)?;
            let poseidon_last_block_header = sanitize_entry_hex(
                &entry.poseidon.last_block_header,
                "poseidon last block header",
                32,
            )?;
            if poseidon_last_block_header.as_slice() != block_hash_bytes.as_slice() {
                return Err(ChainError::Crypto(format!(
                    "vrf entry #{index} poseidon last block header must match block hash",
                )));
            }
            let poseidon_tier_seed =
                sanitize_entry_hex(&entry.poseidon.tier_seed, "poseidon tier seed", 32)?;

            let poseidon_epoch_str = entry.poseidon.epoch.trim();
            if poseidon_epoch_str.is_empty() {
                return Err(ChainError::Crypto(format!(
                    "consensus certificate vrf entry #{index} missing poseidon epoch",
                )));
            }
            let poseidon_epoch = poseidon_epoch_str.parse::<u64>().map_err(|err| {
                ChainError::Crypto(format!(
                    "invalid vrf entry #{index} poseidon epoch '{poseidon_epoch_str}': {err}",
                ))
            })?;
            if poseidon_epoch != certificate.metadata.epoch {
                return Err(ChainError::Crypto(format!(
                    "vrf entry #{index} poseidon epoch mismatch",
                )));
            }

            vrf_entries.push(ConsensusVrfWitnessEntry {
                randomness: hex::encode(randomness),
                pre_output: hex::encode(pre_output),
                proof: hex::encode(proof_bytes),
                public_key: hex::encode(public_key),
                input: ConsensusVrfPoseidonInput {
                    last_block_header: normalized_block_hash.clone(),
                    epoch: poseidon_epoch,
                    tier_seed: hex::encode(poseidon_tier_seed),
                },
            });
        }

        let pre_votes = certificate
            .pre_votes
            .iter()
            .map(|record| to_vote_power(record, "pre-vote"))
            .collect::<ChainResult<Vec<_>>>()?;
        let pre_commits = certificate
            .pre_commits
            .iter()
            .map(|record| to_vote_power(record, "pre-commit"))
            .collect::<ChainResult<Vec<_>>>()?;
        let commit_votes = pre_commits.clone();

        Ok(ConsensusWitness {
            block_hash: normalized_block_hash.clone(),
            round: certificate.round,
            epoch: certificate.metadata.epoch,
            slot: certificate.metadata.slot,
            leader_proposal: normalized_block_hash,
            quorum_threshold,
            pre_votes,
            pre_commits,
            commit_votes,
            quorum_bitmap_root: certificate.metadata.quorum_bitmap_root.clone(),
            quorum_signature_root: certificate.metadata.quorum_signature_root.clone(),
            vrf_entries,
            witness_commitments: certificate.metadata.witness_commitments.clone(),
            reputation_roots: certificate.metadata.reputation_roots.clone(),
        })
    }
}

impl<'a> ProofProver for WalletProver<'a> {
    type IdentityWitness = IdentityWitness;
    type TransactionWitness = TransactionWitness;
    type StateWitness = StateWitness;
    type PruningWitness = PruningWitness;
    type RecursiveWitness = RecursiveWitness;
    type UptimeWitness = UptimeWitness;
    type ConsensusWitness = ConsensusWitness;

    fn system(&self) -> ProofSystemKind {
        ProofSystemKind::Stwo
    }

    fn build_identity_witness(
        &self,
        genesis: &IdentityGenesis,
    ) -> ChainResult<Self::IdentityWitness> {
        self.derive_identity_witness(genesis)
    }

    fn build_transaction_witness(
        &self,
        tx: &SignedTransaction,
    ) -> ChainResult<Self::TransactionWitness> {
        self.derive_transaction_witness(tx)
    }

    fn build_state_witness(
        &self,
        prev_state_root: &str,
        new_state_root: &str,
        identities: &[AttestedIdentityRequest],
        transactions: &[SignedTransaction],
    ) -> ChainResult<Self::StateWitness> {
        self.derive_state_witness(prev_state_root, new_state_root, identities, transactions)
    }

    fn build_pruning_witness(
        &self,
        expected_previous_state_root: Option<&str>,
        previous_identities: &[AttestedIdentityRequest],
        previous_txs: &[SignedTransaction],
        pruning: &Envelope,
        removed: Vec<String>,
    ) -> ChainResult<Self::PruningWitness> {
        self.derive_pruning_witness(
            expected_previous_state_root,
            previous_identities,
            previous_txs,
            pruning,
            removed,
        )
    }

    fn build_recursive_witness(
        &self,
        previous_recursive: Option<&ChainProof>,
        identity_proofs: &[ChainProof],
        tx_proofs: &[ChainProof],
        uptime_proofs: &[ChainProof],
        consensus_proofs: &[ChainProof],
        state_commitments: &GlobalStateCommitments,
        state_proof: &ChainProof,
        pruning_envelope: &Envelope,
        pruning_proof: &ChainProof,
        block_height: u64,
    ) -> ChainResult<Self::RecursiveWitness> {
        self.derive_recursive_witness(
            previous_recursive,
            identity_proofs,
            tx_proofs,
            uptime_proofs,
            consensus_proofs,
            state_commitments,
            state_proof,
            pruning_proof,
            pruning_envelope,
            block_height,
        )
    }

    fn build_uptime_witness(&self, claim: &UptimeClaim) -> ChainResult<Self::UptimeWitness> {
        self.derive_uptime_witness(claim)
    }

    fn build_consensus_witness(
        &self,
        block_hash: &str,
        certificate: &ConsensusCertificate,
    ) -> ChainResult<Self::ConsensusWitness> {
        self.derive_consensus_witness(block_hash, certificate)
    }

    fn prove_transaction(&self, witness: Self::TransactionWitness) -> ChainResult<ChainProof> {
        let proof = self.prove_transaction_witness(witness)?;
        Ok(ChainProof::Stwo(proof))
    }

    fn prove_identity(&self, witness: Self::IdentityWitness) -> ChainResult<ChainProof> {
        let proof = self.prove_identity_witness(witness)?;
        Ok(ChainProof::Stwo(proof))
    }

    fn prove_state_transition(&self, witness: Self::StateWitness) -> ChainResult<ChainProof> {
        let proof = self.prove_state_transition_witness(witness)?;
        Ok(ChainProof::Stwo(proof))
    }

    fn prove_pruning(&self, witness: Self::PruningWitness) -> ChainResult<ChainProof> {
        let proof = self.prove_pruning_witness(witness)?;
        Ok(ChainProof::Stwo(proof))
    }

    fn prove_recursive(&self, witness: Self::RecursiveWitness) -> ChainResult<ChainProof> {
        let proof = self.prove_recursive_witness(witness)?;
        Ok(ChainProof::Stwo(proof))
    }

    fn prove_uptime(&self, witness: Self::UptimeWitness) -> ChainResult<ChainProof> {
        let proof = self.prove_uptime_witness(witness)?;
        Ok(ChainProof::Stwo(proof))
    }

    fn prove_consensus(&self, witness: Self::ConsensusWitness) -> ChainResult<ChainProof> {
        let proof = self.prove_consensus_witness(witness)?;
        Ok(ChainProof::Stwo(proof))
    }
}

impl<'a> WalletProver<'a> {
    fn prove_transaction_witness(&self, witness: TransactionWitness) -> ChainResult<StarkProof> {
        let circuit = TransactionCircuit::new(witness.clone());
        circuit.evaluate_constraints().map_err(map_circuit_error)?;
        let trace = circuit
            .generate_trace(&self.parameters)
            .map_err(map_circuit_error)?;
        circuit
            .verify_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let air = circuit
            .define_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let tx = &witness.signed_tx.payload;
        let inputs = vec![
            string_to_field(&self.parameters, &tx.from),
            string_to_field(&self.parameters, &tx.to),
            self.parameters.element_from_u128(tx.amount),
            self.parameters.element_from_u64(tx.fee as u64),
            self.parameters.element_from_u64(tx.nonce),
        ];
        let hasher = self.hasher();
        let fri_prover = FriProver::new(&self.parameters);
        let fri_output = fri_prover.prove(&air, &trace, &inputs);
        Ok(StarkProof::new(
            ProofKind::Transaction,
            ProofPayload::Transaction(witness),
            inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        ))
    }

    fn prove_identity_witness(&self, witness: IdentityWitness) -> ChainResult<StarkProof> {
        let circuit = IdentityCircuit::new(witness.clone());
        circuit.evaluate_constraints().map_err(map_circuit_error)?;
        let trace = circuit
            .generate_trace(&self.parameters)
            .map_err(map_circuit_error)?;
        circuit
            .verify_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let air = circuit
            .define_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let inputs = vec![
            string_to_field(&self.parameters, &witness.wallet_addr),
            string_to_field(&self.parameters, &witness.vrf_tag),
            string_to_field(&self.parameters, &witness.identity_root),
            string_to_field(&self.parameters, &witness.state_root),
        ];
        let hasher = self.hasher();
        let fri_prover = FriProver::new(&self.parameters);
        let fri_output = fri_prover.prove(&air, &trace, &inputs);
        Ok(StarkProof::new(
            ProofKind::Identity,
            ProofPayload::Identity(witness),
            inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        ))
    }

    fn prove_state_transition_witness(&self, witness: StateWitness) -> ChainResult<StarkProof> {
        let circuit = StateCircuit::new(witness.clone());
        circuit.evaluate_constraints().map_err(map_circuit_error)?;
        let trace = circuit
            .generate_trace(&self.parameters)
            .map_err(map_circuit_error)?;
        circuit
            .verify_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let air = circuit
            .define_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let inputs = vec![
            string_to_field(&self.parameters, &witness.prev_state_root),
            string_to_field(&self.parameters, &witness.new_state_root),
            self.parameters
                .element_from_u64(witness.transactions.len() as u64),
        ];
        let hasher = self.hasher();
        let fri_prover = FriProver::new(&self.parameters);
        let fri_output = fri_prover.prove(&air, &trace, &inputs);
        Ok(StarkProof::new(
            ProofKind::State,
            ProofPayload::State(witness),
            inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        ))
    }

    fn prove_pruning_witness(&self, witness: PruningWitness) -> ChainResult<StarkProof> {
        let circuit = PruningCircuit::new(witness.clone());
        circuit.evaluate_constraints().map_err(map_circuit_error)?;
        let trace = circuit
            .generate_trace(&self.parameters)
            .map_err(map_circuit_error)?;
        circuit
            .verify_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let air = circuit
            .define_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let inputs = vec![
            string_to_field(&self.parameters, &witness.previous_tx_root),
            string_to_field(&self.parameters, &witness.pruned_tx_root),
            self.parameters
                .element_from_u64(witness.removed_transactions.len() as u64),
        ];
        let hasher = self.hasher();
        let fri_prover = FriProver::new(&self.parameters);
        let fri_output = fri_prover.prove(&air, &trace, &inputs);
        Ok(StarkProof::new(
            ProofKind::Pruning,
            ProofPayload::Pruning(witness),
            inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        ))
    }

    fn prove_recursive_witness(&self, witness: RecursiveWitness) -> ChainResult<StarkProof> {
        let circuit = RecursiveCircuit::new(witness.clone());
        circuit.evaluate_constraints().map_err(map_circuit_error)?;
        let trace = circuit
            .generate_trace(&self.parameters)
            .map_err(map_circuit_error)?;
        circuit
            .verify_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let air = circuit
            .define_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let prev = witness.previous_commitment.clone().unwrap_or_default();
        let inputs = vec![
            string_to_field(&self.parameters, &prev),
            string_to_field(&self.parameters, &witness.aggregated_commitment),
            self.parameters
                .element_from_u64(witness.tx_commitments.len() as u64),
        ];
        let hasher = self.hasher();
        let fri_prover = FriProver::new(&self.parameters);
        let fri_output = fri_prover.prove(&air, &trace, &inputs);
        Ok(StarkProof::new(
            ProofKind::Recursive,
            ProofPayload::Recursive(witness),
            inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        ))
    }

    fn prove_uptime_witness(&self, witness: UptimeWitness) -> ChainResult<StarkProof> {
        let circuit = UptimeCircuit::new(witness.clone());
        circuit.evaluate_constraints().map_err(map_circuit_error)?;
        let trace = circuit
            .generate_trace(&self.parameters)
            .map_err(map_circuit_error)?;
        circuit
            .verify_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let air = circuit
            .define_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let inputs = vec![
            string_to_field(&self.parameters, &witness.wallet_address),
            self.parameters.element_from_u64(witness.node_clock),
            self.parameters.element_from_u64(witness.epoch),
            string_to_field(&self.parameters, &witness.head_hash),
            self.parameters.element_from_u64(witness.window_start),
            self.parameters.element_from_u64(witness.window_end),
            string_to_field(&self.parameters, &witness.commitment),
        ];
        let hasher = self.hasher();
        let fri_prover = FriProver::new(&self.parameters);
        let fri_output = fri_prover.prove(&air, &trace, &inputs);
        Ok(StarkProof::new(
            ProofKind::Uptime,
            ProofPayload::Uptime(witness),
            inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        ))
    }

    fn prove_consensus_witness(&self, witness: ConsensusWitness) -> ChainResult<StarkProof> {
        let circuit = ConsensusCircuit::new(witness.clone());
        circuit.evaluate_constraints().map_err(map_circuit_error)?;
        let trace = circuit
            .generate_trace(&self.parameters)
            .map_err(map_circuit_error)?;
        circuit
            .verify_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let air = circuit
            .define_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let inputs = ConsensusCircuit::public_inputs(&self.parameters, &witness)
            .map_err(map_circuit_error)?;
        let hasher = self.hasher();
        let fri_prover = FriProver::new(&self.parameters);
        let fri_output = fri_prover.prove(&air, &trace, &inputs);
        Ok(StarkProof::new(
            ProofKind::Consensus,
            ProofPayload::Consensus(witness),
            inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        ))
    }
}
