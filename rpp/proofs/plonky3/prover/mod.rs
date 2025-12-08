//! Wallet integration for the Plonky3 backend.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::num::IntErrorKind;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use serde_json::Value;

use plonky3_backend::{
    validate_consensus_public_inputs, ConsensusCircuit as BackendConsensusCircuit,
    ProverContext as BackendProverContext,
};

use crate::consensus::ConsensusCertificate;
use crate::errors::{ChainError, ChainResult};
use crate::proof_system::ProofProver;
use crate::rpp::{GlobalStateCommitments, ProofSystemKind};
use crate::types::{
    AttestedIdentityRequest, ChainProof, IdentityGenesis, SignedTransaction, UptimeClaim,
};
use rpp_crypto_vrf::{VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH};
use rpp_pruning::Envelope;

use super::aggregation::RecursiveAggregator;
use super::circuit::consensus::{
    ConsensusVrfEntry, ConsensusVrfPoseidonInput, ConsensusWitness, VotePower,
};
use super::circuit::identity::IdentityWitness;
use super::circuit::pruning::PruningWitness;
use super::circuit::recursive::RecursiveWitness;
use super::circuit::state::StateWitness;
use super::circuit::transaction::TransactionWitness;
use super::circuit::uptime::UptimeWitness;
use super::circuit::Plonky3CircuitWitness;
use super::crypto;
use super::params::Plonky3Parameters;
use super::proof::Plonky3Proof;

#[derive(Clone, Debug, Eq)]
struct CircuitCacheKey {
    circuit: String,
    security_bits: u32,
    use_gpu: bool,
}

impl PartialEq for CircuitCacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.circuit == other.circuit
            && self.security_bits == other.security_bits
            && self.use_gpu == other.use_gpu
    }
}

impl Hash for CircuitCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.circuit.hash(state);
        self.security_bits.hash(state);
        self.use_gpu.hash(state);
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Plonky3BackendError {
    pub message: String,
    pub at_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Plonky3BackendHealth {
    pub cached_circuits: usize,
    pub proofs_generated: u64,
    pub failed_proofs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<Plonky3BackendError>,
}

#[derive(Default)]
struct Plonky3Telemetry {
    cached_circuits: AtomicUsize,
    proofs_generated: AtomicU64,
    failed_proofs: AtomicU64,
    last_success_ms: AtomicU64,
    last_error: RwLock<Option<Plonky3BackendError>>,
}

static PLONKY3_TELEMETRY: Lazy<Plonky3Telemetry> = Lazy::new(Plonky3Telemetry::default);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl Plonky3Telemetry {
    fn record_cache_size(&self, size: usize) {
        self.cached_circuits.store(size, Ordering::SeqCst);
    }

    fn record_success(&self) {
        self.proofs_generated.fetch_add(1, Ordering::SeqCst);
        self.last_success_ms.store(now_ms(), Ordering::SeqCst);
        let mut guard = self.last_error.write();
        guard.take();
    }

    fn record_failure(&self, message: String) {
        self.failed_proofs.fetch_add(1, Ordering::SeqCst);
        *self.last_error.write() = Some(Plonky3BackendError {
            message,
            at_ms: now_ms(),
        });
    }

    fn snapshot(&self) -> Plonky3BackendHealth {
        let cached_circuits = self.cached_circuits.load(Ordering::SeqCst);
        let proofs_generated = self.proofs_generated.load(Ordering::SeqCst);
        let failed_proofs = self.failed_proofs.load(Ordering::SeqCst);
        let last_success_raw = self.last_success_ms.load(Ordering::SeqCst);
        let last_success_ms = if last_success_raw == 0 {
            None
        } else {
            Some(last_success_raw)
        };
        let last_error = self.last_error.read().clone();
        Plonky3BackendHealth {
            cached_circuits,
            proofs_generated,
            failed_proofs,
            last_success_ms,
            last_error,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct Plonky3Backend {
    compiled: Arc<Mutex<HashMap<CircuitCacheKey, BackendProverContext>>>,
}

impl Plonky3Backend {
    fn ensure_compiled(
        &self,
        params: &Plonky3Parameters,
        circuit: &str,
    ) -> ChainResult<BackendProverContext> {
        let key = CircuitCacheKey {
            circuit: circuit.to_string(),
            security_bits: params.security_bits,
            use_gpu: params.use_gpu_acceleration,
        };
        {
            let guard = self.compiled.lock();
            if let Some(compiled) = guard.get(&key).cloned() {
                PLONKY3_TELEMETRY.record_cache_size(guard.len());
                return Ok(compiled);
            }
        }

        let (verifying_key, proving_key) = crypto::circuit_keys(circuit)?;
        let compiled = BackendProverContext::new(
            circuit.to_string(),
            verifying_key,
            proving_key,
            params.security_bits,
            params.use_gpu_acceleration,
        )
        .map_err(|err| {
            ChainError::Crypto(format!(
                "failed to prepare Plonky3 {circuit} circuit for proving: {err}"
            ))
        })?;

        let mut guard = self.compiled.lock();
        guard.insert(key, compiled.clone());
        PLONKY3_TELEMETRY.record_cache_size(guard.len());
        Ok(compiled)
    }

    fn prove<W: Plonky3CircuitWitness>(
        &self,
        params: &Plonky3Parameters,
        witness: &W,
    ) -> ChainResult<Plonky3Proof> {
        let circuit = witness.circuit();
        let compiled = self.ensure_compiled(params, circuit)?;
        let raw_public_inputs = witness.public_inputs()?;
        let (expected_commitment, _, canonical_bytes) =
            super::public_inputs::compute_commitment_and_inputs(&raw_public_inputs)?;
        let canonical_public_inputs: Value =
            serde_json::from_slice(&canonical_bytes).map_err(|err| {
                ChainError::Crypto(format!(
                    "failed to decode canonical Plonky3 public inputs: {err}"
                ))
            })?;
        if circuit == "consensus" {
            validate_consensus_public_inputs(&canonical_public_inputs).map_err(|err| {
                ChainError::Crypto(format!(
                    "invalid consensus public inputs supplied to Plonky3 prover: {err}"
                ))
            })?;

            BackendConsensusCircuit::from_public_inputs_value(&canonical_public_inputs).map_err(
                |err| {
                    ChainError::Crypto(format!(
                        "failed to instantiate consensus circuit for Plonky3 prover: {err}"
                    ))
                },
            )?;
        }
        let (commitment, backend_proof) =
            compiled.prove(&canonical_public_inputs).map_err(|err| {
                let message = err.to_string();
                PLONKY3_TELEMETRY.record_failure(message.clone());
                ChainError::Crypto(message)
            })?;
        if commitment != expected_commitment {
            let message = format!(
                "Plonky3 backend commitment mismatch: expected {expected_commitment}, found {commitment}"
            );
            PLONKY3_TELEMETRY.record_failure(message.clone());
            return Err(ChainError::CommitmentMismatch(message));
        }
        let proof = match Plonky3Proof::from_backend(
            circuit.to_string(),
            commitment,
            canonical_public_inputs,
            backend_proof,
        ) {
            Ok(proof) => proof,
            Err(err) => {
                PLONKY3_TELEMETRY.record_failure(err.to_string());
                return Err(err);
            }
        };
        if let Err(detail) = proof.payload.metadata.ensure_alignment(&self.params) {
            PLONKY3_TELEMETRY.record_failure(detail.clone());
            return Err(ChainError::Crypto(detail));
        }
        PLONKY3_TELEMETRY.record_success();
        Ok(proof)
    }
}

/// Wallet-facing prover stub for Plonky3. The structure mirrors the STWO
/// implementation so the surrounding plumbing can be developed in parallel.
#[derive(Clone, Debug)]
pub struct Plonky3Prover {
    pub params: Plonky3Parameters,
    backend: Plonky3Backend,
}

impl Plonky3Prover {
    pub fn new() -> Self {
        Self {
            params: Plonky3Parameters::default(),
            backend: Plonky3Backend::default(),
        }
    }

    fn prove_with_backend<W>(&self, witness: &W) -> ChainResult<ChainProof>
    where
        W: Plonky3CircuitWitness,
    {
        let proof = self.backend.prove(&self.params, witness)?;
        proof.into_value().map(ChainProof::Plonky3)
    }
}

pub fn telemetry_snapshot() -> Plonky3BackendHealth {
    PLONKY3_TELEMETRY.snapshot()
}

impl ProofProver for Plonky3Prover {
    type IdentityWitness = IdentityWitness;
    type TransactionWitness = TransactionWitness;
    type StateWitness = StateWitness;
    type PruningWitness = PruningWitness;
    type RecursiveWitness = RecursiveWitness;
    type UptimeWitness = UptimeWitness;
    type ConsensusWitness = ConsensusWitness;

    fn system(&self) -> ProofSystemKind {
        ProofSystemKind::Plonky3
    }

    fn build_identity_witness(
        &self,
        genesis: &IdentityGenesis,
    ) -> ChainResult<Self::IdentityWitness> {
        Ok(IdentityWitness::new(genesis))
    }

    fn build_transaction_witness(
        &self,
        tx: &SignedTransaction,
    ) -> ChainResult<Self::TransactionWitness> {
        Ok(TransactionWitness::new(tx))
    }

    fn build_state_witness(
        &self,
        prev_state_root: &str,
        new_state_root: &str,
        identities: &[AttestedIdentityRequest],
        transactions: &[SignedTransaction],
    ) -> ChainResult<Self::StateWitness> {
        Ok(StateWitness::new(
            prev_state_root,
            new_state_root,
            identities,
            transactions,
        ))
    }

    fn build_pruning_witness(
        &self,
        expected_previous_state_root: Option<&str>,
        previous_identities: &[AttestedIdentityRequest],
        previous_txs: &[SignedTransaction],
        pruning: &Envelope,
        removed: Vec<String>,
    ) -> ChainResult<Self::PruningWitness> {
        let snapshot_state_root = hex::encode(pruning.snapshot().state_commitment().digest());
        if let Some(expected) = expected_previous_state_root {
            if expected != snapshot_state_root {
                return Err(ChainError::Crypto(format!(
                    "pruning envelope snapshot root mismatch: expected {expected}, envelope {snapshot_state_root}",
                )));
            }
        }
        if pruning.segments().is_empty() {
            return Err(ChainError::Crypto(
                "pruning envelope missing transaction segment".into(),
            ));
        }
        Ok(PruningWitness::new(
            previous_identities,
            previous_txs,
            pruning,
            removed,
        ))
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
        _pruning_envelope: &Envelope,
        pruning_proof: &ChainProof,
        block_height: u64,
    ) -> ChainResult<Self::RecursiveWitness> {
        Ok(RecursiveWitness::new(
            previous_recursive.cloned(),
            identity_proofs,
            tx_proofs,
            uptime_proofs,
            consensus_proofs,
            state_commitments,
            state_proof,
            pruning_proof,
            block_height,
        ))
    }

    fn build_uptime_witness(&self, claim: &UptimeClaim) -> ChainResult<Self::UptimeWitness> {
        Ok(UptimeWitness::new(
            &claim.wallet_address,
            claim.node_clock,
            claim.epoch,
            &claim.head_hash,
            claim.window_start,
            claim.window_end,
            claim.commitment(),
        ))
    }

    fn build_consensus_witness(
        &self,
        block_hash: &str,
        certificate: &ConsensusCertificate,
    ) -> ChainResult<Self::ConsensusWitness> {
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
            let poseidon_digest =
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

            vrf_entries.push(ConsensusVrfEntry {
                randomness: hex::encode(randomness),
                pre_output: hex::encode(pre_output),
                proof: hex::encode(proof_bytes),
                public_key: hex::encode(public_key),
                poseidon: ConsensusVrfPoseidonInput {
                    digest: hex::encode(poseidon_digest),
                    last_block_header: normalized_block_hash.clone(),
                    epoch: poseidon_epoch.to_string(),
                    tier_seed: hex::encode(poseidon_tier_seed),
                },
            });
        }

        if vrf_entries.is_empty() {
            return Err(ChainError::Crypto(
                "consensus certificate missing VRF entries".into(),
            ));
        }

        let parse_weight = |stage: &str, weight: &str| -> ChainResult<u64> {
            weight.parse::<u64>().map_err(|err| {
                let message = match err.kind() {
                    IntErrorKind::InvalidDigit => {
                        format!("failed to parse {stage} voting weight '{weight}'")
                    }
                    _ => format!("{stage} voting weight '{weight}' exceeds supported range"),
                };
                ChainError::Crypto(message)
            })
        };
        let pre_votes = certificate
            .pre_votes
            .iter()
            .map(|record| {
                let voter = record.vote.vote.voter.clone();
                let weight = parse_weight("pre-vote", &record.weight)?;
                Ok(VotePower { voter, weight })
            })
            .collect::<ChainResult<Vec<_>>>()?;
        let pre_commits = certificate
            .pre_commits
            .iter()
            .map(|record| {
                let voter = record.vote.vote.voter.clone();
                let weight = parse_weight("pre-commit", &record.weight)?;
                Ok(VotePower { voter, weight })
            })
            .collect::<ChainResult<Vec<_>>>()?;
        let commit_votes = pre_commits.clone();
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
        let witness = ConsensusWitness::new(
            normalized_block_hash.clone(),
            certificate.round,
            certificate.metadata.epoch,
            certificate.metadata.slot,
            normalized_block_hash,
            quorum_threshold,
            pre_votes,
            pre_commits,
            commit_votes,
            certificate.metadata.quorum_bitmap_root.clone(),
            certificate.metadata.quorum_signature_root.clone(),
            vrf_entries,
            certificate.metadata.witness_commitments.clone(),
            certificate.metadata.reputation_roots.clone(),
        );
        witness.validate_metadata()?;
        Ok(witness)
    }

    fn prove_transaction(&self, witness: Self::TransactionWitness) -> ChainResult<ChainProof> {
        self.prove_with_backend(&witness)
    }

    fn prove_identity(&self, witness: Self::IdentityWitness) -> ChainResult<ChainProof> {
        self.prove_with_backend(&witness)
    }

    fn prove_state_transition(&self, witness: Self::StateWitness) -> ChainResult<ChainProof> {
        self.prove_with_backend(&witness)
    }

    fn prove_pruning(&self, witness: Self::PruningWitness) -> ChainResult<ChainProof> {
        self.prove_with_backend(&witness)
    }

    fn prove_recursive(&self, witness: Self::RecursiveWitness) -> ChainResult<ChainProof> {
        // TODO(fold_global): hand the recursive batch output to `fold_global`
        // once the folding backend consumes Plonky3 recursion artifacts
        // directly instead of relying on the legacy aggregator.
        let aggregator = RecursiveAggregator::new(self.params.clone(), self.backend.clone());
        let proof = aggregator.finalize(&witness)?;
        proof.into_value().map(ChainProof::Plonky3)
    }

    fn prove_uptime(&self, witness: Self::UptimeWitness) -> ChainResult<ChainProof> {
        self.prove_with_backend(&witness)
    }

    fn prove_consensus(&self, witness: Self::ConsensusWitness) -> ChainResult<ChainProof> {
        self.prove_with_backend(&witness)
    }
}
