use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use blake3::hash;
use tracing::{info_span, warn};

use crate::consensus::ConsensusCertificate;
use crate::errors::{ChainError, ChainResult, ProofSizeGateError};
use crate::proof_backend::{ProofBytes, TxPublicInputs};
use crate::rpp::{GlobalStateCommitments, ProofSystemKind};
use crate::types::{
    AttestedIdentityRequest, BlockProofBundle, ChainProof, IdentityGenesis, SignedTransaction,
    UptimeClaim,
};
use prover_backend_interface::audit::{now_timestamp_ms, AuditLog, AuditRecord, AuditRole};
use prover_backend_interface::crash_reports::{CrashContextGuard, CrashReportHook};
use rpp_p2p::{ProofCacheMetrics, ProofCacheMetricsSnapshot};
use rpp_pruning::Envelope;

#[cfg(feature = "backend-plonky3")]
use crate::plonky3::verifier::Plonky3Verifier;
#[cfg(feature = "prover-stwo")]
use crate::stwo::aggregation::StateCommitmentSnapshot;
#[cfg(not(feature = "prover-stwo"))]
use crate::stwo::aggregation::StateCommitmentSnapshot as DisabledStateCommitmentSnapshot;
#[cfg(feature = "prover-stwo")]
use crate::stwo::verifier::NodeVerifier;

#[cfg(feature = "backend-rpp-stark")]
use crate::zk::rpp_verifier::{
    RppStarkVerificationReport, RppStarkVerifier, RppStarkVerifierError,
};
use parking_lot::Mutex;
use serde::Serialize;

#[cfg(not(feature = "prover-stwo"))]
type StateCommitmentSnapshot = DisabledStateCommitmentSnapshot;

const STWO_BYPASS_REASON: &str = "prover-stwo feature disabled";

#[derive(Clone)]
struct StwoVerifierDispatch {
    #[cfg(feature = "prover-stwo")]
    inner: NodeVerifier,
}

impl StwoVerifierDispatch {
    fn new() -> Self {
        #[cfg(feature = "prover-stwo")]
        {
            return Self {
                inner: NodeVerifier::new(),
            };
        }

        #[cfg(not(feature = "prover-stwo"))]
        {
            Self {}
        }
    }

    #[cfg(feature = "prover-stwo")]
    fn is_bypass(&self) -> bool {
        false
    }

    #[cfg(not(feature = "prover-stwo"))]
    fn is_bypass(&self) -> bool {
        true
    }

    fn verifier(&self) -> ChainResult<&dyn ProofVerifier> {
        #[cfg(feature = "prover-stwo")]
        {
            Ok(&self.inner)
        }

        #[cfg(not(feature = "prover-stwo"))]
        {
            Ok(self as &dyn ProofVerifier)
        }
    }

    #[cfg(feature = "prover-stwo")]
    fn verify_bundle(
        &self,
        identity_proofs: &[ChainProof],
        transaction_proofs: &[ChainProof],
        uptime_proofs: &[ChainProof],
        consensus_proofs: &[ChainProof],
        state_proof: &ChainProof,
        pruning_proof: &ChainProof,
        pruning_envelope: &Envelope,
        recursive_proof: &ChainProof,
        state_commitments: &StateCommitmentSnapshot,
        expected_previous_commitment: Option<&str>,
    ) -> ChainResult<()> {
        self.inner
            .verify_bundle(
                identity_proofs,
                transaction_proofs,
                uptime_proofs,
                consensus_proofs,
                state_proof,
                pruning_proof,
                pruning_envelope,
                recursive_proof,
                state_commitments,
                expected_previous_commitment,
            )
            .map(|_| ())
    }

    #[cfg(not(feature = "prover-stwo"))]
    #[allow(clippy::too_many_arguments)]
    fn verify_bundle(
        &self,
        identity_proofs: &[ChainProof],
        transaction_proofs: &[ChainProof],
        uptime_proofs: &[ChainProof],
        consensus_proofs: &[ChainProof],
        state_proof: &ChainProof,
        pruning_proof: &ChainProof,
        pruning_envelope: &Envelope,
        recursive_proof: &ChainProof,
        state_commitments: &StateCommitmentSnapshot,
        expected_previous_commitment: Option<&str>,
    ) -> ChainResult<()> {
        let _ = (
            identity_proofs,
            transaction_proofs,
            uptime_proofs,
            consensus_proofs,
            state_proof,
            pruning_proof,
            pruning_envelope,
            recursive_proof,
            state_commitments,
            expected_previous_commitment,
        );
        Ok(())
    }

    #[cfg(feature = "prover-stwo")]
    fn verify_decoded_transaction(
        &self,
        proof: &prover_stwo_backend::backend::DecodedTxProof,
    ) -> ChainResult<()> {
        self.inner.verify_transaction_proof(proof)
    }

    #[cfg(not(feature = "prover-stwo"))]
    fn verify_decoded_transaction(
        &self,
        proof: &prover_stwo_backend::backend::DecodedTxProof,
    ) -> ChainResult<()> {
        let _ = proof;
        Ok(())
    }
}

#[cfg(feature = "prover-stwo")]
impl ProofVerifier for StwoVerifierDispatch {
    fn system(&self) -> ProofSystemKind {
        ProofSystemKind::Stwo
    }

    fn verify_transaction(&self, proof: &ChainProof) -> ChainResult<()> {
        self.inner.verify_transaction(proof)
    }

    fn verify_identity(&self, proof: &ChainProof) -> ChainResult<()> {
        self.inner.verify_identity(proof)
    }

    fn verify_state(&self, proof: &ChainProof) -> ChainResult<()> {
        self.inner.verify_state(proof)
    }

    fn verify_pruning(&self, proof: &ChainProof) -> ChainResult<()> {
        self.inner.verify_pruning(proof)
    }

    fn verify_recursive(&self, proof: &ChainProof) -> ChainResult<()> {
        self.inner.verify_recursive(proof)
    }

    fn verify_uptime(&self, proof: &ChainProof) -> ChainResult<()> {
        self.inner.verify_uptime(proof)
    }

    fn verify_consensus(&self, proof: &ChainProof) -> ChainResult<()> {
        self.inner.verify_consensus(proof)
    }
}

#[cfg(not(feature = "prover-stwo"))]
impl ProofVerifier for StwoVerifierDispatch {
    fn system(&self) -> ProofSystemKind {
        ProofSystemKind::Stwo
    }

    fn verify_transaction(&self, proof: &ChainProof) -> ChainResult<()> {
        let _ = proof;
        Ok(())
    }

    fn verify_identity(&self, proof: &ChainProof) -> ChainResult<()> {
        let _ = proof;
        Ok(())
    }

    fn verify_state(&self, proof: &ChainProof) -> ChainResult<()> {
        let _ = proof;
        Ok(())
    }

    fn verify_pruning(&self, proof: &ChainProof) -> ChainResult<()> {
        let _ = proof;
        Ok(())
    }

    fn verify_recursive(&self, proof: &ChainProof) -> ChainResult<()> {
        let _ = proof;
        Ok(())
    }

    fn verify_uptime(&self, proof: &ChainProof) -> ChainResult<()> {
        let _ = proof;
        Ok(())
    }

    fn verify_consensus(&self, proof: &ChainProof) -> ChainResult<()> {
        let _ = proof;
        Ok(())
    }
}

/// High-level abstraction for wallet-side proof generation that any backend must satisfy.
pub trait ProofProver {
    type IdentityWitness;
    type TransactionWitness;
    type StateWitness;
    type PruningWitness;
    type RecursiveWitness;
    type UptimeWitness;
    type ConsensusWitness;

    /// Identify the underlying proof system implementation.
    fn system(&self) -> ProofSystemKind;

    /// Construct the witness for an identity declaration proof.
    fn build_identity_witness(
        &self,
        genesis: &IdentityGenesis,
    ) -> ChainResult<Self::IdentityWitness>;

    /// Construct the witness for a signed transaction.
    fn build_transaction_witness(
        &self,
        tx: &SignedTransaction,
    ) -> ChainResult<Self::TransactionWitness>;

    /// Construct the witness for a batched state transition.
    fn build_state_witness(
        &self,
        prev_state_root: &str,
        new_state_root: &str,
        identities: &[AttestedIdentityRequest],
        transactions: &[SignedTransaction],
    ) -> ChainResult<Self::StateWitness>;

    /// Construct the pruning witness linking prior and current state roots.
    fn build_pruning_witness(
        &self,
        expected_previous_state_root: Option<&str>,
        previous_identities: &[AttestedIdentityRequest],
        previous_txs: &[SignedTransaction],
        pruning: &Envelope,
        removed: Vec<String>,
    ) -> ChainResult<Self::PruningWitness>;

    /// Construct the recursive witness aggregating all proof commitments.
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
    ) -> ChainResult<Self::RecursiveWitness>;

    /// Construct the witness for an uptime proof.
    fn build_uptime_witness(&self, claim: &UptimeClaim) -> ChainResult<Self::UptimeWitness>;

    /// Construct the witness capturing consensus aggregation for the given block hash.
    fn build_consensus_witness(
        &self,
        block_hash: &str,
        certificate: &ConsensusCertificate,
    ) -> ChainResult<Self::ConsensusWitness>;

    /// Produce a proof attesting to transaction validity.
    fn prove_transaction(&self, witness: Self::TransactionWitness) -> ChainResult<ChainProof>;

    /// Produce a proof validating an identity genesis declaration.
    fn prove_identity(&self, witness: Self::IdentityWitness) -> ChainResult<ChainProof>;

    /// Produce a state transition proof for a batch of identities and transactions.
    fn prove_state_transition(&self, witness: Self::StateWitness) -> ChainResult<ChainProof>;

    /// Prove correctness of pruning decisions relative to prior blocks.
    fn prove_pruning(&self, witness: Self::PruningWitness) -> ChainResult<ChainProof>;

    /// Aggregate individual proofs recursively to extend the block chain.
    fn prove_recursive(&self, witness: Self::RecursiveWitness) -> ChainResult<ChainProof>;

    /// Produce a proof attesting to node uptime within the declared window.
    fn prove_uptime(&self, witness: Self::UptimeWitness) -> ChainResult<ChainProof>;

    /// Produce a proof validating consensus quorum aggregation for the block proposal.
    fn prove_consensus(&self, witness: Self::ConsensusWitness) -> ChainResult<ChainProof>;
}

/// Abstraction for node-side verification of proof artifacts.
pub trait ProofVerifier {
    /// Identify the proof system this verifier handles.
    fn system(&self) -> ProofSystemKind;

    fn verify_transaction(&self, proof: &ChainProof) -> ChainResult<()>;
    fn verify_identity(&self, proof: &ChainProof) -> ChainResult<()>;
    fn verify_state(&self, proof: &ChainProof) -> ChainResult<()>;
    fn verify_pruning(&self, proof: &ChainProof) -> ChainResult<()>;
    fn verify_recursive(&self, proof: &ChainProof) -> ChainResult<()>;
    fn verify_uptime(&self, proof: &ChainProof) -> ChainResult<()>;
    fn verify_consensus(&self, proof: &ChainProof) -> ChainResult<()>;
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct BackendVerificationMetrics {
    pub accepted: u64,
    pub rejected: u64,
    pub bypassed: u64,
    pub total_duration_ms: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct BackendSlaStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_budget_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_rate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_budget: Option<f64>,
    pub healthy: bool,
}

impl BackendSlaStatus {
    pub fn new(
        latency_ms: Option<f64>,
        error_rate: Option<f64>,
        latency_budget_ms: Option<f64>,
        error_budget: Option<f64>,
    ) -> Self {
        let latency_ok = match (latency_ms, latency_budget_ms) {
            (Some(value), Some(budget)) => value <= budget,
            _ => true,
        };
        let error_ok = match (error_rate, error_budget) {
            (Some(value), Some(budget)) => value <= budget,
            _ => true,
        };

        Self {
            latency_ms,
            latency_budget_ms,
            error_rate,
            error_budget,
            healthy: latency_ok && error_ok,
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub enum BackendVerificationOutcome {
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BackendVerificationSnapshot {
    pub backend: String,
    pub outcome: BackendVerificationOutcome,
    #[serde(skip_serializing_if = "|b: &bool| !*b")]
    pub bypassed: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct VerifierMetricsSnapshot {
    pub per_backend: BTreeMap<String, BackendVerificationMetrics>,
    pub cache: ProofCacheMetricsSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<BackendVerificationSnapshot>,
}

const VERIFIER_LATENCY_SLA_MS: f64 = 8_000.0;
const VERIFIER_ERROR_RATE_BUDGET: f64 = 0.02;

pub fn verifier_sla_status(metrics: &BackendVerificationMetrics) -> BackendSlaStatus {
    let attempts = metrics.accepted.saturating_add(metrics.rejected) as f64;
    let latency_ms = if attempts > 0.0 {
        Some(metrics.total_duration_ms as f64 / attempts)
    } else {
        None
    };
    let error_rate = if attempts > 0.0 {
        Some(metrics.rejected as f64 / attempts)
    } else {
        None
    };

    BackendSlaStatus::new(
        latency_ms,
        error_rate,
        Some(VERIFIER_LATENCY_SLA_MS),
        Some(VERIFIER_ERROR_RATE_BUDGET),
    )
}

impl Default for VerifierMetricsSnapshot {
    fn default() -> Self {
        let mut per_backend = BTreeMap::new();
        for system in registry_backends() {
            per_backend.insert(
                proof_system_label(system).to_string(),
                BackendVerificationMetrics::default(),
            );
        }
        Self {
            per_backend,
            cache: ProofCacheMetricsSnapshot::default(),
            last: None,
        }
    }
}

#[derive(Clone)]
struct VerifierMetrics {
    inner: Arc<Mutex<BTreeMap<String, BackendVerificationMetrics>>>,
    cache: ProofCacheMetrics,
    last: Arc<Mutex<Option<BackendVerificationSnapshot>>>,
}

impl VerifierMetrics {
    fn new() -> Self {
        let mut per_backend = BTreeMap::new();
        for system in registry_backends() {
            per_backend.insert(
                proof_system_label(system).to_string(),
                BackendVerificationMetrics::default(),
            );
        }
        Self {
            inner: Arc::new(Mutex::new(per_backend)),
            cache: ProofCacheMetrics::default(),
            last: Arc::new(Mutex::new(None)),
        }
    }

    fn record(&self, system: ProofSystemKind, duration: Duration, succeeded: bool, bypass: bool) {
        let label = proof_system_label(system).to_string();
        let mut guard = self.inner.lock();
        let entry = guard
            .entry(label)
            .or_insert_with(BackendVerificationMetrics::default);
        if succeeded {
            entry.accepted = entry.accepted.saturating_add(1);
        } else {
            entry.rejected = entry.rejected.saturating_add(1);
        }
        if bypass {
            entry.bypassed = entry.bypassed.saturating_add(1);
        }
        entry.total_duration_ms = entry
            .total_duration_ms
            .saturating_add(duration_to_millis(duration));

        *self.last.lock() = Some(BackendVerificationSnapshot {
            backend: label,
            outcome: if succeeded {
                BackendVerificationOutcome::Accepted
            } else {
                BackendVerificationOutcome::Rejected
            },
            bypassed: bypass,
        });
    }

    fn snapshot(&self) -> VerifierMetricsSnapshot {
        let guard = self.inner.lock();
        let mut per_backend = VerifierMetricsSnapshot::default().per_backend;
        for (label, metrics) in guard.iter() {
            per_backend
                .entry(label.clone())
                .or_insert_with(BackendVerificationMetrics::default)
                .clone_from(metrics);
        }
        VerifierMetricsSnapshot {
            per_backend,
            cache: self.cache.snapshot(),
            last: self.last.lock().clone(),
        }
    }

    fn cache_metrics(&self) -> ProofCacheMetrics {
        self.cache.clone()
    }
}

impl Default for VerifierMetrics {
    fn default() -> Self {
        Self::new()
    }
}

fn duration_to_millis(duration: Duration) -> u64 {
    duration
        .as_millis()
        .min(u128::from(u64::MAX))
        .try_into()
        .unwrap_or(u64::MAX)
}

fn registry_backends() -> Vec<ProofSystemKind> {
    let mut systems = vec![ProofSystemKind::Stwo];
    #[cfg(feature = "backend-plonky3")]
    {
        systems.push(ProofSystemKind::Plonky3);
    }
    #[cfg(feature = "backend-rpp-stark")]
    {
        systems.push(ProofSystemKind::RppStark);
    }
    systems
}

fn proof_system_label(system: ProofSystemKind) -> &'static str {
    match system {
        ProofSystemKind::Stwo => "stwo",
        ProofSystemKind::Plonky3 => "plonky3",
        ProofSystemKind::Plonky2 => "plonky2",
        ProofSystemKind::Halo2 => "halo2",
        ProofSystemKind::RppStark => "rpp-stark",
    }
}

fn verifier_audit_log() -> Option<AuditLog> {
    match AuditLog::from_env(AuditLog::ENV_VAR, AuditLog::DEFAULT_VERIFIER_PATH) {
        Ok(log) => log,
        Err(err) => {
            warn!(
                target = "runtime.proof.audit",
                %err,
                "failed to initialise verifier audit log"
            );
            None
        }
    }
}

fn install_zk_crash_reports() -> &'static Option<CrashReportHook> {
    static HOOK: OnceLock<Option<CrashReportHook>> = OnceLock::new();
    HOOK.get_or_init(|| CrashReportHook::install_from_env("verifier"))
}

fn crash_context_guard(system: ProofSystemKind, operation: &'static str) -> CrashContextGuard {
    install_zk_crash_reports();
    CrashContextGuard::enter(proof_system_label(system), operation)
}

/// Maintains verifier instances for all supported proof backends and provides
/// ergonomic dispatch helpers for consumers that only work with the unified
/// [`ChainProof`] abstraction.
#[derive(Clone)]
pub struct ProofVerifierRegistry {
    metrics: VerifierMetrics,
    stwo: StwoVerifierDispatch,
    #[cfg(feature = "backend-plonky3")]
    plonky3: Plonky3Verifier,
    #[cfg(feature = "backend-rpp-stark")]
    rpp_stark: RppStarkProofVerifier,
    audit_log: Option<AuditLog>,
}

#[cfg(feature = "backend-rpp-stark")]
const DEFAULT_RPP_STARK_PROOF_LIMIT_BYTES: usize = 4 * 1024 * 1024;

impl Default for ProofVerifierRegistry {
    fn default() -> Self {
        Self {
            metrics: VerifierMetrics::default(),
            stwo: StwoVerifierDispatch::new(),
            #[cfg(feature = "backend-plonky3")]
            plonky3: Plonky3Verifier::default(),
            #[cfg(feature = "backend-rpp-stark")]
            rpp_stark: RppStarkProofVerifier::new(
                u32::try_from(DEFAULT_RPP_STARK_PROOF_LIMIT_BYTES)
                    .expect("default proof limit fits in u32"),
            ),
            audit_log: verifier_audit_log(),
        }
    }
}

#[cfg(feature = "backend-rpp-stark")]
#[derive(Clone)]
struct RppStarkProofVerifier {
    inner: RppStarkVerifier,
    max_proof_size_bytes: u32,
}

#[cfg(feature = "backend-rpp-stark")]
impl RppStarkProofVerifier {
    fn new(max_proof_size_bytes: u32) -> Self {
        Self {
            inner: RppStarkVerifier::new(),
            max_proof_size_bytes,
        }
    }

    fn verify_with_report(
        &self,
        proof: &ChainProof,
        kind: &'static str,
    ) -> ChainResult<RppStarkVerificationReport> {
        self.verify_with_report_raw(proof, kind)
            .map_err(|err| self.map_error(kind, err))
    }

    fn verify_with_report_raw(
        &self,
        proof: &ChainProof,
        kind: &'static str,
    ) -> Result<RppStarkVerificationReport, RppStarkVerifierError> {
        let artifact = proof.expect_rpp_stark()?;
        self.inner.verify(
            artifact.params(),
            artifact.public_inputs(),
            artifact.proof(),
            self.max_proof_size_bytes,
        )
    }

    fn verify_block_bundle(&self, bundle: &BlockProofBundle) -> ChainResult<()> {
        for proof in &bundle.transaction_proofs {
            self.verify_with_report(proof, "transaction")?;
        }
        self.verify_with_report(&bundle.state_proof, "state")?;
        self.verify_with_report(&bundle.pruning_proof, "pruning")?;
        self.verify_with_report(&bundle.recursive_proof, "recursive")?;
        Ok(())
    }

    fn map_error(&self, kind: &'static str, error: RppStarkVerifierError) -> ChainError {
        match error {
            RppStarkVerifierError::ProofSizeLimitMismatch {
                params_kib,
                expected_kib,
            } => ChainError::ProofSizeGate {
                backend: ProofSystemKind::RppStark,
                circuit: kind,
                error: ProofSizeGateError::LimitMismatch {
                    params_kib,
                    expected_kib,
                },
            },
            RppStarkVerifierError::ProofSizeLimitOverflow { max_kib } => {
                ChainError::ProofSizeGate {
                    backend: ProofSystemKind::RppStark,
                    circuit: kind,
                    error: ProofSizeGateError::LimitOverflow { max_kib },
                }
            }
            RppStarkVerifierError::VerificationFailed {
                failure: RppStarkVerifyFailure::ProofTooLarge { max_kib, got_kib },
                report: _,
            } => ChainError::ProofSizeGate {
                backend: ProofSystemKind::RppStark,
                circuit: kind,
                error: ProofSizeGateError::ProofTooLarge { max_kib, got_kib },
            },
            RppStarkVerifierError::VerificationFailed { failure, report } => ChainError::Crypto(
                format!("rpp-stark {kind} verification failed: {failure}; report={report}"),
            ),
            other => ChainError::Crypto(format!("rpp-stark {kind} verification error: {other}")),
        }
    }
}

#[cfg(feature = "backend-rpp-stark")]
impl ProofVerifier for RppStarkProofVerifier {
    fn system(&self) -> ProofSystemKind {
        ProofSystemKind::RppStark
    }

    fn verify_transaction(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_with_report(proof, "transaction").map(|_| ())
    }

    fn verify_identity(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_with_report(proof, "identity").map(|_| ())
    }

    fn verify_state(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_with_report(proof, "state").map(|_| ())
    }

    fn verify_pruning(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_with_report(proof, "pruning").map(|_| ())
    }

    fn verify_recursive(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_with_report(proof, "recursive").map(|_| ())
    }

    fn verify_uptime(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_with_report(proof, "uptime").map(|_| ())
    }

    fn verify_consensus(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_with_report(proof, "consensus").map(|_| ())
    }
}

impl ProofVerifierRegistry {
    /// Construct a registry with a custom proof-size limit for RPP-STARK verification.
    pub fn with_max_proof_size_bytes(max_bytes: usize) -> ChainResult<Self> {
        #[cfg(not(feature = "backend-rpp-stark"))]
        let _ = max_bytes;

        #[cfg(feature = "backend-rpp-stark")]
        let limit = u32::try_from(max_bytes).map_err(|_| {
            ChainError::Config(
                "max_proof_size_bytes exceeds u32::MAX and cannot be forwarded to rpp-stark".into(),
            )
        })?;

        Ok(Self {
            metrics: VerifierMetrics::default(),
            stwo: StwoVerifierDispatch::new(),
            #[cfg(feature = "backend-plonky3")]
            plonky3: Plonky3Verifier::default(),
            #[cfg(feature = "backend-rpp-stark")]
            rpp_stark: RppStarkProofVerifier::new(limit),
            audit_log: verifier_audit_log(),
        })
    }

    /// Construct a new registry with default verifier instances for each
    /// backend.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stable fingerprint of the compiled verifier backends for cache namespacing.
    pub fn backend_fingerprint() -> String {
        Self::advertised_backends().join(",")
    }

    /// Ordered list of proof system backends compiled into the verifier registry.
    pub fn advertised_backends() -> Vec<String> {
        let mut systems = registry_backends();
        systems.sort();
        systems
            .into_iter()
            .map(proof_system_label)
            .map(ToString::to_string)
            .collect()
    }

    fn system_verifier(&self, system: ProofSystemKind) -> ChainResult<&dyn ProofVerifier> {
        match system {
            ProofSystemKind::Stwo => self.stwo.verifier(),
            #[cfg(feature = "backend-plonky3")]
            ProofSystemKind::Plonky3 => Ok(&self.plonky3),
            #[cfg(feature = "backend-rpp-stark")]
            ProofSystemKind::RppStark => Ok(&self.rpp_stark),
            other => Err(ChainError::Crypto(format!(
                "unsupported proof system {:?} in verifier registry",
                other
            ))),
        }
    }

    fn proof_verifier(&self, proof: &ChainProof) -> ChainResult<&dyn ProofVerifier> {
        self.system_verifier(proof.system())
    }

    fn append_audit(
        &self,
        system: ProofSystemKind,
        operation: &str,
        fingerprint: Option<&str>,
        success: bool,
        error: Option<&ChainError>,
    ) {
        let Some(log) = &self.audit_log else {
            return;
        };

        let record = AuditRecord {
            index: 0,
            timestamp_ms: now_timestamp_ms(),
            role: AuditRole::Verifier,
            backend: proof_system_label(system).to_string(),
            operation: operation.to_string(),
            circuit: None,
            proof_fingerprint: fingerprint.map(|value| value.to_string()),
            result: if success { "ok" } else { "err" }.to_string(),
            message: error.map(ToString::to_string),
            witness_bytes: None,
            proof_bytes: None,
            prev_hash: String::new(),
            entry_hash: String::new(),
        };

        if let Err(err) = log.append(record) {
            warn!(
                target = "runtime.proof.audit",
                %err,
                backend = %proof_system_label(system),
                operation,
                "failed to append verifier audit record"
            );
        }
    }

    #[cfg(feature = "backend-rpp-stark")]
    pub fn verify_rpp_stark_with_report(
        &self,
        proof: &ChainProof,
        proof_kind: &'static str,
    ) -> ChainResult<RppStarkVerificationReport> {
        self.verify_rpp_stark_with_report_raw(proof, proof_kind)
            .map_err(|err| self.map_rpp_stark_error(proof_kind, err))
    }

    #[cfg(feature = "backend-rpp-stark")]
    pub fn verify_rpp_stark_with_report_raw(
        &self,
        proof: &ChainProof,
        proof_kind: &'static str,
    ) -> Result<RppStarkVerificationReport, RppStarkVerifierError> {
        if proof.system() != ProofSystemKind::RppStark {
            return Err(RppStarkVerifierError::BackendUnavailable(
                "expected RPP-STARK proof",
            ));
        }
        let mut failure = None;
        let result =
            self.record_backend(ProofSystemKind::RppStark, "rpp-stark-report", || match self
                .rpp_stark
                .verify_with_report_raw(proof, proof_kind)
            {
                Ok(report) => Ok(report),
                Err(err) => {
                    failure = Some(err.clone());
                    Err(self.map_rpp_stark_error(proof_kind, err))
                }
            });

        match result {
            Ok(report) => Ok(report),
            Err(_) => Err(failure.expect("rpp-stark error captured during metrics recording")),
        }
    }

    #[cfg(feature = "backend-rpp-stark")]
    pub fn verify_rpp_stark_block_bundle(&self, bundle: &BlockProofBundle) -> ChainResult<()> {
        self.record_backend(ProofSystemKind::RppStark, "rpp-stark-block-bundle", || {
            self.rpp_stark.verify_block_bundle(bundle)
        })
    }

    #[cfg(feature = "backend-rpp-stark")]
    pub fn map_rpp_stark_error(
        &self,
        kind: &'static str,
        error: RppStarkVerifierError,
    ) -> ChainError {
        self.rpp_stark.map_error(kind, error)
    }

    fn ensure_bundle_system(
        &self,
        bundle: &BlockProofBundle,
        expected: ProofSystemKind,
    ) -> ChainResult<()> {
        for proof in &bundle.transaction_proofs {
            if proof.system() != expected {
                return Err(ChainError::Crypto(format!(
                    "transaction proof uses {:?} but {:?} bundle expected",
                    proof.system(),
                    expected
                )));
            }
        }
        for proof in [
            &bundle.state_proof,
            &bundle.pruning_proof,
            &bundle.recursive_proof,
        ] {
            if proof.system() != expected {
                return Err(ChainError::Crypto(format!(
                    "block proof uses {:?} but {:?} bundle expected",
                    proof.system(),
                    expected
                )));
            }
        }
        Ok(())
    }

    /// Verify a transaction proof using the appropriate backend.
    pub fn verify_transaction(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_with_metrics("transaction", proof, |verifier, proof| {
            verifier.verify_transaction(proof)
        })
    }

    /// Verify an identity proof using the appropriate backend.
    pub fn verify_identity(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_with_metrics("identity", proof, |verifier, proof| {
            verifier.verify_identity(proof)
        })
    }

    /// Verify a state transition proof using the appropriate backend.
    pub fn verify_state(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_with_metrics("state", proof, |verifier, proof| {
            verifier.verify_state(proof)
        })
    }

    /// Verify a pruning proof using the appropriate backend.
    pub fn verify_pruning(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_with_metrics("pruning", proof, |verifier, proof| {
            verifier.verify_pruning(proof)
        })
    }

    /// Verify a recursive aggregation proof using the appropriate backend.
    pub fn verify_recursive(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_with_metrics("recursive", proof, |verifier, proof| {
            verifier.verify_recursive(proof)
        })
    }

    /// Verify an uptime proof using the appropriate backend.
    pub fn verify_uptime(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_with_metrics("uptime", proof, |verifier, proof| {
            verifier.verify_uptime(proof)
        })
    }

    /// Verify a consensus proof using the appropriate backend.
    pub fn verify_consensus(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_with_metrics("consensus", proof, |verifier, proof| {
            verifier.verify_consensus(proof)
        })
    }

    /// Verify a transaction proof provided as backend artifacts for the STWO system.
    pub fn verify_stwo_proof_bytes(
        &self,
        proof_bytes: &ProofBytes,
        public_inputs: &TxPublicInputs,
    ) -> ChainResult<()> {
        #[cfg(not(feature = "prover-stwo"))]
        {
            let _ = (proof_bytes, public_inputs);
            warn!(
                target = "runtime.proof.bypass",
                operation = "decoded-transaction",
                backend = %proof_system_label(ProofSystemKind::Stwo),
                bypass = true,
                reason = STWO_BYPASS_REASON,
                "accepting proof via STWO bypass"
            );
            Ok(())
        }

        #[cfg(feature = "prover-stwo")]
        {
            self.verify_stwo_proof_bytes_impl(proof_bytes, public_inputs)
        }
    }

    #[cfg(feature = "prover-stwo")]
    fn verify_stwo_proof_bytes_impl(
        &self,
        proof_bytes: &ProofBytes,
        public_inputs: &TxPublicInputs,
    ) -> ChainResult<()> {
        use prover_stwo_backend::backend::decode_tx_proof;
        use prover_stwo_backend::official::params::{FieldElement, StarkParameters};

        let decoded = decode_tx_proof(proof_bytes).map_err(map_stwo_backend_error)?;

        let parameters = StarkParameters::blueprint_default();
        let expected_fields = rebuild_tx_public_inputs(&parameters, public_inputs);
        let expected_inputs: Vec<String> =
            expected_fields.iter().map(FieldElement::to_hex).collect();

        if decoded.public_inputs != expected_inputs {
            return Err(ChainError::Crypto(
                "transaction public inputs mismatch".into(),
            ));
        }

        let hasher = parameters.poseidon_hasher();
        let expected_commitment = hasher.hash(&expected_fields);
        if decoded.commitment != expected_commitment.to_hex() {
            return Err(ChainError::Crypto("transaction commitment mismatch".into()));
        }

        if field_to_padded_bytes(&expected_commitment) != public_inputs.transaction_commitment {
            return Err(ChainError::Crypto(
                "transaction commitment digest mismatch".into(),
            ));
        }

        self.record_backend(ProofSystemKind::Stwo, "decoded-transaction", || {
            self.stwo.verify_decoded_transaction(&decoded)
        })
    }

    /// Verify the collection of proofs tied to a block and ensure they all use
    /// the same backend implementation.
    pub fn verify_block_bundle(
        &self,
        bundle: &BlockProofBundle,
        identity_proofs: &[ChainProof],
        uptime_proofs: &[ChainProof],
        consensus_proofs: &[ChainProof],
        pruning_envelope: &Envelope,
        state_commitments: &StateCommitmentSnapshot,
        expected_previous_commitment: Option<&str>,
    ) -> ChainResult<()> {
        match bundle.state_proof.system() {
            ProofSystemKind::Stwo => {
                self.ensure_bundle_system(bundle, ProofSystemKind::Stwo)?;
                self.record_backend(ProofSystemKind::Stwo, "block-bundle", || {
                    self.stwo.verify_bundle(
                        identity_proofs,
                        &bundle.transaction_proofs,
                        uptime_proofs,
                        consensus_proofs,
                        &bundle.state_proof,
                        &bundle.pruning_proof,
                        pruning_envelope,
                        &bundle.recursive_proof,
                        state_commitments,
                        expected_previous_commitment,
                    )
                })
            }
            #[cfg(feature = "backend-plonky3")]
            ProofSystemKind::Plonky3 => {
                self.ensure_bundle_system(bundle, ProofSystemKind::Plonky3)?;
                self.record_backend(ProofSystemKind::Plonky3, "block-bundle", || {
                    self.plonky3
                        .verify_bundle(bundle, expected_previous_commitment)
                })
            }
            #[cfg(feature = "backend-rpp-stark")]
            ProofSystemKind::RppStark => {
                self.ensure_bundle_system(bundle, ProofSystemKind::RppStark)?;
                let _ = state_commitments;
                let _ = expected_previous_commitment;
                for proof in identity_proofs {
                    self.verify_identity(proof)?;
                }
                for proof in uptime_proofs {
                    self.verify_uptime(proof)?;
                }
                for proof in consensus_proofs {
                    self.verify_consensus(proof)?;
                }
                self.record_backend(ProofSystemKind::RppStark, "block-bundle", || {
                    self.rpp_stark.verify_block_bundle(bundle)
                })
            }
            other => Err(ChainError::Crypto(format!(
                "unsupported proof system {:?} for block bundle",
                other
            ))),
        }
    }

    pub fn metrics_snapshot(&self) -> VerifierMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn cache_metrics(&self) -> ProofCacheMetrics {
        self.metrics.cache_metrics()
    }

    fn verify_with_metrics<F, T>(
        &self,
        operation: &'static str,
        proof: &ChainProof,
        verify_fn: F,
    ) -> ChainResult<T>
    where
        F: FnOnce(&dyn ProofVerifier, &ChainProof) -> ChainResult<T>,
    {
        let verifier = self.proof_verifier(proof)?;
        let system = verifier.system();
        let _crash_guard = crash_context_guard(system, operation);
        let fingerprint = proof_fingerprint(proof);
        let bypass = matches!(system, ProofSystemKind::Stwo) && self.stwo.is_bypass();
        let span = info_span!(
            "runtime.proof.verify",
            operation,
            backend = ?system,
            proof_hash = %fingerprint,
            bypass_mode = bypass
        );
        let _guard = span.enter();
        if bypass {
            warn!(
                target = "runtime.proof.bypass",
                operation,
                backend = %proof_system_label(system),
                proof_hash = %fingerprint,
                bypass = true,
                reason = STWO_BYPASS_REASON,
                "accepting proof via STWO bypass"
            );
        }
        let started = Instant::now();
        let result = verify_fn(verifier, proof);
        let success = result.is_ok();
        self.metrics
            .record(system, started.elapsed(), success, bypass);
        self.append_audit(
            system,
            operation,
            Some(fingerprint.as_str()),
            success,
            result.as_ref().err(),
        );
        result
    }

    fn record_backend<F, T>(
        &self,
        system: ProofSystemKind,
        operation: &'static str,
        action: F,
    ) -> ChainResult<T>
    where
        F: FnOnce() -> ChainResult<T>,
    {
        let _crash_guard = crash_context_guard(system, operation);
        let bypass = matches!(system, ProofSystemKind::Stwo) && self.stwo.is_bypass();
        if bypass {
            warn!(
                target = "runtime.proof.bypass",
                operation,
                backend = %proof_system_label(system),
                bypass = true,
                reason = STWO_BYPASS_REASON,
                "accepting proof via STWO bypass"
            );
        }
        let started = Instant::now();
        let result = action();
        let success = result.is_ok();
        self.metrics
            .record(system, started.elapsed(), success, bypass);
        self.append_audit(system, operation, None, success, result.as_ref().err());
        result
    }
}

fn proof_fingerprint(proof: &ChainProof) -> String {
    serde_json::to_vec(proof)
        .map(|bytes| hash(&bytes).to_hex().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(all(test, feature = "prover-stwo"))]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
    use tracing_subscriber::registry::LookupSpan;
    use tracing_subscriber::Registry;

    #[derive(Clone, Default)]
    struct RecordingLayer {
        spans: Arc<Mutex<Vec<String>>>,
    }

    impl RecordingLayer {
        fn names(&self) -> Vec<String> {
            self.spans.lock().expect("record spans").clone()
        }
    }

    #[test]
    fn verifier_sla_detects_breaches() {
        let metrics = BackendVerificationMetrics {
            accepted: 1,
            rejected: 1,
            bypassed: 0,
            total_duration_ms: 10_000,
        };

        let sla = verifier_sla_status(&metrics);

        assert!(!sla.healthy);
        assert!(sla
            .latency_ms
            .zip(sla.latency_budget_ms)
            .map(|(latency, budget)| latency > budget)
            .unwrap_or(false));
        assert!(sla
            .error_rate
            .zip(sla.error_budget)
            .map(|(rate, budget)| rate > budget)
            .unwrap_or(false));
    }

    #[test]
    fn verifier_sla_is_healthy_within_budget() {
        let metrics = BackendVerificationMetrics {
            accepted: 10,
            rejected: 0,
            bypassed: 0,
            total_duration_ms: 5_000,
        };

        let sla = verifier_sla_status(&metrics);

        assert!(sla.healthy);
        assert_eq!(sla.error_rate, Some(0.0));
        assert!(sla
            .latency_ms
            .zip(sla.latency_budget_ms)
            .map(|(latency, budget)| latency <= budget)
            .unwrap_or(false));
    }

    impl<S> Layer<S> for RecordingLayer
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::Id,
            _ctx: Context<'_, S>,
        ) {
            self.spans
                .lock()
                .expect("record span name")
                .push(attrs.metadata().name().to_string());
        }
    }

    fn dummy_state_proof() -> StarkProof {
        StarkProof {
            kind: ProofKind::State,
            commitment: "11".repeat(32),
            public_inputs: Vec::new(),
            payload: ProofPayload::State(StateWitness {
                prev_state_root: "22".repeat(32),
                new_state_root: "33".repeat(32),
                identities: Vec::new(),
                transactions: Vec::new(),
                accounts_before: Vec::new(),
                accounts_after: Vec::new(),
                required_tier: crate::reputation::Tier::Tl0,
                reputation_weights: crate::reputation::ReputationWeights::default(),
            }),
            trace: crate::stwo::circuit::ExecutionTrace {
                segments: Vec::new(),
            },
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
        }
    }

    use crate::stwo::circuit::state::StateWitness;
    use crate::stwo::proof::{
        CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
    };

    #[cfg(feature = "backend-rpp-stark")]
    fn oversized_rpp_stark_proof() -> (ProofVerifierRegistry, ChainProof, u32, u32) {
        use rpp_stark::backend::params_limit_to_node_bytes;
        use rpp_stark::params::deserialize_params;
        use std::path::Path;

        let vectors_dir = Path::new("vendor/rpp-stark/vectors/stwo/mini");
        let params =
            std::fs::read(vectors_dir.join("params.bin")).expect("read RPP-STARK params vector");
        let public_inputs = std::fs::read(vectors_dir.join("public_inputs.bin"))
            .expect("read RPP-STARK public inputs vector");
        let mut proof_bytes =
            std::fs::read(vectors_dir.join("proof.bin")).expect("read RPP-STARK proof vector");

        let stark_params = deserialize_params(&params).expect("deserialize params");
        let node_limit =
            params_limit_to_node_bytes(&stark_params).expect("params encode a valid proof limit");
        let max_kib = node_limit.div_ceil(1024);

        proof_bytes.extend(std::iter::repeat(0u8).take(node_limit as usize / 2 + 1));
        let got_kib = u64::try_from(proof_bytes.len())
            .expect("proof length fits in u64")
            .div_ceil(1024);
        let got_kib = u32::try_from(got_kib).expect("proof length fits in u32 kibibytes");

        let registry = ProofVerifierRegistry::with_max_proof_size_bytes(node_limit as usize)
            .expect("custom proof limit should fit in registry");
        let chain_proof =
            ChainProof::RppStark(RppStarkProof::new(params, public_inputs, proof_bytes));

        (registry, chain_proof, max_kib, got_kib)
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn assert_rpp_size_gate(
        result: ChainResult<()>,
        circuit: &'static str,
        max_kib: u32,
        got_kib: u32,
    ) {
        let message = result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_default();

        match result {
            Err(ChainError::ProofSizeGate {
                backend,
                circuit: actual_circuit,
                error:
                    ProofSizeGateError::ProofTooLarge {
                        max_kib: actual_max,
                        got_kib: actual_got,
                    },
            }) => {
                assert_eq!(backend, ProofSystemKind::RppStark);
                assert_eq!(actual_circuit, circuit);
                assert_eq!(actual_max, max_kib);
                assert_eq!(actual_got, got_kib);
                assert!(message.contains(circuit));
            }
            other => panic!("expected proof-size gate for {circuit}, got {other:?}"),
        }
    }

    #[test]
    fn verify_state_emits_runtime_span() {
        let recorder = RecordingLayer::default();
        let subscriber = Registry::default().with(recorder.clone());
        tracing::subscriber::with_default(subscriber, || {
            let registry = ProofVerifierRegistry::new();
            let proof = ChainProof::Stwo(dummy_state_proof());
            let _ = registry.verify_state(&proof);
        });
        assert!(recorder
            .names()
            .iter()
            .any(|name| name == "runtime.proof.verify"));
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[test]
    fn maps_rpp_stark_size_gate_errors() {
        use crate::errors::ProofSizeGateError;

        let registry = ProofVerifierRegistry::default();

        let mismatch = registry.map_rpp_stark_error(
            "consensus",
            RppStarkVerifierError::ProofSizeLimitMismatch {
                params_kib: 128,
                expected_kib: 256,
            },
        );

        match mismatch {
            ChainError::ProofSizeGate {
                backend,
                circuit,
                error:
                    ProofSizeGateError::LimitMismatch {
                        params_kib,
                        expected_kib,
                    },
            } => {
                assert_eq!(backend, ProofSystemKind::RppStark);
                assert_eq!(circuit, "consensus");
                assert_eq!(params_kib, 128);
                assert_eq!(expected_kib, 256);
            }
            other => panic!("unexpected mapping for mismatch: {other:?}"),
        }

        let oversize = registry.map_rpp_stark_error(
            "uptime",
            RppStarkVerifierError::VerificationFailed {
                failure: RppStarkVerifyFailure::ProofTooLarge {
                    max_kib: 4096,
                    got_kib: 5120,
                },
                report: RppStarkVerificationReport::pending("test"),
            },
        );

        match oversize {
            ChainError::ProofSizeGate {
                backend,
                circuit,
                error: ProofSizeGateError::ProofTooLarge { max_kib, got_kib },
            } => {
                assert_eq!(backend, ProofSystemKind::RppStark);
                assert_eq!(circuit, "uptime");
                assert_eq!(max_kib, 4096);
                assert_eq!(got_kib, 5120);
            }
            other => panic!("unexpected mapping for oversize: {other:?}"),
        }
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[test]
    fn rpp_stark_transaction_size_gate_reports_circuit() {
        let (registry, proof, max_kib, got_kib) = oversized_rpp_stark_proof();

        let result = registry.verify_transaction(&proof);
        assert_rpp_size_gate(result, "transaction", max_kib, got_kib);
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[test]
    fn rpp_stark_identity_size_gate_reports_circuit() {
        let (registry, proof, max_kib, got_kib) = oversized_rpp_stark_proof();

        let result = registry.verify_identity(&proof);
        assert_rpp_size_gate(result, "identity", max_kib, got_kib);
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[test]
    fn rpp_stark_state_size_gate_reports_circuit() {
        let (registry, proof, max_kib, got_kib) = oversized_rpp_stark_proof();

        let result = registry.verify_state(&proof);
        assert_rpp_size_gate(result, "state", max_kib, got_kib);
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[test]
    fn rpp_stark_pruning_size_gate_reports_circuit() {
        let (registry, proof, max_kib, got_kib) = oversized_rpp_stark_proof();

        let result = registry.verify_pruning(&proof);
        assert_rpp_size_gate(result, "pruning", max_kib, got_kib);
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[test]
    fn rpp_stark_recursive_size_gate_reports_circuit() {
        let (registry, proof, max_kib, got_kib) = oversized_rpp_stark_proof();

        let result = registry.verify_recursive(&proof);
        assert_rpp_size_gate(result, "recursive", max_kib, got_kib);
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[test]
    fn rpp_stark_uptime_size_gate_reports_circuit() {
        let (registry, proof, max_kib, got_kib) = oversized_rpp_stark_proof();

        let result = registry.verify_uptime(&proof);
        assert_rpp_size_gate(result, "uptime", max_kib, got_kib);
    }
}

#[cfg(all(test, not(feature = "prover-stwo")))]
mod bypass_tests {
    use super::*;
    use rpp_pruning::{DIGEST_LENGTH, DOMAIN_TAG_LENGTH};
    use tracing_test::{logs_contain, traced_test};

    fn dummy_recursive_proof() -> ChainProof {
        use crate::stwo::circuit::{recursive::RecursiveWitness, ExecutionTrace};
        use crate::stwo::proof::{
            CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
        };

        let witness = RecursiveWitness {
            previous_commitment: None,
            aggregated_commitment: String::new(),
            identity_commitments: Vec::new(),
            tx_commitments: Vec::new(),
            uptime_commitments: Vec::new(),
            consensus_commitments: Vec::new(),
            state_commitment: String::new(),
            global_state_root: String::new(),
            utxo_root: String::new(),
            reputation_root: String::new(),
            timetoke_root: String::new(),
            zsi_root: String::new(),
            proof_root: String::new(),
            pruning_binding_digest: [0u8; DOMAIN_TAG_LENGTH + DIGEST_LENGTH],
            pruning_segment_commitments: Vec::new(),
            block_height: 0,
        };

        let proof = StarkProof {
            kind: ProofKind::Recursive,
            commitment: String::new(),
            public_inputs: Vec::new(),
            payload: ProofPayload::Recursive(witness),
            trace: ExecutionTrace {
                segments: Vec::new(),
            },
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
        };

        ChainProof::Stwo(proof)
    }

    #[test]
    #[traced_test]
    fn stwo_bypass_accepts_and_logs() {
        let registry = ProofVerifierRegistry::default();
        let proof = dummy_recursive_proof();

        registry
            .verify_recursive(&proof)
            .expect("bypass should accept recursive proof");

        assert!(
            logs_contain("accepting proof via STWO bypass"),
            "expected bypass warning to be emitted"
        );

        let snapshot = registry.metrics_snapshot();
        let stwo_metrics = snapshot
            .per_backend
            .get("stwo")
            .expect("metrics entry for stwo backend");
        assert_eq!(stwo_metrics.accepted, 1);
        assert_eq!(stwo_metrics.bypassed, 1);
        assert_eq!(stwo_metrics.rejected, 0);
    }
}

#[cfg(feature = "prover-stwo")]
fn map_stwo_backend_error(err: crate::proof_backend::BackendError) -> ChainError {
    match err {
        crate::proof_backend::BackendError::Failure(message) => ChainError::Crypto(message),
        crate::proof_backend::BackendError::Unsupported(context) => {
            ChainError::Crypto(format!("STWO backend unsupported: {context}"))
        }
        crate::proof_backend::BackendError::Serialization(err) => {
            ChainError::Crypto(format!("failed to decode STWO proof: {err}"))
        }
    }
}

#[cfg(feature = "prover-stwo")]
fn rebuild_tx_public_inputs(
    parameters: &prover_stwo_backend::official::params::StarkParameters,
    inputs: &TxPublicInputs,
) -> Vec<prover_stwo_backend::official::params::FieldElement> {
    fn digest_chunks(
        parameters: &prover_stwo_backend::official::params::StarkParameters,
        digest: &[u8; 32],
    ) -> Vec<prover_stwo_backend::official::params::FieldElement> {
        digest
            .chunks(8)
            .map(|chunk| parameters.element_from_bytes(chunk))
            .collect()
    }

    let mut fields = digest_chunks(parameters, &inputs.utxo_root);
    fields.extend(digest_chunks(parameters, &inputs.transaction_commitment));
    fields
}

#[cfg(feature = "prover-stwo")]
fn field_to_padded_bytes(value: &prover_stwo_backend::official::params::FieldElement) -> [u8; 32] {
    let repr = value.to_bytes();
    let mut bytes = [0u8; 32];
    let offset = bytes.len().saturating_sub(repr.len());
    bytes[offset..offset + repr.len()].copy_from_slice(&repr);
    bytes
}
