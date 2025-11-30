//! Stateful runtime node coordinating consensus, storage, and external services.
//!
//! The [`Node`] type wraps the chain runtime, orchestrating mempool management,
//! block production, and proof generation. Invariants maintained here include:
//!
//! * The in-memory tip (`ChainTip`) always reflects the latest committed block
//!   stored in [`Storage`].
//! * VRF submissions are validated against the current epoch before they are
//!   admitted to consensus queues.
//! * Side-effectful subsystems (telemetry, gossip, prover tasks) are spawned and
//!   owned by [`NodeHandle`], which ensures graceful shutdown via the async
//!   join handles it tracks.
//!
//! Public status/reporting structs are defined alongside the runtime to expose
//! snapshot views without leaking internal locks.
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Keypair, Signature, SigningKey, Verifier};
use malachite::num::conversion::traits::ToPrimitive;
use malachite::Natural;
use once_cell::sync::OnceCell;
use parking_lot::{Mutex as ParkingMutex, RwLock};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{broadcast, mpsc, watch, Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time;
use tracing::field::display;
use tracing::instrument;
use tracing::Instrument;
use tracing::Span;
use tracing::{debug, error, info, info_span, warn};
use uuid::Uuid;

use blake2::{
    digest::{consts::U32, Digest},
    Blake2b,
};
use hex;
use rpp_wallet_interface::runtime_config::MempoolStatus;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{self, Value};
use sha2::Sha256;

use crate::config::{
    FeatureGates, GenesisAccount, NodeConfig, QueueWeightsConfig, ReleaseChannel, SecretsConfig,
    SnapshotChecksumAlgorithm, SnapshotSigningKey, SnapshotSizingConfig,
    DEFAULT_SNAPSHOT_CHUNK_SIZE,
};
use crate::consensus::messages::compute_consensus_bindings;
use crate::consensus::{
    aggregate_total_stake, build_consensus_witness, classify_participants, evaluate_vrf, BftVote,
    BftVoteKind, ConsensusCertificate, ConsensusRound, EvidenceKind, EvidencePool, EvidenceRecord,
    SignedBftVote, ValidatorCandidate,
};
use crate::crypto::{
    address_from_public_key, load_or_generate_keypair, sign_message, signature_to_hex,
    vrf_public_key_to_hex, VrfKeypair,
};
use crate::errors::{ChainError, ChainResult};
use crate::ledger::{
    EpochInfo, Ledger, ReputationAudit, SlashingEvent, SlashingReason, VrfHistoryRecord,
};
#[cfg(feature = "backend-plonky3")]
use crate::plonky3::circuit::transaction::TransactionWitness as Plonky3TransactionWitness;
#[cfg(feature = "backend-plonky3")]
use crate::plonky3::prover::{
    telemetry_snapshot as plonky3_prover_telemetry, Plonky3BackendHealth,
};
use crate::proof_backend::{
    Blake2sHasher, ConsensusVrfPublicEntry as BackendVrfPublicEntry, ProofBytes,
};
#[cfg(feature = "prover-stwo")]
use crate::proof_backend::{
    ConsensusCircuitDef, PruningCircuitDef, RecursiveCircuitDef, StateCircuitDef, WitnessBytes,
    WitnessHeader,
};
use crate::proof_system::{
    verifier_sla_status, BackendSlaStatus, BackendVerificationMetrics, ProofProver,
    ProofVerifierRegistry, VerifierMetricsSnapshot,
};
use crate::reputation::{Tier, TimetokeParams};
use crate::rpp::{
    GlobalStateCommitments, ModuleWitnessBundle, ProofArtifact, ProofModule, ProofSystemKind,
    TimetokeRecord,
};
use crate::runtime::node_runtime::{
    node::{
        IdentityProfile as RuntimeIdentityProfile, MetaTelemetryReport, NodeError as P2pError,
        NodeRuntimeConfig as P2pRuntimeConfig, TimetokeDeltaBroadcast,
    },
    NodeEvent, NodeHandle as P2pHandle, NodeInner as P2pRuntime, NodeMetrics as P2pMetrics,
};
use crate::runtime::sync::{
    state_sync_chunk_by_index as runtime_state_sync_chunk_by_index,
    stream_state_sync_chunks as runtime_stream_state_sync_chunks, StateSyncServer,
};
use crate::runtime::vrf_gossip::{submission_to_gossip, verify_submission};
use crate::runtime::{
    ProofVerificationBackend, ProofVerificationKind, ProofVerificationOutcome,
    ProofVerificationStage, RuntimeMetrics,
};
use crate::state::lifecycle::StateLifecycle;
use crate::state::merkle::compute_merkle_root;
use crate::storage::{ConsensusRecoveryState, StateTransitionReceipt, Storage};
use crate::stwo::circuit::transaction::TransactionWitness;
use crate::stwo::proof::ProofPayload;
#[cfg(feature = "prover-stwo")]
use crate::stwo::prover::WalletProver;
use crate::sync::{
    invariants::enforce_block_invariants, CheckpointSignatureConfig, PayloadProvider,
    ReconstructionEngine, ReconstructionPlan, StateSyncPlan,
};
use crate::types::serde_pruning_proof;
use crate::types::{
    pruning_from_previous, Account, Address, AttestedIdentityRequest, Block, BlockHeader,
    BlockMetadata, BlockProofBundle, ChainProof, IdentityDeclaration, PruningEnvelopeMetadata,
    PruningProof, PruningProofExt, RecursiveProof, ReputationUpdate, SignedTransaction, Stake,
    TimetokeUpdate, TransactionProofBundle, UptimeProof, IDENTITY_ATTESTATION_GOSSIP_MIN,
    IDENTITY_ATTESTATION_QUORUM,
};
use crate::vrf::{
    self, PoseidonVrfInput, VrfEpochManager, VrfProof, VrfSubmission, VrfSubmissionPool,
    VRF_PROOF_LENGTH,
};
#[cfg(feature = "backend-rpp-stark")]
use crate::zk::rpp_adapter::compute_public_digest;
#[cfg(feature = "backend-rpp-stark")]
use crate::zk::rpp_verifier::RppStarkVerificationReport;
use crate::zk::rpp_verifier::{
    RppStarkSerializationContext, RppStarkVerificationFlags, RppStarkVerifierError,
    RppStarkVerifyFailure,
};
use blake3::Hash;
use libp2p::PeerId;
#[cfg(feature = "prover-stwo")]
use prover_stwo_backend::backend::{
    decode_consensus_proof, decode_pruning_proof, decode_recursive_proof, decode_state_proof,
    StwoBackend,
};
use rpp::node::{
    LightClientVerificationEvent, LightClientVerifier, StateSyncVerificationReport,
    VerificationErrorKind,
};
use rpp_chain::stwo::{params::StarkParameters, FieldElement};
use rpp_p2p::vendor::PeerId as NetworkPeerId;
use rpp_p2p::{
    AllowlistedPeer, GossipTopic, HandshakePayload, LightClientHead, NetworkLightClientUpdate,
    NetworkStateSyncChunk, NetworkStateSyncPlan, NodeIdentity, PipelineError,
    ProofCacheMetricsSnapshot, ResumeBoundKind, SnapshotBreakerStatus, SnapshotChunk,
    SnapshotChunkCapabilities, SnapshotChunkStream, SnapshotItemKind, SnapshotProvider,
    SnapshotProviderHandle, SnapshotResumeState, SnapshotSessionId, SnapshotStore, TierLevel,
    VRF_HANDSHAKE_CONTEXT,
};
use rpp_pruning::{TaggedDigest, SNAPSHOT_STATE_TAG};

const BASE_BLOCK_REWARD: u64 = 5;
const LEADER_BONUS_PERCENT: u8 = 20;
pub const DEFAULT_STATE_SYNC_CHUNK: usize = DEFAULT_SNAPSHOT_CHUNK_SIZE;
const SNAPSHOT_BREAKER_THRESHOLD: u64 = 3;

fn proof_backend(proof: &ChainProof) -> ProofVerificationBackend {
    match proof {
        ChainProof::RppStark(_) => ProofVerificationBackend::RppStark,
        _ => ProofVerificationBackend::Stwo,
    }
}

#[cfg(feature = "backend-rpp-stark")]
const RPP_STARK_PROOF_BUCKETS: [u64; 4] =
    [512 * 1024, 1024 * 1024, 2 * 1024 * 1024, 4 * 1024 * 1024];

#[cfg(feature = "backend-rpp-stark")]
fn proof_size_bucket(bytes: u64) -> &'static str {
    if bytes <= RPP_STARK_PROOF_BUCKETS[0] {
        "le_512_kib"
    } else if bytes <= RPP_STARK_PROOF_BUCKETS[1] {
        "le_1_mib"
    } else if bytes <= RPP_STARK_PROOF_BUCKETS[2] {
        "le_2_mib"
    } else if bytes <= RPP_STARK_PROOF_BUCKETS[3] {
        "le_4_mib"
    } else {
        "gt_4_mib"
    }
}

#[cfg(feature = "backend-rpp-stark")]
#[derive(Clone, Copy)]
struct RppStarkProofSizeSnapshot {
    proof_bytes: u64,
    params_bytes: u64,
    public_inputs_bytes: u64,
    payload_bytes: u64,
    size_bucket: &'static str,
}

#[derive(Clone, Default)]
struct ProofLogLabels {
    peer_id: Option<String>,
    height: Option<u64>,
    slot: Option<u64>,
    proof_id: Option<String>,
    circuit: Option<String>,
}

struct ProofLogLabelValues<'a> {
    peer_id: &'a str,
    height: Option<u64>,
    slot: Option<u64>,
    proof_id: &'a str,
    circuit: &'a str,
}

impl ProofLogLabels {
    fn resolve(&self, proof_kind: ProofVerificationKind) -> ProofLogLabelValues<'_> {
        ProofLogLabelValues {
            peer_id: self.peer_id.as_deref().unwrap_or("unknown"),
            height: self.height,
            slot: self.slot,
            proof_id: self.proof_id.as_deref().unwrap_or("unknown"),
            circuit: self
                .circuit
                .as_deref()
                .unwrap_or_else(|| proof_kind.as_str()),
        }
    }
}

#[cfg(feature = "backend-rpp-stark")]
fn record_rpp_stark_size_metrics(
    proof_metrics: &ProofMetrics,
    backend: ProofVerificationBackend,
    proof_kind: ProofVerificationKind,
    circuit: &str,
    proof: &ChainProof,
    outcome: ProofVerificationOutcome,
) -> Option<RppStarkProofSizeSnapshot> {
    let artifact = proof.expect_rpp_stark().ok()?;
    let params_bytes = u64::try_from(artifact.params_len()).unwrap_or(u64::MAX);
    let public_inputs_bytes = u64::try_from(artifact.public_inputs_len()).unwrap_or(u64::MAX);
    let payload_bytes = u64::try_from(artifact.proof_len()).unwrap_or(u64::MAX);
    let proof_bytes = u64::try_from(artifact.total_len()).unwrap_or(u64::MAX);
    let size_bucket = proof_size_bucket(proof_bytes);

    proof_metrics.observe_verification_total_bytes(backend, proof_kind, circuit, proof_bytes);
    proof_metrics.observe_verification_total_bytes_by_result(
        backend,
        proof_kind,
        circuit,
        outcome,
        proof_bytes,
    );
    proof_metrics.observe_verification_params_bytes(backend, proof_kind, circuit, params_bytes);
    proof_metrics.observe_verification_public_inputs_bytes(
        backend,
        proof_kind,
        circuit,
        public_inputs_bytes,
    );
    proof_metrics.observe_verification_payload_bytes(backend, proof_kind, circuit, payload_bytes);

    Some(RppStarkProofSizeSnapshot {
        proof_bytes,
        params_bytes,
        public_inputs_bytes,
        payload_bytes,
        size_bucket,
    })
}

const PROOF_IO_MARKER: &str = "ProofError::IO";
#[derive(Clone)]
struct ChainTip {
    height: u64,
    last_hash: [u8; 32],
    pruning: Option<PruningEnvelopeMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConsensusLockState {
    height: u64,
    round: u64,
    block_hash: String,
}

#[cfg(not(feature = "backend-plonky3"))]
#[derive(Clone, Debug, Serialize)]
struct BackendProverHealthSnapshot;

#[cfg(feature = "backend-plonky3")]
type BackendProverHealthSnapshot = Plonky3BackendHealth;

const PROVER_ERROR_RATE_BUDGET: f64 = 0.05;

#[cfg(feature = "backend-plonky3")]
fn plonky3_prover_sla(snapshot: &Plonky3BackendHealth) -> BackendSlaStatus {
    let attempts = snapshot
        .proofs_generated
        .saturating_add(snapshot.failed_proofs) as f64;
    let error_rate = if attempts > 0.0 {
        Some(snapshot.failed_proofs as f64 / attempts)
    } else {
        None
    };

    BackendSlaStatus::new(None, error_rate, None, Some(PROVER_ERROR_RATE_BUDGET))
}

#[derive(Clone, Debug, Serialize)]
pub struct BackendHealthReport {
    pub verifier: BackendVerificationMetrics,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prover: Option<BackendProverHealthSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_sla: Option<BackendSlaStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prover_sla: Option<BackendSlaStatus>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeStatus {
    pub address: Address,
    pub height: u64,
    pub last_hash: String,
    pub epoch: u64,
    pub epoch_nonce: String,
    pub pending_block_proposals: usize,
    pub pending_transactions: usize,
    pub pending_identities: usize,
    pub pending_votes: usize,
    pub pending_uptime_proofs: usize,
    pub vrf_metrics: crate::vrf::VrfSelectionMetrics,
    pub tip: Option<BlockMetadata>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub backend_health: BTreeMap<String, BackendHealthReport>,
}

#[derive(Clone, Debug, Serialize)]
pub struct P2pCensorshipEntry {
    pub peer: String,
    pub vote_timeouts: u64,
    pub proof_relay_misses: u64,
    pub gossip_backpressure_events: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct P2pCensorshipReport {
    pub entries: Vec<P2pCensorshipEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingTransactionSummary {
    pub hash: String,
    pub from: Address,
    pub to: Address,
    pub amount: u128,
    pub fee: u64,
    pub nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<ChainProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<TransactionWitness>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_payload: Option<ProofPayload>,
    #[cfg(feature = "backend-rpp-stark")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_inputs_digest: Option<String>,
}

#[derive(Clone, Debug)]
struct PendingTransactionMetadata {
    proof: ChainProof,
    witness: Option<TransactionWitness>,
    proof_payload: Option<ProofPayload>,
    #[cfg(feature = "backend-rpp-stark")]
    public_inputs_digest: Option<String>,
    enqueued_at: Instant,
}

impl PendingTransactionMetadata {
    fn from_bundle(bundle: &TransactionProofBundle) -> Self {
        let witness = bundle.witness.clone().or_else(|| {
            bundle
                .proof_payload
                .as_ref()
                .and_then(Self::transaction_witness)
        });
        let proof_payload = bundle
            .proof_payload
            .clone()
            .or_else(|| Self::clone_payload(&bundle.proof));
        #[cfg(feature = "backend-rpp-stark")]
        let public_inputs_digest = match &bundle.proof {
            ChainProof::RppStark(proof) => {
                Some(compute_public_digest(proof.public_inputs()).to_hex())
            }
            _ => None,
        };
        Self {
            proof: bundle.proof.clone(),
            witness,
            proof_payload,
            #[cfg(feature = "backend-rpp-stark")]
            public_inputs_digest,
            enqueued_at: Instant::now(),
        }
    }

    fn transaction_witness(payload: &ProofPayload) -> Option<TransactionWitness> {
        match payload {
            ProofPayload::Transaction(witness) => Some(witness.clone()),
            _ => None,
        }
    }

    fn clone_payload(proof: &ChainProof) -> Option<ProofPayload> {
        match proof {
            ChainProof::Stwo(stark) => Some(stark.payload.clone()),
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => None,
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(_) => None,
        }
    }
}

fn wallet_rpc_flow_span(method: &'static str, wallet: &Address, hash: &str) -> Span {
    info_span!(
        "runtime.wallet.rpc",
        method,
        wallet = %wallet,
        tx_hash = %hash
    )
}

fn proof_operation_span(
    operation: &'static str,
    backend: ProofSystemKind,
    height: Option<u64>,
    block_hash: Option<&str>,
) -> Span {
    let span = info_span!(
        "runtime.proof.operation",
        operation,
        backend = ?backend,
        height = tracing::field::Empty,
        block_hash = tracing::field::Empty
    );
    if let Some(height) = height {
        span.record("height", &height);
    }
    if let Some(block_hash) = block_hash {
        span.record("block_hash", &display(block_hash));
    }
    span
}

fn storage_flush_span(operation: &'static str, height: u64, block_hash: &str) -> Span {
    info_span!(
        "runtime.storage.flush",
        operation,
        height,
        block_hash = %block_hash
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingIdentitySummary {
    pub wallet_addr: Address,
    pub commitment: String,
    pub epoch_nonce: String,
    pub state_root: String,
    pub identity_root: String,
    pub vrf_tag: String,
    pub attested_votes: usize,
    pub gossip_confirmations: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingVoteSummary {
    pub hash: String,
    pub voter: Address,
    pub height: u64,
    pub round: u64,
    pub block_hash: String,
    pub kind: BftVoteKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingUptimeSummary {
    pub identity: Address,
    pub window_start: u64,
    pub window_end: u64,
    pub credited_hours: u64,
}

fn encode_pending_summaries<T>(entries: Vec<T>, label: &'static str) -> ChainResult<Vec<Value>>
where
    T: Serialize,
{
    entries
        .into_iter()
        .map(|entry| {
            serde_json::to_value(entry).map_err(|err| {
                ChainError::Config(format!("failed to encode {label} summary: {err}"))
            })
        })
        .collect()
}

fn decode_pending_summaries<T>(entries: &[Value], label: &'static str) -> ChainResult<Vec<T>>
where
    T: DeserializeOwned,
{
    entries
        .iter()
        .map(|entry| {
            serde_json::from_value(entry.clone()).map_err(|err| {
                ChainError::Config(format!("failed to decode {label} summary: {err}"))
            })
        })
        .collect()
}

pub trait MempoolStatusExt {
    fn decode_transactions(&self) -> ChainResult<Vec<PendingTransactionSummary>>;
    fn decode_identities(&self) -> ChainResult<Vec<PendingIdentitySummary>>;
    fn decode_votes(&self) -> ChainResult<Vec<PendingVoteSummary>>;
    fn decode_uptime_proofs(&self) -> ChainResult<Vec<PendingUptimeSummary>>;
}

impl MempoolStatusExt for MempoolStatus {
    fn decode_transactions(&self) -> ChainResult<Vec<PendingTransactionSummary>> {
        decode_pending_summaries(&self.transactions, "transaction")
    }

    fn decode_identities(&self) -> ChainResult<Vec<PendingIdentitySummary>> {
        decode_pending_summaries(&self.identities, "identity")
    }

    fn decode_votes(&self) -> ChainResult<Vec<PendingVoteSummary>> {
        decode_pending_summaries(&self.votes, "vote")
    }

    fn decode_uptime_proofs(&self) -> ChainResult<Vec<PendingUptimeSummary>> {
        decode_pending_summaries(&self.uptime_proofs, "uptime proof")
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ConsensusStatus {
    pub height: u64,
    pub block_hash: Option<String>,
    pub proposer: Option<Address>,
    pub round: u64,
    pub total_power: String,
    pub quorum_threshold: String,
    pub pre_vote_power: String,
    pub pre_commit_power: String,
    pub commit_power: String,
    pub quorum_reached: bool,
    pub observers: u64,
    pub epoch: u64,
    pub epoch_nonce: String,
    pub pending_votes: usize,
    pub round_latencies_ms: Vec<u64>,
    pub leader_changes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quorum_latency_ms: Option<u64>,
    pub witness_events: u64,
    pub slashing_events: u64,
    pub failed_votes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConsensusProofStatus {
    pub height: u64,
    pub round: u64,
    pub block_hash: String,
    pub total_power: String,
    pub quorum_threshold: String,
    pub prevote_power: String,
    pub precommit_power: String,
    pub commit_power: String,
    pub epoch: u64,
    pub slot: u64,
    pub vrf_entries: Vec<ConsensusProofVrfEntry>,
    pub witness_commitments: Vec<String>,
    pub reputation_roots: Vec<String>,
    pub quorum_bitmap_root: String,
    pub quorum_signature_root: String,
    pub vrf_output: String,
    pub vrf_proof: String,
    pub witness_commitment_root: String,
    pub reputation_root: String,
    pub quorum_bitmap: String,
    pub quorum_signature: String,
}

impl ConsensusProofStatus {
    pub fn legacy_vrf_outputs(&self) -> Vec<String> {
        self.vrf_entries
            .iter()
            .map(|entry| entry.pre_output.clone())
            .collect()
    }

    pub fn legacy_vrf_proofs(&self) -> Vec<String> {
        self.vrf_entries
            .iter()
            .map(|entry| entry.proof.clone())
            .collect()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ConsensusProofVrfEntry {
    pub randomness: String,
    pub pre_output: String,
    pub proof: String,
    pub public_key: String,
    pub poseidon: ConsensusProofVrfPoseidon,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bindings: Option<ConsensusProofVrfBindings>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConsensusProofVrfBindings {
    pub randomness: String,
    pub proof: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConsensusProofVrfPoseidon {
    pub digest: String,
    pub last_block_header: String,
    pub epoch: String,
    pub tier_seed: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct VrfStatus {
    pub address: Address,
    pub epoch: u64,
    pub epoch_nonce: String,
    pub public_key: String,
    pub proof: crate::vrf::VrfProof,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct VrfThresholdStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<String>,
    pub committee_target: usize,
    pub pool_entries: usize,
    pub accepted_validators: usize,
    pub participation_rate: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatorMembershipEntry {
    pub address: Address,
    pub stake: Stake,
    pub reputation_score: f64,
    pub tier: Tier,
    pub timetoke_hours: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObserverMembershipEntry {
    pub address: Address,
    pub tier: Tier,
}

#[derive(Clone, Debug, Serialize)]
pub struct BftMembership {
    pub height: u64,
    pub epoch: u64,
    pub epoch_nonce: String,
    pub validators: Vec<ValidatorMembershipEntry>,
    pub observers: Vec<ObserverMembershipEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockProofArtifactsView {
    pub hash: String,
    pub height: u64,
    #[serde(with = "serde_pruning_proof")]
    pub pruning_proof: PruningProof,
    pub recursive_proof: RecursiveProof,
    pub stark: BlockProofBundle,
    pub module_witnesses: ModuleWitnessBundle,
    pub proof_artifacts: Vec<ProofArtifact>,
    pub consensus_proof: Option<ChainProof>,
    pub pruned: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct TelemetryRuntimeStatus {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub sample_interval_secs: u64,
    pub last_observed_height: Option<u64>,
}

const DEFAULT_PRUNING_SHARD: &str = "primary";
const DEFAULT_PRUNING_PARTITION: &str = "0";
const PRUNING_SHARD_ENV: &str = "RPP_PRUNING_SHARD";
const PRUNING_PARTITION_ENV: &str = "RPP_PRUNING_PARTITION";

#[derive(Clone, Debug, Serialize)]
pub struct RolloutStatus {
    pub release_channel: ReleaseChannel,
    pub feature_gates: FeatureGates,
    pub telemetry: TelemetryRuntimeStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PruningJobStatus {
    pub plan: StateSyncPlan,
    pub missing_heights: Vec<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted_path: Option<String>,
    pub stored_proofs: Vec<u64>,
    pub last_updated: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_time_remaining_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_bytes_written: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_throughput_bytes_per_sec: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct PruningCycleSummary {
    pub status: Option<PruningJobStatus>,
    pub cancelled: bool,
}

impl PruningCycleSummary {
    pub fn completed(status: Option<PruningJobStatus>) -> Self {
        Self {
            status,
            cancelled: false,
        }
    }

    pub fn cancelled(status: Option<PruningJobStatus>) -> Self {
        Self {
            status,
            cancelled: true,
        }
    }
}

impl PruningJobStatus {
    pub fn estimate_time_remaining_ms(&self, cycle_duration: Duration) -> Option<u64> {
        let processed = self.stored_proofs.len() as u64;
        let remaining = self
            .missing_heights
            .len()
            .saturating_sub(self.stored_proofs.len()) as u64;

        if processed == 0 || remaining == 0 {
            return None;
        }

        let per_key_ms = cycle_duration.as_secs_f64() * 1_000.0 / processed as f64;
        let estimate = per_key_ms * remaining as f64;
        if estimate.is_finite() && estimate.is_sign_positive() {
            Some(estimate.round() as u64)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Default)]
struct PruningLogContext {
    checkpoint_id: Option<String>,
    shard: String,
    partition: String,
}

impl PruningLogContext {
    fn new() -> Self {
        Self {
            checkpoint_id: None,
            shard: env::var(PRUNING_SHARD_ENV)
                .unwrap_or_else(|_| DEFAULT_PRUNING_SHARD.to_string()),
            partition: env::var(PRUNING_PARTITION_ENV)
                .unwrap_or_else(|_| DEFAULT_PRUNING_PARTITION.to_string()),
        }
    }

    fn set_checkpoint_id(&mut self, checkpoint_id: impl Into<String>) {
        self.checkpoint_id = Some(checkpoint_id.into());
    }

    fn checkpoint_id(&self) -> &str {
        self.checkpoint_id.as_deref().unwrap_or("uninitialized")
    }
}

fn checkpoint_identifier(snapshot_height: u64, snapshot_hash: &str) -> String {
    format!("snapshot-{snapshot_height}-{snapshot_hash}")
}

fn log_pruning_cycle_start(
    context: &PruningLogContext,
    chunk_size: usize,
    retention_depth: u64,
    snapshot_height: u64,
    tip_height: u64,
    missing_heights: usize,
    chunk_count: usize,
    resume_from_checkpoint: bool,
) {
    info!(
        target = "pruning",
        event = "pruning_cycle_start",
        checkpoint_id = context.checkpoint_id(),
        shard = context.shard.as_str(),
        partition = context.partition.as_str(),
        chunk_size,
        retention_depth,
        snapshot_height,
        tip_height,
        missing_heights,
        chunk_count,
        resume_from_checkpoint,
        "pruning cycle started",
    );
}

fn log_pruning_checkpoint_saved(
    context: &PruningLogContext,
    checkpoint_path: &Path,
    snapshot_height: u64,
) {
    info!(
        target = "pruning",
        event = "pruning_checkpoint_saved",
        checkpoint_id = context.checkpoint_id(),
        shard = context.shard.as_str(),
        partition = context.partition.as_str(),
        snapshot_height,
        ?checkpoint_path,
        "persisted pruning checkpoint",
    );
}

fn log_pruning_batch_complete(
    context: &PruningLogContext,
    batch_index: usize,
    persisted: usize,
    last_height: u64,
) {
    info!(
        target = "pruning",
        event = "pruning_batch_complete",
        checkpoint_id = context.checkpoint_id(),
        shard = context.shard.as_str(),
        partition = context.partition.as_str(),
        batch_index,
        persisted,
        last_height,
        "pruning batch persisted",
    );
}

fn log_pruning_cycle_finished(
    context: &PruningLogContext,
    summary: &PruningCycleSummary,
    elapsed: Duration,
    resume_from_checkpoint: bool,
) {
    let (missing_heights, stored_proofs, persisted_path) = match summary.status.as_ref() {
        Some(status) => (
            status.missing_heights.len(),
            status.stored_proofs.len(),
            status.persisted_path.as_deref(),
        ),
        None => (0, 0, None),
    };

    info!(
        target = "pruning",
        event = "pruning_cycle_finished",
        checkpoint_id = context.checkpoint_id(),
        shard = context.shard.as_str(),
        partition = context.partition.as_str(),
        cancelled = summary.cancelled,
        missing_heights,
        stored_proofs,
        persisted_path,
        elapsed_ms = elapsed.as_millis(),
        resume_from_checkpoint,
        "pruning cycle finished",
    );
}

fn log_pruning_cycle_error(context: &PruningLogContext, err: &ChainError) {
    warn!(
        target = "pruning",
        event = "pruning_cycle_error",
        checkpoint_id = context.checkpoint_id(),
        shard = context.shard.as_str(),
        partition = context.partition.as_str(),
        ?err,
        "pruning cycle failed",
    );
}

#[cfg(test)]
mod pruning_log_tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt;

    struct EnvGuard {
        shard: Option<String>,
        partition: Option<String>,
    }

    impl EnvGuard {
        fn set(shard: &str, partition: &str) -> Self {
            let guard = Self {
                shard: env::var(PRUNING_SHARD_ENV).ok(),
                partition: env::var(PRUNING_PARTITION_ENV).ok(),
            };
            env::set_var(PRUNING_SHARD_ENV, shard);
            env::set_var(PRUNING_PARTITION_ENV, partition);
            guard
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.shard.take() {
                Some(value) => env::set_var(PRUNING_SHARD_ENV, value),
                None => env::remove_var(PRUNING_SHARD_ENV),
            }
            match self.partition.take() {
                Some(value) => env::set_var(PRUNING_PARTITION_ENV, value),
                None => env::remove_var(PRUNING_PARTITION_ENV),
            }
        }
    }

    #[test]
    fn pruning_log_markers_include_identifiers() {
        let _env_guard = EnvGuard::set("ops-shard", "5");
        let mut context = PruningLogContext::new();
        context.set_checkpoint_id("snapshot-42-deadbeef");
        let summary = PruningCycleSummary::cancelled(None);

        let output = capture_logs(|| {
            log_pruning_cycle_start(&context, 4, 128, 42, 90, 12, 3, false);
            log_pruning_checkpoint_saved(&context, Path::new("/var/lib/rpp/snapshot-42.json"), 42);
            log_pruning_batch_complete(&context, 1, 7, 44);
            log_pruning_cycle_finished(&context, &summary, Duration::from_millis(25), false);
            log_pruning_cycle_error(&context, &ChainError::Config("boom".into()));
        });

        assert!(output.contains("event=\"pruning_cycle_start\""));
        assert!(output.contains("event=\"pruning_checkpoint_saved\""));
        assert!(output.contains("event=\"pruning_batch_complete\""));
        assert!(output.contains("event=\"pruning_cycle_finished\""));
        assert!(output.contains("event=\"pruning_cycle_error\""));
        assert!(output.contains("checkpoint_id=\"snapshot-42-deadbeef\""));
        assert!(output.contains("shard=\"ops-shard\""));
        assert!(output.contains("partition=\"5\""));
    }

    #[test]
    fn checkpoint_identifier_format_is_stable() {
        let checkpoint_id = checkpoint_identifier(10, "abc123");

        assert_eq!(checkpoint_id, "snapshot-10-abc123");
    }

    fn capture_logs<F: FnOnce()>(f: F) -> String {
        struct VecWriter(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for VecWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("lock").write(buf)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = buffer.clone();

        let subscriber = fmt()
            .with_writer(move || VecWriter(writer.clone()))
            .with_ansi(false)
            .without_time()
            .finish();

        let _guard = tracing::subscriber::set_default(subscriber);
        f();

        String::from_utf8(buffer.lock().expect("lock").clone()).expect("utf8 logs")
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatorTelemetryView {
    pub rollout: RolloutStatus,
    pub node: NodeStatus,
    pub consensus: ValidatorConsensusTelemetry,
    pub mempool: ValidatorMempoolTelemetry,
    pub timetoke_params: TimetokeParams,
    pub verifier_metrics: VerifierMetricsSnapshot,
    pub pruning: Option<PruningJobStatus>,
    pub vrf_threshold: VrfThresholdStatus,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatorConsensusTelemetry {
    pub height: u64,
    pub round: u64,
    pub pending_votes: usize,
    pub quorum_reached: bool,
    pub leader_changes: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub round_latencies_ms: Vec<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quorum_latency_ms: Option<u64>,
    pub witness_events: u64,
    pub slashing_events: u64,
    pub failed_votes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatorMempoolTelemetry {
    pub transactions: usize,
    pub identities: usize,
    pub votes: usize,
    pub uptime_proofs: usize,
}

impl From<ConsensusStatus> for ValidatorConsensusTelemetry {
    fn from(status: ConsensusStatus) -> Self {
        Self {
            height: status.height,
            round: status.round,
            pending_votes: status.pending_votes,
            quorum_reached: status.quorum_reached,
            leader_changes: status.leader_changes,
            round_latencies_ms: status.round_latencies_ms,
            quorum_latency_ms: status.quorum_latency_ms,
            witness_events: status.witness_events,
            slashing_events: status.slashing_events,
            failed_votes: status.failed_votes,
        }
    }
}

impl From<&NodeStatus> for ValidatorMempoolTelemetry {
    fn from(status: &NodeStatus) -> Self {
        Self {
            transactions: status.pending_transactions,
            identities: status.pending_identities,
            votes: status.pending_votes,
            uptime_proofs: status.pending_uptime_proofs,
        }
    }
}

#[derive(Clone, Debug)]
pub enum PipelineObservation {
    VrfLeadership {
        height: u64,
        round: u64,
        proposer: Address,
        randomness: String,
        block_hash: Option<String>,
    },
    BftFinalised {
        height: u64,
        round: u64,
        block_hash: String,
        commitments: GlobalStateCommitments,
        certificate: ConsensusCertificate,
    },
    FirewoodCommitment {
        height: u64,
        round: u64,
        block_hash: String,
        previous_root: String,
        new_root: String,
        pruning_proof: Option<PruningProof>,
    },
}

const MAX_ROUND_LATENCY_SAMPLES: usize = 32;

#[derive(Clone, Debug, Default, Serialize)]
pub struct ConsensusTelemetrySnapshot {
    pub round_latencies_ms: Vec<u64>,
    pub leader_changes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quorum_latency_ms: Option<u64>,
    pub witness_events: u64,
    pub slashing_events: u64,
    pub failed_votes: u64,
}

#[derive(Default)]
struct ConsensusTelemetryState {
    round_latencies_ms: VecDeque<u64>,
    last_round_started: Option<Instant>,
    last_round_height: Option<u64>,
    last_round_number: Option<u64>,
    leader_changes: u64,
    last_leader: Option<Address>,
    quorum_latency_ms: Option<u64>,
    witness_events: u64,
    slashing_events: u64,
    failed_votes: u64,
    pending_validator_change: Option<ValidatorChangeMarker>,
    proposer_share: Option<ProposerShareState>,
}

#[derive(Clone, Default)]
struct ProposerShareState {
    epoch: u64,
    total_slots: u64,
    backend_totals: HashMap<String, u64>,
    validator_shares: HashMap<(Address, String), ProposerShareStats>,
}

impl ProposerShareState {
    fn new(epoch: u64) -> Self {
        Self {
            epoch,
            total_slots: 0,
            backend_totals: HashMap::new(),
            validator_shares: HashMap::new(),
        }
    }
}

#[derive(Clone, Default)]
struct ProposerShareStats {
    observed_slots: u64,
    expected_weight: f64,
    last_deviation_pct: f64,
}

pub struct ConsensusTelemetry {
    state: ParkingMutex<ConsensusTelemetryState>,
    metrics: Arc<RuntimeMetrics>,
}

#[derive(Clone, Debug)]
struct ValidatorChangeMarker {
    epoch: u64,
    height: u64,
    started: Instant,
}

impl ConsensusTelemetry {
    pub fn new(metrics: Arc<RuntimeMetrics>) -> Self {
        Self {
            state: ParkingMutex::new(ConsensusTelemetryState::default()),
            metrics,
        }
    }

    pub fn record_validator_change(&self, epoch: u64, height: u64) {
        let mut state = self.state.lock();
        state.pending_validator_change = Some(ValidatorChangeMarker {
            epoch,
            height,
            started: Instant::now(),
        });
        drop(state);
        self.metrics.record_validator_set_change(epoch, height);
    }

    pub fn record_round_start(&self, height: u64, round: u64, leader: &Address) {
        let mut state = self.state.lock();
        let leader_changed = state
            .last_leader
            .as_ref()
            .map(|previous| previous != leader)
            .unwrap_or(true);
        if leader_changed {
            state.leader_changes = state.leader_changes.saturating_add(1);
        }
        state.last_leader = Some(leader.clone());
        state.last_round_started = Some(Instant::now());
        state.last_round_height = Some(height);
        state.last_round_number = Some(round);
        state.quorum_latency_ms = None;
        drop(state);

        if leader_changed {
            self.metrics
                .record_consensus_leader_change(height, round, leader.clone());
        }
    }

    pub fn record_quorum(&self, height: u64, round: u64) {
        let (latency_ms, pending_change) = {
            let mut state = self.state.lock();
            if state.last_round_height == Some(height) && state.last_round_number == Some(round) {
                let latency_ms = state
                    .last_round_started
                    .map(|started| started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
                let pending_change = latency_ms
                    .is_some()
                    .then(|| state.pending_validator_change.take())
                    .flatten();
                state.quorum_latency_ms = latency_ms;
                (latency_ms, pending_change)
            } else {
                (None, None)
            }
        };
        if let Some(latency_ms) = latency_ms {
            let latency = Duration::from_millis(latency_ms);
            self.metrics
                .record_consensus_quorum_latency(height, round, latency);
            if let Some(change) = pending_change {
                self.metrics.record_validator_set_quorum_delay(
                    change.epoch,
                    change.height,
                    latency,
                );
            }
        }
    }

    pub fn record_round_end(&self, height: u64, round: u64) {
        let mut state = self.state.lock();
        if state.last_round_height == Some(height) && state.last_round_number == Some(round) {
            if let Some(started) = state.last_round_started.take() {
                let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                if state.round_latencies_ms.len() >= MAX_ROUND_LATENCY_SAMPLES {
                    state.round_latencies_ms.pop_front();
                }
                state.round_latencies_ms.push_back(duration_ms);
                drop(state);
                self.metrics.record_consensus_round_duration(
                    height,
                    round,
                    Duration::from_millis(duration_ms),
                );
                return;
            }
        }
    }

    pub fn record_proposer_observation(
        &self,
        epoch: u64,
        expected_proposer: &Address,
        observed_proposer: &Address,
        backend: ProofVerificationBackend,
        expected_weight: f64,
    ) {
        let mut state = self.state.lock();
        let mut share_state = state
            .proposer_share
            .take()
            .unwrap_or_else(|| ProposerShareState::new(epoch));
        if share_state.epoch != epoch {
            share_state = ProposerShareState::new(epoch);
        }
        share_state.total_slots = share_state.total_slots.saturating_add(1);
        let backend_label = backend.as_str().to_string();
        let backend_total = share_state
            .backend_totals
            .entry(backend_label.clone())
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
        let stats = share_state
            .validator_shares
            .entry((observed_proposer.clone(), backend_label))
            .or_insert_with(ProposerShareStats::default);
        stats.expected_weight = expected_weight;
        stats.observed_slots = stats.observed_slots.saturating_add(1);
        let observed_share = stats.observed_slots as f64 / (*backend_total as f64).max(1.0);
        let deviation_pct = if expected_weight > 0.0 {
            ((observed_share - expected_weight) / expected_weight) * 100.0
        } else {
            0.0
        };
        stats.last_deviation_pct = deviation_pct;
        state.proposer_share = Some(share_state);
        drop(state);

        self.metrics.record_proposer_slot_share(
            expected_proposer,
            observed_proposer,
            backend,
            epoch,
            expected_weight,
            observed_share,
            deviation_pct,
        );
    }

    pub fn record_witness_event<S: Into<String>>(&self, topic: S) {
        let mut state = self.state.lock();
        state.witness_events = state.witness_events.saturating_add(1);
        drop(state);
        self.metrics.record_consensus_witness_event(topic.into());
    }

    pub fn record_slashing<S: Into<String>>(&self, reason: S) {
        let mut state = self.state.lock();
        state.slashing_events = state.slashing_events.saturating_add(1);
        drop(state);
        self.metrics.record_consensus_slashing_event(reason.into());
    }

    pub fn record_failed_vote<S: Into<String>>(&self, reason: S) {
        let mut state = self.state.lock();
        state.failed_votes = state.failed_votes.saturating_add(1);
        drop(state);
        self.metrics.record_consensus_failed_vote(reason.into());
    }

    pub fn snapshot(&self) -> ConsensusTelemetrySnapshot {
        let state = self.state.lock();
        ConsensusTelemetrySnapshot {
            round_latencies_ms: state.round_latencies_ms.iter().copied().collect(),
            leader_changes: state.leader_changes,
            quorum_latency_ms: state.quorum_latency_ms,
            witness_events: state.witness_events,
            slashing_events: state.slashing_events,
            failed_votes: state.failed_votes,
        }
    }
}

struct WitnessChannels {
    blocks: broadcast::Sender<Vec<u8>>,
    votes: broadcast::Sender<Vec<u8>>,
    proofs: broadcast::Sender<Vec<u8>>,
    snapshots: broadcast::Sender<Vec<u8>>,
    meta: broadcast::Sender<Vec<u8>>,
    publisher: ParkingMutex<Option<mpsc::Sender<(GossipTopic, Vec<u8>)>>>,
    backpressure_hook: ParkingMutex<Option<Arc<dyn Fn(GossipTopic, usize) + Send + Sync>>>,
    queue_capacity: usize,
}

impl WitnessChannels {
    fn new(capacity: usize) -> Self {
        let (blocks, _) = broadcast::channel(capacity);
        let (votes, _) = broadcast::channel(capacity);
        let (proofs, _) = broadcast::channel(capacity);
        let (snapshots, _) = broadcast::channel(capacity);
        let (meta, _) = broadcast::channel(capacity);
        Self {
            blocks,
            votes,
            proofs,
            snapshots,
            meta,
            publisher: ParkingMutex::new(None),
            backpressure_hook: ParkingMutex::new(None),
            queue_capacity: capacity,
        }
    }

    fn attach_publisher(&self, publisher: mpsc::Sender<(GossipTopic, Vec<u8>)>) {
        *self.publisher.lock() = Some(publisher);
    }

    fn set_backpressure_hook(&self, hook: Arc<dyn Fn(GossipTopic, usize) + Send + Sync>) {
        *self.backpressure_hook.lock() = Some(hook);
    }

    fn publish_local(&self, topic: GossipTopic, payload: Vec<u8>) {
        self.forward_to_network(topic.clone(), payload.clone());
        self.fanout_local(topic, payload);
    }

    fn ingest_remote(&self, topic: GossipTopic, payload: Vec<u8>) {
        self.fanout_local(topic, payload);
    }

    fn subscribe(&self, topic: GossipTopic) -> broadcast::Receiver<Vec<u8>> {
        match topic {
            GossipTopic::Blocks => self.blocks.subscribe(),
            GossipTopic::Votes => self.votes.subscribe(),
            GossipTopic::Proofs | GossipTopic::WitnessProofs => self.proofs.subscribe(),
            GossipTopic::Snapshots => self.snapshots.subscribe(),
            GossipTopic::Meta | GossipTopic::WitnessMeta => self.meta.subscribe(),
        }
    }

    fn forward_to_network(&self, topic: GossipTopic, payload: Vec<u8>) {
        if let Some(sender) = self.publisher.lock().as_ref() {
            match sender.try_send((topic.clone(), payload)) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    warn!(
                        ?topic,
                        queue_depth = self.queue_capacity,
                        "failed to enqueue witness gossip for publishing"
                    );
                    if let Some(callback) = self.backpressure_hook.lock().as_ref() {
                        callback(topic, self.queue_capacity);
                    }
                }
                Err(TrySendError::Closed(_)) => {
                    warn!(
                        ?topic,
                        "failed to enqueue witness gossip for publishing: channel closed"
                    );
                }
            }
        }
    }

    fn fanout_local(&self, topic: GossipTopic, payload: Vec<u8>) {
        let sender = match topic {
            GossipTopic::Blocks => &self.blocks,
            GossipTopic::Votes => &self.votes,
            GossipTopic::Proofs | GossipTopic::WitnessProofs => &self.proofs,
            GossipTopic::Snapshots => &self.snapshots,
            GossipTopic::Meta | GossipTopic::WitnessMeta => &self.meta,
        };
        let _ = sender.send(payload);
    }
}

pub struct Node {
    inner: Arc<NodeInner>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StateSyncVerificationStatus {
    Idle,
    Verifying,
    Verified,
    Failed,
}

#[derive(Clone, Debug)]
pub struct StateSyncSessionCache {
    report: Option<StateSyncVerificationReport>,
    snapshot_root: Option<Hash>,
    total_chunks: Option<usize>,
    chunk_size: Option<usize>,
    served_chunks: HashSet<u64>,
    last_completed_step: Option<LightClientVerificationEvent>,
    progress_log: Vec<String>,
    snapshot_store: Option<Arc<RwLock<SnapshotStore>>>,
    status: StateSyncVerificationStatus,
    error: Option<String>,
    error_kind: Option<VerificationErrorKind>,
    request_id: Option<String>,
}

impl Default for StateSyncSessionCache {
    fn default() -> Self {
        Self {
            report: None,
            snapshot_root: None,
            total_chunks: None,
            chunk_size: None,
            served_chunks: HashSet::new(),
            last_completed_step: None,
            progress_log: Vec::new(),
            snapshot_store: None,
            status: StateSyncVerificationStatus::Idle,
            error: None,
            error_kind: None,
            request_id: None,
        }
    }
}

impl StateSyncSessionCache {
    fn reset(&mut self) {
        *self = Self::default();
    }

    fn status(&self) -> StateSyncVerificationStatus {
        self.status
    }

    fn snapshot_root(&self) -> Option<Hash> {
        self.snapshot_root
    }

    fn total_chunks(&self) -> Option<usize> {
        self.total_chunks
    }

    fn chunk_size(&self) -> Option<usize> {
        self.chunk_size
    }

    fn configure(
        &mut self,
        chunk_size: Option<usize>,
        total_chunks: Option<usize>,
        root: Option<Hash>,
    ) {
        if let Some(size) = chunk_size {
            let safe_to_update = self.status != StateSyncVerificationStatus::Verifying
                || self.served_chunks.is_empty();
            if self.chunk_size != Some(size) && safe_to_update {
                self.snapshot_store = None;
                self.chunk_size = Some(size);
            }
        }
        if let Some(count) = total_chunks {
            self.total_chunks = Some(count);
        }
        if let Some(root) = root {
            if self.snapshot_root != Some(root) {
                self.snapshot_store = None;
            }
            self.snapshot_root = Some(root);
        }
    }

    fn mark_chunk_served(&mut self, index: u64) -> bool {
        self.served_chunks.insert(index)
    }

    fn set_report(&mut self, report: StateSyncVerificationReport) {
        self.snapshot_store = None;
        if let Some(root_hex) = report.summary.snapshot_root.as_ref() {
            if let Some(root) = Self::decode_snapshot_root(root_hex) {
                self.snapshot_root = Some(root);
            }
        }
        if self.request_id.is_none() {
            self.request_id = report.summary.request_id.clone();
        }
        self.report = Some(report);
    }

    #[cfg(any(test, feature = "integration"))]
    pub fn verified_for_tests(
        snapshot_root: Hash,
        chunk_size: usize,
        total_chunks: usize,
        store: Arc<RwLock<SnapshotStore>>,
    ) -> Self {
        let mut cache = Self::default();
        cache.snapshot_root = Some(snapshot_root);
        cache.chunk_size = Some(chunk_size);
        cache.total_chunks = Some(total_chunks);
        cache.snapshot_store = Some(store);
        cache.status = StateSyncVerificationStatus::Verified;
        cache
    }

    fn set_status(&mut self, status: StateSyncVerificationStatus) {
        self.status = status;
        if status != StateSyncVerificationStatus::Failed {
            self.error = None;
            self.error_kind = None;
        }
    }

    fn record_event(&mut self, event: LightClientVerificationEvent) {
        if let LightClientVerificationEvent::PlanLoaded { chunk_count, .. }
        | LightClientVerificationEvent::PlanIngested { chunk_count, .. } = &event
        {
            self.total_chunks = Some(*chunk_count);
        }

        if let LightClientVerificationEvent::VerificationCompleted { snapshot_root } = &event {
            if let Some(root) = Self::decode_snapshot_root(snapshot_root) {
                self.snapshot_root = Some(root);
            }
        }

        let message = Self::render_event(&event);
        self.progress_log.push(message);
        self.last_completed_step = Some(event);
    }

    fn render_event(event: &LightClientVerificationEvent) -> String {
        match event {
            LightClientVerificationEvent::PlanLoaded {
                snapshot_height,
                chunk_count,
                update_count,
            } => format!(
                "Loaded state sync plan for snapshot height {snapshot_height} with {chunk_count} chunks and {update_count} light client updates"
            ),
            LightClientVerificationEvent::PlanIngested {
                chunk_count,
                update_count,
            } => format!(
                "Ingested plan containing {chunk_count} chunks and {update_count} light client updates"
            ),
            LightClientVerificationEvent::SnapshotMetadataValidated {
                dataset_label,
                state_root,
                state_commitment,
            } => format!(
                "Validated snapshot metadata '{dataset_label}' (state root {state_root}, commitment {state_commitment})"
            ),
            LightClientVerificationEvent::ReceiptsMatched {
                dataset_label,
                snapshot_count,
            } => format!(
                "Matched {snapshot_count} snapshot receipts for dataset '{dataset_label}'"
            ),
            LightClientVerificationEvent::MerkleRootConfirmed {
                start_height,
                end_height,
            } => format!(
                "Confirmed snapshot Merkle roots across blocks {start_height}..={end_height}"
            ),
            LightClientVerificationEvent::RecursiveProofVerified { height } => {
                format!("Verified recursive proof at height {height}")
            }
            LightClientVerificationEvent::VerificationCompleted { snapshot_root } => {
                format!("State sync verification completed for snapshot root {snapshot_root}")
            }
        }
    }

    fn chunk_count_from_events(events: &[LightClientVerificationEvent]) -> Option<usize> {
        events.iter().find_map(|event| match event {
            LightClientVerificationEvent::PlanLoaded { chunk_count, .. }
            | LightClientVerificationEvent::PlanIngested { chunk_count, .. } => Some(*chunk_count),
            _ => None,
        })
    }

    fn decode_snapshot_root(root_hex: &str) -> Option<Hash> {
        match hex::decode(root_hex) {
            Ok(bytes) => match bytes.as_slice().try_into() {
                Ok(array) => Some(Hash::from(array)),
                Err(_) => {
                    warn!(root = %root_hex, "snapshot root must decode to 32 bytes");
                    None
                }
            },
            Err(err) => {
                warn!(%err, root = %root_hex, "unable to decode snapshot root");
                None
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum StateSyncChunkError {
    NoActiveSession,
    ChunkIndexOutOfRange {
        index: u32,
        total: u32,
    },
    ChunkNotFound {
        index: u32,
        reason: String,
    },
    SnapshotRootMismatch {
        expected: Hash,
        actual: Hash,
    },
    ManifestViolation {
        reason: String,
    },
    Io(std::io::Error),
    IoProof {
        index: u32,
        message: String,
    },
    BudgetExceeded {
        budget: &'static str,
        limit: Duration,
        elapsed: Duration,
    },
    Internal(String),
}

const SNAPSHOT_MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
struct SnapshotChunkManifest {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    checksum_algorithm: Option<SnapshotChecksumAlgorithm>,
    #[serde(default)]
    segments: Vec<ManifestSegment>,
}

#[derive(Debug, Deserialize)]
struct ManifestSegment {
    #[serde(rename = "segment_name")]
    name: Option<String>,
    #[serde(default)]
    size_bytes: Option<u64>,
    #[serde(default)]
    checksum: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
}

type Blake2b256 = Blake2b<U32>;

fn resolve_manifest_algorithm(
    manifest_algorithm: Option<SnapshotChecksumAlgorithm>,
    configured_algorithm: SnapshotChecksumAlgorithm,
) -> Result<SnapshotChecksumAlgorithm, SnapshotManifestError> {
    match manifest_algorithm {
        Some(actual) if actual != configured_algorithm => {
            Err(SnapshotManifestError::ChecksumAlgorithmMismatch {
                expected: configured_algorithm,
                actual,
            })
        }
        Some(actual) => Ok(actual),
        None => Ok(configured_algorithm),
    }
}

enum SnapshotChecksumHasher {
    Sha256(Sha256),
    Blake2b(Blake2b256),
}

impl SnapshotChecksumHasher {
    fn new(algorithm: SnapshotChecksumAlgorithm) -> Self {
        match algorithm {
            SnapshotChecksumAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
            SnapshotChecksumAlgorithm::Blake2b => Self::Blake2b(Blake2b256::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            SnapshotChecksumHasher::Sha256(hasher) => hasher.update(bytes),
            SnapshotChecksumHasher::Blake2b(hasher) => hasher.update(bytes),
        }
    }

    fn finalize(self) -> String {
        match self {
            SnapshotChecksumHasher::Sha256(hasher) => hex::encode(hasher.finalize()),
            SnapshotChecksumHasher::Blake2b(hasher) => hex::encode(hasher.finalize()),
        }
    }
}

fn compute_manifest_checksum(
    path: &Path,
    algorithm: SnapshotChecksumAlgorithm,
) -> Result<String, SnapshotManifestError> {
    let mut file = fs::File::open(path).map_err(SnapshotManifestError::Io)?;
    let mut hasher = SnapshotChecksumHasher::new(algorithm);
    let mut buffer = [0u8; 8 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(SnapshotManifestError::Io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hasher.finalize())
}

#[derive(Debug)]
enum SnapshotManifestError {
    VersionMismatch {
        expected: u32,
        actual: u32,
    },
    ChecksumAlgorithmMismatch {
        expected: SnapshotChecksumAlgorithm,
        actual: SnapshotChecksumAlgorithm,
    },
    MissingChunkDirectory(PathBuf),
    MissingChunk {
        name: String,
        path: PathBuf,
    },
    SizeMismatch {
        name: String,
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    ChecksumMismatch {
        name: String,
        path: PathBuf,
        expected: String,
        actual: String,
    },
    Decode(serde_json::Error),
    Io(std::io::Error),
}

#[derive(Debug)]
enum SnapshotPayloadError {
    Io(std::io::Error),
    Manifest(SnapshotManifestError),
    Signature(String),
}

impl From<std::io::Error> for SnapshotPayloadError {
    fn from(err: std::io::Error) -> Self {
        SnapshotPayloadError::Io(err)
    }
}

impl fmt::Display for SnapshotManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotManifestError::MissingChunkDirectory(dir) => {
                write!(f, "snapshot chunk directory missing at {}", dir.display())
            }
            SnapshotManifestError::VersionMismatch { expected, actual } => write!(
                f,
                "snapshot manifest version mismatch (expected {expected}, found {actual})"
            ),
            SnapshotManifestError::ChecksumAlgorithmMismatch { expected, actual } => write!(
                f,
                "snapshot manifest checksum algorithm mismatch (expected {}, found {})",
                expected.as_str(),
                actual.as_str()
            ),
            SnapshotManifestError::MissingChunk { name, path } => {
                write!(f, "snapshot chunk '{name}' missing at {}", path.display())
            }
            SnapshotManifestError::SizeMismatch {
                name,
                path,
                expected,
                actual,
            } => write!(
                f,
                "snapshot chunk '{name}' size mismatch at {} (expected {expected}, found {actual})",
                path.display()
            ),
            SnapshotManifestError::ChecksumMismatch {
                name,
                path,
                expected,
                actual,
            } => write!(
                f,
                "snapshot chunk '{name}' checksum mismatch at {} (expected {expected}, found {actual})",
                path.display()
            ),
            SnapshotManifestError::Decode(err) => {
                write!(f, "snapshot manifest decode failed: {err}")
            }
            SnapshotManifestError::Io(err) => write!(f, "snapshot manifest I/O failed: {err}"),
        }
    }
}

impl fmt::Display for SnapshotPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotPayloadError::Io(err) => write!(f, "{err}"),
            SnapshotPayloadError::Manifest(err) => write!(f, "{err}"),
            SnapshotPayloadError::Signature(err) => write!(f, "{err}"),
        }
    }
}

fn log_manifest_error(manifest_path: &Path, err: &SnapshotManifestError) {
    match err {
        SnapshotManifestError::MissingChunkDirectory(dir) => {
            error!(
                target: "node",
                path = %manifest_path.display(),
                chunk_dir = %dir.display(),
                "snapshot manifest chunk directory missing",
            );
        }
        SnapshotManifestError::VersionMismatch { expected, actual } => {
            error!(
                target: "node",
                path = %manifest_path.display(),
                expected_version = expected,
                actual_version = actual,
                "snapshot manifest version mismatch",
            );
        }
        SnapshotManifestError::ChecksumAlgorithmMismatch { expected, actual } => {
            error!(
                target: "node",
                path = %manifest_path.display(),
                expected_algorithm = %expected.as_str(),
                actual_algorithm = %actual.as_str(),
                "snapshot manifest checksum algorithm mismatch",
            );
        }
        SnapshotManifestError::MissingChunk { name, path } => {
            error!(
                target: "node",
                path = %manifest_path.display(),
                segment = name,
                chunk = %path.display(),
                "snapshot manifest chunk missing",
            );
        }
        SnapshotManifestError::SizeMismatch {
            name,
            path,
            expected,
            actual,
        } => {
            error!(
                target: "node",
                path = %manifest_path.display(),
                segment = name,
                chunk = %path.display(),
                expected_size = expected,
                actual_size = actual,
                "snapshot manifest chunk size mismatch",
            );
        }
        SnapshotManifestError::ChecksumMismatch {
            name,
            path,
            expected,
            actual,
        } => {
            error!(
                target: "node",
                path = %manifest_path.display(),
                segment = name,
                chunk = %path.display(),
                expected_checksum = expected,
                actual_checksum = actual,
                "snapshot manifest chunk checksum mismatch",
            );
        }
        SnapshotManifestError::Decode(err) => {
            error!(
                target: "node",
                path = %manifest_path.display(),
                error = %err,
                "snapshot manifest decode failed",
            );
        }
        SnapshotManifestError::Io(err) => {
            error!(
                target: "node",
                path = %manifest_path.display(),
                error = %err,
                "snapshot manifest I/O failure",
            );
        }
    }
}

fn parse_snapshot_signature(
    raw: &str,
    signature_path: &Path,
) -> Result<(u32, Signature), SnapshotPayloadError> {
    let trimmed = raw.trim();
    let (version_str, encoded_signature) = trimmed.split_once(':').unwrap_or(("0", trimmed));
    let version = version_str.parse::<u32>().map_err(|err| {
        SnapshotPayloadError::Signature(format!(
            "invalid snapshot signature version at {}: {err}",
            signature_path.display()
        ))
    })?;
    let signature_bytes = BASE64.decode(encoded_signature).map_err(|err| {
        SnapshotPayloadError::Signature(format!(
            "invalid snapshot signature encoding at {}: {err}",
            signature_path.display()
        ))
    })?;
    let signature = Signature::from_bytes(&signature_bytes).map_err(|err| {
        SnapshotPayloadError::Signature(format!(
            "invalid snapshot signature bytes at {}: {err}",
            signature_path.display()
        ))
    })?;
    Ok((version, signature))
}

pub(crate) struct NodeInner {
    config: NodeConfig,
    mempool_limit: AtomicUsize,
    pruning_cancelled: AtomicBool,
    queue_weights: RwLock<QueueWeightsConfig>,
    keypair: Keypair,
    vrf_keypair: VrfKeypair,
    timetoke_snapshot_signing_key: SnapshotSigningKey,
    pruning_checkpoint_signatures: CheckpointSignatureConfig,
    p2p_identity: Arc<NodeIdentity>,
    address: Address,
    storage: Storage,
    ledger: Ledger,
    last_epoch: AtomicU64,
    mempool: RwLock<VecDeque<TransactionProofBundle>>,
    pending_transaction_metadata: RwLock<HashMap<String, PendingTransactionMetadata>>,
    identity_mempool: RwLock<VecDeque<AttestedIdentityRequest>>,
    uptime_mempool: RwLock<VecDeque<RecordedUptimeProof>>,
    vrf_mempool: RwLock<VrfSubmissionPool>,
    vrf_epoch: RwLock<VrfEpochManager>,
    chain_tip: RwLock<ChainTip>,
    block_interval: Duration,
    vote_mempool: RwLock<VecDeque<QueuedVote>>,
    proposal_inbox: RwLock<HashMap<(u64, Address), VerifiedProposal>>,
    consensus_rounds: RwLock<HashMap<u64, u64>>,
    consensus_lock: RwLock<Option<ConsensusLockState>>,
    consensus_state: RwLock<ConsensusRecoveryState>,
    evidence_pool: RwLock<EvidencePool>,
    pruning_status: RwLock<Option<PruningJobStatus>>,
    vrf_metrics: RwLock<crate::vrf::VrfSelectionMetrics>,
    vrf_threshold: RwLock<VrfThresholdStatus>,
    verifiers: ProofVerifierRegistry,
    shutdown: broadcast::Sender<()>,
    pipeline_events: broadcast::Sender<PipelineObservation>,
    worker_tasks: Mutex<Vec<JoinHandle<()>>>,
    completion: Notify,
    witness_channels: WitnessChannels,
    p2p_runtime: ParkingMutex<Option<P2pHandle>>,
    consensus_telemetry: Arc<ConsensusTelemetry>,
    audit_exporter: AuditExporter,
    runtime_metrics: Arc<RuntimeMetrics>,
    cache_metrics_checkpoint: ParkingMutex<ProofCacheMetricsSnapshot>,
    state_sync_session: ParkingMutex<StateSyncSessionCache>,
    state_sync_server: OnceCell<Arc<StateSyncServer>>,
    snapshot_breaker: SnapshotCircuitBreaker,
}

#[cfg_attr(not(feature = "prover-stwo"), allow(dead_code))]
struct LocalProofArtifacts {
    bundle: BlockProofBundle,
    consensus_proof: Option<ChainProof>,
    module_witnesses: ModuleWitnessBundle,
    proof_artifacts: Vec<ProofArtifact>,
}

enum FinalizationContext {
    Local(LocalFinalizationContext),
    #[allow(dead_code)]
    External(ExternalFinalizationContext),
}

struct LocalFinalizationContext {
    round: ConsensusRound,
    block_hash: String,
    header: BlockHeader,
    parent_height: u64,
    commitments: GlobalStateCommitments,
    accepted_identities: Vec<AttestedIdentityRequest>,
    transactions: Vec<SignedTransaction>,
    transaction_proofs: Vec<ChainProof>,
    identity_proofs: Vec<ChainProof>,
    uptime_proofs: Vec<UptimeProof>,
    timetoke_updates: Vec<TimetokeUpdate>,
    reputation_updates: Vec<ReputationUpdate>,
    recorded_votes: Vec<SignedBftVote>,
    expected_proposer: Address,
    expected_weight: f64,
    epoch: u64,
}

#[allow(dead_code)]
pub struct ExternalFinalizationContext {
    round: ConsensusRound,
    block: Block,
    previous_block: Option<Block>,
    archived_votes: Vec<SignedBftVote>,
    peer_id: Option<NetworkPeerId>,
    expected_proposer: Address,
    expected_weight: f64,
    epoch: u64,
}

pub enum FinalizationOutcome {
    Sealed { block: Block, tip_height: u64 },
    AwaitingQuorum,
}

#[derive(Clone)]
pub struct NodeHandle {
    inner: Arc<NodeInner>,
}

#[derive(Clone, Debug, Clone, Debug)]
struct RuntimeSnapshotSession {
    plan: NetworkStateSyncPlan,
    updates: Vec<NetworkLightClientUpdate>,
    snapshot_root: Hash,
    plan_id: String,
    peer: NetworkPeerId,
    chunk_size: u64,
    min_chunk_size: u64,
    max_chunk_size: u64,
    total_chunks: u64,
    total_updates: u64,
    last_chunk_index: Option<u64>,
    last_update_index: Option<u64>,
    confirmed_chunk_index: Option<u64>,
    confirmed_update_index: Option<u64>,
}

impl RuntimeSnapshotSession {
    fn to_stored(&self, session_id: SnapshotSessionId) -> StoredSnapshotSession {
        StoredSnapshotSession {
            session: session_id.get(),
            peer: self.peer.to_base58(),
            root: self.snapshot_root.to_hex().to_string(),
            plan_id: Some(self.plan_id.clone()),
            chunk_size: Some(self.chunk_size),
            min_chunk_size: Some(self.min_chunk_size),
            max_chunk_size: Some(self.max_chunk_size),
            total_chunks: self.total_chunks,
            total_updates: self.total_updates,
            last_chunk_index: self.last_chunk_index,
            last_update_index: self.last_update_index,
            confirmed_chunk_index: self.confirmed_chunk_index,
            confirmed_update_index: self.confirmed_update_index,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredSnapshotSession {
    session: u64,
    peer: String,
    root: String,
    #[serde(default)]
    plan_id: Option<String>,
    #[serde(default)]
    chunk_size: Option<u64>,
    #[serde(default)]
    min_chunk_size: Option<u64>,
    #[serde(default)]
    max_chunk_size: Option<u64>,
    total_chunks: u64,
    total_updates: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_chunk_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_update_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    confirmed_chunk_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    confirmed_update_index: Option<u64>,
}

#[derive(Debug)]
struct SnapshotSessionStore {
    path: PathBuf,
    sessions: ParkingMutex<HashMap<SnapshotSessionId, StoredSnapshotSession>>,
}

impl SnapshotSessionStore {
    fn open(path: PathBuf) -> Result<Self, PipelineError> {
        if let Some(parent) = path.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                return Err(PipelineError::Persistence(err.to_string()));
            }
        }

        let sessions = if path.exists() {
            match fs::read(&path) {
                Ok(bytes) => {
                    if bytes.is_empty() {
                        HashMap::new()
                    } else {
                        match serde_json::from_slice::<Vec<StoredSnapshotSession>>(&bytes) {
                            Ok(records) => records
                                .into_iter()
                                .filter_map(|record| {
                                    Some((SnapshotSessionId::new(record.session), record))
                                })
                                .collect(),
                            Err(err) => return Err(PipelineError::Persistence(err.to_string())),
                        }
                    }
                }
                Err(err) if err.kind() == ErrorKind::NotFound => HashMap::new(),
                Err(err) => return Err(PipelineError::Persistence(err.to_string())),
            }
        } else {
            HashMap::new()
        };

        Ok(Self {
            path,
            sessions: ParkingMutex::new(sessions),
        })
    }

    fn records(&self) -> HashMap<SnapshotSessionId, StoredSnapshotSession> {
        self.sessions.lock().clone()
    }

    fn upsert(
        &self,
        session_id: SnapshotSessionId,
        record: StoredSnapshotSession,
    ) -> Result<(), PipelineError> {
        let mut sessions = self.sessions.lock();
        sessions.insert(session_id, record);
        self.persist_locked(&sessions)
    }

    fn remove(&self, session_id: SnapshotSessionId) -> Result<(), PipelineError> {
        let mut sessions = self.sessions.lock();
        sessions.remove(&session_id);
        self.persist_locked(&sessions)
    }

    fn persist_locked(
        &self,
        sessions: &HashMap<SnapshotSessionId, StoredSnapshotSession>,
    ) -> Result<(), PipelineError> {
        let mut records: Vec<StoredSnapshotSession> = sessions
            .iter()
            .map(|(session_id, record)| StoredSnapshotSession {
                session: session_id.get(),
                peer: record.peer.clone(),
                root: record.root.clone(),
                plan_id: record.plan_id.clone(),
                chunk_size: record.chunk_size,
                min_chunk_size: record.min_chunk_size,
                max_chunk_size: record.max_chunk_size,
                total_chunks: record.total_chunks,
                total_updates: record.total_updates,
                last_chunk_index: record.last_chunk_index,
                last_update_index: record.last_update_index,
                confirmed_chunk_index: record.confirmed_chunk_index,
                confirmed_update_index: record.confirmed_update_index,
            })
            .collect();
        records.sort_by_key(|record| record.session);
        let encoded = serde_json::to_vec_pretty(&records)
            .map_err(|err| PipelineError::Persistence(err.to_string()))?;
        fs::write(&self.path, encoded).map_err(|err| PipelineError::Persistence(err.to_string()))
    }
}

#[derive(Clone, Debug)]
struct SnapshotCircuitBreaker {
    threshold: u64,
    state: Arc<ParkingMutex<SnapshotCircuitState>>,
}

#[derive(Clone, Debug, Default)]
struct SnapshotCircuitState {
    consecutive_failures: u64,
    open: bool,
    last_error: Option<String>,
}

impl SnapshotCircuitBreaker {
    fn new(threshold: u64) -> Self {
        Self {
            threshold,
            state: Arc::new(ParkingMutex::new(SnapshotCircuitState::default())),
        }
    }

    fn guard(&self) -> Result<(), PipelineError> {
        let state = self.state.lock();
        if state.open {
            let last_error = state
                .last_error
                .clone()
                .unwrap_or_else(|| "unknown error".to_string());
            return Err(PipelineError::SnapshotVerification(format!(
                "snapshot serving circuit open after {} failures: {last_error}",
                state.consecutive_failures
            )));
        }

        Ok(())
    }

    fn record_success(&self) {
        let mut state = self.state.lock();
        if state.open {
            return;
        }
        state.consecutive_failures = 0;
    }

    fn record_failure(&self, error: PipelineError) -> PipelineError {
        let message = error.to_string();
        let mut state = self.state.lock();
        state.last_error = Some(message);
        if !state.open {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            if state.consecutive_failures >= self.threshold {
                state.open = true;
            }
        }

        if state.open {
            let last_error = state
                .last_error
                .clone()
                .unwrap_or_else(|| "unknown error".to_string());
            return PipelineError::SnapshotVerification(format!(
                "snapshot serving circuit open after {} failures: {last_error}",
                state.consecutive_failures
            ));
        }

        error
    }

    fn status(&self) -> SnapshotBreakerStatus {
        let state = self.state.lock();
        SnapshotBreakerStatus {
            open: state.open,
            consecutive_failures: state.consecutive_failures,
            last_error: state.last_error.clone(),
        }
    }

    fn reset(&self) {
        let mut state = self.state.lock();
        *state = SnapshotCircuitState::default();
    }
}

struct RuntimeSnapshotProvider {
    inner: Arc<NodeInner>,
    sizing: SnapshotSizingConfig,
    sessions: ParkingMutex<HashMap<SnapshotSessionId, RuntimeSnapshotSession>>,
    snapshots: RwLock<SnapshotStore>,
    session_store: Arc<SnapshotSessionStore>,
    session_peers: ParkingMutex<HashMap<SnapshotSessionId, NetworkPeerId>>,
    breaker: SnapshotCircuitBreaker,
}

impl RuntimeSnapshotProvider {
    fn build(
        inner: Arc<NodeInner>,
        sizing: SnapshotSizingConfig,
        breaker: SnapshotCircuitBreaker,
    ) -> Arc<Self> {
        let store_path = inner.config.snapshot_dir.join("snapshot_sessions.json");
        let chunk_size = sizing.default_chunk_size;
        let (store, persisted) = match SnapshotSessionStore::open(store_path.clone()) {
            Ok(store) => {
                let records = store.records();
                (Arc::new(store), records)
            }
            Err(err) => {
                warn!(
                    target: "node",
                    path = %store_path.display(),
                    %err,
                    "failed to open snapshot session store"
                );
                (
                    Arc::new(SnapshotSessionStore {
                        path: store_path,
                        sessions: ParkingMutex::new(HashMap::new()),
                    }),
                    HashMap::new(),
                )
            }
        };

        let mut restored_sessions = HashMap::new();
        for (session_id, record) in persisted {
            match Self::restore_session(&inner, &sizing, &record) {
                Ok(session) => {
                    restored_sessions.insert(session_id, session);
                }
                Err(err) => {
                    warn!(
                        target: "node",
                        session = session_id.get(),
                        %err,
                        "failed to restore snapshot session"
                    );
                    let _ = store.remove(session_id);
                }
            }
        }

        let peers = restored_sessions
            .iter()
            .map(|(id, session)| (*id, session.peer.clone()))
            .collect();

        Arc::new(Self {
            inner,
            sizing,
            sessions: ParkingMutex::new(restored_sessions),
            snapshots: RwLock::new(SnapshotStore::new(chunk_size)),
            session_store: store,
            session_peers: ParkingMutex::new(peers),
            breaker,
        })
    }

    fn new(
        inner: Arc<NodeInner>,
        sizing: SnapshotSizingConfig,
        breaker: SnapshotCircuitBreaker,
    ) -> SnapshotProviderHandle {
        Self::build(inner, sizing, breaker) as SnapshotProviderHandle
    }

    #[cfg(test)]
    fn new_arc(
        inner: Arc<NodeInner>,
        sizing: SnapshotSizingConfig,
        breaker: SnapshotCircuitBreaker,
    ) -> Arc<Self> {
        Self::build(inner, sizing, breaker)
    }

    fn decode_root(plan: &NetworkStateSyncPlan) -> Result<Hash, PipelineError> {
        let root = plan.snapshot.commitments.global_state_root.clone();
        let bytes = hex::decode(&root).map_err(|err| {
            PipelineError::SnapshotVerification(format!(
                "invalid snapshot root encoding '{root}': {err}"
            ))
        })?;
        let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            PipelineError::SnapshotVerification(format!(
                "snapshot root must encode 32 bytes, received {}",
                bytes.len()
            ))
        })?;
        Ok(Hash::from_bytes(array))
    }

    fn decode_root_str(root: &str) -> Result<Hash, PipelineError> {
        let bytes = hex::decode(root)
            .map_err(|err| PipelineError::Persistence(format!("invalid snapshot root: {err}")))?;
        let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            PipelineError::Persistence("snapshot root must decode to 32 bytes".into())
        })?;
        Ok(Hash::from_bytes(array))
    }

    fn persist_session(
        &self,
        session_id: SnapshotSessionId,
        session: &RuntimeSnapshotSession,
    ) -> Result<(), PipelineError> {
        let record = session.to_stored(session_id);
        self.session_store.upsert(session_id, record)
    }

    fn restore_session(
        inner: &Arc<NodeInner>,
        sizing: &SnapshotSizingConfig,
        record: &StoredSnapshotSession,
    ) -> Result<RuntimeSnapshotSession, PipelineError> {
        let peer = NetworkPeerId::from_str(&record.peer)
            .map_err(|err| PipelineError::Persistence(format!("invalid peer id: {err}")))?;
        let snapshot_root = Self::decode_root_str(&record.root)?;
        let plan_id = record
            .plan_id
            .clone()
            .unwrap_or_else(|| record.root.clone());

        let chunk_size = record
            .chunk_size
            .unwrap_or(sizing.default_chunk_size as u64)
            .clamp(sizing.min_chunk_size as u64, sizing.max_chunk_size as u64);
        let min_chunk_size = record
            .min_chunk_size
            .unwrap_or(sizing.min_chunk_size as u64);
        let max_chunk_size = record
            .max_chunk_size
            .unwrap_or(sizing.max_chunk_size as u64);

        let state_plan = inner
            .state_sync_plan(sizing.default_chunk_size)
            .map_err(|err| PipelineError::SnapshotVerification(err.to_string()))?;
        let network_plan = state_plan
            .to_network_plan()
            .map_err(|err| PipelineError::SnapshotVerification(err.to_string()))?;
        let updates = state_plan
            .light_client_messages()
            .map_err(|err| PipelineError::SnapshotVerification(err.to_string()))?;
        let computed_root = Self::decode_root(&network_plan)?;
        if computed_root != snapshot_root {
            return Err(PipelineError::SnapshotVerification(
                "persisted snapshot root does not match regenerated plan".into(),
            ));
        }

        let plan_total_chunks = u64::try_from(network_plan.chunks.len())
            .map_err(|_| PipelineError::SnapshotVerification("chunk count overflow".into()))?;
        let plan_total_updates = u64::try_from(updates.len())
            .map_err(|_| PipelineError::SnapshotVerification("update count overflow".into()))?;

        let total_chunks = if record.total_chunks == 0 {
            plan_total_chunks
        } else if record.total_chunks > plan_total_chunks {
            return Err(PipelineError::SnapshotVerification(format!(
                "persisted chunk total {} exceeds regenerated plan {plan_total_chunks}",
                record.total_chunks
            )));
        } else {
            record.total_chunks
        };

        let total_updates = if record.total_updates == 0 {
            plan_total_updates
        } else if record.total_updates > plan_total_updates {
            return Err(PipelineError::SnapshotVerification(format!(
                "persisted update total {} exceeds regenerated plan {plan_total_updates}",
                record.total_updates
            )));
        } else {
            record.total_updates
        };

        let last_chunk_index = if total_chunks == 0 {
            None
        } else {
            record
                .last_chunk_index
                .filter(|index| *index < total_chunks)
        };
        let last_update_index = if total_updates == 0 {
            None
        } else {
            record
                .last_update_index
                .filter(|index| *index < total_updates)
        };
        let confirmed_chunk_index = if total_chunks == 0 {
            None
        } else {
            record
                .confirmed_chunk_index
                .filter(|index| *index < total_chunks)
        };
        let confirmed_update_index = if total_updates == 0 {
            None
        } else {
            record
                .confirmed_update_index
                .filter(|index| *index < total_updates)
        };

        Ok(RuntimeSnapshotSession {
            plan: network_plan,
            updates,
            snapshot_root,
            plan_id,
            peer,
            chunk_size,
            min_chunk_size,
            max_chunk_size,
            total_chunks,
            total_updates,
            last_chunk_index,
            last_update_index,
            confirmed_chunk_index,
            confirmed_update_index,
        })
    }
}

impl SnapshotProvider for RuntimeSnapshotProvider {
    type Error = PipelineError;

    fn open_session(
        &self,
        session_id: SnapshotSessionId,
        peer: &NetworkPeerId,
    ) -> Result<(), Self::Error> {
        self.breaker.guard()?;

        let result: Result<(), PipelineError> = (|| {
            {
                let mut peers = self.session_peers.lock();
                peers.insert(session_id, peer.clone());
            }
            let mut sessions = self.sessions.lock();
            if let Some(session) = sessions.get_mut(&session_id) {
                if session.peer != *peer {
                    session.peer = peer.clone();
                    self.persist_session(session_id, session)?;
                }
            }
            Ok(())
        })();

        match result {
            Ok(()) => {
                self.breaker.record_success();
                Ok(())
            }
            Err(err) => Err(self.breaker.record_failure(err)),
        }
    }

    fn fetch_plan(
        &self,
        session_id: SnapshotSessionId,
    ) -> Result<NetworkStateSyncPlan, Self::Error> {
        self.breaker.guard()?;

        let result: Result<NetworkStateSyncPlan, PipelineError> = (|| {
            let state_plan = self
                .inner
                .state_sync_plan(self.sizing.default_chunk_size)
                .map_err(|err| {
                    PipelineError::SnapshotVerification(format!(
                        "failed to build state sync plan: {err}"
                    ))
                })?;
            let mut network_plan = state_plan.to_network_plan().map_err(|err| {
                PipelineError::SnapshotVerification(format!(
                    "failed to encode state sync plan: {err}"
                ))
            })?;
            network_plan.max_concurrent_requests =
                self.chunk_capabilities().max_concurrent_requests;
            let updates = state_plan.light_client_messages().map_err(|err| {
                PipelineError::SnapshotVerification(format!(
                    "failed to encode light client updates: {err}"
                ))
            })?;
            let snapshot_root = Self::decode_root(&network_plan)?;
            let plan_id = network_plan.snapshot.commitments.global_state_root.clone();
            let total_chunks = u64::try_from(network_plan.chunks.len())
                .map_err(|_| PipelineError::SnapshotVerification("chunk count overflow".into()))?;
            let total_updates = u64::try_from(updates.len())
                .map_err(|_| PipelineError::SnapshotVerification("update count overflow".into()))?;
            let peer = {
                let peers = self.session_peers.lock();
                peers.get(&session_id).cloned().ok_or_else(|| {
                    PipelineError::SnapshotVerification("unknown snapshot session peer".into())
                })?
            };

            let mut sessions = self.sessions.lock();
            let session = sessions
                .entry(session_id)
                .or_insert_with(|| RuntimeSnapshotSession {
                    plan: network_plan.clone(),
                    updates: updates.clone(),
                    snapshot_root,
                    plan_id: plan_id.clone(),
                    peer: peer.clone(),
                    chunk_size: self.sizing.default_chunk_size as u64,
                    min_chunk_size: self.sizing.min_chunk_size as u64,
                    max_chunk_size: self.sizing.max_chunk_size as u64,
                    total_chunks,
                    total_updates,
                    last_chunk_index: None,
                    last_update_index: None,
                    confirmed_chunk_index: None,
                    confirmed_update_index: None,
                });
            session.plan = network_plan.clone();
            session.updates = updates.clone();
            session.snapshot_root = snapshot_root;
            session.plan_id = plan_id;
            session.peer = peer;
            session.chunk_size = session.chunk_size.clamp(
                self.sizing.min_chunk_size as u64,
                self.sizing.max_chunk_size as u64,
            );
            session.min_chunk_size = self.sizing.min_chunk_size as u64;
            session.max_chunk_size = self.sizing.max_chunk_size as u64;
            session.total_chunks = total_chunks;
            session.total_updates = total_updates;
            session.last_chunk_index = if total_chunks == 0 {
                None
            } else {
                session.last_chunk_index.and_then(|index| {
                    if index < total_chunks {
                        Some(index)
                    } else {
                        total_chunks.checked_sub(1)
                    }
                })
            };
            session.last_update_index = if total_updates == 0 {
                None
            } else {
                session.last_update_index.and_then(|index| {
                    if index < total_updates {
                        Some(index)
                    } else {
                        total_updates.checked_sub(1)
                    }
                })
            };
            session.confirmed_chunk_index = if total_chunks == 0 {
                None
            } else {
                session.confirmed_chunk_index.and_then(|index| {
                    if index < total_chunks {
                        Some(index)
                    } else {
                        total_chunks.checked_sub(1)
                    }
                })
            };
            session.confirmed_update_index = if total_updates == 0 {
                None
            } else {
                session.confirmed_update_index.and_then(|index| {
                    if index < total_updates {
                        Some(index)
                    } else {
                        total_updates.checked_sub(1)
                    }
                })
            };
            self.persist_session(session_id, session)?;
            Ok(network_plan)
        })();

        match result {
            Ok(plan) => {
                self.breaker.record_success();
                Ok(plan)
            }
            Err(err) => Err(self.breaker.record_failure(err)),
        }
    }

    fn fetch_chunk(
        &self,
        session_id: SnapshotSessionId,
        chunk_index: u64,
    ) -> Result<SnapshotChunk, Self::Error> {
        self.breaker.guard()?;

        let result: Result<SnapshotChunk, PipelineError> = (|| {
            let snapshot_root = {
                let sessions = self.sessions.lock();
                let session = sessions
                    .get(&session_id)
                    .ok_or(PipelineError::SnapshotNotFound)?;
                session.snapshot_root
            };
            let store = self.snapshots.read();
            let stream = self
                .inner
                .stream_state_sync_chunks(&*store, &snapshot_root)
                .map_err(|err| {
                    PipelineError::SnapshotVerification(format!(
                        "failed to stream state sync chunks: {err}"
                    ))
                })?;
            let total = stream.total();
            if chunk_index >= total {
                return Err(PipelineError::SnapshotVerification(format!(
                    "state sync chunk {chunk_index} out of range (total {total})"
                )));
            }
            let chunk = self
                .inner
                .state_sync_chunk_by_index(&*store, &snapshot_root, chunk_index)
                .map_err(|err| {
                    PipelineError::SnapshotVerification(format!(
                        "failed to fetch state sync chunk {chunk_index}: {err}"
                    ))
                })?;

            {
                let mut sessions = self.sessions.lock();
                let session = sessions
                    .get_mut(&session_id)
                    .ok_or(PipelineError::SnapshotNotFound)?;
                let updated = session
                    .last_chunk_index
                    .map(|current| current.max(chunk_index))
                    .or(Some(chunk_index));
                session.last_chunk_index = updated;
                self.persist_session(session_id, session)?;
            }

            Ok(chunk)
        })();

        match result {
            Ok(chunk) => {
                self.breaker.record_success();
                Ok(chunk)
            }
            Err(err) => Err(self.breaker.record_failure(err)),
        }
    }

    fn fetch_update(
        &self,
        session_id: SnapshotSessionId,
        update_index: u64,
    ) -> Result<NetworkLightClientUpdate, Self::Error> {
        self.breaker.guard()?;

        let result: Result<NetworkLightClientUpdate, PipelineError> = (|| {
            let index = usize::try_from(update_index).map_err(|_| {
                PipelineError::SnapshotVerification(format!(
                    "light client update index {update_index} exceeds addressable range"
                ))
            })?;
            let sessions = self.sessions.lock();
            let session = sessions
                .get(&session_id)
                .ok_or(PipelineError::SnapshotNotFound)?;
            let update = session.updates.get(index).cloned().ok_or_else(|| {
                PipelineError::SnapshotVerification(format!(
                    "light client update index {update_index} out of range (total {})",
                    session.updates.len()
                ))
            })?;
            let updated = session
                .last_update_index
                .map(|current| current.max(update_index))
                .or(Some(update_index));
            session.last_update_index = updated;
            self.persist_session(session_id, session)?;
            Ok(update)
        })();

        match result {
            Ok(update) => {
                self.breaker.record_success();
                Ok(update)
            }
            Err(err) => Err(self.breaker.record_failure(err)),
        }
    }

    fn resume_session(
        &self,
        session_id: SnapshotSessionId,
        plan_id: &str,
        chunk_index: u64,
        update_index: u64,
        chunk_size: Option<u64>,
        min_chunk_size: Option<u64>,
        max_chunk_size: Option<u64>,
    ) -> Result<SnapshotResumeState, Self::Error> {
        self.breaker.guard()?;

        let result: Result<SnapshotResumeState, PipelineError> = (|| {
            let sessions = self.sessions.lock();
            let session = sessions
                .get(&session_id)
                .ok_or(PipelineError::SnapshotNotFound)?;
            if session.plan_id != plan_id {
                return Err(PipelineError::SnapshotVerification(format!(
                    "resume plan id {plan_id} does not match persisted plan {}",
                    session.plan_id
                )));
            }
            if chunk_index > session.total_chunks {
                return Err(PipelineError::ResumeBoundsExceeded {
                    kind: ResumeBoundKind::Chunk,
                    requested: chunk_index,
                    total: session.total_chunks,
                });
            }
            if update_index > session.total_updates {
                return Err(PipelineError::ResumeBoundsExceeded {
                    kind: ResumeBoundKind::Update,
                    requested: update_index,
                    total: session.total_updates,
                });
            }
            let expected_chunk_index = session
                .confirmed_chunk_index
                .or(session.last_chunk_index)
                .map(|index| index.saturating_add(1).min(session.total_chunks))
                .unwrap_or(0);
            if chunk_index < expected_chunk_index {
                return Err(PipelineError::SnapshotVerification(format!(
                    "resume chunk index {chunk_index} precedes next expected chunk {expected_chunk_index}"
                )));
            }
            if chunk_index > expected_chunk_index {
                return Err(PipelineError::SnapshotVerification(format!(
                    "resume chunk index {chunk_index} skips ahead of next expected chunk {expected_chunk_index}"
                )));
            }
            let expected_update_index = session
                .confirmed_update_index
                .or(session.last_update_index)
                .map(|index| index.saturating_add(1).min(session.total_updates))
                .unwrap_or(0);
            if update_index < expected_update_index {
                return Err(PipelineError::SnapshotVerification(format!(
                    "resume update index {update_index} precedes next expected update {expected_update_index}"
                )));
            }
            if update_index > expected_update_index {
                return Err(PipelineError::SnapshotVerification(format!(
                    "resume update index {update_index} skips ahead of next expected update {expected_update_index}"
                )));
            }
            drop(sessions);

            let mut sessions = self.sessions.lock();
            let session = sessions
                .get_mut(&session_id)
                .ok_or(PipelineError::SnapshotNotFound)?;
            let resolved_chunk_size = chunk_size.unwrap_or(session.chunk_size);
            let resolved_min_chunk_size = min_chunk_size.unwrap_or(session.min_chunk_size);
            let resolved_max_chunk_size = max_chunk_size.unwrap_or(session.max_chunk_size);
            session.chunk_size = resolved_chunk_size.clamp(
                self.sizing.min_chunk_size as u64,
                self.sizing.max_chunk_size as u64,
            );
            session.min_chunk_size = resolved_min_chunk_size;
            session.max_chunk_size = resolved_max_chunk_size;
            self.persist_session(session_id, session)?;
            Ok(SnapshotResumeState {
                next_chunk_index: chunk_index,
                next_update_index: update_index,
            })
        })();

        match result {
            Ok(state) => {
                self.breaker.record_success();
                Ok(state)
            }
            Err(err) => Err(self.breaker.record_failure(err)),
        }
    }

    fn acknowledge(
        &self,
        session_id: SnapshotSessionId,
        kind: SnapshotItemKind,
        index: u64,
    ) -> Result<(), Self::Error> {
        self.breaker.guard()?;

        let result: Result<(), PipelineError> = (|| {
            let mut sessions = self.sessions.lock();
            let session = sessions
                .get_mut(&session_id)
                .ok_or(PipelineError::SnapshotNotFound)?;
            match kind {
                SnapshotItemKind::Chunk => {
                    if index >= session.total_chunks {
                        return Err(PipelineError::SnapshotVerification(format!(
                            "acknowledged chunk index {index} exceeds total {}",
                            session.total_chunks
                        )));
                    }
                    let updated = session
                        .last_chunk_index
                        .map(|current| current.max(index))
                        .or(Some(index));
                    session.last_chunk_index = updated;
                    let confirmed = session
                        .confirmed_chunk_index
                        .map(|current| current.max(index))
                        .or(Some(index));
                    session.confirmed_chunk_index = confirmed;
                }
                SnapshotItemKind::LightClientUpdate => {
                    if index >= session.total_updates {
                        return Err(PipelineError::SnapshotVerification(format!(
                            "acknowledged update index {index} exceeds total {}",
                            session.total_updates
                        )));
                    }
                    let updated = session
                        .last_update_index
                        .map(|current| current.max(index))
                        .or(Some(index));
                    session.last_update_index = updated;
                    let confirmed = session
                        .confirmed_update_index
                        .map(|current| current.max(index))
                        .or(Some(index));
                    session.confirmed_update_index = confirmed;
                }
                _ => {}
            }
            self.persist_session(session_id, session)
        })();

        match result {
            Ok(()) => {
                self.breaker.record_success();
                Ok(())
            }
            Err(err) => Err(self.breaker.record_failure(err)),
        }
    }

    fn chunk_capabilities(&self) -> SnapshotChunkCapabilities {
        let chunk_size = u64::try_from(self.sizing.default_chunk_size).unwrap_or(u64::MAX);
        let min_chunk_size = u64::try_from(self.sizing.min_chunk_size).unwrap_or(u64::MAX);
        let max_chunk_size = u64::try_from(self.sizing.max_chunk_size).unwrap_or(u64::MAX);
        SnapshotChunkCapabilities {
            chunk_size: Some(chunk_size),
            min_chunk_size: Some(min_chunk_size),
            max_chunk_size: Some(max_chunk_size),
            max_concurrent_requests: None,
        }
    }

    fn breaker_status(&self) -> SnapshotBreakerStatus {
        self.breaker.status()
    }

    fn reset_breaker(&self) -> Result<(), Self::Error> {
        self.breaker.reset();
        Ok(())
    }
}

#[derive(Clone)]
struct RecordedUptimeProof {
    proof: UptimeProof,
    credited_hours: u64,
}

#[derive(Clone)]
struct QueuedVote {
    vote: SignedBftVote,
    received_at: SystemTime,
}

#[derive(Clone)]
struct VerifiedProposal {
    block: Block,
}

#[derive(Clone, Debug)]
pub struct NetworkIdentityProfile {
    pub zsi_id: String,
    pub tier: TierLevel,
    pub vrf_public_key: Vec<u8>,
    pub vrf_proof: Vec<u8>,
    pub feature_gates: FeatureGates,
}

struct AuditExporter {
    reputation: AuditStream,
    slashing: AuditStream,
}

impl AuditExporter {
    fn new(base_dir: &Path) -> ChainResult<Self> {
        fs::create_dir_all(base_dir)?;
        let reputation = AuditStream::new(base_dir.join("reputation"), "reputation")?;
        let slashing = AuditStream::new(base_dir.join("slashing"), "slashing")?;
        Ok(Self {
            reputation,
            slashing,
        })
    }

    fn export_reputation(&self, audit: &ReputationAudit) -> ChainResult<()> {
        self.reputation.append(audit)
    }

    fn export_slashing(&self, event: &SlashingEvent) -> ChainResult<()> {
        self.slashing.append(event)
    }

    fn recent_reputation(&self, limit: usize) -> ChainResult<Vec<ReputationAudit>> {
        self.reputation.tail(limit)
    }

    fn recent_slashing(&self, limit: usize) -> ChainResult<Vec<SlashingEvent>> {
        self.slashing.tail(limit)
    }
}

struct AuditStream {
    directory: PathBuf,
    prefix: &'static str,
    rotation: Duration,
    retention: usize,
    state: ParkingMutex<Option<ActiveAuditFile>>,
}

impl AuditStream {
    fn new(directory: PathBuf, prefix: &'static str) -> ChainResult<Self> {
        fs::create_dir_all(&directory)?;
        Ok(Self {
            directory,
            prefix,
            rotation: Duration::from_secs(24 * 60 * 60),
            retention: 30,
            state: ParkingMutex::new(None),
        })
    }

    fn append<T: Serialize>(&self, record: &T) -> ChainResult<()> {
        let now = SystemTime::now();
        let mut guard = self.state.lock();
        let file = self.ensure_file(now, &mut guard)?;
        serde_json::to_writer(&mut file.writer, record)
            .map_err(|err| ChainError::Config(format!("failed to encode audit record: {err}")))?;
        file.writer.write_all(b"\n")?;
        file.writer.flush()?;
        Ok(())
    }

    fn tail<T>(&self, limit: usize) -> ChainResult<Vec<T>>
    where
        T: DeserializeOwned,
    {
        if limit == 0 {
            return Ok(Vec::new());
        }
        if let Some(state) = self.state.lock().as_mut() {
            state.writer.flush()?;
        }
        let mut entries = fs::read_dir(&self.directory)?
            .filter_map(|entry| match entry {
                Ok(entry) if entry.path().is_file() => Some(entry.path()),
                _ => None,
            })
            .collect::<Vec<_>>();
        entries.sort();
        let mut tail = std::collections::VecDeque::with_capacity(limit);
        for path in entries {
            let file = File::open(&path)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line?;
                let record: T = serde_json::from_str(&line).map_err(|err| {
                    ChainError::Config(format!(
                        "failed to decode audit record from {}: {err}",
                        path.display()
                    ))
                })?;
                if tail.len() == limit {
                    tail.pop_front();
                }
                tail.push_back(record);
            }
        }
        Ok(tail.into_iter().collect())
    }

    fn ensure_file<'a>(
        &self,
        now: SystemTime,
        state: &'a mut Option<ActiveAuditFile>,
    ) -> ChainResult<&'a mut ActiveAuditFile> {
        let rotate = match state {
            Some(current) => {
                now.duration_since(current.opened_at).unwrap_or_default() >= self.rotation
            }
            None => true,
        };
        if rotate {
            *state = Some(self.open_file(now)?);
            self.prune_old_files()?;
        }
        Ok(state.as_mut().expect("audit file initialized"))
    }

    fn open_file(&self, now: SystemTime) -> ChainResult<ActiveAuditFile> {
        let timestamp = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let path = self
            .directory
            .join(format!("{}-{}.jsonl", self.prefix, timestamp));
        let file = File::create(&path)?;
        Ok(ActiveAuditFile {
            opened_at: now,
            writer: BufWriter::new(file),
            path,
        })
    }

    fn prune_old_files(&self) -> ChainResult<()> {
        let mut entries = fs::read_dir(&self.directory)?
            .filter_map(|entry| match entry {
                Ok(entry) if entry.path().is_file() => Some(entry.path()),
                _ => None,
            })
            .collect::<Vec<_>>();
        entries.sort();
        while entries.len() > self.retention {
            if let Some(path) = entries.first().cloned() {
                if let Err(err) = fs::remove_file(&path) {
                    warn!(?err, ?path, "failed to prune audit file");
                }
                entries.remove(0);
            } else {
                break;
            }
        }
        Ok(())
    }
}

struct ActiveAuditFile {
    opened_at: SystemTime,
    writer: BufWriter<File>,
    path: PathBuf,
}

impl Node {
    pub fn new(config: NodeConfig, runtime_metrics: Arc<RuntimeMetrics>) -> ChainResult<Self> {
        validate_zk_backend_support(&ZkBackendSupport::compiled())?;
        config.validate()?;
        config.ensure_directories()?;
        let keypair = load_or_generate_keypair(&config.key_path)?;
        let vrf_keypair = config.load_or_generate_vrf_keypair()?;
        let timetoke_snapshot_signing_key =
            config.load_or_generate_timetoke_snapshot_signing_key()?;
        let pruning_signing_key = config.pruning.checkpoint_signatures.load_signing_key()?;
        let pruning_verifying_key = config.pruning.checkpoint_signatures.verifying_key()?;
        let pruning_checkpoint_signatures = CheckpointSignatureConfig {
            signing_key: pruning_signing_key.clone(),
            verifying_key: pruning_verifying_key.or_else(|| {
                pruning_signing_key
                    .as_ref()
                    .map(|key| key.signing_key.verifying_key())
            }),
            expected_version: config.pruning.checkpoint_signatures.signature_version,
            require_signatures: config.pruning.checkpoint_signatures.require_signatures,
            allow_unsigned_legacy: config.pruning.checkpoint_signatures.allow_unsigned_legacy,
        };
        let p2p_identity = Arc::new(
            NodeIdentity::load_or_generate(&config.p2p_key_path)
                .map_err(|err| ChainError::Config(format!("unable to load p2p identity: {err}")))?,
        );
        let address = address_from_public_key(&keypair.public);
        let reputation_params = config.reputation_params();
        let db_path = config.data_dir.join("db");
        let storage = Storage::open(&db_path)?;
        let mut accounts = storage.load_accounts()?;
        let mut tip_metadata = storage.tip()?;
        let verifier_registry =
            ProofVerifierRegistry::with_max_proof_size_bytes(config.max_proof_size_bytes)?;
        if tip_metadata.is_none() {
            let genesis_accounts = if config.genesis.accounts.is_empty() {
                vec![GenesisAccount {
                    address: address.clone(),
                    balance: 1_000_000_000,
                    stake: "1000".to_string(),
                }]
            } else {
                config.genesis.accounts.clone()
            };
            accounts = build_genesis_accounts(genesis_accounts)?;
            for account in &accounts {
                storage.persist_account(account)?;
            }
            let utxo_snapshot = storage.load_utxo_snapshot()?.unwrap_or_default();
            let mut ledger = Ledger::load(accounts.clone(), utxo_snapshot, config.epoch_length);
            ledger.set_reputation_params(reputation_params.clone());
            ledger.set_timetoke_params(config.timetoke_params());
            ledger.configure_reward_pools(
                config.malachite.rewards.treasury_accounts(),
                config.malachite.rewards.witness_pool_weights(),
            );
            let mut tx_hashes: Vec<[u8; 32]> = Vec::new();
            let tx_root = compute_merkle_root(&mut tx_hashes);
            let commitments = ledger.global_commitments();
            let state_root_hex = hex::encode(commitments.global_state_root);
            let stakes = ledger.stake_snapshot();
            let total_stake = aggregate_total_stake(&stakes);
            let genesis_seed = [0u8; 32];
            let vrf = evaluate_vrf(&genesis_seed, 0, &address, 0, Some(&vrf_keypair.secret))?;
            let header = BlockHeader::new(
                0,
                hex::encode([0u8; 32]),
                hex::encode(tx_root),
                state_root_hex.clone(),
                hex::encode(commitments.utxo_root),
                hex::encode(commitments.reputation_root),
                hex::encode(commitments.timetoke_root),
                hex::encode(commitments.zsi_root),
                hex::encode(commitments.proof_root),
                total_stake.to_string(),
                vrf.randomness.to_string(),
                vrf_public_key_to_hex(&vrf_keypair.public),
                vrf.preoutput.clone(),
                vrf.proof.clone(),
                address.clone(),
                Tier::Tl5.to_string(),
                0,
            );
            let pruning_proof = pruning_from_previous(None, &header);
            let transactions: Vec<SignedTransaction> = Vec::new();
            let transaction_proofs: Vec<ChainProof> = Vec::new();
            let identity_proofs: Vec<ChainProof> = Vec::new();
            let LocalProofArtifacts {
                bundle: stark_bundle,
                consensus_proof,
                module_witnesses,
                mut proof_artifacts,
            } = NodeInner::generate_local_block_proofs(
                &storage,
                &ledger,
                &header,
                &commitments,
                &pruning_proof,
                &[],
                &transactions,
                transaction_proofs,
                &identity_proofs,
                &[],
                None,
                None,
                config.max_proof_size_bytes,
            )?;
            debug_assert!(
                consensus_proof.is_none(),
                "genesis consensus proof should not be generated",
            );
            #[cfg(feature = "backend-rpp-stark")]
            if let Err(err) = verifier_registry.verify_rpp_stark_block_bundle(&stark_bundle) {
                error!(?err, "genesis block bundle rejected by RPP-STARK verifier");
                return Err(err);
            }
            let recursive_proof =
                RecursiveProof::genesis(&header, &pruning_proof, &stark_bundle.recursive_proof)?;
            let signature = sign_message(&keypair, &header.canonical_bytes());
            let consensus_certificate = ConsensusCertificate::genesis();
            let genesis_block = Block::new(
                header,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                module_witnesses,
                proof_artifacts,
                pruning_proof,
                recursive_proof,
                stark_bundle,
                signature,
                consensus_certificate,
                None,
            );
            genesis_block.verify(None, &keypair.public)?;
            let genesis_metadata = BlockMetadata::from(&genesis_block);
            storage.store_block(&genesis_block, &genesis_metadata)?;
            tip_metadata = Some(genesis_metadata);
        }

        if accounts.is_empty() {
            accounts = storage.load_accounts()?;
        }

        let utxo_snapshot = storage.load_utxo_snapshot()?.unwrap_or_default();
        let mut ledger = Ledger::load(accounts, utxo_snapshot, config.epoch_length);
        ledger.set_reputation_params(reputation_params);
        ledger.set_timetoke_params(config.timetoke_params());
        ledger.configure_reward_pools(
            config.malachite.rewards.treasury_accounts(),
            config.malachite.rewards.witness_pool_weights(),
        );

        let node_pk_hex = hex::encode(keypair.public.to_bytes());
        if ledger.get_account(&address).is_none() {
            let mut account = Account::new(address.clone(), 0, Stake::default());
            let _ = account.ensure_wallet_binding(&node_pk_hex)?;
            ledger.upsert_account(account)?;
        }
        ledger.ensure_node_binding(&address, &node_pk_hex)?;

        let next_height = tip_metadata
            .as_ref()
            .map(|meta| meta.height.saturating_add(1))
            .unwrap_or(0);
        ledger.sync_epoch_for_height(next_height);
        let epoch_manager = VrfEpochManager::new(config.epoch_length, ledger.current_epoch());

        let (shutdown, _shutdown_rx) = broadcast::channel(1);
        let (pipeline_events, _) = broadcast::channel(256);
        let mempool_limit = config.mempool_limit;
        let queue_weights = config.queue_weights.clone();
        let consensus_telemetry = Arc::new(ConsensusTelemetry::new(runtime_metrics.clone()));
        let audit_exporter = AuditExporter::new(&config.data_dir.join("audits"))?;
        let consensus_state_record = storage.read_consensus_state()?.unwrap_or_default();
        let mut consensus_rounds_map = HashMap::new();
        if consensus_state_record.locked_proposal.is_some() || consensus_state_record.round > 0 {
            consensus_rounds_map
                .insert(consensus_state_record.height, consensus_state_record.round);
        }
        let consensus_lock_state =
            consensus_state_record
                .locked_proposal
                .as_ref()
                .map(|hash| ConsensusLockState {
                    height: consensus_state_record.height,
                    round: consensus_state_record.round,
                    block_hash: hash.clone(),
                });
        let inner = Arc::new(NodeInner {
            block_interval: Duration::from_millis(config.block_time_ms),
            config,
            mempool_limit: AtomicUsize::new(mempool_limit),
            pruning_cancelled: AtomicBool::new(false),
            queue_weights: RwLock::new(queue_weights),
            keypair,
            vrf_keypair,
            timetoke_snapshot_signing_key,
            pruning_checkpoint_signatures,
            p2p_identity,
            address,
            storage,
            ledger,
            last_epoch: AtomicU64::new(ledger.current_epoch()),
            mempool: RwLock::new(VecDeque::new()),
            pending_transaction_metadata: RwLock::new(HashMap::new()),
            identity_mempool: RwLock::new(VecDeque::new()),
            uptime_mempool: RwLock::new(VecDeque::new()),
            vrf_mempool: RwLock::new(VrfSubmissionPool::new()),
            vrf_epoch: RwLock::new(epoch_manager),
            chain_tip: RwLock::new(ChainTip {
                height: 0,
                last_hash: [0u8; 32],
                pruning: None,
            }),
            vote_mempool: RwLock::new(VecDeque::new()),
            proposal_inbox: RwLock::new(HashMap::new()),
            consensus_rounds: RwLock::new(consensus_rounds_map),
            consensus_lock: RwLock::new(consensus_lock_state),
            consensus_state: RwLock::new(consensus_state_record),
            evidence_pool: RwLock::new(EvidencePool::default()),
            pruning_status: RwLock::new(None),
            vrf_metrics: RwLock::new(crate::vrf::VrfSelectionMetrics::default()),
            vrf_threshold: RwLock::new(VrfThresholdStatus::default()),
            verifiers: verifier_registry,
            shutdown,
            pipeline_events,
            worker_tasks: Mutex::new(Vec::new()),
            completion: Notify::new(),
            witness_channels: WitnessChannels::new(128),
            p2p_runtime: ParkingMutex::new(None),
            consensus_telemetry,
            audit_exporter,
            runtime_metrics: runtime_metrics.clone(),
            cache_metrics_checkpoint: ParkingMutex::new(ProofCacheMetricsSnapshot::default()),
            state_sync_session: ParkingMutex::new(StateSyncSessionCache::default()),
            state_sync_server: OnceCell::new(),
            snapshot_breaker: SnapshotCircuitBreaker::new(SNAPSHOT_BREAKER_THRESHOLD),
        });
        let server = Arc::new(StateSyncServer::new(
            Arc::downgrade(&inner),
            runtime_metrics.clone(),
        ));
        let _ = inner.state_sync_server.set(server);
        {
            let weak_inner = Arc::downgrade(&inner);
            inner
                .witness_channels
                .set_backpressure_hook(Arc::new(move |topic, queue_depth| {
                    if let Some(inner) = weak_inner.upgrade() {
                        if let Some(runtime) = inner.p2p_runtime.lock().clone() {
                            let topic_clone = topic.clone();
                            let span = info_span!(
                                "runtime.gossip.backpressure",
                                topic = %topic_clone,
                                queue_depth
                            );
                            tokio::spawn(
                                async move {
                                    if let Err(err) = runtime
                                        .report_gossip_backpressure(
                                            topic_clone.clone(),
                                            queue_depth,
                                        )
                                        .await
                                    {
                                        warn!(
                                            target: "node",
                                            ?topic_clone,
                                            queue_depth,
                                            ?err,
                                            "failed to report gossip backpressure"
                                        );
                                    }
                                }
                                .instrument(span),
                            );
                        }
                    }
                }));
        }
        debug!(peer_id = %inner.p2p_identity.peer_id(), "libp2p identity initialised");
        inner.bootstrap()?;
        Ok(Self { inner })
    }

    pub fn handle(&self) -> NodeHandle {
        NodeHandle {
            inner: self.inner.clone(),
        }
    }

    pub fn runtime_metrics(&self) -> Arc<RuntimeMetrics> {
        self.inner.runtime_metrics.clone()
    }

    pub fn subscribe_witness_gossip(&self, topic: GossipTopic) -> broadcast::Receiver<Vec<u8>> {
        self.inner.subscribe_witness_gossip(topic)
    }

    pub fn p2p_handle(&self) -> Option<P2pHandle> {
        self.inner.p2p_handle()
    }

    pub async fn start(self) -> ChainResult<()> {
        let inner = self.inner;
        let join = inner.spawn_runtime();
        let result = join
            .await
            .map_err(|err| ChainError::Config(format!("node runtime join error: {err}")));
        result
    }

    pub fn network_identity_profile(&self) -> ChainResult<NetworkIdentityProfile> {
        self.inner.network_identity_profile()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ZkBackendSupport {
    rpp_stark: bool,
    plonky3_cpu: bool,
    plonky3_gpu: bool,
    stwo: bool,
    mock: bool,
}

impl ZkBackendSupport {
    fn compiled() -> Self {
        Self {
            rpp_stark: cfg!(feature = "backend-rpp-stark"),
            plonky3_cpu: cfg!(feature = "backend-plonky3"),
            plonky3_gpu: cfg!(feature = "backend-plonky3-gpu"),
            stwo: cfg!(any(feature = "prover-stwo", feature = "prover-stwo-simd")),
            mock: cfg!(feature = "prover-mock"),
        }
    }
}

fn validate_zk_backend_support(support: &ZkBackendSupport) -> ChainResult<()> {
    if support.plonky3_cpu && support.plonky3_gpu {
        return Err(ChainError::Config(
            "`backend-plonky3` and `backend-plonky3-gpu` are mutually exclusive; enable only one"
                .into(),
        ));
    }

    if !(support.rpp_stark
        || support.plonky3_cpu
        || support.plonky3_gpu
        || support.stwo
        || support.mock)
    {
        return Err(ChainError::Config(
            "no zk proof backend enabled; compile with at least one of `prover-stwo`, `prover-stwo-simd`, `backend-plonky3`, `backend-plonky3-gpu`, `backend-rpp-stark`, or `prover-mock`".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod zk_backend_validation_tests {
    use super::*;

    #[test]
    fn plonky3_variants_are_exclusive() {
        let support = ZkBackendSupport {
            rpp_stark: false,
            plonky3_cpu: true,
            plonky3_gpu: true,
            stwo: false,
            mock: false,
        };

        let error =
            validate_zk_backend_support(&support).expect_err("plonky3 variants should conflict");
        assert!(
            matches!(error, ChainError::Config(message) if message.contains("mutually exclusive")),
            "unexpected error: {error:?}",
        );
    }

    #[test]
    fn requires_at_least_one_backend() {
        let support = ZkBackendSupport {
            rpp_stark: false,
            plonky3_cpu: false,
            plonky3_gpu: false,
            stwo: false,
            mock: false,
        };

        let error =
            validate_zk_backend_support(&support).expect_err("missing backends should fail");
        assert!(
            matches!(error, ChainError::Config(message) if message.contains("no zk proof backend enabled")),
            "unexpected error: {error:?}",
        );
    }

    #[test]
    fn compiled_feature_set_is_valid() {
        validate_zk_backend_support(&ZkBackendSupport::compiled())
            .expect("compiled zk backend set should be valid");
    }
    #[test]
    fn rpp_stark_failure_size_metrics_are_bucketed() -> std::result::Result<(), MetricError> {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("rpp-stark-size-metrics");
        let metrics = RuntimeMetrics::from_meter(&meter);
        let proof_metrics = metrics.proofs();

        proof_metrics.observe_verification_total_bytes_by_result(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Consensus,
            ProofVerificationKind::Consensus.as_str(),
            ProofVerificationOutcome::Fail,
            5 * 1024 * 1024,
        );

        provider.force_flush()?;
        let exported = exporter.get_finished_metrics()?;

        let mut saw_fail_bucket = false;
        for resource in exported {
            for scope in resource.scope_metrics {
                for metric in scope.metrics {
                    if metric.name != "rpp_stark_proof_total_bytes_by_result" {
                        continue;
                    }
                    if let Data::Histogram(Histogram { data_points, .. }) = metric.data {
                        for point in data_points {
                            let mut attrs = HashMap::new();
                            for attribute in point.attributes {
                                attrs
                                    .insert(attribute.key.to_string(), attribute.value.to_string());
                            }
                            if attrs.get(ProofVerificationOutcome::KEY)
                                == Some(&ProofVerificationOutcome::Fail.as_str().to_string())
                                && attrs.get(ProofVerificationBackend::KEY)
                                    == Some(
                                        &ProofVerificationBackend::RppStark.as_str().to_string(),
                                    )
                                && attrs.get(ProofVerificationKind::KEY)
                                    == Some(&ProofVerificationKind::Consensus.as_str().to_string())
                                && point.count > 0
                            {
                                saw_fail_bucket = true;
                            }
                        }
                    }
                }
            }
        }

        assert!(
            saw_fail_bucket,
            "expected histogram bucket for failing proof bytes"
        );

        Ok(())
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[test]
    fn rpp_stark_size_gate_errors_record_lengths() -> std::result::Result<(), MetricError> {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("rpp-stark-size-gate-metrics");
        let metrics = RuntimeMetrics::from_meter(&meter);
        let proof_metrics = metrics.proofs();

        let proof = ChainProof::RppStark(RppStarkProof::new(
            vec![0u8; 2 * 1024],
            vec![0u8; 1024],
            vec![0u8; 4 * 1024],
        ));
        let snapshot = record_rpp_stark_size_metrics(
            proof_metrics,
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Consensus,
            ProofVerificationKind::Consensus.as_str(),
            &proof,
            ProofVerificationOutcome::Fail,
        )
        .expect("size snapshot should be captured");

        assert_eq!(snapshot.params_bytes, 2 * 1024);
        assert_eq!(snapshot.public_inputs_bytes, 1024);
        assert_eq!(snapshot.payload_bytes, 4 * 1024);
        assert_eq!(snapshot.proof_bytes, 7 * 1024);
        assert_eq!(
            snapshot.size_bucket,
            proof_size_bucket(snapshot.proof_bytes)
        );

        provider.force_flush()?;
        let exported = exporter.get_finished_metrics()?;

        let mut saw_total_histogram = false;
        let mut saw_params_histogram = false;
        let mut saw_public_inputs_histogram = false;
        let mut saw_payload_histogram = false;

        for resource in exported {
            for scope in resource.scope_metrics {
                for metric in scope.metrics {
                    match metric.name.as_str() {
                        "rpp_stark_proof_total_bytes_by_result" => {
                            if let Data::Histogram(Histogram { data_points, .. }) = metric.data {
                                for point in data_points {
                                    let mut attrs = HashMap::new();
                                    for attribute in point.attributes {
                                        attrs.insert(
                                            attribute.key.to_string(),
                                            attribute.value.to_string(),
                                        );
                                    }
                                    if attrs.get(ProofVerificationOutcome::KEY)
                                        == Some(
                                            &ProofVerificationOutcome::Fail.as_str().to_string(),
                                        )
                                        && attrs.get(ProofVerificationBackend::KEY)
                                            == Some(
                                                &ProofVerificationBackend::RppStark
                                                    .as_str()
                                                    .to_string(),
                                            )
                                        && attrs.get(ProofVerificationKind::KEY)
                                            == Some(
                                                &ProofVerificationKind::Consensus
                                                    .as_str()
                                                    .to_string(),
                                            )
                                        && point.count > 0
                                    {
                                        saw_total_histogram = true;
                                    }
                                }
                            }
                        }
                        "rpp_stark_params_bytes" => {
                            if let Data::Histogram(Histogram { data_points, .. }) = metric.data {
                                for point in data_points {
                                    let mut attrs = HashMap::new();
                                    for attribute in point.attributes {
                                        attrs.insert(
                                            attribute.key.to_string(),
                                            attribute.value.to_string(),
                                        );
                                    }
                                    if attrs.get(ProofVerificationBackend::KEY)
                                        == Some(
                                            &ProofVerificationBackend::RppStark
                                                .as_str()
                                                .to_string(),
                                        )
                                        && attrs.get(ProofVerificationKind::KEY)
                                            == Some(
                                                &ProofVerificationKind::Consensus
                                                    .as_str()
                                                    .to_string(),
                                            )
                                        && point.count > 0
                                    {
                                        saw_params_histogram = true;
                                    }
                                }
                            }
                        }
                        "rpp_stark_public_inputs_bytes" => {
                            if let Data::Histogram(Histogram { data_points, .. }) = metric.data {
                                for point in data_points {
                                    let mut attrs = HashMap::new();
                                    for attribute in point.attributes {
                                        attrs.insert(
                                            attribute.key.to_string(),
                                            attribute.value.to_string(),
                                        );
                                    }
                                    if attrs.get(ProofVerificationBackend::KEY)
                                        == Some(
                                            &ProofVerificationBackend::RppStark
                                                .as_str()
                                                .to_string(),
                                        )
                                        && attrs.get(ProofVerificationKind::KEY)
                                            == Some(
                                                &ProofVerificationKind::Consensus
                                                    .as_str()
                                                    .to_string(),
                                            )
                                        && point.count > 0
                                    {
                                        saw_public_inputs_histogram = true;
                                    }
                                }
                            }
                        }
                        "rpp_stark_payload_bytes" => {
                            if let Data::Histogram(Histogram { data_points, .. }) = metric.data {
                                for point in data_points {
                                    let mut attrs = HashMap::new();
                                    for attribute in point.attributes {
                                        attrs.insert(
                                            attribute.key.to_string(),
                                            attribute.value.to_string(),
                                        );
                                    }
                                    if attrs.get(ProofVerificationBackend::KEY)
                                        == Some(
                                            &ProofVerificationBackend::RppStark
                                                .as_str()
                                                .to_string(),
                                        )
                                        && attrs.get(ProofVerificationKind::KEY)
                                            == Some(
                                                &ProofVerificationKind::Consensus
                                                    .as_str()
                                                    .to_string(),
                                            )
                                        && point.count > 0
                                    {
                                        saw_payload_histogram = true;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        assert!(
            saw_total_histogram,
            "expected proof-by-result histogram to be populated"
        );
        assert!(
            saw_params_histogram,
            "expected params histogram to be populated"
        );
        assert!(
            saw_public_inputs_histogram,
            "expected public inputs histogram to be populated"
        );
        assert!(
            saw_payload_histogram,
            "expected payload histogram to be populated"
        );

        Ok(())
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[traced_test]
    fn oversized_failure_logs_include_bucket() {
        let failure = RppStarkVerifyFailure::ProofTooLarge {
            max_kib: 4096,
            got_kib: 6144,
        };
        let proof_bytes = 5 * 1024 * 1024 + 12;
        let size_bucket = proof_size_bucket(proof_bytes);
        let labels = ProofLogLabels {
            peer_id: Some("peer.test".into()),
            height: Some(10),
            slot: Some(3),
            proof_id: Some("proof.test".into()),
            circuit: Some("consensus".into()),
        };
        let resolved = labels.resolve(ProofVerificationKind::Consensus);

        warn!(
            target = "proofs",
            peer_id = resolved.peer_id,
            height = ?resolved.height,
            slot = ?resolved.slot,
            proof_id = resolved.proof_id,
            circuit = resolved.circuit,
            backend = ProofVerificationBackend::RppStark.as_str(),
            proof_backend = "rpp-stark",
            proof_kind = ProofVerificationKind::Consensus.as_str(),
            valid = false,
            proof_bytes,
            size_bucket,
            params_bytes = 1024u64,
            public_inputs_bytes = 2048u64,
            payload_bytes = 4096u64,
            verify_duration_ms = 7u64,
            error = %failure,
            "rpp-stark proof verification failed"
        );

        assert!(logs_contain("size_bucket=gt_4_mib"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GenesisAccount, NodeConfig};
    use crate::consensus::{
        classify_participants, evaluate_vrf, BftVote, BftVoteKind, ConsensusRound, SignedBftVote,
    };
    use crate::crypto::{
        address_from_public_key, generate_vrf_keypair, load_or_generate_keypair,
        vrf_public_key_from_hex, vrf_public_key_to_hex,
    };
    use crate::errors::ChainError;
    use crate::ledger::Ledger;
    use crate::proof_backend::Blake2sHasher;
    use crate::reputation::Tier;
    use crate::stwo::circuit::{
        identity::{IdentityCircuit, IdentityWitness},
        string_to_field, StarkCircuit,
    };
    use crate::stwo::fri::FriProver;
    use crate::stwo::params::StarkParameters;
    use crate::stwo::proof::{
        CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
    };
    #[cfg(feature = "backend-rpp-stark")]
    use crate::types::RppStarkProof;
    use crate::types::{ChainProof, IdentityDeclaration, IdentityGenesis, IdentityProof};
    use crate::vrf::{self, PoseidonVrfInput, VrfProof, VrfSubmission, VrfSubmissionPool};
    use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};
    use malachite::Natural;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
    use tracing_subscriber::registry::LookupSpan;
    use tracing_subscriber::Registry;
    use tracing_test::traced_test;

    #[derive(Clone, Default)]
    struct RecordingLayer {
        spans: Arc<Mutex<Vec<String>>>,
    }

    impl RecordingLayer {
        fn names(&self) -> Vec<String> {
            self.spans.lock().expect("record spans").clone()
        }
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

    #[test]
    fn wallet_flow_span_emits_runtime_span() {
        let recorder = RecordingLayer::default();
        let subscriber = Registry::default().with(recorder.clone());
        tracing::subscriber::with_default(subscriber, || {
            let address: Address = "wallet-span".into();
            let span = wallet_rpc_flow_span("submit", &address, "hash-span");
            let _guard = span.enter();
            info!("within wallet span");
        });
        assert!(recorder
            .names()
            .iter()
            .any(|name| name == "runtime.wallet.rpc"));
    }

    #[test]
    fn proof_operation_span_emits_runtime_span() {
        let recorder = RecordingLayer::default();
        let subscriber = Registry::default().with(recorder.clone());
        tracing::subscriber::with_default(subscriber, || {
            let span = proof_operation_span(
                "prove_state",
                ProofSystemKind::Stwo,
                Some(42),
                Some("block-hash"),
            );
            let _guard = span.enter();
            info!("within proof span");
        });
        assert!(recorder
            .names()
            .iter()
            .any(|name| name == "runtime.proof.operation"));
    }

    fn seeded_keypair(seed: u8) -> Keypair {
        let secret = SecretKey::from_bytes(&[seed; 32]).expect("secret");
        let public = PublicKey::from(&secret);
        Keypair { secret, public }
    }

    fn sign_identity_vote(keypair: &Keypair, height: u64, hash: &str) -> SignedBftVote {
        let voter = address_from_public_key(&keypair.public);
        let vote = BftVote {
            round: 0,
            height,
            block_hash: hash.to_string(),
            voter: voter.clone(),
            kind: BftVoteKind::PreCommit,
        };
        let signature = keypair.sign(&vote.message_bytes());
        SignedBftVote {
            vote,
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(signature.to_bytes()),
        }
    }

    fn sample_identity_declaration(ledger: &Ledger) -> IdentityDeclaration {
        ledger.sync_epoch_for_height(1);
        let pk_bytes = vec![1u8; 32];
        let wallet_pk = hex::encode(&pk_bytes);
        let wallet_addr = hex::encode::<[u8; 32]>(Blake2sHasher::hash(&pk_bytes).into());
        let epoch_nonce_bytes = ledger.current_epoch_nonce();
        let vrf_keypair = generate_vrf_keypair().expect("generate vrf keypair");
        let vrf = evaluate_vrf(
            &epoch_nonce_bytes,
            0,
            &wallet_addr,
            0,
            Some(&vrf_keypair.secret),
        )
        .expect("evaluate vrf");
        let commitment_proof = ledger.identity_commitment_proof(&wallet_addr);
        let genesis = IdentityGenesis {
            wallet_pk,
            wallet_addr,
            vrf_public_key: vrf_public_key_to_hex(&vrf_keypair.public),
            vrf_proof: vrf.clone(),
            epoch_nonce: hex::encode(epoch_nonce_bytes),
            state_root: hex::encode(ledger.state_root()),
            identity_root: hex::encode(ledger.identity_root()),
            initial_reputation: 0,
            commitment_proof: commitment_proof.clone(),
        };
        let parameters = StarkParameters::blueprint_default();
        let expected_commitment = genesis.expected_commitment().expect("commitment");
        let witness = IdentityWitness {
            wallet_pk: genesis.wallet_pk.clone(),
            wallet_addr: genesis.wallet_addr.clone(),
            vrf_tag: genesis.vrf_tag().to_string(),
            epoch_nonce: genesis.epoch_nonce.clone(),
            state_root: genesis.state_root.clone(),
            identity_root: genesis.identity_root.clone(),
            initial_reputation: genesis.initial_reputation,
            commitment: expected_commitment.clone(),
            identity_leaf: commitment_proof.leaf.clone(),
            identity_path: commitment_proof.siblings.clone(),
        };
        let circuit = IdentityCircuit::new(witness.clone());
        circuit.evaluate_constraints().expect("constraints");
        let trace = circuit
            .generate_trace(&parameters)
            .expect("trace generation");
        circuit
            .verify_air(&parameters, &trace)
            .expect("air verification");
        let inputs = vec![
            string_to_field(&parameters, &witness.wallet_addr),
            string_to_field(&parameters, &witness.vrf_tag),
            string_to_field(&parameters, &witness.identity_root),
            string_to_field(&parameters, &witness.state_root),
        ];
        let hasher = parameters.poseidon_hasher();
        let fri_prover = FriProver::new(&parameters);
        let air = circuit
            .define_air(&parameters, &trace)
            .expect("air definition");
        let fri_output = fri_prover.prove(&air, &trace, &inputs);
        let proof = StarkProof::new(
            ProofKind::Identity,
            ProofPayload::Identity(witness),
            inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        );
        IdentityDeclaration {
            genesis,
            proof: IdentityProof {
                commitment: expected_commitment,
                zk_proof: ChainProof::Stwo(proof),
            },
        }
    }

    fn attested_request(ledger: &Ledger, height: u64) -> AttestedIdentityRequest {
        let declaration = sample_identity_declaration(ledger);
        let identity_hash = hex::encode(declaration.hash().expect("hash"));
        let voters: Vec<Keypair> = (0..IDENTITY_ATTESTATION_QUORUM)
            .map(|idx| seeded_keypair(50 + idx as u8))
            .collect();
        let attested_votes = voters
            .iter()
            .map(|kp| sign_identity_vote(kp, height, &identity_hash))
            .collect();
        let gossip_confirmations = voters
            .iter()
            .take(IDENTITY_ATTESTATION_GOSSIP_MIN)
            .map(|kp| address_from_public_key(&kp.public))
            .collect();
        AttestedIdentityRequest {
            declaration,
            attested_votes,
            gossip_confirmations,
        }
    }

    fn temp_config() -> (tempfile::TempDir, NodeConfig) {
        let dir = tempdir().expect("tempdir");
        let base = dir.path();
        let mut config = NodeConfig::default();
        config.data_dir = base.join("data");
        config.key_path = base.join("node_key.toml");
        config.p2p_key_path = base.join("p2p_key.toml");
        config.vrf_key_path = base.join("vrf_key.toml");
        config.snapshot_dir = base.join("snapshots");
        config.proof_cache_dir = base.join("proofs");
        (dir, config)
    }

    #[test]
    fn node_accepts_valid_identity_attestation() {
        let (_tmp, config) = temp_config();
        let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
        let height = node.inner.chain_tip.read().height + 1;
        let request = attested_request(&node.inner.ledger, height);
        node.inner
            .validate_identity_attestation(&request, height)
            .expect("valid attestation accepted");
    }

    #[test]
    fn node_rejects_attestation_below_quorum() {
        let (_tmp, config) = temp_config();
        let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
        let height = node.inner.chain_tip.read().height + 1;
        let mut request = attested_request(&node.inner.ledger, height);
        request
            .attested_votes
            .truncate(IDENTITY_ATTESTATION_QUORUM - 1);
        let err = node
            .inner
            .validate_identity_attestation(&request, height)
            .expect_err("insufficient quorum rejected");
        match err {
            ChainError::Transaction(message) => {
                assert!(message.contains("quorum"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn node_rejects_attestation_with_insufficient_gossip() {
        let (_tmp, config) = temp_config();
        let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
        let height = node.inner.chain_tip.read().height + 1;
        let mut request = attested_request(&node.inner.ledger, height);
        request
            .gossip_confirmations
            .truncate(IDENTITY_ATTESTATION_GOSSIP_MIN - 1);
        let err = node
            .inner
            .validate_identity_attestation(&request, height)
            .expect_err("insufficient gossip rejected");
        match err {
            ChainError::Transaction(message) => {
                assert!(message.contains("gossip"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn finalizes_external_block_from_remote_proposer() {
        let (_tmp_a, mut config_a) = temp_config();
        let (_tmp_b, mut config_b) = temp_config();

        config_a.rollout.feature_gates.pruning = false;
        config_b.rollout.feature_gates.pruning = false;
        config_a.rollout.feature_gates.consensus_enforcement = false;
        config_b.rollout.feature_gates.consensus_enforcement = false;

        let key_a = load_or_generate_keypair(&config_a.key_path).expect("generate key a");
        let key_b = load_or_generate_keypair(&config_b.key_path).expect("generate key b");
        let address_a = address_from_public_key(&key_a.public);
        let address_b = address_from_public_key(&key_b.public);

        let genesis_accounts = vec![
            GenesisAccount {
                address: address_a.clone(),
                balance: 1_000_000_000,
                stake: "1000".to_string(),
            },
            GenesisAccount {
                address: address_b.clone(),
                balance: 1_000_000_000,
                stake: "1000".to_string(),
            },
        ];
        config_a.genesis.accounts = genesis_accounts.clone();
        config_b.genesis.accounts = genesis_accounts;

        let node_a = Node::new(config_a, RuntimeMetrics::noop()).expect("node a");
        let node_b = Node::new(config_b, RuntimeMetrics::noop()).expect("node b");

        let height = node_a.inner.chain_tip.read().height + 1;
        let request = attested_request(&node_a.inner.ledger, height);
        node_a
            .inner
            .submit_identity(request)
            .expect("submit identity");
        node_a.inner.produce_block().expect("produce block");

        let block = node_a
            .inner
            .storage
            .read_block(height)
            .expect("read block")
            .expect("block exists");
        assert_eq!(block.header.proposer, address_a);

        let previous_hash_bytes =
            hex::decode(&block.header.previous_hash).expect("decode prev hash");
        let mut seed = [0u8; 32];
        if !previous_hash_bytes.is_empty() {
            seed.copy_from_slice(&previous_hash_bytes);
        }

        let accounts_snapshot = node_b.inner.ledger.accounts_snapshot();
        let (validators, observers) = classify_participants(&accounts_snapshot);
        let proposer_candidate = validators
            .iter()
            .find(|candidate| candidate.address == block.header.proposer)
            .expect("proposer candidate")
            .clone();

        node_b
            .inner
            .ledger
            .sync_epoch_for_height(block.header.height);
        let epoch = node_b.inner.ledger.current_epoch();

        let tier = match block.header.leader_tier.as_str() {
            "New" => Tier::Tl0,
            "Validated" => Tier::Tl1,
            "Available" => Tier::Tl2,
            "Committed" => Tier::Tl3,
            "Reliable" => Tier::Tl4,
            "Trusted" => Tier::Tl5,
            other => panic!("unexpected leader tier: {other}"),
        };
        let tier_seed = vrf::derive_tier_seed(
            &proposer_candidate.address,
            proposer_candidate.timetoke_hours,
        );
        let input = PoseidonVrfInput::new(seed, epoch, tier_seed);
        let randomness = Natural::from_str(&block.header.randomness).expect("parse randomness");
        let proof = VrfProof {
            randomness,
            preoutput: block.header.vrf_preoutput.clone(),
            proof: block.header.vrf_proof.clone(),
        };
        let public_key = if block.header.vrf_public_key.trim().is_empty() {
            None
        } else {
            Some(vrf_public_key_from_hex(&block.header.vrf_public_key).expect("vrf key"))
        };
        let mut pool = VrfSubmissionPool::new();
        pool.insert(VrfSubmission {
            address: block.header.proposer.clone(),
            public_key,
            input,
            proof,
            tier,
            timetoke_hours: block.header.leader_timetoke,
        });

        let mut round = ConsensusRound::new(
            block.header.height,
            block.consensus.round,
            seed,
            node_b.inner.config.validator_set_size(),
            validators,
            observers,
            &pool,
        );
        round.set_block_hash(block.hash.clone());
        for record in &block.consensus.pre_votes {
            round
                .register_prevote(&record.vote)
                .expect("register prevote");
        }
        for record in &block.consensus.pre_commits {
            round
                .register_precommit(&record.vote)
                .expect("register precommit");
        }
        assert!(round.commit_reached());

        let previous_block = if block.header.height == 0 {
            None
        } else {
            node_b
                .inner
                .storage
                .read_block(block.header.height - 1)
                .expect("read previous block")
        };

        let outcome = node_b
            .inner
            .finalize_block(FinalizationContext::External(ExternalFinalizationContext {
                round,
                block: block.clone(),
                previous_block,
                archived_votes: block.bft_votes.clone(),
                peer_id: None,
                expected_proposer: block.header.proposer.clone(),
                expected_weight: 0.0,
                epoch: 0,
            }))
            .expect("finalize external");

        let sealed = match outcome {
            FinalizationOutcome::Sealed { block: sealed, .. } => sealed,
            FinalizationOutcome::AwaitingQuorum => panic!("expected sealed block"),
        };
        assert_eq!(sealed.hash, block.hash);

        let tip_metadata = node_b
            .inner
            .storage
            .tip()
            .expect("tip metadata")
            .expect("metadata");
        assert_eq!(tip_metadata.height, block.header.height);
        assert_eq!(tip_metadata.new_state_root, block.header.state_root);

        let stored_record = node_b
            .inner
            .storage
            .read_block_record(block.header.height)
            .expect("read record")
            .expect("stored block");
        let stored_pruning = &stored_record.envelope.pruning_proof;
        assert_eq!(stored_pruning, &block.pruning_proof);
        let stored_consensus = &stored_record.envelope.consensus;
        assert_eq!(stored_consensus.round, block.consensus.round);
        assert_eq!(stored_consensus.total_power, block.consensus.total_power);
        assert_eq!(
            stored_consensus.pre_votes.len(),
            block.consensus.pre_votes.len()
        );
        assert_eq!(
            stored_consensus.pre_commits.len(),
            block.consensus.pre_commits.len()
        );

        assert_eq!(
            hex::encode(node_b.inner.ledger.state_root()),
            block.header.state_root
        );
        assert_eq!(node_b.inner.chain_tip.read().height, block.header.height);
    }

    #[test]
    #[traced_test]
    fn rejects_external_block_with_tampered_state_fri_proof() {
        let (_tmp_a, mut config_a) = temp_config();
        let (_tmp_b, mut config_b) = temp_config();

        config_a.rollout.feature_gates.pruning = false;
        config_b.rollout.feature_gates.pruning = false;
        config_a.rollout.feature_gates.consensus_enforcement = false;
        config_b.rollout.feature_gates.consensus_enforcement = false;

        let key_a = load_or_generate_keypair(&config_a.key_path).expect("generate key a");
        let key_b = load_or_generate_keypair(&config_b.key_path).expect("generate key b");
        let address_a = address_from_public_key(&key_a.public);
        let address_b = address_from_public_key(&key_b.public);

        let genesis_accounts = vec![
            GenesisAccount {
                address: address_a.clone(),
                balance: 1_000_000_000,
                stake: "1000".to_string(),
            },
            GenesisAccount {
                address: address_b.clone(),
                balance: 1_000_000_000,
                stake: "1000".to_string(),
            },
        ];
        config_a.genesis.accounts = genesis_accounts.clone();
        config_b.genesis.accounts = genesis_accounts;

        let node_a = Node::new(config_a, RuntimeMetrics::noop()).expect("node a");
        let node_b = Node::new(config_b, RuntimeMetrics::noop()).expect("node b");

        let height = node_a.inner.chain_tip.read().height + 1;
        let request = attested_request(&node_a.inner.ledger, height);
        node_a
            .inner
            .submit_identity(request)
            .expect("submit identity");
        node_a.inner.produce_block().expect("produce block");

        let block = node_a
            .inner
            .storage
            .read_block(height)
            .expect("read block")
            .expect("block exists");
        assert_eq!(block.header.proposer, address_a);

        let previous_hash_bytes =
            hex::decode(&block.header.previous_hash).expect("decode prev hash");
        let mut seed = [0u8; 32];
        if !previous_hash_bytes.is_empty() {
            seed.copy_from_slice(&previous_hash_bytes);
        }

        let accounts_snapshot = node_b.inner.ledger.accounts_snapshot();
        let (validators, observers) = classify_participants(&accounts_snapshot);
        let proposer_candidate = validators
            .iter()
            .find(|candidate| candidate.address == block.header.proposer)
            .expect("proposer candidate")
            .clone();

        node_b
            .inner
            .ledger
            .sync_epoch_for_height(block.header.height);
        let epoch = node_b.inner.ledger.current_epoch();

        let tier = match block.header.leader_tier.as_str() {
            "New" => Tier::Tl0,
            "Validated" => Tier::Tl1,
            "Available" => Tier::Tl2,
            "Committed" => Tier::Tl3,
            "Reliable" => Tier::Tl4,
            "Trusted" => Tier::Tl5,
            other => panic!("unexpected leader tier: {other}"),
        };
        let tier_seed = vrf::derive_tier_seed(
            &proposer_candidate.address,
            proposer_candidate.timetoke_hours,
        );
        let input = PoseidonVrfInput::new(seed, epoch, tier_seed);
        let randomness = Natural::from_str(&block.header.randomness).expect("parse randomness");
        let proof = VrfProof {
            randomness,
            preoutput: block.header.vrf_preoutput.clone(),
            proof: block.header.vrf_proof.clone(),
        };
        let public_key = if block.header.vrf_public_key.trim().is_empty() {
            None
        } else {
            Some(vrf_public_key_from_hex(&block.header.vrf_public_key).expect("vrf key"))
        };
        let mut pool = VrfSubmissionPool::new();
        pool.insert(VrfSubmission {
            address: block.header.proposer.clone(),
            public_key,
            input,
            proof,
            tier,
            timetoke_hours: block.header.leader_timetoke,
        });

        let mut round = ConsensusRound::new(
            block.header.height,
            block.consensus.round,
            seed,
            node_b.inner.config.validator_set_size(),
            validators,
            observers,
            &pool,
        );
        round.set_block_hash(block.hash.clone());
        for record in &block.consensus.pre_votes {
            round
                .register_prevote(&record.vote)
                .expect("register prevote");
        }
        for record in &block.consensus.pre_commits {
            round
                .register_precommit(&record.vote)
                .expect("register precommit");
        }
        assert!(round.commit_reached());

        let mut tampered_block = block.clone();
        let tampered_state_proof = match tampered_block.stark.state_proof.clone() {
            ChainProof::Stwo(mut stark) => {
                stark.commitment_proof = CommitmentSchemeProofData::default();
                stark.fri_proof = FriProof::default();
                ChainProof::Stwo(stark)
            }
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => panic!("expected STWO state proof"),
        };
        tampered_block.stark.state_proof = tampered_state_proof;

        let previous_block = if tampered_block.header.height == 0 {
            None
        } else {
            node_b
                .inner
                .storage
                .read_block(tampered_block.header.height - 1)
                .expect("read previous block")
        };

        let tip_before = node_b.inner.storage.tip().expect("tip before");
        let chain_tip_before = node_b.inner.chain_tip.read().clone();
        let epoch_before = node_b.inner.ledger.current_epoch();

        let result = node_b.inner.finalize_block(FinalizationContext::External(
            ExternalFinalizationContext {
                round,
                block: tampered_block.clone(),
                previous_block,
                archived_votes: tampered_block.bft_votes.clone(),
                peer_id: None,
                expected_proposer: tampered_block.header.proposer.clone(),
                expected_weight: 0.0,
                epoch: epoch_before,
            },
        ));

        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("expected tampered block to be rejected"),
        };
        match err {
            ChainError::Crypto(message) => {
                assert!(message.contains("fri proof mismatch"));
            }
            other => panic!("unexpected error: {other:?}"),
        }

        assert!(logs_contain("external block proof verification failed"));

        let tip_after = node_b.inner.storage.tip().expect("tip after");
        match (tip_before, tip_after) {
            (None, None) => {}
            (Some(before), Some(after)) => {
                assert_eq!(after.height, before.height);
                assert_eq!(after.new_state_root, before.new_state_root);
            }
            (before, after) => {
                panic!("tip changed after failed finalization: before={before:?} after={after:?}")
            }
        }

        let chain_tip_after = node_b.inner.chain_tip.read().clone();
        assert_eq!(chain_tip_after.height, chain_tip_before.height);
        assert_eq!(chain_tip_after.last_hash, chain_tip_before.last_hash);

        assert_eq!(node_b.inner.ledger.current_epoch(), epoch_before);

        let missing = node_b
            .inner
            .storage
            .read_block(tampered_block.header.height)
            .expect("read tampered height");
        assert!(missing.is_none());
    }
}

#[cfg(test)]
mod double_spend_tests {
    use super::is_double_spend;
    use crate::errors::ChainError;

    #[test]
    fn detects_spent_input_error() {
        let err = ChainError::Transaction("transaction input already spent".into());
        assert!(is_double_spend(&err));
    }

    #[test]
    fn detects_missing_input_error() {
        let err = ChainError::Transaction("transaction input not found".into());
        assert!(is_double_spend(&err));
    }

    #[test]
    fn ignores_other_transaction_errors() {
        let err = ChainError::Transaction("insufficient balance".into());
        assert!(!is_double_spend(&err));
    }

    #[test]
    fn ignores_non_transaction_errors() {
        let err = ChainError::Config("some other error".into());
        assert!(!is_double_spend(&err));
    }
}

impl NodeHandle {
    pub async fn stop(&self) -> ChainResult<()> {
        self.inner.stop().await
    }

    pub fn subscribe_pipeline(&self) -> broadcast::Receiver<PipelineObservation> {
        self.inner.subscribe_pipeline()
    }

    pub fn finalize_block(
        &self,
        ctx: ExternalFinalizationContext,
    ) -> ChainResult<FinalizationOutcome> {
        self.inner
            .finalize_block(FinalizationContext::External(ctx))
    }

    #[instrument(
        name = "node.submit_transaction",
        skip(self, bundle),
        fields(hash = tracing::field::Empty),
        err
    )]
    pub fn submit_transaction(&self, bundle: TransactionProofBundle) -> ChainResult<String> {
        let hash = bundle.hash();
        Span::current().record("hash", &display(&hash));
        self.inner.submit_transaction(bundle)
    }

    pub fn subscribe_witness_gossip(&self, topic: GossipTopic) -> broadcast::Receiver<Vec<u8>> {
        self.inner.subscribe_witness_gossip(topic)
    }

    pub fn p2p_handle(&self) -> Option<P2pHandle> {
        self.inner.p2p_handle()
    }

    pub async fn attach_p2p(&self, handle: P2pHandle) {
        self.inner.initialise_p2p_runtime(handle, None).await;
    }

    pub fn fanout_witness_gossip(&self, topic: GossipTopic, payload: &[u8]) {
        self.inner.ingest_witness_bytes(topic, payload.to_vec());
    }

    pub fn submit_identity(&self, request: AttestedIdentityRequest) -> ChainResult<String> {
        self.inner.submit_identity(request)
    }

    #[instrument(
        name = "node.consensus.submit_vote",
        skip(self, vote),
        fields(
            height = vote.vote.height,
            round = vote.vote.round,
            voter = %vote.vote.voter,
            kind = ?vote.vote.kind
        )
    )]
    pub fn submit_vote(
        &self,
        vote: SignedBftVote,
        received_at: Option<SystemTime>,
    ) -> ChainResult<String> {
        self.inner.submit_vote(vote, received_at)
    }

    pub fn submit_block_proposal(&self, block: Block) -> ChainResult<String> {
        self.inner.submit_block_proposal(block)
    }

    pub fn submit_vrf_submission(&self, submission: VrfSubmission) -> ChainResult<()> {
        self.inner.submit_vrf_submission(submission)
    }

    pub fn submit_uptime_proof(&self, proof: UptimeProof) -> ChainResult<u64> {
        self.inner.submit_uptime_proof(proof)
    }

    pub fn get_block(&self, height: u64) -> ChainResult<Option<Block>> {
        self.inner.get_block(height)
    }

    pub fn latest_block(&self) -> ChainResult<Option<Block>> {
        self.inner.latest_block()
    }

    pub fn get_account(&self, address: &str) -> ChainResult<Option<Account>> {
        self.inner.get_account(address)
    }

    pub fn node_status(&self) -> ChainResult<NodeStatus> {
        self.inner.node_status()
    }

    pub fn verifier_metrics(&self) -> VerifierMetricsSnapshot {
        self.inner.verifiers.metrics_snapshot()
    }

    pub fn mempool_status(&self) -> ChainResult<MempoolStatus> {
        self.inner.mempool_status()
    }

    pub fn update_mempool_limit(&self, limit: usize) -> ChainResult<()> {
        self.inner.update_mempool_limit(limit)
    }

    pub fn mempool_limit(&self) -> usize {
        self.inner.mempool_limit()
    }

    pub fn mempool_latency_ms(&self) -> ChainResult<Option<u128>> {
        self.inner.mempool_latency_ms()
    }

    #[cfg(feature = "integration")]
    pub fn drop_pending_transaction_metadata(&self, hash: &str) {
        self.inner.pending_transaction_metadata.write().remove(hash);
    }

    #[cfg(feature = "integration")]
    pub fn seed_orphaned_transaction_metadata(&self, bundle: TransactionProofBundle) {
        let hash = bundle.hash();
        let metadata = PendingTransactionMetadata::from_bundle(&bundle);
        self.inner
            .pending_transaction_metadata
            .write()
            .insert(hash, metadata);
    }

    #[cfg(feature = "integration")]
    pub fn pending_transaction_metadata_hashes(&self) -> Vec<String> {
        self.inner
            .pending_transaction_metadata
            .read()
            .keys()
            .cloned()
            .collect()
    }

    pub fn queue_weights(&self) -> QueueWeightsConfig {
        self.inner.queue_weights()
    }

    pub fn update_queue_weights(&self, weights: QueueWeightsConfig) -> ChainResult<()> {
        self.inner.update_queue_weights(weights)
    }

    pub fn rollout_status(&self) -> RolloutStatus {
        self.inner.rollout_status()
    }

    pub fn consensus_status(&self) -> ChainResult<ConsensusStatus> {
        self.inner.consensus_status()
    }

    pub fn consensus_proof_status(&self) -> ChainResult<Option<ConsensusProofStatus>> {
        self.inner.consensus_proof_status()
    }

    pub fn vrf_threshold(&self) -> VrfThresholdStatus {
        self.inner.vrf_threshold()
    }

    pub fn vrf_status(&self, address: &str) -> ChainResult<VrfStatus> {
        self.inner.vrf_status(address)
    }

    pub fn vrf_history(&self, epoch: Option<u64>) -> ChainResult<Vec<VrfHistoryRecord>> {
        self.inner.vrf_history(epoch)
    }

    pub fn slashing_events(&self, limit: usize) -> ChainResult<Vec<SlashingEvent>> {
        self.inner.slashing_events(limit)
    }

    pub fn reputation_audit(&self, address: &str) -> ChainResult<Option<ReputationAudit>> {
        self.inner.reputation_audit(address)
    }

    pub fn audit_slashing_stream(&self, limit: usize) -> ChainResult<Vec<SlashingEvent>> {
        self.inner.recent_slashing_audits(limit)
    }

    pub fn audit_reputation_stream(&self, limit: usize) -> ChainResult<Vec<ReputationAudit>> {
        self.inner.recent_reputation_audits(limit)
    }

    pub fn slash_validator(&self, address: &str, reason: SlashingReason) -> ChainResult<()> {
        self.inner.slash_validator(address, reason)
    }

    pub fn bft_membership(&self) -> ChainResult<BftMembership> {
        self.inner.bft_membership()
    }

    pub fn timetoke_snapshot(&self) -> ChainResult<Vec<TimetokeRecord>> {
        self.inner.timetoke_snapshot()
    }

    pub fn sync_timetoke_records(&self, records: Vec<TimetokeRecord>) -> ChainResult<Vec<Address>> {
        self.inner.sync_timetoke_records(records)
    }

    pub fn address(&self) -> &str {
        &self.inner.address
    }

    pub fn storage(&self) -> Storage {
        self.inner.storage.clone()
    }

    pub fn vrf_secrets_config(&self) -> SecretsConfig {
        self.inner.config.secrets.clone()
    }

    pub fn vrf_key_path(&self) -> PathBuf {
        self.inner.config.vrf_key_path.clone()
    }

    pub fn state_root(&self) -> ChainResult<String> {
        Ok(hex::encode(self.inner.ledger.state_root()))
    }

    pub fn block_proofs(&self, height: u64) -> ChainResult<Option<BlockProofArtifactsView>> {
        self.inner.block_proofs(height)
    }

    pub fn validator_telemetry(&self) -> ChainResult<ValidatorTelemetryView> {
        self.inner.validator_telemetry()
    }

    pub async fn meta_telemetry_snapshot(&self) -> ChainResult<MetaTelemetryReport> {
        self.inner.meta_telemetry_snapshot().await
    }

    pub async fn p2p_censorship_report(&self) -> ChainResult<P2pCensorshipReport> {
        self.inner.p2p_censorship_report().await
    }

    pub async fn reload_access_lists(
        &self,
        allowlist: Vec<AllowlistedPeer>,
        blocklist: Vec<NetworkPeerId>,
    ) -> ChainResult<()> {
        self.inner.reload_access_lists(allowlist, blocklist).await
    }

    pub fn request_pruning_cancellation(&self) {
        self.inner.request_pruning_cancellation();
    }

    pub fn run_pruning_cycle(
        &self,
        chunk_size: usize,
        retention_depth: u64,
    ) -> ChainResult<PruningCycleSummary> {
        self.inner.run_pruning_cycle(chunk_size, retention_depth)
    }

    pub fn pruning_job_status(&self) -> Option<PruningJobStatus> {
        self.inner.pruning_job_status()
    }

    pub fn update_pruning_status(&self, status: Option<PruningJobStatus>) {
        self.inner.update_pruning_status(status);
    }

    pub fn state_sync_plan(&self, chunk_size: usize) -> ChainResult<StateSyncPlan> {
        self.inner.state_sync_plan(chunk_size)
    }

    pub fn state_sync_server(&self) -> Option<Arc<StateSyncServer>> {
        self.inner.state_sync_server()
    }

    pub fn snapshot_breaker_status(&self) -> SnapshotBreakerStatus {
        self.inner.snapshot_breaker.status()
    }

    pub fn reset_snapshot_breaker(&self) {
        self.inner.snapshot_breaker.reset();
    }

    pub fn network_state_sync_plan(&self, chunk_size: usize) -> ChainResult<NetworkStateSyncPlan> {
        self.inner.network_state_sync_plan(chunk_size)
    }

    pub fn network_state_sync_chunk(
        &self,
        chunk_size: usize,
        start_height: u64,
    ) -> ChainResult<NetworkStateSyncChunk> {
        self.inner
            .network_state_sync_chunk(chunk_size, start_height)
    }

    pub fn reconstruction_plan(&self, start_height: u64) -> ChainResult<ReconstructionPlan> {
        self.inner.reconstruction_plan(start_height)
    }

    pub fn verify_proof_chain(&self) -> ChainResult<()> {
        self.inner.verify_proof_chain()
    }

    pub fn reconstruct_block<P: PayloadProvider>(
        &self,
        height: u64,
        provider: &P,
    ) -> ChainResult<Block> {
        self.inner.reconstruct_block(height, provider)
    }

    pub fn reconstruct_range<P: PayloadProvider>(
        &self,
        start_height: u64,
        end_height: u64,
        provider: &P,
    ) -> ChainResult<Vec<Block>> {
        self.inner
            .reconstruct_range(start_height, end_height, provider)
    }

    pub fn execute_reconstruction_plan<P: PayloadProvider>(
        &self,
        plan: &ReconstructionPlan,
        provider: &P,
    ) -> ChainResult<Vec<Block>> {
        self.inner.execute_reconstruction_plan(plan, provider)
    }

    pub fn stream_state_sync_chunks(
        &self,
        store: &SnapshotStore,
        root: &Hash,
    ) -> ChainResult<SnapshotChunkStream> {
        self.inner.stream_state_sync_chunks(store, root)
    }

    pub fn state_sync_chunk_by_index(
        &self,
        store: &SnapshotStore,
        root: &Hash,
        index: u64,
    ) -> ChainResult<SnapshotChunk> {
        self.inner.state_sync_chunk_by_index(store, root, index)
    }

    pub(crate) fn state_sync_session_chunk(
        &self,
        index: u32,
    ) -> Result<SnapshotChunk, StateSyncChunkError> {
        self.inner.state_sync_session_chunk(index)
    }

    pub(crate) fn maybe_reset_state_sync_session(
        &self,
        snapshot_root: &Hash,
        chunk_size: usize,
        total_chunks: usize,
    ) {
        self.inner
            .maybe_reset_state_sync_session(snapshot_root, chunk_size, total_chunks);
    }

    pub(crate) fn reset_state_sync_session_cache(&self) {
        self.inner.reset_state_sync_session();
    }

    pub(crate) fn replace_state_sync_session_cache(&self, cache: StateSyncSessionCache) {
        self.inner.replace_state_sync_session(cache);
    }

    #[cfg(any(test, feature = "integration"))]
    pub fn install_state_sync_session_cache_for_tests(&self, cache: StateSyncSessionCache) {
        self.replace_state_sync_session_cache(cache);
    }

    pub(crate) fn configure_state_sync_session_cache(
        &self,
        chunk_size: Option<usize>,
        total_chunks: Option<usize>,
        snapshot_root: Option<Hash>,
    ) {
        self.inner
            .configure_state_sync_session(chunk_size, total_chunks, snapshot_root);
    }

    pub(crate) fn record_state_sync_event(&self, event: LightClientVerificationEvent) {
        self.inner.record_state_sync_event(event);
    }

    pub(crate) fn mark_state_sync_chunk_served(&self, index: u64) {
        self.inner.mark_state_sync_chunk_served(index);
    }

    pub(crate) fn update_state_sync_verification_report(
        &self,
        report: StateSyncVerificationReport,
    ) {
        self.inner.update_state_sync_verification_report(report);
    }

    pub(crate) fn prepare_state_sync_session(
        &self,
        chunk_size: usize,
    ) -> ChainResult<StateSyncVerificationStatus> {
        self.inner.ensure_state_sync_session(chunk_size)
    }

    pub(crate) fn state_sync_session_snapshot(&self) -> StateSyncSessionCache {
        self.inner.state_sync_session_snapshot()
    }

    pub fn subscribe_light_client_heads(
        &self,
    ) -> ChainResult<watch::Receiver<Option<LightClientHead>>> {
        self.inner.subscribe_light_client_heads()
    }

    pub fn latest_light_client_head(&self) -> ChainResult<Option<LightClientHead>> {
        self.inner.latest_light_client_head()
    }
}

impl NodeInner {
    fn request_pruning_cancellation(&self) {
        self.pruning_cancelled.store(true, Ordering::SeqCst);
    }

    fn subscribe_witness_gossip(&self, topic: GossipTopic) -> broadcast::Receiver<Vec<u8>> {
        self.witness_channels.subscribe(topic)
    }

    fn emit_witness_bytes(&self, topic: GossipTopic, payload: Vec<u8>) {
        self.witness_channels.publish_local(topic, payload);
    }

    #[instrument(
        name = "node.gossip.emit_witness",
        skip(self, payload),
        fields(topic = ?topic)
    )]
    fn emit_witness_json<T: Serialize>(&self, topic: GossipTopic, payload: &T) {
        if matches!(topic, GossipTopic::Blocks | GossipTopic::Votes) {
            self.consensus_telemetry
                .record_witness_event(format!("{topic:?}"));
            self.update_runtime_metrics();
        }
        match serde_json::to_vec(payload) {
            Ok(bytes) => self.emit_witness_bytes(topic, bytes),
            Err(err) => debug!(?err, ?topic, "failed to encode witness gossip payload"),
        }
    }

    fn persist_timetoke_accounts(&self, addresses: &[Address]) -> ChainResult<()> {
        for address in addresses {
            if let Some(account) = self.ledger.get_account(address) {
                self.storage.persist_account(&account)?;
            }
        }
        Ok(())
    }

    fn emit_timetoke_meta(&self, records: &[TimetokeRecord]) {
        if records.is_empty() {
            return;
        }
        let commitments = self.ledger.global_commitments();
        let payload = TimetokeDeltaBroadcast {
            timetoke_root: hex::encode(commitments.timetoke_root),
            records: records.to_vec(),
        };
        self.emit_witness_json(GossipTopic::Meta, &payload);
    }

    fn apply_remote_timetoke_delta(
        &self,
        peer: &PeerId,
        delta: TimetokeDeltaBroadcast,
    ) -> ChainResult<()> {
        let updated = self.ledger.sync_timetoke_records(&delta.records)?;
        self.persist_timetoke_accounts(&updated)?;
        if !updated.is_empty() {
            if let Ok(bytes) = serde_json::to_vec(&updated) {
                self.ingest_witness_bytes(GossipTopic::Snapshots, bytes);
            }
        }
        let commitments = self.ledger.global_commitments();
        let local_root = hex::encode(commitments.timetoke_root);
        if local_root != delta.timetoke_root {
            warn!(
                target: "node",
                %peer,
                expected = %delta.timetoke_root,
                actual = %local_root,
                "timetoke root mismatch after applying delta"
            );
            self.runtime_metrics
                .record_timetoke_root_mismatch("gossip_delta", Some(peer.to_base58()));
        }
        Ok(())
    }

    fn emit_state_sync_artifacts(&self) {
        if !self.config.rollout.feature_gates.reconstruction {
            return;
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        let plan = match engine.state_sync_plan(DEFAULT_STATE_SYNC_CHUNK) {
            Ok(plan) => plan,
            Err(err) => {
                warn!(?err, "failed to build state sync plan for gossip");
                return;
            }
        };
        let summary = match plan.to_network_plan() {
            Ok(summary) => summary,
            Err(err) => {
                warn!(?err, "failed to encode state sync plan for gossip");
                return;
            }
        };
        self.emit_witness_json(GossipTopic::Snapshots, &summary);

        match plan.chunk_messages() {
            Ok(chunks) => {
                for chunk in chunks {
                    self.emit_witness_json(GossipTopic::Snapshots, &chunk);
                }
            }
            Err(err) => warn!(?err, "failed to encode state sync chunks for gossip"),
        }

        match plan.light_client_messages() {
            Ok(updates) => {
                for update in updates {
                    self.emit_witness_json(GossipTopic::Snapshots, &update);
                }
            }
            Err(err) => warn!(?err, "failed to encode light client updates for gossip"),
        }
    }

    fn ingest_witness_bytes(&self, topic: GossipTopic, payload: Vec<u8>) {
        self.witness_channels.ingest_remote(topic, payload);
    }

    fn attach_witness_publisher(&self, publisher: mpsc::Sender<(GossipTopic, Vec<u8>)>) {
        self.witness_channels.attach_publisher(publisher);
    }

    fn runtime_config(self: &Arc<Self>) -> ChainResult<P2pRuntimeConfig> {
        let mut config = P2pRuntimeConfig::from(&self.config);
        let profile = self.network_identity_profile()?;
        config.identity = Some(RuntimeIdentityProfile::from(profile));
        config.metrics = self.runtime_metrics.clone();
        config.snapshot_provider = Some(RuntimeSnapshotProvider::new(
            Arc::clone(self),
            self.config.snapshot_sizing.clone(),
            self.snapshot_breaker.clone(),
        ));
        Ok(config)
    }

    fn record_proof_cache_metrics(&self, snapshot: &ProofCacheMetricsSnapshot) {
        let mut checkpoint = self.cache_metrics_checkpoint.lock();
        let delta_hits = snapshot.hits.saturating_sub(checkpoint.hits);
        let delta_misses = snapshot.misses.saturating_sub(checkpoint.misses);
        let delta_evictions = snapshot.evictions.saturating_sub(checkpoint.evictions);

        *checkpoint = snapshot.clone();

        let proof_metrics = self.runtime_metrics.proofs();
        proof_metrics.record_cache_depths(
            "gossip-proof-cache",
            snapshot.backend.as_deref(),
            snapshot.queue_depth,
            snapshot.max_queue_depth,
        );
        proof_metrics.record_cache_io_latencies(
            "gossip-proof-cache",
            snapshot.backend.as_deref(),
            snapshot.last_load_latency_ms,
            snapshot.last_persist_latency_ms,
        );
        if delta_hits == 0 && delta_misses == 0 && delta_evictions == 0 {
            return;
        }

        proof_metrics.record_cache_events(
            "gossip-proof-cache",
            snapshot.backend.as_deref(),
            delta_hits,
            delta_misses,
            delta_evictions,
        );
    }

    fn runtime_metrics(&self) -> ChainResult<P2pMetrics> {
        let status = self.node_status()?;
        let reputation_score = self
            .ledger
            .get_account(&self.address)
            .map(|account| account.reputation.score)
            .unwrap_or_default();
        let consensus_snapshot = self.consensus_telemetry.snapshot();
        let verifier_metrics = self.verifiers.metrics_snapshot();
        self.record_proof_cache_metrics(&verifier_metrics.cache);
        self.runtime_metrics.record_block_height(status.height);
        Ok(P2pMetrics {
            block_height: status.height,
            block_hash: status.last_hash,
            transaction_count: status.pending_transactions,
            reputation_score,
            verifier_metrics,
            round_latencies_ms: consensus_snapshot.round_latencies_ms,
            leader_changes: consensus_snapshot.leader_changes,
            quorum_latency_ms: consensus_snapshot.quorum_latency_ms,
            witness_events: consensus_snapshot.witness_events,
            slashing_events: consensus_snapshot.slashing_events,
            failed_votes: consensus_snapshot.failed_votes,
        })
    }

    fn sync_epoch_with_metrics(&self, height: u64) {
        self.ledger.sync_epoch_for_height(height);
        let epoch = self.ledger.current_epoch();
        let previous = self.inner.last_epoch.swap(epoch, Ordering::SeqCst);
        if previous != epoch {
            self.inner
                .consensus_telemetry
                .record_validator_change(epoch, height);
        }
    }

    fn update_runtime_metrics(&self) {
        if let Some(handle) = self.p2p_runtime.lock().clone() {
            match self.runtime_metrics() {
                Ok(metrics) => handle.update_metrics(metrics),
                Err(err) => debug!(?err, "failed to collect runtime metrics"),
            }
        }
    }

    fn subscribe_pipeline(&self) -> broadcast::Receiver<PipelineObservation> {
        self.pipeline_events.subscribe()
    }

    fn publish_pipeline_event(&self, event: PipelineObservation) {
        let _ = self.pipeline_events.send(event);
    }

    async fn meta_telemetry_snapshot(&self) -> ChainResult<MetaTelemetryReport> {
        let handle = self
            .p2p_handle()
            .ok_or_else(|| ChainError::Config("p2p runtime not initialised".into()))?;
        handle
            .meta_telemetry_snapshot()
            .await
            .map_err(|err| ChainError::Config(format!("failed to collect meta telemetry: {err}")))
    }

    async fn p2p_censorship_report(&self) -> ChainResult<P2pCensorshipReport> {
        let handle = self
            .p2p_handle()
            .ok_or_else(|| ChainError::Config("p2p runtime not initialised".into()))?;
        let snapshot = handle.heuristics_snapshot().await.map_err(|err| {
            ChainError::Config(format!("failed to collect p2p heuristics: {err}"))
        })?;
        let entries = snapshot
            .into_iter()
            .map(|(peer, counters)| P2pCensorshipEntry {
                peer: peer.to_base58(),
                vote_timeouts: counters.vote_timeouts,
                proof_relay_misses: counters.proof_relay_misses,
                gossip_backpressure_events: counters.gossip_backpressure_events,
            })
            .collect();
        Ok(P2pCensorshipReport { entries })
    }

    async fn reload_access_lists(
        &self,
        allowlist: Vec<AllowlistedPeer>,
        blocklist: Vec<NetworkPeerId>,
    ) -> ChainResult<()> {
        let handle = self
            .p2p_handle()
            .ok_or_else(|| ChainError::Config("p2p runtime not initialised".into()))?;
        handle
            .reload_access_lists(allowlist, blocklist)
            .await
            .map_err(|err| ChainError::Config(format!("failed to reload access lists: {err}")))
    }

    fn p2p_handle(&self) -> Option<P2pHandle> {
        self.p2p_runtime.lock().clone()
    }

    async fn initialise_p2p_runtime(
        self: &Arc<Self>,
        handle: P2pHandle,
        runtime_task: Option<JoinHandle<()>>,
    ) {
        {
            let mut slot = self.p2p_runtime.lock();
            *slot = Some(handle.clone());
        }
        let (publisher_tx, mut publisher_rx) = mpsc::channel::<(GossipTopic, Vec<u8>)>(128);
        self.attach_witness_publisher(publisher_tx);
        self.update_runtime_metrics();

        let mut publish_shutdown = self.subscribe_shutdown();
        let publisher_handle = handle.clone();
        let publisher_span = info_span!("runtime.gossip.publish", component = "witness");
        self.spawn_worker(tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = publish_shutdown.recv() => {
                        match result {
                            Ok(_) | Err(broadcast::error::RecvError::Closed) => break,
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        }
                    }
                    maybe_message = publisher_rx.recv() => {
                        let Some((topic, payload)) = maybe_message else {
                            break;
                        };
                        if let Err(err) = publisher_handle.publish_gossip(topic, payload).await {
                            warn!(?err, ?topic, "failed to publish witness gossip");
                        }
                    }
                }
            }
        }
        .instrument(publisher_span)))
        .await;

        let mut event_shutdown = self.subscribe_shutdown();
        let mut events = handle.subscribe();
        let ingest = Arc::clone(self);
        let event_span = info_span!("runtime.gossip.ingest", component = "network_events");
        self.spawn_worker(tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = event_shutdown.recv() => {
                        match result {
                            Ok(_) | Err(broadcast::error::RecvError::Closed) => break,
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        }
                    }
                    event = events.recv() => match event {
                        Ok(NodeEvent::BlockProposal { peer, block }) => {
                            if let Err(err) = ingest.submit_block_proposal(block) {
                                warn!(?err, %peer, "failed to ingest block proposal from gossip");
                            }
                        }
                        Ok(NodeEvent::BlockRejected { peer, block, reason }) => {
                            ingest.handle_invalid_block_gossip(&peer, block, &reason);
                        }
                        Ok(NodeEvent::Vote {
                            peer,
                            vote,
                            received_at,
                        }) => {
                            if let Err(err) = ingest.submit_vote(vote, Some(received_at)) {
                                warn!(?err, %peer, "failed to ingest vote from gossip");
                            }
                        }
                        Ok(NodeEvent::VoteRejected { peer, vote, reason }) => {
                            ingest.handle_invalid_vote_gossip(&peer, vote, &reason);
                        }
                        Ok(NodeEvent::VrfSubmission { peer, submission }) => {
                            if let Err(err) = ingest.submit_vrf_submission(submission) {
                                warn!(?err, %peer, "failed to ingest VRF submission from gossip");
                            }
                        }
                        Ok(NodeEvent::Evidence { evidence, .. }) => {
                            ingest.apply_evidence(evidence);
                        }
                        Ok(NodeEvent::TimetokeDelta { peer, delta }) => {
                            if let Err(err) = ingest.apply_remote_timetoke_delta(&peer, delta) {
                                warn!(?err, %peer, "failed to apply timetoke delta from gossip");
                            }
                        }
                        Ok(NodeEvent::Gossip { topic, data, .. }) => {
                            ingest.ingest_witness_bytes(topic, data);
                        }
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(skipped, "lagged on gossip event stream");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                }
            }
        }
        .instrument(event_span)))
        .await;

        if let Some(task) = runtime_task {
            self.spawn_worker(task).await;
        }
    }

    fn mempool_limit(&self) -> usize {
        self.mempool_limit.load(Ordering::Relaxed)
    }

    fn update_mempool_limit(&self, limit: usize) -> ChainResult<()> {
        if limit == 0 {
            return Err(ChainError::Config(
                "node configuration requires mempool_limit to be greater than 0".into(),
            ));
        }
        self.mempool_limit.store(limit, Ordering::SeqCst);
        Ok(())
    }

    fn mempool_latency_ms(&self) -> ChainResult<Option<u128>> {
        let metadata = self.pending_transaction_metadata.read();
        Ok(metadata
            .values()
            .map(|entry| entry.enqueued_at.elapsed().as_millis())
            .max())
    }

    fn queue_weights(&self) -> QueueWeightsConfig {
        self.queue_weights.read().clone()
    }

    fn update_queue_weights(&self, weights: QueueWeightsConfig) -> ChainResult<()> {
        weights.validate()?;
        *self.queue_weights.write() = weights;
        Ok(())
    }

    fn record_stwo_proof_size(
        &self,
        proof_kind: ProofVerificationKind,
        circuit: &str,
        proof: &ChainProof,
        proof_bytes: Option<&[u8]>,
    ) {
        if !matches!(proof, ChainProof::Stwo(_)) {
            return;
        }

        let size = proof_bytes
            .map(|bytes| bytes.len())
            .or_else(|| serde_json::to_vec(proof).ok().map(Vec::len))
            .and_then(|len| u64::try_from(len).ok());

        if let Some(bytes) = size {
            let proof_metrics = self.runtime_metrics.proofs();
            proof_metrics.observe_verification_total_bytes(
                ProofVerificationBackend::Stwo,
                proof_kind,
                circuit,
                bytes,
            );
            proof_metrics.observe_verification_total_bytes_by_result(
                ProofVerificationBackend::Stwo,
                proof_kind,
                circuit,
                ProofVerificationOutcome::Ok,
                bytes,
            );
        }
    }

    fn record_stwo_outcome(
        &self,
        proof_kind: ProofVerificationKind,
        circuit: &str,
        outcome: ProofVerificationOutcome,
    ) {
        self.runtime_metrics.proofs().record_verification_outcome(
            ProofVerificationBackend::Stwo,
            proof_kind,
            circuit,
            outcome,
        );
    }

    fn log_external_block_verification_failure(
        labels: &ProofLogLabels,
        proposer: &Address,
        backend: ProofVerificationBackend,
        proof_kind: ProofVerificationKind,
        err: &ChainError,
    ) {
        let resolved = labels.resolve(proof_kind);

        warn!(
            target = "proofs",
            peer_id = resolved.peer_id,
            height = ?resolved.height,
            slot = ?resolved.slot,
            proof_id = resolved.proof_id,
            circuit = resolved.circuit,
            proposer = %proposer,
            ?err,
            error = %err,
            backend = backend.as_str(),
            proof_backend = backend.as_str(),
            proof_kind = proof_kind.as_str(),
            "external block proof verification failed"
        );
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn verify_rpp_stark_with_metrics(
        &self,
        proof_kind: ProofVerificationKind,
        proof: &ChainProof,
        labels: ProofLogLabels,
    ) -> ChainResult<RppStarkVerificationReport> {
        let started = Instant::now();
        let resolved_labels = labels.resolve(proof_kind);
        match self
            .verifiers
            .verify_rpp_stark_with_report_raw(proof, proof_kind.as_str())
        {
            Ok(report) => {
                self.emit_rpp_stark_metrics(
                    ProofVerificationBackend::RppStark,
                    proof_kind,
                    proof,
                    &report,
                    started.elapsed(),
                    &resolved_labels,
                );
                Ok(report)
            }
            Err(err) => {
                self.emit_rpp_stark_failure_metrics(
                    ProofVerificationBackend::RppStark,
                    proof_kind,
                    proof,
                    started.elapsed(),
                    &err,
                    &resolved_labels,
                );
                Err(self.verifiers.map_rpp_stark_error(proof_kind.as_str(), err))
            }
        }
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn emit_rpp_stark_metrics(
        &self,
        backend: ProofVerificationBackend,
        proof_kind: ProofVerificationKind,
        proof: &ChainProof,
        report: &RppStarkVerificationReport,
        duration: Duration,
        labels: &ProofLogLabelValues,
    ) {
        let flags = report.flags();
        let proof_metrics = self.runtime_metrics.proofs();
        let outcome = ProofVerificationOutcome::from_bool(report.is_verified());
        let resolved = labels;
        proof_metrics.observe_verification(backend, proof_kind, resolved.circuit, duration);
        if let Some(stage_timings) = report.stage_timings() {
            proof_metrics.observe_verification_stage_duration(
                backend,
                proof_kind,
                resolved.circuit,
                ProofVerificationStage::Parse,
                stage_timings.parse,
            );
            proof_metrics.observe_verification_stage_duration(
                backend,
                proof_kind,
                resolved.circuit,
                ProofVerificationStage::Merkle,
                stage_timings.merkle,
            );
            proof_metrics.observe_verification_stage_duration(
                backend,
                proof_kind,
                resolved.circuit,
                ProofVerificationStage::Fri,
                stage_timings.fri,
            );
            let accumulated = stage_timings.total();
            let adapter_duration = duration.saturating_sub(accumulated);
            proof_metrics.observe_verification_stage_duration(
                backend,
                proof_kind,
                resolved.circuit,
                ProofVerificationStage::Adapter,
                adapter_duration,
            );
        }
        let snapshot = record_rpp_stark_size_metrics(
            proof_metrics,
            backend,
            proof_kind,
            resolved.circuit,
            proof,
            outcome,
        );
        if snapshot.is_none() {
            proof_metrics.observe_verification_total_bytes(
                backend,
                proof_kind,
                resolved.circuit,
                report.total_bytes(),
            );
            proof_metrics.observe_verification_total_bytes_by_result(
                backend,
                proof_kind,
                resolved.circuit,
                outcome,
                report.total_bytes(),
            );
        }
        record_rpp_stark_stage_checks(proof_metrics, backend, proof_kind, resolved.circuit, flags);
        proof_metrics.record_verification_outcome(backend, proof_kind, resolved.circuit, outcome);

        let backend_name = backend.as_str();
        let verify_duration_ms = duration.as_millis().min(u128::from(u64::MAX)) as u64;
        if let Some(snapshot) = snapshot {
            info!(
                target = "proofs",
                peer_id = resolved.peer_id,
                height = ?resolved.height,
                slot = ?resolved.slot,
                proof_id = resolved.proof_id,
                circuit = resolved.circuit,
                backend = backend_name,
                proof_backend = "rpp-stark",
                proof_kind = proof_kind.as_str(),
                valid = report.is_verified(),
                params_ok = flags.params(),
                public_ok = flags.public(),
                merkle_ok = flags.merkle(),
                fri_ok = flags.fri(),
                composition_ok = flags.composition(),
                proof_bytes = snapshot.proof_bytes,
                size_bucket = snapshot.size_bucket,
                params_bytes = snapshot.params_bytes,
                public_inputs_bytes = snapshot.public_inputs_bytes,
                payload_bytes = snapshot.payload_bytes,
                verify_duration_ms,
                trace_queries = ?report.trace_query_indices(),
                report = %report,
                "rpp-stark proof verification"
            );
            info!(
                target = "telemetry",
                peer_id = resolved.peer_id,
                height = ?resolved.height,
                slot = ?resolved.slot,
                proof_id = resolved.proof_id,
                circuit = resolved.circuit,
                backend = backend_name,
                proof_backend = "rpp-stark",
                proof_kind = proof_kind.as_str(),
                valid = report.is_verified(),
                params_ok = flags.params(),
                public_ok = flags.public(),
                merkle_ok = flags.merkle(),
                fri_ok = flags.fri(),
                composition_ok = flags.composition(),
                proof_bytes = snapshot.proof_bytes,
                size_bucket = snapshot.size_bucket,
                params_bytes = snapshot.params_bytes,
                public_inputs_bytes = snapshot.public_inputs_bytes,
                payload_bytes = snapshot.payload_bytes,
                verify_duration_ms,
                "rpp-stark proof verification"
            );
        } else {
            let proof_bytes = report.total_bytes();
            info!(
                target = "proofs",
                peer_id = resolved.peer_id,
                height = ?resolved.height,
                slot = ?resolved.slot,
                proof_id = resolved.proof_id,
                circuit = resolved.circuit,
                backend = backend_name,
                proof_backend = "rpp-stark",
                proof_kind = proof_kind.as_str(),
                valid = report.is_verified(),
                params_ok = flags.params(),
                public_ok = flags.public(),
                merkle_ok = flags.merkle(),
                fri_ok = flags.fri(),
                composition_ok = flags.composition(),
                proof_bytes,
                size_bucket = proof_size_bucket(proof_bytes),
                verify_duration_ms,
                trace_queries = ?report.trace_query_indices(),
                report = %report,
                "rpp-stark proof verification"
            );
            info!(
                target = "telemetry",
                peer_id = resolved.peer_id,
                height = ?resolved.height,
                slot = ?resolved.slot,
                proof_id = resolved.proof_id,
                circuit = resolved.circuit,
                backend = backend_name,
                proof_backend = "rpp-stark",
                proof_kind = proof_kind.as_str(),
                valid = report.is_verified(),
                params_ok = flags.params(),
                public_ok = flags.public(),
                merkle_ok = flags.merkle(),
                fri_ok = flags.fri(),
                composition_ok = flags.composition(),
                proof_bytes,
                size_bucket = proof_size_bucket(proof_bytes),
                verify_duration_ms,
                "rpp-stark proof verification"
            );
        }
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn emit_rpp_stark_failure_metrics(
        &self,
        backend: ProofVerificationBackend,
        proof_kind: ProofVerificationKind,
        proof: &ChainProof,
        duration: Duration,
        error: &RppStarkVerifierError,
        labels: &ProofLogLabelValues,
    ) {
        let proof_metrics = self.runtime_metrics.proofs();
        let outcome = ProofVerificationOutcome::Fail;
        proof_metrics.observe_verification(backend, proof_kind, labels.circuit, duration);
        let snapshot = record_rpp_stark_size_metrics(
            proof_metrics,
            backend,
            proof_kind,
            labels.circuit,
            proof,
            outcome,
        );
        match error {
            RppStarkVerifierError::VerificationFailed { failure, report } => {
                let flags = report.flags();
                let incompatibility_reason = rpp_stark_incompatibility_reason(failure);
                if let Some(stage_timings) = report.stage_timings() {
                    proof_metrics.observe_verification_stage_duration(
                        backend,
                        proof_kind,
                        labels.circuit,
                        ProofVerificationStage::Parse,
                        stage_timings.parse,
                    );
                    proof_metrics.observe_verification_stage_duration(
                        backend,
                        proof_kind,
                        labels.circuit,
                        ProofVerificationStage::Merkle,
                        stage_timings.merkle,
                    );
                    proof_metrics.observe_verification_stage_duration(
                        backend,
                        proof_kind,
                        labels.circuit,
                        ProofVerificationStage::Fri,
                        stage_timings.fri,
                    );
                    let adapter_duration = duration.saturating_sub(stage_timings.total());
                    proof_metrics.observe_verification_stage_duration(
                        backend,
                        proof_kind,
                        labels.circuit,
                        ProofVerificationStage::Adapter,
                        adapter_duration,
                    );
                }
                record_rpp_stark_stage_checks(
                    proof_metrics,
                    backend,
                    proof_kind,
                    labels.circuit,
                    flags,
                );
                if let Some(reason) = incompatibility_reason {
                    proof_metrics.record_incompatible_proof(
                        backend,
                        proof_kind,
                        labels.circuit,
                        reason,
                    );
                }
                let verify_duration_ms = duration.as_millis().min(u128::from(u64::MAX)) as u64;
                if let Some(snapshot) = snapshot {
                    warn!(
                        target = "proofs",
                        peer_id = labels.peer_id,
                        height = ?labels.height,
                        slot = ?labels.slot,
                        proof_id = labels.proof_id,
                        circuit = labels.circuit,
                        backend = backend.as_str(),
                        proof_backend = "rpp-stark",
                        proof_kind = proof_kind.as_str(),
                        valid = false,
                        proof_bytes = snapshot.proof_bytes,
                        size_bucket = snapshot.size_bucket,
                        params_bytes = snapshot.params_bytes,
                        public_inputs_bytes = snapshot.public_inputs_bytes,
                        payload_bytes = snapshot.payload_bytes,
                        verify_duration_ms,
                        incompatible_proof = incompatibility_reason.is_some(),
                        incompatibility_reason = incompatibility_reason.unwrap_or("n/a"),
                        error = %failure,
                        "rpp-stark proof verification failed"
                    );
                    warn!(
                        target = "telemetry",
                        peer_id = labels.peer_id,
                        height = ?labels.height,
                        slot = ?labels.slot,
                        proof_id = labels.proof_id,
                        circuit = labels.circuit,
                        backend = backend.as_str(),
                        proof_backend = "rpp-stark",
                        proof_kind = proof_kind.as_str(),
                        valid = false,
                        proof_bytes = snapshot.proof_bytes,
                        size_bucket = snapshot.size_bucket,
                        params_bytes = snapshot.params_bytes,
                        public_inputs_bytes = snapshot.public_inputs_bytes,
                        payload_bytes = snapshot.payload_bytes,
                        verify_duration_ms,
                        incompatible_proof = incompatibility_reason.is_some(),
                        incompatibility_reason = incompatibility_reason.unwrap_or("n/a"),
                        error = %failure,
                        "rpp-stark proof verification failed"
                    );
                } else {
                    warn!(
                        target = "proofs",
                        peer_id = labels.peer_id,
                        height = ?labels.height,
                        slot = ?labels.slot,
                        proof_id = labels.proof_id,
                        circuit = labels.circuit,
                        backend = backend.as_str(),
                        proof_backend = "rpp-stark",
                        proof_kind = proof_kind.as_str(),
                        valid = false,
                        proof_bytes = report.total_bytes(),
                        size_bucket = proof_size_bucket(report.total_bytes()),
                        verify_duration_ms,
                        incompatible_proof = incompatibility_reason.is_some(),
                        incompatibility_reason = incompatibility_reason.unwrap_or("n/a"),
                        error = %failure,
                        "rpp-stark proof verification failed"
                    );
                    warn!(
                        target = "telemetry",
                        peer_id = labels.peer_id,
                        height = ?labels.height,
                        slot = ?labels.slot,
                        proof_id = labels.proof_id,
                        circuit = labels.circuit,
                        backend = backend.as_str(),
                        proof_backend = "rpp-stark",
                        proof_kind = proof_kind.as_str(),
                        valid = false,
                        proof_bytes = report.total_bytes(),
                        size_bucket = proof_size_bucket(report.total_bytes()),
                        verify_duration_ms,
                        incompatible_proof = incompatibility_reason.is_some(),
                        incompatibility_reason = incompatibility_reason.unwrap_or("n/a"),
                        error = %failure,
                        "rpp-stark proof verification failed"
                    );
                }
            }
            other => {
                proof_metrics.observe_verification_stage(
                    backend,
                    proof_kind,
                    classify_rpp_stark_error_stage(other),
                    ProofVerificationOutcome::Fail,
                );
                if snapshot.is_none() {
                    if let Ok(artifact) = proof.expect_rpp_stark() {
                        proof_metrics.observe_verification_total_bytes(
                            backend,
                            proof_kind,
                            u64::try_from(artifact.total_len()).unwrap_or(u64::MAX),
                        );
                        proof_metrics.observe_verification_total_bytes_by_result(
                            backend,
                            proof_kind,
                            outcome,
                            u64::try_from(artifact.total_len()).unwrap_or(u64::MAX),
                        );
                    }
                }
                warn!(
                    target = "proofs",
                    peer_id = labels.peer_id,
                    height = ?labels.height,
                    slot = ?labels.slot,
                    proof_id = labels.proof_id,
                    circuit = labels.circuit,
                    backend = backend.as_str(),
                    proof_backend = "rpp-stark",
                    proof_kind = proof_kind.as_str(),
                    valid = false,
                    verify_duration_ms = duration.as_millis().min(u128::from(u64::MAX)) as u64,
                    error = %other,
                    "rpp-stark proof verification failed"
                );
                warn!(
                    target = "telemetry",
                    peer_id = labels.peer_id,
                    height = ?labels.height,
                    slot = ?labels.slot,
                    proof_id = labels.proof_id,
                    circuit = labels.circuit,
                    backend = backend.as_str(),
                    proof_backend = "rpp-stark",
                    proof_kind = proof_kind.as_str(),
                    valid = false,
                    verify_duration_ms = duration.as_millis().min(u128::from(u64::MAX)) as u64,
                    error = %other,
                    "rpp-stark proof verification failed"
                );
            }
        }

        proof_metrics.record_verification_outcome(backend, proof_kind, labels.circuit, outcome);
    }

    fn record_rpp_stark_stage_checks(
        proof_metrics: &ProofMetrics,
        backend: ProofVerificationBackend,
        proof_kind: ProofVerificationKind,
        circuit: &str,
        flags: RppStarkVerificationFlags,
    ) {
        proof_metrics.observe_verification_stage(
            backend,
            proof_kind,
            circuit,
            ProofVerificationStage::Params,
            ProofVerificationOutcome::from_bool(flags.params()),
        );
        proof_metrics.observe_verification_stage(
            backend,
            proof_kind,
            circuit,
            ProofVerificationStage::Public,
            ProofVerificationOutcome::from_bool(flags.public()),
        );
        proof_metrics.observe_verification_stage(
            backend,
            proof_kind,
            circuit,
            ProofVerificationStage::Merkle,
            ProofVerificationOutcome::from_bool(flags.merkle()),
        );
        proof_metrics.observe_verification_stage(
            backend,
            proof_kind,
            circuit,
            ProofVerificationStage::Fri,
            ProofVerificationOutcome::from_bool(flags.fri()),
        );
        proof_metrics.observe_verification_stage(
            backend,
            proof_kind,
            circuit,
            ProofVerificationStage::Composition,
            ProofVerificationOutcome::from_bool(flags.composition()),
        );
    }

    fn rpp_stark_incompatibility_reason(failure: &RppStarkVerifyFailure) -> Option<&'static str> {
        match failure {
            RppStarkVerifyFailure::VersionMismatch { .. } => Some("proof_version"),
            RppStarkVerifyFailure::ParamsHashMismatch => Some("circuit_digest"),
            _ => None,
        }
    }

    fn classify_rpp_stark_error_stage(error: &RppStarkVerifierError) -> ProofVerificationStage {
        match error {
            RppStarkVerifierError::VerificationFailed { failure, report } => {
                stage_from_failure(failure, report.flags())
                    .unwrap_or(ProofVerificationStage::Adapter)
            }
            RppStarkVerifierError::MalformedParams { .. }
            | RppStarkVerifierError::UnsupportedParamsProfile { .. }
            | RppStarkVerifierError::ProofSizeLimitMismatch { .. }
            | RppStarkVerifierError::ProofSizeLimitOverflow { .. }
            | RppStarkVerifierError::MalformedPublicInputs { .. }
            | RppStarkVerifierError::BackendUnavailable(_) => ProofVerificationStage::Adapter,
        }
    }

    fn spawn_runtime(self: &Arc<Self>) -> JoinHandle<()> {
        let runner = Arc::clone(self);
        let shutdown = runner.subscribe_shutdown();
        let run_span = info_span!("runtime.node.run");
        let run_task = tokio::spawn(async move { runner.run(shutdown).await }.instrument(run_span));

        let completion = Arc::clone(self);
        let completion_span = info_span!("runtime.node.run.join");
        tokio::spawn(
            async move {
                match run_task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        warn!(?err, "node runtime exited with error");
                    }
                    Err(err) => {
                        warn!(?err, "node runtime join error");
                    }
                }
                completion.drain_worker_tasks().await;
                completion.completion.notify_waiters();
            }
            .instrument(completion_span),
        )
    }

    pub async fn start(
        config: NodeConfig,
        runtime_metrics: Arc<RuntimeMetrics>,
    ) -> ChainResult<(NodeHandle, JoinHandle<()>)> {
        let node = Node::new(config, Arc::clone(&runtime_metrics))?;
        let handle = node.handle();
        let runtime_config = handle.inner.runtime_config()?;
        let (p2p_inner, p2p_handle) =
            P2pRuntime::new(runtime_config).map_err(|err: P2pError| {
                ChainError::Config(format!("failed to initialise p2p runtime: {err}"))
            })?;
        let p2p_span = info_span!("runtime.p2p.run");
        let p2p_task = tokio::spawn(
            async move {
                if let Err(err) = p2p_inner.run().await {
                    warn!(?err, "p2p runtime exited with error");
                }
            }
            .instrument(p2p_span),
        );
        handle
            .inner
            .initialise_p2p_runtime(p2p_handle, Some(p2p_task))
            .await;
        let join = handle.inner.spawn_runtime();
        Ok((handle, join))
    }

    pub async fn stop(&self) -> ChainResult<()> {
        self.signal_shutdown();
        if let Some(runtime) = self.inner.p2p_runtime.lock().clone() {
            let _ = runtime.shutdown().await;
        }
        self.completion.notified().await;
        self.drain_worker_tasks().await;
        Ok(())
    }

    async fn run(self: Arc<Self>, mut shutdown: broadcast::Receiver<()>) -> ChainResult<()> {
        info!(
            address = %self.address,
            channel = ?self.config.rollout.release_channel,
            ?self.config.rollout.feature_gates,
            telemetry_enabled = self.config.rollout.telemetry.enabled,
            "starting node"
        );
        let mut ticker = time::interval(self.block_interval);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(err) = self.produce_block() {
                        warn!(?err, "block production failed");
                    }
                }
                result = shutdown.recv() => {
                    match result {
                        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                            info!("node shutdown signal received");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            info!("node shutdown channel closed");
                        }
                    }
                    break;
                }
            }
        }
        Ok(())
    }

    async fn spawn_worker(&self, handle: JoinHandle<()>) {
        let mut workers = self.worker_tasks.lock().await;
        workers.push(handle);
    }

    async fn drain_worker_tasks(&self) {
        let mut workers = self.worker_tasks.lock().await;
        while let Some(handle) = workers.pop() {
            if let Err(err) = handle.await {
                if !err.is_cancelled() {
                    warn!(?err, "node worker task terminated unexpectedly");
                }
            }
        }
    }

    fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown.subscribe()
    }

    fn signal_shutdown(&self) {
        let _ = self.shutdown.send(());
    }

    fn validator_telemetry(&self) -> ChainResult<ValidatorTelemetryView> {
        let rollout = self.rollout_status();
        let node = self.node_status()?;
        let consensus = ValidatorConsensusTelemetry::from(self.consensus_status()?);
        let mempool = ValidatorMempoolTelemetry::from(&node);
        let verifier_metrics = self.verifiers.metrics_snapshot();

        Ok(ValidatorTelemetryView {
            rollout,
            node,
            consensus,
            mempool,
            timetoke_params: self.ledger.timetoke_params(),
            verifier_metrics,
            pruning: self.pruning_status.read().clone(),
            vrf_threshold: self.vrf_threshold(),
        })
    }

    fn block_proofs(&self, height: u64) -> ChainResult<Option<BlockProofArtifactsView>> {
        let stored = self.storage.read_block_record(height)?;
        Ok(stored.map(|record| {
            let envelope = record.envelope;
            BlockProofArtifactsView {
                hash: envelope.hash.clone(),
                height,
                pruning_proof: envelope.pruning_proof.clone(),
                recursive_proof: envelope.recursive_proof.clone(),
                stark: envelope.stark.clone(),
                module_witnesses: envelope.module_witnesses.clone(),
                proof_artifacts: envelope.proof_artifacts.clone(),
                consensus_proof: envelope.consensus_proof.clone(),
                pruned: envelope.pruned,
            }
        }))
    }

    fn bft_membership(&self) -> ChainResult<BftMembership> {
        let accounts_snapshot = self.ledger.accounts_snapshot();
        let (validators, observers) = classify_participants(&accounts_snapshot);
        let validator_entries = validators
            .into_iter()
            .map(|candidate| ValidatorMembershipEntry {
                address: candidate.address,
                stake: candidate.stake,
                reputation_score: candidate.reputation_score,
                tier: candidate.tier,
                timetoke_hours: candidate.timetoke_hours,
            })
            .collect();
        let observer_entries = observers
            .into_iter()
            .map(|observer| ObserverMembershipEntry {
                address: observer.address,
                tier: observer.tier,
            })
            .collect();
        let epoch_info = self.ledger.epoch_info();
        let node_status = self.node_status()?;
        Ok(BftMembership {
            height: node_status.height,
            epoch: epoch_info.epoch,
            epoch_nonce: epoch_info.epoch_nonce,
            validators: validator_entries,
            observers: observer_entries,
        })
    }

    fn reconstruction_plan(&self, start_height: u64) -> ChainResult<ReconstructionPlan> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let engine = ReconstructionEngine::with_snapshot_dir(
            self.storage.clone(),
            self.config.snapshot_dir.clone(),
        )
        .with_checkpoint_signatures(self.pruning_checkpoint_signatures.clone());
        let plan = engine.plan_from_height(start_height)?;
        if let Some(path) = engine.persist_plan(&plan)? {
            info!(?path, "persisted reconstruction plan snapshot");
        }
        Ok(plan)
    }

    fn run_pruning_cycle(
        &self,
        chunk_size: usize,
        retention_depth: u64,
    ) -> ChainResult<PruningCycleSummary> {
        let mut log_context = PruningLogContext::new();
        let log_start = Instant::now();
        let resume_from_checkpoint = self
            .pruning_status
            .read()
            .as_ref()
            .and_then(|status| status.persisted_path.as_ref())
            .map(|path| Path::new(path).exists())
            .unwrap_or(false);

        if !self.config.rollout.feature_gates.reconstruction {
            let summary = PruningCycleSummary::completed(None);
            log_pruning_cycle_finished(
                &log_context,
                &summary,
                log_start.elapsed(),
                resume_from_checkpoint,
            );
            return Ok(summary);
        }
        let result: ChainResult<PruningCycleSummary> = (|| {
            let engine = ReconstructionEngine::with_snapshot_dir(
                self.storage.clone(),
                self.config.snapshot_dir.clone(),
            )
            .with_checkpoint_signatures(self.pruning_checkpoint_signatures.clone());
            let mut state_sync_plan = engine.state_sync_plan(chunk_size)?;
            let mut reconstruction_plan = engine.full_plan()?;
            let retention_floor = if retention_depth == 0 {
                0
            } else {
                state_sync_plan
                    .tip
                    .height
                    .saturating_sub(retention_depth.saturating_sub(1))
            };
            for chunk in state_sync_plan.chunks.iter_mut() {
                chunk
                    .requests
                    .retain(|request| request.height >= retention_floor);
                if let Some(first) = chunk.requests.first() {
                    chunk.start_height = first.height;
                }
                if let Some(last) = chunk.requests.last() {
                    chunk.end_height = last.height;
                }
            }
            state_sync_plan
                .chunks
                .retain(|chunk| !chunk.requests.is_empty());
            state_sync_plan
                .light_client_updates
                .retain(|update| update.height >= retention_floor);
            reconstruction_plan
                .requests
                .retain(|request| request.height >= retention_floor);
            if let Some(first) = reconstruction_plan.requests.first() {
                reconstruction_plan.start_height = first.height;
            }
            let persisted_path = engine.persist_plan(&reconstruction_plan)?;
            let mut missing_heights = Vec::new();
            for chunk in &state_sync_plan.chunks {
                for request in &chunk.requests {
                    missing_heights.push(request.height);
                }
            }
            missing_heights.sort_unstable();
            missing_heights.dedup();
            log_context.set_checkpoint_id(checkpoint_identifier(
                state_sync_plan.snapshot.height,
                &state_sync_plan.snapshot.block_hash,
            ));

            log_pruning_cycle_start(
                &log_context,
                chunk_size,
                retention_depth,
                state_sync_plan.snapshot.height,
                reconstruction_plan.tip.height,
                missing_heights.len(),
                state_sync_plan.chunks.len(),
                resume_from_checkpoint,
            );

            if let Some(path) = persisted_path.as_ref() {
                log_pruning_checkpoint_saved(&log_context, path, state_sync_plan.snapshot.height);
            }
            let mut cancelled = self.pruning_cancelled.swap(false, Ordering::SeqCst);
            let mut stored_proofs = Vec::new();
            let mut previous_cache: Option<Block> = None;
            let mut batch_processed = 0usize;
            let mut batch_index = 0usize;
            let mut io_bytes_written = 0u64;
            let mut io_duration = Duration::ZERO;
            for height in missing_heights.iter().copied() {
                if cancelled || self.pruning_cancelled.swap(false, Ordering::SeqCst) {
                    cancelled = true;
                    break;
                }
                match self.storage.read_block_record(height)? {
                    Some(record) => {
                        let mut block = record.into_block();
                        let metadata =
                            self.storage.read_block_metadata(height)?.ok_or_else(|| {
                                ChainError::CommitmentMismatch(format!(
                                    "missing block metadata for height {height}"
                                ))
                            })?;
                        let previous_block = if block.header.height == 0 {
                            None
                        } else {
                            let expected_height = block.header.height - 1;
                            if previous_cache
                                .as_ref()
                                .map(|candidate| candidate.header.height)
                                != Some(expected_height)
                            {
                                let predecessor =
                                    self.storage.read_block(expected_height)?.ok_or_else(|| {
                                        ChainError::CommitmentMismatch(format!(
                                            "missing predecessor block at height {expected_height}"
                                        ))
                                    })?;
                                previous_cache = Some(predecessor);
                            }
                            previous_cache.as_ref()
                        };

                        enforce_block_invariants(
                            &mut block,
                            &metadata,
                            Some(&block.pruning_proof),
                            previous_block,
                        )?;

                        let persist_started = Instant::now();
                        let written = self
                            .storage
                            .persist_pruning_proof(height, &block.pruning_proof)?;
                        io_bytes_written = io_bytes_written.saturating_add(written);
                        io_duration = io_duration.saturating_add(persist_started.elapsed());
                        stored_proofs.push(height);
                        batch_processed += 1;
                        if batch_processed == chunk_size {
                            batch_index += 1;
                            log_pruning_batch_complete(
                                &log_context,
                                batch_index,
                                stored_proofs.len(),
                                height,
                            );
                            batch_processed = 0;
                        }
                        previous_cache = Some(block);
                    }
                    None => {
                        warn!(height, "missing block record for pruning proof persistence");
                    }
                }

                if self.pruning_cancelled.swap(false, Ordering::SeqCst) {
                    cancelled = true;
                    break;
                }
            }
            if batch_processed > 0 && !stored_proofs.is_empty() {
                batch_index += 1;
                if let Some(&last_height) = stored_proofs.last() {
                    log_pruning_batch_complete(
                        &log_context,
                        batch_index,
                        stored_proofs.len(),
                        last_height,
                    );
                }
            }
            let last_updated = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let io_throughput_bytes_per_sec = if io_duration.is_zero() {
                None
            } else {
                Some(
                    (io_bytes_written as f64 / io_duration.as_secs_f64())
                        .round()
                        .max(0.0) as u64,
                )
            };
            let io_duration_ms = (!io_duration.is_zero()).then_some(io_duration.as_millis() as u64);
            let status = PruningJobStatus {
                plan: state_sync_plan,
                missing_heights,
                persisted_path: persisted_path.map(|path| path.to_string_lossy().to_string()),
                stored_proofs,
                last_updated,
                estimated_time_remaining_ms: None,
                io_bytes_written: (!io_duration.is_zero()).then_some(io_bytes_written),
                io_duration_ms,
                io_throughput_bytes_per_sec,
            };
            if let Some(path) = status.persisted_path.as_ref() {
                info!(?path, "persisted pruning snapshot plan");
            }
            if !status.missing_heights.is_empty() {
                debug!(
                    heights = ?status.missing_heights,
                    proofs = status.stored_proofs.len(),
                    "pruning cycle identified missing history"
                );
            }

            let (rehydrated, orphaned) = self.reconcile_mempool_metadata();
            if rehydrated > 0 || orphaned > 0 {
                self.runtime_metrics
                    .record_mempool_metadata_reconciliation(rehydrated, orphaned);
                if orphaned > 0 {
                    warn!(
                        target = "pruning",
                        event = "mempool_metadata_reconciled",
                        rehydrated,
                        orphaned,
                        "pruning cleared orphaned mempool entries",
                    );
                } else {
                    info!(
                        target = "pruning",
                        event = "mempool_metadata_reconciled",
                        rehydrated,
                        orphaned,
                        "pruning revalidated mempool entries",
                    );
                }
            }

            let summary = if cancelled {
                PruningCycleSummary::cancelled(Some(status.clone()))
            } else {
                PruningCycleSummary::completed(Some(status.clone()))
            };

            {
                let mut slot = self.pruning_status.write();
                *slot = summary.status.clone();
            }

            if let Some(ref payload) = summary.status {
                self.emit_witness_json(GossipTopic::Snapshots, payload);
            }

            log_pruning_cycle_finished(
                &log_context,
                &summary,
                log_start.elapsed(),
                resume_from_checkpoint,
            );

            Ok(summary)
        })();

        if let Err(err) = &result {
            log_pruning_cycle_error(&log_context, err);
        }

        result
    }

    fn pruning_job_status(&self) -> Option<PruningJobStatus> {
        self.pruning_status.read().clone()
    }

    fn update_pruning_status(&self, status: Option<PruningJobStatus>) {
        let mut slot = self.pruning_status.write();
        *slot = status;
    }

    fn state_sync_plan(&self, chunk_size: usize) -> ChainResult<StateSyncPlan> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        let plan = engine.state_sync_plan(chunk_size)?;
        let expected_root = Hash::from(plan.snapshot.commitments.global_state_root);
        let total_chunks = plan.chunks.len();
        self.maybe_reset_state_sync_session(&expected_root, chunk_size, total_chunks);
        Ok(plan)
    }

    fn network_state_sync_plan(&self, chunk_size: usize) -> ChainResult<NetworkStateSyncPlan> {
        let plan = self.state_sync_plan(chunk_size)?;
        plan.to_network_plan()
    }

    fn network_state_sync_chunk(
        &self,
        chunk_size: usize,
        start_height: u64,
    ) -> ChainResult<NetworkStateSyncChunk> {
        let plan = self.state_sync_plan(chunk_size)?;
        plan.chunk_message_for(start_height)
    }

    fn stream_state_sync_chunks(
        &self,
        store: &SnapshotStore,
        root: &Hash,
    ) -> ChainResult<SnapshotChunkStream> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        runtime_stream_state_sync_chunks(store, root)
            .map_err(|err| ChainError::Config(format!("failed to stream state sync chunks: {err}")))
    }

    fn state_sync_chunk_by_index(
        &self,
        store: &SnapshotStore,
        root: &Hash,
        index: u64,
    ) -> ChainResult<SnapshotChunk> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        runtime_state_sync_chunk_by_index(store, root, index).map_err(|err| {
            ChainError::Config(format!(
                "failed to fetch state sync chunk {index} for snapshot {root:?}: {err}"
            ))
        })
    }

    fn ensure_state_sync_session(
        &self,
        chunk_size: usize,
    ) -> ChainResult<StateSyncVerificationStatus> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }

        let plan = self.state_sync_plan(chunk_size)?;
        let expected_root = Hash::from(plan.snapshot.commitments.global_state_root);
        let expected_chunks = plan.chunks.len();

        let request_id = loop {
            {
                let mut cache = self.state_sync_session.lock();
                if cache.chunk_size == Some(chunk_size)
                    && cache.snapshot_root == Some(expected_root)
                {
                    match cache.status {
                        StateSyncVerificationStatus::Verified => {
                            return Ok(StateSyncVerificationStatus::Verified);
                        }
                        StateSyncVerificationStatus::Failed => {
                            return Ok(StateSyncVerificationStatus::Failed);
                        }
                        StateSyncVerificationStatus::Verifying => {
                            drop(cache);
                            thread::yield_now();
                            continue;
                        }
                        StateSyncVerificationStatus::Idle => {}
                    }
                } else if cache.status == StateSyncVerificationStatus::Verifying {
                    drop(cache);
                    thread::yield_now();
                    continue;
                }

                let request_id = cache.request_id.clone().unwrap_or_else(|| {
                    let id = Uuid::new_v4().to_string();
                    cache.request_id = Some(id.clone());
                    id
                });

                cache.set_status(StateSyncVerificationStatus::Verifying);
                cache.chunk_size = Some(chunk_size);
                cache.snapshot_root = Some(expected_root);
                cache.total_chunks = Some(expected_chunks);
                cache.served_chunks.clear();
                cache.progress_log.clear();
                cache.last_completed_step = None;
                break request_id;
            }
        };

        info!(
            target: "node",
            %request_id,
            chunk_size,
            snapshot_root = %hex::encode(expected_root),
            expected_chunks,
            "state sync verification session started",
        );

        let verifier = if self.config.snapshot_dir.as_os_str().is_empty() {
            LightClientVerifier::new(self.storage.clone())
        } else {
            LightClientVerifier::with_snapshot_dir(
                self.storage.clone(),
                self.config.snapshot_dir.clone(),
            )
        };

        let result = verifier.run_with_request(chunk_size, Some(request_id.clone()));

        let mut cache = self.state_sync_session.lock();
        match result {
            Ok(report) => {
                let chunk_count = StateSyncSessionCache::chunk_count_from_events(&report.events)
                    .unwrap_or(expected_chunks);
                let derived_root = report
                    .summary
                    .snapshot_root
                    .as_deref()
                    .and_then(StateSyncSessionCache::decode_snapshot_root)
                    .unwrap_or(expected_root);
                cache.report = Some(report);
                cache.snapshot_root = Some(derived_root);
                cache.total_chunks = Some(chunk_count);
                cache.chunk_size = Some(chunk_size);
                cache.snapshot_store = None;
                cache.served_chunks.clear();
                cache.progress_log.clear();
                cache.last_completed_step = None;
                cache.set_status(StateSyncVerificationStatus::Verified);
                info!(
                    target: "node",
                    %request_id,
                    snapshot_root = %hex::encode(derived_root),
                    chunk_count,
                    "state sync verification completed successfully",
                );
                Ok(StateSyncVerificationStatus::Verified)
            }
            Err(err) => {
                let report = err.report().clone();
                let chunk_count = StateSyncSessionCache::chunk_count_from_events(&report.events)
                    .unwrap_or(expected_chunks);
                let derived_root = report
                    .summary
                    .snapshot_root
                    .as_deref()
                    .and_then(StateSyncSessionCache::decode_snapshot_root)
                    .unwrap_or(expected_root);
                let progress_log = report
                    .events
                    .iter()
                    .map(StateSyncSessionCache::render_event)
                    .collect();
                let last_step = report.events.last().cloned();
                cache.report = Some(report);
                cache.snapshot_root = Some(derived_root);
                cache.total_chunks = Some(chunk_count);
                cache.chunk_size = Some(chunk_size);
                let is_io = matches!(err.kind(), VerificationErrorKind::Io(_));
                if !is_io {
                    cache.snapshot_store = None;
                }
                cache.served_chunks.clear();
                cache.progress_log = progress_log;
                cache.last_completed_step = last_step;
                cache.status = StateSyncVerificationStatus::Failed;
                cache.error = Some(err.to_string());
                cache.error_kind = Some(err.kind().clone());
                error!(
                    target: "node",
                    %request_id,
                    error = %err,
                    "state sync verification failed",
                );
                Ok(StateSyncVerificationStatus::Failed)
            }
        }
    }

    fn reset_state_sync_session(&self) {
        self.state_sync_session.lock().reset();
    }

    fn maybe_reset_state_sync_session(
        &self,
        expected_root: &Hash,
        chunk_size: usize,
        total_chunks: usize,
    ) {
        let mut cache = self.state_sync_session.lock();
        let root_diverged = cache
            .snapshot_root
            .map(|root| root != *expected_root)
            .unwrap_or(false);
        let chunk_size_diverged = cache
            .chunk_size
            .map(|size| size != chunk_size)
            .unwrap_or(false);
        let total_chunks_diverged = cache
            .total_chunks
            .map(|count| count != total_chunks)
            .unwrap_or(false);

        if root_diverged || chunk_size_diverged || total_chunks_diverged {
            cache.reset();
        }
    }

    fn replace_state_sync_session(&self, cache: StateSyncSessionCache) {
        let mut slot = self.state_sync_session.lock();
        *slot = cache;
    }

    fn configure_state_sync_session(
        &self,
        chunk_size: Option<usize>,
        total_chunks: Option<usize>,
        snapshot_root: Option<Hash>,
    ) {
        let mut slot = self.state_sync_session.lock();
        slot.configure(chunk_size, total_chunks, snapshot_root);
    }

    fn record_state_sync_event(&self, event: LightClientVerificationEvent) {
        self.state_sync_session.lock().record_event(event);
    }

    fn mark_state_sync_chunk_served(&self, index: u64) {
        self.state_sync_session.lock().mark_chunk_served(index);
    }

    fn update_state_sync_verification_report(&self, report: StateSyncVerificationReport) {
        self.state_sync_session.lock().set_report(report);
    }

    fn state_sync_session_snapshot(&self) -> StateSyncSessionCache {
        self.state_sync_session.lock().clone()
    }

    fn state_sync_server(&self) -> Option<Arc<StateSyncServer>> {
        self.state_sync_server.get().cloned()
    }

    pub(crate) fn snapshot_download_budgets(&self) -> (Duration, Duration) {
        (
            Duration::from_secs(self.config.snapshot_download.timetoke_budget_secs),
            Duration::from_secs(self.config.snapshot_download.uptime_budget_secs),
        )
    }

    fn parse_chunk_total(message: &str) -> Option<u32> {
        let marker = "total ";
        let start = message.find(marker)? + marker.len();
        let end = message[start..].find(')')? + start;
        message[start..end].trim().parse().ok()
    }

    fn validate_snapshot_manifest(
        &self,
        manifest_bytes: &[u8],
        chunk_root: &Path,
    ) -> Result<(), SnapshotManifestError> {
        let manifest: SnapshotChunkManifest =
            serde_json::from_slice(manifest_bytes).map_err(SnapshotManifestError::Decode)?;

        if manifest.version != SNAPSHOT_MANIFEST_VERSION {
            return Err(SnapshotManifestError::VersionMismatch {
                expected: SNAPSHOT_MANIFEST_VERSION,
                actual: manifest.version,
            });
        }

        let checksum_algorithm = resolve_manifest_algorithm(
            manifest.checksum_algorithm,
            self.config.snapshot_checksum_algorithm,
        )?;

        if !chunk_root.exists() {
            return Err(SnapshotManifestError::MissingChunkDirectory(
                chunk_root.to_path_buf(),
            ));
        }

        for segment in manifest.segments.into_iter() {
            let Some(name) = segment.name else { continue };
            let Some(expected_size) = segment.size_bytes else {
                continue;
            };
            let Some(expected_checksum) = segment.checksum.or(segment.sha256) else {
                continue;
            };
            let expected_checksum = expected_checksum.to_lowercase();

            let path = chunk_root.join(&name);
            if !path.exists() {
                return Err(SnapshotManifestError::MissingChunk { name, path });
            }

            let metadata = fs::metadata(&path).map_err(SnapshotManifestError::Io)?;
            if metadata.len() != expected_size {
                return Err(SnapshotManifestError::SizeMismatch {
                    name,
                    path,
                    expected: expected_size,
                    actual: metadata.len(),
                });
            }

            let digest = compute_manifest_checksum(&path, checksum_algorithm)?;
            if !digest.eq_ignore_ascii_case(&expected_checksum) {
                return Err(SnapshotManifestError::ChecksumMismatch {
                    name,
                    path,
                    expected: expected_checksum,
                    actual: digest,
                });
            }
        }

        Ok(())
    }

    fn load_snapshot_payload(
        &self,
        root: &Hash,
    ) -> Result<Option<(Vec<u8>, String)>, SnapshotPayloadError> {
        let base = self.config.snapshot_dir.clone();
        if base.as_os_str().is_empty() {
            return Ok(None);
        }
        let mut stack = vec![base];
        while let Some(path) = stack.pop() {
            let entries = match fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) => return Err(err),
            };
            for entry in entries {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    stack.push(entry.path());
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                let payload_path = entry.path();
                let payload = fs::read(&payload_path)?;
                if &blake3::hash(&payload) == root {
                    let manifest_root = self.config.snapshot_dir.join("chunks");
                    if let Err(err) = self.validate_snapshot_manifest(&payload, &manifest_root) {
                        log_manifest_error(&payload_path, &err);
                        return Err(SnapshotPayloadError::Manifest(err));
                    }

                    let mut signature_path = payload_path.clone();
                    let mut sig_name = entry.file_name();
                    sig_name.push(".sig");
                    signature_path.set_file_name(sig_name);
                    if !signature_path.exists() {
                        let root_hex = hex::encode(root.as_bytes());
                        error!(
                            target: "node",
                            root = %root_hex,
                            path = %payload_path.display(),
                            signature = %signature_path.display(),
                            "snapshot signature missing"
                        );
                        return Err(std::io::Error::new(
                            ErrorKind::NotFound,
                            format!(
                                "snapshot signature missing for {}",
                                signature_path.display()
                            ),
                        )
                        .into());
                    }
                    let encoded = fs::read_to_string(&signature_path)?;
                    let (signature_version, signature) =
                        parse_snapshot_signature(&encoded, &signature_path)?;

                    if signature_version != self.timetoke_snapshot_signing_key.version {
                        let expected = self.timetoke_snapshot_signing_key.version;
                        return Err(SnapshotPayloadError::Signature(format!(
                            "snapshot signature version {signature_version} rejected; expected {expected} at {}",
                            signature_path.display()
                        )));
                    }

                    let verifying_key = self
                        .timetoke_snapshot_signing_key
                        .signing_key
                        .verifying_key();
                    if let Err(err) = verifying_key.verify(&payload, &signature) {
                        let root_hex = hex::encode(root.as_bytes());
                        error!(
                            target: "node",
                            root = %root_hex,
                            signature = %signature_path.display(),
                            %err,
                            "snapshot signature failed verification",
                        );
                        return Err(SnapshotPayloadError::Signature(format!(
                            "snapshot signature verification failed at {}: {err}",
                            signature_path.display()
                        )));
                    }

                    let canonical = BASE64.encode(signature.to_bytes());
                    return Ok(Some((payload, canonical)));
                }
            }
        }
        Ok(None)
    }

    fn state_sync_session_chunk(&self, index: u32) -> Result<SnapshotChunk, StateSyncChunkError> {
        let (root, chunk_size, total_opt, cached_store) = {
            let cache = self.state_sync_session.lock();
            if cache.status != StateSyncVerificationStatus::Verified {
                return Err(StateSyncChunkError::NoActiveSession);
            }
            let root = cache
                .snapshot_root
                .ok_or(StateSyncChunkError::NoActiveSession)?;
            let chunk_size = cache
                .chunk_size
                .ok_or(StateSyncChunkError::NoActiveSession)?;
            let total_opt = cache
                .total_chunks
                .map(|value| {
                    u32::try_from(value).map_err(|_| {
                        StateSyncChunkError::Internal(format!(
                            "state sync chunk count {value} exceeds supported range"
                        ))
                    })
                })
                .transpose()?;
            let store = cache.snapshot_store.clone();
            (root, chunk_size, total_opt, store)
        };

        if let Some(total) = total_opt {
            if index >= total {
                return Err(StateSyncChunkError::ChunkIndexOutOfRange { index, total });
            }
        }

        let store = if let Some(store) = cached_store {
            store
        } else {
            let (payload, signature) = match self.load_snapshot_payload(&root) {
                Ok(Some(data)) => data,
                Ok(None) => {
                    let reason = format!(
                        "snapshot payload for root {} not found",
                        hex::encode(root.as_bytes())
                    );
                    return Err(StateSyncChunkError::ChunkNotFound { index, reason });
                }
                Err(SnapshotPayloadError::Io(err)) => return Err(StateSyncChunkError::Io(err)),
                Err(SnapshotPayloadError::Manifest(err)) => {
                    return Err(StateSyncChunkError::ManifestViolation {
                        reason: err.to_string(),
                    })
                }
                Err(SnapshotPayloadError::Signature(err)) => {
                    return Err(StateSyncChunkError::Io(std::io::Error::new(
                        ErrorKind::InvalidData,
                        err,
                    )))
                }
            };
            let mut store = SnapshotStore::new(chunk_size);
            let actual_root = store.insert(payload, Some(signature));
            if actual_root != root {
                return Err(StateSyncChunkError::SnapshotRootMismatch {
                    expected: root,
                    actual: actual_root,
                });
            }
            let store = Arc::new(RwLock::new(store));
            {
                let mut cache = self.state_sync_session.lock();
                if cache.status == StateSyncVerificationStatus::Verified
                    && cache.snapshot_root == Some(root)
                    && cache.chunk_size == Some(chunk_size)
                    && cache.snapshot_store.is_none()
                {
                    cache.snapshot_store = Some(store.clone());
                }
            }
            store
        };

        let chunk_result = {
            let guard = store.read();
            guard.chunk(&root, index as u64)
        };

        let chunk = match chunk_result {
            Ok(chunk) => chunk,
            Err(PipelineError::SnapshotNotFound) => {
                let reason = format!(
                    "snapshot payload for root {} missing",
                    hex::encode(root.as_bytes())
                );
                return Err(StateSyncChunkError::ChunkNotFound { index, reason });
            }
            Err(PipelineError::SnapshotVerification(message))
                if message.contains(PROOF_IO_MARKER) =>
            {
                return Err(StateSyncChunkError::IoProof { index, message });
            }
            Err(PipelineError::SnapshotVerification(message)) => {
                if message.contains("out of range") {
                    let total = if let Some(total) = total_opt {
                        total
                    } else if let Some(total) = Self::parse_chunk_total(&message) {
                        total
                    } else {
                        return Err(StateSyncChunkError::Internal(message));
                    };
                    return Err(StateSyncChunkError::ChunkIndexOutOfRange { index, total });
                }
                return Err(StateSyncChunkError::ChunkNotFound {
                    index,
                    reason: message,
                });
            }
            Err(PipelineError::Validation(message)) if message.contains(PROOF_IO_MARKER) => {
                return Err(StateSyncChunkError::IoProof { index, message });
            }
            Err(PipelineError::Persistence(message)) if message.contains(PROOF_IO_MARKER) => {
                return Err(StateSyncChunkError::IoProof { index, message });
            }
            Err(other) => return Err(StateSyncChunkError::Internal(other.to_string())),
        };

        let progress_message = format!("served chunk #{}", index);
        let root_hex = hex::encode(root.as_bytes());
        {
            let mut cache = self.state_sync_session.lock();
            if cache.status != StateSyncVerificationStatus::Verified
                || cache.snapshot_root != Some(root)
                || cache.chunk_size != Some(chunk_size)
            {
                return Err(StateSyncChunkError::NoActiveSession);
            }
            cache.served_chunks.insert(index as u64);
            cache.progress_log.push(progress_message);
            cache.last_completed_step = Some(LightClientVerificationEvent::VerificationCompleted {
                snapshot_root: root_hex,
            });
        }

        Ok(chunk)
    }

    /// Returns a clone of the light client head subscription channel for external observers.
    ///
    /// The returned [`watch::Receiver`] is independent from the node's internal runtime handle,
    /// allowing callers to await updates without holding any locks on [`NodeInner`]. The
    /// underlying channel is multi-consumer, so each subscriber should clone the receiver before
    /// spawning tasks that await notifications.
    fn subscribe_light_client_heads(
        &self,
    ) -> ChainResult<watch::Receiver<Option<LightClientHead>>> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let handle = self
            .p2p_handle()
            .ok_or_else(|| ChainError::Config("p2p runtime not initialised".into()))?;
        Ok(handle.subscribe_light_client_heads())
    }

    fn latest_light_client_head(&self) -> ChainResult<Option<LightClientHead>> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let handle = self
            .p2p_handle()
            .ok_or_else(|| ChainError::Config("p2p runtime not initialised".into()))?;
        Ok(handle.latest_light_client_head())
    }

    fn verify_proof_chain(&self) -> ChainResult<()> {
        if !self.config.rollout.feature_gates.recursive_proofs {
            return Err(ChainError::Config(
                "recursive proof verification disabled by rollout".into(),
            ));
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        match engine.verify_proof_chain() {
            Ok(result) => Ok(result),
            Err(err) => {
                warn!(?err, "proof chain verification failed");
                Err(err)
            }
        }
    }

    fn reconstruct_block<P: PayloadProvider>(
        &self,
        height: u64,
        provider: &P,
    ) -> ChainResult<Block> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        engine.reconstruct_block(height, provider)
    }

    fn reconstruct_range<P: PayloadProvider>(
        &self,
        start_height: u64,
        end_height: u64,
        provider: &P,
    ) -> ChainResult<Vec<Block>> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        engine.reconstruct_range(start_height, end_height, provider)
    }

    fn execute_reconstruction_plan<P: PayloadProvider>(
        &self,
        plan: &ReconstructionPlan,
        provider: &P,
    ) -> ChainResult<Vec<Block>> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        engine.execute_plan(plan, provider)
    }

    #[instrument(
        name = "runtime.wallet.rpc.submit_transaction",
        skip(self, bundle),
        fields(tx_hash = tracing::field::Empty, wallet = tracing::field::Empty),
        err
    )]
    fn submit_transaction(&self, bundle: TransactionProofBundle) -> ChainResult<String> {
        let tx_hash = bundle.hash();
        let wallet = bundle.transaction.payload.from.clone();
        let current = Span::current();
        current.record("tx_hash", &display(&tx_hash));
        current.record("wallet", &display(&wallet));
        let flow_span = wallet_rpc_flow_span("submit_transaction", &wallet, &tx_hash);
        let _guard = flow_span.enter();
        bundle.transaction.verify()?;
        if self.config.rollout.feature_gates.recursive_proofs {
            #[cfg(feature = "backend-rpp-stark")]
            {
                let stwo_started = Instant::now();
                let circuit = ProofVerificationKind::Transaction.as_str();
                let verification = if let (Some(bytes), Some(inputs)) =
                    (bundle.stwo_proof_bytes(), bundle.stwo_public_inputs())
                {
                    let proof_bytes = ProofBytes(bytes.clone());
                    self.verifiers.verify_stwo_proof_bytes(&proof_bytes, inputs)
                } else {
                    match &bundle.proof {
                        ChainProof::RppStark(_) => self
                            .verify_rpp_stark_with_metrics(
                                ProofVerificationKind::Transaction,
                                &bundle.proof,
                                ProofLogLabels {
                                    proof_id: Some(tx_hash.clone()),
                                    circuit: Some("transaction".into()),
                                    ..Default::default()
                                },
                            )
                            .map(|_| ()),
                        _ => self.verifiers.verify_transaction(&bundle.proof),
                    }
                };
                if let Err(err) = verification {
                    let proof_metrics = self.runtime_metrics.proofs();
                    proof_metrics.record_verification_outcome(
                        ProofVerificationBackend::Stwo,
                        ProofVerificationKind::Transaction,
                        circuit,
                        ProofVerificationOutcome::Fail,
                    );
                    warn!(?err, "transaction proof rejected by verifier");
                    return Err(err);
                }
                if matches!(bundle.proof, ChainProof::Stwo(_)) {
                    let duration = stwo_started.elapsed();
                    let proof_metrics = self.runtime_metrics.proofs();
                    proof_metrics.observe_verification(
                        ProofVerificationBackend::Stwo,
                        ProofVerificationKind::Transaction,
                        circuit,
                        duration,
                    );
                    proof_metrics.observe_verification_stage_duration(
                        ProofVerificationBackend::Stwo,
                        ProofVerificationKind::Transaction,
                        circuit,
                        ProofVerificationStage::Parse,
                        duration,
                    );
                    proof_metrics.observe_verification_stage_duration(
                        ProofVerificationBackend::Stwo,
                        ProofVerificationKind::Transaction,
                        circuit,
                        ProofVerificationStage::Adapter,
                        Duration::from_millis(0),
                    );
                    let proof_bytes = bundle.stwo_proof_bytes().map(Vec::as_slice);
                    self.record_stwo_proof_size(
                        ProofVerificationKind::Transaction,
                        circuit,
                        &bundle.proof,
                        proof_bytes,
                    );
                    proof_metrics.record_verification_outcome(
                        ProofVerificationBackend::Stwo,
                        ProofVerificationKind::Transaction,
                        circuit,
                        ProofVerificationOutcome::Ok,
                    );
                }
                if !matches!(bundle.proof, ChainProof::RppStark(_)) {
                    Self::ensure_transaction_payload(&bundle.proof, &bundle.transaction)?;
                }
            }
            #[cfg(not(feature = "backend-rpp-stark"))]
            {
                let stwo_started = Instant::now();
                let circuit = ProofVerificationKind::Transaction.as_str();
                let verification = if let (Some(bytes), Some(inputs)) =
                    (bundle.stwo_proof_bytes(), bundle.stwo_public_inputs())
                {
                    let proof_bytes = ProofBytes(bytes.clone());
                    self.verifiers.verify_stwo_proof_bytes(&proof_bytes, inputs)
                } else {
                    self.verifiers.verify_transaction(&bundle.proof)
                };
                if let Err(err) = verification {
                    let proof_metrics = self.runtime_metrics.proofs();
                    proof_metrics.record_verification_outcome(
                        ProofVerificationBackend::Stwo,
                        ProofVerificationKind::Transaction,
                        circuit,
                        ProofVerificationOutcome::Fail,
                    );
                    warn!(?err, "transaction proof rejected by verifier");
                    return Err(err);
                }
                let duration = stwo_started.elapsed();
                let proof_metrics = self.runtime_metrics.proofs();
                proof_metrics.observe_verification(
                    ProofVerificationBackend::Stwo,
                    ProofVerificationKind::Transaction,
                    circuit,
                    duration,
                );
                proof_metrics.observe_verification_stage_duration(
                    ProofVerificationBackend::Stwo,
                    ProofVerificationKind::Transaction,
                    circuit,
                    ProofVerificationStage::Parse,
                    duration,
                );
                proof_metrics.observe_verification_stage_duration(
                    ProofVerificationBackend::Stwo,
                    ProofVerificationKind::Transaction,
                    circuit,
                    ProofVerificationStage::Adapter,
                    Duration::from_millis(0),
                );
                let proof_bytes = bundle.stwo_proof_bytes().map(Vec::as_slice);
                self.record_stwo_proof_size(
                    ProofVerificationKind::Transaction,
                    circuit,
                    &bundle.proof,
                    proof_bytes,
                );
                proof_metrics.record_verification_outcome(
                    ProofVerificationBackend::Stwo,
                    ProofVerificationKind::Transaction,
                    circuit,
                    ProofVerificationOutcome::Ok,
                );
                Self::ensure_transaction_payload(&bundle.proof, &bundle.transaction)?;
            }
        }
        let mut mempool = self.mempool.write();
        if mempool.len() >= self.mempool_limit() {
            return Err(ChainError::Transaction("mempool full".into()));
        }
        let tx_payload = bundle.transaction.payload.clone();
        if mempool
            .iter()
            .any(|existing| existing.transaction.id == bundle.transaction.id)
        {
            return Err(ChainError::Transaction("transaction already queued".into()));
        }
        let metadata = PendingTransactionMetadata::from_bundle(&bundle);
        mempool.push_back(bundle);
        drop(mempool);
        {
            let mut metadata_store = self.pending_transaction_metadata.write();
            metadata_store.insert(tx_hash.clone(), metadata.clone());
        }
        let summary = PendingTransactionSummary {
            hash: tx_hash.clone(),
            from: tx_payload.from,
            to: tx_payload.to,
            amount: tx_payload.amount,
            fee: tx_payload.fee,
            nonce: tx_payload.nonce,
            proof: Some(metadata.proof.clone()),
            witness: metadata.witness.clone(),
            proof_payload: metadata.proof_payload.clone(),
            #[cfg(feature = "backend-rpp-stark")]
            public_inputs_digest: metadata.public_inputs_digest.clone(),
        };
        self.emit_witness_json(GossipTopic::WitnessProofs, &summary);
        Ok(tx_hash)
    }

    fn ensure_transaction_payload(
        proof: &ChainProof,
        expected: &SignedTransaction,
    ) -> ChainResult<()> {
        match proof {
            ChainProof::Stwo(stark) => match &stark.payload {
                ProofPayload::Transaction(witness) if &witness.signed_tx == expected => Ok(()),
                ProofPayload::Transaction(_) => Err(ChainError::Crypto(
                    "transaction proof does not match submitted transaction".into(),
                )),
                _ => Err(ChainError::Crypto(
                    "transaction proof payload mismatch".into(),
                )),
            },
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(value) => {
                let witness_value = value
                    .get("public_inputs")
                    .and_then(|inputs| inputs.get("witness"))
                    .cloned()
                    .ok_or_else(|| {
                        ChainError::Crypto(
                            "plonky3 transaction proof missing witness payload".into(),
                        )
                    })?;
                let witness: Plonky3TransactionWitness = serde_json::from_value(witness_value)
                    .map_err(|err| {
                        ChainError::Crypto(format!(
                            "failed to decode plonky3 transaction witness: {err}"
                        ))
                    })?;
                if &witness.transaction == expected {
                    Ok(())
                } else {
                    Err(ChainError::Crypto(
                        "transaction proof does not match submitted transaction".into(),
                    ))
                }
            }
        }
    }

    fn compare_transaction_priority(
        lhs: &TransactionProofBundle,
        rhs: &TransactionProofBundle,
    ) -> std::cmp::Ordering {
        rhs.transaction
            .payload
            .fee
            .cmp(&lhs.transaction.payload.fee)
            .then(
                lhs.transaction
                    .payload
                    .nonce
                    .cmp(&rhs.transaction.payload.nonce),
            )
    }

    fn purge_transaction_metadata(&self, bundles: &[TransactionProofBundle]) {
        if bundles.is_empty() {
            return;
        }
        let mut metadata = self.pending_transaction_metadata.write();
        for bundle in bundles {
            metadata.remove(&bundle.hash());
        }
    }

    fn reconcile_mempool_metadata(&self) -> (usize, usize) {
        let mempool = self.mempool.read();
        let mut metadata = self.pending_transaction_metadata.write();

        let mut rehydrated = 0usize;
        let queued_hashes: HashSet<_> = mempool.iter().map(|bundle| bundle.hash()).collect();
        for bundle in mempool.iter() {
            let hash = bundle.hash();
            if metadata.contains_key(&hash) {
                continue;
            }
            metadata.insert(hash, PendingTransactionMetadata::from_bundle(bundle));
            rehydrated += 1;
        }

        let before = metadata.len();
        metadata.retain(|hash, _| queued_hashes.contains(hash));
        let orphaned = before.saturating_sub(metadata.len());

        (rehydrated, orphaned)
    }

    fn submit_identity(&self, request: AttestedIdentityRequest) -> ChainResult<String> {
        let next_height = self.chain_tip.read().height.saturating_add(1);
        self.sync_epoch_with_metrics(next_height);
        if self.config.rollout.feature_gates.recursive_proofs {
            if let Err(err) = self
                .verifiers
                .verify_identity(&request.declaration.proof.zk_proof)
            {
                warn!(
                    wallet = %request.declaration.genesis.wallet_addr,
                    ?err,
                    "identity proof rejected by verifier"
                );
                return Err(err);
            }
        }
        self.validate_identity_attestation(&request, next_height)?;
        let declaration = &request.declaration;
        let expected_epoch_nonce = hex::encode(self.ledger.current_epoch_nonce());
        if expected_epoch_nonce != declaration.genesis.epoch_nonce {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated epoch nonce".into(),
            ));
        }

        let expected_state_root = hex::encode(self.ledger.state_root());
        if expected_state_root != declaration.genesis.state_root {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated state root".into(),
            ));
        }
        let expected_identity_root = hex::encode(self.ledger.identity_root());
        if expected_identity_root != declaration.genesis.identity_root {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated identity root".into(),
            ));
        }

        let hash = request.identity_hash()?;
        let mut mempool = self.identity_mempool.write();
        if mempool.len() >= self.mempool_limit() {
            return Err(ChainError::Transaction("identity mempool full".into()));
        }
        if mempool.iter().any(|existing| {
            existing.declaration.genesis.wallet_addr == declaration.genesis.wallet_addr
        }) {
            return Err(ChainError::Transaction(
                "identity for this wallet already queued".into(),
            ));
        }
        if mempool
            .iter()
            .any(|existing| existing.identity_hash().ok().as_deref() == Some(hash.as_str()))
        {
            return Err(ChainError::Transaction(
                "identity request already queued for attestation".into(),
            ));
        }
        mempool.push_back(request);
        Ok(hash)
    }

    #[instrument(
        name = "node.consensus.queue_vote",
        skip(self, vote),
        fields(
            height = vote.vote.height,
            round = vote.vote.round,
            voter = %vote.vote.voter,
            kind = ?vote.vote.kind
        )
    )]
    fn submit_vote(
        &self,
        vote: SignedBftVote,
        received_at: Option<SystemTime>,
    ) -> ChainResult<String> {
        if self.config.rollout.feature_gates.consensus_enforcement {
            vote.verify()?;
        }
        let next_height = self.chain_tip.read().height.saturating_add(1);
        if vote.vote.height < next_height {
            return Err(ChainError::Transaction(
                "vote references an already finalized height".into(),
            ));
        }
        if let Some(evidence) = self.evidence_pool.write().record_vote(&vote) {
            self.apply_evidence(evidence);
            return Err(ChainError::Transaction(
                "conflicting vote detected for validator".into(),
            ));
        }
        self.observe_consensus_round(vote.vote.height, vote.vote.round);
        let mut mempool = self.vote_mempool.write();
        if mempool.len() >= self.mempool_limit() {
            return Err(ChainError::Transaction("vote mempool full".into()));
        }
        let vote_hash = vote.hash();
        let vote_summary = serde_json::json!({
            "hash": vote_hash.clone(),
            "voter": vote.vote.voter.clone(),
            "height": vote.vote.height,
            "round": vote.vote.round,
            "kind": vote.vote.kind,
        });
        if mempool
            .iter()
            .any(|existing| existing.vote.hash() == vote_hash)
        {
            return Err(ChainError::Transaction("vote already queued".into()));
        }
        mempool.push_back(QueuedVote {
            vote,
            received_at: received_at.unwrap_or_else(SystemTime::now),
        });
        self.emit_witness_json(GossipTopic::Votes, &vote_summary);
        Ok(vote_hash)
    }

    fn validate_identity_attestation(
        &self,
        request: &AttestedIdentityRequest,
        expected_height: u64,
    ) -> ChainResult<()> {
        request.declaration.verify()?;
        let identity_hash = request.identity_hash()?;
        let mut voters = HashSet::new();
        for vote in &request.attested_votes {
            if let Err(err) = vote.verify() {
                self.punish_invalid_identity(
                    &vote.vote.voter,
                    "invalid identity attestation signature",
                );
                return Err(err);
            }
            if vote.vote.block_hash != identity_hash {
                self.punish_invalid_identity(
                    &vote.vote.voter,
                    "identity attestation references mismatched hash",
                );
                return Err(ChainError::Transaction(
                    "identity attestation vote references mismatched request".into(),
                ));
            }
            if vote.vote.height != expected_height {
                self.punish_invalid_identity(
                    &vote.vote.voter,
                    "identity attestation references wrong height",
                );
                return Err(ChainError::Transaction(
                    "identity attestation vote references unexpected height".into(),
                ));
            }
            if vote.vote.kind != BftVoteKind::PreCommit {
                self.punish_invalid_identity(
                    &vote.vote.voter,
                    "identity attestation wrong vote kind",
                );
                return Err(ChainError::Transaction(
                    "identity attestation must be composed of pre-commit votes".into(),
                ));
            }
            if !voters.insert(vote.vote.voter.clone()) {
                return Err(ChainError::Transaction(
                    "duplicate attestation vote detected for identity request".into(),
                ));
            }
        }
        if voters.len() < IDENTITY_ATTESTATION_QUORUM {
            return Err(ChainError::Transaction(
                "insufficient quorum power for identity attestation".into(),
            ));
        }
        let mut gossip = HashSet::new();
        for address in &request.gossip_confirmations {
            gossip.insert(address.clone());
        }
        if gossip.len() < IDENTITY_ATTESTATION_GOSSIP_MIN {
            return Err(ChainError::Transaction(
                "insufficient gossip confirmations for identity attestation".into(),
            ));
        }
        Ok(())
    }

    fn punish_invalid_identity(&self, address: &str, context: &str) {
        if !self.config.rollout.feature_gates.consensus_enforcement {
            return;
        }
        if let Err(err) = self.slash_validator(address, SlashingReason::InvalidIdentity) {
            warn!(
                offender = %address,
                ?err,
                context,
                "failed to slash validator for invalid identity attestation"
            );
        }
    }

    fn punish_invalid_proof(&self, address: &Address, height: u64, round: u64) {
        if !self.config.rollout.feature_gates.consensus_enforcement {
            return;
        }
        let evidence = {
            let mut pool = self.evidence_pool.write();
            pool.record_invalid_proof(address, height, round)
        };
        self.apply_evidence(evidence);
    }

    fn handle_invalid_block_gossip(&self, peer: &PeerId, block: Block, reason: &str) {
        warn!(
            target: "node",
            %peer,
            height = block.header.height,
            round = block.consensus.round,
            proposer = %block.header.proposer,
            reason = %reason,
            "invalid block gossip detected"
        );
        let evidence = {
            let mut pool = self.evidence_pool.write();
            pool.record_invalid_proposal(
                &block.header.proposer,
                block.header.height,
                block.consensus.round,
                Some(block.hash.clone()),
            )
        };
        self.apply_evidence(evidence);
    }

    fn handle_invalid_vote_gossip(&self, peer: &PeerId, vote: SignedBftVote, reason: &str) {
        warn!(
            target: "node",
            %peer,
            height = vote.vote.height,
            round = vote.vote.round,
            voter = %vote.vote.voter,
            reason = %reason,
            "invalid vote gossip detected"
        );
        self.punish_invalid_proof(&vote.vote.voter, vote.vote.height, vote.vote.round);
        self.consensus_telemetry
            .record_failed_vote(format!("invalid_gossip:{reason}"));
        self.update_runtime_metrics();
    }

    fn record_double_spend_if_applicable(&self, block: &Block, round: u64, err: &ChainError) {
        if !self.config.rollout.feature_gates.consensus_enforcement {
            return;
        }
        if !is_double_spend(err) {
            return;
        }
        let evidence = {
            let mut pool = self.evidence_pool.write();
            pool.record_invalid_proposal(
                &block.header.proposer,
                block.header.height,
                round,
                Some(block.hash.clone()),
            )
        };
        self.apply_evidence(evidence);
    }

    fn submit_block_proposal(&self, block: Block) -> ChainResult<String> {
        let height = block.header.height;
        let round = block.consensus.round;
        let proposer = block.header.proposer.clone();
        let previous_block = if height == 0 {
            None
        } else {
            self.storage.read_block(height - 1)?
        };
        let proposer_key = self.ledger.validator_public_key(&proposer)?;
        match block.verify_without_stark_with_metrics(
            previous_block.as_ref(),
            &proposer_key,
            self.metrics.as_ref(),
        ) {
            Ok(()) => {
                let hash = block.hash.clone();
                self.observe_consensus_round(height, round);
                let mut inbox = self.proposal_inbox.write();
                let block_summary = serde_json::json!({
                    "hash": hash.clone(),
                    "height": block.header.height,
                    "round": block.consensus.round,
                    "proposer": block.header.proposer.clone(),
                });
                inbox.insert((height, proposer), VerifiedProposal { block });
                self.emit_witness_json(GossipTopic::Blocks, &block_summary);
                Ok(hash)
            }
            Err(err) => {
                let evidence = self.evidence_pool.write().record_invalid_proposal(
                    &proposer,
                    height,
                    round,
                    Some(block.hash.clone()),
                );
                self.apply_evidence(evidence);
                Err(err)
            }
        }
    }

    #[instrument(
        name = "node.consensus.apply_evidence",
        skip(self, evidence),
        fields(
            address = %evidence.address,
            height = evidence.height,
            round = evidence.round,
            kind = ?evidence.kind
        )
    )]
    fn apply_evidence(&self, evidence: EvidenceRecord) {
        let (reason, reason_label) = match evidence.kind {
            EvidenceKind::DoubleSignPrevote | EvidenceKind::DoubleSignPrecommit => {
                (SlashingReason::ConsensusFault, "double-sign")
            }
            EvidenceKind::InvalidProof => (SlashingReason::InvalidVote, "invalid-proof"),
            EvidenceKind::InvalidProposal => (SlashingReason::ConsensusFault, "invalid-proposal"),
        };
        if let Err(err) = self.slash_validator(&evidence.address, reason) {
            warn!(
                address = %evidence.address,
                ?err,
                reason = reason_label,
                "failed to apply slashing evidence"
            );
            return;
        }
        debug!(
            address = %evidence.address,
            height = evidence.height,
            round = evidence.round,
            reason = reason_label,
            "recorded consensus evidence"
        );
        self.emit_witness_json(GossipTopic::WitnessMeta, &evidence);
        if evidence.kind == EvidenceKind::InvalidProposal {
            let should_clear = {
                let lock = self.consensus_lock.read();
                lock.as_ref()
                    .map(|locked| {
                        locked.height == evidence.height
                            && (evidence.block_hashes.is_empty()
                                || evidence
                                    .block_hashes
                                    .iter()
                                    .any(|hash| hash == &locked.block_hash))
                    })
                    .unwrap_or(false)
            };
            if should_clear {
                self.clear_consensus_lock();
            }
        }
        if let Some(vote_kind) = evidence.vote_kind {
            let mut mempool = self.vote_mempool.write();
            mempool.retain(|vote| {
                !(vote.vote.vote.voter == evidence.address
                    && vote.vote.vote.height == evidence.height
                    && vote.vote.vote.round == evidence.round
                    && vote.vote.vote.kind == vote_kind)
            });
        }
    }

    fn submit_vrf_submission(&self, submission: VrfSubmission) -> ChainResult<()> {
        let address = submission.address.clone();
        let epoch = submission.input.epoch;
        verify_submission(&submission)?;
        {
            let mut epoch_manager = self.vrf_epoch.write();
            if !epoch_manager.register_submission(&submission) {
                debug!(address = %address, epoch, "duplicate VRF submission ignored");
                return Ok(());
            }
        }
        let mut pool = self.vrf_mempool.write();
        if let Some(existing) = pool.get(&address) {
            if existing.input != submission.input {
                debug!(
                    address = %address,
                    prev_epoch = existing.input.epoch,
                    new_epoch = epoch,
                    "updated VRF submission"
                );
            }
        } else {
            debug!(address = %address, epoch, "recorded VRF submission");
        }
        let local_payload = if address == self.address {
            Some(submission_to_gossip(&submission))
        } else {
            None
        };
        vrf::submit_vrf(&mut pool, submission);
        if let Some(payload) = local_payload {
            self.emit_witness_json(GossipTopic::VrfProofs, &payload);
        }
        Ok(())
    }

    fn submit_uptime_proof(&self, proof: UptimeProof) -> ChainResult<u64> {
        let credited = self.ledger.apply_uptime_proof(&proof)?;
        if let Some(account) = self.ledger.get_account(&proof.wallet_address) {
            self.storage.persist_account(&account)?;
        }
        {
            let mut queue = self.uptime_mempool.write();
            queue.push_back(RecordedUptimeProof {
                proof: proof.clone(),
                credited_hours: credited,
            });
        }
        Ok(credited)
    }

    fn timetoke_snapshot(&self) -> ChainResult<Vec<TimetokeRecord>> {
        let records = self.ledger.timetoke_snapshot();
        let addresses: Vec<Address> = records
            .iter()
            .map(|record| record.identity.clone())
            .collect();
        self.persist_timetoke_accounts(&addresses)?;
        self.emit_witness_json(GossipTopic::Snapshots, &records);
        self.emit_timetoke_meta(&records);
        Ok(records)
    }

    fn sync_timetoke_records(&self, records: Vec<TimetokeRecord>) -> ChainResult<Vec<Address>> {
        let updated = self.ledger.sync_timetoke_records(&records)?;
        self.persist_timetoke_accounts(&updated)?;
        if !updated.is_empty() {
            self.emit_witness_json(GossipTopic::Snapshots, &updated);
        }
        self.emit_timetoke_meta(&records);
        Ok(updated)
    }

    fn get_block(&self, height: u64) -> ChainResult<Option<Block>> {
        self.storage.read_block(height)
    }

    fn latest_block(&self) -> ChainResult<Option<Block>> {
        let tip_height = self.chain_tip.read().height;
        self.storage.read_block(tip_height)
    }

    fn get_account(&self, address: &str) -> ChainResult<Option<Account>> {
        Ok(self.ledger.get_account(address))
    }

    fn node_status(&self) -> ChainResult<NodeStatus> {
        let tip = self.chain_tip.read().clone();
        let epoch_info: EpochInfo = self.ledger.epoch_info();
        let metadata = self.storage.tip()?;
        let verifier_metrics = self.verifiers.metrics_snapshot();
        let block_backlog = self.proposal_inbox.read().len();
        let transaction_backlog = self.mempool.read().len();
        let identity_backlog = self.identity_mempool.read().len();
        let vote_backlog = self.vote_mempool.read().len();
        let uptime_backlog = self.uptime_mempool.read().len();
        self.runtime_metrics
            .record_backlog(block_backlog, transaction_backlog);
        let mut backend_health = BTreeMap::new();
        for (backend, metrics) in verifier_metrics.per_backend {
            backend_health.insert(
                backend.clone(),
                BackendHealthReport {
                    verifier_sla: Some(verifier_sla_status(&metrics)),
                    verifier: metrics,
                    prover: None,
                    prover_sla: None,
                },
            );
        }
        #[cfg(feature = "backend-plonky3")]
        {
            let entry = backend_health
                .entry("plonky3".to_string())
                .or_insert_with(|| BackendHealthReport {
                    verifier: BackendVerificationMetrics::default(),
                    prover: None,
                    verifier_sla: Some(verifier_sla_status(&BackendVerificationMetrics::default())),
                    prover_sla: None,
                });
            let prover_health = plonky3_prover_telemetry();
            entry.prover_sla = Some(plonky3_prover_sla(&prover_health));
            entry.prover = Some(prover_health);
        }
        Ok(NodeStatus {
            address: self.address.clone(),
            height: tip.height,
            last_hash: hex::encode(tip.last_hash),
            epoch: epoch_info.epoch,
            epoch_nonce: epoch_info.epoch_nonce,
            pending_block_proposals: block_backlog,
            pending_transactions: transaction_backlog,
            pending_identities: identity_backlog,
            pending_votes: vote_backlog,
            pending_uptime_proofs: uptime_backlog,
            vrf_metrics: self.vrf_metrics.read().clone(),
            tip: metadata,
            backend_health,
        })
    }

    fn vrf_threshold(&self) -> VrfThresholdStatus {
        self.vrf_threshold.read().clone()
    }

    fn mempool_status(&self) -> ChainResult<MempoolStatus> {
        let mempool = self.mempool.read();
        let metadata_store = self.pending_transaction_metadata.read();
        let transactions = mempool
            .iter()
            .map(|bundle| {
                let hash = bundle.hash();
                let payload = bundle.transaction.payload.clone();
                let metadata = metadata_store
                    .get(&hash)
                    .cloned()
                    .unwrap_or_else(|| PendingTransactionMetadata::from_bundle(bundle));
                PendingTransactionSummary {
                    hash,
                    from: payload.from,
                    to: payload.to,
                    amount: payload.amount,
                    fee: payload.fee,
                    nonce: payload.nonce,
                    proof: Some(metadata.proof),
                    witness: metadata.witness,
                    proof_payload: metadata.proof_payload,
                    #[cfg(feature = "backend-rpp-stark")]
                    public_inputs_digest: metadata.public_inputs_digest,
                }
            })
            .collect();
        let identities = self
            .identity_mempool
            .read()
            .iter()
            .map(|request| PendingIdentitySummary {
                wallet_addr: request.declaration.genesis.wallet_addr.clone(),
                commitment: request.declaration.commitment().to_string(),
                epoch_nonce: request.declaration.genesis.epoch_nonce.clone(),
                state_root: request.declaration.genesis.state_root.clone(),
                identity_root: request.declaration.genesis.identity_root.clone(),
                vrf_tag: request.declaration.genesis.vrf_tag().to_string(),
                attested_votes: request.attested_votes.len(),
                gossip_confirmations: request.gossip_confirmations.len(),
            })
            .collect();
        let votes = self
            .vote_mempool
            .read()
            .iter()
            .map(|entry| PendingVoteSummary {
                hash: entry.vote.hash(),
                voter: entry.vote.vote.voter.clone(),
                height: entry.vote.vote.height,
                round: entry.vote.vote.round,
                block_hash: entry.vote.vote.block_hash.clone(),
                kind: entry.vote.vote.kind,
            })
            .collect();
        let uptime_proofs = self
            .uptime_mempool
            .read()
            .iter()
            .map(|record| PendingUptimeSummary {
                identity: record.proof.wallet_address.clone(),
                window_start: record.proof.window_start,
                window_end: record.proof.window_end,
                credited_hours: record.credited_hours,
            })
            .collect();
        Ok(MempoolStatus {
            transactions: encode_pending_summaries(transactions, "transaction")?,
            identities: encode_pending_summaries(identities, "identity")?,
            votes: encode_pending_summaries(votes, "vote")?,
            uptime_proofs: encode_pending_summaries(uptime_proofs, "uptime proof")?,
            queue_weights: self.queue_weights(),
        })
    }

    fn rollout_status(&self) -> RolloutStatus {
        RolloutStatus {
            release_channel: self.config.rollout.release_channel,
            feature_gates: self.config.rollout.feature_gates.clone(),
            telemetry: TelemetryRuntimeStatus {
                enabled: self.config.rollout.telemetry.enabled,
                endpoint: self.config.rollout.telemetry.endpoint.clone(),
                sample_interval_secs: self.config.rollout.telemetry.sample_interval_secs,
                last_observed_height: None,
            },
        }
    }

    fn consensus_status(&self) -> ChainResult<ConsensusStatus> {
        let tip = self.chain_tip.read().clone();
        let block = self.storage.read_block(tip.height)?;
        let epoch_info = self.ledger.epoch_info();
        let pending_votes = self.vote_mempool.read().len();
        let telemetry = self.consensus_telemetry.snapshot();
        let (
            block_hash,
            proposer,
            round,
            total_power,
            quorum_threshold,
            pre_vote_power,
            pre_commit_power,
            commit_power,
            observers,
            quorum_reached,
        ) = if let Some(block) = block.as_ref() {
            let certificate = &block.consensus;
            let commit = Natural::from_str(&certificate.commit_power)
                .unwrap_or_else(|_| Natural::from(0u32));
            let quorum = Natural::from_str(&certificate.quorum_threshold)
                .unwrap_or_else(|_| Natural::from(0u32));
            (
                Some(block.hash.clone()),
                Some(block.header.proposer.clone()),
                certificate.round,
                certificate.total_power.clone(),
                certificate.quorum_threshold.clone(),
                certificate.pre_vote_power.clone(),
                certificate.pre_commit_power.clone(),
                certificate.commit_power.clone(),
                certificate.observers,
                commit >= quorum && commit > Natural::from(0u32),
            )
        } else {
            (
                None,
                None,
                0,
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
                0,
                false,
            )
        };

        Ok(ConsensusStatus {
            height: tip.height,
            block_hash,
            proposer,
            round,
            total_power,
            quorum_threshold,
            pre_vote_power,
            pre_commit_power,
            commit_power,
            quorum_reached,
            observers,
            epoch: epoch_info.epoch,
            epoch_nonce: epoch_info.epoch_nonce,
            pending_votes,
            round_latencies_ms: telemetry.round_latencies_ms,
            leader_changes: telemetry.leader_changes,
            quorum_latency_ms: telemetry.quorum_latency_ms,
            witness_events: telemetry.witness_events,
            slashing_events: telemetry.slashing_events,
            failed_votes: telemetry.failed_votes,
        })
    }

    fn consensus_proof_status(&self) -> ChainResult<Option<ConsensusProofStatus>> {
        let certificate = {
            let state = self.consensus_state.read();
            state.last_certificate.clone()
        };
        match certificate {
            Some(certificate) => summarize_consensus_certificate(&certificate).map(Some),
            None => Ok(None),
        }
    }

    fn vrf_status(&self, address: &str) -> ChainResult<VrfStatus> {
        let epoch_info = self.ledger.epoch_info();
        let nonce = self.ledger.current_epoch_nonce();
        let proof = evaluate_vrf(
            &nonce,
            0,
            &address.to_string(),
            0,
            Some(&self.vrf_keypair.secret),
        )?;
        Ok(VrfStatus {
            address: address.to_string(),
            epoch: epoch_info.epoch,
            epoch_nonce: epoch_info.epoch_nonce,
            public_key: vrf_public_key_to_hex(&self.vrf_keypair.public),
            proof,
        })
    }

    fn vrf_history(&self, epoch: Option<u64>) -> ChainResult<Vec<VrfHistoryRecord>> {
        Ok(self.ledger.vrf_history(epoch))
    }

    fn slashing_events(&self, limit: usize) -> ChainResult<Vec<SlashingEvent>> {
        Ok(self.ledger.slashing_events(limit))
    }

    fn reputation_audit(&self, address: &str) -> ChainResult<Option<ReputationAudit>> {
        let audit = self.ledger.reputation_audit(address)?;
        Ok(audit.map(|mut audit| {
            self.sign_reputation_audit(&mut audit);
            audit
        }))
    }

    fn recent_slashing_audits(&self, limit: usize) -> ChainResult<Vec<SlashingEvent>> {
        self.audit_exporter.recent_slashing(limit)
    }

    fn recent_reputation_audits(&self, limit: usize) -> ChainResult<Vec<ReputationAudit>> {
        self.audit_exporter.recent_reputation(limit)
    }

    fn build_local_vote(
        &self,
        height: u64,
        round: u64,
        block_hash: &str,
        kind: BftVoteKind,
    ) -> SignedBftVote {
        let vote = BftVote {
            round,
            height,
            block_hash: block_hash.to_string(),
            voter: self.address.clone(),
            kind,
        };
        let signature = sign_message(&self.keypair, &vote.message_bytes());
        SignedBftVote {
            vote,
            public_key: hex::encode(self.keypair.public.to_bytes()),
            signature: signature_to_hex(&signature),
        }
    }

    fn vote_backend(&self, block: &Block) -> ProofVerificationBackend {
        block
            .consensus_proof
            .as_ref()
            .map(proof_backend)
            .unwrap_or(ProofVerificationBackend::Stwo)
    }

    fn record_vote_latency(
        &self,
        vote: &SignedBftVote,
        received_at: SystemTime,
        backend: ProofVerificationBackend,
    ) {
        let Ok(latency) = SystemTime::now().duration_since(received_at) else {
            return;
        };
        let epoch = self.ledger.epoch_info().epoch;
        self.runtime_metrics.record_consensus_vote_latency(
            &vote.vote.voter,
            epoch,
            vote.vote.height,
            backend,
            latency,
        );
    }

    fn gather_vrf_submissions(
        &self,
        epoch: u64,
        seed: [u8; 32],
        candidates: &[ValidatorCandidate],
    ) -> VrfSubmissionPool {
        let candidate_addresses: HashSet<Address> = candidates
            .iter()
            .map(|candidate| candidate.address.clone())
            .collect();
        let mut pool = {
            let mut mempool = self.vrf_mempool.write();
            mempool.retain(|address, submission| {
                submission.input.epoch == epoch
                    && submission.input.last_block_header == seed
                    && candidate_addresses.contains(address)
            });
            mempool.clone()
        };

        for candidate in candidates {
            if candidate.address != self.address {
                continue;
            }
            let tier_seed = vrf::derive_tier_seed(&candidate.address, candidate.timetoke_hours);
            let input = PoseidonVrfInput::new(seed, epoch, tier_seed);
            match vrf::generate_vrf(&input, &self.vrf_keypair.secret) {
                Ok(output) => {
                    let submission = VrfSubmission {
                        address: candidate.address.clone(),
                        public_key: Some(self.vrf_keypair.public.clone()),
                        input,
                        proof: VrfProof::from_output(&output),
                        tier: candidate.tier.clone(),
                        timetoke_hours: candidate.timetoke_hours,
                    };
                    vrf::submit_vrf(&mut pool, submission.clone());
                    if let Err(err) = self.submit_vrf_submission(submission) {
                        warn!(
                            address = %candidate.address,
                            ?err,
                            "failed to persist local VRF submission"
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        address = %candidate.address,
                        ?err,
                        "failed to produce local VRF submission"
                    );
                }
            }
        }
        pool
    }

    fn slash_validator(&self, address: &str, reason: SlashingReason) -> ChainResult<()> {
        let event = self
            .ledger
            .slash_validator(address, reason, Some(&self.keypair))?;
        self.audit_exporter.export_slashing(&event)?;
        self.consensus_telemetry
            .record_slashing(format!("{:?}", event.reason));
        self.update_runtime_metrics();
        self.maybe_refresh_local_identity(address);
        Ok(())
    }

    fn sign_reputation_audit(&self, audit: &mut ReputationAudit) {
        if audit.signature.is_some() {
            return;
        }
        let signature = sign_message(&self.keypair, audit.evidence_hash.as_bytes());
        audit.signature = Some(signature_to_hex(&signature));
    }

    fn maybe_refresh_local_identity(&self, address: &str) {
        if address != self.address {
            return;
        }
        self.update_runtime_metrics();
        self.refresh_local_network_identity();
    }

    fn refresh_local_network_identity(&self) {
        let profile = match self.network_identity_profile() {
            Ok(profile) => profile,
            Err(err) => {
                warn!(
                    ?err,
                    "failed to collect network identity profile for refresh"
                );
                return;
            }
        };
        let Some(handle) = self.p2p_runtime.lock().clone() else {
            debug!(tier = ?profile.tier, "p2p runtime not initialised; skipping identity refresh");
            return;
        };
        if tokio::runtime::Handle::try_current().is_err() {
            warn!(tier = ?profile.tier, "no async runtime available for identity refresh");
            return;
        }
        let tier = profile.tier;
        let runtime_profile = RuntimeIdentityProfile::from(profile);
        let refresh_span = info_span!("runtime.identity.refresh", tier = ?tier);
        tokio::spawn(
            async move {
                if let Err(err) = handle.update_identity(runtime_profile).await {
                    warn!(?err, tier = ?tier, "failed to update libp2p identity profile");
                } else {
                    debug!(tier = ?tier, "updated libp2p identity profile");
                }
            }
            .instrument(refresh_span),
        );
    }

    fn drain_votes_for(&self, height: u64, block_hash: &str) -> Vec<QueuedVote> {
        let mut mempool = self.vote_mempool.write();
        let mut retained = VecDeque::new();
        let mut matched = Vec::new();
        while let Some(vote) = mempool.pop_front() {
            if vote.vote.vote.height == height && vote.vote.vote.block_hash == block_hash {
                matched.push(vote);
            } else {
                retained.push_back(vote);
            }
        }
        *mempool = retained;
        matched
    }

    fn current_consensus_round(&self, height: u64) -> u64 {
        self.consensus_rounds
            .read()
            .get(&height)
            .copied()
            .unwrap_or(0)
    }

    fn observe_consensus_round(&self, height: u64, round: u64) {
        {
            let mut rounds = self.consensus_rounds.write();
            let entry = rounds.entry(height).or_insert(round);
            if round > *entry {
                *entry = round;
            }
        }
        let should_clear_lock = {
            let lock = self.consensus_lock.read();
            lock.as_ref()
                .map(|locked| locked.height == height && round > locked.round)
                .unwrap_or(false)
        };
        if should_clear_lock {
            self.clear_consensus_lock();
        }
        self.persist_observed_consensus_round(None);
    }

    fn prune_consensus_rounds_below(&self, threshold_height: u64) {
        self.consensus_rounds
            .write()
            .retain(|&tracked_height, _| tracked_height >= threshold_height);
        let should_clear_lock = {
            let lock = self.consensus_lock.read();
            lock.as_ref()
                .map(|locked| locked.height < threshold_height)
                .unwrap_or(false)
        };
        if should_clear_lock {
            self.clear_consensus_lock();
        }
        self.persist_observed_consensus_round(Some(threshold_height));
    }

    fn take_verified_proposal(&self, height: u64, proposer: &Address) -> Option<Block> {
        let mut inbox = self.proposal_inbox.write();
        inbox
            .remove(&(height, proposer.clone()))
            .map(|proposal| proposal.block)
    }

    fn persist_consensus_state<F>(&self, update: F)
    where
        F: FnOnce(&mut ConsensusRecoveryState),
    {
        let mut state = self.consensus_state.write();
        let mut updated = state.clone();
        update(&mut updated);
        if Self::consensus_states_equal(&state, &updated) {
            return;
        }
        match self.storage.write_consensus_state(&updated) {
            Ok(()) => {
                *state = updated;
            }
            Err(err) => {
                warn!(?err, "failed to persist consensus recovery state");
            }
        }
    }

    fn consensus_states_equal(
        current: &ConsensusRecoveryState,
        updated: &ConsensusRecoveryState,
    ) -> bool {
        if current.height != updated.height
            || current.round != updated.round
            || current.locked_proposal != updated.locked_proposal
        {
            return false;
        }
        match (&current.last_certificate, &updated.last_certificate) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                let left_bytes = bincode::serialize(left);
                let right_bytes = bincode::serialize(right);
                match (left_bytes, right_bytes) {
                    (Ok(left_encoded), Ok(right_encoded)) => left_encoded == right_encoded,
                    (Err(err), _) | (_, Err(err)) => {
                        warn!(
                            ?err,
                            "failed to serialize consensus certificate for comparison"
                        );
                        false
                    }
                }
            }
            _ => false,
        }
    }

    fn persist_observed_consensus_round(&self, fallback_height: Option<u64>) {
        let observed = {
            let rounds = self.consensus_rounds.read();
            rounds
                .iter()
                .max_by_key(|(height, _)| *height)
                .map(|(height, round)| (*height, *round))
        };
        let (height, round) = if let Some(entry) = observed {
            entry
        } else {
            let fallback =
                fallback_height.unwrap_or_else(|| self.chain_tip.read().height.saturating_add(1));
            (fallback, 0)
        };
        self.persist_consensus_state(|state| {
            state.height = height;
            state.round = round;
        });
    }

    fn set_consensus_lock(&self, height: u64, round: u64, block_hash: &str) {
        let new_lock = ConsensusLockState {
            height,
            round,
            block_hash: block_hash.to_string(),
        };
        let already_locked = {
            let lock = self.consensus_lock.read();
            lock.as_ref() == Some(&new_lock)
        };
        if already_locked {
            return;
        }
        {
            let mut lock = self.consensus_lock.write();
            *lock = Some(new_lock.clone());
        }
        self.persist_consensus_state(|state| {
            state.height = height;
            state.round = round;
            state.locked_proposal = Some(new_lock.block_hash.clone());
        });
        debug!(
            height,
            round,
            block_hash = %new_lock.block_hash,
            "consensus lock updated"
        );
    }

    fn clear_consensus_lock(&self) {
        let cleared = {
            let mut lock = self.consensus_lock.write();
            lock.take()
        };
        if cleared.is_some() {
            self.persist_consensus_state(|state| {
                state.locked_proposal = None;
            });
            debug!("consensus lock cleared");
        }
    }

    fn clear_consensus_lock_for(&self, height: u64, block_hash: &str) {
        let should_clear = {
            let lock = self.consensus_lock.read();
            lock.as_ref()
                .map(|locked| locked.height == height && locked.block_hash == block_hash)
                .unwrap_or(false)
        };
        if should_clear {
            self.clear_consensus_lock();
        }
    }

    fn record_committed_certificate(&self, certificate: &ConsensusCertificate) {
        let cert_clone = certificate.clone();
        self.persist_consensus_state(|state| {
            state.height = cert_clone.height;
            state.round = cert_clone.round;
            state.locked_proposal = None;
            state.last_certificate = Some(cert_clone.clone());
        });
    }

    #[cfg(feature = "prover-stwo")]
    fn map_backend_error(err: crate::proof_backend::BackendError) -> ChainError {
        match err {
            crate::proof_backend::BackendError::Failure(message) => ChainError::Crypto(message),
            crate::proof_backend::BackendError::Unsupported(context) => {
                ChainError::Crypto(format!("STWO backend unsupported: {context}"))
            }
            crate::proof_backend::BackendError::Serialization(err) => {
                ChainError::Crypto(format!("failed to encode STWO payload: {err}"))
            }
        }
    }

    #[cfg(feature = "prover-stwo")]
    #[allow(clippy::too_many_arguments)]
    fn generate_local_block_proofs(
        storage: &Storage,
        ledger: &Ledger,
        header: &BlockHeader,
        commitments: &GlobalStateCommitments,
        pruning_proof: &PruningProof,
        accepted_identities: &[AttestedIdentityRequest],
        transactions: &[SignedTransaction],
        transaction_proofs: Vec<ChainProof>,
        identity_proofs: &[ChainProof],
        uptime_proofs: &[UptimeProof],
        previous_block: Option<&Block>,
        consensus_certificate: Option<&ConsensusCertificate>,
        block_hash: Option<&str>,
        max_proof_size_bytes: usize,
    ) -> ChainResult<LocalProofArtifacts> {
        let prover = WalletProver::new(storage);
        let backend = StwoBackend::new();
        let backend_kind = ProofSystemKind::Stwo;

        let previous_state_root_hex =
            hex::encode(pruning_proof.snapshot().state_commitment().digest());
        let state_witness = {
            let span = proof_operation_span(
                "build_state_witness",
                backend_kind,
                Some(header.height),
                block_hash,
            );
            let _guard = span.enter();
            prover.build_state_witness(
                &previous_state_root_hex,
                &header.state_root,
                accepted_identities,
                transactions,
            )?
        };
        let state_bytes = WitnessBytes::encode(
            &WitnessHeader::new(ProofSystemKind::Stwo, "state"),
            &state_witness,
        )
        .map_err(Self::map_backend_error)?;
        let (state_pk, _) = backend
            .keygen_state(&StateCircuitDef::new("state"))
            .map_err(Self::map_backend_error)?;
        let state_proof_bytes = {
            let span = proof_operation_span(
                "prove_state_transition",
                backend_kind,
                Some(header.height),
                block_hash,
            );
            let _guard = span.enter();
            backend
                .prove_state(&state_pk, &state_bytes)
                .map_err(Self::map_backend_error)?
        };
        let state_stark =
            decode_state_proof(&state_proof_bytes).map_err(Self::map_backend_error)?;
        let state_chain_proof = ChainProof::Stwo(state_stark);

        let previous_transactions = previous_block
            .map(|block| block.transactions.clone())
            .unwrap_or_default();
        let previous_identities = previous_block
            .map(|block| block.identities.clone())
            .unwrap_or_default();
        let expected_previous_state_root =
            previous_block.map(|block| block.header.state_root.clone());
        let pruning_witness = {
            let span = proof_operation_span(
                "build_pruning_witness",
                backend_kind,
                Some(header.height),
                block_hash,
            );
            let _guard = span.enter();
            prover.build_pruning_witness(
                expected_previous_state_root.as_deref(),
                &previous_identities,
                &previous_transactions,
                pruning_proof.as_ref(),
                Vec::new(),
            )?
        };
        let pruning_bytes = WitnessBytes::encode(
            &WitnessHeader::new(ProofSystemKind::Stwo, "pruning"),
            &pruning_witness,
        )
        .map_err(Self::map_backend_error)?;
        let (pruning_pk, _) = backend
            .keygen_pruning(&PruningCircuitDef::new("pruning"))
            .map_err(Self::map_backend_error)?;
        let pruning_proof_bytes = {
            let span = proof_operation_span(
                "prove_pruning",
                backend_kind,
                Some(header.height),
                block_hash,
            );
            let _guard = span.enter();
            backend
                .prove_pruning(&pruning_pk, &pruning_bytes)
                .map_err(Self::map_backend_error)?
        };
        let pruning_stark =
            decode_pruning_proof(&pruning_proof_bytes).map_err(Self::map_backend_error)?;
        let pruning_chain_proof = ChainProof::Stwo(pruning_stark);

        let previous_recursive = previous_block.map(|block| &block.stark.recursive_proof);

        let uptime_chain_proofs: Vec<ChainProof> = uptime_proofs
            .iter()
            .map(|proof| {
                proof.proof.clone().ok_or_else(|| {
                    ChainError::Crypto("uptime proof missing zk proof payload".into())
                })
            })
            .collect::<ChainResult<_>>()?;

        let mut consensus_chain_proof = None;
        if let Some(certificate) = consensus_certificate {
            let block_hash = block_hash.expect("consensus block hash must be present");
            let consensus_witness = {
                let span = proof_operation_span(
                    "build_consensus_witness",
                    backend_kind,
                    Some(header.height),
                    Some(block_hash),
                );
                let _guard = span.enter();
                prover.build_consensus_witness(block_hash, certificate)?
            };
            let consensus_bytes = WitnessBytes::encode(
                &WitnessHeader::new(ProofSystemKind::Stwo, "consensus"),
                &consensus_witness,
            )
            .map_err(Self::map_backend_error)?;
            let (consensus_proof_bytes, _vk, _circuit) = {
                let span = proof_operation_span(
                    "prove_consensus",
                    backend_kind,
                    Some(header.height),
                    Some(block_hash),
                );
                let _guard = span.enter();
                backend
                    .prove_consensus(&consensus_bytes)
                    .map_err(Self::map_backend_error)?
            };
            let (_, consensus_stark) =
                decode_consensus_proof(&consensus_proof_bytes).map_err(Self::map_backend_error)?;
            consensus_chain_proof = Some(ChainProof::Stwo(consensus_stark));
        }

        let mut consensus_chain_proofs = Vec::new();
        if let Some(proof) = consensus_chain_proof.as_ref() {
            consensus_chain_proofs.push(proof.clone());
        }

        let recursive_witness = {
            let span = proof_operation_span(
                "build_recursive_witness",
                backend_kind,
                Some(header.height),
                block_hash,
            );
            let _guard = span.enter();
            prover.build_recursive_witness(
                previous_recursive,
                identity_proofs,
                &transaction_proofs,
                &uptime_chain_proofs,
                &consensus_chain_proofs,
                commitments,
                &state_chain_proof,
                pruning_proof.as_ref(),
                &pruning_chain_proof,
                header.height,
            )?
        };
        let recursive_bytes = WitnessBytes::encode(
            &WitnessHeader::new(ProofSystemKind::Stwo, "recursive"),
            &recursive_witness,
        )
        .map_err(Self::map_backend_error)?;
        let (recursive_pk, _) = backend
            .keygen_recursive(&RecursiveCircuitDef::new("recursive"))
            .map_err(Self::map_backend_error)?;
        let recursive_proof_bytes = {
            let span = proof_operation_span(
                "prove_recursive",
                backend_kind,
                Some(header.height),
                block_hash,
            );
            let _guard = span.enter();
            backend
                .prove_recursive(&recursive_pk, &recursive_bytes)
                .map_err(Self::map_backend_error)?
        };
        let recursive_stark =
            decode_recursive_proof(&recursive_proof_bytes).map_err(Self::map_backend_error)?;
        let recursive_chain_proof = ChainProof::Stwo(recursive_stark);

        let bundle = BlockProofBundle::new(
            transaction_proofs,
            state_chain_proof.clone(),
            pruning_chain_proof.clone(),
            recursive_chain_proof.clone(),
        );

        let module_witnesses = ledger.drain_module_witnesses();
        let module_artifacts = ledger.stage_module_witnesses(&module_witnesses)?;
        let mut proof_artifacts = Self::collect_proof_artifacts(&bundle, max_proof_size_bytes)?;
        proof_artifacts.extend(module_artifacts);

        Ok(LocalProofArtifacts {
            bundle,
            consensus_proof: consensus_chain_proof,
            module_witnesses,
            proof_artifacts,
        })
    }

    #[cfg(not(feature = "prover-stwo"))]
    #[allow(clippy::too_many_arguments)]
    fn generate_local_block_proofs(
        storage: &Storage,
        ledger: &Ledger,
        header: &BlockHeader,
        commitments: &GlobalStateCommitments,
        pruning_proof: &PruningProof,
        accepted_identities: &[AttestedIdentityRequest],
        transactions: &[SignedTransaction],
        transaction_proofs: Vec<ChainProof>,
        identity_proofs: &[ChainProof],
        uptime_proofs: &[UptimeProof],
        previous_block: Option<&Block>,
        consensus_certificate: Option<&ConsensusCertificate>,
        block_hash: Option<&str>,
        max_proof_size_bytes: usize,
    ) -> ChainResult<LocalProofArtifacts> {
        let _ = (
            storage,
            ledger,
            header,
            commitments,
            pruning_proof,
            accepted_identities,
            transactions,
            transaction_proofs,
            identity_proofs,
            uptime_proofs,
            previous_block,
            consensus_certificate,
            block_hash,
            max_proof_size_bytes,
        );
        Err(ChainError::Crypto("STWO prover disabled".into()))
    }

    #[instrument(
        name = "node.proof.collect_artifacts",
        skip(self, bundle),
        fields(
            transaction_proofs = bundle.transaction_proofs.len(),
            max_bytes = max_bytes
        )
    )]
    fn collect_proof_artifacts(
        bundle: &BlockProofBundle,
        max_bytes: usize,
    ) -> ChainResult<Vec<ProofArtifact>> {
        let mut artifacts = Vec::new();
        for proof in &bundle.transaction_proofs {
            if let Some(artifact) = Self::proof_artifact(ProofModule::Utxo, proof, max_bytes)? {
                artifacts.push(artifact);
            }
        }
        if let Some(artifact) =
            Self::proof_artifact(ProofModule::BlockTransition, &bundle.state_proof, max_bytes)?
        {
            artifacts.push(artifact);
        }
        if let Some(artifact) =
            Self::proof_artifact(ProofModule::Consensus, &bundle.pruning_proof, max_bytes)?
        {
            artifacts.push(artifact);
        }
        if let Some(artifact) =
            Self::proof_artifact(ProofModule::Consensus, &bundle.recursive_proof, max_bytes)?
        {
            artifacts.push(artifact);
        }
        Ok(artifacts)
    }

    #[instrument(
        name = "node.proof.encode_artifact",
        skip(proof),
        fields(module = ?module, max_bytes = max_bytes)
    )]
    fn proof_artifact(
        module: ProofModule,
        proof: &ChainProof,
        max_bytes: usize,
    ) -> ChainResult<Option<ProofArtifact>> {
        match proof {
            ChainProof::Stwo(stark) => {
                let bytes = match hex::decode(&stark.commitment) {
                    Ok(bytes) => bytes,
                    Err(_) => return Ok(None),
                };
                let mut commitment = [0u8; 32];
                if bytes.len() >= 32 {
                    commitment.copy_from_slice(&bytes[..32]);
                } else {
                    commitment[..bytes.len()].copy_from_slice(&bytes);
                }
                let encoded = serde_json::to_vec(proof).map_err(|err| {
                    ChainError::Config(format!(
                        "failed to encode {:?} proof artifact: {err}",
                        module
                    ))
                })?;
                if encoded.len() > max_bytes {
                    return Err(ChainError::Config(format!(
                        "proof artifact for {:?} exceeds max_proof_size_bytes ({max_bytes})",
                        module
                    )));
                }
                Ok(Some(ProofArtifact {
                    module,
                    commitment,
                    proof: encoded,
                    verification_key: None,
                }))
            }
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(stark) => {
                let digest = compute_public_digest(stark.public_inputs()).into_bytes();
                let encoded = serde_json::to_vec(stark).map_err(|err| {
                    ChainError::Config(format!(
                        "failed to encode {:?} proof artifact: {err}",
                        module
                    ))
                })?;
                if encoded.len() > max_bytes {
                    return Err(ChainError::Config(format!(
                        "proof artifact for {:?} exceeds max_proof_size_bytes ({max_bytes})",
                        module
                    )));
                }
                Ok(Some(ProofArtifact {
                    module,
                    commitment: digest,
                    proof: encoded,
                    verification_key: None,
                }))
            }
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => Ok(None),
        }
    }

    #[instrument(
        name = "node.consensus.produce_block",
        skip(self),
        fields(
            height = tracing::field::Empty,
            round = tracing::field::Empty
        )
    )]
    fn produce_block(&self) -> ChainResult<()> {
        let span = Span::current();
        let tip_snapshot = self.chain_tip.read().clone();
        let height = tip_snapshot.height + 1;
        span.record("height", &height);
        self.prune_consensus_rounds_below(height);
        self.sync_epoch_with_metrics(height);
        let epoch = self.ledger.current_epoch();
        self.runtime_metrics.record_block_schedule_slot(epoch);
        let accounts_snapshot = self.ledger.accounts_snapshot();
        let (validators, observers) = classify_participants(&accounts_snapshot);
        let vrf_pool = self.gather_vrf_submissions(epoch, tip_snapshot.last_hash, &validators);
        let round_number = self.current_consensus_round(height);
        span.record("round", &round_number);
        self.observe_consensus_round(height, round_number);
        let mut round = ConsensusRound::new(
            height,
            round_number,
            tip_snapshot.last_hash,
            self.config.validator_set_size(),
            validators,
            observers,
            &vrf_pool,
        );
        let round_metrics = round.vrf_metrics().clone();
        {
            let mut metrics = self.vrf_metrics.write();
            *metrics = round_metrics.clone();
        }
        {
            let mut threshold = self.vrf_threshold.write();
            *threshold = VrfThresholdStatus {
                epoch: round_metrics.latest_epoch,
                threshold: round_metrics.active_epoch_threshold.clone(),
                committee_target: round_metrics.target_validator_count,
                pool_entries: round_metrics.pool_entries,
                accepted_validators: round_metrics.accepted_validators,
                participation_rate: round_metrics.participation_rate,
            };
        }
        if let Some(epoch_value) = round_metrics.latest_epoch {
            if let Ok(bytes) = hex::decode(&round_metrics.entropy_beacon) {
                if bytes.len() == 32 {
                    let mut beacon = [0u8; 32];
                    beacon.copy_from_slice(&bytes);
                    self.vrf_epoch.write().record_entropy(epoch_value, beacon);
                }
            }
        }
        self.ledger
            .record_vrf_history(epoch, round.round(), round.vrf_audit());
        let selection = match round.select_proposer() {
            Some(selection) => selection,
            None => {
                warn!("no proposer could be selected");
                return Ok(());
            }
        };
        let expected_weight = {
            let proposer_power = round
                .validators()
                .iter()
                .find(|profile| profile.address == selection.proposer)
                .and_then(|profile| profile.voting_power().to_f64())
                .unwrap_or(0.0);
            let total_power = round.total_power().to_f64().unwrap_or(0.0);
            if total_power > 0.0 {
                (proposer_power / total_power).min(1.0)
            } else {
                0.0
            }
        };
        let round_id = round.round();
        self.consensus_telemetry
            .record_round_start(height, round_id, &selection.proposer);

        if selection.proposer != self.address {
            if let Some(proposal) = self.take_verified_proposal(height, &selection.proposer) {
                info!(
                    proposer = %selection.proposer,
                    height,
                    "processing verified external proposal"
                );
                let block_hash = proposal.hash.clone();
                let backend = self.vote_backend(&proposal.block);
                round.set_block_hash(block_hash.clone());
                let local_prevote =
                    self.build_local_vote(height, round.round(), &block_hash, BftVoteKind::PreVote);
                if let Err(err) = round.register_prevote(&local_prevote) {
                    warn!(
                        ?err,
                        "failed to register local prevote for external proposal"
                    );
                    self.consensus_telemetry
                        .record_failed_vote("local_prevote".to_string());
                    self.update_runtime_metrics();
                } else {
                    self.record_vote_latency(&local_prevote, SystemTime::now(), backend);
                }
                let local_precommit = self.build_local_vote(
                    height,
                    round.round(),
                    &block_hash,
                    BftVoteKind::PreCommit,
                );
                if let Err(err) = round.register_precommit(&local_precommit) {
                    warn!(
                        ?err,
                        "failed to register local precommit for external proposal"
                    );
                    self.consensus_telemetry
                        .record_failed_vote("local_precommit".to_string());
                    self.update_runtime_metrics();
                } else {
                    self.record_vote_latency(&local_precommit, SystemTime::now(), backend);
                    self.set_consensus_lock(height, round.round(), &block_hash);
                }
                let external_votes = self.drain_votes_for(height, &block_hash);
                for vote in &external_votes {
                    let result = match vote.vote.vote.kind {
                        BftVoteKind::PreVote => round.register_prevote(&vote.vote),
                        BftVoteKind::PreCommit => round.register_precommit(&vote.vote),
                    };
                    if let Err(err) = result {
                        warn!(?err, voter = %vote.vote.vote.voter, "rejecting invalid consensus vote");
                        if self.config.rollout.feature_gates.consensus_enforcement {
                            if let Err(slash_err) = self
                                .slash_validator(&vote.vote.vote.voter, SlashingReason::InvalidVote)
                            {
                                warn!(
                                    ?slash_err,
                                    voter = %vote.vote.vote.voter,
                                    "failed to slash validator for invalid vote"
                                );
                            }
                        }
                        self.consensus_telemetry
                            .record_failed_vote("external_vote".to_string());
                        self.update_runtime_metrics();
                    } else {
                        self.record_vote_latency(&vote.vote, vote.received_at, backend);
                    }
                }
                let mut recorded_votes = vec![local_prevote.clone(), local_precommit.clone()];
                recorded_votes.extend(external_votes.iter().map(|vote| vote.vote.clone()));

                let finalization_ctx = FinalizationContext::Local(LocalFinalizationContext {
                    round,
                    block_hash,
                    header: proposal.header.clone(),
                    parent_height: proposal.header.height.saturating_sub(1),
                    commitments: proposal.commitments.clone(),
                    accepted_identities: Vec::new(),
                    transactions: proposal.transactions.clone(),
                    transaction_proofs: Vec::new(),
                    identity_proofs: Vec::new(),
                    uptime_proofs: Vec::new(),
                    timetoke_updates: Vec::new(),
                    reputation_updates: Vec::new(),
                    recorded_votes,
                    expected_proposer: selection.proposer.clone(),
                    expected_weight,
                    epoch,
                });
                match self.finalize_block(finalization_ctx)? {
                    FinalizationOutcome::Sealed { block, tip_height } => {
                        let _ = (block, tip_height);
                        self.consensus_telemetry.record_quorum(height, round_id);
                        self.consensus_telemetry.record_round_end(height, round_id);
                        self.update_runtime_metrics();
                    }
                    FinalizationOutcome::AwaitingQuorum => {}
                }
            } else {
                warn!(
                    proposer = %selection.proposer,
                    height,
                    "no verified proposal available for external leader"
                );
            }
            return Ok(());
        }

        if selection.total_voting_power == 0 {
            warn!("validator set has no voting power");
            return Ok(());
        }

        let existing_lock = self.consensus_lock.read().clone();
        if let Some(lock) = existing_lock {
            if lock.height == height && lock.round == round_id {
                debug!(
                    height,
                    round = round_id,
                    block_hash = %lock.block_hash,
                    "consensus lock persists; skipping duplicate proposal"
                );
                return Ok(());
            }
        }

        let has_identity_candidates = { !self.identity_mempool.read().is_empty() };
        let has_transaction_candidates = { !self.mempool.read().is_empty() };
        let has_uptime_candidates = { !self.uptime_mempool.read().is_empty() };
        if !has_identity_candidates && !has_transaction_candidates && !has_uptime_candidates {
            return Ok(());
        }

        let mut identity_pending: Vec<AttestedIdentityRequest> = Vec::new();
        {
            let mut mempool = self.identity_mempool.write();
            while identity_pending.len() < self.config.max_block_identity_registrations {
                if let Some(request) = mempool.pop_front() {
                    identity_pending.push(request);
                } else {
                    break;
                }
            }
        }

        let mut pending: Vec<TransactionProofBundle> = Vec::new();
        {
            let mut mempool = self.mempool.write();
            if !mempool.is_empty() {
                let mut ordered: Vec<_> = mempool.drain(..).collect();
                ordered.sort_by(Self::compare_transaction_priority);
                for bundle in ordered.into_iter() {
                    if pending.len() < self.config.max_block_transactions {
                        pending.push(bundle);
                    } else {
                        mempool.push_back(bundle);
                    }
                }
            }
        }
        self.purge_transaction_metadata(&pending);

        let mut uptime_pending: Vec<RecordedUptimeProof> = Vec::new();
        {
            let mut mempool = self.uptime_mempool.write();
            while let Some(record) = mempool.pop_front() {
                uptime_pending.push(record);
            }
        }

        if pending.is_empty() && identity_pending.is_empty() && uptime_pending.is_empty() {
            return Ok(());
        }

        self.publish_pipeline_event(PipelineObservation::VrfLeadership {
            height,
            round: round.round(),
            proposer: selection.proposer.clone(),
            randomness: selection.randomness.to_string(),
            block_hash: None,
        });

        let mut accepted_identities: Vec<AttestedIdentityRequest> = Vec::new();
        for request in identity_pending {
            match self.ledger.register_identity(
                &request,
                height,
                IDENTITY_ATTESTATION_QUORUM,
                IDENTITY_ATTESTATION_GOSSIP_MIN,
            ) {
                Ok(_) => accepted_identities.push(request),
                Err(err) => {
                    warn!(?err, "dropping invalid identity declaration");
                    if self.config.rollout.feature_gates.consensus_enforcement {
                        if let Err(slash_err) =
                            self.slash_validator(&self.address, SlashingReason::InvalidIdentity)
                        {
                            warn!(?slash_err, "failed to slash proposer for invalid identity");
                        }
                    }
                }
            }
        }

        let identity_declarations: Vec<IdentityDeclaration> = accepted_identities
            .iter()
            .map(|request| request.declaration.clone())
            .collect();

        let mut accepted: Vec<TransactionProofBundle> = Vec::new();
        let mut total_fees: u64 = 0;
        for bundle in pending {
            match self
                .ledger
                .select_inputs_for_transaction(&bundle.transaction)
                .and_then(|inputs| self.ledger.apply_transaction(&bundle.transaction, &inputs))
            {
                Ok(fee) => {
                    total_fees = total_fees.saturating_add(fee);
                    accepted.push(bundle);
                }
                Err(err) => warn!(?err, "dropping invalid transaction"),
            }
        }

        if accepted.is_empty() && accepted_identities.is_empty() && uptime_pending.is_empty() {
            return Ok(());
        }

        let block_reward = BASE_BLOCK_REWARD.saturating_add(total_fees);
        self.ledger.distribute_consensus_rewards(
            &selection.proposer,
            round.validators(),
            block_reward,
            LEADER_BONUS_PERCENT,
        )?;

        let (transactions, transaction_proofs): (Vec<SignedTransaction>, Vec<_>) = accepted
            .into_iter()
            .map(|bundle| (bundle.transaction, bundle.proof))
            .unzip();

        let identity_proofs: Vec<ChainProof> = accepted_identities
            .iter()
            .map(|request| request.declaration.proof.zk_proof.clone())
            .collect();

        let mut uptime_proofs = Vec::new();
        let mut timetoke_updates = Vec::new();
        for record in uptime_pending {
            let RecordedUptimeProof {
                proof,
                credited_hours,
            } = record;
            timetoke_updates.push(TimetokeUpdate {
                identity: proof.wallet_address.clone(),
                window_start: proof.window_start,
                window_end: proof.window_end,
                credited_hours,
            });
            uptime_proofs.push(proof);
        }

        let mut touched_identities: HashSet<Address> = HashSet::new();
        for tx in &transactions {
            touched_identities.insert(tx.payload.from.clone());
            touched_identities.insert(tx.payload.to.clone());
        }
        for declaration in &identity_declarations {
            touched_identities.insert(declaration.genesis.wallet_addr.clone());
        }
        for update in &timetoke_updates {
            touched_identities.insert(update.identity.clone());
        }

        let mut reputation_updates = Vec::new();
        for identity in touched_identities {
            if let Some(mut audit) = self.ledger.reputation_audit(&identity)? {
                self.sign_reputation_audit(&mut audit);
                self.audit_exporter.export_reputation(&audit)?;
                reputation_updates.push(ReputationUpdate::from(audit));
            }
        }
        reputation_updates.sort_by(|a, b| a.identity.cmp(&b.identity));

        let mut operation_hashes = Vec::new();
        for declaration in &identity_declarations {
            operation_hashes.push(declaration.hash()?);
        }
        for tx in &transactions {
            operation_hashes.push(tx.hash());
        }
        for proof in &uptime_proofs {
            let encoded = serde_json::to_vec(proof).expect("serialize uptime proof");
            operation_hashes.push(Blake2sHasher::hash(&encoded).into());
        }
        for update in &timetoke_updates {
            let encoded = serde_json::to_vec(update).expect("serialize timetoke update");
            operation_hashes.push(Blake2sHasher::hash(&encoded).into());
        }
        for update in &reputation_updates {
            let encoded = serde_json::to_vec(update).expect("serialize reputation update");
            operation_hashes.push(Blake2sHasher::hash(&encoded).into());
        }
        let tx_root = compute_merkle_root(&mut operation_hashes);
        let commitments = self.ledger.global_commitments();
        let header = BlockHeader::new(
            height,
            hex::encode(tip_snapshot.last_hash),
            hex::encode(tx_root),
            hex::encode(commitments.global_state_root),
            hex::encode(commitments.utxo_root),
            hex::encode(commitments.reputation_root),
            hex::encode(commitments.timetoke_root),
            hex::encode(commitments.zsi_root),
            hex::encode(commitments.proof_root),
            selection.total_voting_power.to_string(),
            selection.randomness.to_string(),
            selection.vrf_public_key.clone(),
            selection.proof.preoutput.clone(),
            selection.proof.proof.clone(),
            self.address.clone(),
            selection.tier.to_string(),
            selection.timetoke_hours,
        );
        let block_hash_hex = hex::encode(header.hash());
        round.set_block_hash(block_hash_hex.clone());
        let backend = if cfg!(feature = "backend-rpp-stark") {
            ProofVerificationBackend::RppStark
        } else {
            ProofVerificationBackend::Stwo
        };

        let local_prevote =
            self.build_local_vote(height, round.round(), &block_hash_hex, BftVoteKind::PreVote);
        round.register_prevote(&local_prevote)?;
        self.record_vote_latency(&local_prevote, SystemTime::now(), backend);
        let local_precommit = self.build_local_vote(
            height,
            round.round(),
            &block_hash_hex,
            BftVoteKind::PreCommit,
        );
        round.register_precommit(&local_precommit)?;
        self.record_vote_latency(&local_precommit, SystemTime::now(), backend);
        self.set_consensus_lock(height, round.round(), &block_hash_hex);

        let external_votes = self.drain_votes_for(height, &block_hash_hex);
        for vote in &external_votes {
            let result = match vote.vote.vote.kind {
                BftVoteKind::PreVote => round.register_prevote(&vote.vote),
                BftVoteKind::PreCommit => round.register_precommit(&vote.vote),
            };
            if let Err(err) = result {
                warn!(?err, voter = %vote.vote.vote.voter, "rejecting invalid consensus vote");
                if self.config.rollout.feature_gates.consensus_enforcement {
                    if let Err(slash_err) =
                        self.slash_validator(&vote.vote.vote.voter, SlashingReason::InvalidVote)
                    {
                        warn!(
                            ?slash_err,
                            voter = %vote.vote.vote.voter,
                            "failed to slash validator for invalid vote"
                        );
                    }
                }
                self.consensus_telemetry
                    .record_failed_vote("external_vote".to_string());
                self.update_runtime_metrics();
            } else {
                self.record_vote_latency(&vote.vote, vote.received_at, backend);
            }
        }

        let mut recorded_votes = vec![local_prevote.clone(), local_precommit.clone()];
        recorded_votes.extend(external_votes.iter().map(|vote| vote.vote.clone()));

        let finalization_ctx = FinalizationContext::Local(LocalFinalizationContext {
            round,
            block_hash: block_hash_hex,
            header,
            parent_height: tip_snapshot.height,
            commitments,
            accepted_identities,
            transactions,
            transaction_proofs,
            identity_proofs,
            uptime_proofs,
            timetoke_updates,
            reputation_updates,
            recorded_votes,
            expected_proposer: selection.proposer.clone(),
            expected_weight,
            epoch,
        });

        match self.finalize_block(finalization_ctx)? {
            FinalizationOutcome::Sealed { block, tip_height } => {
                let _ = (block, tip_height);
                self.consensus_telemetry.record_quorum(height, round_id);
                self.consensus_telemetry.record_round_end(height, round_id);
                self.update_runtime_metrics();
            }
            FinalizationOutcome::AwaitingQuorum => {}
        }
        Ok(())
    }
    fn finalize_block(&self, ctx: FinalizationContext) -> ChainResult<FinalizationOutcome> {
        match ctx {
            FinalizationContext::Local(ctx) => self.finalize_local_block(ctx),
            FinalizationContext::External(ctx) => self.finalize_external_block(ctx),
        }
    }

    fn decode_commitment(value: &str) -> ChainResult<[u8; 32]> {
        let bytes = hex::decode(value)
            .map_err(|err| ChainError::Config(format!("invalid commitment encoding: {err}")))?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ChainError::Config("commitment digest must be 32 bytes".into()))?;
        Ok(array)
    }

    fn commitments_from_header(header: &BlockHeader) -> ChainResult<GlobalStateCommitments> {
        Ok(GlobalStateCommitments {
            global_state_root: Self::decode_commitment(&header.state_root)?,
            utxo_root: Self::decode_commitment(&header.utxo_root)?,
            reputation_root: Self::decode_commitment(&header.reputation_root)?,
            timetoke_root: Self::decode_commitment(&header.timetoke_root)?,
            zsi_root: Self::decode_commitment(&header.zsi_root)?,
            proof_root: Self::decode_commitment(&header.proof_root)?,
        })
    }

    fn finalize_local_block(
        &self,
        ctx: LocalFinalizationContext,
    ) -> ChainResult<FinalizationOutcome> {
        let LocalFinalizationContext {
            round,
            block_hash,
            header,
            parent_height,
            commitments,
            accepted_identities,
            transactions,
            transaction_proofs,
            identity_proofs,
            uptime_proofs,
            timetoke_updates,
            reputation_updates,
            recorded_votes,
            expected_proposer,
            expected_weight,
            epoch,
        } = ctx;

        if !round.commit_reached() {
            warn!("quorum not reached for commit");
            return Ok(FinalizationOutcome::AwaitingQuorum);
        }

        let height = header.height;
        let receipt = self.persist_accounts(height)?;
        let pruning_proof = receipt
            .pruning_proof
            .clone()
            .ok_or_else(|| ChainError::Config("firewood pruning envelope missing".into()))?;
        let previous_block = self.storage.read_block(parent_height)?;
        let participants = round.commit_participants();
        let consensus_certificate = round.certificate();
        let witness_bundle =
            build_consensus_witness(height, round.round(), participants, &consensus_certificate);
        self.ledger.record_consensus_witness(&witness_bundle);
        let LocalProofArtifacts {
            bundle: stark_bundle,
            consensus_proof,
            module_witnesses,
            proof_artifacts,
        } = NodeInner::generate_local_block_proofs(
            &self.storage,
            &self.ledger,
            &header,
            &commitments,
            &pruning_proof,
            &accepted_identities,
            &transactions,
            transaction_proofs,
            &identity_proofs,
            &uptime_proofs,
            previous_block.as_ref(),
            Some(&consensus_certificate),
            Some(&block_hash),
            self.config.max_proof_size_bytes,
        )?;
        let consensus_proof = consensus_proof
            .ok_or_else(|| ChainError::Crypto("local consensus proof missing".into()))?;

        #[cfg(feature = "backend-rpp-stark")]
        if let Err(err) = self.verifiers.verify_rpp_stark_block_bundle(&stark_bundle) {
            error!(
                height,
                block_hash = %block_hash,
                ?err,
                "local block bundle rejected by RPP-STARK verifier"
            );
            return Err(err);
        }

        let state_proof = stark_bundle.state_proof.clone();
        #[cfg(feature = "backend-rpp-stark")]
        let base_labels = ProofLogLabels {
            height: Some(height),
            slot: Some(round.round().into()),
            proof_id: Some(block_hash.clone()),
            ..Default::default()
        };
        #[cfg(feature = "backend-rpp-stark")]
        let state_result = match &state_proof {
            ChainProof::RppStark(_) => self
                .verify_rpp_stark_with_metrics(
                    ProofVerificationKind::State,
                    &state_proof,
                    ProofLogLabels {
                        circuit: Some("state".into()),
                        ..base_labels.clone()
                    },
                )
                .map(|_| ()),
            _ => self.verifiers.verify_state(&state_proof),
        };
        #[cfg(not(feature = "backend-rpp-stark"))]
        let state_result = self.verifiers.verify_state(&state_proof);
        if let Err(err) = state_result {
            if matches!(state_proof, ChainProof::Stwo(_)) {
                self.record_stwo_outcome(
                    ProofVerificationKind::State,
                    ProofVerificationKind::State.as_str(),
                    ProofVerificationOutcome::Fail,
                );
            }
            error!(
                height,
                block_hash = %block_hash,
                ?err,
                "local state proof rejected by verifier"
            );
            return Err(err);
        }
        self.record_stwo_proof_size(
            ProofVerificationKind::State,
            ProofVerificationKind::State.as_str(),
            &state_proof,
            None,
        );

        if matches!(state_proof, ChainProof::Stwo(_)) {
            self.record_stwo_outcome(
                ProofVerificationKind::State,
                ProofVerificationKind::State.as_str(),
                ProofVerificationOutcome::Ok,
            );
        }

        let pruning_stark = stark_bundle.pruning_proof.clone();
        #[cfg(feature = "backend-rpp-stark")]
        let pruning_result = match &pruning_stark {
            ChainProof::RppStark(_) => self
                .verify_rpp_stark_with_metrics(
                    ProofVerificationKind::Pruning,
                    &pruning_stark,
                    ProofLogLabels {
                        circuit: Some("pruning".into()),
                        ..base_labels.clone()
                    },
                )
                .map(|_| ()),
            _ => self.verifiers.verify_pruning(&pruning_stark),
        };
        #[cfg(not(feature = "backend-rpp-stark"))]
        let pruning_result = self.verifiers.verify_pruning(&pruning_stark);
        if let Err(err) = pruning_result {
            if matches!(pruning_stark, ChainProof::Stwo(_)) {
                self.record_stwo_outcome(
                    ProofVerificationKind::Pruning,
                    ProofVerificationKind::Pruning.as_str(),
                    ProofVerificationOutcome::Fail,
                );
            }
            error!(
                height,
                block_hash = %block_hash,
                ?err,
                "local pruning proof rejected by verifier"
            );
            return Err(err);
        }
        self.record_stwo_proof_size(
            ProofVerificationKind::Pruning,
            ProofVerificationKind::Pruning.as_str(),
            &pruning_stark,
            None,
        );

        if matches!(pruning_stark, ChainProof::Stwo(_)) {
            self.record_stwo_outcome(
                ProofVerificationKind::Pruning,
                ProofVerificationKind::Pruning.as_str(),
                ProofVerificationOutcome::Ok,
            );
        }

        let recursive_stark = stark_bundle.recursive_proof.clone();
        #[cfg(feature = "backend-rpp-stark")]
        let recursive_result = match &recursive_stark {
            ChainProof::RppStark(_) => self
                .verify_rpp_stark_with_metrics(
                    ProofVerificationKind::Recursive,
                    &recursive_stark,
                    ProofLogLabels {
                        circuit: Some("recursive".into()),
                        ..base_labels.clone()
                    },
                )
                .map(|_| ()),
            _ => self.verifiers.verify_recursive(&recursive_stark),
        };
        #[cfg(not(feature = "backend-rpp-stark"))]
        let recursive_result = self.verifiers.verify_recursive(&recursive_stark);
        if let Err(err) = recursive_result {
            if matches!(recursive_stark, ChainProof::Stwo(_)) {
                self.record_stwo_outcome(
                    ProofVerificationKind::Recursive,
                    ProofVerificationKind::Recursive.as_str(),
                    ProofVerificationOutcome::Fail,
                );
            }
            error!(
                height,
                block_hash = %block_hash,
                ?err,
                "local recursive proof rejected by verifier"
            );
            return Err(err);
        }
        self.record_stwo_proof_size(
            ProofVerificationKind::Recursive,
            ProofVerificationKind::Recursive.as_str(),
            &recursive_stark,
            None,
        );

        if matches!(recursive_stark, ChainProof::Stwo(_)) {
            self.record_stwo_outcome(
                ProofVerificationKind::Recursive,
                ProofVerificationKind::Recursive.as_str(),
                ProofVerificationOutcome::Ok,
            );
        }

        #[cfg(feature = "backend-rpp-stark")]
        let consensus_result = match &consensus_proof {
            ChainProof::RppStark(_) => self
                .verify_rpp_stark_with_metrics(
                    ProofVerificationKind::Consensus,
                    &consensus_proof,
                    ProofLogLabels {
                        circuit: Some("consensus".into()),
                        ..base_labels.clone()
                    },
                )
                .map(|_| ()),
            _ => self.verifiers.verify_consensus(&consensus_proof),
        };
        #[cfg(not(feature = "backend-rpp-stark"))]
        let consensus_result = self.verifiers.verify_consensus(&consensus_proof);
        if let Err(err) = consensus_result {
            if matches!(consensus_proof, ChainProof::Stwo(_)) {
                self.record_stwo_outcome(
                    ProofVerificationKind::Consensus,
                    ProofVerificationKind::Consensus.as_str(),
                    ProofVerificationOutcome::Fail,
                );
            }
            error!(
                height,
                block_hash = %block_hash,
                ?err,
                "local consensus proof rejected by verifier"
            );
            return Err(err);
        }
        self.record_stwo_proof_size(
            ProofVerificationKind::Consensus,
            ProofVerificationKind::Consensus.as_str(),
            &consensus_proof,
            None,
        );

        if matches!(consensus_proof, ChainProof::Stwo(_)) {
            self.record_stwo_outcome(
                ProofVerificationKind::Consensus,
                ProofVerificationKind::Consensus.as_str(),
                ProofVerificationOutcome::Ok,
            );
        }

        let recursive_proof = match previous_block.as_ref() {
            Some(block) => RecursiveProof::extend(
                &block.recursive_proof,
                &header,
                &pruning_proof,
                &stark_bundle.recursive_proof,
            )?,
            None => {
                RecursiveProof::genesis(&header, &pruning_proof, &stark_bundle.recursive_proof)?
            }
        };
        let signature = sign_message(&self.keypair, &header.canonical_bytes());
        let state_proof_artifact = state_proof.clone();
        let mut block = Block::new(
            header,
            accepted_identities,
            transactions,
            uptime_proofs,
            timetoke_updates,
            reputation_updates,
            recorded_votes,
            module_witnesses,
            proof_artifacts,
            pruning_proof,
            recursive_proof,
            stark_bundle,
            signature,
            consensus_certificate,
            Some(consensus_proof),
        );
        block.verify(previous_block.as_ref(), &self.keypair.public)?;
        self.sync_epoch_with_metrics(height.saturating_add(1));
        let encoded_new_root = hex::encode(receipt.new_root);
        let previous_root_hex = hex::encode(
            TaggedDigest::new(SNAPSHOT_STATE_TAG, receipt.previous_root).prefixed_bytes(),
        );
        if encoded_new_root != block.header.state_root {
            return Err(ChainError::Config(
                "firewood state root does not match block header".into(),
            ));
        }
        let lifecycle = StateLifecycle::new(&self.storage);
        lifecycle.verify_transition(
            &state_proof_artifact,
            &receipt.previous_root,
            &receipt.new_root,
        )?;
        let mut metadata = BlockMetadata::from(&block);
        metadata.previous_state_root = previous_root_hex.clone();
        metadata.new_state_root = encoded_new_root;
        let final_pruning_envelope = receipt.pruning_proof.clone();
        if let Some(firewood_proof) = final_pruning_envelope.clone() {
            let pruning = firewood_proof;
            block.pruning_proof = pruning.clone();
            metadata.pruning = Some(pruning.envelope_metadata());
        } else {
            metadata.pruning = Some(block.pruning_proof.envelope_metadata());
        }
        let pruning_metadata = metadata.pruning.clone();
        {
            let span = storage_flush_span("store_block", block.header.height, &block.hash);
            let _guard = span.enter();
            self.storage.store_block(&block, &metadata)?;
        }
        if self.config.rollout.feature_gates.pruning && block.header.height > 0 {
            let span =
                storage_flush_span("prune_block_payload", block.header.height - 1, &block.hash);
            let _guard = span.enter();
            let _ = self.storage.prune_block_payload(block.header.height - 1)?;
        }
        let mut tip = self.chain_tip.write();
        tip.height = block.header.height;
        tip.last_hash = block.block_hash();
        tip.pruning = pruning_metadata;
        info!(height = tip.height, "sealed block");
        self.record_committed_certificate(&block.consensus);
        self.clear_consensus_lock_for(block.header.height, &block.hash);
        self.evidence_pool
            .write()
            .prune_below(block.header.height.saturating_add(1));
        self.prune_consensus_rounds_below(block.header.height.saturating_add(1));

        let backend = proof_backend(&block.stark.recursive_proof);
        self.consensus_telemetry.record_proposer_observation(
            epoch,
            &expected_proposer,
            &block.header.proposer,
            backend,
            expected_weight,
        );

        self.update_runtime_metrics();

        let block_hash = block.hash.clone();
        let event_round = block.consensus.round;
        let pruning_proof = final_pruning_envelope;
        self.publish_pipeline_event(PipelineObservation::BftFinalised {
            height,
            round: event_round,
            block_hash: block_hash.clone(),
            commitments,
            certificate: block.consensus.clone(),
        });
        self.publish_pipeline_event(PipelineObservation::FirewoodCommitment {
            height,
            round: event_round,
            block_hash,
            previous_root: previous_root_hex,
            new_root: encoded_new_root.clone(),
            pruning_proof,
        });

        self.emit_state_sync_artifacts();

        Ok(FinalizationOutcome::Sealed {
            tip_height: block.header.height,
            block,
        })
    }

    fn finalize_external_block(
        &self,
        ctx: ExternalFinalizationContext,
    ) -> ChainResult<FinalizationOutcome> {
        let ExternalFinalizationContext {
            round,
            mut block,
            mut previous_block,
            archived_votes,
            peer_id,
            expected_proposer,
            expected_weight,
            epoch,
        } = ctx;

        if !round.commit_reached() {
            warn!("quorum not reached for commit");
            return Ok(FinalizationOutcome::AwaitingQuorum);
        }

        let height = block.header.height;
        if previous_block.is_none() && height > 0 {
            previous_block = self.storage.read_block(height - 1)?;
        }

        let proposer_key = self.ledger.validator_public_key(&block.header.proposer)?;

        let mut recorded_votes = block.bft_votes.clone();
        let mut vote_index = HashSet::new();
        for vote in &recorded_votes {
            vote_index.insert((
                vote.vote.voter.clone(),
                vote.vote.kind,
                vote.vote.round,
                vote.vote.height,
                vote.vote.block_hash.clone(),
            ));
        }
        for vote in archived_votes {
            let key = (
                vote.vote.voter.clone(),
                vote.vote.kind,
                vote.vote.round,
                vote.vote.height,
                vote.vote.block_hash.clone(),
            );
            if vote_index.insert(key) {
                recorded_votes.push(vote);
            }
        }
        block.bft_votes = recorded_votes;

        block.verify_without_stark_with_metrics(
            previous_block.as_ref(),
            &proposer_key,
            self.metrics.as_ref(),
        )?;

        let round_number = round.round();
        #[cfg(feature = "backend-rpp-stark")]
        let base_labels = ProofLogLabels {
            peer_id: peer_id.as_ref().map(|peer| peer.to_string()),
            height: Some(height),
            slot: Some(round_number.into()),
            proof_id: Some(block.hash.clone()),
            ..Default::default()
        };
        #[cfg(feature = "backend-rpp-stark")]
        let state_backend = proof_backend(&block.stark.state_proof);
        let state_result = match &block.stark.state_proof {
            ChainProof::RppStark(_) => self
                .verify_rpp_stark_with_metrics(
                    ProofVerificationKind::State,
                    &block.stark.state_proof,
                    ProofLogLabels {
                        circuit: Some("state".into()),
                        ..base_labels.clone()
                    },
                )
                .map(|_| ()),
            _ => self.verifiers.verify_state(&block.stark.state_proof),
        };
        #[cfg(not(feature = "backend-rpp-stark"))]
        let state_result = self.verifiers.verify_state(&block.stark.state_proof);
        if let Err(err) = state_result {
            Self::log_external_block_verification_failure(
                &ProofLogLabels {
                    circuit: Some("state".into()),
                    ..base_labels.clone()
                },
                &block.header.proposer,
                state_backend,
                ProofVerificationKind::State,
                &err,
            );
            self.punish_invalid_proof(&block.header.proposer, height, round_number);
            return Err(err);
        }
        self.record_stwo_proof_size(
            ProofVerificationKind::State,
            ProofVerificationKind::State.as_str(),
            &block.stark.state_proof,
            None,
        );

        #[cfg(feature = "backend-rpp-stark")]
        let pruning_backend = proof_backend(&block.stark.pruning_proof);
        let pruning_result = match &block.stark.pruning_proof {
            ChainProof::RppStark(_) => self
                .verify_rpp_stark_with_metrics(
                    ProofVerificationKind::Pruning,
                    &block.stark.pruning_proof,
                    ProofLogLabels {
                        circuit: Some("pruning".into()),
                        ..base_labels.clone()
                    },
                )
                .map(|_| ()),
            _ => self.verifiers.verify_pruning(&block.stark.pruning_proof),
        };
        #[cfg(not(feature = "backend-rpp-stark"))]
        let pruning_result = self.verifiers.verify_pruning(&block.stark.pruning_proof);
        if let Err(err) = pruning_result {
            Self::log_external_block_verification_failure(
                &ProofLogLabels {
                    circuit: Some("pruning".into()),
                    ..base_labels.clone()
                },
                &block.header.proposer,
                pruning_backend,
                ProofVerificationKind::Pruning,
                &err,
            );
            self.punish_invalid_proof(&block.header.proposer, height, round_number);
            return Err(err);
        }
        self.record_stwo_proof_size(
            ProofVerificationKind::Pruning,
            ProofVerificationKind::Pruning.as_str(),
            &block.stark.pruning_proof,
            None,
        );

        #[cfg(feature = "backend-rpp-stark")]
        let recursive_backend = proof_backend(&block.stark.recursive_proof);
        let recursive_result = match &block.stark.recursive_proof {
            ChainProof::RppStark(_) => self
                .verify_rpp_stark_with_metrics(
                    ProofVerificationKind::Recursive,
                    &block.stark.recursive_proof,
                    ProofLogLabels {
                        circuit: Some("recursive".into()),
                        ..base_labels.clone()
                    },
                )
                .map(|_| ()),
            _ => self
                .verifiers
                .verify_recursive(&block.stark.recursive_proof),
        };
        #[cfg(not(feature = "backend-rpp-stark"))]
        let recursive_result = self
            .verifiers
            .verify_recursive(&block.stark.recursive_proof);
        if let Err(err) = recursive_result {
            Self::log_external_block_verification_failure(
                &ProofLogLabels {
                    circuit: Some("recursive".into()),
                    ..base_labels.clone()
                },
                &block.header.proposer,
                recursive_backend,
                ProofVerificationKind::Recursive,
                &err,
            );
            self.punish_invalid_proof(&block.header.proposer, height, round_number);
            return Err(err);
        }
        self.record_stwo_proof_size(
            ProofVerificationKind::Recursive,
            ProofVerificationKind::Recursive.as_str(),
            &block.stark.recursive_proof,
            None,
        );

        if let Some(proof) = &block.consensus_proof {
            #[cfg(feature = "backend-rpp-stark")]
            let consensus_backend = proof_backend(proof);
            let consensus_result = match proof {
                ChainProof::RppStark(_) => self
                    .verify_rpp_stark_with_metrics(
                        ProofVerificationKind::Consensus,
                        proof,
                        ProofLogLabels {
                            circuit: Some("consensus".into()),
                            ..base_labels.clone()
                        },
                    )
                    .map(|_| ()),
                _ => self.verifiers.verify_consensus(proof),
            };
            #[cfg(not(feature = "backend-rpp-stark"))]
            let consensus_result = self.verifiers.verify_consensus(proof);
            if let Err(err) = consensus_result {
                Self::log_external_block_verification_failure(
                    &ProofLogLabels {
                        circuit: Some("consensus".into()),
                        ..base_labels.clone()
                    },
                    &block.header.proposer,
                    consensus_backend,
                    ProofVerificationKind::Consensus,
                    &err,
                );
                self.punish_invalid_proof(&block.header.proposer, height, round_number);
                return Err(err);
            }
        }
        if let Some(proof) = &block.consensus_proof {
            self.record_stwo_proof_size(
                ProofVerificationKind::Consensus,
                ProofVerificationKind::Consensus.as_str(),
                proof,
                None,
            );
        }

        self.sync_epoch_with_metrics(height);

        let participants = round.commit_participants();
        let witness_bundle =
            build_consensus_witness(height, round_number, participants, &block.consensus);
        self.ledger.record_consensus_witness(&witness_bundle);

        for request in &block.identities {
            self.ledger.register_identity(
                request,
                height,
                IDENTITY_ATTESTATION_QUORUM,
                IDENTITY_ATTESTATION_GOSSIP_MIN,
            )?;
        }

        let mut total_fees: u64 = 0;
        for tx in &block.transactions {
            let inputs = match self.ledger.select_inputs_for_transaction(tx) {
                Ok(inputs) => inputs,
                Err(err) => {
                    self.record_double_spend_if_applicable(&block, round_number, &err);
                    return Err(err);
                }
            };
            let fee = match self.ledger.apply_transaction(tx, &inputs) {
                Ok(fee) => fee,
                Err(err) => {
                    self.record_double_spend_if_applicable(&block, round_number, &err);
                    return Err(err);
                }
            };
            total_fees = total_fees.saturating_add(fee);
        }

        for proof in &block.uptime_proofs {
            if let Err(err) = self.ledger.apply_uptime_proof(proof) {
                match err {
                    ChainError::Transaction(message)
                        if message == "uptime proof does not extend the recorded online window" =>
                    {
                        debug!(
                            identity = %proof.wallet_address,
                            "skipping previously applied uptime proof"
                        );
                    }
                    other => return Err(other),
                }
            }
        }

        let block_reward = BASE_BLOCK_REWARD.saturating_add(total_fees);
        self.ledger.distribute_consensus_rewards(
            &block.header.proposer,
            round.validators(),
            block_reward,
            LEADER_BONUS_PERCENT,
        )?;

        let produced_witnesses = self.ledger.drain_module_witnesses();
        let produced_bytes =
            bincode::serialize(&produced_witnesses).map_err(ChainError::Serialization)?;
        let block_bytes =
            bincode::serialize(&block.module_witnesses).map_err(ChainError::Serialization)?;
        if produced_bytes != block_bytes {
            return Err(ChainError::Config(
                "module witness bundle mismatch for external block".into(),
            ));
        }
        let module_artifacts = self.ledger.stage_module_witnesses(&produced_witnesses)?;
        for artifact in module_artifacts {
            if !block.proof_artifacts.iter().any(|existing| {
                existing.module == artifact.module
                    && existing.commitment == artifact.commitment
                    && existing.proof == artifact.proof
            }) {
                return Err(ChainError::Config(
                    "external block missing module proof artifact".into(),
                ));
            }
        }

        let mut touched_identities: HashSet<Address> = HashSet::new();
        for tx in &block.transactions {
            touched_identities.insert(tx.payload.from.clone());
            touched_identities.insert(tx.payload.to.clone());
        }
        for identity in &block.identities {
            touched_identities.insert(identity.declaration.genesis.wallet_addr.clone());
        }
        for update in &block.timetoke_updates {
            touched_identities.insert(update.identity.clone());
        }
        let mut expected_reputation = Vec::new();
        for identity in touched_identities {
            if let Some(mut audit) = self.ledger.reputation_audit(&identity)? {
                self.sign_reputation_audit(&mut audit);
                self.audit_exporter.export_reputation(&audit)?;
                expected_reputation.push(ReputationUpdate::from(audit));
            }
        }
        expected_reputation.sort_by(|a, b| a.identity.cmp(&b.identity));
        let expected_bytes =
            bincode::serialize(&expected_reputation).map_err(ChainError::Serialization)?;
        let provided_bytes =
            bincode::serialize(&block.reputation_updates).map_err(ChainError::Serialization)?;
        if expected_bytes != provided_bytes {
            return Err(ChainError::Config(
                "external block reputation updates mismatch ledger state".into(),
            ));
        }

        let state_proof_artifact = block.stark.state_proof.clone();
        self.sync_epoch_with_metrics(height.saturating_add(1));
        let receipt = self.persist_accounts(height)?;
        let encoded_new_root = hex::encode(receipt.new_root);
        let previous_root_hex = hex::encode(
            TaggedDigest::new(SNAPSHOT_STATE_TAG, receipt.previous_root).prefixed_bytes(),
        );
        if encoded_new_root != block.header.state_root {
            return Err(ChainError::Config(
                "firewood state root does not match block header".into(),
            ));
        }

        let lifecycle = StateLifecycle::new(&self.storage);
        lifecycle.verify_transition(
            &state_proof_artifact,
            &receipt.previous_root,
            &receipt.new_root,
        )?;

        let mut metadata = BlockMetadata::from(&block);
        metadata.previous_state_root = previous_root_hex.clone();
        metadata.new_state_root = encoded_new_root;
        let final_pruning_envelope = receipt.pruning_proof.clone();
        if let Some(firewood_proof) = final_pruning_envelope.clone() {
            let pruning = firewood_proof;
            block.pruning_proof = pruning.clone();
            metadata.pruning = Some(pruning.envelope_metadata());
        } else {
            metadata.pruning = Some(block.pruning_proof.envelope_metadata());
        }
        let pruning_metadata = metadata.pruning.clone();
        self.storage.store_block(&block, &metadata)?;
        if self.config.rollout.feature_gates.pruning && block.header.height > 0 {
            let _ = self.storage.prune_block_payload(block.header.height - 1)?;
        }

        let mut tip = self.chain_tip.write();
        tip.height = block.header.height;
        tip.last_hash = block.block_hash();
        tip.pruning = pruning_metadata;
        info!(
            height = tip.height,
            proposer = %block.header.proposer,
            "sealed external block"
        );
        drop(tip);
        self.record_committed_certificate(&block.consensus);
        self.clear_consensus_lock_for(block.header.height, &block.hash);

        self.evidence_pool
            .write()
            .prune_below(block.header.height.saturating_add(1));
        self.prune_consensus_rounds_below(block.header.height.saturating_add(1));

        let backend = proof_backend(&block.stark.recursive_proof);
        self.consensus_telemetry.record_proposer_observation(
            epoch,
            &expected_proposer,
            &block.header.proposer,
            backend,
            expected_weight,
        );

        self.update_runtime_metrics();

        let block_hash = block.hash.clone();
        let event_round = block.consensus.round;
        match Self::commitments_from_header(&block.header) {
            Ok(commitments) => {
                self.publish_pipeline_event(PipelineObservation::BftFinalised {
                    height,
                    round: event_round,
                    block_hash: block_hash.clone(),
                    commitments,
                    certificate: block.consensus.clone(),
                });
            }
            Err(err) => {
                warn!(
                    ?err,
                    height,
                    round = event_round,
                    "failed to decode commitments for pipeline event"
                );
            }
        }
        let pruning_proof = final_pruning_envelope;
        self.publish_pipeline_event(PipelineObservation::FirewoodCommitment {
            height,
            round: event_round,
            block_hash,
            previous_root: previous_root_hex,
            new_root: encoded_new_root.clone(),
            pruning_proof,
        });

        self.emit_state_sync_artifacts();

        Ok(FinalizationOutcome::Sealed {
            tip_height: block.header.height,
            block,
        })
    }

    fn persist_accounts(&self, block_height: u64) -> ChainResult<StateTransitionReceipt> {
        let accounts = self.ledger.accounts_snapshot();
        let lifecycle = StateLifecycle::new(&self.storage);
        lifecycle.apply_block(block_height, &accounts)
    }

    fn bootstrap(&self) -> ChainResult<()> {
        if let Some(metadata) = self.storage.tip()? {
            let block = self
                .storage
                .read_block(metadata.height)?
                .ok_or_else(|| ChainError::Config("tip metadata missing block".into()))?;
            let proposer_key = self.ledger.validator_public_key(&block.header.proposer)?;
            block.verify(None, &proposer_key)?;
            let mut tip = self.chain_tip.write();
            tip.height = block.header.height;
            tip.last_hash = block.block_hash();
            tip.pruning = metadata.pruning.clone();
            if self.config.rollout.feature_gates.pruning {
                for height in 0..block.header.height {
                    let _ = self.storage.prune_block_payload(height)?;
                }
            }
        } else {
            let mut tip = self.chain_tip.write();
            tip.height = 0;
            tip.last_hash = [0u8; 32];
            tip.pruning = None;
        }
        Ok(())
    }

    fn network_identity_profile(&self) -> ChainResult<NetworkIdentityProfile> {
        let account = self
            .ledger
            .get_account(&self.address)
            .ok_or_else(|| ChainError::Config("node account missing in ledger".into()))?;
        let tier_level = tier_to_level(&account.reputation.tier);
        let zsi_id = account.reputation.zsi.public_key_commitment.clone();
        let vrf_public_key = self.vrf_keypair.public.to_bytes().to_vec();
        let template = HandshakePayload::new(
            zsi_id.clone(),
            Some(vrf_public_key.clone()),
            None,
            tier_level,
        );
        let sr_keypair = self.vrf_keypair.secret.expand_to_keypair();
        let signature = sr_keypair.sign_simple(VRF_HANDSHAKE_CONTEXT, &template.vrf_message());
        let vrf_proof = signature.to_bytes().to_vec();
        Ok(NetworkIdentityProfile {
            zsi_id,
            tier: tier_level,
            vrf_public_key,
            vrf_proof,
            feature_gates: self.config.rollout.feature_gates.clone(),
        })
    }
}

const VRF_PUBLIC_KEY_LENGTH: usize = 32;

fn summarize_consensus_certificate(
    certificate: &ConsensusCertificate,
) -> ChainResult<ConsensusProofStatus> {
    let block_hash_hex = certificate.block_hash.0.clone();
    let block_hash = decode_digest("consensus block hash", &block_hash_hex)?;
    let metadata = &certificate.metadata;

    let (mut vrf_entries, vrf_public_entries) = sanitize_vrf_entries(&metadata.vrf.entries)?;
    let vrf_entry_bindings = compute_vrf_entry_bindings(&block_hash, &vrf_public_entries)?;
    for (entry, bindings) in vrf_entries.iter_mut().zip(vrf_entry_bindings) {
        entry.bindings = Some(bindings);
    }
    let witness_commitments =
        decode_digest_list("witness commitment", &metadata.witness_commitments)?;
    let reputation_roots = decode_digest_list("reputation root", &metadata.reputation_roots)?;
    let quorum_bitmap_root = decode_digest("quorum bitmap root", &metadata.quorum_bitmap_root)?;
    let quorum_signature_root =
        decode_digest("quorum signature root", &metadata.quorum_signature_root)?;

    let bindings = compute_consensus_bindings(
        &block_hash,
        &vrf_public_entries,
        &witness_commitments,
        &reputation_roots,
        &quorum_bitmap_root,
        &quorum_signature_root,
    )?;

    let encode = |digest: [u8; 32]| hex::encode(digest);

    Ok(ConsensusProofStatus {
        height: certificate.height,
        round: certificate.round,
        block_hash: block_hash_hex,
        total_power: certificate.total_power.to_string(),
        quorum_threshold: certificate.quorum_threshold.to_string(),
        prevote_power: certificate.prevote_power.to_string(),
        precommit_power: certificate.precommit_power.to_string(),
        commit_power: certificate.commit_power.to_string(),
        epoch: metadata.epoch,
        slot: metadata.slot,
        vrf_entries,
        witness_commitments: witness_commitments
            .into_iter()
            .map(|digest| hex::encode(digest))
            .collect(),
        reputation_roots: reputation_roots
            .into_iter()
            .map(|digest| hex::encode(digest))
            .collect(),
        quorum_bitmap_root: hex::encode(quorum_bitmap_root),
        quorum_signature_root: hex::encode(quorum_signature_root),
        vrf_output: encode(bindings.vrf_output),
        vrf_proof: encode(bindings.vrf_proof),
        witness_commitment_root: encode(bindings.witness_commitment),
        reputation_root: encode(bindings.reputation_root),
        quorum_bitmap: encode(bindings.quorum_bitmap),
        quorum_signature: encode(bindings.quorum_signature),
    })
}

fn decode_digest(label: &str, value: &str) -> ChainResult<[u8; 32]> {
    let bytes =
        hex::decode(value).map_err(|err| ChainError::Crypto(format!("invalid {label}: {err}")))?;
    if bytes.len() != 32 {
        return Err(ChainError::Crypto(format!("{label} must encode 32 bytes")));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

fn decode_digest_list(label: &str, values: &[String]) -> ChainResult<Vec<[u8; 32]>> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| decode_digest(&format!("{label} #{index}"), value))
        .collect()
}

fn sanitize_vrf_entries(
    entries: &[crate::consensus::messages::ConsensusVrfEntry],
) -> ChainResult<(Vec<ConsensusProofVrfEntry>, Vec<BackendVrfPublicEntry>)> {
    if entries.is_empty() {
        return Err(ChainError::Crypto(
            "consensus metadata missing VRF entries".into(),
        ));
    }

    let mut sanitized_entries = Vec::with_capacity(entries.len());
    let mut backend_entries = Vec::with_capacity(entries.len());

    for (index, entry) in entries.iter().enumerate() {
        let randomness = decode_digest(&format!("vrf randomness #{index}"), &entry.randomness)?;
        let pre_output = decode_hex_array::<{ crate::vrf::VRF_PREOUTPUT_LENGTH }>(
            &format!("vrf pre-output #{index}"),
            &entry.pre_output,
        )?;
        let proof = decode_hex_buffer(
            &format!("vrf proof #{index}"),
            &entry.proof,
            VRF_PROOF_LENGTH,
        )?;
        let public_key = decode_hex_array::<{ VRF_PUBLIC_KEY_LENGTH }>(
            &format!("vrf public key #{index}"),
            &entry.public_key,
        )?;
        let poseidon_digest = decode_digest(
            &format!("vrf poseidon digest #{index}"),
            &entry.poseidon.digest,
        )?;
        let poseidon_last_block_header = decode_digest(
            &format!("vrf poseidon last block header #{index}"),
            &entry.poseidon.last_block_header,
        )?;
        let poseidon_tier_seed = decode_digest(
            &format!("vrf poseidon tier seed #{index}"),
            &entry.poseidon.tier_seed,
        )?;
        let poseidon_epoch = entry.poseidon.epoch.parse::<u64>().map_err(|err| {
            ChainError::Crypto(format!("invalid vrf poseidon epoch #{index}: {err}"))
        })?;

        sanitized_entries.push(ConsensusProofVrfEntry {
            randomness: hex::encode(randomness),
            pre_output: hex::encode(pre_output),
            proof: hex::encode(&proof),
            public_key: hex::encode(public_key),
            poseidon: ConsensusProofVrfPoseidon {
                digest: hex::encode(poseidon_digest),
                last_block_header: hex::encode(poseidon_last_block_header),
                epoch: poseidon_epoch.to_string(),
                tier_seed: hex::encode(poseidon_tier_seed),
            },
            bindings: None,
        });

        backend_entries.push(BackendVrfPublicEntry {
            randomness,
            pre_output,
            proof,
            public_key,
            poseidon_digest,
            poseidon_last_block_header,
            poseidon_epoch,
            poseidon_tier_seed,
        });
    }

    Ok((sanitized_entries, backend_entries))
}

fn compute_vrf_entry_bindings(
    block_hash: &[u8; 32],
    entries: &[BackendVrfPublicEntry],
) -> ChainResult<Vec<ConsensusProofVrfBindings>> {
    let parameters = StarkParameters::blueprint_default();
    let hasher = parameters.poseidon_hasher();
    let zero = FieldElement::zero(parameters.modulus());
    let mut randomness_accumulator = parameters.element_from_bytes(block_hash);
    let mut proof_accumulator = randomness_accumulator.clone();

    let mut bindings = Vec::with_capacity(entries.len());
    for entry in entries {
        let randomness_element = parameters.element_from_bytes(entry.randomness.as_slice());
        randomness_accumulator = hasher.hash(&[
            randomness_accumulator.clone(),
            randomness_element,
            zero.clone(),
        ]);

        let proof_element = parameters.element_from_bytes(entry.proof.as_slice());
        proof_accumulator = hasher.hash(&[proof_accumulator.clone(), proof_element, zero.clone()]);

        bindings.push(ConsensusProofVrfBindings {
            randomness: field_element_to_hex(&randomness_accumulator),
            proof: field_element_to_hex(&proof_accumulator),
        });
    }

    Ok(bindings)
}

fn field_element_to_hex(value: &FieldElement) -> String {
    let bytes = value.to_bytes();
    let mut buffer = [0u8; 32];
    let offset = buffer.len().saturating_sub(bytes.len());
    buffer[offset..offset + bytes.len()].copy_from_slice(&bytes);
    hex::encode(buffer)
}

fn decode_hex_array<const N: usize>(label: &str, value: &str) -> ChainResult<[u8; N]> {
    let bytes =
        hex::decode(value).map_err(|err| ChainError::Crypto(format!("invalid {label}: {err}")))?;
    if bytes.len() != N {
        return Err(ChainError::Crypto(format!("{label} must encode {N} bytes")));
    }
    let mut buffer = [0u8; N];
    buffer.copy_from_slice(&bytes);
    Ok(buffer)
}

fn decode_hex_buffer(label: &str, value: &str, expected: usize) -> ChainResult<Vec<u8>> {
    let bytes =
        hex::decode(value).map_err(|err| ChainError::Crypto(format!("invalid {label}: {err}")))?;
    if bytes.len() != expected {
        return Err(ChainError::Crypto(format!(
            "{label} must encode {expected} bytes"
        )));
    }
    Ok(bytes)
}

fn is_double_spend(err: &ChainError) -> bool {
    matches!(
        err,
        ChainError::Transaction(message)
            if matches!(
                message.as_str(),
                "transaction input already spent" | "transaction input not found"
            )
    )
}

fn tier_to_level(tier: &Tier) -> TierLevel {
    match tier {
        Tier::Tl0 => TierLevel::Tl0,
        Tier::Tl1 => TierLevel::Tl1,
        Tier::Tl2 => TierLevel::Tl2,
        Tier::Tl3 => TierLevel::Tl3,
        Tier::Tl4 => TierLevel::Tl4,
        Tier::Tl5 => TierLevel::Tl5,
    }
}

#[cfg(test)]
mod telemetry_metrics_tests {
    use super::{
        classify_rpp_stark_error_stage, proof_size_bucket, record_rpp_stark_size_metrics,
        record_rpp_stark_stage_checks, ConsensusTelemetry, ProofVerificationBackend,
        ProofVerificationKind, ProofVerificationOutcome, RuntimeInner, RuntimeMetrics,
    };
    use crate::errors::ChainError;
    use crate::types::Address;
    #[cfg(feature = "backend-rpp-stark")]
    use crate::types::{ChainProof, RppStarkProof};
    use crate::zk::rpp_verifier::RppStarkVerificationFlags;
    use crate::zk::rpp_verifier::{RppStarkVerifierError, RppStarkVerifyFailure};
    use opentelemetry_sdk::metrics::data::{Data, Histogram};
    use opentelemetry_sdk::metrics::{
        InMemoryMetricExporter, MetricError, PeriodicReader, SdkMeterProvider,
    };
    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tracing_test::{logs_contain, traced_test};

    #[test]
    fn consensus_telemetry_records_metrics() -> std::result::Result<(), MetricError> {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("telemetry-test");
        let metrics = Arc::new(RuntimeMetrics::from_meter(&meter));
        let telemetry = ConsensusTelemetry::new(metrics.clone());

        let leader: Address = "leader".into();
        telemetry.record_round_start(10, 2, &leader);
        {
            let mut state = telemetry.state.lock();
            state.last_round_started = Some(Instant::now() - Duration::from_millis(25));
        }
        telemetry.record_quorum(10, 2);
        telemetry.record_round_end(10, 2);
        telemetry.record_witness_event("blocks");
        telemetry.record_slashing("invalid_vote");
        telemetry.record_failed_vote("timeout");

        provider.force_flush()?;
        let exported = exporter.get_finished_metrics()?;

        let mut seen = HashSet::new();
        for resource in exported {
            for scope in resource.scope_metrics {
                for metric in scope.metrics {
                    seen.insert(metric.name.clone());
                }
            }
        }

        assert!(seen.contains("rpp.runtime.consensus.round.duration"));
        assert!(seen.contains("rpp.runtime.consensus.round.quorum_latency"));
        assert!(seen.contains("rpp.runtime.consensus.round.leader_changes"));
        assert!(seen.contains("rpp.runtime.consensus.witness.events"));
        assert!(seen.contains("rpp.runtime.consensus.slashing.events"));
        assert!(seen.contains("rpp.runtime.consensus.failed_votes"));

        Ok(())
    }

    #[test]
    fn consensus_vote_latency_records_backend_and_labels() -> std::result::Result<(), MetricError> {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("vote-latency-metrics");
        let metrics = Arc::new(RuntimeMetrics::from_meter(&meter));

        metrics.record_consensus_vote_latency(
            "validator-a",
            1,
            10,
            ProofVerificationBackend::Stwo,
            Duration::from_millis(42),
        );
        metrics.record_consensus_vote_latency(
            "validator-b",
            2,
            20,
            ProofVerificationBackend::RppStark,
            Duration::from_millis(84),
        );

        provider.force_flush()?;
        let exported = exporter.get_finished_metrics()?;

        let mut backends = HashSet::new();
        let mut slots = HashSet::new();
        for resource in exported {
            for scope in resource.scope_metrics {
                for metric in scope.metrics {
                    if metric.name != "rpp.runtime.consensus.vote.latency" {
                        continue;
                    }
                    if let Data::Histogram(histogram) = metric.data {
                        for point in histogram.data_points {
                            let mut attrs = HashMap::new();
                            for attribute in point.attributes {
                                attrs
                                    .insert(attribute.key.to_string(), attribute.value.to_string());
                            }
                            if let Some(backend) = attrs.get(ProofVerificationBackend::KEY) {
                                backends.insert(backend.clone());
                            }
                            if let Some(slot) = attrs.get("slot") {
                                slots.insert(slot.clone());
                            }
                        }
                    }
                }
            }
        }

        assert!(
            backends.contains(&ProofVerificationBackend::Stwo.as_str().to_string()),
            "expected stwo backend label",
        );
        assert!(
            backends.contains(&ProofVerificationBackend::RppStark.as_str().to_string()),
            "expected rpp-stark backend label",
        );
        assert!(slots.contains(&"10".to_string()));
        assert!(slots.contains(&"20".to_string()));

        Ok(())
    }

    #[test]
    fn rpp_stark_failure_metrics_include_stage_labels() -> std::result::Result<(), MetricError> {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("rpp-stark-stage-metrics");
        let metrics = RuntimeMetrics::from_meter(&meter);
        let proof_metrics = metrics.proofs();

        record_rpp_stark_stage_checks(
            proof_metrics,
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Consensus,
            ProofVerificationKind::Consensus.as_str(),
            RppStarkVerificationFlags::from_bools(true, true, false, true, true),
        );

        let adapter_stage =
            classify_rpp_stark_error_stage(&RppStarkVerifierError::ProofSizeLimitMismatch {
                params_kib: 64,
                expected_kib: 32,
            });
        proof_metrics.observe_verification_stage(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Consensus,
            ProofVerificationKind::Consensus.as_str(),
            adapter_stage,
            ProofVerificationOutcome::Fail,
        );

        provider.force_flush()?;
        let exported = exporter.get_finished_metrics()?;

        let mut stages: HashMap<String, HashSet<String>> = HashMap::new();
        for resource in exported {
            for scope in resource.scope_metrics {
                for metric in scope.metrics {
                    if metric.name != "rpp_stark_stage_checks_total" {
                        continue;
                    }
                    if let Data::Sum(sum) = metric.data {
                        for point in sum.data_points {
                            let mut attrs = HashMap::new();
                            for attribute in point.attributes {
                                attrs
                                    .insert(attribute.key.to_string(), attribute.value.to_string());
                            }
                            if let (Some(stage), Some(result)) =
                                (attrs.get("stage"), attrs.get("result"))
                            {
                                stages
                                    .entry(stage.clone())
                                    .or_default()
                                    .insert(result.clone());
                            }
                        }
                    }
                }
            }
        }

        assert_eq!(
            stages.get("merkle"),
            Some(&HashSet::from(["fail".to_string()])),
        );
        assert_eq!(
            stages.get("adapter"),
            Some(&HashSet::from(["fail".to_string()])),
        );

        Ok(())
    }
    #[test]
    fn rpp_stark_failure_size_metrics_are_bucketed() -> std::result::Result<(), MetricError> {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("rpp-stark-size-metrics");
        let metrics = RuntimeMetrics::from_meter(&meter);
        let proof_metrics = metrics.proofs();

        proof_metrics.observe_verification_total_bytes_by_result(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Consensus,
            ProofVerificationKind::Consensus.as_str(),
            ProofVerificationOutcome::Fail,
            5 * 1024 * 1024,
        );

        provider.force_flush()?;
        let exported = exporter.get_finished_metrics()?;

        let mut saw_fail_bucket = false;
        for resource in exported {
            for scope in resource.scope_metrics {
                for metric in scope.metrics {
                    if metric.name != "rpp_stark_proof_total_bytes_by_result" {
                        continue;
                    }
                    if let Data::Histogram(Histogram { data_points, .. }) = metric.data {
                        for point in data_points {
                            let mut attrs = HashMap::new();
                            for attribute in point.attributes {
                                attrs
                                    .insert(attribute.key.to_string(), attribute.value.to_string());
                            }
                            if attrs.get(ProofVerificationOutcome::KEY)
                                == Some(&ProofVerificationOutcome::Fail.as_str().to_string())
                                && attrs.get(ProofVerificationBackend::KEY)
                                    == Some(
                                        &ProofVerificationBackend::RppStark.as_str().to_string(),
                                    )
                                && attrs.get(ProofVerificationKind::KEY)
                                    == Some(&ProofVerificationKind::Consensus.as_str().to_string())
                                && point.count > 0
                            {
                                saw_fail_bucket = true;
                            }
                        }
                    }
                }
            }
        }

        assert!(
            saw_fail_bucket,
            "expected histogram bucket for failing proof bytes"
        );

        Ok(())
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[traced_test]
    fn oversized_failure_logs_include_bucket() {
        let failure = RppStarkVerifyFailure::ProofTooLarge {
            max_kib: 4096,
            got_kib: 6144,
        };
        let proof_bytes = 5 * 1024 * 1024 + 12;
        let size_bucket = proof_size_bucket(proof_bytes);
        let labels = ProofLogLabels {
            peer_id: Some("peer.test".into()),
            height: Some(10),
            slot: Some(3),
            proof_id: Some("proof.test".into()),
            circuit: Some("consensus".into()),
        };
        let resolved = labels.resolve(ProofVerificationKind::Consensus);

        warn!(
            target = "proofs",
            peer_id = resolved.peer_id,
            height = ?resolved.height,
            slot = ?resolved.slot,
            proof_id = resolved.proof_id,
            circuit = resolved.circuit,
            backend = ProofVerificationBackend::RppStark.as_str(),
            proof_backend = "rpp-stark",
            proof_kind = ProofVerificationKind::Consensus.as_str(),
            valid = false,
            proof_bytes,
            size_bucket,
            params_bytes = 1024u64,
            public_inputs_bytes = 2048u64,
            payload_bytes = 4096u64,
            verify_duration_ms = 7u64,
            error = %failure,
            "rpp-stark proof verification failed"
        );

        assert!(logs_contain("size_bucket=gt_4_mib"));
        assert!(logs_contain("peer_id=peer.test"));
        assert!(logs_contain("proof_id=proof.test"));
        assert!(logs_contain("backend=rpp-stark"));
        assert!(logs_contain("circuit=consensus"));
    }

    #[cfg(feature = "backend-rpp-stark")]
    #[traced_test]
    fn rpp_stark_success_logs_include_context_fields() {
        let labels = ProofLogLabels {
            peer_id: Some("peer.success".into()),
            height: Some(11),
            slot: Some(4),
            proof_id: Some("proof.success".into()),
            circuit: Some("state".into()),
        };
        let resolved = labels.resolve(ProofVerificationKind::State);

        info!(
            target = "proofs",
            peer_id = resolved.peer_id,
            height = ?resolved.height,
            slot = ?resolved.slot,
            proof_id = resolved.proof_id,
            circuit = resolved.circuit,
            backend = ProofVerificationBackend::RppStark.as_str(),
            proof_backend = "rpp-stark",
            proof_kind = ProofVerificationKind::State.as_str(),
            valid = true,
            proof_bytes = 1024u64,
            size_bucket = proof_size_bucket(1024),
            params_bytes = 256u64,
            public_inputs_bytes = 128u64,
            payload_bytes = 640u64,
            verify_duration_ms = 3u64,
            "rpp-stark proof verification",
        );

        assert!(logs_contain("peer_id=peer.success"));
        assert!(logs_contain("proof_id=proof.success"));
        assert!(logs_contain("backend=rpp-stark"));
        assert!(logs_contain("circuit=state"));
    }

    #[traced_test]
    fn external_block_failure_logs_include_backend_identity() {
        let err = ChainError::Crypto("expected failure".into());
        let labels = ProofLogLabels {
            peer_id: Some("12D3KooWtest".into()),
            height: Some(42),
            slot: Some(7),
            proof_id: Some("block-hash".into()),
            circuit: Some("state".into()),
        };

        RuntimeInner::log_external_block_verification_failure(
            &labels,
            &Address::from("validator-rpp"),
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::State,
            &err,
        );

        let alt_labels = ProofLogLabels {
            circuit: Some("pruning".into()),
            ..labels.clone()
        };
        RuntimeInner::log_external_block_verification_failure(
            &alt_labels,
            &Address::from("validator-failover"),
            ProofVerificationBackend::Stwo,
            ProofVerificationKind::Pruning,
            &err,
        );

        assert!(logs_contain("proof_backend=rpp-stark"));
        assert!(logs_contain("proof_backend=stwo"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::Path;

    use crate::consensus::messages::{
        BlockId, ConsensusProofMetadata, ConsensusProofMetadataVrf, ConsensusVrfEntry,
        ConsensusVrfPoseidonInput,
    };
    use tempfile::tempdir;

    use crate::crypto::{address_from_public_key, generate_keypair, sign_message};
    use crate::types::{
        Account, ChainProof, ExecutionTrace, ProofKind, ProofPayload, ReputationWeights,
        RppStarkProof, SignedTransaction, Stake, StarkProof, Tier, Transaction,
        TransactionProofBundle, TransactionWitness,
    };
    use rpp_p2p::{
        vendor::PeerId as NetworkPeerId, SnapshotItemKind, SnapshotProvider, SnapshotSessionId,
    };

    fn sample_consensus_certificate() -> ConsensusCertificate {
        let digest = |byte: u8| hex::encode([byte; 32]);
        let pre_output = |byte: u8| hex::encode(vec![byte; crate::vrf::VRF_PREOUTPUT_LENGTH]);
        let proof_bytes = |byte: u8| hex::encode(vec![byte; VRF_PROOF_LENGTH]);

        let metadata = ConsensusProofMetadata {
            vrf: ConsensusProofMetadataVrf {
                entries: vec![
                    ConsensusVrfEntry {
                        randomness: digest(0x11),
                        pre_output: pre_output(0x11),
                        proof: proof_bytes(0x21),
                        public_key: digest(0x13),
                        poseidon: ConsensusVrfPoseidonInput {
                            digest: digest(0x31),
                            last_block_header: digest(0x32),
                            epoch: "49".into(),
                            tier_seed: digest(0x33),
                        },
                    },
                    ConsensusVrfEntry {
                        randomness: digest(0x12),
                        pre_output: pre_output(0x12),
                        proof: proof_bytes(0x22),
                        public_key: digest(0x14),
                        poseidon: ConsensusVrfPoseidonInput {
                            digest: digest(0x34),
                            last_block_header: digest(0x35),
                            epoch: "57".into(),
                            tier_seed: digest(0x36),
                        },
                    },
                ],
            },
            witness_commitments: vec![digest(0x33)],
            reputation_roots: vec![digest(0x44)],
            epoch: 5,
            slot: 7,
            quorum_bitmap_root: digest(0x55),
            quorum_signature_root: digest(0x66),
        };

        ConsensusCertificate {
            block_hash: BlockId(digest(0x77)),
            height: 42,
            round: 3,
            total_power: 100,
            quorum_threshold: 67,
            prevote_power: 80,
            precommit_power: 80,
            commit_power: 80,
            prevotes: Vec::new(),
            precommits: Vec::new(),
            metadata,
        }
    }

    #[test]
    fn summarize_consensus_certificate_includes_bindings() {
        let certificate = sample_consensus_certificate();
        let status = summarize_consensus_certificate(&certificate).expect("status computed");

        assert_eq!(status.height, certificate.height);
        assert_eq!(status.round, certificate.round);
        assert_eq!(status.block_hash, certificate.block_hash.0);
        let block_hash = decode_digest("block hash", &certificate.block_hash.0).unwrap();
        assert_eq!(
            status.vrf_entries.len(),
            certificate.metadata.vrf.entries.len()
        );
        let (_, backend_entries) = sanitize_vrf_entries(&certificate.metadata.vrf.entries)
            .expect("sanitize metadata vrf entries");
        let expected_entry_bindings =
            compute_vrf_entry_bindings(&block_hash, &backend_entries).expect("entry bindings");

        for ((status_entry, certificate_entry), expected_binding) in status
            .vrf_entries
            .iter()
            .zip(&certificate.metadata.vrf.entries)
            .zip(expected_entry_bindings.iter())
        {
            assert_eq!(status_entry.randomness, certificate_entry.randomness);
            assert_eq!(status_entry.pre_output, certificate_entry.pre_output);
            assert_eq!(status_entry.proof, certificate_entry.proof);
            assert_eq!(status_entry.public_key, certificate_entry.public_key);
            assert_eq!(
                status_entry.poseidon.digest,
                certificate_entry.poseidon.digest
            );
            assert_eq!(
                status_entry.poseidon.last_block_header,
                certificate_entry.poseidon.last_block_header
            );
            assert_eq!(
                status_entry.poseidon.epoch,
                certificate_entry.poseidon.epoch
            );
            assert_eq!(
                status_entry.poseidon.tier_seed,
                certificate_entry.poseidon.tier_seed
            );
            let bindings = status_entry
                .bindings
                .as_ref()
                .expect("entry bindings populated");
            assert_eq!(bindings.randomness, expected_binding.randomness);
            assert_eq!(bindings.proof, expected_binding.proof);
        }
        let expected_outputs: Vec<String> = certificate
            .metadata
            .vrf
            .entries
            .iter()
            .map(|entry| entry.pre_output.clone())
            .collect();
        assert_eq!(status.legacy_vrf_outputs(), expected_outputs);
        let expected_proofs: Vec<String> = certificate
            .metadata
            .vrf
            .entries
            .iter()
            .map(|entry| entry.proof.clone())
            .collect();
        assert_eq!(status.legacy_vrf_proofs(), expected_proofs);
        assert_eq!(
            status.witness_commitments,
            certificate.metadata.witness_commitments
        );
        assert_eq!(
            status.reputation_roots,
            certificate.metadata.reputation_roots
        );
        assert_eq!(
            status.quorum_bitmap_root,
            certificate.metadata.quorum_bitmap_root
        );
        assert_eq!(
            status.quorum_signature_root,
            certificate.metadata.quorum_signature_root
        );

        let witness_commitments =
            decode_digest_list("witness", &certificate.metadata.witness_commitments).unwrap();
        let reputation_roots =
            decode_digest_list("reputation", &certificate.metadata.reputation_roots).unwrap();
        let bitmap_root =
            decode_digest("bitmap", &certificate.metadata.quorum_bitmap_root).unwrap();
        let signature_root =
            decode_digest("signature", &certificate.metadata.quorum_signature_root).unwrap();

        let expected = compute_consensus_bindings(
            &block_hash,
            &backend_entries,
            &witness_commitments,
            &reputation_roots,
            &bitmap_root,
            &signature_root,
        )
        .unwrap();

        assert_eq!(status.vrf_output, hex::encode(expected.vrf_output));
        assert_eq!(status.vrf_proof, hex::encode(expected.vrf_proof));
        assert_eq!(
            status.witness_commitment_root,
            hex::encode(expected.witness_commitment)
        );
        assert_eq!(
            status.reputation_root,
            hex::encode(expected.reputation_root)
        );
        assert_eq!(status.quorum_bitmap, hex::encode(expected.quorum_bitmap));
        assert_eq!(
            status.quorum_signature,
            hex::encode(expected.quorum_signature)
        );
    }

    fn sample_node_config(base: &Path) -> NodeConfig {
        let data_dir = base.join("data");
        let keys_dir = base.join("keys");
        fs::create_dir_all(&data_dir).expect("node data dir");
        fs::create_dir_all(&keys_dir).expect("node key dir");

        let mut config = NodeConfig::default();
        config.data_dir = data_dir.clone();
        config.snapshot_dir = data_dir.join("snapshots");
        config.proof_cache_dir = data_dir.join("proofs");
        config.network.p2p.peerstore_path = data_dir.join("p2p/peerstore.json");
        config.network.p2p.gossip_path = Some(data_dir.join("p2p/gossip.json"));
        config.key_path = keys_dir.join("node.toml");
        config.p2p_key_path = keys_dir.join("p2p.toml");
        config.vrf_key_path = keys_dir.join("vrf.toml");
        config.block_time_ms = 200;
        config.mempool_limit = 8;
        config.rollout.feature_gates.pruning = false;
        config.rollout.feature_gates.recursive_proofs = false;
        config.rollout.feature_gates.reconstruction = false;
        config.rollout.feature_gates.consensus_enforcement = false;
        config
    }

    fn sample_transaction_bundle(to: &str, nonce: u64) -> TransactionProofBundle {
        let keypair = generate_keypair();
        let from = address_from_public_key(&keypair.public);
        let tx = Transaction::new(from.clone(), to.to_string(), 42, nonce, 1, None);
        let signature = sign_message(&keypair, &tx.canonical_bytes());
        let signed_tx = SignedTransaction::new(tx, signature, &keypair.public);

        let mut sender = Account::new(from.clone(), 1_000_000, Stake::from_u128(1_000));
        sender.nonce = nonce;

        let receiver = Account::new(to.to_string(), 0, Stake::default());

        let witness = TransactionWitness {
            signed_tx: signed_tx.clone(),
            sender_account: sender,
            receiver_account: Some(receiver),
            required_tier: Tier::Tl0,
            reputation_weights: ReputationWeights::default(),
        };

        let payload = ProofPayload::Transaction(witness.clone());
        let proof = StarkProof {
            kind: ProofKind::Transaction,
            commitment: String::new(),
            public_inputs: Vec::new(),
            payload: payload.clone(),
            trace: ExecutionTrace {
                segments: Vec::new(),
            },
            commitment_proof: Default::default(),
            fri_proof: Default::default(),
        };

        TransactionProofBundle::new(
            signed_tx,
            ChainProof::Stwo(proof),
            Some(witness),
            Some(payload),
        )
    }

    #[test]
    #[cfg(feature = "prover-stwo")]
    fn proof_artifact_serializes_stwo_commitment() {
        let mut bundle = sample_transaction_bundle("receiver", 0);
        if let ChainProof::Stwo(ref mut stark) = bundle.proof {
            stark.commitment = "ab".repeat(32);
        }
        let artifact = NodeInner::proof_artifact(ProofModule::Utxo, &bundle.proof, 16_384)
            .expect("artifact generation")
            .expect("artifact emitted");
        assert_eq!(artifact.commitment, [0xAB; 32]);
        let decoded: ChainProof = serde_json::from_slice(&artifact.proof).expect("decode");
        assert!(matches!(decoded, ChainProof::Stwo(_)));
    }

    #[test]
    #[cfg(feature = "backend-rpp-stark")]
    fn proof_artifact_serializes_rpp_stark_commitment() {
        let proof = ChainProof::RppStark(RppStarkProof::new(
            vec![0xAA, 0xBB],
            vec![0xCC, 0xDD, 0xEE],
            vec![0x01, 0x02],
        ));
        let expected_commitment = match &proof {
            ChainProof::RppStark(stark) => {
                compute_public_digest(stark.public_inputs()).into_bytes()
            }
            _ => unreachable!(),
        };
        let artifact = NodeInner::proof_artifact(ProofModule::Utxo, &proof, 16_384)
            .expect("artifact generation")
            .expect("artifact emitted");
        assert_eq!(artifact.commitment, expected_commitment);
        let decoded: RppStarkProof = serde_json::from_slice(&artifact.proof).expect("decode rpp");
        assert_eq!(decoded.public_inputs(), &[0xCC, 0xDD, 0xEE]);
        assert_eq!(decoded.proof(), &[0x01, 0x02]);
    }

    #[test]
    fn snapshot_breaker_state_tracks_failures() {
        let breaker = SnapshotCircuitBreaker::new(2);
        assert!(!breaker.status().open);

        let first_error = PipelineError::SnapshotVerification("manifest mismatch".into());
        let _ = breaker.record_failure(first_error);
        assert_eq!(breaker.status().consecutive_failures, 1);

        let second_error = PipelineError::SnapshotVerification("auth failed".into());
        let open_error = breaker.record_failure(second_error);
        assert!(matches!(open_error, PipelineError::SnapshotVerification(_)));
        let status = breaker.status();
        assert!(status.open);
        assert_eq!(status.consecutive_failures, 2);
        assert!(status
            .last_error
            .as_deref()
            .is_some_and(|message| message.contains("auth failed")));
        assert!(breaker.guard().is_err());

        breaker.record_success();
        assert!(breaker.status().open, "circuit stays open until reset");

        breaker.reset();
        let reset_status = breaker.status();
        assert!(!reset_status.open);
        assert_eq!(reset_status.consecutive_failures, 0);
        assert!(reset_status.last_error.is_none());
    }

    #[test]
    fn mempool_status_exposes_witness_metadata_with_and_without_cache() {
        let tempdir = tempdir().expect("tempdir");
        let config = sample_node_config(tempdir.path());
        let node = Node::new(config, RuntimeMetrics::noop()).expect("node init");
        let handle = node.handle();
        let recipient = handle.address().to_string();

        let bundle = sample_transaction_bundle(&recipient, 0);
        let hash = handle
            .submit_transaction(bundle.clone())
            .expect("transaction accepted");

        let status = handle.mempool_status().expect("mempool status");
        let summary = status
            .transactions
            .iter()
            .find(|tx| tx.hash == hash)
            .expect("summary present");
        assert!(summary.witness.is_some(), "witness missing from snapshot");
        assert!(summary.proof.is_some(), "proof missing from snapshot");
        assert!(
            summary.proof_payload.is_some(),
            "proof payload missing from snapshot"
        );

        node.inner
            .pending_transaction_metadata
            .write()
            .remove(&hash);

        let status_after = handle.mempool_status().expect("mempool status fallback");
        let summary_after = status_after
            .transactions
            .iter()
            .find(|tx| tx.hash == hash)
            .expect("summary present after purge");
        assert!(summary_after.witness.is_some(), "fallback witness missing");
        assert!(summary_after.proof.is_some(), "fallback proof missing");
        assert!(
            summary_after.proof_payload.is_some(),
            "fallback proof payload missing"
        );

        drop(handle);
        drop(node);
    }

    #[test]
    fn snapshot_acknowledgements_persist_across_restart() {
        let tempdir = tempdir().expect("tempdir");
        let config = sample_node_config(tempdir.path());
        let config_restart = config.clone();
        let node = Node::new(config, RuntimeMetrics::noop()).expect("node init");
        let provider = RuntimeSnapshotProvider::new_arc(
            Arc::clone(&node.inner),
            node.inner.config.snapshot_sizing.clone(),
            SnapshotCircuitBreaker::new(SNAPSHOT_BREAKER_THRESHOLD),
        );

        let session = SnapshotSessionId::new(7);
        let peer = NetworkPeerId::random();

        provider.open_session(session, &peer).expect("open session");
        let plan = SnapshotProvider::fetch_plan(&*provider, session).expect("fetch plan");

        let total_chunks = plan.chunks.len() as u64;
        assert!(
            total_chunks > 0,
            "expected plan to contain at least one chunk"
        );
        let chunk_index = 0u64;
        SnapshotProvider::fetch_chunk(&*provider, session, chunk_index).expect("chunk fetched");
        SnapshotProvider::acknowledge(&*provider, session, SnapshotItemKind::Chunk, chunk_index)
            .expect("chunk acknowledged");

        let update_index = if plan.light_client_updates.is_empty() {
            None
        } else {
            let update_index = 0u64;
            SnapshotProvider::fetch_update(&*provider, session, update_index)
                .expect("update fetched");
            SnapshotProvider::acknowledge(
                &*provider,
                session,
                SnapshotItemKind::LightClientUpdate,
                update_index,
            )
            .expect("update acknowledged");
            Some(update_index)
        };

        {
            let sessions = provider.sessions.lock();
            let record = sessions.get(&session).expect("session state");
            assert_eq!(record.confirmed_chunk_index, Some(chunk_index));
            match update_index {
                Some(index) => assert_eq!(record.confirmed_update_index, Some(index)),
                None => assert!(record.confirmed_update_index.is_none()),
            }
        }

        drop(provider);
        drop(node);

        let node = Node::new(config_restart, RuntimeMetrics::noop()).expect("node restart");
        let provider = RuntimeSnapshotProvider::new_arc(
            Arc::clone(&node.inner),
            node.inner.config.snapshot_sizing.clone(),
            SnapshotCircuitBreaker::new(SNAPSHOT_BREAKER_THRESHOLD),
        );
        {
            let sessions = provider.sessions.lock();
            let record = sessions.get(&session).expect("restored session state");
            assert_eq!(record.confirmed_chunk_index, Some(chunk_index));
            match update_index {
                Some(index) => assert_eq!(record.confirmed_update_index, Some(index)),
                None => assert!(record.confirmed_update_index.is_none()),
            }
        }
    }

    #[test]
    fn state_sync_cache_updates_chunk_size_after_verification() {
        let mut cache = StateSyncSessionCache::default();
        cache.configure(Some(16), Some(4), None);
        cache.mark_chunk_served(0);
        cache.set_status(StateSyncVerificationStatus::Verifying);

        cache.configure(Some(32), None, None);
        assert_eq!(cache.chunk_size, Some(16));

        cache.set_status(StateSyncVerificationStatus::Verified);
        cache.configure(Some(32), None, None);
        assert_eq!(cache.chunk_size, Some(32));
        assert!(cache.served_chunks.contains(&0));
    }

    #[test]
    fn snapshot_provider_persists_chunk_sizing_over_resume() {
        let tempdir = tempdir().expect("tempdir");
        let mut config = sample_node_config(tempdir.path());
        config.snapshot_sizing = SnapshotSizingConfig {
            default_chunk_size: 24,
            min_chunk_size: 16,
            max_chunk_size: 64,
        };
        let mut config_restart = config.clone();
        config_restart.snapshot_sizing.default_chunk_size = 20;
        let node = Node::new(config, RuntimeMetrics::noop()).expect("node init");
        let provider = RuntimeSnapshotProvider::new_arc(
            Arc::clone(&node.inner),
            node.inner.config.snapshot_sizing.clone(),
            SnapshotCircuitBreaker::new(SNAPSHOT_BREAKER_THRESHOLD),
        );

        let session = SnapshotSessionId::new(11);
        let peer = NetworkPeerId::random();

        provider.open_session(session, &peer).expect("open session");
        let plan = SnapshotProvider::fetch_plan(&*provider, session).expect("fetch plan");

        SnapshotProvider::resume_session(
            &*provider,
            session,
            &plan.snapshot.commitments.global_state_root,
            0,
            0,
            Some(48),
            Some(16),
            Some(64),
        )
        .expect("resume session");

        {
            let sessions = provider.sessions.lock();
            let record = sessions.get(&session).expect("session state");
            assert_eq!(record.chunk_size, 48);
            assert_eq!(record.min_chunk_size, 16);
            assert_eq!(record.max_chunk_size, 64);
        }

        drop(provider);
        drop(node);

        let node = Node::new(config_restart, RuntimeMetrics::noop()).expect("node restart");
        let provider = RuntimeSnapshotProvider::new_arc(
            Arc::clone(&node.inner),
            node.inner.config.snapshot_sizing.clone(),
            SnapshotCircuitBreaker::new(SNAPSHOT_BREAKER_THRESHOLD),
        );
        {
            let sessions = provider.sessions.lock();
            let record = sessions.get(&session).expect("restored session state");
            assert_eq!(record.chunk_size, 48);
            assert_eq!(record.min_chunk_size, 16);
            assert_eq!(record.max_chunk_size, 64);
        }
    }
}

fn build_genesis_accounts(entries: Vec<GenesisAccount>) -> ChainResult<Vec<Account>> {
    entries
        .into_iter()
        .map(|entry| {
            let stake = entry.stake_value()?;
            Ok(Account::new(entry.address, entry.balance, stake))
        })
        .collect()
}

#[cfg(feature = "backend-rpp-stark")]
fn stage_from_failure(
    failure: &RppStarkVerifyFailure,
    flags: RppStarkVerificationFlags,
) -> Option<ProofVerificationStage> {
    use RppStarkSerializationContext as SerCtx;
    use RppStarkVerifyFailure as Failure;

    let mapped = match failure {
        Failure::ParamsHashMismatch
        | Failure::VersionMismatch { .. }
        | Failure::UnknownProofKind(_)
        | Failure::HeaderLengthMismatch { .. }
        | Failure::BodyLengthMismatch { .. }
        | Failure::UnexpectedEndOfBuffer { .. }
        | Failure::IntegrityDigestMismatch
        | Failure::NonCanonicalFieldElement
        | Failure::DeterministicHashSlice { .. } => Some(ProofVerificationStage::Params),
        Failure::PublicInputMismatch | Failure::PublicDigestMismatch | Failure::TranscriptOrder => {
            Some(ProofVerificationStage::Public)
        }
        Failure::RootMismatch { .. }
        | Failure::MerkleVerifyFailed { .. }
        | Failure::TraceLeafMismatch
        | Failure::CompositionLeafMismatch
        | Failure::UnsupportedMerkleScheme => Some(ProofVerificationStage::Merkle),
        Failure::FriVerifyFailed { .. }
        | Failure::OutOfDomainInvalid
        | Failure::DegreeBoundExceeded
        | Failure::EmptyOpenings
        | Failure::IndicesNotSorted
        | Failure::IndicesDuplicate { .. }
        | Failure::IndicesMismatch
        | Failure::InvalidFriSection { .. } => Some(ProofVerificationStage::Fri),
        Failure::AggregationDigestMismatch
        | Failure::CompositionOodMismatch
        | Failure::CompositionInconsistent { .. } => Some(ProofVerificationStage::Composition),
        Failure::Serialization { context } => match context {
            SerCtx::Params => Some(ProofVerificationStage::Params),
            SerCtx::PublicInputs => Some(ProofVerificationStage::Public),
            SerCtx::TraceCommitment | SerCtx::CompositionCommitment => {
                Some(ProofVerificationStage::Merkle)
            }
            SerCtx::Fri | SerCtx::Openings => Some(ProofVerificationStage::Fri),
            SerCtx::Telemetry | SerCtx::Proof => Some(ProofVerificationStage::Adapter),
        },
        Failure::ProofTooLarge { .. } => Some(ProofVerificationStage::Adapter),
        Failure::TraceOodMismatch | Failure::CompositionOodMismatch => {
            Some(ProofVerificationStage::Composition)
        }
    };

    mapped.or_else(|| first_failing_stage(flags))
}

#[cfg(feature = "backend-rpp-stark")]
const fn first_failing_stage(flags: RppStarkVerificationFlags) -> Option<ProofVerificationStage> {
    if !flags.params() {
        return Some(ProofVerificationStage::Params);
    }
    if !flags.public() {
        return Some(ProofVerificationStage::Public);
    }
    if !flags.merkle() {
        return Some(ProofVerificationStage::Merkle);
    }
    if !flags.fri() {
        return Some(ProofVerificationStage::Fri);
    }
    if !flags.composition() {
        return Some(ProofVerificationStage::Composition);
    }
    None
}
