use std::collections::BTreeMap;

use crate::proof_backend::Blake2sHasher;
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

use crate::consensus::messages::ConsensusVrfEntry;
use crate::consensus::ConsensusWitnessBindings;
use crate::errors::{ChainError, ChainResult};
use crate::proof_backend::{
    ProofSystemKind as BackendProofSystemKind, WitnessBytes, WitnessHeader,
};
use crate::runtime::types::block::Block;
use crate::state::{merkle::compute_merkle_root, StoredUtxo};
use crate::types::Address;
use crate::types::PruningProof;
use crate::types::SignedTransaction;
use rayon::prelude::*;

/// 32-byte digest representing a commitment root.
pub type CommitmentDigest = [u8; 32];

const CIRCUIT_TRANSACTIONS: &str = "rpp.bundle.transactions";
const CIRCUIT_TIMETOKE: &str = "rpp.bundle.timetoke";
const CIRCUIT_REPUTATION: &str = "rpp.bundle.reputation";
const CIRCUIT_ZSI: &str = "rpp.bundle.zsi";
const CIRCUIT_BLOCK: &str = "rpp.bundle.block";
const CIRCUIT_CONSENSUS: &str = "rpp.bundle.consensus";

fn encode_witness_payload<T: Serialize>(circuit: &str, payload: &T) -> ChainResult<Vec<u8>> {
    let header = WitnessHeader::new(BackendProofSystemKind::from(ProofSystemKind::Stwo), circuit);
    WitnessBytes::encode(&header, payload)
        .map_err(ChainError::from)
        .map(WitnessBytes::into_inner)
}

/// Serialises a single transaction witness into the canonical encoding used by
/// proof backends.
#[cfg(feature = "backend-rpp-stark")]
pub fn encode_transaction_witness(witness: &TransactionWitness) -> ChainResult<Vec<u8>> {
    encode_witness_payload(CIRCUIT_TRANSACTIONS, witness)
}

/// Enumeration of all state modules that participate in the recursive pruning proof pipeline.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StateModule {
    GlobalAccounts,
    Utxo,
    Reputation,
    Timetoke,
    ZsiRegistry,
    ProofRegistry,
}

/// Supported cryptographic hash functions for commitment trees.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum HashFunction {
    Poseidon,
    Blake2s,
    Sha256,
    Keccak256,
}

/// Supported commitment schemes for substates.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommitmentScheme {
    Merkle,
    Verkle,
    PolynomialIpa,
}

/// High-level proof systems used in the blueprint.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofSystemKind {
    Stwo,
    Plonky3,
    Plonky2,
    Halo2,
    RppStark,
}

impl From<ProofSystemKind> for BackendProofSystemKind {
    fn from(kind: ProofSystemKind) -> Self {
        match kind {
            ProofSystemKind::Stwo => BackendProofSystemKind::Stwo,
            ProofSystemKind::Plonky3 => BackendProofSystemKind::Plonky3,
            ProofSystemKind::Plonky2 => BackendProofSystemKind::Plonky2,
            ProofSystemKind::Halo2 => BackendProofSystemKind::Halo2,
            ProofSystemKind::RppStark => BackendProofSystemKind::RppStark,
        }
    }
}

/// Encoding used for witnesses that accompany commitment proofs.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WitnessEncoding {
    BinaryMerklePath,
    VerkleProof,
    PolynomialCommitment,
    RecursiveTranscript,
}

/// Describes the commitment configuration for a specific state module.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentDescriptor {
    pub scheme: CommitmentScheme,
    pub hash: HashFunction,
    pub arity: u8,
    pub depth: u32,
    pub description: String,
}

impl CommitmentDescriptor {
    pub fn merkle_poseidon(depth: u32, description: impl Into<String>) -> Self {
        Self {
            scheme: CommitmentScheme::Merkle,
            hash: HashFunction::Poseidon,
            arity: 2,
            depth,
            description: description.into(),
        }
    }

    pub fn verkle_poseidon(description: impl Into<String>) -> Self {
        Self {
            scheme: CommitmentScheme::Verkle,
            hash: HashFunction::Poseidon,
            arity: 2,
            depth: 0,
            description: description.into(),
        }
    }
}

/// Blueprint entry describing a module's state schema and commitment configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModuleBlueprint {
    pub module: StateModule,
    pub commitment: CommitmentDescriptor,
    pub record_schema: Schema,
    pub witness_encoding: WitnessEncoding,
    pub proof_system: ProofSystemKind,
}

/// Aggregation strategy for combining module commitments into a block header field.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum HeaderAggregation {
    Blake2sBinary,
}

/// Defines how module commitments are ordered and aggregated for the block header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderLayout {
    pub aggregation: HeaderAggregation,
    pub module_order: Vec<StateModule>,
}

impl HeaderLayout {
    /// Aggregate all module commitments into a single digest according to the layout.
    pub fn aggregate(&self, commitments: &GlobalStateCommitments) -> CommitmentDigest {
        let mut iter = self
            .module_order
            .iter()
            .map(|module| commitments.commitment_for(*module));

        match self.aggregation {
            HeaderAggregation::Blake2sBinary => {
                if let Some(first) = iter.next() {
                    iter.fold(first, |acc, item| {
                        let mut hasher = Blake2s256::new();
                        hasher.update(acc);
                        hasher.update(item);
                        let hash = hasher.finalize();
                        let mut digest = [0u8; 32];
                        digest.copy_from_slice(&hash);
                        digest
                    })
                } else {
                    [0u8; 32]
                }
            }
        }
    }
}

/// Complete architecture blueprint tying the module layout, commitment aggregation and proof system together.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchitectureBlueprint {
    pub header_layout: HeaderLayout,
    pub modules: Vec<ModuleBlueprint>,
    pub proof_system: ProofSystemDescriptor,
    pub circuits: CircuitBlueprint,
}

/// Describes how recursive proofs are composed for block validation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofSystemDescriptor {
    pub base_layer: ProofSystemKind,
    pub recursion_layer: ProofSystemKind,
    pub public_inputs: Vec<RecursionInput>,
}

/// Canonical description of a circuit signal that can be either a witness or public input.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitSignal {
    pub name: String,
    pub data_type: DataType,
    pub description: String,
}

impl CircuitSignal {
    pub fn new(
        name: impl Into<String>,
        data_type: DataType,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            data_type,
            description: description.into(),
        }
    }
}

/// Binding between a circuit signal and an external commitment/module reference.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitBinding {
    pub signal: String,
    pub module: Option<StateModule>,
    pub description: String,
}

impl CircuitBinding {
    pub fn new(
        signal: impl Into<String>,
        module: Option<StateModule>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            signal: signal.into(),
            module,
            description: description.into(),
        }
    }
}

/// High-level constraint description attached to a circuit stage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitConstraint {
    pub name: String,
    pub expression: String,
    pub description: String,
}

impl CircuitConstraint {
    pub fn new(
        name: impl Into<String>,
        expression: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            expression: expression.into(),
            description: description.into(),
        }
    }
}

/// Enumerates the role a circuit stage plays within the recursive composition.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CircuitStageKind {
    Base,
    Aggregation,
    Recursion,
}

/// Blueprint entry describing a specific circuit and its public interface.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitStage {
    pub name: String,
    pub kind: CircuitStageKind,
    pub proof_system: ProofSystemKind,
    pub description: String,
    pub witness_signals: Vec<CircuitSignal>,
    pub public_inputs: Vec<CircuitBinding>,
    pub public_outputs: Vec<CircuitBinding>,
    pub constraints: Vec<CircuitConstraint>,
    pub dependencies: Vec<String>,
}

impl CircuitStage {
    pub fn new(
        name: impl Into<String>,
        kind: CircuitStageKind,
        proof_system: ProofSystemKind,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            proof_system,
            description: description.into(),
            witness_signals: Vec::new(),
            public_inputs: Vec::new(),
            public_outputs: Vec::new(),
            constraints: Vec::new(),
            dependencies: Vec::new(),
        }
    }

    pub fn with_witness_signals(mut self, signals: Vec<CircuitSignal>) -> Self {
        self.witness_signals = signals;
        self
    }

    pub fn with_public_inputs(mut self, inputs: Vec<CircuitBinding>) -> Self {
        self.public_inputs = inputs;
        self
    }

    pub fn with_public_outputs(mut self, outputs: Vec<CircuitBinding>) -> Self {
        self.public_outputs = outputs;
        self
    }

    pub fn with_constraints(mut self, constraints: Vec<CircuitConstraint>) -> Self {
        self.constraints = constraints;
        self
    }

    pub fn with_dependencies(mut self, dependencies: Vec<String>) -> Self {
        self.dependencies = dependencies;
        self
    }
}

/// Ordered list of all circuits needed to produce and verify the recursive pruning proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitBlueprint {
    pub stages: Vec<CircuitStage>,
}

impl CircuitBlueprint {
    pub fn stage(&self, name: &str) -> Option<&CircuitStage> {
        self.stages.iter().find(|stage| stage.name == name)
    }
}

/// Definition of a public input that must be fed into the recursive circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursionInput {
    pub module: StateModule,
    pub description: String,
}

/// Schema definition for a state module.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Schema {
    pub name: String,
    pub description: String,
    pub fields: Vec<FieldDescriptor>,
}

/// Description of a field inside a state schema.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldDescriptor {
    pub name: String,
    pub data_type: DataType,
    pub description: String,
}

/// Primitive data types used across the blueprint schemas.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DataType {
    Address,
    Amount,
    Hash32,
    Bytes,
    Timestamp,
    Boolean,
    Float64,
    Uint64,
    Uint128,
    Int64,
    CommitmentDigest,
    Tier,
}

/// Aggregated commitment digests for all substates that will be embedded in the block header.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct GlobalStateCommitments {
    pub global_state_root: CommitmentDigest,
    pub utxo_root: CommitmentDigest,
    pub reputation_root: CommitmentDigest,
    pub timetoke_root: CommitmentDigest,
    pub zsi_root: CommitmentDigest,
    pub proof_root: CommitmentDigest,
}

impl GlobalStateCommitments {
    pub fn commitment_for(&self, module: StateModule) -> CommitmentDigest {
        match module {
            StateModule::GlobalAccounts => self.global_state_root,
            StateModule::Utxo => self.utxo_root,
            StateModule::Reputation => self.reputation_root,
            StateModule::Timetoke => self.timetoke_root,
            StateModule::ZsiRegistry => self.zsi_root,
            StateModule::ProofRegistry => self.proof_root,
        }
    }
}

impl Default for GlobalStateCommitments {
    fn default() -> Self {
        Self {
            global_state_root: [0u8; 32],
            utxo_root: [0u8; 32],
            reputation_root: [0u8; 32],
            timetoke_root: [0u8; 32],
            zsi_root: [0u8; 32],
            proof_root: [0u8; 32],
        }
    }
}

/// Outpoint that uniquely identifies a UTXO inside the ledger.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct UtxoOutpoint {
    pub tx_id: CommitmentDigest,
    pub index: u32,
}

/// Representation of an unspent output that participates in the UTXO commitment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UtxoRecord {
    pub outpoint: UtxoOutpoint,
    pub owner: Address,
    pub value: u128,
    pub asset_type: AssetType,
    pub script_hash: CommitmentDigest,
    pub timelock: Option<u64>,
}

/// Asset categories supported by the chain.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssetType {
    Native,
    Custom(String),
}

/// Snapshot of a node's time-based participation token balance.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct TimetokeRecord {
    pub identity: Address,
    pub balance: u128,
    pub epoch_accrual: u64,
    pub decay_rate: f32,
    pub last_update: u64,
    pub last_sync: u64,
    pub last_decay: u64,
}

impl Default for TimetokeRecord {
    fn default() -> Self {
        Self {
            identity: String::new(),
            balance: 0,
            epoch_accrual: 0,
            decay_rate: 1.0,
            last_update: 0,
            last_sync: 0,
            last_decay: 0,
        }
    }
}

/// Consolidated reputation information committed into `rep_root`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationRecord {
    pub identity: Address,
    pub score: f64,
    pub tier: TierDescriptor,
    pub uptime_hours: u64,
    pub consensus_success: u64,
    pub peer_feedback: i64,
    pub zsi_validated: bool,
}

/// Abstract tier information.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TierDescriptor {
    Candidate,
    Validator,
    Guardian,
    Booted,
    Custom(String),
}

/// Registry entry representing a zero-state identity (ZSI).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZsiRecord {
    pub identity: Address,
    pub genesis_id: String,
    pub attestation_digest: CommitmentDigest,
    pub approvals: Vec<ConsensusApproval>,
}

/// Approval emitted by the consensus module when onboarding a new identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusApproval {
    pub validator: Address,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

/// Compact description of an attached proof artifact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofArtifact {
    pub module: ProofModule,
    pub commitment: CommitmentDigest,
    pub proof: Vec<u8>,
    pub verification_key: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountBalanceWitness {
    pub address: Address,
    pub balance: u128,
    pub nonce: u64,
}

impl AccountBalanceWitness {
    pub fn new(address: Address, balance: u128, nonce: u64) -> Self {
        Self {
            address,
            balance,
            nonce,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionUtxoSnapshot {
    pub outpoint: UtxoOutpoint,
    pub utxo: StoredUtxo,
}

impl TransactionUtxoSnapshot {
    pub fn new(outpoint: UtxoOutpoint, utxo: StoredUtxo) -> Self {
        Self { outpoint, utxo }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerklePathWitness {
    pub siblings: Vec<CommitmentDigest>,
}

impl MerklePathWitness {
    pub fn new(expected_depth: u32, siblings: Vec<CommitmentDigest>) -> ChainResult<Self> {
        let path = Self { siblings };
        path.validate_depth(expected_depth)?;
        Ok(path)
    }

    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    pub fn validate_depth(&self, expected_depth: u32) -> ChainResult<()> {
        if self.depth() != expected_depth as usize {
            return Err(ChainError::Config(format!(
                "merkle path depth mismatch: expected {expected_depth}, found {}",
                self.depth()
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockWitness {
    pub transactions: Vec<TransactionWitness>,
    pub transaction_paths: Vec<MerklePathWitness>,
    pub pruning_proofs: Vec<PruningProof>,
}

impl BlockWitness {
    pub fn validate(&self, expected_tx_count: usize, expected_path_depth: u32) -> ChainResult<()> {
        if self.transactions.len() != expected_tx_count {
            return Err(ChainError::Config(format!(
                "block witness transaction count mismatch: expected {expected_tx_count}, found {}",
                self.transactions.len()
            )));
        }

        if self.transaction_paths.len() != expected_tx_count {
            return Err(ChainError::Config(format!(
                "block witness merkle path count mismatch: expected {expected_tx_count}, found {}",
                self.transaction_paths.len()
            )));
        }

        for (index, path) in self.transaction_paths.iter().enumerate() {
            path.validate_depth(expected_path_depth)
                .map_err(|err| ChainError::Config(format!("transaction #{index} {err}")))?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BlockWitnessBuilder {
    transactions: Vec<TransactionWitness>,
    transaction_paths: Vec<MerklePathWitness>,
    pruning_proofs: Vec<PruningProof>,
    expected_path_depth: Option<u32>,
}

impl BlockWitnessBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_expected_path_depth(mut self, depth: u32) -> Self {
        self.expected_path_depth = Some(depth);
        self
    }

    pub fn with_transactions(mut self, transactions: Vec<TransactionWitness>) -> Self {
        self.transactions = transactions;
        self
    }

    pub fn with_transaction_paths(mut self, paths: Vec<MerklePathWitness>) -> Self {
        self.transaction_paths = paths;
        self
    }

    pub fn with_pruning_proofs(mut self, proofs: Vec<PruningProof>) -> Self {
        self.pruning_proofs = proofs;
        self
    }

    pub fn build(self) -> ChainResult<BlockWitness> {
        let expected_depth = match (self.expected_path_depth, self.transaction_paths.first()) {
            (Some(depth), _) => depth,
            (None, Some(path)) => path.depth() as u32,
            (None, None) => {
                return Err(ChainError::Config(
                    "block witness requires a merkle path depth".into(),
                ))
            }
        };

        let witness = BlockWitness {
            transactions: self.transactions,
            transaction_paths: self.transaction_paths,
            pruning_proofs: self.pruning_proofs,
        };

        witness.validate(witness.transactions.len(), expected_depth)?;
        Ok(witness)
    }
}

/// Abstraction over the state view required to assemble a block witness.
///
/// Implementations are responsible for sourcing transaction witnesses and
/// Merkle paths, ideally reusing cached values where possible.
pub trait StateView: Send + Sync {
    /// Return the expected Merkle path depth for transaction inclusion proofs.
    fn merkle_path_depth(&self) -> ChainResult<u32>;

    /// Attempt to fetch a cached Merkle path for the provided transaction.
    fn cached_transaction_path(&self, tx: &SignedTransaction) -> Option<MerklePathWitness>;

    /// Load (and cache) the Merkle path for the provided transaction.
    fn load_transaction_path(&self, tx: &SignedTransaction) -> ChainResult<MerklePathWitness>;

    /// Attempt to fetch cached pruning proofs for the block.
    fn cached_pruning_proofs(&self) -> Option<Vec<PruningProof>>;

    /// Load pruning proofs for the block when the cache misses.
    fn load_pruning_proofs(&self) -> ChainResult<Vec<PruningProof>>;

    /// Build a transaction witness for the supplied signed transaction.
    fn transaction_witness(&self, tx: &SignedTransaction) -> ChainResult<TransactionWitness>;

    /// Log cache misses for diagnostics.
    fn log_cache_miss(&self, kind: &str);
}

/// Assemble a [`BlockWitness`] for the provided block using the supplied
/// [`StateView`]. Transaction witness derivation is parallelised to minimise
/// latency while reusing cached Merkle paths and pruning proofs when available.
pub fn produce_block_witness(
    block: Block,
    state_view: &dyn StateView,
) -> ChainResult<BlockWitness> {
    let expected_depth = state_view.merkle_path_depth()?;

    let pruning_proofs = match state_view.cached_pruning_proofs() {
        Some(proofs) => proofs,
        None => {
            state_view.log_cache_miss("pruning_proofs");
            state_view.load_pruning_proofs()?
        }
    };

    let transaction_results: ChainResult<Vec<(TransactionWitness, MerklePathWitness)>> = block
        .transactions
        .par_iter()
        .map(|tx| {
            let witness = state_view.transaction_witness(tx)?;
            let path = match state_view.cached_transaction_path(tx) {
                Some(path) => path,
                None => {
                    state_view.log_cache_miss("transaction_merkle_path");
                    state_view.load_transaction_path(tx)?
                }
            };
            Ok((witness, path))
        })
        .collect();

    let (transactions, transaction_paths): (Vec<_>, Vec<_>) =
        transaction_results?.into_iter().unzip();

    let witness = BlockWitnessBuilder::new()
        .with_expected_path_depth(expected_depth)
        .with_transactions(transactions)
        .with_transaction_paths(transaction_paths)
        .with_pruning_proofs(pruning_proofs)
        .build()?;

    witness.validate(block.transactions.len(), expected_depth)?;
    Ok(witness)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionWitness {
    pub tx_id: CommitmentDigest,
    pub fee: u64,
    pub sender_before: AccountBalanceWitness,
    pub sender_after: AccountBalanceWitness,
    pub recipient_before: Option<AccountBalanceWitness>,
    pub recipient_after: AccountBalanceWitness,
    pub sender_utxos_before: Vec<TransactionUtxoSnapshot>,
    pub sender_utxos_after: Vec<TransactionUtxoSnapshot>,
    pub recipient_utxos_before: Vec<TransactionUtxoSnapshot>,
    pub recipient_utxos_after: Vec<TransactionUtxoSnapshot>,
}

impl TransactionWitness {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_id: CommitmentDigest,
        fee: u64,
        sender_before: AccountBalanceWitness,
        sender_after: AccountBalanceWitness,
        recipient_before: Option<AccountBalanceWitness>,
        recipient_after: AccountBalanceWitness,
        sender_utxos_before: Vec<TransactionUtxoSnapshot>,
        sender_utxos_after: Vec<TransactionUtxoSnapshot>,
        recipient_utxos_before: Vec<TransactionUtxoSnapshot>,
        recipient_utxos_after: Vec<TransactionUtxoSnapshot>,
    ) -> Self {
        Self {
            tx_id,
            fee,
            sender_before,
            sender_after,
            recipient_before,
            recipient_after,
            sender_utxos_before,
            sender_utxos_after,
            recipient_utxos_before,
            recipient_utxos_after,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimetokeWitness {
    pub identity: Address,
    pub previous: Option<TimetokeRecord>,
    pub updated: TimetokeRecord,
    pub window_start: u64,
    pub window_end: u64,
    pub credited_hours: u64,
}

impl TimetokeWitness {
    pub fn new(
        identity: Address,
        previous: Option<TimetokeRecord>,
        updated: TimetokeRecord,
        window_start: u64,
        window_end: u64,
        credited_hours: u64,
    ) -> Self {
        Self {
            identity,
            previous,
            updated,
            window_start,
            window_end,
            credited_hours,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReputationEventKind {
    IdentityOnboarding,
    TransferDebit,
    TransferCredit,
    TimetokeAccrual,
    ConsensusReward,
    Slashing,
    Custom(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationWitness {
    pub identity: Address,
    pub cause: ReputationEventKind,
    pub previous: Option<ReputationRecord>,
    pub updated: ReputationRecord,
}

impl ReputationWitness {
    pub fn new(
        identity: Address,
        cause: ReputationEventKind,
        previous: Option<ReputationRecord>,
        updated: ReputationRecord,
    ) -> Self {
        Self {
            identity,
            cause,
            previous,
            updated,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZsiWitness {
    pub identity: Address,
    pub previous: Option<ZsiRecord>,
    pub updated: ZsiRecord,
}

impl ZsiWitness {
    pub fn new(identity: Address, previous: Option<ZsiRecord>, updated: ZsiRecord) -> Self {
        Self {
            identity,
            previous,
            updated,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusWitness {
    pub height: u64,
    pub round: u64,
    pub participants: Vec<Address>,
    #[serde(default)]
    pub vrf_entries: Vec<ConsensusVrfEntry>,
    pub vrf_outputs: Vec<String>,
    pub vrf_proofs: Vec<String>,
    pub witness_commitments: Vec<String>,
    #[serde(default)]
    pub reputation_roots: Vec<String>,
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub slot: u64,
    pub quorum_bitmap_root: String,
    pub quorum_signature_root: String,
    #[serde(default)]
    pub bindings: ConsensusWitnessBindings,
}

impl ConsensusWitness {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        round: u64,
        participants: Vec<Address>,
        vrf_entries: Vec<ConsensusVrfEntry>,
        vrf_outputs: Vec<String>,
        vrf_proofs: Vec<String>,
        witness_commitments: Vec<String>,
        reputation_roots: Vec<String>,
        epoch: u64,
        slot: u64,
        quorum_bitmap_root: String,
        quorum_signature_root: String,
        bindings: ConsensusWitnessBindings,
    ) -> Self {
        Self {
            height,
            round,
            participants,
            vrf_entries,
            vrf_outputs,
            vrf_proofs,
            witness_commitments,
            reputation_roots,
            epoch,
            slot,
            quorum_bitmap_root,
            quorum_signature_root,
            bindings,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ModuleWitnessBundle {
    #[serde(default)]
    pub block: Option<BlockWitness>,
    pub transactions: Vec<TransactionWitness>,
    pub timetoke: Vec<TimetokeWitness>,
    pub reputation: Vec<ReputationWitness>,
    pub zsi: Vec<ZsiWitness>,
    pub consensus: Vec<ConsensusWitness>,
}

impl ModuleWitnessBundle {
    const UTXO_DOMAIN: &'static [u8] = b"rpp-utxo-witness";
    const TIMETOKE_DOMAIN: &'static [u8] = b"rpp-timetoke-witness";
    const REPUTATION_DOMAIN: &'static [u8] = b"rpp-reputation-witness";
    const ZSI_DOMAIN: &'static [u8] = b"rpp-zsi-witness";
    const BLOCK_DOMAIN: &'static [u8] = b"rpp-block-witness";
    const CONSENSUS_DOMAIN: &'static [u8] = b"rpp-consensus-witness";

    pub fn record_block(&mut self, witness: BlockWitness) {
        self.block = Some(witness);
    }

    pub fn record_transaction(&mut self, witness: TransactionWitness) {
        self.transactions.push(witness);
    }

    pub fn record_timetoke(&mut self, witness: TimetokeWitness) {
        self.timetoke.push(witness);
    }

    pub fn record_reputation(&mut self, witness: ReputationWitness) {
        self.reputation.push(witness);
    }

    pub fn record_zsi(&mut self, witness: ZsiWitness) {
        self.zsi.push(witness);
    }

    pub fn record_consensus(&mut self, witness: ConsensusWitness) {
        self.consensus.push(witness);
    }

    pub fn is_empty(&self) -> bool {
        self.block.is_none()
            && self.transactions.is_empty()
            && self.timetoke.is_empty()
            && self.reputation.is_empty()
            && self.zsi.is_empty()
            && self.consensus.is_empty()
    }

    pub fn expected_artifacts(&self) -> ChainResult<Vec<(ProofModule, CommitmentDigest, Vec<u8>)>> {
        let mut artifacts = Vec::new();
        artifacts.push((
            ProofModule::UtxoWitness,
            self.namespaced_commitment(
                Self::UTXO_DOMAIN,
                &self.transactions,
                CIRCUIT_TRANSACTIONS,
            )?,
            encode_witness_payload(CIRCUIT_TRANSACTIONS, &self.transactions)
                .map_err(|err| ChainError::Config(format!("serialize utxo witnesses: {err}")))?,
        ));
        artifacts.push((
            ProofModule::TimetokeWitness,
            self.namespaced_commitment(Self::TIMETOKE_DOMAIN, &self.timetoke, CIRCUIT_TIMETOKE)?,
            encode_witness_payload(CIRCUIT_TIMETOKE, &self.timetoke).map_err(|err| {
                ChainError::Config(format!("serialize timetoke witnesses: {err}"))
            })?,
        ));
        artifacts.push((
            ProofModule::ReputationWitness,
            self.namespaced_commitment(
                Self::REPUTATION_DOMAIN,
                &self.reputation,
                CIRCUIT_REPUTATION,
            )?,
            encode_witness_payload(CIRCUIT_REPUTATION, &self.reputation).map_err(|err| {
                ChainError::Config(format!("serialize reputation witnesses: {err}"))
            })?,
        ));
        artifacts.push((
            ProofModule::ZsiWitness,
            self.namespaced_commitment(Self::ZSI_DOMAIN, &self.zsi, CIRCUIT_ZSI)?,
            encode_witness_payload(CIRCUIT_ZSI, &self.zsi)
                .map_err(|err| ChainError::Config(format!("serialize zsi witnesses: {err}")))?,
        ));
        artifacts.push((
            ProofModule::BlockWitness,
            self.namespaced_commitment(
                Self::BLOCK_DOMAIN,
                &[self
                    .block
                    .as_ref()
                    .ok_or_else(|| ChainError::Config("missing block witness".into()))?],
                CIRCUIT_BLOCK,
            )?,
            encode_witness_payload(
                CIRCUIT_BLOCK,
                self.block
                    .as_ref()
                    .ok_or_else(|| ChainError::Config("missing block witness".into()))?,
            )
            .map_err(|err| ChainError::Config(format!("serialize block witness bundle: {err}")))?,
        ));
        artifacts.push((
            ProofModule::ConsensusWitness,
            self.namespaced_commitment(Self::CONSENSUS_DOMAIN, &self.consensus, CIRCUIT_CONSENSUS)?,
            encode_witness_payload(CIRCUIT_CONSENSUS, &self.consensus).map_err(|err| {
                ChainError::Config(format!("serialize consensus witnesses: {err}"))
            })?,
        ));
        Ok(artifacts)
    }

    pub fn namespaced_commitment<T>(
        &self,
        domain: &[u8],
        items: &[T],
        circuit: &str,
    ) -> ChainResult<CommitmentDigest>
    where
        T: Serialize,
    {
        let merkle_root = if items.is_empty() {
            [0u8; 32]
        } else {
            let mut leaves = items
                .iter()
                .map(|item| {
                    let bytes = encode_witness_payload(circuit, item).map_err(|err| {
                        ChainError::Config(format!(
                            "serialize witness leaf for merkle commitment: {err}"
                        ))
                    })?;
                    let digest: [u8; 32] = Blake2sHasher::hash(&bytes).into();
                    Ok(digest)
                })
                .collect::<ChainResult<Vec<_>>>()?;
            compute_merkle_root(&mut leaves)
        };
        let mut hasher = Blake2s256::new();
        hasher.update(domain);
        hasher.update(merkle_root);
        let hash = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&hash);
        Ok(digest)
    }
}

/// Proof modules that feed into the recursive composition.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProofModule {
    BlockTransition,
    Utxo,
    Reputation,
    Timetoke,
    Zsi,
    Consensus,
    UtxoWitness,
    ReputationWitness,
    TimetokeWitness,
    ZsiWitness,
    ConsensusWitness,
    BlockWitness,
}

/// Blueprint for the default recursive pruning proof architecture.
fn default_circuit_blueprint() -> CircuitBlueprint {
    let global_state_stage = CircuitStage::new(
        "global_state_transition",
        CircuitStageKind::Base,
        ProofSystemKind::Stwo,
        "Applies account-level balance, stake and nonce updates while linking to the global state commitment.",
    )
    .with_witness_signals(vec![
        CircuitSignal::new(
            "accounts_before",
            DataType::Bytes,
            "Poseidon-Merkle authentication paths for all accounts touched by the block.",
        ),
        CircuitSignal::new(
            "accounts_after",
            DataType::Bytes,
            "Merkle paths proving the updated accounts are consistent with the new global root.",
        ),
        CircuitSignal::new(
            "transaction_batch_commitment",
            DataType::CommitmentDigest,
            "Digest of the ordered transaction batch applied by the block producer.",
        ),
        CircuitSignal::new(
            "fee_accumulator",
            DataType::Uint128,
            "Total fees collected from the batch, credited to the fee pool.",
        ),
    ])
    .with_public_inputs(vec![
        CircuitBinding::new(
            "prev_global_root",
            Some(StateModule::GlobalAccounts),
            "Global account commitment before applying the block.",
        ),
        CircuitBinding::new(
            "next_global_root",
            Some(StateModule::GlobalAccounts),
            "Global account commitment after applying the block.",
        ),
        CircuitBinding::new(
            "block_height",
            None,
            "Block height to bind the execution trace to a specific transition.",
        ),
    ])
    .with_public_outputs(vec![CircuitBinding::new(
        "state_transition_commitment",
        Some(StateModule::ProofRegistry),
        "Digest exported to the proof registry so the recursive layer can authenticate the state transition.",
    )])
    .with_constraints(vec![
        CircuitConstraint::new(
            "balance_conservation",
            "sum(input_balances) = sum(output_balances) + fee_accumulator",
            "Guarantees that account balances are conserved up to the collected fees.",
        ),
        CircuitConstraint::new(
            "nonce_increment",
            "nonce_after = nonce_before + tx_count",
            "Ensures every sender increments its nonce exactly once per authorized transaction.",
        ),
        CircuitConstraint::new(
            "merkle_consistency",
            "Merkle(accounts_before, prev_global_root) && Merkle(accounts_after, next_global_root)",
            "Binds the witness accounts to both the previous and next global commitments.",
        ),
    ]);

    let utxo_stage = CircuitStage::new(
        "utxo_transition",
        CircuitStageKind::Base,
        ProofSystemKind::Stwo,
        "Validates consumption and creation of UTXOs across the transaction batch.",
    )
    .with_witness_signals(vec![
        CircuitSignal::new(
            "spent_utxos",
            DataType::Bytes,
            "Authentication paths proving the membership of every consumed UTXO.",
        ),
        CircuitSignal::new(
            "created_utxos",
            DataType::Bytes,
            "Commitments describing the outputs created by the batch.",
        ),
        CircuitSignal::new(
            "fee_commitment",
            DataType::Uint64,
            "Total fee amount withdrawn from the transaction inputs.",
        ),
    ])
    .with_public_inputs(vec![
        CircuitBinding::new(
            "prev_utxo_root",
            Some(StateModule::Utxo),
            "UTXO commitment prior to applying the block transactions.",
        ),
        CircuitBinding::new(
            "next_utxo_root",
            Some(StateModule::Utxo),
            "UTXO commitment after the block transactions are applied.",
        ),
    ])
    .with_public_outputs(vec![CircuitBinding::new(
        "utxo_transition_commitment",
        Some(StateModule::ProofRegistry),
        "Digest exported to the proof registry capturing the spend and create delta.",
    )])
    .with_constraints(vec![
        CircuitConstraint::new(
            "unique_outpoints",
            "forall spent: unique(outpoint)",
            "Enforces that no outpoint is referenced more than once, preventing double spends.",
        ),
        CircuitConstraint::new(
            "value_conservation",
            "sum(spent_values) = sum(created_values) + fee_commitment",
            "Matches the total value destroyed with the value created plus fees.",
        ),
        CircuitConstraint::new(
            "merkle_paths",
            "Merkle(spent_utxos, prev_utxo_root) && Merkle(created_utxos, next_utxo_root)",
            "Links the witness proofs to the advertised pre and post UTXO commitments.",
        ),
    ])
    .with_dependencies(vec!["global_state_transition".into()]);

    let timetoke_stage = CircuitStage::new(
        "timetoke_accrual",
        CircuitStageKind::Base,
        ProofSystemKind::Stwo,
        "Checks epoch-bounded uptime proofs and updates timetoke balances.",
    )
    .with_witness_signals(vec![
        CircuitSignal::new(
            "uptime_proofs",
            DataType::Bytes,
            "Raw uptime attestations collected for the epoch window.",
        ),
        CircuitSignal::new(
            "balances_before",
            DataType::Bytes,
            "Merkle paths attesting the previous timetoke balances.",
        ),
        CircuitSignal::new(
            "balances_after",
            DataType::Bytes,
            "Merkle paths attesting the updated timetoke balances.",
        ),
    ])
    .with_public_inputs(vec![
        CircuitBinding::new(
            "prev_timetoke_root",
            Some(StateModule::Timetoke),
            "Timetoke commitment before applying uptime rewards.",
        ),
        CircuitBinding::new(
            "next_timetoke_root",
            Some(StateModule::Timetoke),
            "Timetoke commitment after applying uptime rewards.",
        ),
        CircuitBinding::new(
            "epoch",
            None,
            "Epoch identifier for which the uptime proofs are valid.",
        ),
    ])
    .with_public_outputs(vec![CircuitBinding::new(
        "timetoke_transition_commitment",
        Some(StateModule::ProofRegistry),
        "Digest exported to the proof registry with the accumulated timetoke delta.",
    )])
    .with_constraints(vec![
        CircuitConstraint::new(
            "epoch_window",
            "forall proof: window_start <= proof.timestamp <= window_end",
            "Validates that uptime attestations fall inside the declared epoch window.",
        ),
        CircuitConstraint::new(
            "balance_update",
            "balance_after = balance_before + credited_hours",
            "Ensures balances only increase by the computed uptime credit.",
        ),
        CircuitConstraint::new(
            "merkle_consistency",
            "Merkle(balances_before, prev_timetoke_root) && Merkle(balances_after, next_timetoke_root)",
            "Binds the before/after witnesses to their respective commitments.",
        ),
    ]);

    let reputation_stage = CircuitStage::new(
        "reputation_update",
        CircuitStageKind::Base,
        ProofSystemKind::Stwo,
        "Aggregates timetoke rewards, consensus participation and penalties into updated reputation tiers.",
    )
    .with_witness_signals(vec![
        CircuitSignal::new(
            "reputation_before",
            DataType::Bytes,
            "Merkle authentication paths for the prior reputation records.",
        ),
        CircuitSignal::new(
            "reputation_after",
            DataType::Bytes,
            "Merkle authentication paths for the updated reputation records.",
        ),
        CircuitSignal::new(
            "timetoke_contribution",
            DataType::Uint64,
            "Effective hours credited from the timetoke module.",
        ),
        CircuitSignal::new(
            "consensus_contribution",
            DataType::Uint64,
            "Weighted consensus participation gathered from BFT votes.",
        ),
    ])
    .with_public_inputs(vec![
        CircuitBinding::new(
            "prev_reputation_root",
            Some(StateModule::Reputation),
            "Reputation commitment prior to applying this block.",
        ),
        CircuitBinding::new(
            "next_reputation_root",
            Some(StateModule::Reputation),
            "Reputation commitment after applying this block.",
        ),
        CircuitBinding::new(
            "timetoke_transition_commitment",
            Some(StateModule::Timetoke),
            "Link to the timetoke accrual digest consumed during reputation updates.",
        ),
    ])
    .with_public_outputs(vec![CircuitBinding::new(
        "reputation_transition_commitment",
        Some(StateModule::ProofRegistry),
        "Digest exported to the proof registry representing the reputation delta.",
    )])
    .with_constraints(vec![
        CircuitConstraint::new(
            "score_update",
            "score_after = score_before + timetoke_contribution + consensus_contribution - penalties",
            "Combines uptime, consensus and penalties into the updated reputation score.",
        ),
        CircuitConstraint::new(
            "tier_rules",
            "tier_after = tier(score_after)",
            "Checks that tier assignments follow the configured threshold map.",
        ),
        CircuitConstraint::new(
            "merkle_consistency",
            "Merkle(reputation_before, prev_reputation_root) && Merkle(reputation_after, next_reputation_root)",
            "Binds the witness records to the reputation commitments.",
        ),
    ])
    .with_dependencies(vec!["timetoke_accrual".into(), "consensus_attestation".into()]);

    let consensus_stage = CircuitStage::new(
        "consensus_attestation",
        CircuitStageKind::Base,
        ProofSystemKind::Stwo,
        "Validates Malachite BFT votes and quorum signatures for the proposed block.",
    )
    .with_witness_signals(vec![
        CircuitSignal::new(
            "vote_records",
            DataType::Bytes,
            "Serialized signatures and voting power assignments for the round.",
        ),
        CircuitSignal::new(
            "validator_set",
            DataType::Bytes,
            "Merkle authentication for the validator identities participating in the round.",
        ),
        CircuitSignal::new(
            "round_metadata",
            DataType::Bytes,
            "Round number, proposer identity and VRF output referenced by the block.",
        ),
    ])
    .with_public_inputs(vec![
        CircuitBinding::new(
            "prev_validator_commitment",
            Some(StateModule::GlobalAccounts),
            "Snapshot of the validator set commitment inherited from the previous block.",
        ),
        CircuitBinding::new(
            "block_header_hash",
            None,
            "Digest of the block header being voted on.",
        ),
    ])
    .with_public_outputs(vec![CircuitBinding::new(
        "consensus_commitment",
        Some(StateModule::ProofRegistry),
        "Digest exported to the proof registry capturing the BFT vote aggregation.",
    )])
    .with_constraints(vec![
        CircuitConstraint::new(
            "quorum_threshold",
            "sum(voting_power) >= 2/3 * total_power",
            "Checks that the accumulated voting power meets the required BFT quorum.",
        ),
        CircuitConstraint::new(
            "no_double_sign",
            "forall validator: unique(vote_signature)",
            "Prevents validators from contributing more than one vote per round.",
        ),
        CircuitConstraint::new(
            "signature_verification",
            "verify_signature(validator_pk, block_header_hash, vote_signature)",
            "Verifies each vote signature against the block header hash.",
        ),
    ]);

    let zsi_stage = CircuitStage::new(
        "zsi_onboarding",
        CircuitStageKind::Base,
        ProofSystemKind::Stwo,
        "Proves correct inclusion of newly approved zero-state identities.",
    )
    .with_witness_signals(vec![
        CircuitSignal::new(
            "zsi_records",
            DataType::Bytes,
            "New ZSI entries along with their attestation payloads.",
        ),
        CircuitSignal::new(
            "consensus_approvals",
            DataType::Bytes,
            "Validator approvals referenced during onboarding.",
        ),
        CircuitSignal::new(
            "registry_before",
            DataType::Bytes,
            "Authentication paths for the registry prior to insertion.",
        ),
        CircuitSignal::new(
            "registry_after",
            DataType::Bytes,
            "Authentication paths for the registry after insertion.",
        ),
    ])
    .with_public_inputs(vec![
        CircuitBinding::new(
            "prev_zsi_root",
            Some(StateModule::ZsiRegistry),
            "ZSI commitment before applying consensus-approved identities.",
        ),
        CircuitBinding::new(
            "next_zsi_root",
            Some(StateModule::ZsiRegistry),
            "ZSI commitment after applying consensus-approved identities.",
        ),
        CircuitBinding::new(
            "consensus_commitment",
            Some(StateModule::ProofRegistry),
            "BFT vote digest ensuring the onboarding references the verified approvals.",
        ),
    ])
    .with_public_outputs(vec![CircuitBinding::new(
        "zsi_transition_commitment",
        Some(StateModule::ProofRegistry),
        "Digest exported to the proof registry describing the ZSI onboarding delta.",
    )])
    .with_constraints(vec![
        CircuitConstraint::new(
            "uniqueness",
            "forall zsi: unique(identity)",
            "Ensures each onboarded identity appears only once in the batch.",
        ),
        CircuitConstraint::new(
            "approval_threshold",
            "approvals >= consensus_threshold",
            "Requires that each identity carries the minimum consensus approvals.",
        ),
        CircuitConstraint::new(
            "merkle_consistency",
            "Merkle(registry_before, prev_zsi_root) && Merkle(registry_after, next_zsi_root)",
            "Binds the registry witness to the before/after commitments.",
        ),
    ])
    .with_dependencies(vec!["consensus_attestation".into()]);

    let aggregation_stage = CircuitStage::new(
        "block_transition_aggregation",
        CircuitStageKind::Aggregation,
        ProofSystemKind::Stwo,
        "Aggregates all module digests, binds them to the block header and exposes the proof registry root.",
    )
    .with_witness_signals(vec![
        CircuitSignal::new(
            "module_commitments",
            DataType::Bytes,
            "Ordered list of digests emitted by each base circuit stage.",
        ),
        CircuitSignal::new(
            "witness_bundle_commitment",
            DataType::CommitmentDigest,
            "Commitment over the serialized module witness bundle attached to the block.",
        ),
        CircuitSignal::new(
            "previous_proof_commitment",
            DataType::CommitmentDigest,
            "Digest of the recursive proof from the previous block for folding.",
        ),
    ])
    .with_public_inputs(vec![
        CircuitBinding::new(
            "prev_global_root",
            Some(StateModule::GlobalAccounts),
            "Global commitment inherited from the previous block header.",
        ),
        CircuitBinding::new(
            "prev_utxo_root",
            Some(StateModule::Utxo),
            "UTXO commitment inherited from the previous block header.",
        ),
        CircuitBinding::new(
            "prev_reputation_root",
            Some(StateModule::Reputation),
            "Reputation commitment inherited from the previous block header.",
        ),
        CircuitBinding::new(
            "prev_timetoke_root",
            Some(StateModule::Timetoke),
            "Timetoke commitment inherited from the previous block header.",
        ),
        CircuitBinding::new(
            "prev_zsi_root",
            Some(StateModule::ZsiRegistry),
            "ZSI commitment inherited from the previous block header.",
        ),
        CircuitBinding::new(
            "next_global_root",
            Some(StateModule::GlobalAccounts),
            "Global commitment produced by the current block.",
        ),
        CircuitBinding::new(
            "next_utxo_root",
            Some(StateModule::Utxo),
            "UTXO commitment produced by the current block.",
        ),
        CircuitBinding::new(
            "next_reputation_root",
            Some(StateModule::Reputation),
            "Reputation commitment produced by the current block.",
        ),
        CircuitBinding::new(
            "next_timetoke_root",
            Some(StateModule::Timetoke),
            "Timetoke commitment produced by the current block.",
        ),
        CircuitBinding::new(
            "next_zsi_root",
            Some(StateModule::ZsiRegistry),
            "ZSI commitment produced by the current block.",
        ),
    ])
    .with_public_outputs(vec![
        CircuitBinding::new(
            "proof_registry_root",
            Some(StateModule::ProofRegistry),
            "Final proof registry commitment that must match the block header.",
        ),
        CircuitBinding::new(
            "module_witness_commitment",
            Some(StateModule::ProofRegistry),
            "Commitment to the module witness bundle shipped alongside the block.",
        ),
    ])
    .with_constraints(vec![
        CircuitConstraint::new(
            "module_binding",
            "module_commitments fold to proof_registry_root",
            "Ensures the ordered module digests produce the proof registry commitment included in the header.",
        ),
        CircuitConstraint::new(
            "witness_integrity",
            "hash(module_witness_bundle) = module_witness_commitment",
            "Guarantees that the bundled witnesses correspond to the aggregated digest.",
        ),
        CircuitConstraint::new(
            "state_progression",
            "prev_roots + module_transitions -> next_roots",
            "Checks that the advertised previous commitments combined with the module deltas yield the new commitments.",
        ),
    ])
    .with_dependencies(vec![
        "global_state_transition".into(),
        "utxo_transition".into(),
        "timetoke_accrual".into(),
        "reputation_update".into(),
        "zsi_onboarding".into(),
        "consensus_attestation".into(),
    ]);

    let recursion_stage = CircuitStage::new(
        "recursive_wrapper",
        CircuitStageKind::Recursion,
        ProofSystemKind::Plonky2,
        "Wraps the STWO block proof and the previous recursive accumulator into a succinct proof chain.",
    )
    .with_witness_signals(vec![
        CircuitSignal::new(
            "previous_recursive_commitment",
            DataType::CommitmentDigest,
            "Commitment to the prior recursive accumulator.",
        ),
        CircuitSignal::new(
            "current_block_commitment",
            DataType::CommitmentDigest,
            "Commitment emitted by the block aggregation circuit for this block.",
        ),
        CircuitSignal::new(
            "proof_accumulator",
            DataType::Bytes,
            "Plonky2 transcript folding both commitments.",
        ),
    ])
    .with_public_inputs(vec![
        CircuitBinding::new(
            "block_header_hash",
            None,
            "Hash of the block header to which the recursive proof is bound.",
        ),
        CircuitBinding::new(
            "proof_registry_root",
            Some(StateModule::ProofRegistry),
            "Proof registry root emitted by the aggregation circuit.",
        ),
        CircuitBinding::new(
            "previous_recursive_commitment",
            Some(StateModule::ProofRegistry),
            "Accumulator commitment from the previous block's recursive proof.",
        ),
    ])
    .with_public_outputs(vec![CircuitBinding::new(
        "recursive_commitment",
        Some(StateModule::ProofRegistry),
        "Updated recursive accumulator to be stored in the proof registry.",
    )])
    .with_constraints(vec![
        CircuitConstraint::new(
            "link_previous",
            "hash(previous_recursive_commitment, current_block_commitment) = recursive_commitment",
            "Chains the previous accumulator with the new block commitment.",
        ),
        CircuitConstraint::new(
            "bind_block_hash",
            "public block_header_hash included in transcript",
            "Binds the recursive proof to the exact block header witnessed on-chain.",
        ),
        CircuitConstraint::new(
            "transcript_soundness",
            "Fiat-Shamir(proof_accumulator) sound",
            "Ensures the recursive transcript satisfies the Plonky2 soundness conditions.",
        ),
    ])
    .with_dependencies(vec!["block_transition_aggregation".into()]);

    CircuitBlueprint {
        stages: vec![
            global_state_stage,
            utxo_stage,
            timetoke_stage,
            reputation_stage,
            consensus_stage,
            zsi_stage,
            aggregation_stage,
            recursion_stage,
        ],
    }
}

pub fn default_blueprint() -> ArchitectureBlueprint {
    let header_layout = HeaderLayout {
        aggregation: HeaderAggregation::Blake2sBinary,
        module_order: vec![
            StateModule::GlobalAccounts,
            StateModule::Utxo,
            StateModule::Reputation,
            StateModule::Timetoke,
            StateModule::ZsiRegistry,
            StateModule::ProofRegistry,
        ],
    };

    let modules = vec![
        ModuleBlueprint {
            module: StateModule::GlobalAccounts,
            commitment: CommitmentDescriptor::merkle_poseidon(
                32,
                "Account-level commitment containing balances, stake and bindings.",
            ),
            record_schema: Schema {
                name: "Account".into(),
                description: "Meta account record stored in the global state tree".into(),
                fields: vec![
                    FieldDescriptor {
                        name: "address".into(),
                        data_type: DataType::Address,
                        description: "Unique account address".into(),
                    },
                    FieldDescriptor {
                        name: "balance".into(),
                        data_type: DataType::Uint128,
                        description: "Spendable balance of the account".into(),
                    },
                    FieldDescriptor {
                        name: "stake".into(),
                        data_type: DataType::Uint128,
                        description: "Amount locked for validator participation".into(),
                    },
                    FieldDescriptor {
                        name: "reputation".into(),
                        data_type: DataType::CommitmentDigest,
                        description: "Link to the reputation sub-tree".into(),
                    },
                ],
            },
            witness_encoding: WitnessEncoding::BinaryMerklePath,
            proof_system: ProofSystemKind::Stwo,
        },
        ModuleBlueprint {
            module: StateModule::Utxo,
            commitment: CommitmentDescriptor::merkle_poseidon(
                48,
                "Binary Merkle tree over UTXO commitments.",
            ),
            record_schema: Schema {
                name: "UTXO".into(),
                description: "Unspent transaction output".into(),
                fields: vec![
                    FieldDescriptor {
                        name: "outpoint".into(),
                        data_type: DataType::CommitmentDigest,
                        description: "Hash of transaction id and output index".into(),
                    },
                    FieldDescriptor {
                        name: "owner".into(),
                        data_type: DataType::Address,
                        description: "Address controlling the output".into(),
                    },
                    FieldDescriptor {
                        name: "value".into(),
                        data_type: DataType::Uint128,
                        description: "Value denominated in smallest unit".into(),
                    },
                    FieldDescriptor {
                        name: "script_hash".into(),
                        data_type: DataType::Hash32,
                        description: "Commitment to the spending predicate".into(),
                    },
                ],
            },
            witness_encoding: WitnessEncoding::BinaryMerklePath,
            proof_system: ProofSystemKind::Stwo,
        },
        ModuleBlueprint {
            module: StateModule::Reputation,
            commitment: CommitmentDescriptor::merkle_poseidon(
                40,
                "Merkle tree over validator reputation snapshots.",
            ),
            record_schema: Schema {
                name: "Reputation".into(),
                description: "Validator reputation state".into(),
                fields: vec![
                    FieldDescriptor {
                        name: "identity".into(),
                        data_type: DataType::Address,
                        description: "Validator identity address".into(),
                    },
                    FieldDescriptor {
                        name: "score".into(),
                        data_type: DataType::Float64,
                        description: "Aggregated reputation score".into(),
                    },
                    FieldDescriptor {
                        name: "tier".into(),
                        data_type: DataType::Tier,
                        description: "Tier classification derived from score".into(),
                    },
                    FieldDescriptor {
                        name: "uptime_hours".into(),
                        data_type: DataType::Uint64,
                        description: "Cumulative uptime proven by timetoke proofs".into(),
                    },
                ],
            },
            witness_encoding: WitnessEncoding::BinaryMerklePath,
            proof_system: ProofSystemKind::Stwo,
        },
        ModuleBlueprint {
            module: StateModule::Timetoke,
            commitment: CommitmentDescriptor::merkle_poseidon(
                32,
                "Merkle tree storing timetoke balances and metadata.",
            ),
            record_schema: Schema {
                name: "Timetoke".into(),
                description: "Epoch-based uptime accounting".into(),
                fields: vec![
                    FieldDescriptor {
                        name: "identity".into(),
                        data_type: DataType::Address,
                        description: "Validator identity tracked for timetoke accrual".into(),
                    },
                    FieldDescriptor {
                        name: "balance".into(),
                        data_type: DataType::Uint128,
                        description: "Timetoke balance available for spending".into(),
                    },
                    FieldDescriptor {
                        name: "last_update".into(),
                        data_type: DataType::Timestamp,
                        description: "Last epoch timestamp applied to the record".into(),
                    },
                ],
            },
            witness_encoding: WitnessEncoding::BinaryMerklePath,
            proof_system: ProofSystemKind::Stwo,
        },
        ModuleBlueprint {
            module: StateModule::ZsiRegistry,
            commitment: CommitmentDescriptor::verkle_poseidon(
                "Verkle tree capturing zero-state identity commitments.",
            ),
            record_schema: Schema {
                name: "ZSI".into(),
                description: "Zero-state identity registry".into(),
                fields: vec![
                    FieldDescriptor {
                        name: "identity".into(),
                        data_type: DataType::Address,
                        description: "Registered identity address".into(),
                    },
                    FieldDescriptor {
                        name: "genesis_id".into(),
                        data_type: DataType::Bytes,
                        description: "Genesis identifier assigned by consensus".into(),
                    },
                    FieldDescriptor {
                        name: "attestation_digest".into(),
                        data_type: DataType::CommitmentDigest,
                        description: "Commitment to ZSI attestation".into(),
                    },
                ],
            },
            witness_encoding: WitnessEncoding::VerkleProof,
            proof_system: ProofSystemKind::Stwo,
        },
        ModuleBlueprint {
            module: StateModule::ProofRegistry,
            commitment: CommitmentDescriptor {
                scheme: CommitmentScheme::Merkle,
                hash: HashFunction::Blake2s,
                arity: 2,
                depth: 16,
                description: "Merkle commitment over block-local proof artifacts.".into(),
            },
            record_schema: Schema {
                name: "ProofArtifact".into(),
                description: "Recursive proof fragments referenced by the block".into(),
                fields: vec![
                    FieldDescriptor {
                        name: "module".into(),
                        data_type: DataType::Bytes,
                        description: "Identifier of the originating module".into(),
                    },
                    FieldDescriptor {
                        name: "commitment".into(),
                        data_type: DataType::CommitmentDigest,
                        description: "Commitment digest attested by the proof".into(),
                    },
                    FieldDescriptor {
                        name: "proof".into(),
                        data_type: DataType::Bytes,
                        description: "Serialized proof blob".into(),
                    },
                ],
            },
            witness_encoding: WitnessEncoding::RecursiveTranscript,
            proof_system: ProofSystemKind::Plonky2,
        },
    ];

    let public_inputs = vec![
        RecursionInput {
            module: StateModule::GlobalAccounts,
            description: "Previous global account root".into(),
        },
        RecursionInput {
            module: StateModule::ProofRegistry,
            description: "Recursive proof commitment from prior block".into(),
        },
    ];

    ArchitectureBlueprint {
        header_layout,
        modules,
        proof_system: ProofSystemDescriptor {
            base_layer: ProofSystemKind::Stwo,
            recursion_layer: ProofSystemKind::Plonky2,
            public_inputs,
        },
        circuits: default_circuit_blueprint(),
    }
}

/// Build a lookup table for schemas keyed by state module.
pub fn schema_lookup(blueprint: &ArchitectureBlueprint) -> BTreeMap<StateModule, &Schema> {
    blueprint
        .modules
        .iter()
        .map(|module| (module.module, &module.record_schema))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::pruning_genesis;
    use std::collections::BTreeSet;

    fn sample_witness_bundle() -> ModuleWitnessBundle {
        fn digest(byte: u8) -> CommitmentDigest {
            [byte; 32]
        }

        let mut bundle = ModuleWitnessBundle::default();
        let sender_before = AccountBalanceWitness::new("alice".into(), 1_000, 1);
        let sender_after = AccountBalanceWitness::new("alice".into(), 900, 2);
        let recipient_before = AccountBalanceWitness::new("bob".into(), 500, 0);
        let recipient_after = AccountBalanceWitness::new("bob".into(), 600, 0);
        let tx_witness = TransactionWitness::new(
            digest(0xA1),
            10,
            sender_before,
            sender_after,
            Some(recipient_before),
            recipient_after,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        bundle.record_transaction(tx_witness.clone());

        let block_witness = BlockWitnessBuilder::new()
            .with_expected_path_depth(0)
            .with_transactions(vec![tx_witness])
            .with_transaction_paths(vec![
                MerklePathWitness::new(0, Vec::new()).expect("merkle path builds")
            ])
            .with_pruning_proofs(vec![pruning_genesis(&"00".repeat(32))])
            .build()
            .expect("block witness");
        bundle.record_block(block_witness);

        let previous_timetoke = TimetokeRecord {
            identity: "alice".into(),
            balance: 10,
            epoch_accrual: 1,
            decay_rate: 0.0,
            last_update: 100,
            last_sync: 80,
            last_decay: 90,
        };
        let updated_timetoke = TimetokeRecord {
            identity: "alice".into(),
            balance: 12,
            epoch_accrual: 3,
            decay_rate: 0.0,
            last_update: 200,
            last_sync: 180,
            last_decay: 190,
        };
        bundle.record_timetoke(TimetokeWitness::new(
            "alice".into(),
            Some(previous_timetoke),
            updated_timetoke,
            0,
            3_600,
            2,
        ));

        let previous_reputation = ReputationRecord {
            identity: "alice".into(),
            score: 1.0,
            tier: TierDescriptor::Candidate,
            uptime_hours: 1,
            consensus_success: 1,
            peer_feedback: 0,
            zsi_validated: true,
        };
        let updated_reputation = ReputationRecord {
            identity: "alice".into(),
            score: 2.5,
            tier: TierDescriptor::Validator,
            uptime_hours: 3,
            consensus_success: 2,
            peer_feedback: 1,
            zsi_validated: true,
        };
        bundle.record_reputation(ReputationWitness::new(
            "alice".into(),
            ReputationEventKind::ConsensusReward,
            Some(previous_reputation),
            updated_reputation,
        ));

        let zsi_updated = ZsiRecord {
            identity: "alice".into(),
            genesis_id: "genesis".into(),
            attestation_digest: digest(0xB1),
            approvals: vec![ConsensusApproval {
                validator: "bob".into(),
                signature: vec![0xCA, 0xFE],
                timestamp: 42,
            }],
        };
        bundle.record_zsi(ZsiWitness::new("alice".into(), None, zsi_updated));

        let vrf_entry = ConsensusVrfEntry::default();
        let bindings = ConsensusWitnessBindings {
            vrf_output: "11".repeat(32),
            vrf_proof: "22".repeat(32),
            witness_commitment: "33".repeat(32),
            reputation_root: "44".repeat(32),
            quorum_bitmap: "55".repeat(32),
            quorum_signature: "66".repeat(32),
        };
        bundle.record_consensus(ConsensusWitness::new(
            42,
            3,
            vec!["alice".into(), "bob".into()],
            vec![vrf_entry],
            vec!["aa".repeat(32)],
            vec!["bb".repeat(32)],
            vec!["cc".repeat(32)],
            vec!["dd".repeat(32)],
            7,
            9,
            "dd".repeat(32),
            "ee".repeat(32),
            bindings,
        ));

        bundle
    }

    #[test]
    fn aggregates_commitments_in_order() {
        let layout = HeaderLayout {
            aggregation: HeaderAggregation::Blake2sBinary,
            module_order: vec![
                StateModule::GlobalAccounts,
                StateModule::Utxo,
                StateModule::ProofRegistry,
            ],
        };

        let mut commitments = GlobalStateCommitments::default();
        commitments.global_state_root = [1u8; 32];
        commitments.utxo_root = [2u8; 32];
        commitments.proof_root = [3u8; 32];

        let digest = layout.aggregate(&commitments);

        // Ensure deterministic non-zero digest.
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn blueprint_contains_all_modules() {
        let blueprint = default_blueprint();
        assert_eq!(blueprint.modules.len(), 6);
        let schema_map = schema_lookup(&blueprint);
        assert!(schema_map.contains_key(&StateModule::Timetoke));
        assert!(schema_map.contains_key(&StateModule::ProofRegistry));
        assert_eq!(blueprint.circuits.stages.len(), 8);
    }

    #[test]
    fn circuit_blueprint_has_recursion_stage() {
        let blueprint = default_blueprint();
        let recursion = blueprint
            .circuits
            .stage("recursive_wrapper")
            .expect("recursive stage present");
        assert_eq!(recursion.kind, CircuitStageKind::Recursion);
        assert_eq!(recursion.proof_system, ProofSystemKind::Plonky2);
    }

    #[test]
    fn module_witness_bundle_emits_commitments_for_all_modules() {
        let bundle = sample_witness_bundle();
        let artifacts = bundle.expected_artifacts().expect("witness artifacts");
        assert_eq!(artifacts.len(), 6);

        let modules = artifacts
            .iter()
            .map(|(module, _, _)| *module)
            .collect::<BTreeSet<_>>();
        let expected = vec![
            ProofModule::UtxoWitness,
            ProofModule::TimetokeWitness,
            ProofModule::ReputationWitness,
            ProofModule::ZsiWitness,
            ProofModule::BlockWitness,
            ProofModule::ConsensusWitness,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(modules, expected);

        let consensus_artifact = artifacts
            .iter()
            .find(|(module, _, _)| *module == ProofModule::ConsensusWitness)
            .expect("consensus witness artifact");
        let consensus_commitment = bundle
            .namespaced_commitment(
                b"rpp-consensus-witness",
                &bundle.consensus,
                CIRCUIT_CONSENSUS,
            )
            .expect("consensus commitment");
        assert_eq!(consensus_artifact.1, consensus_commitment);

        let block_artifact = artifacts
            .iter()
            .find(|(module, _, _)| *module == ProofModule::BlockWitness)
            .expect("block witness artifact");
        let block_commitment = bundle
            .namespaced_commitment(
                b"rpp-block-witness",
                &[bundle.block.clone().expect("block witness")],
                CIRCUIT_BLOCK,
            )
            .expect("block commitment");
        assert_eq!(block_artifact.1, block_commitment);
    }

    #[test]
    fn block_witness_builder_rejects_missing_paths() {
        let witness = TransactionWitness::new(
            [0xAA; 32],
            0,
            AccountBalanceWitness::new("alice".into(), 1, 0),
            AccountBalanceWitness::new("alice".into(), 1, 1),
            None,
            AccountBalanceWitness::new("bob".into(), 1, 0),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let result = BlockWitnessBuilder::new()
            .with_expected_path_depth(0)
            .with_transactions(vec![witness])
            .with_transaction_paths(Vec::new())
            .with_pruning_proofs(Vec::new())
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn block_witness_builder_checks_depth() {
        let witness = TransactionWitness::new(
            [0xAB; 32],
            0,
            AccountBalanceWitness::new("alice".into(), 1, 0),
            AccountBalanceWitness::new("alice".into(), 1, 1),
            None,
            AccountBalanceWitness::new("bob".into(), 1, 0),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let result = BlockWitnessBuilder::new()
            .with_expected_path_depth(2)
            .with_transactions(vec![witness])
            .with_transaction_paths(vec![
                MerklePathWitness::new(1, vec![[0u8; 32]]).expect("path is valid")
            ])
            .with_pruning_proofs(Vec::new())
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn block_witness_builder_supports_minimal_witness() {
        let witness = TransactionWitness::new(
            [0xAC; 32],
            0,
            AccountBalanceWitness::new("alice".into(), 1, 0),
            AccountBalanceWitness::new("alice".into(), 1, 1),
            None,
            AccountBalanceWitness::new("bob".into(), 1, 0),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let block_witness = BlockWitnessBuilder::new()
            .with_expected_path_depth(0)
            .with_transactions(vec![witness.clone()])
            .with_transaction_paths(vec![
                MerklePathWitness::new(0, Vec::new()).expect("empty path allowed")
            ])
            .with_pruning_proofs(vec![pruning_genesis(&"00".repeat(32))])
            .build()
            .expect("block witness builds");

        assert_eq!(block_witness.transactions, vec![witness]);
    }
}
