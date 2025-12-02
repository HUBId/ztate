//! Shared prover backend interface consumed across the workspace.
//!
//! # Toolchain and feature flags
//! * The STWO backend currently requires a nightly toolchain because the
//!   upstream fork ships nightly-only dependencies. The workspace pins an
//!   appropriate toolchain via `rust-toolchain.toml` so downstream crates simply
//!   inherit it.
//! * `prover-stwo` exposes the STWO backend types. This flag should be enabled
//!   by consumers that intend to prove or verify real STWO circuits.
//! * `prover-stwo-simd` forwards to the STWO `parallel` feature and enables the
//!   accelerator-friendly SIMD pathway. Downstream crates can opt into this flag
//!   when the target platform provides the required intrinsics.
//! * `prover-mock` exposes the lightweight mock backend for deterministic tests
//!   that do not need STARKs.
//!
//! Consumers opt in or out exclusively through Cargo features; no sample code is
//! required to change the active backend. The interface enumerates the circuits
//! supported by the STWO wallet prover so downstream components can request keys
//! and proofs for identity, state transition, pruning, recursive aggregation,
//! uptime, consensus, and transaction checks.
pub mod audit;
pub mod crash_reports;
pub mod determinism;
pub mod folding;

use std::fmt;

pub mod blake2s {
    use blake2::{Blake2s256, Digest};

    /// Simple Blake2s hasher mirroring the upstream STWO API.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct Blake2sHasher;

    /// Wrapper returned by [`Blake2sHasher::hash`] to ease conversions.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Blake2sHash(pub [u8; 32]);

    impl Blake2sHasher {
        /// Hash an arbitrary byte slice using Blake2s-256.
        pub fn hash(input: &[u8]) -> Blake2sHash {
            Blake2sHash(Blake2s256::digest(input).into())
        }
    }

    impl From<Blake2sHash> for [u8; 32] {
        fn from(value: Blake2sHash) -> Self {
            value.0
        }
    }
}

pub use blake2s::{Blake2sHash, Blake2sHasher};

use bincode::Options;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_little_endian()
}

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("backend functionality not implemented: {0}")]
    Unsupported(&'static str),
    #[error("backend failure: {0}")]
    Failure(String),
}

pub type BackendResult<T> = Result<T, BackendError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessHeader {
    pub version: u16,
    pub backend: ProofSystemKind,
    pub circuit: String,
}

impl WitnessHeader {
    pub fn new(backend: ProofSystemKind, circuit: impl Into<String>) -> Self {
        Self {
            version: WITNESS_FORMAT_VERSION,
            backend,
            circuit: circuit.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofHeader {
    pub version: u16,
    pub backend: ProofSystemKind,
    pub circuit: String,
}

impl ProofHeader {
    pub fn new(backend: ProofSystemKind, circuit: impl Into<String>) -> Self {
        Self {
            version: PROOF_FORMAT_VERSION,
            backend,
            circuit: circuit.into(),
        }
    }
}

pub const WITNESS_FORMAT_VERSION: u16 = 1;
pub const PROOF_FORMAT_VERSION: u16 = 1;

#[derive(Serialize)]
struct WitnessEnvelope<'a, T> {
    header: &'a WitnessHeader,
    #[serde(borrow)]
    payload: &'a T,
}

#[derive(Deserialize)]
struct WitnessEnvelopeOwned<T> {
    header: WitnessHeader,
    payload: T,
}

#[derive(Serialize)]
struct ProofEnvelope<'a, T> {
    header: &'a ProofHeader,
    #[serde(borrow)]
    payload: &'a T,
}

#[derive(Deserialize)]
struct ProofEnvelopeOwned<T> {
    header: ProofHeader,
    payload: T,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessBytes(pub Vec<u8>);

impl fmt::Debug for WitnessBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WitnessBytes(len={})", self.0.len())
    }
}

impl WitnessBytes {
    pub fn encode<T: Serialize>(header: &WitnessHeader, payload: &T) -> BackendResult<Self> {
        let envelope = WitnessEnvelope { header, payload };
        let bytes = canonical_options()
            .serialize(&envelope)
            .map_err(BackendError::from)?;
        Ok(Self(bytes))
    }

    pub fn decode<T: DeserializeOwned>(&self) -> BackendResult<(WitnessHeader, T)> {
        let envelope: WitnessEnvelopeOwned<T> = canonical_options()
            .deserialize(&self.0)
            .map_err(BackendError::from)?;
        Ok((envelope.header, envelope.payload))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for WitnessBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBytes(pub Vec<u8>);

impl fmt::Debug for ProofBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProofBytes(len={})", self.0.len())
    }
}

impl ProofBytes {
    pub fn encode<T: Serialize>(header: &ProofHeader, payload: &T) -> BackendResult<Self> {
        let envelope = ProofEnvelope { header, payload };
        let bytes = canonical_options()
            .serialize(&envelope)
            .map_err(BackendError::from)?;
        Ok(Self(bytes))
    }

    pub fn decode<T: DeserializeOwned>(&self) -> BackendResult<(ProofHeader, T)> {
        let envelope: ProofEnvelopeOwned<T> = canonical_options()
            .deserialize(&self.0)
            .map_err(BackendError::from)?;
        Ok((envelope.header, envelope.payload))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for ProofBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityLevel {
    Standard128,
    Elevated192,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::Standard128
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxCircuitDef {
    pub identifier: String,
}

impl TxCircuitDef {
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusCircuitDef {
    pub identifier: String,
}

impl ConsensusCircuitDef {
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxPublicInputs {
    pub utxo_root: [u8; 32],
    pub transaction_commitment: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityCircuitDef {
    pub identifier: String,
}

impl IdentityCircuitDef {
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateCircuitDef {
    pub identifier: String,
}

impl StateCircuitDef {
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PruningCircuitDef {
    pub identifier: String,
}

impl PruningCircuitDef {
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecursiveCircuitDef {
    pub identifier: String,
}

impl RecursiveCircuitDef {
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UptimeCircuitDef {
    pub identifier: String,
}

impl UptimeCircuitDef {
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityPublicInputs {
    pub wallet_address: [u8; 32],
    pub vrf_tag: Vec<u8>,
    pub identity_root: [u8; 32],
    pub state_root: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatePublicInputs {
    pub previous_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    pub transaction_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PruningPublicInputs {
    pub previous_tx_root: [u8; 32],
    pub pruned_tx_root: [u8; 32],
    pub removed_transactions: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecursivePublicInputs {
    pub previous_commitment: Option<[u8; 32]>,
    pub aggregated_commitment: [u8; 32],
    pub transaction_commitments: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UptimePublicInputs {
    pub wallet_address: [u8; 32],
    pub node_clock: u64,
    pub epoch: u64,
    pub head_hash: [u8; 32],
    pub window_start: u64,
    pub window_end: u64,
    pub commitment: [u8; 32],
}

/// Public VRF material included in consensus proofs.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusVrfPublicEntry {
    /// Poseidon randomness emitted by the VRF evaluation.
    pub randomness: [u8; 32],
    /// Randomness independently re-derived from the VRF proof.
    #[serde(default)]
    pub derived_randomness: [u8; 32],
    /// Poseidon pre-output associated with the randomness.
    pub pre_output: [u8; 32],
    /// Raw VRF proof bytes attesting to the output.
    pub proof: Vec<u8>,
    /// Validator VRF public key used to produce the proof.
    pub public_key: [u8; 32],
    /// Poseidon digest derived from the VRF input tuple.
    pub poseidon_digest: [u8; 32],
    /// Last block header hash folded into the Poseidon transcript.
    pub poseidon_last_block_header: [u8; 32],
    /// Epoch identifier included in the Poseidon sponge.
    pub poseidon_epoch: u64,
    /// Tier seed binding the validator selection round.
    pub poseidon_tier_seed: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusPublicInputs {
    pub block_hash: [u8; 32],
    pub round: u64,
    pub leader_proposal: [u8; 32],
    pub epoch: u64,
    pub slot: u64,
    pub quorum_threshold: u64,
    pub quorum_bitmap_root: [u8; 32],
    pub quorum_signature_root: [u8; 32],
    pub vrf_entries: Vec<ConsensusVrfPublicEntry>,
    pub witness_commitments: Vec<[u8; 32]>,
    pub reputation_roots: Vec<[u8; 32]>,
    pub vrf_output_binding: [u8; 32],
    pub vrf_proof_binding: [u8; 32],
    pub witness_commitment_binding: [u8; 32],
    pub reputation_root_binding: [u8; 32],
    pub quorum_bitmap_binding: [u8; 32],
    pub quorum_signature_binding: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvingKey(pub Vec<u8>);

impl fmt::Debug for ProvingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProvingKey(len={})", self.0.len())
    }
}

impl ProvingKey {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyingKey(pub Vec<u8>);

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey(len={})", self.0.len())
    }
}

impl VerifyingKey {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofSystemKind {
    Stwo,
    Mock,
    Plonky3,
    Plonky2,
    Halo2,
    RppStark,
}

pub trait ProofBackend: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    fn setup_params(&self, _security: SecurityLevel) -> BackendResult<()> {
        Ok(())
    }

    fn keygen_tx(&self, _circuit: &TxCircuitDef) -> BackendResult<(ProvingKey, VerifyingKey)> {
        Err(BackendError::Unsupported("transaction keygen"))
    }

    fn prove_tx(&self, _pk: &ProvingKey, _witness: &WitnessBytes) -> BackendResult<ProofBytes> {
        Err(BackendError::Unsupported("transaction proving"))
    }

    fn verify_tx(
        &self,
        _vk: &VerifyingKey,
        _proof: &ProofBytes,
        _public_inputs: &TxPublicInputs,
    ) -> BackendResult<bool> {
        Err(BackendError::Unsupported("transaction verification"))
    }

    fn keygen_identity(
        &self,
        _circuit: &IdentityCircuitDef,
    ) -> BackendResult<(ProvingKey, VerifyingKey)> {
        Err(BackendError::Unsupported("identity keygen"))
    }

    fn prove_identity(
        &self,
        _pk: &ProvingKey,
        _witness: &WitnessBytes,
    ) -> BackendResult<ProofBytes> {
        Err(BackendError::Unsupported("identity proving"))
    }

    fn verify_identity(
        &self,
        _vk: &VerifyingKey,
        _proof: &ProofBytes,
        _public_inputs: &IdentityPublicInputs,
    ) -> BackendResult<()> {
        Err(BackendError::Unsupported("identity verification"))
    }

    fn keygen_state(
        &self,
        _circuit: &StateCircuitDef,
    ) -> BackendResult<(ProvingKey, VerifyingKey)> {
        Err(BackendError::Unsupported("state keygen"))
    }

    fn prove_state(&self, _pk: &ProvingKey, _witness: &WitnessBytes) -> BackendResult<ProofBytes> {
        Err(BackendError::Unsupported("state proving"))
    }

    fn verify_state(
        &self,
        _vk: &VerifyingKey,
        _proof: &ProofBytes,
        _public_inputs: &StatePublicInputs,
    ) -> BackendResult<()> {
        Err(BackendError::Unsupported("state verification"))
    }

    fn keygen_pruning(
        &self,
        _circuit: &PruningCircuitDef,
    ) -> BackendResult<(ProvingKey, VerifyingKey)> {
        Err(BackendError::Unsupported("pruning keygen"))
    }

    fn prove_pruning(
        &self,
        _pk: &ProvingKey,
        _witness: &WitnessBytes,
    ) -> BackendResult<ProofBytes> {
        Err(BackendError::Unsupported("pruning proving"))
    }

    fn verify_pruning(
        &self,
        _vk: &VerifyingKey,
        _proof: &ProofBytes,
        _public_inputs: &PruningPublicInputs,
    ) -> BackendResult<()> {
        Err(BackendError::Unsupported("pruning verification"))
    }

    fn keygen_recursive(
        &self,
        _circuit: &RecursiveCircuitDef,
    ) -> BackendResult<(ProvingKey, VerifyingKey)> {
        Err(BackendError::Unsupported("recursive keygen"))
    }

    fn prove_recursive(
        &self,
        _pk: &ProvingKey,
        _witness: &WitnessBytes,
    ) -> BackendResult<ProofBytes> {
        Err(BackendError::Unsupported("recursive proving"))
    }

    fn verify_recursive(
        &self,
        _vk: &VerifyingKey,
        _proof: &ProofBytes,
        _public_inputs: &RecursivePublicInputs,
    ) -> BackendResult<()> {
        Err(BackendError::Unsupported("recursive verification"))
    }

    fn keygen_uptime(
        &self,
        _circuit: &UptimeCircuitDef,
    ) -> BackendResult<(ProvingKey, VerifyingKey)> {
        Err(BackendError::Unsupported("uptime keygen"))
    }

    fn prove_uptime(&self, _pk: &ProvingKey, _witness: &WitnessBytes) -> BackendResult<ProofBytes> {
        Err(BackendError::Unsupported("uptime proving"))
    }

    fn verify_uptime(
        &self,
        _vk: &VerifyingKey,
        _proof: &ProofBytes,
        _public_inputs: &UptimePublicInputs,
    ) -> BackendResult<()> {
        Err(BackendError::Unsupported("uptime verification"))
    }

    fn prove_consensus(
        &self,
        _witness: &WitnessBytes,
    ) -> BackendResult<(ProofBytes, VerifyingKey, ConsensusCircuitDef)> {
        Err(BackendError::Unsupported("consensus proving"))
    }

    fn verify_consensus(
        &self,
        _vk: &VerifyingKey,
        _proof: &ProofBytes,
        _circuit: &ConsensusCircuitDef,
        _public_inputs: &ConsensusPublicInputs,
    ) -> BackendResult<()> {
        Err(BackendError::Unsupported("consensus verification"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct DummyWitness {
        sender: [u8; 32],
        receiver: [u8; 32],
        amount: u64,
    }

    fn sample_witness() -> DummyWitness {
        DummyWitness {
            sender: [0x11; 32],
            receiver: [0x22; 32],
            amount: 42,
        }
    }

    #[test]
    fn witness_roundtrip_is_stable() {
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "tx");
        let bytes = WitnessBytes::encode(&header, &sample_witness()).expect("encode witness");
        let (decoded_header, decoded) = bytes.decode::<DummyWitness>().expect("decode witness");
        assert_eq!(decoded_header, header);
        assert_eq!(decoded, sample_witness());
    }

    #[test]
    fn witness_encoding_matches_known_vector() {
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "tx");
        let bytes = WitnessBytes::encode(&header, &sample_witness()).expect("encode witness");
        let encoded = hex::encode(bytes.as_slice());
        assert_eq!(encoded.len(), 176);
        let digest = blake3::hash(bytes.as_slice());
        assert_eq!(
            digest.to_hex().as_str(),
            "87c8c6dfb9cd52ee3366a907bedd206254efb8b75397ee3b0761c6e258f96bde"
        );
    }
}
