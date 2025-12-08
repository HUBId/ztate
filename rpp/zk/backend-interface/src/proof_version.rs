use serde::{Deserialize, Serialize};

/// Version tag for folding and recursive proofs shared by prover and verifier.
///
/// * `AggregatedV1` reflects the existing aggregated proof envelope.
/// * `NovaV2` enables the Nova-backed folding pipeline.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofVersion {
    AggregatedV1,
    NovaV2,
}

/// Block height at which Nova V2 proofs become mandatory.
pub const NOVA_V2_MANDATORY_HEIGHT: u64 = 1_500_000;

/// Epoch at which Nova V2 proofs become mandatory.
pub const NOVA_V2_MANDATORY_EPOCH: u64 = 300;

impl ProofVersion {
    /// Return the proof version required for a given height/epoch pair.
    ///
    /// If the block predates the Nova V2 cutover, the aggregated pathway
    /// remains valid as a compatibility fallback.
    pub fn for_height_and_epoch(height: Option<u64>, epoch: Option<u64>) -> Self {
        if height.map_or(false, |h| h >= NOVA_V2_MANDATORY_HEIGHT)
            || epoch.map_or(false, |e| e >= NOVA_V2_MANDATORY_EPOCH)
        {
            ProofVersion::NovaV2
        } else {
            ProofVersion::AggregatedV1
        }
    }
}
