use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

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

static CUTOVER_HEIGHT: AtomicU64 = AtomicU64::new(NOVA_V2_MANDATORY_HEIGHT);
static CUTOVER_EPOCH: AtomicU64 = AtomicU64::new(NOVA_V2_MANDATORY_EPOCH);

impl ProofVersion {
    /// Return the proof version required for a given height/epoch pair.
    ///
    /// If the block predates the Nova V2 cutover, the aggregated pathway
    /// remains valid as a compatibility fallback.
    pub fn for_height_and_epoch(height: Option<u64>, epoch: Option<u64>) -> Self {
        let cutover_height = CUTOVER_HEIGHT.load(Ordering::Relaxed);
        let cutover_epoch = CUTOVER_EPOCH.load(Ordering::Relaxed);

        if height.map_or(false, |h| h >= cutover_height)
            || epoch.map_or(false, |e| e >= cutover_epoch)
        {
            ProofVersion::NovaV2
        } else {
            ProofVersion::AggregatedV1
        }
    }

    /// Override the Nova V2 cutover thresholds used by
    /// [`ProofVersion::for_height_and_epoch`].
    pub fn configure_cutover(height: u64, epoch: u64) {
        CUTOVER_HEIGHT.store(height, Ordering::Relaxed);
        CUTOVER_EPOCH.store(epoch, Ordering::Relaxed);
    }

    /// Return the currently configured cutover values for observability or
    /// testing.
    pub fn current_cutover() -> (u64, u64) {
        (
            CUTOVER_HEIGHT.load(Ordering::Relaxed),
            CUTOVER_EPOCH.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cutover_configuration_overrides_defaults() {
        struct ResetCutover(u64, u64);
        impl Drop for ResetCutover {
            fn drop(&mut self) {
                ProofVersion::configure_cutover(self.0, self.1);
            }
        }

        let original = ProofVersion::current_cutover();
        let _guard = ResetCutover(original.0, original.1);

        ProofVersion::configure_cutover(10, 2);

        assert_eq!(ProofVersion::current_cutover(), (10, 2));
        assert_eq!(
            ProofVersion::for_height_and_epoch(Some(9), Some(1)),
            ProofVersion::AggregatedV1
        );
        assert_eq!(
            ProofVersion::for_height_and_epoch(Some(10), Some(1)),
            ProofVersion::NovaV2
        );
        assert_eq!(
            ProofVersion::for_height_and_epoch(Some(1), Some(2)),
            ProofVersion::NovaV2
        );
    }
}
