use std::collections::VecDeque;

use crate::kv::Hash;
use rpp_pruning::{
    BlockHeight, Commitment, Envelope, ParameterVersion, ProofSegment, SchemaVersion, SegmentIndex,
    Snapshot, TaggedDigest, COMMITMENT_TAG, ENVELOPE_TAG, PROOF_SEGMENT_TAG, SNAPSHOT_STATE_TAG,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;

const SNAPSHOT_PREFIX: &[u8] = b"fw-pruning-snapshot";
const SEGMENT_PREFIX: &[u8] = b"fw-pruning-segment";
const COMMITMENT_PREFIX: &[u8] = b"fw-pruning-commit";
const ENVELOPE_PREFIX: &[u8] = b"fw-pruning-envelope";

#[derive(Clone, Debug)]
struct SnapshotRecord {
    block_height: BlockHeight,
    state_commitment: TaggedDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossShardReference {
    pub shard: String,
    pub partition: String,
    pub block_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedPrunerSnapshot {
    block_height: u64,
    state_commitment: Hash,
    #[serde(default)]
    cross_references: Vec<CrossShardReference>,
}

impl PersistedPrunerSnapshot {
    pub fn block_height(&self) -> u64 {
        self.block_height
    }

    pub fn state_commitment(&self) -> Hash {
        self.state_commitment
    }

    pub fn cross_references(&self) -> &[CrossShardReference] {
        &self.cross_references
    }

    pub fn cross_references_mut(&mut self) -> &mut Vec<CrossShardReference> {
        &mut self.cross_references
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedPrunerState {
    pub retain: usize,
    pub schema_digest: Hash,
    pub parameter_digest: Hash,
    pub snapshots: Vec<PersistedPrunerSnapshot>,
    #[serde(default)]
    pub layout_version: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub layout_version: u32,
    pub block_height: u64,
    pub state_root: String,
    pub schema_digest: String,
    pub parameter_digest: String,
    pub schema_version: u16,
    pub parameter_version: u16,
    pub proof_file: String,
    pub proof_checksum: String,
}

impl SnapshotManifest {
    pub fn checksum_matches(&self, data: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        let encoded = hex::encode(digest);
        encoded == self.proof_checksum
    }
}

fn schema_version_from_digest(digest: &Hash) -> SchemaVersion {
    SchemaVersion::new(u16::from_be_bytes([digest[0], digest[1]]))
}

fn parameter_version_from_digest(digest: &Hash) -> ParameterVersion {
    ParameterVersion::new(u16::from_be_bytes([digest[0], digest[1]]))
}

fn compute_state_commitment(
    schema_digest: &Hash,
    parameter_digest: &Hash,
    block_height: BlockHeight,
    root: &Hash,
) -> TaggedDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SNAPSHOT_PREFIX);
    hasher.update(schema_digest);
    hasher.update(parameter_digest);
    hasher.update(&block_height.as_u64().to_be_bytes());
    hasher.update(root);
    TaggedDigest::new(SNAPSHOT_STATE_TAG, hasher.finalize().into())
}

fn compute_segment_commitment(
    schema_digest: &Hash,
    parameter_digest: &Hash,
    segment_index: SegmentIndex,
    start_height: BlockHeight,
    end_height: BlockHeight,
    state_commitment: TaggedDigest,
) -> TaggedDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SEGMENT_PREFIX);
    hasher.update(schema_digest);
    hasher.update(parameter_digest);
    hasher.update(&segment_index.as_u32().to_be_bytes());
    hasher.update(&start_height.as_u64().to_be_bytes());
    hasher.update(&end_height.as_u64().to_be_bytes());
    hasher.update(&state_commitment.prefixed_bytes());
    TaggedDigest::new(PROOF_SEGMENT_TAG, hasher.finalize().into())
}

fn compute_aggregate_commitment(
    schema_digest: &Hash,
    parameter_digest: &Hash,
    snapshot: &Snapshot,
    segments: &[ProofSegment],
) -> TaggedDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMITMENT_PREFIX);
    hasher.update(schema_digest);
    hasher.update(parameter_digest);
    hasher.update(&snapshot.block_height().as_u64().to_be_bytes());
    hasher.update(&snapshot.state_commitment().prefixed_bytes());
    for segment in segments {
        hasher.update(&segment.segment_index().as_u32().to_be_bytes());
        hasher.update(&segment.start_height().as_u64().to_be_bytes());
        hasher.update(&segment.end_height().as_u64().to_be_bytes());
        hasher.update(&segment.segment_commitment().prefixed_bytes());
    }
    TaggedDigest::new(COMMITMENT_TAG, hasher.finalize().into())
}

fn compute_binding_digest(
    schema_digest: &Hash,
    parameter_digest: &Hash,
    snapshot: &Snapshot,
    segments: &[ProofSegment],
    commitment: &Commitment,
) -> TaggedDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ENVELOPE_PREFIX);
    hasher.update(schema_digest);
    hasher.update(parameter_digest);
    hasher.update(&snapshot.block_height().as_u64().to_be_bytes());
    hasher.update(&snapshot.state_commitment().prefixed_bytes());
    for segment in segments {
        hasher.update(&segment.segment_index().as_u32().to_be_bytes());
        hasher.update(&segment.start_height().as_u64().to_be_bytes());
        hasher.update(&segment.end_height().as_u64().to_be_bytes());
        hasher.update(&segment.segment_commitment().prefixed_bytes());
    }
    hasher.update(&commitment.aggregate_commitment().prefixed_bytes());
    TaggedDigest::new(ENVELOPE_TAG, hasher.finalize().into())
}

fn verify_with_digests(
    schema_digest: &Hash,
    parameter_digest: &Hash,
    root: Hash,
    proof: &Envelope,
) -> bool {
    let schema_version = schema_version_from_digest(schema_digest);
    let parameter_version = parameter_version_from_digest(parameter_digest);

    if proof.schema_version() != schema_version || proof.parameter_version() != parameter_version {
        return false;
    }

    let snapshot = proof.snapshot();
    if snapshot.schema_version() != schema_version
        || snapshot.parameter_version() != parameter_version
    {
        return false;
    }

    let block_height = snapshot.block_height();
    let expected_state_commitment =
        compute_state_commitment(schema_digest, parameter_digest, block_height, &root);
    if snapshot.state_commitment() != expected_state_commitment {
        return false;
    }

    let segments = proof.segments();
    if segments.len() != 1 {
        return false;
    }

    let segment = &segments[0];
    if segment.schema_version() != schema_version
        || segment.parameter_version() != parameter_version
    {
        return false;
    }

    if segment.start_height() != block_height || segment.end_height() != block_height {
        return false;
    }

    let expected_segment_commitment = compute_segment_commitment(
        schema_digest,
        parameter_digest,
        segment.segment_index(),
        segment.start_height(),
        segment.end_height(),
        expected_state_commitment,
    );
    if segment.segment_commitment() != expected_segment_commitment {
        return false;
    }

    let expected_commitment_digest =
        compute_aggregate_commitment(schema_digest, parameter_digest, snapshot, segments);
    let Ok(expected_commitment) = Commitment::new(
        schema_version,
        parameter_version,
        expected_commitment_digest,
    ) else {
        return false;
    };

    if proof.commitment() != &expected_commitment {
        return false;
    }

    let expected_binding = compute_binding_digest(
        schema_digest,
        parameter_digest,
        snapshot,
        segments,
        proof.commitment(),
    );

    proof.binding_digest() == expected_binding
}

/// Lightweight pruning manager that tracks block snapshots and constructs canonical envelopes.
#[derive(Debug)]
pub struct FirewoodPruner {
    snapshots: VecDeque<SnapshotRecord>,
    retain: usize,
    schema_digest: Hash,
    parameter_digest: Hash,
    schema_version: SchemaVersion,
    parameter_version: ParameterVersion,
}

impl FirewoodPruner {
    pub const DEFAULT_SCHEMA_DIGEST: Hash = [0x11; 32];
    pub const DEFAULT_PARAMETER_DIGEST: Hash = [0x22; 32];

    pub fn new(retain: usize) -> Self {
        Self::with_digests(
            retain,
            Self::DEFAULT_SCHEMA_DIGEST,
            Self::DEFAULT_PARAMETER_DIGEST,
        )
    }

    pub fn with_digests(retain: usize, schema_digest: Hash, parameter_digest: Hash) -> Self {
        let schema_version = schema_version_from_digest(&schema_digest);
        let parameter_version = parameter_version_from_digest(&parameter_digest);
        FirewoodPruner {
            snapshots: VecDeque::new(),
            retain: retain.max(1),
            schema_digest,
            parameter_digest,
            schema_version,
            parameter_version,
        }
    }

    pub fn from_persisted(state: PersistedPrunerState) -> Self {
        let mut pruner = FirewoodPruner::with_digests(
            state.retain.max(1),
            state.schema_digest,
            state.parameter_digest,
        );

        let mut snapshots = VecDeque::with_capacity(state.snapshots.len());
        for snapshot in state.snapshots {
            let record = SnapshotRecord {
                block_height: BlockHeight::new(snapshot.block_height),
                state_commitment: TaggedDigest::new(SNAPSHOT_STATE_TAG, snapshot.state_commitment),
            };
            snapshots.push_back(record);
        }

        while snapshots.len() > pruner.retain {
            snapshots.pop_front();
        }

        pruner.snapshots = snapshots;
        pruner
    }

    pub fn prune_block(&mut self, block_id: u64, root: Hash) -> Envelope {
        let block_height = BlockHeight::new(block_id);
        let state_commitment = compute_state_commitment(
            &self.schema_digest,
            &self.parameter_digest,
            block_height,
            &root,
        );
        let record = SnapshotRecord {
            block_height,
            state_commitment,
        };
        self.snapshots.push_back(record.clone());
        while self.snapshots.len() > self.retain {
            self.snapshots.pop_front();
        }

        let snapshot = Snapshot::new(
            self.schema_version,
            self.parameter_version,
            record.block_height,
            record.state_commitment,
        )
        .expect("state commitment must carry the snapshot tag");

        let segments = vec![ProofSegment::new(
            self.schema_version,
            self.parameter_version,
            SegmentIndex::new(0),
            record.block_height,
            record.block_height,
            compute_segment_commitment(
                &self.schema_digest,
                &self.parameter_digest,
                SegmentIndex::new(0),
                record.block_height,
                record.block_height,
                record.state_commitment,
            ),
        )
        .expect("segment commitment must carry the proof tag")];

        let commitment_digest = compute_aggregate_commitment(
            &self.schema_digest,
            &self.parameter_digest,
            &snapshot,
            &segments,
        );
        let commitment = Commitment::new(
            self.schema_version,
            self.parameter_version,
            commitment_digest,
        )
        .expect("aggregate commitment must carry the commitment tag");

        let binding_digest = compute_binding_digest(
            &self.schema_digest,
            &self.parameter_digest,
            &snapshot,
            &segments,
            &commitment,
        );

        let envelope = Envelope::new(
            self.schema_version,
            self.parameter_version,
            snapshot,
            segments,
            commitment,
            binding_digest,
        )
        .expect("binding digest must carry the envelope tag");

        info!(
            target: "pruning.firewood",
            block_height = block_id,
            schema_version = %self.schema_version,
            parameter_version = %self.parameter_version,
            retained = self.retain,
            "pruning snapshot updated",
        );

        envelope
    }

    pub fn verify_with_config(&self, root: Hash, proof: &Envelope) -> bool {
        verify_with_digests(&self.schema_digest, &self.parameter_digest, root, proof)
    }

    pub fn verify_pruned_state(root: Hash, proof: &Envelope) -> bool {
        Self::verify_pruned_state_with_digests(
            Self::DEFAULT_SCHEMA_DIGEST,
            Self::DEFAULT_PARAMETER_DIGEST,
            root,
            proof,
        )
    }

    pub fn verify_pruned_state_with_digests(
        schema_digest: Hash,
        parameter_digest: Hash,
        root: Hash,
        proof: &Envelope,
    ) -> bool {
        verify_with_digests(&schema_digest, &parameter_digest, root, proof)
    }

    pub fn export_state(&self) -> PersistedPrunerState {
        let snapshots = self
            .snapshots
            .iter()
            .map(|record| PersistedPrunerSnapshot {
                block_height: record.block_height.as_u64(),
                state_commitment: *record.state_commitment.digest(),
                cross_references: Vec::new(),
            })
            .collect();

        PersistedPrunerState {
            retain: self.retain,
            schema_digest: self.schema_digest,
            parameter_digest: self.parameter_digest,
            snapshots,
            layout_version: 0,
        }
    }

    pub fn schema_digest(&self) -> Hash {
        self.schema_digest
    }

    pub fn parameter_digest(&self) -> Hash {
        self.parameter_digest
    }

    pub fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    pub fn parameter_version(&self) -> ParameterVersion {
        self.parameter_version
    }

    pub fn manifest(
        &self,
        layout_version: u32,
        block_height: u64,
        state_root: Hash,
        proof_file: String,
        proof_bytes: &[u8],
    ) -> SnapshotManifest {
        let mut hasher = Sha256::new();
        hasher.update(proof_bytes);
        let checksum = hex::encode(hasher.finalize());

        SnapshotManifest {
            layout_version,
            block_height,
            state_root: hex::encode(state_root),
            schema_digest: hex::encode(self.schema_digest),
            parameter_digest: hex::encode(self.parameter_digest),
            schema_version: self.schema_version.get(),
            parameter_version: self.parameter_version.get(),
            proof_file,
            proof_checksum: checksum,
        }
    }
}

#[cfg(test)]
mod tests_prop;
