use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use rpp_pruning::Envelope;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::kv::Hash;
use crate::pruning::{FirewoodPruner, SnapshotManifest};
use crate::state::{FirewoodState, StateError, STORAGE_LAYOUT_VERSION};

const META_PROGRESS_KEY: &str = "lifecycle_progress.json";
const SNAPSHOT_FAILURE_METRIC: &str = "firewood.snapshot.ingest.failures";
const SNAPSHOT_FAILURE_DESC: &str = "count of snapshot ingestion or verification failures";

fn record_snapshot_failure(reason: &'static str) {
    metrics::describe_counter!(SNAPSHOT_FAILURE_METRIC, SNAPSHOT_FAILURE_DESC);
    metrics::counter!(SNAPSHOT_FAILURE_METRIC, "reason" => reason).increment(1);
}

#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error("state error: {0}")]
    State(#[from] StateError),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to decode snapshot proof: {0}")]
    ProofDecode(#[from] bincode::Error),
    #[error("invalid hex digest in manifest: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("manifest checksum mismatch for {path}")]
    ChecksumMismatch { path: PathBuf },
    #[error("snapshot manifest {path} is missing a file name")]
    MissingManifestName { path: PathBuf },
    #[error("snapshot layout version {found} does not match supported {expected}")]
    LayoutVersionMismatch { found: u32, expected: u32 },
    #[error("snapshot progression from {current:?} to {next} is not monotonic")]
    NonMonotonic { current: Option<u64>, next: u64 },
    #[error("rollback target {target} exceeds applied height {current:?}")]
    InvalidRollback { target: u64, current: Option<u64> },
    #[error("snapshot proof rejected for {path}")]
    ProofVerificationFailed { path: PathBuf },
    #[error("failed to parse snapshot manifest {path}: {source}")]
    ManifestParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct LifecycleProgress {
    height: Option<u64>,
    root: Option<Hash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecycleStatus {
    pub height: Option<u64>,
    pub root: Option<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleReceipt {
    pub previous_height: Option<u64>,
    pub previous_root: Option<Hash>,
    pub new_height: u64,
    pub new_root: Hash,
}

pub struct FirewoodLifecycle {
    state: Arc<FirewoodState>,
    progress: Mutex<LifecycleProgress>,
}

impl FirewoodLifecycle {
    pub fn new(state: Arc<FirewoodState>) -> Result<Self, LifecycleError> {
        let progress = state
            .load_meta::<LifecycleProgress>(META_PROGRESS_KEY)?
            .unwrap_or_default();
        Ok(Self {
            state,
            progress: Mutex::new(progress),
        })
    }

    pub fn open(path: &str) -> Result<Self, LifecycleError> {
        let state = FirewoodState::open(path)?;
        Self::new(state)
    }

    pub fn status(&self) -> LifecycleStatus {
        let progress = self.progress.lock();
        LifecycleStatus {
            height: progress.height,
            root: progress.root,
        }
    }

    pub fn ingest_snapshot<P: AsRef<Path>>(
        &self,
        manifest_path: P,
    ) -> Result<LifecycleReceipt, LifecycleError> {
        let manifest_path = manifest_path.as_ref();
        let bundle = SnapshotBundle::load(manifest_path)?;
        ensure_supported_layout(bundle.manifest.layout_version)?;
        verify_proof(&bundle, manifest_path)?;

        let manifest_name = manifest_file_name(manifest_path)?;
        self.state.import_snapshot_artifacts(
            &manifest_name,
            &bundle.manifest,
            &bundle.proof_bytes,
        )?;

        let mut progress = self.progress.lock();
        if let Some(current) = progress.height {
            if bundle.manifest.block_height <= current {
                return Err(LifecycleError::NonMonotonic {
                    current: progress.height,
                    next: bundle.manifest.block_height,
                });
            }
        }

        let receipt = LifecycleReceipt {
            previous_height: progress.height,
            previous_root: progress.root,
            new_height: bundle.manifest.block_height,
            new_root: bundle.root,
        };
        progress.height = Some(bundle.manifest.block_height);
        progress.root = Some(bundle.root);
        self.state.store_meta(META_PROGRESS_KEY, &*progress)?;
        Ok(receipt)
    }

    pub fn rollback_to_snapshot<P: AsRef<Path>>(
        &self,
        manifest_path: P,
    ) -> Result<LifecycleReceipt, LifecycleError> {
        let manifest_path = manifest_path.as_ref();
        let bundle = SnapshotBundle::load(manifest_path)?;
        ensure_supported_layout(bundle.manifest.layout_version)?;
        verify_proof(&bundle, manifest_path)?;

        let mut progress = self.progress.lock();
        let current_height = progress.height.ok_or(LifecycleError::InvalidRollback {
            target: bundle.manifest.block_height,
            current: None,
        })?;
        if bundle.manifest.block_height > current_height {
            return Err(LifecycleError::InvalidRollback {
                target: bundle.manifest.block_height,
                current: progress.height,
            });
        }

        self.state
            .remove_snapshots_newer_than(bundle.manifest.block_height)?;
        let manifest_name = manifest_file_name(manifest_path)?;
        self.state.import_snapshot_artifacts(
            &manifest_name,
            &bundle.manifest,
            &bundle.proof_bytes,
        )?;

        let receipt = LifecycleReceipt {
            previous_height: progress.height,
            previous_root: progress.root,
            new_height: bundle.manifest.block_height,
            new_root: bundle.root,
        };
        progress.height = Some(bundle.manifest.block_height);
        progress.root = Some(bundle.root);
        self.state.store_meta(META_PROGRESS_KEY, &*progress)?;
        Ok(receipt)
    }
}

fn ensure_supported_layout(layout: u32) -> Result<(), LifecycleError> {
    if layout == STORAGE_LAYOUT_VERSION {
        Ok(())
    } else {
        Err(LifecycleError::LayoutVersionMismatch {
            found: layout,
            expected: STORAGE_LAYOUT_VERSION,
        })
    }
}

fn manifest_file_name(path: &Path) -> Result<String, LifecycleError> {
    Ok(path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| LifecycleError::MissingManifestName {
            path: path.to_path_buf(),
        })?
        .to_string())
}

fn verify_proof(bundle: &SnapshotBundle, manifest_path: &Path) -> Result<(), LifecycleError> {
    let valid = FirewoodPruner::verify_pruned_state_with_digests(
        bundle.schema_digest,
        bundle.parameter_digest,
        bundle.root,
        &bundle.proof,
    );
    if valid {
        Ok(())
    } else {
        record_snapshot_failure("proof_rejected");
        Err(LifecycleError::ProofVerificationFailed {
            path: manifest_path.to_path_buf(),
        })
    }
}

struct SnapshotBundle {
    manifest: SnapshotManifest,
    proof: Envelope,
    proof_bytes: Vec<u8>,
    root: Hash,
    schema_digest: Hash,
    parameter_digest: Hash,
}

impl SnapshotBundle {
    fn load(path: &Path) -> Result<Self, LifecycleError> {
        let bytes = fs::read(path)?;
        let manifest: SnapshotManifest =
            serde_json::from_slice(&bytes).map_err(|source| LifecycleError::ManifestParse {
                path: path.to_path_buf(),
                source,
            })?;
        let proof_path = path
            .parent()
            .map(|dir| dir.join(&manifest.proof_file))
            .unwrap_or_else(|| PathBuf::from(&manifest.proof_file));
        let proof_bytes = fs::read(&proof_path).map_err(|err| {
            record_snapshot_failure("missing_proof");
            LifecycleError::Io(err)
        })?;
        if !manifest.checksum_matches(&proof_bytes) {
            record_snapshot_failure("checksum_mismatch");
            return Err(LifecycleError::ChecksumMismatch { path: proof_path });
        }
        let proof: Envelope = bincode::deserialize(&proof_bytes)?;
        let root = decode_hash(&manifest.state_root)?;
        let schema_digest = decode_hash(&manifest.schema_digest)?;
        let parameter_digest = decode_hash(&manifest.parameter_digest)?;
        Ok(Self {
            manifest,
            proof,
            proof_bytes,
            root,
            schema_digest,
            parameter_digest,
        })
    }
}

fn decode_hash(value: &str) -> Result<Hash, LifecycleError> {
    let bytes = hex::decode(value)?;
    if bytes.len() != 32 {
        return Err(LifecycleError::ChecksumMismatch {
            path: PathBuf::from(value),
        });
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::{decode_hash, SnapshotBundle, SnapshotManifest};
    use crate::STORAGE_LAYOUT_VERSION;
    use rpp_pruning::COMMITMENT_TAG;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn decode_hash_rejects_invalid_length() {
        let err = decode_hash("deadbeef").expect_err("length mismatch");
        match err {
            super::LifecycleError::ChecksumMismatch { .. } => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    fn hex_digest(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn manifest_template() -> SnapshotManifest {
        SnapshotManifest {
            layout_version: STORAGE_LAYOUT_VERSION,
            block_height: 42,
            state_root: hex_digest(1),
            schema_digest: hex_digest(2),
            parameter_digest: hex_digest(3),
            schema_version: 0,
            parameter_version: 0,
            proof_file: "proof.bin".into(),
            proof_checksum: hex::encode([0u8; 32]),
        }
    }

    #[test]
    fn snapshot_bundle_load_fails_when_proof_missing() {
        let temp = tempdir().expect("tempdir");
        let manifest_path = temp.path().join("snapshot.json");
        let manifest = manifest_template();
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        let err = match SnapshotBundle::load(&manifest_path) {
            Ok(_) => panic!("missing proof should fail"),
            Err(err) => err,
        };
        assert!(
            matches!(err, super::LifecycleError::Io(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn snapshot_bundle_load_detects_checksum_mismatch() {
        let temp = tempdir().expect("tempdir");
        let manifest_path = temp.path().join("snapshot.json");
        let proof_path = temp.path().join("proof.bin");
        let mut manifest = manifest_template();
        manifest.proof_file = proof_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        manifest.proof_checksum = hex_digest(4);

        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::write(&proof_path, COMMITMENT_TAG.as_bytes()).unwrap();

        let err = match SnapshotBundle::load(&manifest_path) {
            Ok(_) => panic!("checksum mismatch expected"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            super::LifecycleError::ChecksumMismatch { .. }
        ));
    }
}
