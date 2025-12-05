use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hex::encode;
use parking_lot::{Mutex, RwLock};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use crate::{
    column_family::ColumnFamily,
    kv::{FirewoodKv, Hash, KvError},
    pruning::{FirewoodPruner, PersistedPrunerState, SnapshotManifest},
    tree::{FirewoodTree, MerkleProof},
};

pub type StateRoot = Hash;

pub const STORAGE_LAYOUT_VERSION: u32 = 2;
const CF_PRUNING_SNAPSHOTS: &str = "cf_pruning_snapshots";
const CF_PRUNING_PROOFS: &str = "cf_pruning_proofs";
const CF_META: &str = "cf_meta";
const CF_GLOBAL_INSTANCES: &str = "cf_global_instances";
const CF_GLOBAL_PROOF_TIPS: &str = "cf_global_proof_tips";
const META_LAYOUT_KEY: &str = "layout_version.json";
const META_PRUNER_KEY: &str = "pruner_state.json";
const META_TELEMETRY_KEY: &str = "telemetry.json";

#[derive(Debug, Error)]
pub enum StateError {
    #[error("kv error: {0}")]
    Kv(#[from] KvError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("snapshot manifest at height {height} diverges from committed state: {reason}")]
    PruningInvariantViolation { height: u64, reason: String },
    #[error("storage layout requires migration from {from} to {to}")]
    MigrationRequired { from: u32, to: u32 },
    #[error("storage layout {stored} is newer than supported {current}")]
    UnsupportedLayout { stored: u32, current: u32 },
}

pub struct FirewoodState {
    kv: Mutex<FirewoodKv>,
    tree: RwLock<FirewoodTree>,
    pruner: Mutex<FirewoodPruner>,
    snapshots_cf: ColumnFamily,
    proofs_cf: ColumnFamily,
    meta_cf: ColumnFamily,
    global_instances_cf: Option<ColumnFamily>,
    global_proof_tips_cf: Option<ColumnFamily>,
    options: StorageOptions,
}

impl FirewoodState {
    pub fn open(path: &str) -> Result<Arc<Self>, StateError> {
        Self::open_with_options(path, StorageOptions::default())
    }

    pub fn open_with_options<P: AsRef<Path>>(
        path: P,
        options: StorageOptions,
    ) -> Result<Arc<Self>, StateError> {
        let kv = FirewoodKv::open(path)?;
        let mut tree = FirewoodTree::new();
        for (key, value) in kv.scan_prefix(b"") {
            tree.update(&key, value);
        }
        let base_dir = kv.base_dir().to_path_buf();
        let snapshots_cf = if let Some(dir) = options.snapshot_dir.clone() {
            ColumnFamily::open_at(dir)?
        } else {
            ColumnFamily::open(&base_dir, CF_PRUNING_SNAPSHOTS)?
        };
        let proofs_cf = if let Some(dir) = options.proof_dir.clone() {
            ColumnFamily::open_at(dir)?
        } else {
            ColumnFamily::open(&base_dir, CF_PRUNING_PROOFS)?
        };
        let meta_cf = ColumnFamily::open(&base_dir, CF_META)?;
        let stored_layout = read_layout_version(&meta_cf)?;
        if stored_layout > STORAGE_LAYOUT_VERSION {
            return Err(StateError::UnsupportedLayout {
                stored: stored_layout,
                current: STORAGE_LAYOUT_VERSION,
            });
        }

        if stored_layout < STORAGE_LAYOUT_VERSION {
            if env::var_os("FIREWOOD_MIGRATION_DRY_RUN").is_some() {
                return Err(StateError::MigrationRequired {
                    from: stored_layout,
                    to: STORAGE_LAYOUT_VERSION,
                });
            }
            run_migrations(
                &meta_cf,
                &base_dir,
                stored_layout,
                STORAGE_LAYOUT_VERSION,
                options.sync_policy,
            )?;
        }

        let effective_layout = read_layout_version(&meta_cf)?;
        let global_instances_cf = maybe_open_global_cf(
            &base_dir,
            CF_GLOBAL_INSTANCES,
            effective_layout,
            options.enable_global_proof_tip,
        )?;
        let global_proof_tips_cf = maybe_open_global_cf(
            &base_dir,
            CF_GLOBAL_PROOF_TIPS,
            effective_layout,
            options.enable_global_proof_tip,
        )?;

        let mut pruner = if let Some(mut persisted) =
            meta_cf.get_json::<PersistedPrunerState>(META_PRUNER_KEY)?
        {
            if persisted.retain == 0 {
                persisted.retain = options.retain_snapshots.max(1);
            }
            FirewoodPruner::from_persisted(persisted)
        } else {
            FirewoodPruner::new(options.retain_snapshots)
        };

        // Ensure we persist the current layout marker for fresh deployments.
        persist_pruner_state(
            &meta_cf,
            &mut pruner,
            STORAGE_LAYOUT_VERSION,
            options.sync_policy,
        )?;

        Ok(Arc::new(FirewoodState {
            kv: Mutex::new(kv),
            tree: RwLock::new(tree),
            pruner: Mutex::new(pruner),
            snapshots_cf,
            proofs_cf,
            meta_cf,
            global_instances_cf,
            global_proof_tips_cf,
            options,
        }))
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.kv.lock().get(key)
    }

    pub fn put(&self, key: Vec<u8>, value: Vec<u8>) {
        self.kv.lock().put(key.clone(), value.clone());
        let mut tree = self.tree.write();
        tree.update(&key, value);
    }

    pub fn delete(&self, key: &[u8]) {
        self.kv.lock().delete(key);
        let mut tree = self.tree.write();
        tree.delete(key);
    }

    pub fn commit_block(
        &self,
        block_id: u64,
    ) -> Result<(StateRoot, Arc<rpp_pruning::Envelope>), StateError> {
        let mut kv = self.kv.lock();
        let root = kv.commit()?;
        drop(kv);
        let mut pruner = self.pruner.lock();
        let proof = Arc::new(pruner.prune_block(block_id, root));
        let proof_bytes = bincode::serialize(proof.as_ref())?;
        let proof_name = format!("{block_id:020}.bin");
        let schema_digest = pruner.schema_digest();
        let parameter_digest = pruner.parameter_digest();
        self.proofs_cf.put_bytes(
            &proof_name,
            &proof_bytes,
            self.options.sync_policy == SyncPolicy::Always,
        )?;

        let manifest = pruner.manifest(
            STORAGE_LAYOUT_VERSION,
            block_id,
            root,
            proof_name.clone(),
            &proof_bytes,
        );
        let manifest_name = format!("{block_id:020}.json");
        validate_manifest_alignment(
            &self.snapshots_cf,
            &self.proofs_cf,
            &manifest_name,
            &manifest,
            &proof_bytes,
            &root,
            &schema_digest,
            &parameter_digest,
        )?;
        self.snapshots_cf.put_json(
            &manifest_name,
            &manifest,
            self.options.sync_policy == SyncPolicy::Always,
        )?;

        let exported = pruner.export_state();
        let persisted = persist_state_snapshot(
            &self.meta_cf,
            exported,
            STORAGE_LAYOUT_VERSION,
            self.options.sync_policy,
        )?;
        prune_old_artifacts(&self.snapshots_cf, &self.proofs_cf, &persisted)?;

        metrics::counter!(
            "firewood.storage.bytes_written",
            "cf" => CF_PRUNING_PROOFS
        )
        .increment(proof_bytes.len() as u64);

        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|err| StateError::Serialization(err.to_string()))?;
        metrics::counter!(
            "firewood.storage.bytes_written",
            "cf" => CF_PRUNING_SNAPSHOTS
        )
        .increment(manifest_bytes.len() as u64);

        metrics::gauge!(
            "firewood.storage.io_budget",
            "stage" => "commit"
        )
        .set(self.options.commit_io_budget_bytes as f64);
        metrics::gauge!(
            "firewood.storage.io_budget",
            "stage" => "compaction"
        )
        .set(self.options.compaction_io_budget_bytes as f64);

        let telemetry = CommitTelemetry {
            snapshot_bytes: manifest_bytes.len() as u64,
            proof_bytes: proof_bytes.len() as u64,
            commit_budget_bytes: self.options.commit_io_budget_bytes,
            compaction_budget_bytes: self.options.compaction_io_budget_bytes,
        };
        self.meta_cf.put_json(
            META_TELEMETRY_KEY,
            &telemetry,
            self.options.sync_policy == SyncPolicy::Always,
        )?;

        Ok((root, proof))
    }

    pub fn prove(&self, key: &[u8]) -> MerkleProof {
        let tree = self.tree.read();
        tree.get_proof(key)
    }

    pub fn put_global_instance(&self, block_ref: &str, instance: &[u8]) -> Result<(), StateError> {
        if !self.options.enable_global_proof_tip {
            return Ok(());
        }

        let Some(cf) = &self.global_instances_cf else {
            return Ok(());
        };

        cf.put_bytes(
            block_ref,
            instance,
            self.options.sync_policy == SyncPolicy::Always,
        )?;
        Ok(())
    }

    pub fn get_global_instance(&self, block_ref: &str) -> Result<Option<Vec<u8>>, StateError> {
        let Some(cf) = &self.global_instances_cf else {
            return Ok(None);
        };

        Ok(cf.get_bytes(block_ref)?)
    }

    pub fn iter_global_instances(
        &self,
        range: std::ops::RangeInclusive<&str>,
    ) -> Result<Vec<(String, Vec<u8>)>, StateError> {
        let Some(cf) = &self.global_instances_cf else {
            return Ok(Vec::new());
        };

        let mut entries = Vec::new();
        for key in cf.list_keys()? {
            if range.contains(&key.as_str()) {
                if let Some(value) = cf.get_bytes(&key)? {
                    entries.push((key.clone(), value));
                }
            }
        }
        Ok(entries)
    }

    pub fn delete_global_instance(&self, block_ref: &str) -> Result<(), StateError> {
        let Some(cf) = &self.global_instances_cf else {
            return Ok(());
        };
        cf.remove(block_ref)?;
        Ok(())
    }

    pub fn put_global_proof_tip(&self, tip_ref: &str, proof: &[u8]) -> Result<(), StateError> {
        if !self.options.enable_global_proof_tip {
            return Ok(());
        }

        let Some(cf) = &self.global_proof_tips_cf else {
            return Ok(());
        };

        cf.put_bytes(
            tip_ref,
            proof,
            self.options.sync_policy == SyncPolicy::Always,
        )?;
        Ok(())
    }

    pub fn get_global_proof_tip(&self, tip_ref: &str) -> Result<Option<Vec<u8>>, StateError> {
        let Some(cf) = &self.global_proof_tips_cf else {
            return Ok(None);
        };

        Ok(cf.get_bytes(tip_ref)?)
    }

    pub fn iter_global_proof_tips(
        &self,
        range: std::ops::RangeInclusive<&str>,
    ) -> Result<Vec<(String, Vec<u8>)>, StateError> {
        let Some(cf) = &self.global_proof_tips_cf else {
            return Ok(Vec::new());
        };

        let mut entries = Vec::new();
        for key in cf.list_keys()? {
            if range.contains(&key.as_str()) {
                if let Some(value) = cf.get_bytes(&key)? {
                    entries.push((key.clone(), value));
                }
            }
        }
        Ok(entries)
    }

    pub fn delete_global_proof_tip(&self, tip_ref: &str) -> Result<(), StateError> {
        let Some(cf) = &self.global_proof_tips_cf else {
            return Ok(());
        };
        cf.remove(tip_ref)?;
        Ok(())
    }

    pub(crate) fn load_meta<T: DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, StateError> {
        Ok(self.meta_cf.get_json(key)?)
    }

    pub(crate) fn store_meta<T: Serialize>(&self, key: &str, value: &T) -> Result<(), StateError> {
        self.meta_cf
            .put_json(key, value, self.options.sync_policy == SyncPolicy::Always)?;
        Ok(())
    }

    pub(crate) fn import_snapshot_artifacts(
        &self,
        manifest_name: &str,
        manifest: &SnapshotManifest,
        proof_bytes: &[u8],
    ) -> Result<(), StateError> {
        self.snapshots_cf.put_json(
            manifest_name,
            manifest,
            self.options.sync_policy == SyncPolicy::Always,
        )?;
        self.proofs_cf.put_bytes(
            &manifest.proof_file,
            proof_bytes,
            self.options.sync_policy == SyncPolicy::Always,
        )?;
        Ok(())
    }

    pub(crate) fn remove_snapshots_newer_than(&self, height: u64) -> Result<(), StateError> {
        let keys = self.snapshots_cf.list_keys()?;
        for key in keys {
            if let Some(id) = snapshot_id_from_name(&key) {
                if id > height {
                    if let Some(manifest) = self.snapshots_cf.get_json::<SnapshotManifest>(&key)? {
                        self.snapshots_cf.remove(&key)?;
                        self.proofs_cf.remove(&manifest.proof_file)?;
                    } else {
                        self.snapshots_cf.remove(&key)?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl From<bincode::Error> for StateError {
    fn from(err: bincode::Error) -> Self {
        StateError::Serialization(err.to_string())
    }
}

fn read_layout_version(meta_cf: &ColumnFamily) -> Result<u32, StateError> {
    Ok(meta_cf.get_json::<u32>(META_LAYOUT_KEY)?.unwrap_or(0))
}

fn maybe_open_global_cf(
    base_dir: &Path,
    name: &str,
    layout_version: u32,
    enable_write: bool,
) -> Result<Option<ColumnFamily>, StateError> {
    let path = base_dir.join(name);
    let should_open = layout_version >= 2 || enable_write || path.exists();
    if should_open {
        Ok(Some(ColumnFamily::open(base_dir, name)?))
    } else {
        Ok(None)
    }
}

fn validate_manifest_alignment(
    snapshots_cf: &ColumnFamily,
    proofs_cf: &ColumnFamily,
    manifest_name: &str,
    manifest: &SnapshotManifest,
    proof_bytes: &[u8],
    expected_root: &Hash,
    expected_schema_digest: &Hash,
    expected_parameter_digest: &Hash,
) -> Result<(), StateError> {
    if manifest.block_height == 0 {
        return Err(StateError::PruningInvariantViolation {
            height: manifest.block_height,
            reason: "snapshot height must be non-zero".to_string(),
        });
    }

    let expected_root_hex = encode(expected_root);
    if manifest.state_root != expected_root_hex {
        return Err(StateError::PruningInvariantViolation {
            height: manifest.block_height,
            reason: "state root mismatch".to_string(),
        });
    }

    if manifest.schema_digest != encode(expected_schema_digest) {
        return Err(StateError::PruningInvariantViolation {
            height: manifest.block_height,
            reason: "schema digest mismatch".to_string(),
        });
    }

    if manifest.parameter_digest != encode(expected_parameter_digest) {
        return Err(StateError::PruningInvariantViolation {
            height: manifest.block_height,
            reason: "parameter digest mismatch".to_string(),
        });
    }

    if !manifest.checksum_matches(proof_bytes) {
        return Err(StateError::PruningInvariantViolation {
            height: manifest.block_height,
            reason: "manifest checksum does not match freshly generated proof".to_string(),
        });
    }

    if let Some(existing) = snapshots_cf.get_json::<SnapshotManifest>(manifest_name)? {
        if existing.state_root != manifest.state_root {
            return Err(StateError::PruningInvariantViolation {
                height: manifest.block_height,
                reason: "existing manifest state root diverges".to_string(),
            });
        }

        if existing.schema_digest != manifest.schema_digest
            || existing.parameter_digest != manifest.parameter_digest
        {
            return Err(StateError::PruningInvariantViolation {
                height: manifest.block_height,
                reason: "existing manifest digests diverge".to_string(),
            });
        }

        let Some(proof_file) = proofs_cf.get_bytes(&existing.proof_file)? else {
            return Err(StateError::PruningInvariantViolation {
                height: manifest.block_height,
                reason: "manifest proof file missing".to_string(),
            });
        };

        if !existing.checksum_matches(&proof_file) {
            return Err(StateError::PruningInvariantViolation {
                height: manifest.block_height,
                reason: "existing manifest checksum rejected stored proof".to_string(),
            });
        }

        if existing.proof_file != manifest.proof_file {
            return Err(StateError::PruningInvariantViolation {
                height: manifest.block_height,
                reason: "existing manifest references unexpected proof name".to_string(),
            });
        }
    }

    Ok(())
}

fn write_layout_version(
    meta_cf: &ColumnFamily,
    version: u32,
    policy: SyncPolicy,
) -> Result<(), StateError> {
    meta_cf.put_json(META_LAYOUT_KEY, &version, policy == SyncPolicy::Always)?;
    Ok(())
}

#[derive(Serialize)]
struct CommitTelemetry {
    snapshot_bytes: u64,
    proof_bytes: u64,
    commit_budget_bytes: u64,
    compaction_budget_bytes: u64,
}

fn run_migrations(
    meta_cf: &ColumnFamily,
    base_dir: &Path,
    from: u32,
    to: u32,
    policy: SyncPolicy,
) -> Result<(), StateError> {
    let mut version = from;
    while version < to {
        match version {
            0 => {
                write_layout_version(meta_cf, 1, policy)?;
            }
            1 => {
                fs::create_dir_all(base_dir.join(CF_GLOBAL_INSTANCES))?;
                fs::create_dir_all(base_dir.join(CF_GLOBAL_PROOF_TIPS))?;
                write_layout_version(meta_cf, 2, policy)?;
            }
            other => {
                return Err(StateError::UnsupportedLayout {
                    stored: other,
                    current: to,
                });
            }
        }
        version += 1;
    }
    Ok(())
}

fn persist_pruner_state(
    meta_cf: &ColumnFamily,
    pruner: &mut FirewoodPruner,
    layout_version: u32,
    policy: SyncPolicy,
) -> Result<(), StateError> {
    let exported = pruner.export_state();
    let _ = persist_state_snapshot(meta_cf, exported, layout_version, policy)?;
    Ok(())
}

fn persist_state_snapshot(
    meta_cf: &ColumnFamily,
    mut state: PersistedPrunerState,
    layout_version: u32,
    policy: SyncPolicy,
) -> Result<PersistedPrunerState, StateError> {
    state.layout_version = layout_version;
    meta_cf.put_json(META_PRUNER_KEY, &state, policy == SyncPolicy::Always)?;
    Ok(state)
}

fn prune_old_artifacts(
    snapshots_cf: &ColumnFamily,
    proofs_cf: &ColumnFamily,
    state: &PersistedPrunerState,
) -> Result<(), StateError> {
    let retain: HashSet<String> = state
        .snapshots
        .iter()
        .map(|snapshot| format!("{:020}", snapshot.block_height()))
        .collect();

    for entry in snapshots_cf.list_keys()? {
        if let Some(id) = entry.strip_suffix(".json") {
            if !retain.contains(id) {
                snapshots_cf.remove(&entry)?;
            }
        }
    }

    for entry in proofs_cf.list_keys()? {
        if let Some(id) = entry.strip_suffix(".bin") {
            if !retain.contains(id) {
                proofs_cf.remove(&entry)?;
            }
        }
    }

    Ok(())
}

fn snapshot_id_from_name(name: &str) -> Option<u64> {
    let id = name.strip_suffix(".json")?;
    id.parse().ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncPolicy {
    Always,
    Deferred,
}

impl Default for SyncPolicy {
    fn default() -> Self {
        SyncPolicy::Always
    }
}

#[derive(Clone, Debug)]
pub struct StorageOptions {
    pub snapshot_dir: Option<PathBuf>,
    pub proof_dir: Option<PathBuf>,
    pub sync_policy: SyncPolicy,
    pub commit_io_budget_bytes: u64,
    pub compaction_io_budget_bytes: u64,
    pub retain_snapshots: usize,
    pub enable_global_proof_tip: bool,
}

impl Default for StorageOptions {
    fn default() -> Self {
        Self {
            snapshot_dir: None,
            proof_dir: None,
            sync_policy: SyncPolicy::Always,
            commit_io_budget_bytes: 64 * 1024 * 1024,
            compaction_io_budget_bytes: 128 * 1024 * 1024,
            retain_snapshots: 3,
            enable_global_proof_tip: false,
        }
    }
}
