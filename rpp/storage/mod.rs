use std::collections::HashSet;
use std::convert::TryInto;
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use storage_firewood::api::StateUpdate;
use storage_firewood::kv::FirewoodKv;
use storage_firewood::pruning::{FirewoodPruner, PersistedPrunerState};

use serde::{Deserialize, Serialize};

use crate::consensus::ConsensusCertificate;
use crate::errors::{ChainError, ChainResult};
use crate::rpp::UtxoOutpoint;
use crate::state::StoredUtxo;
use crate::zk::backend_interface::folding::{GlobalInstance, GlobalProof};
use tracing::{info, warn};
pub mod blueprint;
pub mod pruner;

use crate::types::{
    pruning_from_previous, Account, Block, BlockMetadata, CanonicalPruningEnvelope, PruningProof,
    PruningProofExt, StoredBlock,
};

pub const STORAGE_SCHEMA_VERSION: u32 = 2;

const PREFIX_BLOCK: u8 = b'b';
const PREFIX_ACCOUNT: u8 = b'a';
const PREFIX_METADATA: u8 = b'm';
const TIP_HEIGHT_KEY: &[u8] = b"tip_height";
const TIP_HASH_KEY: &[u8] = b"tip_hash";
const TIP_TIMESTAMP_KEY: &[u8] = b"tip_timestamp";
const TIP_METADATA_KEY: &[u8] = b"tip_metadata";
const BLOCK_METADATA_PREFIX: &[u8] = b"block_metadata/";
const GLOBAL_INSTANCE_PREFIX: &[u8] = b"global_instance/";
const GLOBAL_PROOF_PREFIX: &[u8] = b"global_proof/";
pub(crate) const PRUNING_PROOF_PREFIX: &[u8] = b"pruning_proofs/";
pub(crate) const SCHEMA_VERSION_KEY: &[u8] = b"schema_version";
const WALLET_UTXO_SNAPSHOT_KEY: &[u8] = b"wallet_utxo_snapshot";
const PRUNER_STATE_KEY: &[u8] = b"pruner_state";
const CONSENSUS_STATE_KEY: &[u8] = b"consensus_state";

const SCHEMA_ACCOUNTS: &str = "accounts";

#[derive(Clone, Debug)]
pub struct StateTransitionReceipt {
    pub previous_root: [u8; 32],
    pub new_root: [u8; 32],
    pub pruning_proof: Option<PruningProof>,
}

#[cfg(test)]
mod interface_schemas {
    use crate::storage::StateTransitionReceipt;
    use jsonschema::{Draft, JSONSchema};
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use serde_json::Value;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn interfaces_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/interfaces")
    }

    fn load_json(path: &Path) -> Value {
        let raw = fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("unable to read {}: {err}", path.display()));
        serde_json::from_str(&raw)
            .unwrap_or_else(|err| panic!("invalid JSON in {}: {err}", path.display()))
    }

    fn resolve_refs(value: &mut Value, base: &Path) {
        match value {
            Value::Object(map) => {
                if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
                    let target_path = base.join(reference);
                    let mut target = load_json(&target_path);
                    let target_base = target_path
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| base.to_path_buf());
                    resolve_refs(&mut target, &target_base);
                    *value = target;
                } else {
                    for sub in map.values_mut() {
                        resolve_refs(sub, base);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    resolve_refs(item, base);
                }
            }
            _ => {}
        }
    }

    fn load_schema(segment: &str) -> Value {
        let path = interfaces_dir().join(segment);
        let mut schema = load_json(&path);
        let base = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| interfaces_dir());
        resolve_refs(&mut schema, &base);
        schema
    }

    fn load_example(segment: &str) -> Value {
        load_json(&interfaces_dir().join(segment))
    }

    fn assert_roundtrip<T>(schema_file: &str, example_file: &str)
    where
        T: Serialize + DeserializeOwned,
    {
        let schema = load_schema(schema_file);
        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .expect("schema compiles");
        let example = load_example(example_file);
        compiled.validate(&example).expect("example matches schema");
        let typed: T = serde_json::from_value(example.clone()).expect("deserialize example");
        let roundtrip = serde_json::to_value(&typed).expect("serialize payload");
        assert_eq!(roundtrip, example);
    }

    #[test]
    fn state_transition_receipt_schema_roundtrip() {
        assert_roundtrip::<StateTransitionReceipt>(
            "runtime/state_transition_receipt.jsonschema",
            "runtime/examples/state_transition_receipt.json",
        );
    }
}

pub struct Storage {
    kv: Arc<Mutex<FirewoodKv>>,
    pruner: Arc<Mutex<FirewoodPruner>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrunedProofStats {
    pub scanned: u64,
    pub pruned: u64,
    pub retained: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipReference {
    pub chain_id: String,
    pub height: u64,
    pub hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalInstanceRecord {
    pub block_height: u64,
    pub block_hash: String,
    pub instance: GlobalInstance,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalProofRecord {
    pub produced_at_height: u64,
    pub proof: GlobalProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum StoredGlobalInstance {
    V1 { instance: GlobalInstance },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum StoredGlobalProof {
    V1 {
        proof: GlobalProof,
        produced_at_height: u64,
    },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConsensusRecoveryState {
    pub height: u64,
    pub round: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_proposal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_certificate: Option<ConsensusCertificate>,
}

impl Storage {
    pub fn open(path: &Path) -> ChainResult<Self> {
        let kv = FirewoodKv::open(path)?;
        let pruner = match Self::read_pruner_state_raw(&kv)? {
            Some(state) => FirewoodPruner::from_persisted(state),
            None => FirewoodPruner::new(8),
        };
        let storage = Self {
            kv: Arc::new(Mutex::new(kv)),
            pruner: Arc::new(Mutex::new(pruner)),
        };
        storage.ensure_schema_supported()?;
        Ok(storage)
    }

    fn ensure_schema_supported(&self) -> ChainResult<()> {
        let version = self.read_schema_version()?;
        match version {
            Some(version) if version > STORAGE_SCHEMA_VERSION => Err(ChainError::Config(format!(
                "database schema version {version} is newer than supported {STORAGE_SCHEMA_VERSION}"
            ))),
            Some(version) if version < STORAGE_SCHEMA_VERSION => {
                Err(ChainError::MigrationRequired {
                    found: version,
                    required: STORAGE_SCHEMA_VERSION,
                })
            }
            Some(_) => Ok(()),
            None => {
                if self.is_empty()? {
                    self.write_schema_version(STORAGE_SCHEMA_VERSION)?;
                    Ok(())
                } else {
                    Err(ChainError::MigrationRequired {
                        found: 0,
                        required: STORAGE_SCHEMA_VERSION,
                    })
                }
            }
        }
    }

    fn is_empty(&self) -> ChainResult<bool> {
        let kv = self.kv.lock();
        if kv.scan_prefix(&[PREFIX_BLOCK]).next().is_some() {
            return Ok(false);
        }
        if kv.scan_prefix(&[PREFIX_ACCOUNT]).next().is_some() {
            return Ok(false);
        }
        if kv.get(&metadata_key(TIP_HEIGHT_KEY)).is_some() {
            return Ok(false);
        }
        Ok(true)
    }

    fn read_schema_version(&self) -> ChainResult<Option<u32>> {
        let kv = self.kv.lock();
        Self::read_schema_version_raw(&kv)
    }

    pub fn schema_version(&self) -> ChainResult<u32> {
        Ok(self
            .read_schema_version()?
            .unwrap_or(STORAGE_SCHEMA_VERSION))
    }

    fn write_schema_version(&self, version: u32) -> ChainResult<()> {
        let mut kv = self.kv.lock();
        Self::write_schema_version_raw(&mut kv, version)
    }

    pub(crate) fn write_schema_version_raw(kv: &mut FirewoodKv, version: u32) -> ChainResult<()> {
        kv.put(
            metadata_key(SCHEMA_VERSION_KEY),
            version.to_be_bytes().to_vec(),
        );
        kv.commit()?;
        Ok(())
    }

    pub(crate) fn read_schema_version_raw(kv: &FirewoodKv) -> ChainResult<Option<u32>> {
        match kv.get(&metadata_key(SCHEMA_VERSION_KEY)) {
            Some(bytes) => {
                let bytes: [u8; 4] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| ChainError::Config("invalid schema version encoding".into()))?;
                Ok(Some(u32::from_be_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    fn persist_pruner_state_raw(
        kv: &mut FirewoodKv,
        state: &PersistedPrunerState,
    ) -> ChainResult<()> {
        let encoded = bincode::serialize(state)?;
        kv.put(metadata_key(PRUNER_STATE_KEY), encoded);
        Ok(())
    }

    fn read_pruner_state_raw(kv: &FirewoodKv) -> ChainResult<Option<PersistedPrunerState>> {
        match kv.get(&metadata_key(PRUNER_STATE_KEY)) {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    pub(crate) fn open_db(path: &Path) -> ChainResult<FirewoodKv> {
        FirewoodKv::open(path).map_err(ChainError::from)
    }

    pub fn state_root(&self) -> ChainResult<[u8; 32]> {
        let kv = self.kv.lock();
        Ok(kv.root_hash())
    }

    pub fn read_metadata_blob(&self, key: &[u8]) -> ChainResult<Option<Vec<u8>>> {
        let kv = self.kv.lock();
        Ok(kv.get(&metadata_key(key)))
    }

    pub fn write_metadata_blob(&self, key: &[u8], value: Vec<u8>) -> ChainResult<()> {
        let mut kv = self.kv.lock();
        kv.put(metadata_key(key), value);
        kv.commit()?;
        Ok(())
    }

    pub fn read_consensus_state(&self) -> ChainResult<Option<ConsensusRecoveryState>> {
        let kv = self.kv.lock();
        if let Some(bytes) = kv.get(&metadata_key(CONSENSUS_STATE_KEY)) {
            Ok(Some(bincode::deserialize(&bytes)?))
        } else {
            Ok(None)
        }
    }

    pub fn write_consensus_state(&self, state: &ConsensusRecoveryState) -> ChainResult<()> {
        let encoded = bincode::serialize(state)?;
        let mut kv = self.kv.lock();
        kv.put(metadata_key(CONSENSUS_STATE_KEY), encoded);
        kv.commit()?;
        Ok(())
    }

    pub fn delete_metadata_blob(&self, key: &[u8]) -> ChainResult<()> {
        let mut kv = self.kv.lock();
        kv.delete(&metadata_key(key));
        kv.commit()?;
        Ok(())
    }

    pub fn persist_pruning_proof(&self, height: u64, proof: &PruningProof) -> ChainResult<u64> {
        let pruner_state = {
            let pruner = self.pruner.lock();
            pruner.export_state()
        };
        let mut kv = self.kv.lock();
        let canonical = CanonicalPruningEnvelope::from(proof.as_ref());
        let data = rpp_pruning::canonical_bincode_options().serialize(&canonical)?;
        let written_bytes = data.len() as u64;
        kv.put(metadata_key(&pruning_proof_suffix(height)), data);
        Self::persist_pruner_state_raw(&mut kv, &pruner_state)?;
        kv.commit()?;
        Ok(written_bytes)
    }

    pub fn load_pruning_proof(&self, height: u64) -> ChainResult<Option<PruningProof>> {
        let kv = self.kv.lock();
        let key = metadata_key(&pruning_proof_suffix(height));
        Ok(match kv.get(&key) {
            Some(bytes) => {
                #[derive(serde::Deserialize)]
                #[serde(untagged)]
                enum StoredEnvelope {
                    Canonical(CanonicalPruningEnvelope),
                    Legacy(rpp_pruning::Envelope),
                }

                let stored: StoredEnvelope =
                    rpp_pruning::canonical_bincode_options().deserialize(&bytes)?;
                let envelope = match stored {
                    StoredEnvelope::Canonical(canonical) => canonical.into_envelope()?,
                    StoredEnvelope::Legacy(legacy) => legacy,
                };
                Some(Arc::new(envelope))
            }
            None => None,
        })
    }

    pub fn prune_pruning_proofs(
        &self,
        finalized_height: u64,
        safety_margin: u64,
        tip_window: RangeInclusive<u64>,
    ) -> ChainResult<PrunedProofStats> {
        let retain_floor = finalized_height.saturating_sub(safety_margin);
        let (tip_start, tip_end) = (*tip_window.start(), *tip_window.end());
        let prefix = metadata_key(PRUNING_PROOF_PREFIX);
        let prefix_len = prefix.len();

        let mut kv = self.kv.lock();
        let mut stats = PrunedProofStats::default();
        let mut deletes = Vec::new();

        for (key, _) in kv.scan_prefix(&prefix) {
            stats.scanned += 1;
            if key.len() < prefix_len + 8 {
                warn!(
                    ?key,
                    "skipping malformed pruning proof key while pruning old proofs"
                );
                continue;
            }

            let Ok(height_bytes) = <[u8; 8]>::try_from(&key[prefix_len..prefix_len + 8]) else {
                warn!(
                    ?key,
                    "unable to parse pruning proof height while pruning old proofs"
                );
                continue;
            };
            let height = u64::from_be_bytes(height_bytes);

            let in_tip_window = (tip_start..=tip_end).contains(&height);
            if height < retain_floor && !in_tip_window {
                deletes.push(key);
                stats.pruned += 1;
            } else {
                stats.retained += 1;
            }
        }

        for key in &deletes {
            kv.delete(key);
        }

        if !deletes.is_empty() {
            kv.commit()?;
        }

        info!(
            retain_floor,
            tip_start,
            tip_end,
            scanned = stats.scanned,
            pruned = stats.pruned,
            retained = stats.retained,
            "pruned historical pruning proofs beyond finalized checkpoint"
        );

        Ok(stats)
    }

    pub fn persist_global_instance_by_block(
        &self,
        chain_id: &str,
        block_height: u64,
        block_hash: &str,
        instance: &GlobalInstance,
    ) -> ChainResult<()> {
        let record = StoredGlobalInstance::V1 {
            instance: instance.clone(),
        };
        let encoded = bincode::serialize(&record)?;
        let key = metadata_key(&global_instance_suffix(chain_id, block_height, block_hash));
        let mut kv = self.kv.lock();
        kv.put(key, encoded);
        kv.commit()?;
        Ok(())
    }

    pub fn load_global_instance_by_block(
        &self,
        chain_id: &str,
        block_height: u64,
        block_hash: &str,
    ) -> ChainResult<Option<GlobalInstance>> {
        let kv = self.kv.lock();
        let key = metadata_key(&global_instance_suffix(chain_id, block_height, block_hash));
        let Some(bytes) = kv.get(&key) else {
            return Ok(None);
        };

        let stored: StoredGlobalInstance = bincode::deserialize(&bytes)?;
        match stored {
            StoredGlobalInstance::V1 { instance } => Ok(Some(instance)),
        }
    }

    pub fn iter_global_instances_in_range(
        &self,
        chain_id: &str,
        start_height: u64,
        end_height: u64,
    ) -> ChainResult<Vec<GlobalInstanceRecord>> {
        if start_height > end_height {
            return Ok(Vec::new());
        }

        let prefix = metadata_key(&global_instance_chain_prefix(chain_id));
        let entries: Vec<(Vec<u8>, Vec<u8>)> = {
            let kv = self.kv.lock();
            kv.scan_prefix(&prefix).collect()
        };

        let mut records = Vec::new();
        for (key, value) in entries {
            let suffix = key
                .get(prefix.len()..)
                .ok_or_else(|| ChainError::Config("malformed global instance key".into()))?;
            if suffix.len() < 17 || suffix[16] != b'/' {
                return Err(ChainError::Config("invalid global instance suffix".into()));
            }
            let height = u64::from_str_radix(
                std::str::from_utf8(&suffix[..16])
                    .map_err(|err| ChainError::Config(format!("invalid height utf8: {err}")))?,
                16,
            )
            .map_err(|err| ChainError::Config(format!("invalid height encoding: {err}")))?;
            if height < start_height || height > end_height {
                continue;
            }
            let block_hash = std::str::from_utf8(&suffix[17..])
                .map_err(|err| ChainError::Config(format!("invalid block hash utf8: {err}")))?
                .to_string();
            let stored: StoredGlobalInstance = bincode::deserialize(&value)?;
            let instance = match stored {
                StoredGlobalInstance::V1 { instance } => instance,
            };
            records.push(GlobalInstanceRecord {
                block_height: height,
                block_hash,
                instance,
            });
        }

        Ok(records)
    }

    pub fn persist_global_proof_by_tip(
        &self,
        chain_id: &str,
        tip_height: u64,
        tip_hash: &str,
        produced_at_height: u64,
        proof: Option<&GlobalProof>,
    ) -> ChainResult<()> {
        let Some(proof) = proof else {
            return Ok(());
        };

        let record = StoredGlobalProof::V1 {
            proof: proof.clone(),
            produced_at_height,
        };
        let encoded = bincode::serialize(&record)?;
        let key = metadata_key(&global_proof_suffix(chain_id, tip_height, tip_hash));
        let mut kv = self.kv.lock();
        kv.put(key, encoded);
        kv.commit()?;
        Ok(())
    }

    pub fn load_global_proof_by_tip(
        &self,
        chain_id: &str,
        tip_height: u64,
        tip_hash: &str,
    ) -> ChainResult<Option<GlobalProofRecord>> {
        let kv = self.kv.lock();
        let key = metadata_key(&global_proof_suffix(chain_id, tip_height, tip_hash));
        let Some(bytes) = kv.get(&key) else {
            return Ok(None);
        };

        let stored: StoredGlobalProof = bincode::deserialize(&bytes)?;
        match stored {
            StoredGlobalProof::V1 {
                proof,
                produced_at_height,
            } => Ok(Some(GlobalProofRecord {
                produced_at_height,
                proof,
            })),
        }
    }

    pub fn load_or_rebuild_global_proof_by_tip<R>(
        &self,
        tip_ref: &TipReference,
        rpp_state: &R,
        rebuild: impl Fn(&TipReference, &R) -> ChainResult<(GlobalProof, u64)>,
    ) -> ChainResult<Option<GlobalProofRecord>> {
        if let Some(record) =
            self.load_global_proof_by_tip(&tip_ref.chain_id, tip_ref.height, &tip_ref.hash)?
        {
            return Ok(Some(record));
        }

        info!(
            height = tip_ref.height,
            hash = %tip_ref.hash,
            chain = %tip_ref.chain_id,
            "global proof missing at tip, attempting rebuild from RPP state"
        );

        let (proof, produced_at_height) = rebuild(tip_ref, rpp_state)?;
        self.persist_global_proof_by_tip(
            &tip_ref.chain_id,
            tip_ref.height,
            &tip_ref.hash,
            produced_at_height,
            Some(&proof),
        )?;

        Ok(Some(GlobalProofRecord {
            produced_at_height,
            proof,
        }))
    }

    pub fn persist_utxo_snapshot(
        &self,
        snapshot: &[(UtxoOutpoint, StoredUtxo)],
    ) -> ChainResult<()> {
        let encoded = bincode::serialize(snapshot)?;
        self.write_metadata_blob(WALLET_UTXO_SNAPSHOT_KEY, encoded)
    }

    pub fn load_utxo_snapshot(&self) -> ChainResult<Option<Vec<(UtxoOutpoint, StoredUtxo)>>> {
        let maybe_bytes = self.read_metadata_blob(WALLET_UTXO_SNAPSHOT_KEY)?;
        let Some(bytes) = maybe_bytes else {
            return Ok(None);
        };
        let snapshot = bincode::deserialize(&bytes)?;
        Ok(Some(snapshot))
    }

    fn schema_key(&self, schema: &str, key: Vec<u8>) -> ChainResult<Vec<u8>> {
        match schema {
            SCHEMA_ACCOUNTS => {
                let mut namespaced = Vec::with_capacity(1 + key.len());
                namespaced.push(PREFIX_ACCOUNT);
                namespaced.extend_from_slice(&key);
                Ok(namespaced)
            }
            other => Err(ChainError::Config(format!(
                "unsupported firewood schema '{}'",
                other
            ))),
        }
    }

    pub fn apply_state_updates(
        &self,
        block_height: Option<u64>,
        updates: Vec<StateUpdate>,
    ) -> ChainResult<StateTransitionReceipt> {
        let previous_root = self.state_root()?;
        if updates.is_empty() {
            let pruning_proof = block_height.map(|height| {
                let mut pruner = self.pruner.lock();
                let proof = pruner.prune_block(height, previous_root);
                Arc::new(proof)
            });
            return Ok(StateTransitionReceipt {
                previous_root,
                new_root: previous_root,
                pruning_proof,
            });
        }

        let mut kv = self.kv.lock();
        for update in updates {
            let key = self.schema_key(&update.schema, update.key)?;
            if let Some(value) = update.value {
                kv.put(key, value);
            } else {
                kv.delete(&key);
            }
        }
        let new_root = kv.commit()?;
        drop(kv);
        let pruning_proof = block_height.map(|height| {
            let mut pruner = self.pruner.lock();
            Arc::new(pruner.prune_block(height, new_root))
        });
        Ok(StateTransitionReceipt {
            previous_root,
            new_root,
            pruning_proof,
        })
    }

    pub fn apply_account_snapshot(
        &self,
        block_height: Option<u64>,
        accounts: &[Account],
    ) -> ChainResult<StateTransitionReceipt> {
        let previous_root = self.state_root()?;
        let mut kv = self.kv.lock();
        let existing_keys: Vec<Vec<u8>> = kv
            .scan_prefix(&[PREFIX_ACCOUNT])
            .map(|(key, _)| key)
            .collect();
        let allowed: HashSet<String> = accounts
            .iter()
            .map(|account| account.address.clone())
            .collect();
        for key in existing_keys {
            if key.len() < 2 {
                continue;
            }
            if let Ok(address) = String::from_utf8(key[1..].to_vec()) {
                if !allowed.contains(&address) {
                    kv.delete(&key);
                }
            }
        }
        for account in accounts {
            let data = bincode::serialize(account)?;
            kv.put(account_key(&account.address), data);
        }
        let new_root = kv.commit()?;
        drop(kv);
        let pruning_proof = block_height.map(|height| {
            let mut pruner = self.pruner.lock();
            Arc::new(pruner.prune_block(height, new_root))
        });
        Ok(StateTransitionReceipt {
            previous_root,
            new_root,
            pruning_proof,
        })
    }

    pub fn store_block(&self, block: &Block, metadata: &BlockMetadata) -> ChainResult<()> {
        let mut kv = self.kv.lock();
        let key = block_key(block.header.height);
        let record = StoredBlock::from_block(block);
        let data = bincode::serialize(&record)?;
        kv.put(key, data);
        let mut metadata = metadata.clone();
        Self::hydrate_metadata_from_block(block, &mut metadata);
        kv.put(
            metadata_key(TIP_HEIGHT_KEY),
            block.header.height.to_be_bytes().to_vec(),
        );
        kv.put(metadata_key(TIP_HASH_KEY), block.hash.as_bytes().to_vec());
        kv.put(
            metadata_key(TIP_TIMESTAMP_KEY),
            block.header.timestamp.to_be_bytes().to_vec(),
        );
        let encoded_metadata = bincode::serialize(&metadata)?;
        kv.put(metadata_key(TIP_METADATA_KEY), encoded_metadata.clone());
        kv.put(
            metadata_key(&block_metadata_suffix(block.header.height)),
            encoded_metadata,
        );
        kv.commit()?;
        Ok(())
    }

    pub fn read_block(&self, height: u64) -> ChainResult<Option<Block>> {
        let kv = self.kv.lock();
        let key = block_key(height);
        match kv.get(&key) {
            Some(value) => {
                let record: StoredBlock = bincode::deserialize(&value)?;
                Ok(Some(record.into_block()))
            }
            None => Ok(None),
        }
    }

    pub fn read_block_metadata(&self, height: u64) -> ChainResult<Option<BlockMetadata>> {
        let suffix = block_metadata_suffix(height);
        let key = metadata_key(&suffix);
        let maybe_bytes = {
            let kv = self.kv.lock();
            kv.get(&key)
        };
        if let Some(bytes) = maybe_bytes {
            let mut metadata: BlockMetadata = bincode::deserialize(&bytes)?;
            if metadata.height == 0 {
                metadata.height = height;
            }
            self.populate_metadata_from_block(height, &mut metadata)?;
            return Ok(Some(metadata));
        }
        if let Some(record) = self.read_block_record(height)? {
            let block = record.into_block();
            let mut metadata = BlockMetadata::from(&block);
            metadata.height = block.header.height;
            metadata.hash = block.hash.clone();
            metadata.timestamp = block.header.timestamp;
            Self::hydrate_metadata_from_block(&block, &mut metadata);
            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn read_block_record(&self, height: u64) -> ChainResult<Option<StoredBlock>> {
        let kv = self.kv.lock();
        let key = block_key(height);
        match kv.get(&key) {
            Some(value) => Ok(Some(bincode::deserialize(&value)?)),
            None => Ok(None),
        }
    }

    pub fn load_blockchain(&self) -> ChainResult<Vec<Block>> {
        let kv = self.kv.lock();
        let entries: Vec<(Vec<u8>, Vec<u8>)> = kv.scan_prefix(&[PREFIX_BLOCK]).collect();
        drop(kv);
        let mut blocks = Vec::new();
        for (_key, value) in entries {
            let record: StoredBlock = bincode::deserialize(&value)?;
            blocks.push(record.into_block());
        }
        blocks.sort_by_key(|block| block.header.height);
        Ok(blocks)
    }

    pub(crate) fn load_block_records_from(&self, start: u64) -> ChainResult<Vec<StoredBlock>> {
        let kv = self.kv.lock();
        let entries: Vec<(Vec<u8>, Vec<u8>)> = kv.scan_prefix(&[PREFIX_BLOCK]).collect();
        drop(kv);
        let mut records = Vec::new();
        for (key, value) in entries {
            if key.len() != 1 + 8 {
                continue;
            }
            let height = u64::from_be_bytes(
                key[1..]
                    .try_into()
                    .map_err(|_| ChainError::Config("invalid block height encoding".into()))?,
            );
            if height < start {
                continue;
            }
            let record: StoredBlock = bincode::deserialize(&value)?;
            records.push(record);
        }
        records.sort_by_key(|record| record.height());
        Ok(records)
    }

    pub fn prune_block_payload(&self, height: u64) -> ChainResult<bool> {
        let mut kv = self.kv.lock();
        let key = block_key(height);
        let Some(value) = kv.get(&key) else {
            return Ok(false);
        };
        let mut record: StoredBlock = bincode::deserialize(&value)?;
        if record.payload.is_none() {
            return Ok(false);
        }
        record.prune_payload();
        let data = bincode::serialize(&record)?;
        kv.put(key, data);
        kv.commit()?;
        Ok(true)
    }

    pub fn persist_account(&self, account: &Account) -> ChainResult<()> {
        let update = StateUpdate {
            schema: SCHEMA_ACCOUNTS.to_string(),
            key: account.address.as_bytes().to_vec(),
            value: Some(bincode::serialize(account)?),
        };
        let _ = self.apply_state_updates(None, vec![update])?;
        Ok(())
    }

    pub fn read_account(&self, address: &str) -> ChainResult<Option<Account>> {
        let kv = self.kv.lock();
        match kv.get(&account_key(address)) {
            Some(value) => Ok(Some(bincode::deserialize(&value)?)),
            None => Ok(None),
        }
    }

    pub fn load_accounts(&self) -> ChainResult<Vec<Account>> {
        let kv = self.kv.lock();
        let entries: Vec<(Vec<u8>, Vec<u8>)> = kv.scan_prefix(&[PREFIX_ACCOUNT]).collect();
        drop(kv);
        let mut accounts = Vec::new();
        for (_key, value) in entries {
            accounts.push(bincode::deserialize::<Account>(&value)?);
        }
        accounts.sort_by(|a, b| a.address.cmp(&b.address));
        Ok(accounts)
    }

    pub fn tip(&self) -> ChainResult<Option<BlockMetadata>> {
        let kv = self.kv.lock();
        if let Some(metadata) = kv.get(&metadata_key(TIP_METADATA_KEY)) {
            let mut metadata: BlockMetadata = bincode::deserialize(&metadata)?;
            drop(kv);
            self.populate_metadata_from_block(metadata.height, &mut metadata)?;
            return Ok(Some(metadata));
        }

        let Some(height_bytes) = kv.get(&metadata_key(TIP_HEIGHT_KEY)) else {
            return Ok(None);
        };
        let hash_bytes = kv
            .get(&metadata_key(TIP_HASH_KEY))
            .ok_or_else(|| ChainError::Config("missing tip hash".into()))?;
        let timestamp_bytes = kv
            .get(&metadata_key(TIP_TIMESTAMP_KEY))
            .ok_or_else(|| ChainError::Config("missing tip timestamp".into()))?;
        let height = u64::from_be_bytes(
            height_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ChainError::Config("invalid tip height encoding".into()))?,
        );
        let hash = String::from_utf8(hash_bytes.to_vec())
            .map_err(|err| ChainError::Config(format!("invalid tip hash encoding: {err}")))?;
        let timestamp = u64::from_be_bytes(
            timestamp_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ChainError::Config("invalid tip timestamp encoding".into()))?,
        );

        let block_bytes = kv
            .get(&block_key(height))
            .ok_or_else(|| ChainError::Config("missing tip block record".into()))?;
        let record: StoredBlock = bincode::deserialize(&block_bytes)?;
        let block = record.into_block();
        let mut metadata = BlockMetadata::from(&block);
        metadata.height = height;
        metadata.hash = hash;
        metadata.timestamp = timestamp;
        Self::hydrate_metadata_from_block(&block, &mut metadata);
        if metadata.proof_hash.is_empty() {
            metadata.proof_hash = block.header.proof_root;
        }
        Ok(Some(metadata))
    }
}

impl Storage {
    fn populate_metadata_from_block(
        &self,
        height: u64,
        metadata: &mut BlockMetadata,
    ) -> ChainResult<()> {
        if let Some(record) = self.read_block_record(height)? {
            let block = record.into_block();
            Self::hydrate_metadata_from_block(&block, metadata);
        }
        Ok(())
    }

    fn hydrate_metadata_from_block(block: &Block, metadata: &mut BlockMetadata) {
        if metadata.height == 0 {
            metadata.height = block.header.height;
        }
        if metadata.hash.is_empty() {
            metadata.hash = block.hash.clone();
        }
        if metadata.timestamp == 0 {
            metadata.timestamp = block.header.timestamp;
        }
        if metadata.proof_hash.is_empty() {
            metadata.proof_hash = block.header.proof_root.clone();
        }
        let pruning = block.pruning_proof.envelope_metadata();
        if metadata.previous_state_root.is_empty() {
            metadata.previous_state_root = pruning.snapshot.state_commitment.as_str().to_owned();
        }
        if metadata.new_state_root.is_empty() {
            metadata.new_state_root = block.header.state_root.clone();
        }
        if metadata.pruning.is_none() {
            metadata.pruning = Some(pruning);
        }
    }
}

impl Clone for Storage {
    fn clone(&self) -> Self {
        Self {
            kv: self.kv.clone(),
            pruner: self.pruner.clone(),
        }
    }
}

fn block_key(height: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 8);
    key.push(PREFIX_BLOCK);
    key.extend_from_slice(&height.to_be_bytes());
    key
}

fn account_key(address: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + address.len());
    key.push(PREFIX_ACCOUNT);
    key.extend_from_slice(address.as_bytes());
    key
}

fn metadata_key(suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + suffix.len());
    key.push(PREFIX_METADATA);
    key.extend_from_slice(suffix);
    key
}

fn global_instance_suffix(chain_id: &str, block_height: u64, block_hash: &str) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(
        GLOBAL_INSTANCE_PREFIX.len() + chain_id.len() + block_hash.len() + 1 + 16 + 1,
    );
    suffix.extend_from_slice(GLOBAL_INSTANCE_PREFIX);
    suffix.extend_from_slice(chain_id.as_bytes());
    suffix.push(b'/');
    suffix.extend_from_slice(format!("{block_height:016x}").as_bytes());
    suffix.push(b'/');
    suffix.extend_from_slice(block_hash.as_bytes());
    suffix
}

fn global_instance_chain_prefix(chain_id: &str) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(GLOBAL_INSTANCE_PREFIX.len() + chain_id.len() + 1);
    suffix.extend_from_slice(GLOBAL_INSTANCE_PREFIX);
    suffix.extend_from_slice(chain_id.as_bytes());
    suffix.push(b'/');
    suffix
}

fn global_proof_suffix(chain_id: &str, tip_height: u64, tip_hash: &str) -> Vec<u8> {
    let mut suffix =
        Vec::with_capacity(GLOBAL_PROOF_PREFIX.len() + chain_id.len() + tip_hash.len() + 18);
    suffix.extend_from_slice(GLOBAL_PROOF_PREFIX);
    suffix.extend_from_slice(chain_id.as_bytes());
    suffix.push(b'/');
    suffix.extend_from_slice(format!("{tip_height:016x}").as_bytes());
    suffix.push(b'/');
    suffix.extend_from_slice(tip_hash.as_bytes());
    suffix
}

fn block_metadata_suffix(height: u64) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(BLOCK_METADATA_PREFIX.len() + 8);
    suffix.extend_from_slice(BLOCK_METADATA_PREFIX);
    suffix.extend_from_slice(&height.to_be_bytes());
    suffix
}

fn pruning_proof_suffix(height: u64) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(PRUNING_PROOF_PREFIX.len() + 8);
    suffix.extend_from_slice(PRUNING_PROOF_PREFIX);
    suffix.extend_from_slice(&height.to_be_bytes());
    suffix
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ConsensusCertificate;
    use crate::reputation::Tier;
    use crate::rpp::{ModuleWitnessBundle, ProofArtifact};
    use crate::state::merkle::compute_merkle_root;
    use crate::stwo::circuit::{
        pruning::PruningWitness, recursive::RecursiveWitness, state::StateWitness, ExecutionTrace,
    };
    use crate::stwo::params::{FieldElement, StarkParameters};
    use crate::stwo::proof::{
        CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
    };
    use crate::types::{
        pruning_from_previous, Block, BlockHeader, BlockMetadata, BlockProofBundle, ChainProof,
        PruningProof, RecursiveProof,
    };
    use crate::zk::backend_interface::ProofVersion;
    use ed25519_dalek::Signature;
    use hex;
    use rpp_pruning::{
        TaggedDigest, DIGEST_LENGTH, DOMAIN_TAG_LENGTH, ENVELOPE_TAG, PROOF_SEGMENT_TAG,
    };
    use serde::Deserialize;
    use std::sync::Arc;
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
    };
    use storage_firewood::api::StateUpdate;
    use tempfile::tempdir;

    #[test]
    fn pruning_proofs_are_arc_wrapped() {
        let temp_dir = tempdir().expect("tempdir");
        let storage = Storage::open(temp_dir.path()).expect("open storage");

        let empty_receipt = storage
            .apply_state_updates(Some(1), Vec::new())
            .expect("apply empty updates");
        let empty_clone = empty_receipt.clone();
        let empty_proof = empty_receipt
            .pruning_proof
            .expect("empty updates pruning proof");
        let empty_proof_clone = empty_clone
            .pruning_proof
            .expect("empty updates pruning proof clone");
        assert!(Arc::ptr_eq(&empty_proof, &empty_proof_clone));

        let update = StateUpdate {
            schema: SCHEMA_ACCOUNTS.to_string(),
            key: b"arc-wrapper".to_vec(),
            value: Some(vec![0u8]),
        };
        let receipt = storage
            .apply_state_updates(Some(2), vec![update])
            .expect("apply state updates");
        let receipt_clone = receipt.clone();
        let proof = receipt.pruning_proof.expect("state updates pruning proof");
        let proof_clone = receipt_clone
            .pruning_proof
            .expect("state updates pruning proof clone");
        assert!(Arc::ptr_eq(&proof, &proof_clone));

        let snapshot_receipt = storage
            .apply_account_snapshot(Some(3), &[])
            .expect("apply account snapshot");
        let snapshot_clone = snapshot_receipt.clone();
        let snapshot_proof = snapshot_receipt
            .pruning_proof
            .expect("account snapshot pruning proof");
        let snapshot_proof_clone = snapshot_clone
            .pruning_proof
            .expect("account snapshot pruning proof clone");
        assert!(Arc::ptr_eq(&snapshot_proof, &snapshot_proof_clone));
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
                required_tier: Tier::Tl0,
                reputation_weights: crate::reputation::ReputationWeights::default(),
            }),
            trace: ExecutionTrace {
                segments: Vec::new(),
            },
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
        }
    }

    #[test]
    fn global_instances_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let storage = Storage::open(dir.path()).expect("open storage");
        let instance = GlobalInstance::from_state_and_rpp(7, b"state", b"rpp");
        let chain_id = "chain-A";
        let block_hash = "block-hash";

        storage
            .persist_global_instance_by_block(chain_id, 42, block_hash, &instance)
            .expect("persist instance");
        storage
            .persist_global_instance_by_block(chain_id, 100, "other-hash", &instance)
            .expect("persist instance outside range");

        let loaded = storage
            .load_global_instance_by_block(chain_id, 42, block_hash)
            .expect("load instance")
            .expect("instance present");
        assert_eq!(loaded, instance);

        let iterated = storage
            .iter_global_instances_in_range(chain_id, 40, 60)
            .expect("iterate instances");
        assert_eq!(iterated.len(), 1);
        assert_eq!(iterated[0].block_height, 42);
        assert_eq!(iterated[0].block_hash, block_hash);
        assert_eq!(iterated[0].instance, instance);
    }

    #[test]
    fn global_proof_persistence_is_optional() {
        let dir = tempdir().expect("tempdir");
        let storage = Storage::open(dir.path()).expect("open storage");
        let chain_id = "chain-B";
        let tip_hash = "tip-hash";

        storage
            .persist_global_proof_by_tip(chain_id, 5, tip_hash, 3, None)
            .expect("skip optional proof");
        assert!(storage
            .load_global_proof_by_tip(chain_id, 5, tip_hash)
            .expect("load optional proof")
            .is_none());

        let proof = GlobalProof::new(b"ic", b"proof-bytes", b"vk", ProofVersion::AggregatedV1)
            .expect("construct proof");
        storage
            .persist_global_proof_by_tip(chain_id, 5, tip_hash, 4, Some(&proof))
            .expect("persist proof");

        let loaded = storage
            .load_global_proof_by_tip(chain_id, 5, tip_hash)
            .expect("load proof")
            .expect("proof present");
        assert_eq!(loaded.produced_at_height, 4);
        assert_eq!(loaded.proof, proof);
    }

    fn dummy_pruning_proof() -> StarkProof {
        let parameters = StarkParameters::blueprint_default();
        let hasher = parameters.poseidon_hasher();
        let zero = FieldElement::zero(parameters.modulus());
        let pruning_binding_digest =
            TaggedDigest::new(ENVELOPE_TAG, [0x44; DIGEST_LENGTH]).prefixed_bytes();
        let pruning_segment_commitments =
            vec![TaggedDigest::new(PROOF_SEGMENT_TAG, [0x55; DIGEST_LENGTH]).prefixed_bytes()];
        let pruning_fold = {
            let mut accumulator = zero.clone();
            let binding_element = parameters.element_from_bytes(&pruning_binding_digest);
            accumulator = hasher.hash(&[accumulator.clone(), binding_element, zero.clone()]);
            for digest in &pruning_segment_commitments {
                let element = parameters.element_from_bytes(digest);
                accumulator = hasher.hash(&[accumulator.clone(), element, zero.clone()]);
            }
            accumulator.to_hex()
        };

        StarkProof {
            kind: ProofKind::Pruning,
            commitment: "44".repeat(32),
            public_inputs: Vec::new(),
            payload: ProofPayload::Pruning(PruningWitness {
                previous_tx_root: "55".repeat(32),
                pruned_tx_root: "66".repeat(32),
                original_transactions: Vec::new(),
                removed_transactions: Vec::new(),
                pruning_binding_digest,
                pruning_segment_commitments,
                pruning_fold,
            }),
            trace: ExecutionTrace {
                segments: Vec::new(),
            },
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
        }
    }

    #[derive(Deserialize)]
    enum WalRecord {
        Put { key: Vec<u8>, value: Vec<u8> },
        Delete { key: Vec<u8> },
        Commit { root: [u8; 32] },
    }

    fn truncate_last_commit(path: &std::path::Path) -> ChainResult<()> {
        let mut file = OpenOptions::new().read(true).open(path)?;
        let mut offsets = Vec::new();
        let mut cursor = 0u64;

        loop {
            let mut len_buf = [0u8; 4];
            match file.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(ChainError::Io(err)),
            }

            let len = u32::from_le_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            file.read_exact(&mut buf)?;

            let record: WalRecord = bincode::deserialize(&buf)?;
            offsets.push((cursor, 4 + len as u64, record));
            cursor += 4 + len as u64;
        }

        let Some((offset, _, WalRecord::Commit { .. })) = offsets.pop() else {
            return Ok(());
        };

        drop(file);
        let mut writable = OpenOptions::new().write(true).open(path)?;
        writable.set_len(offset)?;
        writable.flush()?;
        Ok(())
    }

    #[test]
    fn pruner_state_recovers_after_partial_commit() -> ChainResult<()> {
        let temp_dir = tempdir()?;
        fs::create_dir_all(temp_dir.path())?;

        let storage = Storage::open(temp_dir.path())?;

        let receipt_one = storage.apply_state_updates(
            Some(1),
            vec![StateUpdate {
                schema: SCHEMA_ACCOUNTS.to_string(),
                key: b"alice".to_vec(),
                value: Some(vec![1, 2, 3]),
            }],
        )?;
        let proof_one = receipt_one
            .pruning_proof
            .clone()
            .expect("pruning proof for first block");
        let _ = storage.persist_pruning_proof(1, &proof_one)?;
        let root_one = receipt_one.new_root;

        drop(storage);

        let storage = Storage::open(temp_dir.path())?;
        let receipt_two = storage.apply_state_updates(
            Some(2),
            vec![StateUpdate {
                schema: SCHEMA_ACCOUNTS.to_string(),
                key: b"alice".to_vec(),
                value: None,
            }],
        )?;
        let proof_two = receipt_two
            .pruning_proof
            .clone()
            .expect("pruning proof for second block");
        let _ = storage.persist_pruning_proof(2, &proof_two)?;
        drop(storage);

        let wal_path = temp_dir.path().join("firewood.wal");
        truncate_last_commit(&wal_path)?;

        let storage = Storage::open(temp_dir.path())?;
        let resumed_root = storage.state_root()?;
        assert_eq!(resumed_root, root_one, "partial commit should roll back");

        let account = storage.read_account("alice")?;
        assert!(account.is_some(), "account data must survive rollback");

        assert!(storage.load_pruning_proof(1)?.is_some());
        assert!(storage.load_pruning_proof(2)?.is_none());

        Ok(())
    }

    fn dummy_recursive_proof(
        previous_commitment: Option<String>,
        aggregated_commitment: String,
        header: &BlockHeader,
        pruning: &PruningProof,
    ) -> StarkProof {
        let previous_commitment = previous_commitment.or_else(|| Some(RecursiveProof::anchor()));
        let pruning_binding_digest = pruning.binding_digest().prefixed_bytes();
        let pruning_segment_commitments = pruning
            .segments()
            .iter()
            .map(|segment| segment.segment_commitment().prefixed_bytes())
            .collect();
        StarkProof {
            kind: ProofKind::Recursive,
            commitment: aggregated_commitment.clone(),
            public_inputs: Vec::new(),
            payload: ProofPayload::Recursive(RecursiveWitness {
                previous_commitment,
                aggregated_commitment,
                identity_commitments: Vec::new(),
                tx_commitments: Vec::new(),
                uptime_commitments: Vec::new(),
                consensus_commitments: Vec::new(),
                state_commitment: header.state_root.clone(),
                global_state_root: header.state_root.clone(),
                utxo_root: header.utxo_root.clone(),
                reputation_root: header.reputation_root.clone(),
                timetoke_root: header.timetoke_root.clone(),
                zsi_root: header.zsi_root.clone(),
                proof_root: header.proof_root.clone(),
                pruning_binding_digest,
                pruning_segment_commitments,
                block_height: header.height,
            }),
            trace: ExecutionTrace {
                segments: Vec::new(),
            },
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
        }
    }

    fn make_block(height: u64, previous: Option<&Block>) -> Block {
        let previous_hash = previous
            .map(|block| block.hash.clone())
            .unwrap_or_else(|| hex::encode([0u8; 32]));
        let mut tx_leaves: Vec<[u8; 32]> = Vec::new();
        let tx_root = hex::encode(compute_merkle_root(&mut tx_leaves));
        let state_root = hex::encode([height as u8 + 2; 32]);
        let utxo_root = hex::encode([height as u8 + 3; 32]);
        let reputation_root = hex::encode([height as u8 + 4; 32]);
        let timetoke_root = hex::encode([height as u8 + 5; 32]);
        let zsi_root = hex::encode([height as u8 + 6; 32]);
        let proof_root = hex::encode([height as u8 + 7; 32]);
        let header = BlockHeader::new(
            height,
            previous_hash,
            tx_root,
            state_root,
            utxo_root,
            reputation_root,
            timetoke_root,
            zsi_root,
            proof_root,
            "0".to_string(),
            height.to_string(),
            format!("vrfpk{:02}", height),
            format!("preout{:02}", height),
            format!("vrf{:02}", height),
            format!("proposer{:02}", height),
            Tier::Tl3.to_string(),
            height,
        );
        let pruning_proof = pruning_from_previous(previous, &header);
        let aggregated_commitment = hex::encode([height as u8 + 8; 32]);
        let previous_recursive_commitment =
            previous.map(|block| block.recursive_proof.commitment.clone());
        let recursive_stark = dummy_recursive_proof(
            previous_recursive_commitment.clone(),
            aggregated_commitment.clone(),
            &header,
            &pruning_proof,
        );
        let recursive_chain_proof = ChainProof::Stwo(recursive_stark.clone());
        let recursive_proof = match previous {
            Some(prev) => RecursiveProof::extend(
                &prev.recursive_proof,
                &header,
                &pruning_proof,
                &recursive_chain_proof,
            )
            .expect("recursive extend"),
            None => RecursiveProof::genesis(&header, &pruning_proof, &recursive_chain_proof)
                .expect("recursive genesis"),
        };
        let state_stark = dummy_state_proof();
        let pruning_stark = dummy_pruning_proof();
        let module_witnesses = ModuleWitnessBundle::default();
        let proof_artifacts = module_witnesses
            .expected_artifacts()
            .expect("expected artifacts")
            .into_iter()
            .map(|(module, commitment, payload)| ProofArtifact {
                module,
                commitment,
                proof: payload,
                verification_key: None,
            })
            .collect();
        let stark_bundle = BlockProofBundle::new(
            Vec::new(),
            ChainProof::Stwo(state_stark),
            ChainProof::Stwo(pruning_stark),
            recursive_chain_proof,
        );
        let signature = Signature::from_bytes(&[0u8; 64]).expect("signature bytes");
        let mut consensus = ConsensusCertificate::genesis();
        consensus.round = height;
        Block::new(
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
            consensus,
            None,
        )
    }

    #[test]
    fn tip_metadata_persists_receipt_fields() {
        let temp_dir = tempdir().expect("tempdir");
        let storage = Storage::open(temp_dir.path()).expect("open storage");
        let genesis = make_block(0, None);
        let mut metadata = BlockMetadata::from(&genesis);
        metadata.previous_state_root = "aa".repeat(32);
        metadata.new_state_root = "bb".repeat(32);
        metadata.proof_hash = "dd".repeat(32);
        storage
            .store_block(&genesis, &metadata)
            .expect("store genesis");
        drop(storage);

        let reopened = Storage::open(temp_dir.path()).expect("reopen storage");
        let tip = reopened.tip().expect("tip").expect("metadata");
        assert_eq!(tip.height, 0);
        assert_eq!(tip.hash, genesis.hash);
        assert_eq!(tip.previous_state_root, metadata.previous_state_root);
        assert_eq!(tip.new_state_root, metadata.new_state_root);
        assert_eq!(tip.proof_hash, metadata.proof_hash);
        assert_eq!(tip.pruning, metadata.pruning);
        assert_eq!(tip.recursive_commitment, metadata.recursive_commitment);
        assert_eq!(tip.recursive_anchor, metadata.recursive_anchor);
    }

    #[test]
    fn tip_metadata_falls_back_when_serialized_entry_missing() {
        let temp_dir = tempdir().expect("tempdir");
        let storage = Storage::open(temp_dir.path()).expect("open storage");
        let genesis = make_block(0, None);
        let metadata = BlockMetadata::from(&genesis);
        storage
            .store_block(&genesis, &metadata)
            .expect("store genesis");
        {
            let mut kv = storage.kv.lock();
            kv.delete(&metadata_key(TIP_METADATA_KEY));
            kv.commit().expect("commit deletion");
        }
        let tip = storage.tip().expect("tip").expect("metadata");
        assert_eq!(tip.height, 0);
        assert_eq!(tip.hash, genesis.hash);
        assert_eq!(tip.timestamp, genesis.header.timestamp);
        assert_eq!(
            tip.previous_state_root,
            genesis.pruning_proof.snapshot_state_root_hex()
        );
        assert_eq!(tip.new_state_root, genesis.header.state_root);
        assert_eq!(tip.proof_hash, genesis.header.proof_root);
        let pruning = tip.pruning_metadata().expect("pruning metadata");
        assert_eq!(
            tip.pruning_binding_digest,
            genesis.pruning_proof.binding_digest().prefixed_bytes()
        );
        let expected_segments: Vec<_> = genesis
            .pruning_proof
            .segments()
            .iter()
            .map(|segment| segment.segment_commitment().prefixed_bytes())
            .collect();
        assert_eq!(tip.pruning_segment_commitments, expected_segments);
        let expected_binding = hex::encode(genesis.pruning_proof.binding_digest().prefixed_bytes());
        assert_eq!(pruning.binding_digest.as_str(), expected_binding);
        let expected_commitment = hex::encode(
            genesis
                .pruning_proof
                .aggregate_commitment()
                .prefixed_bytes(),
        );
        assert_eq!(
            pruning.commitment.aggregate_commitment.as_str(),
            expected_commitment
        );
        assert_eq!(
            pruning.schema_version,
            genesis.pruning_proof.schema_version()
        );
        assert_eq!(
            pruning.parameter_version,
            genesis.pruning_proof.parameter_version()
        );
        assert_eq!(tip.recursive_commitment, genesis.recursive_proof.commitment);
    }

    #[test]
    fn block_metadata_roundtrip_with_backfill() {
        let temp_dir = tempdir().expect("tempdir");
        let storage = Storage::open(temp_dir.path()).expect("open storage");
        let genesis = make_block(0, None);
        let mut metadata = BlockMetadata::from(&genesis);
        metadata.proof_hash.clear();
        storage
            .store_block(&genesis, &metadata)
            .expect("store block");

        let loaded = storage
            .read_block_metadata(genesis.header.height)
            .expect("read metadata")
            .expect("metadata exists");
        assert_eq!(loaded.height, genesis.header.height);
        assert_eq!(loaded.hash, genesis.hash);
        assert_eq!(loaded.timestamp, genesis.header.timestamp);
        assert_eq!(loaded.proof_hash, genesis.header.proof_root);
        assert_eq!(
            loaded.previous_state_root,
            genesis.pruning_proof.snapshot_state_root_hex()
        );
        assert_eq!(loaded.new_state_root, genesis.header.state_root);
        assert_eq!(
            loaded.pruning_binding_digest,
            genesis.pruning_proof.binding_digest().prefixed_bytes()
        );
        let expected_segments: Vec<_> = genesis
            .pruning_proof
            .segments()
            .iter()
            .map(|segment| segment.segment_commitment().prefixed_bytes())
            .collect();
        assert_eq!(loaded.pruning_segment_commitments, expected_segments);
        let pruning = loaded.pruning_metadata().expect("pruning metadata");
        let expected_binding = hex::encode(genesis.pruning_proof.binding_digest().prefixed_bytes());
        assert_eq!(pruning.binding_digest.as_str(), expected_binding);
        let expected_commitment = hex::encode(
            genesis
                .pruning_proof
                .aggregate_commitment()
                .prefixed_bytes(),
        );
        assert_eq!(
            pruning.commitment.aggregate_commitment.as_str(),
            expected_commitment
        );
        assert_eq!(
            pruning.schema_version,
            genesis.pruning_proof.schema_version()
        );
        assert_eq!(
            pruning.parameter_version,
            genesis.pruning_proof.parameter_version()
        );
    }
}
