use std::collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet};
use std::mem;

use crate::proof_backend::Blake2sHasher;
use parking_lot::RwLock;

use crate::consensus::ValidatorProfile as ConsensusValidatorProfile;
use crate::consensus_engine::state::{TreasuryAccounts, WitnessPoolWeights};
use crate::crypto::{public_key_from_hex, sign_message, signature_to_hex};
use crate::errors::{ChainError, ChainResult};
use crate::identity_tree::{IdentityCommitmentProof, IdentityCommitmentTree, IDENTITY_TREE_DEPTH};
use crate::proof_system::ProofVerifierRegistry;
use crate::reputation::{self, ReputationParams, Tier, TierRequirementError, TimetokeParams};
use crate::rpp::{
    AccountBalanceWitness, BlockWitness, BlockWitnessBuilder, ConsensusApproval, ConsensusWitness,
    GlobalStateCommitments, MerklePathWitness, ModuleWitnessBundle, ProofArtifact,
    ReputationEventKind, ReputationRecord, ReputationWitness, TimetokeRecord, TimetokeWitness,
    TransactionUtxoSnapshot, TransactionWitness, UtxoOutpoint, UtxoRecord, ZsiRecord, ZsiWitness,
};
use crate::state::{
    GlobalState, ProofRegistry, ReputationState, StoredUtxo, TimetokeState, UtxoState, ZsiRegistry,
};
use crate::types::{
    Account, Address, AttestedIdentityRequest, SignedTransaction, Stake, UptimeProof,
    WalletBindingChange,
};
use crate::vrf::{VrfProof, VrfSelectionRecord};
use ed25519_dalek::{Keypair, PublicKey};
use hex;
use serde::{Deserialize, Serialize};

const EPOCH_NONCE_DOMAIN: &[u8] = b"rpp-epoch-nonce";

#[derive(Clone, Debug)]
struct EpochState {
    epoch: u64,
    nonce: [u8; 32],
    used_vrf_tags: HashSet<String>,
}

impl EpochState {
    fn new(epoch: u64, nonce: [u8; 32]) -> Self {
        Self {
            epoch,
            nonce,
            used_vrf_tags: HashSet::new(),
        }
    }
}

pub const DEFAULT_EPOCH_LENGTH: u64 = 720;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlashingReason {
    InvalidIdentity,
    InvalidVote,
    ConsensusFault,
}

impl SlashingReason {
    fn penalty_percent(self) -> u8 {
        match self {
            SlashingReason::InvalidIdentity => 50,
            SlashingReason::InvalidVote => 25,
            SlashingReason::ConsensusFault => 10,
        }
    }
}

pub struct Ledger {
    global_state: GlobalState,
    utxo_state: UtxoState,
    reputation_state: ReputationState,
    timetoke_state: TimetokeState,
    zsi_registry: ZsiRegistry,
    proof_registry: ProofRegistry,
    module_witnesses: RwLock<ModuleWitnessBook>,
    identity_tree: RwLock<IdentityCommitmentTree>,
    epoch_length: u64,
    epoch_state: RwLock<EpochState>,
    slashing_log: RwLock<Vec<SlashingEvent>>,
    vrf_history: RwLock<HashMap<u64, Vec<VrfHistoryRecord>>>,
    vrf_history_tags: RwLock<HashMap<u64, HashSet<String>>>,
    reputation_params: ReputationParams,
    timetoke_params: TimetokeParams,
    treasury_accounts: RwLock<TreasuryAccounts>,
    witness_pool_weights: RwLock<WitnessPoolWeights>,
    reward_shortfall: RwLock<u128>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEvent {
    pub address: Address,
    pub reason: SlashingReason,
    pub penalty_percent: u8,
    pub timestamp: u64,
    pub evidence_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationAudit {
    pub address: Address,
    pub balance: u128,
    pub stake: String,
    pub score: f64,
    pub tier: Tier,
    pub uptime_hours: u64,
    pub consensus_success: u64,
    pub peer_feedback: i64,
    pub last_decay_timestamp: u64,
    pub zsi_validated: bool,
    pub zsi_commitment: String,
    pub zsi_reputation_proof: Option<String>,
    pub evidence_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl ReputationAudit {
    pub fn from_account(account: &Account) -> Self {
        Self {
            address: account.address.clone(),
            balance: account.balance,
            stake: account.stake.to_string(),
            score: account.reputation.score,
            tier: account.reputation.tier.clone(),
            uptime_hours: account.reputation.timetokes.hours_online,
            consensus_success: account.reputation.consensus_success,
            peer_feedback: account.reputation.peer_feedback,
            last_decay_timestamp: account.reputation.last_decay_timestamp,
            zsi_validated: account.reputation.zsi.validated,
            zsi_commitment: account.reputation.zsi.public_key_commitment.clone(),
            zsi_reputation_proof: account.reputation.zsi.reputation_proof.clone(),
            evidence_hash: reputation_evidence_hash(account),
            signature: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochInfo {
    pub epoch: u64,
    pub epoch_nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VrfHistoryRecord {
    pub epoch: u64,
    pub round: u64,
    pub address: Address,
    pub tier: Tier,
    pub timetoke_hours: u64,
    pub public_key: Option<String>,
    pub proof: VrfProof,
    pub verified: bool,
    pub accepted: bool,
    pub threshold: Option<String>,
    pub rejection_reason: Option<String>,
    pub weight: Option<String>,
    pub weighted_randomness: Option<String>,
}

impl Ledger {
    pub fn new(epoch_length: u64) -> Self {
        let ledger = Self {
            global_state: GlobalState::new(),
            utxo_state: UtxoState::new(),
            reputation_state: ReputationState::new(),
            timetoke_state: TimetokeState::new(),
            zsi_registry: ZsiRegistry::new(),
            proof_registry: ProofRegistry::new(),
            module_witnesses: RwLock::new(ModuleWitnessBook::default()),
            identity_tree: RwLock::new(IdentityCommitmentTree::new(IDENTITY_TREE_DEPTH)),
            epoch_length: epoch_length.max(1),
            epoch_state: RwLock::new(EpochState::new(u64::MAX, [0u8; 32])),
            slashing_log: RwLock::new(Vec::new()),
            vrf_history: RwLock::new(HashMap::new()),
            vrf_history_tags: RwLock::new(HashMap::new()),
            reputation_params: ReputationParams::default(),
            timetoke_params: TimetokeParams::default(),
            treasury_accounts: RwLock::new(TreasuryAccounts::default()),
            witness_pool_weights: RwLock::new(WitnessPoolWeights::default()),
            reward_shortfall: RwLock::new(0),
        };
        ledger.sync_epoch_for_height(0);
        ledger
    }

    pub fn configure_reward_pools(&self, accounts: TreasuryAccounts, weights: WitnessPoolWeights) {
        *self.treasury_accounts.write() = accounts;
        *self.witness_pool_weights.write() = weights;
    }

    pub fn set_reputation_params(&mut self, params: ReputationParams) {
        self.reputation_params = params;
    }

    pub fn set_timetoke_params(&mut self, params: TimetokeParams) {
        self.timetoke_params = params;
    }

    pub fn reputation_params(&self) -> ReputationParams {
        self.reputation_params.clone()
    }

    pub fn timetoke_params(&self) -> TimetokeParams {
        self.timetoke_params.clone()
    }

    pub fn reward_shortfall(&self) -> u128 {
        *self.reward_shortfall.read()
    }

    pub fn load(
        initial: Vec<Account>,
        utxo_snapshots: Vec<(UtxoOutpoint, StoredUtxo)>,
        epoch_length: u64,
    ) -> Self {
        let ledger = Ledger::new(epoch_length);
        let mut tree = ledger.identity_tree.write();
        for account in initial {
            tree.force_insert(
                &account.address,
                &account.reputation.zsi.public_key_commitment,
            )
            .expect("genesis identity commitment");
            ledger.global_state.upsert(account.clone());
            ledger.index_account_modules(&account);
        }
        drop(tree);
        for (outpoint, stored) in utxo_snapshots {
            ledger.utxo_state.insert(outpoint, stored);
        }
        ledger.sync_epoch_for_height(0);
        ledger
    }

    pub fn upsert_account(&self, account: Account) -> ChainResult<()> {
        let new_commitment = account.reputation.zsi.public_key_commitment.clone();
        let address = account.address.clone();
        let previous_commitment = self
            .global_state
            .upsert(account.clone())
            .map(|existing| existing.reputation.zsi.public_key_commitment);
        self.index_account_modules(&account);
        let mut tree = self.identity_tree.write();
        tree.replace_commitment(&address, previous_commitment.as_deref(), &new_commitment)?;
        Ok(())
    }

    pub fn identity_commitment_proof(&self, wallet_addr: &str) -> IdentityCommitmentProof {
        self.identity_tree.read().proof_for(wallet_addr)
    }

    pub fn get_account(&self, address: &str) -> Option<Account> {
        self.global_state.get(address)
    }

    pub fn accounts_snapshot(&self) -> Vec<Account> {
        self.global_state.accounts_snapshot()
    }

    pub fn utxos_for_owner(&self, address: &Address) -> Vec<UtxoRecord> {
        self.utxo_state.unspent_outputs_for_owner(address)
    }

    pub fn select_inputs_for_transaction(
        &self,
        tx: &SignedTransaction,
    ) -> ChainResult<Vec<UtxoOutpoint>> {
        let sender_account = self
            .get_account(tx.payload.from.as_str())
            .ok_or_else(|| ChainError::Transaction("transaction sender account missing".into()))?;
        let thresholds = &self.reputation_params.tier_thresholds;
        let minimum_tier = reputation::minimum_transaction_tier(thresholds);
        let derived_tier =
            reputation::transaction_tier_requirement(&sender_account.reputation, thresholds)
                .map_err(map_tier_requirement_error)?;
        if sender_account.reputation.tier < minimum_tier {
            return Err(ChainError::Transaction(format!(
                "transaction requires at least {:?}, account tier {:?}",
                minimum_tier, sender_account.reputation.tier
            )));
        }
        let required_tier = derived_tier.max(minimum_tier);
        if sender_account.reputation.tier < required_tier {
            return Err(ChainError::Transaction(format!(
                "transaction requires at least {:?}, account tier {:?}",
                required_tier, sender_account.reputation.tier
            )));
        }
        let required_value = tx
            .payload
            .amount
            .checked_add(tx.payload.fee as u128)
            .ok_or_else(|| ChainError::Transaction("transaction amount overflow".into()))?;
        let mut total: u128 = 0;
        let mut selected = Vec::new();
        for record in self.utxo_state.unspent_outputs_for_owner(&tx.payload.from) {
            total = total
                .checked_add(record.value)
                .ok_or_else(|| ChainError::Transaction("transaction input overflow".into()))?;
            selected.push(record.outpoint.clone());
            if total >= required_value {
                break;
            }
        }
        if total < required_value {
            return Err(ChainError::Transaction(
                "insufficient input value for transaction".into(),
            ));
        }
        if selected.is_empty() {
            return Err(ChainError::Transaction(
                "transaction requires available inputs".into(),
            ));
        }
        Ok(selected)
    }

    pub fn validator_public_key(&self, address: &str) -> ChainResult<PublicKey> {
        let account = self.get_account(address).ok_or_else(|| {
            ChainError::Crypto("validator account missing for signature verification".into())
        })?;
        let key_hex = account.identity.wallet_public_key.ok_or_else(|| {
            ChainError::Crypto("validator wallet public key not registered".into())
        })?;
        public_key_from_hex(&key_hex)
    }

    pub fn timetoke_snapshot(&self) -> Vec<TimetokeRecord> {
        let now = reputation::current_timestamp();
        let mut accounts = self.global_state.write_accounts();
        let mut records = Vec::new();
        let mut touched = Vec::new();
        for account in accounts.values_mut() {
            let mut updated = false;
            if account
                .reputation
                .timetokes
                .apply_decay(now, &self.timetoke_params)
                .is_some()
            {
                account
                    .reputation
                    .recompute_with_params(&self.reputation_params, now);
                account.reputation.update_decay_reference(now);
                updated = true;
            }
            if account
                .reputation
                .timetokes
                .should_sync(now, &self.timetoke_params)
            {
                account.reputation.timetokes.mark_synced(now);
                records.push(account.reputation.timetokes.as_record(&account.address));
                updated = true;
            }
            if updated {
                touched.push(account.clone());
            }
        }
        drop(accounts);
        for account in &touched {
            self.index_account_modules(account);
        }
        records.sort_by(|a, b| a.identity.cmp(&b.identity));
        records
    }

    pub fn sync_timetoke_records(&self, records: &[TimetokeRecord]) -> ChainResult<Vec<Address>> {
        let mut accounts = self.global_state.write_accounts();
        let mut updated_accounts = Vec::new();
        let now = reputation::current_timestamp();
        for record in records {
            if let Some(account) = accounts.get_mut(&record.identity) {
                if account.reputation.timetokes.merge_snapshot(record) {
                    account
                        .reputation
                        .recompute_with_params(&self.reputation_params, now);
                    account.reputation.update_decay_reference(now);
                    updated_accounts.push(account.clone());
                }
            }
        }
        drop(accounts);
        for account in &updated_accounts {
            self.index_account_modules(account);
        }
        Ok(updated_accounts
            .into_iter()
            .map(|account| account.address)
            .collect())
    }

    fn module_records(&self, address: &str) -> ModuleRecordSnapshots {
        let address = address.to_string();
        ModuleRecordSnapshots {
            utxo: TransactionUtxoSets::default(),
            reputation: self.reputation_state.get(&address),
            timetoke: self.timetoke_state.get(&address),
            zsi: self.zsi_registry.get(&address),
        }
    }

    pub fn stake_snapshot(&self) -> Vec<(Address, Stake)> {
        self.global_state.stake_snapshot()
    }

    pub fn ensure_node_binding(
        &self,
        address: &str,
        wallet_public_key_hex: &str,
    ) -> ChainResult<()> {
        let (binding_change, updated_account) = {
            let mut accounts = self.global_state.write_accounts();
            let account = accounts.get_mut(address).ok_or_else(|| {
                ChainError::Config("node account missing for identity binding".into())
            })?;
            let change = account.ensure_wallet_binding(wallet_public_key_hex)?;
            account.bind_node_identity()?;
            (change, account.clone())
        };
        let WalletBindingChange { previous, current } = binding_change;
        let mut tree = self.identity_tree.write();
        tree.replace_commitment(address, previous.as_deref(), &current)?;
        self.index_account_modules(&updated_account);
        Ok(())
    }

    pub fn slash_validator(
        &self,
        address: &str,
        reason: SlashingReason,
        signer: Option<&Keypair>,
    ) -> ChainResult<SlashingEvent> {
        let module_before = self.module_records(address);
        let (timestamp, updated_account) = {
            let mut accounts = self.global_state.write_accounts();
            let account = accounts.get_mut(address).ok_or_else(|| {
                ChainError::Transaction("validator account missing for slashing".into())
            })?;
            account.stake.slash_percent(reason.penalty_percent());
            account.reputation.zsi.invalidate();
            account.reputation.tier = Tier::Tl0;
            account.reputation.score = 0.0;
            account.reputation.consensus_success = 0;
            account.reputation.peer_feedback = 0;
            account.reputation.timetokes = reputation::TimetokeBalance::default();
            account.reputation.last_decay_timestamp = reputation::current_timestamp();
            let timestamp = account.reputation.last_decay_timestamp;
            (timestamp, account.clone())
        };
        let mut log = self.slashing_log.write();
        let penalty_percent = reason.penalty_percent();
        let evidence_hash = slashing_evidence_hash(address, reason, penalty_percent, timestamp);
        let signature = signer.map(|signer| {
            let signature = sign_message(signer, evidence_hash.as_bytes());
            signature_to_hex(&signature)
        });
        let event = SlashingEvent {
            address: address.to_string(),
            reason,
            penalty_percent,
            timestamp,
            evidence_hash,
            signature,
        };
        log.push(event.clone());
        self.index_account_modules(&updated_account);
        let module_after = self.module_records(address);
        if let Some(reputation_after) = module_after.reputation.clone() {
            let mut book = self.module_witnesses.write();
            book.record_reputation(ReputationWitness::new(
                updated_account.address.clone(),
                ReputationEventKind::Slashing,
                module_before.reputation,
                reputation_after,
            ));
        }
        Ok(event)
    }

    pub fn sync_epoch_for_height(&self, height: u64) {
        let target_epoch = height / self.epoch_length;
        {
            let state = self.epoch_state.read();
            if state.epoch == target_epoch {
                return;
            }
        }
        let new_state = self.build_epoch_state(target_epoch);
        let mut state = self.epoch_state.write();
        *state = new_state;
    }

    fn build_epoch_state(&self, epoch: u64) -> EpochState {
        let state_root = self.state_root();
        let nonce = derive_epoch_nonce(epoch, &state_root);
        EpochState::new(epoch, nonce)
    }

    pub fn current_epoch(&self) -> u64 {
        self.epoch_state.read().epoch
    }

    pub fn current_epoch_nonce(&self) -> [u8; 32] {
        self.epoch_state.read().nonce
    }

    pub fn epoch_info(&self) -> EpochInfo {
        let state = self.epoch_state.read();
        EpochInfo {
            epoch: state.epoch,
            epoch_nonce: hex::encode(state.nonce),
        }
    }

    pub fn register_identity(
        &self,
        request: &AttestedIdentityRequest,
        expected_height: u64,
        quorum_threshold: usize,
        min_gossip: usize,
    ) -> ChainResult<()> {
        let outcome = request.verify(expected_height, quorum_threshold, min_gossip)?;
        let declaration = &request.declaration;
        let genesis = &declaration.genesis;
        let key_commitment = genesis.public_key_commitment()?;
        {
            let commitments = self.identity_tree.read();
            if commitments.contains_commitment(&key_commitment) {
                return Err(ChainError::Transaction(
                    "identity already registered for this public key".into(),
                ));
            }
        }
        {
            let accounts = self.global_state.read_accounts();
            if accounts.contains_key(&genesis.wallet_addr) {
                return Err(ChainError::Transaction(
                    "wallet address already associated with an identity".into(),
                ));
            }
        }

        let current_state_root = hex::encode(self.state_root());
        if current_state_root != genesis.state_root {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated state root".into(),
            ));
        }
        let current_identity_root = hex::encode(self.identity_root());
        if current_identity_root != genesis.identity_root {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated identity root".into(),
            ));
        }

        if !genesis.commitment_proof.is_vacant()? {
            return Err(ChainError::Transaction(
                "identity commitment slot already occupied".into(),
            ));
        }

        {
            let tree = self.identity_tree.read();
            let current_leaf = tree.leaf_hex(&genesis.wallet_addr);
            if current_leaf != genesis.commitment_proof.leaf {
                return Err(ChainError::Transaction(
                    "identity declaration proof does not match ledger state".into(),
                ));
            }
            let proof_root = genesis
                .commitment_proof
                .compute_root(&genesis.wallet_addr)?;
            if proof_root != genesis.identity_root {
                return Err(ChainError::Transaction(
                    "identity commitment proof does not reconstruct the identity root".into(),
                ));
            }
        }

        let timestamp = reputation::current_timestamp();
        let approvals: ChainResult<Vec<ConsensusApproval>> = outcome
            .approved_votes
            .iter()
            .map(|vote| {
                let signature = hex::decode(&vote.signature).map_err(|err| {
                    ChainError::Transaction(format!(
                        "invalid consensus approval signature encoding: {err}"
                    ))
                })?;
                Ok(ConsensusApproval {
                    validator: vote.vote.voter.clone(),
                    signature,
                    timestamp,
                })
            })
            .collect();
        let approvals = approvals?;
        for validator in &outcome.slashable_validators {
            self.slash_validator(validator, SlashingReason::InvalidVote, None)?;
        }

        let mut account = Account::new(genesis.wallet_addr.clone(), 0, Stake::default());
        account.reputation = crate::reputation::ReputationProfile::new(&genesis.wallet_pk);
        account.ensure_wallet_binding(&genesis.wallet_pk)?;
        account
            .reputation
            .bind_genesis_identity(declaration.commitment());

        {
            let state = self.epoch_state.read();
            let expected_nonce = hex::encode(state.nonce);
            if expected_nonce != genesis.epoch_nonce {
                return Err(ChainError::Transaction(
                    "identity declaration references an outdated epoch nonce".into(),
                ));
            }
        }
        if !self.register_vrf_tag(genesis.vrf_tag()) {
            return Err(ChainError::Transaction(
                "VRF tag already registered for this epoch".into(),
            ));
        }
        let module_before = self.module_records(&genesis.wallet_addr);
        self.upsert_account(account.clone())?;
        self.zsi_registry
            .upsert_with_approvals(&account, approvals.clone());
        let module_after = self.module_records(&genesis.wallet_addr);
        {
            let mut book = self.module_witnesses.write();
            if let Some(zsi_after) = module_after.zsi.clone() {
                book.record_zsi(ZsiWitness::new(
                    account.address.clone(),
                    module_before.zsi.clone(),
                    zsi_after,
                ));
            }
            if let Some(reputation_after) = module_after.reputation.clone() {
                book.record_reputation(ReputationWitness::new(
                    account.address.clone(),
                    ReputationEventKind::IdentityOnboarding,
                    module_before.reputation,
                    reputation_after,
                ));
            }
        }
        Ok(())
    }

    pub fn identity_root(&self) -> [u8; 32] {
        self.identity_tree.read().root()
    }

    pub fn apply_uptime_proof(&self, proof: &UptimeProof) -> ChainResult<u64> {
        if proof.window_end <= proof.window_start {
            return Err(ChainError::Transaction(
                "uptime proof window end must be greater than start".into(),
            ));
        }
        if proof.window_end.saturating_sub(proof.window_start) < 3_600 {
            return Err(ChainError::Transaction(
                "uptime proof must cover at least one hour".into(),
            ));
        }
        if !proof.verify_commitment() {
            return Err(ChainError::Transaction(
                "uptime proof commitment mismatch".into(),
            ));
        }
        let zk_proof = proof.proof().map_err(|_| {
            ChainError::Transaction("uptime proof must include a zk payload".into())
        })?;
        let registry = ProofVerifierRegistry::default();
        registry.verify_uptime(zk_proof)?;
        let claim = proof.claim()?;
        if claim.wallet_address != proof.wallet_address {
            return Err(ChainError::Transaction(
                "uptime proof wallet address mismatch".into(),
            ));
        }
        let module_before = self.module_records(&proof.wallet_address);
        let (credited_hours, updated_account) = {
            let mut accounts = self.global_state.write_accounts();
            let account = accounts.get_mut(&proof.wallet_address).ok_or_else(|| {
                ChainError::Transaction("uptime proof references unknown account".into())
            })?;
            if !account.reputation.zsi.validated {
                return Err(ChainError::Transaction(
                    "uptime proof requires a validated genesis identity".into(),
                ));
            }
            let credited = account
                .reputation
                .record_online_proof(proof.window_start, proof.window_end, &self.timetoke_params)
                .ok_or_else(|| {
                    ChainError::Transaction(
                        "uptime proof does not extend the recorded online window".into(),
                    )
                })?;
            if credited == 0 {
                return Err(ChainError::Transaction(
                    "uptime proof does not extend the recorded online window".into(),
                ));
            }
            let now = crate::reputation::current_timestamp();
            account
                .reputation
                .recompute_with_params(&self.reputation_params, now);
            account.reputation.update_decay_reference(now);
            (credited, account.clone())
        };
        self.index_account_modules(&updated_account);
        let module_after = self.module_records(&proof.wallet_address);
        {
            let mut book = self.module_witnesses.write();
            if let Some(timetoke_after) = module_after.timetoke.clone() {
                book.record_timetoke(TimetokeWitness::new(
                    proof.wallet_address.clone(),
                    module_before.timetoke.clone(),
                    timetoke_after,
                    proof.window_start,
                    proof.window_end,
                    credited_hours,
                ));
            }
            if let Some(reputation_after) = module_after.reputation.clone() {
                book.record_reputation(ReputationWitness::new(
                    proof.wallet_address.clone(),
                    ReputationEventKind::TimetokeAccrual,
                    module_before.reputation,
                    reputation_after,
                ));
            }
        }
        Ok(credited_hours)
    }

    pub fn apply_transaction(
        &self,
        tx: &SignedTransaction,
        inputs: &[UtxoOutpoint],
    ) -> ChainResult<u64> {
        tx.verify()?;
        let tx_id = tx.hash();
        let mut unique_inputs = BTreeSet::new();
        let mut sender_inputs = Vec::new();
        let mut total_input_value: u128 = 0;
        for outpoint in inputs {
            if !unique_inputs.insert(outpoint.clone()) {
                return Err(ChainError::Transaction(
                    "duplicate transaction input".into(),
                ));
            }
            let record = self
                .utxo_state
                .get(outpoint)
                .ok_or_else(|| ChainError::Transaction("transaction input not found".into()))?;
            if record.owner != tx.payload.from {
                return Err(ChainError::Transaction(
                    "transaction input not owned by sender".into(),
                ));
            }
            total_input_value = total_input_value
                .checked_add(record.value)
                .ok_or_else(|| ChainError::Transaction("transaction input overflow".into()))?;
            sender_inputs.push(TransactionUtxoSnapshot::new(
                outpoint.clone(),
                StoredUtxo::new(record.owner.clone(), record.value),
            ));
        }
        if sender_inputs.is_empty() {
            return Err(ChainError::Transaction(
                "transaction requires at least one input".into(),
            ));
        }

        let required_value = tx
            .payload
            .amount
            .checked_add(tx.payload.fee as u128)
            .ok_or_else(|| ChainError::Transaction("transaction amount overflow".into()))?;
        if total_input_value < required_value {
            return Err(ChainError::Transaction(
                "transaction inputs do not cover amount and fee".into(),
            ));
        }
        let change_value = total_input_value - required_value;

        let mut module_sender_before = self.module_records(&tx.payload.from);
        module_sender_before.utxo = TransactionUtxoSets::with_inputs(sender_inputs.clone());
        let mut module_recipient_before = self.module_records(&tx.payload.to);
        module_recipient_before.utxo = TransactionUtxoSets::default();
        let now = crate::reputation::current_timestamp();
        let (binding_change, sender_before, sender_after, recipient_before, recipient_after) = {
            let mut accounts = self.global_state.write_accounts();
            let (binding_change, sender_before, sender_after) = {
                let sender = accounts
                    .get_mut(&tx.payload.from)
                    .ok_or_else(|| ChainError::Transaction("sender account not found".into()))?;
                let binding_change = sender.ensure_wallet_binding(&tx.public_key)?;
                if sender.nonce + 1 != tx.payload.nonce {
                    return Err(ChainError::Transaction("invalid nonce".into()));
                }
                if sender.balance < required_value {
                    return Err(ChainError::Transaction("insufficient balance".into()));
                }
                let before = sender.clone();
                sender.balance -= required_value;
                sender.nonce += 1;
                sender
                    .reputation
                    .recompute_with_params(&self.reputation_params, now);
                sender.reputation.update_decay_reference(now);
                let after = sender.clone();
                (binding_change, before, after)
            };

            let (recipient_before, recipient_after) = match accounts.entry(tx.payload.to.clone()) {
                Entry::Occupied(mut existing) => {
                    let recipient = existing.get_mut();
                    let before = recipient.clone();
                    recipient.balance = recipient.balance.saturating_add(tx.payload.amount);
                    recipient
                        .reputation
                        .recompute_with_params(&self.reputation_params, now);
                    recipient.reputation.update_decay_reference(now);
                    (Some(before), recipient.clone())
                }
                Entry::Vacant(entry) => {
                    let mut account = Account::new(tx.payload.to.clone(), 0, Stake::default());
                    account.balance = tx.payload.amount;
                    account
                        .reputation
                        .recompute_with_params(&self.reputation_params, now);
                    account.reputation.update_decay_reference(now);
                    let inserted = entry.insert(account);
                    (None, inserted.clone())
                }
            };
            (
                binding_change,
                sender_before,
                sender_after,
                recipient_before,
                recipient_after,
            )
        };
        for outpoint in inputs {
            if !self.utxo_state.remove_spent(outpoint) {
                return Err(ChainError::Transaction(
                    "transaction input already spent".into(),
                ));
            }
        }
        let WalletBindingChange { previous, current } = binding_change;
        let mut tree = self.identity_tree.write();
        tree.replace_commitment(&tx.payload.from, previous.as_deref(), &current)?;
        drop(tree);
        let mut accounts_for_update = vec![sender_after.clone()];
        if sender_after.address != recipient_after.address {
            accounts_for_update.push(recipient_after.clone());
        }
        for account in &accounts_for_update {
            self.reputation_state.upsert_from_account(account);
            self.timetoke_state.upsert_from_account(account);
            self.zsi_registry.upsert_from_account(account);
        }

        let mut utxo_outputs: Vec<(UtxoOutpoint, StoredUtxo)> = Vec::new();
        if tx.payload.amount > 0 {
            utxo_outputs.push((
                UtxoOutpoint {
                    tx_id,
                    index: utxo_outputs.len() as u32,
                },
                StoredUtxo::new(recipient_after.address.clone(), tx.payload.amount),
            ));
        }
        if change_value > 0 {
            utxo_outputs.push((
                UtxoOutpoint {
                    tx_id,
                    index: utxo_outputs.len() as u32,
                },
                StoredUtxo::new(sender_after.address.clone(), change_value),
            ));
        }
        let mut sender_outputs = Vec::new();
        let mut recipient_outputs = Vec::new();
        for (outpoint, stored) in &utxo_outputs {
            self.utxo_state.insert(outpoint.clone(), stored.clone());
            let snapshot = TransactionUtxoSnapshot::new(outpoint.clone(), stored.clone());
            if stored.owner == sender_after.address {
                sender_outputs.push(snapshot.clone());
            }
            if stored.owner == recipient_after.address {
                recipient_outputs.push(snapshot);
            }
        }

        let mut sender_modules_after = self.module_records(&tx.payload.from);
        sender_modules_after.utxo =
            TransactionUtxoSets::new(sender_inputs.clone(), sender_outputs.clone());
        let mut recipient_modules_after = self.module_records(&tx.payload.to);
        recipient_modules_after.utxo = TransactionUtxoSets::with_outputs(recipient_outputs.clone());

        let sender_before_witness = AccountBalanceWitness::new(
            sender_before.address.clone(),
            sender_before.balance,
            sender_before.nonce,
        );
        let sender_after_witness = AccountBalanceWitness::new(
            sender_after.address.clone(),
            sender_after.balance,
            sender_after.nonce,
        );
        let recipient_before_witness = recipient_before.as_ref().map(|account| {
            AccountBalanceWitness::new(account.address.clone(), account.balance, account.nonce)
        });
        let recipient_after_witness = AccountBalanceWitness::new(
            recipient_after.address.clone(),
            recipient_after.balance,
            recipient_after.nonce,
        );
        let tx_witness = TransactionWitness::new(
            tx_id,
            tx.payload.fee,
            sender_before_witness,
            sender_after_witness,
            recipient_before_witness,
            recipient_after_witness,
            module_sender_before.utxo.inputs.clone(),
            sender_modules_after.utxo.outputs.clone(),
            module_recipient_before.utxo.inputs.clone(),
            recipient_modules_after.utxo.outputs.clone(),
        );
        let sender_reputation_witness = sender_modules_after.reputation.clone().map(|after| {
            ReputationWitness::new(
                sender_after.address.clone(),
                ReputationEventKind::TransferDebit,
                module_sender_before.reputation,
                after,
            )
        });
        let recipient_reputation_witness =
            recipient_modules_after.reputation.clone().map(|after| {
                ReputationWitness::new(
                    recipient_after.address.clone(),
                    ReputationEventKind::TransferCredit,
                    module_recipient_before.reputation,
                    after,
                )
            });

        {
            let mut book = self.module_witnesses.write();
            book.record_transaction(tx_witness);
            if let Some(witness) = sender_reputation_witness {
                book.record_reputation(witness);
            }
            if let Some(witness) = recipient_reputation_witness {
                book.record_reputation(witness);
            }
        }

        self.credit_fee_pool_account(tx.payload.fee);

        Ok(tx.payload.fee)
    }

    pub fn reward_proposer(&self, address: &str, reward: u64) -> ChainResult<()> {
        self.reward_with_source(address, reward, RewardSource::Validator)
    }

    pub fn distribute_witness_payouts(&self, payouts: &BTreeMap<Address, u64>) -> ChainResult<()> {
        for (address, reward) in payouts {
            self.reward_with_source(address, *reward, RewardSource::Witness)?;
        }
        Ok(())
    }

    pub fn distribute_consensus_rewards(
        &self,
        leader: &Address,
        validators: &[ConsensusValidatorProfile],
        base_reward: u64,
        leader_bonus_percent: u8,
    ) -> ChainResult<()> {
        if validators.is_empty() {
            return Ok(());
        }

        let validator_count = validators.len() as u64;
        let base_share = base_reward / validator_count;
        let mut remainder = base_reward.saturating_sub(base_share * validator_count);

        let leader_bonus = if leader_bonus_percent == 0 {
            0
        } else {
            let raw = (u128::from(base_reward) * u128::from(leader_bonus_percent)) + 99;
            (raw / 100).min(u128::from(u64::MAX)) as u64
        };

        let mut ordered: Vec<_> = validators.to_vec();
        ordered.sort_by(|a, b| {
            b.tier
                .cmp(&a.tier)
                .then(b.timetoke_hours.cmp(&a.timetoke_hours))
                .then(b.randomness.cmp(&a.randomness))
                .then(a.address.cmp(&b.address))
        });

        let mut leader_rewarded = false;
        for profile in ordered {
            let mut payout = base_share;
            if remainder > 0 {
                payout = payout.saturating_add(1);
                remainder -= 1;
            }
            if &profile.address == leader {
                payout = payout.saturating_add(leader_bonus);
                leader_rewarded = true;
            }
            self.reward_proposer(&profile.address, payout)?;
        }

        if !leader_rewarded && leader_bonus > 0 {
            self.reward_proposer(leader, leader_bonus)?;
        }

        Ok(())
    }

    fn reward_with_source(
        &self,
        address: &str,
        reward: u64,
        source: RewardSource,
    ) -> ChainResult<()> {
        let module_before = self.module_records(address);
        let paid = self.withdraw_reward(reward, source);
        let updated_account = {
            let mut accounts = self.global_state.write_accounts();
            match accounts.entry(address.to_string()) {
                Entry::Occupied(mut entry) => {
                    let account = entry.get_mut();
                    account.bind_node_identity()?;
                    account.balance = account.balance.saturating_add(paid as u128);
                    account.reputation.record_consensus_success();
                    let now = crate::reputation::current_timestamp();
                    account
                        .reputation
                        .recompute_with_params(&self.reputation_params, now);
                    account.reputation.update_decay_reference(now);
                    account.clone()
                }
                Entry::Vacant(entry) => {
                    let mut account = Account::new(address.to_string(), 0, Stake::default());
                    account.bind_node_identity()?;
                    account.balance = account.balance.saturating_add(paid as u128);
                    account.reputation.record_consensus_success();
                    let now = crate::reputation::current_timestamp();
                    account
                        .reputation
                        .recompute_with_params(&self.reputation_params, now);
                    account.reputation.update_decay_reference(now);
                    let inserted = entry.insert(account);
                    inserted.clone()
                }
            }
        };
        self.index_account_modules(&updated_account);
        let module_after = self.module_records(address);
        if let Some(reputation_after) = module_after.reputation.clone() {
            let mut book = self.module_witnesses.write();
            book.record_reputation(ReputationWitness::new(
                updated_account.address.clone(),
                ReputationEventKind::ConsensusReward,
                module_before.reputation,
                reputation_after,
            ));
        }
        Ok(())
    }

    fn withdraw_reward(&self, reward: u64, source: RewardSource) -> u64 {
        if reward == 0 {
            return 0;
        }

        let accounts = self.treasury_accounts.read().clone();
        let weights = *self.witness_pool_weights.read();

        let (treasury_target, fee_target) = match source {
            RewardSource::Validator => (reward, 0),
            RewardSource::Witness => weights.split(reward),
        };

        let treasury_address = match source {
            RewardSource::Validator => accounts.validator_account().to_string(),
            RewardSource::Witness => accounts.witness_account().to_string(),
        };
        let fee_address = accounts.fee_account().to_string();

        let mut covered = self.withdraw_from_account(&treasury_address, treasury_target as u128);
        let mut remaining = (reward as u128).saturating_sub(covered);

        let fee_allocation = (fee_target as u128).saturating_add(remaining);
        if fee_allocation > 0 {
            let fee_withdrawn = self.withdraw_from_account(&fee_address, fee_allocation);
            covered = covered.saturating_add(fee_withdrawn);
            remaining = (reward as u128).saturating_sub(covered);
        }

        if remaining > 0 {
            let mut shortfall = self.reward_shortfall.write();
            *shortfall = shortfall.saturating_add(remaining);
        }

        covered.min(reward as u128) as u64
    }

    fn withdraw_from_account(&self, address: &str, amount: u128) -> u128 {
        if address.is_empty() || amount == 0 {
            return 0;
        }

        let mut updated: Option<Account> = None;
        let mut withdrawn = 0u128;
        {
            let mut accounts = self.global_state.write_accounts();
            if let Some(account) = accounts.get_mut(address) {
                let take = account.balance.min(amount);
                if take > 0 {
                    account.balance -= take;
                    withdrawn = take;
                    updated = Some(account.clone());
                }
            }
        }
        if let Some(account) = updated {
            self.index_account_modules(&account);
        }
        withdrawn
    }

    fn credit_fee_pool_account(&self, amount: u64) {
        if amount == 0 {
            return;
        }
        let address = self.treasury_accounts.read().fee_account().to_string();
        if address.is_empty() {
            return;
        }
        let updated_account = {
            let mut accounts = self.global_state.write_accounts();
            match accounts.entry(address.clone()) {
                Entry::Occupied(mut entry) => {
                    let account = entry.get_mut();
                    account.balance = account.balance.saturating_add(amount as u128);
                    Some(account.clone())
                }
                Entry::Vacant(entry) => {
                    let mut account = Account::new(address.clone(), 0, Stake::default());
                    account.balance = amount as u128;
                    Some(entry.insert(account).clone())
                }
            }
        };
        if let Some(account) = updated_account {
            self.index_account_modules(&account);
        }
    }

    pub fn global_commitments(&self) -> GlobalStateCommitments {
        GlobalStateCommitments {
            global_state_root: self.state_root(),
            utxo_root: self.utxo_state.commitment(),
            reputation_root: self.reputation_state.commitment(),
            timetoke_root: self.timetoke_state.commitment(),
            zsi_root: self.zsi_registry.commitment(),
            proof_root: self.proof_registry.commitment(),
        }
    }

    pub fn drain_module_witnesses(&self) -> ModuleWitnessBundle {
        self.module_witnesses.write().drain()
    }

    pub fn register_vrf_tag(&self, tag: &str) -> bool {
        self.epoch_state
            .write()
            .used_vrf_tags
            .insert(tag.to_string())
    }

    pub fn record_vrf_history(&self, epoch: u64, round: u64, records: &[VrfSelectionRecord]) {
        if records.is_empty() {
            return;
        }
        let mut tags = self.vrf_history_tags.write();
        let tag_set = tags.entry(epoch).or_default();
        let mut history = self.vrf_history.write();
        let bucket = history.entry(epoch).or_default();
        for record in records {
            let tag = record.proof.proof.clone();
            if !tag_set.insert(tag) {
                continue;
            }
            bucket.push(VrfHistoryRecord {
                epoch,
                round,
                address: record.address.clone(),
                tier: record.tier.clone(),
                timetoke_hours: record.timetoke_hours,
                public_key: record.public_key.clone(),
                proof: record.proof.clone(),
                verified: record.verified,
                accepted: record.accepted,
                threshold: record.threshold.clone(),
                rejection_reason: record.rejection_reason.clone(),
                weight: record.weight.clone(),
                weighted_randomness: record.weighted_randomness.clone(),
            });
        }
    }

    pub fn vrf_history(&self, epoch: Option<u64>) -> Vec<VrfHistoryRecord> {
        let history = self.vrf_history.read();
        match epoch {
            Some(epoch) => history.get(&epoch).cloned().unwrap_or_default(),
            None => {
                let mut entries: Vec<VrfHistoryRecord> = history
                    .values()
                    .flat_map(|records| records.clone())
                    .collect();
                entries.sort_by(|a, b| {
                    a.epoch
                        .cmp(&b.epoch)
                        .then_with(|| a.round.cmp(&b.round))
                        .then_with(|| a.address.cmp(&b.address))
                });
                entries
            }
        }
    }

    pub fn stage_module_witnesses(
        &self,
        bundle: &ModuleWitnessBundle,
    ) -> ChainResult<Vec<ProofArtifact>> {
        let artifacts = bundle
            .expected_artifacts()?
            .into_iter()
            .map(|(module, commitment, payload)| ProofArtifact {
                module,
                commitment,
                proof: payload,
                verification_key: None,
            })
            .collect::<Vec<_>>();
        for artifact in &artifacts {
            self.proof_registry.register(artifact.clone());
        }
        Ok(artifacts)
    }

    pub fn record_consensus_witness(&self, bundle: &crate::consensus::ConsensusWitnessBundle) {
        let participants: Vec<Address> = bundle.participants.iter().cloned().collect();
        let witness = ConsensusWitness::new(
            bundle.height,
            bundle.round,
            participants,
            bundle.vrf_entries.clone(),
            bundle.vrf_outputs.clone(),
            bundle.vrf_proofs.clone(),
            bundle.witness_commitments.clone(),
            bundle.reputation_roots.clone(),
            bundle.epoch,
            bundle.slot,
            bundle.quorum_bitmap_root.clone(),
            bundle.quorum_signature_root.clone(),
            bundle.bindings.clone(),
        );
        let mut book = self.module_witnesses.write();
        book.record_consensus(witness);
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.global_state.state_root()
    }

    pub fn slashing_events(&self, limit: usize) -> Vec<SlashingEvent> {
        let log = self.slashing_log.read();
        let start = log.len().saturating_sub(limit);
        log[start..].to_vec()
    }

    pub fn reputation_audit(&self, address: &str) -> ChainResult<Option<ReputationAudit>> {
        let accounts = self.global_state.read_accounts();
        Ok(accounts
            .get(address)
            .map(|account| ReputationAudit::from_account(account)))
    }

    fn index_account_modules(&self, account: &Account) {
        self.reputation_state.upsert_from_account(account);
        self.timetoke_state.upsert_from_account(account);
        self.zsi_registry.upsert_from_account(account);
    }
}

fn map_tier_requirement_error(err: TierRequirementError) -> ChainError {
    match err {
        TierRequirementError::MissingZsiValidation => {
            ChainError::Transaction("wallet identity must be ZSI-validated".into())
        }
        TierRequirementError::InsufficientTimetoke {
            required,
            available,
        } => ChainError::Transaction(format!(
            "timetoke balance {available}h below required {required}h for transaction"
        )),
    }
}

fn reputation_evidence_hash(account: &Account) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(account.address.as_bytes());
    data.extend_from_slice(&account.balance.to_be_bytes());
    data.extend_from_slice(account.stake.to_string().as_bytes());
    data.extend_from_slice(&account.reputation.score.to_be_bytes());
    data.push(account.reputation.tier as u8);
    data.extend_from_slice(&account.reputation.timetokes.hours_online.to_be_bytes());
    data.extend_from_slice(&account.reputation.consensus_success.to_be_bytes());
    data.extend_from_slice(&account.reputation.peer_feedback.to_be_bytes());
    data.extend_from_slice(&account.reputation.last_decay_timestamp.to_be_bytes());
    data.push(account.reputation.zsi.validated as u8);
    data.extend_from_slice(account.reputation.zsi.public_key_commitment.as_bytes());
    if let Some(proof) = &account.reputation.zsi.reputation_proof {
        data.extend_from_slice(proof.as_bytes());
    }
    hex::encode::<[u8; 32]>(Blake2sHasher::hash(&data).into())
}

fn slashing_evidence_hash(
    address: &str,
    reason: SlashingReason,
    penalty_percent: u8,
    timestamp: u64,
) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(address.as_bytes());
    data.push(reason as u8);
    data.push(penalty_percent);
    data.extend_from_slice(&timestamp.to_be_bytes());
    hex::encode::<[u8; 32]>(Blake2sHasher::hash(&data).into())
}

#[derive(Default, Clone)]
struct ModuleRecordSnapshots {
    utxo: TransactionUtxoSets,
    reputation: Option<ReputationRecord>,
    timetoke: Option<TimetokeRecord>,
    zsi: Option<ZsiRecord>,
}

#[derive(Default, Clone)]
struct TransactionUtxoSets {
    inputs: Vec<TransactionUtxoSnapshot>,
    outputs: Vec<TransactionUtxoSnapshot>,
}

impl TransactionUtxoSets {
    fn new(inputs: Vec<TransactionUtxoSnapshot>, outputs: Vec<TransactionUtxoSnapshot>) -> Self {
        Self { inputs, outputs }
    }

    fn with_inputs(inputs: Vec<TransactionUtxoSnapshot>) -> Self {
        Self {
            inputs,
            outputs: Vec::new(),
        }
    }

    fn with_outputs(outputs: Vec<TransactionUtxoSnapshot>) -> Self {
        Self {
            inputs: Vec::new(),
            outputs,
        }
    }
}

#[derive(Clone, Copy)]
enum RewardSource {
    Validator,
    Witness,
}

#[derive(Default)]
struct ModuleWitnessBook {
    block: Option<BlockWitness>,
    transactions: Vec<TransactionWitness>,
    timetoke: Vec<TimetokeWitness>,
    reputation: Vec<ReputationWitness>,
    zsi: Vec<ZsiWitness>,
    consensus: Vec<ConsensusWitness>,
}

impl ModuleWitnessBook {
    fn record_block(&mut self, witness: BlockWitness) {
        self.block = Some(witness);
    }

    fn record_transaction(&mut self, witness: TransactionWitness) {
        self.transactions.push(witness);
    }

    fn record_timetoke(&mut self, witness: TimetokeWitness) {
        self.timetoke.push(witness);
    }

    fn record_reputation(&mut self, witness: ReputationWitness) {
        self.reputation.push(witness);
    }

    fn record_zsi(&mut self, witness: ZsiWitness) {
        self.zsi.push(witness);
    }

    fn record_consensus(&mut self, witness: ConsensusWitness) {
        self.consensus.push(witness);
    }

    fn drain(&mut self) -> ModuleWitnessBundle {
        let transactions = mem::take(&mut self.transactions);
        let block = self.block.take().or_else(|| {
            let paths = (0..transactions.len())
                .map(|_| MerklePathWitness::new(0, Vec::new()))
                .collect::<ChainResult<Vec<_>>>();

            let paths = match paths {
                Ok(paths) => paths,
                Err(_) => return None,
            };

            BlockWitnessBuilder::new()
                .with_expected_path_depth(0)
                .with_transactions(transactions.clone())
                .with_transaction_paths(paths)
                .with_pruning_proofs(Vec::new())
                .build()
                .ok()
        });

        ModuleWitnessBundle {
            block,
            transactions,
            timetoke: mem::take(&mut self.timetoke),
            reputation: mem::take(&mut self.reputation),
            zsi: mem::take(&mut self.zsi),
            consensus: mem::take(&mut self.consensus),
        }
    }
}

fn derive_epoch_nonce(epoch: u64, state_root: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(EPOCH_NONCE_DOMAIN.len() + 8 + state_root.len());
    data.extend_from_slice(EPOCH_NONCE_DOMAIN);
    data.extend_from_slice(&epoch.to_le_bytes());
    data.extend_from_slice(state_root);
    Blake2sHasher::hash(&data).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    mod rewards {
        use super::*;
        use crate::consensus_engine::state::{TreasuryAccounts, WitnessPoolWeights};
        use std::collections::BTreeMap;

        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/rpp/storage/tests/rewards.rs"
        ));
    }
    use crate::consensus::{evaluate_vrf, BftVote, BftVoteKind, SignedBftVote};
    use crate::crypto::{address_from_public_key, generate_vrf_keypair, vrf_public_key_to_hex};
    use crate::proof_backend::Blake2sHasher;
    use crate::rpp::{
        AccountBalanceWitness, ConsensusWitness, ModuleWitnessBundle, ProofModule,
        ReputationEventKind, ReputationRecord, ReputationWitness, TierDescriptor, TimetokeRecord,
        TimetokeWitness, TransactionWitness, ZsiRecord, ZsiWitness,
    };
    use crate::storage::Storage;
    use crate::stwo::circuit::identity::{IdentityCircuit, IdentityWitness};
    use crate::stwo::circuit::string_to_field;
    use crate::stwo::circuit::StarkCircuit;
    use crate::stwo::fri::FriProver;
    use crate::stwo::params::StarkParameters;
    use crate::stwo::proof::{ProofKind, ProofPayload, StarkProof};
    use crate::stwo::prover::WalletProver;
    use crate::types::{
        AttestedIdentityRequest, ChainProof, IdentityDeclaration, IdentityGenesis, IdentityProof,
        SignedTransaction, Transaction, UptimeClaim, UptimeProof, IDENTITY_ATTESTATION_GOSSIP_MIN,
        IDENTITY_ATTESTATION_QUORUM,
    };
    use crate::vrf::{VrfProof, VrfSelectionRecord};
    use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};
    use std::collections::{BTreeMap, HashMap, HashSet};
    use tempfile::tempdir;

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

    fn attested_request(declaration: IdentityDeclaration, height: u64) -> AttestedIdentityRequest {
        let identity_hash = hex::encode(declaration.hash().expect("hash"));
        let voters: Vec<Keypair> = (0..IDENTITY_ATTESTATION_QUORUM)
            .map(|idx| seeded_keypair(10 + idx as u8))
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

    fn build_uptime_proof(address: &str, window_start: u64, window_end: u64) -> UptimeProof {
        let claim = UptimeClaim {
            wallet_address: address.to_string(),
            node_clock: window_end + 60,
            epoch: 1,
            head_hash: "00".repeat(32),
            window_start,
            window_end,
        };
        let temp_dir = tempdir().expect("temporary directory");
        let storage = Storage::open(temp_dir.path()).expect("open storage");
        let prover = WalletProver::new(&storage);
        let witness = prover
            .derive_uptime_witness(&claim)
            .expect("derive uptime witness");
        let proof = ChainProof::Stwo(
            prover
                .prove_uptime_witness(witness)
                .expect("prove uptime witness"),
        );
        UptimeProof::new(claim, proof)
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
        let commitment_hex = genesis.expected_commitment().expect("commitment");
        let witness = IdentityWitness {
            wallet_pk: genesis.wallet_pk.clone(),
            wallet_addr: genesis.wallet_addr.clone(),
            vrf_tag: genesis.vrf_tag().to_string(),
            epoch_nonce: genesis.epoch_nonce.clone(),
            state_root: genesis.state_root.clone(),
            identity_root: genesis.identity_root.clone(),
            initial_reputation: genesis.initial_reputation,
            commitment: commitment_hex.clone(),
            identity_leaf: commitment_proof.leaf.clone(),
            identity_path: commitment_proof.siblings.clone(),
        };
        let parameters = StarkParameters::blueprint_default();
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
                commitment: commitment_hex,
                zk_proof: ChainProof::Stwo(proof),
            },
        }
    }

    #[test]
    fn register_identity_creates_account() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let declaration = sample_identity_declaration(&ledger);
        let height = 1;
        let request = attested_request(declaration.clone(), height);
        ledger
            .register_identity(
                &request,
                height,
                IDENTITY_ATTESTATION_QUORUM,
                IDENTITY_ATTESTATION_GOSSIP_MIN,
            )
            .unwrap();

        let account = ledger
            .get_account(&declaration.genesis.wallet_addr)
            .unwrap();
        assert!(account.reputation.zsi.validated);
        assert_eq!(
            account.reputation.zsi.reputation_proof,
            Some(declaration.proof.commitment.clone())
        );
        assert_eq!(
            account.identity.wallet_public_key,
            Some(declaration.genesis.wallet_pk.clone())
        );
        assert!(account.identity.node_address.is_none());
        assert_eq!(account.reputation.score, 0.0);
        assert_eq!(account.reputation.tier, crate::reputation::Tier::Tl0);
    }

    #[test]
    fn duplicate_identity_rejected() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let declaration = sample_identity_declaration(&ledger);
        let height = 1;
        let request = attested_request(declaration.clone(), height);
        ledger
            .register_identity(
                &request,
                height,
                IDENTITY_ATTESTATION_QUORUM,
                IDENTITY_ATTESTATION_GOSSIP_MIN,
            )
            .unwrap();
        let err = ledger
            .register_identity(
                &attested_request(declaration, height),
                height,
                IDENTITY_ATTESTATION_QUORUM,
                IDENTITY_ATTESTATION_GOSSIP_MIN,
            )
            .unwrap_err();
        assert!(matches!(err, ChainError::Transaction(_)));
    }

    #[test]
    fn register_identity_rejects_insufficient_votes() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let declaration = sample_identity_declaration(&ledger);
        let height = 1;
        let mut request = attested_request(declaration, height);
        request
            .attested_votes
            .truncate(IDENTITY_ATTESTATION_QUORUM - 1);
        let err = ledger
            .register_identity(
                &request,
                height,
                IDENTITY_ATTESTATION_QUORUM,
                IDENTITY_ATTESTATION_GOSSIP_MIN,
            )
            .expect_err("insufficient votes rejected");
        assert!(matches!(err, ChainError::Transaction(_)));
    }

    #[test]
    fn register_identity_rejects_insufficient_gossip() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let declaration = sample_identity_declaration(&ledger);
        let height = 1;
        let mut request = attested_request(declaration, height);
        request
            .gossip_confirmations
            .truncate(IDENTITY_ATTESTATION_GOSSIP_MIN - 1);
        let err = ledger
            .register_identity(
                &request,
                height,
                IDENTITY_ATTESTATION_QUORUM,
                IDENTITY_ATTESTATION_GOSSIP_MIN,
            )
            .expect_err("insufficient gossip rejected");
        assert!(matches!(err, ChainError::Transaction(_)));
    }

    fn deterministic_keypair() -> Keypair {
        seeded_keypair(7)
    }

    #[test]
    fn transaction_binds_wallet_key() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let keypair = deterministic_keypair();
        let address = address_from_public_key(&keypair.public);
        let mut account = Account::new(address.clone(), 1_000, Stake::default());
        let _ = account
            .ensure_wallet_binding(&hex::encode(keypair.public.to_bytes()))
            .unwrap();
        ledger.upsert_account(account).unwrap();

        let recipient = "ff00".repeat(16);
        let tx = Transaction::new(address.clone(), recipient.clone(), 100, 1, 1, None);
        let signature = keypair.sign(&tx.canonical_bytes());
        let signed = SignedTransaction::new(tx, signature, &keypair.public);
        let input = UtxoOutpoint {
            tx_id: [9u8; 32],
            index: 0,
        };
        ledger
            .utxo_state
            .insert(input.clone(), StoredUtxo::new(address.clone(), 150));
        ledger
            .apply_transaction(&signed, &[input])
            .expect("transaction applies");

        let account = ledger.get_account(&address).unwrap();
        assert_eq!(
            account.identity.wallet_public_key,
            Some(hex::encode(keypair.public.to_bytes()))
        );
        assert_eq!(account.nonce, 1);
    }

    #[test]
    fn apply_transaction_updates_utxo_state_consistently() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let sender_kp = deterministic_keypair();
        let sender_address = address_from_public_key(&sender_kp.public);
        let mut sender_account = Account::new(sender_address.clone(), 1_000, Stake::default());
        let sender_pk_hex = hex::encode(sender_kp.public.to_bytes());
        let _ = sender_account
            .ensure_wallet_binding(&sender_pk_hex)
            .expect("bind sender wallet");
        ledger
            .upsert_account(sender_account.clone())
            .expect("insert sender");

        let recipient_address = hex::encode([0x33u8; 32]);
        let recipient_account = Account::new(recipient_address.clone(), 250, Stake::default());
        ledger
            .upsert_account(recipient_account.clone())
            .expect("insert recipient");

        let input_outpoint = UtxoOutpoint {
            tx_id: [0u8; 32],
            index: 0,
        };
        let extra_outpoint = UtxoOutpoint {
            tx_id: [2u8; 32],
            index: 5,
        };
        ledger.utxo_state.insert(
            input_outpoint.clone(),
            StoredUtxo::new(sender_address.clone(), 600),
        );
        ledger.utxo_state.insert(
            extra_outpoint.clone(),
            StoredUtxo::new(sender_address.clone(), 75),
        );

        let initial_commitment = ledger.utxo_state.commitment();
        let canonical_before = ledger.utxo_state.snapshot_for_account(&sender_address);
        assert_eq!(canonical_before.len(), 2);
        assert_eq!(canonical_before[0].0, input_outpoint);
        assert_eq!(canonical_before[1].0, extra_outpoint);
        assert!(canonical_before
            .iter()
            .all(|(_, stored)| !stored.is_spent()));

        let owner_unspent_before = ledger.utxos_for_owner(&sender_address);
        assert_eq!(owner_unspent_before.len(), 2);
        assert_eq!(owner_unspent_before[0].outpoint, input_outpoint);
        assert_eq!(owner_unspent_before[1].outpoint, extra_outpoint);

        let tx = Transaction::new(
            sender_address.clone(),
            recipient_address.clone(),
            150,
            5,
            sender_account.nonce + 1,
            None,
        );
        let signature = sender_kp.sign(&tx.canonical_bytes());
        let signed = SignedTransaction::new(tx, signature, &sender_kp.public);
        let tx_id = signed.hash();

        let fee = ledger
            .apply_transaction(&signed, &[input_outpoint.clone()])
            .expect("apply transaction");
        assert_eq!(fee, 5);

        let snapshot_after = ledger.utxo_state.snapshot();
        let snapshot_map: BTreeMap<_, _> = snapshot_after.iter().cloned().collect();
        assert!(snapshot_map
            .get(&input_outpoint)
            .expect("spent input entry")
            .is_spent());
        assert!(!snapshot_map
            .get(&extra_outpoint)
            .expect("secondary output")
            .is_spent());

        let recipient_outpoint = UtxoOutpoint { tx_id, index: 0 };
        let sender_change_outpoint = UtxoOutpoint { tx_id, index: 1 };

        let recipient_entry = snapshot_map
            .get(&recipient_outpoint)
            .expect("recipient output");
        assert_eq!(recipient_entry.owner, recipient_address);
        assert_eq!(recipient_entry.amount, 150);
        assert!(!recipient_entry.is_spent());

        let sender_entry = snapshot_map
            .get(&sender_change_outpoint)
            .expect("sender change output");
        assert_eq!(sender_entry.owner, sender_address);
        assert_eq!(sender_entry.amount, 445);
        assert!(!sender_entry.is_spent());

        let sender_unspent_after = ledger.utxos_for_owner(&sender_address);
        assert_eq!(sender_unspent_after.len(), 2);
        assert_eq!(sender_unspent_after[0].outpoint, sender_change_outpoint);
        assert_eq!(sender_unspent_after[1].outpoint, extra_outpoint);

        let sender_snapshot = ledger.utxo_state.snapshot_for_account(&sender_address);
        assert_eq!(sender_snapshot.len(), 2);
        assert_eq!(sender_snapshot[0].0, sender_change_outpoint);
        assert_eq!(sender_snapshot[1].0, extra_outpoint);
        assert!(sender_snapshot.iter().all(|(_, stored)| !stored.is_spent()));

        let recipient_unspent_after = ledger.utxos_for_owner(&recipient_address);
        assert_eq!(recipient_unspent_after.len(), 1);
        assert_eq!(recipient_unspent_after[0].outpoint, recipient_outpoint);

        let recipient_snapshot = ledger.utxo_state.snapshot_for_account(&recipient_address);
        assert_eq!(recipient_snapshot.len(), 1);
        assert_eq!(recipient_snapshot[0].0, recipient_outpoint);

        assert_ne!(initial_commitment, ledger.utxo_state.commitment());

        let serialized = bincode::serialize(&snapshot_after).expect("serialize utxo snapshot");
        let restored: Vec<(UtxoOutpoint, StoredUtxo)> =
            bincode::deserialize(&serialized).expect("deserialize utxo snapshot");
        assert_eq!(restored.len(), snapshot_after.len());
        let mirror = UtxoState::new();
        for (outpoint, stored) in restored.iter() {
            mirror.insert(outpoint.clone(), stored.clone());
        }
        assert_eq!(mirror.commitment(), ledger.utxo_state.commitment());

        let sender_snapshot = ledger.utxo_state.snapshot_for_account(&sender_address);
        assert_eq!(sender_snapshot.len(), 2);
        assert_eq!(sender_snapshot[0].0, sender_change_outpoint);
        assert_eq!(sender_snapshot[0].1.amount, 445);
        assert_eq!(sender_snapshot[1].0, extra_outpoint);
        assert_eq!(sender_snapshot[1].1.amount, 75);
        let recipient_snapshot = ledger.utxo_state.snapshot_for_account(&recipient_address);
        assert_eq!(recipient_snapshot.len(), 1);
        assert_eq!(recipient_snapshot[0].0, recipient_outpoint);
        assert_eq!(recipient_snapshot[0].1.amount, 150);
    }

    #[test]
    fn apply_transaction_preserves_existing_recipient_utxos() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let sender_kp = deterministic_keypair();
        let sender_address = address_from_public_key(&sender_kp.public);
        let mut sender_account = Account::new(sender_address.clone(), 1_200, Stake::default());
        let sender_pk_hex = hex::encode(sender_kp.public.to_bytes());
        let _ = sender_account
            .ensure_wallet_binding(&sender_pk_hex)
            .expect("bind sender wallet");
        ledger
            .upsert_account(sender_account.clone())
            .expect("insert sender");

        let recipient_address = hex::encode([0x44u8; 32]);
        let recipient_account = Account::new(recipient_address.clone(), 300, Stake::default());
        ledger
            .upsert_account(recipient_account.clone())
            .expect("insert recipient");
        let recipient_existing_tx_id = [4u8; 32];
        let recipient_existing = UtxoOutpoint {
            tx_id: recipient_existing_tx_id,
            index: 0,
        };
        ledger.utxo_state.insert(
            recipient_existing.clone(),
            StoredUtxo::new(recipient_address.clone(), recipient_account.balance),
        );

        let sender_input = UtxoOutpoint {
            tx_id: [3u8; 32],
            index: 0,
        };
        ledger.utxo_state.insert(
            sender_input.clone(),
            StoredUtxo::new(sender_address.clone(), 700),
        );

        let recipient_before_snapshot = ledger.utxo_state.snapshot_for_account(&recipient_address);
        assert_eq!(recipient_before_snapshot.len(), 1);
        assert_eq!(recipient_before_snapshot[0].0, recipient_existing);

        let tx = Transaction::new(
            sender_address.clone(),
            recipient_address.clone(),
            200,
            6,
            sender_account.nonce + 1,
            None,
        );
        let signature = sender_kp.sign(&tx.canonical_bytes());
        let signed = SignedTransaction::new(tx, signature, &sender_kp.public);
        let tx_id = signed.hash();

        ledger
            .apply_transaction(&signed, &[sender_input.clone()])
            .expect("apply transaction with existing recipient utxo");

        let snapshot_after = ledger.utxo_state.snapshot();
        let snapshot_map: BTreeMap<_, _> = snapshot_after.iter().cloned().collect();
        assert!(snapshot_map
            .get(&sender_input)
            .expect("sender input marked")
            .is_spent());
        assert!(!snapshot_map
            .get(&recipient_existing)
            .expect("recipient prior output")
            .is_spent());

        let recipient_outpoint = UtxoOutpoint { tx_id, index: 0 };
        let recipient_entry = snapshot_map
            .get(&recipient_outpoint)
            .expect("new recipient output");
        assert_eq!(recipient_entry.owner, recipient_address);
        assert_eq!(recipient_entry.amount, 200);
        assert!(!recipient_entry.is_spent());

        let recipient_snapshot = ledger.utxo_state.snapshot_for_account(&recipient_address);
        assert_eq!(recipient_snapshot.len(), 2);
        assert!(recipient_snapshot
            .iter()
            .any(|(outpoint, stored)| outpoint == &recipient_existing && stored.amount == 300));
        assert!(recipient_snapshot
            .iter()
            .any(|(outpoint, stored)| outpoint == &recipient_outpoint && stored.amount == 200));
    }

    #[test]
    fn apply_transaction_self_transfer_produces_change_output() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let keypair = deterministic_keypair();
        let address = address_from_public_key(&keypair.public);
        let mut account = Account::new(address.clone(), 900, Stake::default());
        let wallet_hex = hex::encode(keypair.public.to_bytes());
        let _ = account
            .ensure_wallet_binding(&wallet_hex)
            .expect("bind wallet");
        ledger
            .upsert_account(account.clone())
            .expect("insert account");

        let existing_tx_id = [5u8; 32];
        let existing_outpoint = UtxoOutpoint {
            tx_id: existing_tx_id,
            index: 0,
        };
        ledger.utxo_state.insert(
            existing_outpoint.clone(),
            StoredUtxo::new(address.clone(), account.balance),
        );

        let before_snapshot = ledger.utxo_state.snapshot_for_account(&address);
        assert_eq!(before_snapshot.len(), 1);
        assert_eq!(before_snapshot[0].0, existing_outpoint);

        let tx = Transaction::new(
            address.clone(),
            address.clone(),
            120,
            8,
            account.nonce + 1,
            None,
        );
        let signature = keypair.sign(&tx.canonical_bytes());
        let signed = SignedTransaction::new(tx, signature, &keypair.public);
        let tx_id = signed.hash();

        ledger
            .apply_transaction(&signed, &[existing_outpoint.clone()])
            .expect("self transfer applies");

        let snapshot_after = ledger.utxo_state.snapshot();
        let snapshot_map: BTreeMap<_, _> = snapshot_after.iter().cloned().collect();
        assert!(snapshot_map
            .get(&existing_outpoint)
            .expect("existing outpoint")
            .is_spent());

        let payment_outpoint = UtxoOutpoint { tx_id, index: 0 };
        let payment_entry = snapshot_map.get(&payment_outpoint).expect("payment output");
        assert_eq!(payment_entry.owner, address);
        assert_eq!(payment_entry.amount, 120);
        assert!(!payment_entry.is_spent());

        let change_outpoint = UtxoOutpoint { tx_id, index: 1 };
        let change_entry = snapshot_map.get(&change_outpoint).expect("change output");
        assert_eq!(change_entry.owner, address);
        assert_eq!(change_entry.amount, 772);
        assert!(!change_entry.is_spent());

        let snapshot_for_account = ledger.utxo_state.snapshot_for_account(&address);
        assert_eq!(snapshot_for_account.len(), 2);
        assert_eq!(snapshot_for_account[0].0, payment_outpoint);
        assert_eq!(snapshot_for_account[0].1.amount, 120);
        assert_eq!(snapshot_for_account[1].0, change_outpoint);
        assert_eq!(snapshot_for_account[1].1.amount, 772);
    }

    #[test]
    fn slashing_resets_validator_state() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let address = "deadbeef".repeat(4);
        let mut account = Account::new(address.clone(), 0, Stake::from_u128(1_000));
        account.reputation.bind_genesis_identity("proof");
        account.reputation.tier = crate::reputation::Tier::Tl4;
        account.reputation.score = 1.5;
        account.reputation.consensus_success = 8;
        account.reputation.peer_feedback = 4;
        account.reputation.timetokes.hours_online = 12;
        ledger.upsert_account(account).unwrap();

        ledger
            .slash_validator(&address, super::SlashingReason::InvalidVote, None)
            .unwrap();

        let slashed = ledger.get_account(&address).unwrap();
        assert_eq!(slashed.stake.to_string(), "750");
        assert!(!slashed.reputation.zsi.validated);
        assert_eq!(slashed.reputation.tier, crate::reputation::Tier::Tl0);
        assert_eq!(slashed.reputation.score, 0.0);
        assert_eq!(slashed.reputation.consensus_success, 0);
        assert_eq!(slashed.reputation.peer_feedback, 0);
        assert_eq!(slashed.reputation.timetokes.hours_online, 0);
    }

    #[test]
    fn records_slashing_events() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let mut account = Account::new("validator".into(), 1_000_000, Stake::from_u128(10_000));
        account.reputation.bind_genesis_identity("genesis-proof");
        ledger.upsert_account(account).unwrap();

        ledger
            .slash_validator("validator", SlashingReason::InvalidVote, None)
            .unwrap();

        let events = ledger.slashing_events(10);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.address, "validator");
        assert_eq!(event.reason, SlashingReason::InvalidVote);
        assert!(event.signature.is_none());
        assert!(!event.evidence_hash.is_empty());
        assert_eq!(
            event.penalty_percent,
            SlashingReason::InvalidVote.penalty_percent()
        );
        assert!(event.timestamp > 0);
    }

    #[test]
    fn record_vrf_history_tracks_entries() {
        use malachite::Natural;

        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        ledger.sync_epoch_for_height(1);
        let epoch = ledger.current_epoch();
        let proof_hex = "aa".repeat(crate::vrf::VRF_PROOF_LENGTH);
        let preoutput_hex = "bb".repeat(crate::vrf::VRF_PREOUTPUT_LENGTH);
        let record = VrfSelectionRecord {
            epoch,
            address: "validator".into(),
            tier: Tier::Tl3,
            timetoke_hours: 12,
            public_key: Some("pk".into()),
            proof: VrfProof {
                randomness: Natural::from(5u32),
                preoutput: preoutput_hex.clone(),
                proof: proof_hex.clone(),
            },
            verified: true,
            accepted: true,
            threshold: Some("10".into()),
            rejection_reason: None,
            weight: Some("48".into()),
            weighted_randomness: Some("1".into()),
        };
        ledger.record_vrf_history(epoch, 1, &[record.clone()]);
        ledger.record_vrf_history(epoch, 1, &[record.clone()]);
        let mut other = record.clone();
        other.proof.preoutput = "cc".repeat(crate::vrf::VRF_PREOUTPUT_LENGTH);
        other.proof.proof = "dd".repeat(crate::vrf::VRF_PROOF_LENGTH);
        other.accepted = false;
        other.rejection_reason = Some("threshold".into());
        other.weight = Some("48".into());
        other.weighted_randomness = Some("3".into());
        ledger.record_vrf_history(epoch + 1, 0, &[other.clone()]);

        let current_epoch_history = ledger.vrf_history(Some(epoch));
        assert_eq!(current_epoch_history.len(), 1);
        let entry = &current_epoch_history[0];
        assert_eq!(entry.round, 1);
        assert_eq!(entry.address, record.address);
        assert!(entry.accepted);
        assert_eq!(entry.public_key, record.public_key);
        assert_eq!(entry.weight, record.weight);

        let all_history = ledger.vrf_history(None);
        assert_eq!(all_history.len(), 2);
        assert_eq!(all_history[0].epoch, epoch);
        assert_eq!(all_history[1].epoch, epoch + 1);
    }

    #[test]
    fn register_vrf_tag_rejects_duplicates() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        assert!(ledger.register_vrf_tag("tag-1"));
        assert!(!ledger.register_vrf_tag("tag-1"));
    }

    #[test]
    fn distributes_consensus_rewards_with_leader_bonus() {
        use crate::consensus::ValidatorProfile as RoundValidator;
        use crate::vrf::VrfProof;
        use malachite::Natural;

        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let leader_address = "aa".repeat(16);
        let peer_one = "bb".repeat(16);
        let peer_two = "cc".repeat(16);

        let validators = vec![
            RoundValidator {
                address: leader_address.clone(),
                stake: Stake::from_u128(1_000),
                reputation_score: 1.2,
                tier: Tier::Tl4,
                timetoke_hours: 180,
                vrf: VrfProof {
                    randomness: Natural::from(5u32),
                    preoutput: "00ff".to_string(),
                    proof: "00ff".to_string(),
                },
                randomness: Natural::from(5u32),
            },
            RoundValidator {
                address: peer_one.clone(),
                stake: Stake::from_u128(900),
                reputation_score: 1.0,
                tier: Tier::Tl3,
                timetoke_hours: 160,
                vrf: VrfProof {
                    randomness: Natural::from(7u32),
                    preoutput: "00aa".to_string(),
                    proof: "00aa".to_string(),
                },
                randomness: Natural::from(7u32),
            },
            RoundValidator {
                address: peer_two.clone(),
                stake: Stake::from_u128(800),
                reputation_score: 0.95,
                tier: Tier::Tl3,
                timetoke_hours: 120,
                vrf: VrfProof {
                    randomness: Natural::from(9u32),
                    preoutput: "0099".to_string(),
                    proof: "0099".to_string(),
                },
                randomness: Natural::from(9u32),
            },
        ];

        ledger
            .distribute_consensus_rewards(&leader_address, &validators, 100, 20)
            .unwrap();

        let leader = ledger.get_account(&leader_address).unwrap();
        let one = ledger.get_account(&peer_one).unwrap();
        let two = ledger.get_account(&peer_two).unwrap();

        assert_eq!(leader.balance, 54);
        assert_eq!(one.balance, 33);
        assert_eq!(two.balance, 33);

        assert_eq!(leader.reputation.consensus_success, 1);
        assert_eq!(one.reputation.consensus_success, 1);
        assert_eq!(two.reputation.consensus_success, 1);
    }

    #[test]
    fn reputation_audit_reflects_account_state() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let mut account = Account::new("audited".into(), 5_000, Stake::from_u128(1_000));
        account.reputation.bind_genesis_identity("audit-proof");
        account.reputation.consensus_success = 7;
        account.reputation.peer_feedback = 3;
        account.reputation.timetokes.hours_online = 12;
        ledger.upsert_account(account.clone()).unwrap();

        let audit = ledger
            .reputation_audit("audited")
            .unwrap()
            .expect("audit entry");
        assert_eq!(audit.address, account.address);
        assert_eq!(audit.balance, account.balance);
        assert_eq!(audit.stake, account.stake.to_string());
        assert_eq!(
            audit.consensus_success,
            account.reputation.consensus_success
        );
        assert_eq!(audit.peer_feedback, account.reputation.peer_feedback);
        assert_eq!(
            audit.uptime_hours,
            account.reputation.timetokes.hours_online
        );
        assert!(audit.zsi_validated);
        assert_eq!(
            audit.zsi_commitment,
            account.reputation.zsi.public_key_commitment
        );
        assert_eq!(
            audit.zsi_reputation_proof,
            account.reputation.zsi.reputation_proof
        );
    }

    #[test]
    fn apply_uptime_proof_updates_timetokes() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let address = "cafebabe".repeat(4);
        let mut account = Account::new(address.clone(), 0, Stake::default());
        account.reputation.bind_genesis_identity("genesis-proof");
        ledger.upsert_account(account).unwrap();

        let window_start = 3_600;
        let window_end = 10_800;
        let proof = build_uptime_proof(&address, window_start, window_end);

        let credited_hours = ledger.apply_uptime_proof(&proof).unwrap();
        assert_eq!(credited_hours, 2);
        let account = ledger.get_account(&address).unwrap();
        assert_eq!(account.reputation.timetokes.hours_online, 2);
        assert_eq!(
            account.reputation.timetokes.last_proof_timestamp,
            window_end
        );
    }

    #[test]
    fn reject_duplicate_uptime_proofs() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let address = "feedface".repeat(4);
        let mut account = Account::new(address.clone(), 0, Stake::default());
        account.reputation.bind_genesis_identity("genesis-proof");
        ledger.upsert_account(account).unwrap();

        let first_start = 1_000;
        let first_end = first_start + 3_600;
        let proof = build_uptime_proof(&address, first_start, first_end);

        ledger.apply_uptime_proof(&proof).unwrap();

        let duplicate = proof.clone();

        let err = ledger.apply_uptime_proof(&duplicate).unwrap_err();
        assert!(matches!(err, ChainError::Transaction(_)));
    }

    #[test]
    fn reject_uptime_proof_without_payload() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let address = "payloadless".repeat(4);
        let mut account = Account::new(address.clone(), 0, Stake::default());
        account.reputation.bind_genesis_identity("genesis-proof");
        ledger.upsert_account(account).unwrap();

        let proof = build_uptime_proof(&address, 3_600, 7_200);
        let mut missing = proof.clone();
        missing.proof = None;

        let err = ledger.apply_uptime_proof(&missing).unwrap_err();
        assert!(matches!(err, ChainError::Transaction(_)));
    }

    #[test]
    fn reject_uptime_proof_with_invalid_payload() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let address = "invalidpayload".repeat(3);
        let mut account = Account::new(address.clone(), 0, Stake::default());
        account.reputation.bind_genesis_identity("genesis-proof");
        ledger.upsert_account(account).unwrap();

        let mut proof = build_uptime_proof(&address, 3_600, 10_800);
        if let Some(ChainProof::Stwo(stark)) = proof.proof.as_mut() {
            if let ProofPayload::Uptime(witness) = &mut stark.payload {
                witness.node_clock = witness.window_end.saturating_sub(1);
            } else {
                panic!("expected uptime witness");
            }
        } else {
            panic!("expected embedded STWO proof");
        }

        let err = ledger.apply_uptime_proof(&proof).unwrap_err();
        assert!(matches!(err, ChainError::Crypto(_)));
    }

    #[test]
    fn uptime_proof_only_counts_new_hours() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let address = "decafbad".repeat(4);
        let mut account = Account::new(address.clone(), 0, Stake::default());
        account.reputation.bind_genesis_identity("genesis-proof");
        ledger.upsert_account(account).unwrap();

        let first_start = 0;
        let first_end = 3_600;
        let first_proof = build_uptime_proof(&address, first_start, first_end);

        ledger.apply_uptime_proof(&first_proof).unwrap();

        // Second proof overlaps the first hour but extends for two additional hours.
        let second_start = 1_800; // overlaps with the already credited hour
        let second_end = 10_800; // extends two new hours beyond the first proof
        let second_proof = build_uptime_proof(&address, second_start, second_end);

        let credited_hours = ledger.apply_uptime_proof(&second_proof).unwrap();
        assert_eq!(credited_hours, 2);
        let account = ledger.get_account(&address).unwrap();
        assert_eq!(account.reputation.timetokes.hours_online, 3);
    }

    #[test]
    fn timetoke_snapshot_marks_sync() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let address = "syncnode".repeat(4);
        let mut account = Account::new(address.clone(), 0, Stake::default());
        account.reputation.bind_genesis_identity("sync-proof");
        account.reputation.timetokes.hours_online = 5;
        ledger.upsert_account(account).unwrap();

        let snapshot = ledger.timetoke_snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].identity, address);
        assert_eq!(snapshot[0].balance, 5);

        let refreshed = ledger.get_account(&address).unwrap();
        assert!(refreshed.reputation.timetokes.last_sync_timestamp > 0);
    }

    #[test]
    fn sync_timetoke_records_merges_newer_state() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let address = "peer".repeat(4);
        let mut account = Account::new(address.clone(), 0, Stake::default());
        account.reputation.bind_genesis_identity("peer-proof");
        ledger.upsert_account(account).unwrap();

        let record = TimetokeRecord {
            identity: address.clone(),
            balance: 8,
            epoch_accrual: 0,
            decay_rate: 1.0,
            last_update: 1_000,
            last_sync: 1_000,
            last_decay: 1_000,
        };

        let updated = ledger.sync_timetoke_records(&[record]).unwrap();
        assert_eq!(updated, vec![address.clone()]);
        let refreshed = ledger.get_account(&address).unwrap();
        assert_eq!(refreshed.reputation.timetokes.hours_online, 8);
        assert_eq!(refreshed.reputation.timetokes.last_proof_timestamp, 1_000);
    }

    fn sample_witness_bundle() -> ModuleWitnessBundle {
        let mut bundle = ModuleWitnessBundle::default();

        let sender_before = AccountBalanceWitness::new("alice".into(), 1_000, 1);
        let sender_after = AccountBalanceWitness::new("alice".into(), 900, 2);
        let recipient_before = AccountBalanceWitness::new("bob".into(), 500, 0);
        let recipient_after = AccountBalanceWitness::new("bob".into(), 600, 0);
        let tx_witness = TransactionWitness::new(
            [0x11; 32],
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
        bundle.record_transaction(tx_witness);

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
            attestation_digest: [0x22; 32],
            approvals: Vec::new(),
        };
        bundle.record_zsi(ZsiWitness::new("alice".into(), None, zsi_updated));

        let vrf_entry = crate::consensus::messages::ConsensusVrfEntry::default();
        let bindings = crate::consensus::ConsensusWitnessBindings {
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
            5,
            7,
            "ee".repeat(32),
            "ff".repeat(32),
            bindings,
        ));

        bundle
    }

    #[test]
    fn staging_module_witnesses_updates_proof_root() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let initial_root = ledger.global_commitments().proof_root;

        let bundle = sample_witness_bundle();
        let expected = bundle.expected_artifacts().expect("expected artifacts");
        let staged = ledger
            .stage_module_witnesses(&bundle)
            .expect("stage witnesses");

        assert_eq!(staged.len(), expected.len());
        let mut expected_map = HashMap::new();
        for (module, digest, payload) in expected {
            expected_map.insert(module, (digest, payload));
        }
        for artifact in &staged {
            let (digest, payload) = expected_map
                .get(&artifact.module)
                .expect("artifact present");
            assert_eq!(&artifact.commitment, digest);
            assert_eq!(&artifact.proof, payload);
        }

        let updated_root = ledger.global_commitments().proof_root;
        assert_ne!(updated_root, initial_root);
        assert_ne!(updated_root, [0u8; 32]);

        let modules = staged
            .iter()
            .map(|artifact| artifact.module)
            .collect::<HashSet<_>>();
        for required in [
            ProofModule::UtxoWitness,
            ProofModule::TimetokeWitness,
            ProofModule::ReputationWitness,
            ProofModule::ZsiWitness,
            ProofModule::BlockWitness,
            ProofModule::ConsensusWitness,
        ] {
            assert!(modules.contains(&required));
        }
    }
}
