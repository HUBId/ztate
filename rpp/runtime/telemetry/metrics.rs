use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use firewood_storage::{
    StorageMetrics as StorageMetricsFacade, WalFlushOutcome as StorageWalFlushOutcome,
};
use http::StatusCode;
use log::warn;
use opentelemetry::global;
use opentelemetry::metrics::noop::NoopMeterProvider;
use opentelemetry::metrics::{CallbackRegistration, Counter, Histogram, Meter, ObservableGauge};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::Resource;
use parking_lot::Mutex;

use super::exporter::{ExporterBuildOutcome, TelemetryExporterBuilder};
use crate::config::TelemetryConfig;
use crate::types::Address;
use rpp_wallet_interface::runtime_telemetry::RuntimeMetrics as WalletRuntimeMetrics;
pub use rpp_wallet_interface::runtime_telemetry::{
    WalletAccountType, WalletAction, WalletActionResult, WalletSignMode,
};

const METER_NAME: &str = "rpp-runtime";
const MILLIS_PER_SECOND: f64 = 1_000.0;

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
struct ProposerGaugeKey {
    validator: String,
    backend: String,
    epoch: u64,
}

/// Initialise the runtime metrics provider using the OTLP exporter configured via `TelemetryConfig`.
///
/// When telemetry is disabled the returned provider still registers all instruments but no exporter
/// is attached which results in no data being sent.
pub fn init_runtime_metrics(
    config: &TelemetryConfig,
    resource: Resource,
) -> Result<(Arc<RuntimeMetrics>, RuntimeMetricsGuard, bool)> {
    let mut provider_builder = SdkMeterProvider::builder().with_resource(resource);
    let mut used_failover = false;

    if config.enabled {
        let exporter_builder = TelemetryExporterBuilder::new(config);
        match exporter_builder.build_metric_exporter()? {
            ExporterBuildOutcome {
                exporter: Some(exporter),
                failover_used,
            } => {
                used_failover = failover_used;
                let interval = Duration::from_secs(config.sample_interval_secs.max(1));
                let reader = PeriodicReader::builder(exporter)
                    .with_interval(interval)
                    .build();
                provider_builder = provider_builder.with_reader(reader);
            }
            ExporterBuildOutcome { exporter: None, .. } => {
                if config.warn_on_drop {
                    warn!(
                        target = "telemetry",
                        "telemetry metrics exporter disabled due to missing OTLP/HTTP endpoint; metrics will only be logged"
                    );
                }
            }
        }
    }

    let provider = provider_builder.build();
    global::set_meter_provider(provider.clone());

    let meter = provider.meter(METER_NAME);
    let (metrics, callbacks) = RuntimeMetrics::from_meter(&meter)?;
    let metrics = Arc::new(metrics);
    let guard = RuntimeMetricsGuard::new(provider, callbacks);

    Ok((metrics, guard, used_failover))
}

/// Wrapper that holds all runtime specific metric instruments.
#[derive(Clone)]
pub struct RuntimeMetrics {
    proofs: ProofMetrics,
    consensus_block_duration: EnumF64Histogram<ConsensusStage>,
    #[cfg(feature = "wallet-integration")]
    wallet_rpc_latency: EnumF64Histogram<WalletRpcMethod>,
    #[cfg(feature = "wallet-integration")]
    wallet_action_total: RpcCounter<WalletAction, WalletActionResult>,
    #[cfg(feature = "wallet-integration")]
    wallet_fee_estimate_latency: Histogram<f64>,
    #[cfg(feature = "wallet-integration")]
    wallet_prover_job_duration: Histogram<f64>,
    #[cfg(feature = "wallet-integration")]
    wallet_prover_witness_bytes: Histogram<u64>,
    #[cfg(feature = "wallet-integration")]
    wallet_prover_backend_total: Counter<u64>,
    #[cfg(feature = "wallet-integration")]
    wallet_prover_failures: Counter<u64>,
    #[cfg(feature = "wallet-integration")]
    wallet_sign_latency: Histogram<f64>,
    #[cfg(feature = "wallet-integration")]
    wallet_sign_failures: Counter<u64>,
    #[cfg(feature = "wallet-integration")]
    wallet_rescan_duration: Histogram<f64>,
    #[cfg(feature = "wallet-integration")]
    wallet_broadcast_rejected: Counter<u64>,
    #[cfg(feature = "wallet-integration")]
    wallet_runtime_watch_active: Histogram<u64>,
    #[cfg(feature = "wallet-integration")]
    wallet_sync_driver_active: Histogram<u64>,
    #[cfg(feature = "wallet-integration")]
    wallet_sync_wallet_height: Histogram<u64>,
    #[cfg(feature = "wallet-integration")]
    wallet_sync_chain_tip_height: Histogram<u64>,
    #[cfg(feature = "wallet-integration")]
    wallet_sync_lag_blocks: Histogram<u64>,
    #[cfg(feature = "wallet-integration")]
    wallet_last_successful_sync_timestamp: Histogram<u64>,
    #[cfg(feature = "wallet-integration")]
    wallet_sync_progress: Arc<Mutex<WalletSyncSnapshot>>,
    rpc_request_latency: RpcHistogram<RpcMethod, RpcResult>,
    rpc_request_total: RpcCounter<RpcMethod, RpcResult>,
    rpc_rate_limit_total: RpcRateLimitCounter<RpcClass, RpcMethod, RpcRateLimitStatus>,
    consensus_rpc_failures: EnumCounter<ConsensusRpcFailure>,
    wal_flush_duration: EnumF64Histogram<WalFlushOutcome>,
    wal_flush_bytes: EnumU64Histogram<WalFlushOutcome>,
    wal_flush_total: EnumCounter<WalFlushOutcome>,
    header_flush_duration: Histogram<f64>,
    header_flush_bytes: Histogram<u64>,
    header_flush_total: Counter<u64>,
    consensus_round_duration: Histogram<f64>,
    consensus_quorum_latency: Histogram<f64>,
    consensus_vrf_verification_time: Histogram<f64>,
    consensus_vrf_verifications_total: Counter<u64>,
    consensus_quorum_verifications_total: Counter<u64>,
    consensus_leader_changes: Counter<u64>,
    consensus_witness_events: Counter<u64>,
    consensus_slashing_events: Counter<u64>,
    consensus_failed_votes: Counter<u64>,
    consensus_proposer_slots_total: Counter<u64>,
    consensus_proposer_expected_weight: Histogram<f64>,
    consensus_proposer_observed_share: Histogram<f64>,
    consensus_proposer_share_deviation: ObservableGauge<f64>,
    proposer_deviation_values: Arc<Mutex<BTreeMap<ProposerGaugeKey, f64>>>,
    validator_height_lag: Histogram<u64>,
    validator_set_changes: Counter<u64>,
    validator_set_change_height: Histogram<u64>,
    validator_set_quorum_delay: Histogram<f64>,
    timetoke_root_mismatches: Counter<u64>,
    consensus_vote_latency: Histogram<f64>,
    consensus_block_schedule_slots_total: Counter<u64>,
    chain_block_height: Histogram<u64>,
    backlog_block_queue: Histogram<u64>,
    backlog_transaction_queue: Histogram<u64>,
    mempool_metadata_rehydrated: Counter<u64>,
    mempool_metadata_orphans: Counter<u64>,
    network_peer_counts: Histogram<u64>,
    reputation_penalties: Counter<u64>,
    state_sync_stream_starts: Counter<u64>,
    state_sync_stream_chunks: Counter<u64>,
    state_sync_stream_chunks_sent: Histogram<u64>,
    state_sync_stream_backpressure: Counter<u64>,
    state_sync_active_streams: Histogram<u64>,
    state_sync_stream_last_chunk_age: Histogram<f64>,
}

#[cfg(feature = "wallet-integration")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WalletSyncSnapshot {
    pub wallet_height: Option<u64>,
    pub chain_tip_height: Option<u64>,
    pub lag_blocks: Option<u64>,
    pub last_success_timestamp: Option<u64>,
}

impl RuntimeMetrics {
    fn from_meter(meter: &Meter) -> Result<(Self, Vec<CallbackRegistration>)> {
        let proposer_deviation_values = Arc::new(Mutex::new(BTreeMap::new()));
        let consensus_proposer_share_deviation = meter
            .f64_observable_gauge("rpp.runtime.consensus.proposer.deviation_pct")
            .with_description(
                "Percent deviation between expected proposer weight and observed slot share",
            )
            .with_unit("percent")
            .init();
        let gauge_values = proposer_deviation_values.clone();
        let proposer_callback = meter.register_callback(move |ctx| {
            for (key, value) in gauge_values.lock().iter() {
                let attributes = [
                    KeyValue::new("validator", key.validator.clone()),
                    KeyValue::new(ProofVerificationBackend::KEY, key.backend.clone()),
                    KeyValue::new("epoch", key.epoch as i64),
                ];
                ctx.observe_gauge(&consensus_proposer_share_deviation, *value, &attributes);
            }
        })?;

        let metrics = Self {
            proofs: ProofMetrics::new(meter),
            consensus_block_duration: EnumF64Histogram::new(
                meter
                    .f64_histogram("rpp.runtime.consensus.block_duration")
                    .with_description("Duration of consensus block pipeline phases in milliseconds")
                    .with_unit("ms")
                    .build(),
            ),
            #[cfg(feature = "wallet-integration")]
            wallet_rpc_latency: EnumF64Histogram::new(
                meter
                    .f64_histogram("rpp.runtime.wallet.rpc_latency")
                    .with_description("Latency of wallet RPC requests in milliseconds")
                    .with_unit("ms")
                    .build(),
            ),
            #[cfg(feature = "wallet-integration")]
            wallet_action_total: RpcCounter::new(
                meter
                    .u64_counter("rpp.runtime.wallet.action.total")
                    .with_description("Total wallet action outcomes grouped by label and result")
                    .with_unit("1")
                    .build(),
            ),
            #[cfg(feature = "wallet-integration")]
            wallet_fee_estimate_latency: meter
                .f64_histogram("rpp.runtime.wallet.fee.estimate.latency_ms")
                .with_description("Latency of wallet fee estimation requests in milliseconds")
                .with_unit("ms")
                .build(),
            #[cfg(feature = "wallet-integration")]
            wallet_prover_job_duration: meter
                .f64_histogram("rpp.runtime.wallet.prover.job.duration_ms")
                .with_description("Duration of wallet prover jobs in milliseconds")
                .with_unit("ms")
                .build(),
            #[cfg(feature = "wallet-integration")]
            wallet_prover_witness_bytes: meter
                .u64_histogram("rpp.runtime.wallet.prover.witness.bytes")
                .with_description("Size of wallet prover witnesses in bytes")
                .with_unit("By")
                .build(),
            #[cfg(feature = "wallet-integration")]
            wallet_prover_backend_total: meter
                .u64_counter("rpp.runtime.wallet.prover.jobs")
                .with_description("Total wallet prover jobs grouped by backend and outcome")
                .with_unit("1")
                .build(),
            #[cfg(feature = "wallet-integration")]
            wallet_prover_failures: meter
                .u64_counter("rpp.runtime.wallet.prover.failures")
                .with_description("Total wallet prover failures grouped by error code")
                .with_unit("1")
                .build(),
            #[cfg(feature = "wallet-integration")]
            wallet_sign_latency: meter
                .f64_histogram("rpp.runtime.wallet.sign.latency_ms")
                .with_description(
                    "Latency of wallet signing operations grouped by mode and account type",
                )
                .with_unit("ms")
                .build(),
            #[cfg(feature = "wallet-integration")]
            wallet_sign_failures: meter
                .u64_counter("rpp.runtime.wallet.sign.failures")
                .with_description("Total wallet signing failures grouped by mode and error code")
                .with_unit("1")
                .build(),
            #[cfg(feature = "wallet-integration")]
            wallet_rescan_duration: meter
                .f64_histogram("rpp.runtime.wallet.scan.rescan.duration_ms")
                .with_description("Latency of wallet rescan scheduling requests in milliseconds")
                .with_unit("ms")
                .build(),
            #[cfg(feature = "wallet-integration")]
            wallet_broadcast_rejected: meter
                .u64_counter("rpp.runtime.wallet.broadcast.rejected")
                .with_description("Total wallet transaction broadcast rejections grouped by reason")
                .with_unit("1")
                .build(),
            #[cfg(feature = "wallet-integration")]
            wallet_runtime_watch_active: meter
                .u64_histogram("rpp.runtime.wallet.runtime.active")
                .with_description("Samples indicating whether the wallet runtime loop is active")
                .with_unit("1")
                .build(),
            #[cfg(feature = "wallet-integration")]
            wallet_sync_driver_active: meter
                .u64_histogram("rpp.runtime.wallet.sync.active")
                .with_description("Samples indicating whether the wallet sync driver is active")
                .with_unit("1")
                .build(),
            #[cfg(feature = "wallet-integration")]
            wallet_sync_wallet_height: meter
                .u64_histogram("rpp.runtime.wallet.sync.wallet_height")
                .with_description("Latest wallet chain height observed by the sync driver")
                .with_unit("1")
                .build(),
            #[cfg(feature = "wallet-integration")]
            wallet_sync_chain_tip_height: meter
                .u64_histogram("rpp.runtime.wallet.sync.chain_tip_height")
                .with_description("Chain tip height observed while syncing the wallet")
                .with_unit("1")
                .build(),
            #[cfg(feature = "wallet-integration")]
            wallet_sync_lag_blocks: meter
                .u64_histogram("rpp.runtime.wallet.sync.lag.blocks")
                .with_description("Block distance between chain tip and wallet height during sync")
                .with_unit("1")
                .build(),
            #[cfg(feature = "wallet-integration")]
            wallet_last_successful_sync_timestamp: meter
                .u64_histogram("rpp.runtime.wallet.sync.last_success_timestamp.seconds")
                .with_description("Unix timestamp of the last successful wallet sync")
                .with_unit("s")
                .build(),
            #[cfg(feature = "wallet-integration")]
            wallet_sync_progress: Arc::new(Mutex::new(WalletSyncSnapshot::default())),
            rpc_request_latency: RpcHistogram::new(
                meter
                    .f64_histogram("rpp.runtime.rpc.request.latency")
                    .with_description("Latency of RPC handlers in milliseconds")
                    .with_unit("ms")
                    .build(),
            ),
            rpc_request_total: RpcCounter::new(
                meter
                    .u64_counter("rpp.runtime.rpc.request.total")
                    .with_description("Total RPC handler invocations grouped by method and result")
                    .with_unit("1")
                    .build(),
            ),
            rpc_rate_limit_total: RpcRateLimitCounter::new(
                meter
                    .u64_counter("rpp.runtime.rpc.rate_limit.total")
                    .with_description(
                        "RPC rate limit decisions grouped by class, method, tenant, and allow/throttle status",
                    )
                    .with_unit("1")
                    .build(),
            ),
            consensus_rpc_failures: EnumCounter::new(
                meter
                    .u64_counter("rpp.runtime.consensus.rpc.failures")
                    .with_description(
                        "Consensus RPC failures grouped by reason (verifier failure, missing finality)",
                    )
                    .with_unit("1")
                    .build(),
            ),
            wal_flush_duration: EnumF64Histogram::new(
                meter
                    .f64_histogram("rpp.runtime.storage.wal_flush.duration")
                    .with_description("Duration of WAL flush operations in milliseconds")
                    .with_unit("ms")
                    .build(),
            ),
            wal_flush_bytes: EnumU64Histogram::new(
                meter
                    .u64_histogram("rpp.runtime.storage.wal_flush.bytes")
                    .with_description("Size of flushed WAL batches in bytes")
                    .with_unit("By")
                    .build(),
            ),
            wal_flush_total: EnumCounter::new(
                meter
                    .u64_counter("rpp.runtime.storage.wal_flush.total")
                    .with_description("Count of WAL flush attempts grouped by outcome")
                    .with_unit("1")
                    .build(),
            ),
            header_flush_duration: meter
                .f64_histogram("rpp.runtime.storage.header_flush.duration")
                .with_description("Duration of header flush operations in milliseconds")
                .with_unit("ms")
                .build(),
            header_flush_bytes: meter
                .u64_histogram("rpp.runtime.storage.header_flush.bytes")
                .with_description("Size of flushed headers in bytes")
                .with_unit("By")
                .build(),
            header_flush_total: meter
                .u64_counter("rpp.runtime.storage.header_flush.total")
                .with_description("Total number of header flush operations")
                .with_unit("1")
                .build(),
            consensus_round_duration: meter
                .f64_histogram("rpp.runtime.consensus.round.duration")
                .with_description("Duration of consensus rounds in milliseconds")
                .with_unit("ms")
                .build(),
            consensus_quorum_latency: meter
                .f64_histogram("rpp.runtime.consensus.round.quorum_latency")
                .with_description(
                    "Latency between round start and quorum formation in milliseconds",
                )
                .with_unit("ms")
                .build(),
            consensus_vrf_verification_time: meter
                .f64_histogram("consensus_vrf_verification_time_ms")
                .with_description(
                    "VRF verification duration for consensus certificates in milliseconds",
                )
                .with_unit("ms")
                .build(),
            consensus_vrf_verifications_total: meter
                .u64_counter("consensus_vrf_verifications_total")
                .with_description("Total VRF verification attempts grouped by result")
                .with_unit("1")
                .build(),
            consensus_quorum_verifications_total: meter
                .u64_counter("consensus_quorum_verifications_total")
                .with_description("Consensus quorum verification attempts grouped by result")
                .with_unit("1")
                .build(),
            consensus_leader_changes: meter
                .u64_counter("rpp.runtime.consensus.round.leader_changes")
                .with_description("Total leader changes observed by the runtime")
                .with_unit("1")
                .build(),
            consensus_witness_events: meter
                .u64_counter("rpp.runtime.consensus.witness.events")
                .with_description("Total witness gossip events emitted by the runtime")
                .with_unit("1")
                .build(),
            consensus_slashing_events: meter
                .u64_counter("rpp.runtime.consensus.slashing.events")
                .with_description("Total slashing events applied by the runtime")
                .with_unit("1")
                .build(),
            consensus_failed_votes: meter
                .u64_counter("rpp.runtime.consensus.failed_votes")
                .with_description("Total failed consensus vote registrations")
                .with_unit("1")
                .build(),
            consensus_proposer_slots_total: meter
                .u64_counter("rpp.runtime.consensus.proposer.slots")
                .with_description("Observed proposer slots grouped by validator, backend, and epoch")
                .with_unit("1")
                .build(),
            consensus_proposer_expected_weight: meter
                .f64_histogram("rpp.runtime.consensus.proposer.expected_weight")
                .with_description("Expected slot weight share for the selected proposer")
                .with_unit("ratio")
                .build(),
            consensus_proposer_observed_share: meter
                .f64_histogram("rpp.runtime.consensus.proposer.observed_share")
                .with_description("Observed proposer slot share by validator and backend")
                .with_unit("ratio")
                .build(),
            consensus_proposer_share_deviation,
            proposer_deviation_values,
            validator_height_lag: meter
                .u64_histogram("rpp.runtime.consensus.validator_height_lag")
                .with_description("Block height lag between the local node and remote validators")
                .with_unit("1")
                .build(),
            validator_set_changes: meter
                .u64_counter("validator_set_changes_total")
                .with_description("Count of validator set/epoch transitions observed locally")
                .with_unit("1")
                .build(),
            validator_set_change_height: meter
                .u64_histogram("validator_set_change_height")
                .with_description("Block heights at which validator set transitions were observed")
                .with_unit("1")
                .build(),
            validator_set_quorum_delay: meter
                .f64_histogram("validator_set_change_quorum_delay_ms")
                .with_description(
                    "Latency between validator set transitions and first subsequent quorum",
                )
                .with_unit("ms")
                .build(),
            timetoke_root_mismatches: meter
                .u64_counter("timetoke_root_mismatch_total")
                .with_description(
                    "Total timetoke root mismatches encountered during gossip timetoke sync",
                )
                .with_unit("1")
                .build(),
            consensus_vote_latency: meter
                .f64_histogram("rpp.runtime.consensus.vote.latency")
                .with_description(
                    "Latency between vote receipt and processing, grouped by validator and backend"
                )
                .with_unit("ms")
                .build(),
            consensus_block_schedule_slots_total: meter
                .u64_counter("rpp.runtime.consensus.block_schedule.slots")
                .with_description("Expected consensus block production slots grouped by epoch")
                .with_unit("1")
                .build(),
            chain_block_height: meter
                .u64_histogram("rpp.runtime.chain.block_height")
                .with_description("Observed blockchain heights on the local node")
                .with_unit("1")
                .build(),
            backlog_block_queue: meter
                .u64_histogram("rpp.runtime.backlog.blocks")
                .with_description("Queued block proposals awaiting consensus ingestion")
                .with_unit("1")
                .build(),
            backlog_transaction_queue: meter
                .u64_histogram("rpp.runtime.backlog.transactions")
                .with_description("Queued transactions awaiting block inclusion")
                .with_unit("1")
                .build(),
            mempool_metadata_rehydrated: meter
                .u64_counter("rpp.runtime.mempool.metadata.rehydrated")
                .with_description(
                    "Total mempool entries whose metadata was reconstructed after pruning",
                )
                .with_unit("1")
                .build(),
            mempool_metadata_orphans: meter
                .u64_counter("rpp.runtime.mempool.metadata.orphans")
                .with_description(
                    "Total orphaned mempool metadata records removed after pruning",
                )
                .with_unit("1")
                .build(),
            network_peer_counts: meter
                .u64_histogram("rpp.runtime.network.peer_count")
                .with_description("Number of connected peers observed by the runtime")
                .with_unit("1")
                .build(),
            reputation_penalties: meter
                .u64_counter("rpp.runtime.reputation.penalties")
                .with_description("Total reputation penalties applied by the runtime")
                .with_unit("1")
                .build(),
            state_sync_stream_starts: meter
                .u64_counter("rpp.runtime.state_sync.stream.starts")
                .with_description("Total number of state sync session streams started")
                .with_unit("1")
                .build(),
            state_sync_stream_chunks: meter
                .u64_counter("rpp.runtime.state_sync.stream.chunks")
                .with_description("Total number of state sync snapshot chunks streamed")
                .with_unit("1")
                .build(),
            state_sync_stream_chunks_sent: meter
                .u64_histogram("rpp.runtime.state_sync.stream.chunks_sent")
                .with_description("Chunks delivered per state sync stream before completion")
                .with_unit("1")
                .build(),
            state_sync_stream_backpressure: meter
                .u64_counter("rpp.runtime.state_sync.stream.backpressure")
                .with_description(
                    "Number of times clients waited for state sync chunk stream capacity",
                )
                .with_unit("1")
                .build(),
            state_sync_active_streams: meter
                .u64_histogram("rpp.runtime.state_sync.stream.active")
                .with_description("Active state sync stream count sampled on lifecycle changes")
                .with_unit("1")
                .build(),
            state_sync_stream_last_chunk_age: meter
                .f64_histogram("rpp.runtime.state_sync.stream.last_chunk_age.seconds")
                .with_description("Elapsed seconds between consecutive state sync chunks")
                .with_unit("s")
                .build(),
        };

        Ok((metrics, vec![proposer_callback]))
    }

    /// Construct a new metrics handle from the provided meter.
    ///
    /// This helper primarily exists to support integration tests that need to
    /// attach `RuntimeMetrics` to custom in-memory exporters.
    pub fn from_meter_for_testing(meter: &Meter) -> Self {
        let (metrics, _) = Self::from_meter(meter).expect("failed to build runtime metrics");
        metrics
    }

    pub fn proofs(&self) -> &ProofMetrics {
        &self.proofs
    }

    /// Returns a no-op metrics handle backed by a [`NoopMeterProvider`].
    pub fn noop() -> Arc<Self> {
        let meter = NoopMeterProvider::new().meter(METER_NAME);
        let (metrics, _) = Self::from_meter(&meter).expect("failed to build noop runtime metrics");
        Arc::new(metrics)
    }

    /// Record the duration of a consensus stage.
    pub fn record_consensus_stage_duration(&self, stage: ConsensusStage, duration: Duration) {
        self.consensus_block_duration
            .record_duration(stage, duration);
    }

    /// Record the latency of a wallet RPC invocation.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_rpc_latency(&self, method: WalletRpcMethod, duration: Duration) {
        self.wallet_rpc_latency.record_duration(method, duration);
    }

    #[cfg(not(feature = "wallet-integration"))]
    #[allow(unused_variables)]
    pub fn record_wallet_rpc_latency(&self, _method: WalletRpcMethod, _duration: Duration) {}

    /// Record a wallet action result for in-memory and OTLP consumers.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_action(&self, action: WalletAction, outcome: WalletActionResult) {
        self.wallet_action_total.add(action, outcome, 1);
    }

    #[cfg(not(feature = "wallet-integration"))]
    #[allow(unused_variables)]
    pub fn record_wallet_action(&self, _action: WalletAction, _outcome: WalletActionResult) {}

    /// Record the latency of wallet fee estimation requests.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_fee_estimate_latency(&self, duration: Duration) {
        self.wallet_fee_estimate_latency
            .record(duration.as_secs_f64() * MILLIS_PER_SECOND, &[]);
    }

    #[cfg(not(feature = "wallet-integration"))]
    pub fn record_wallet_fee_estimate_latency(&self, _duration: Duration) {}

    /// Record the duration of a wallet prover job grouped by backend and result.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_prover_job_duration(
        &self,
        backend: &str,
        proof_generated: bool,
        duration: Duration,
    ) {
        let attributes = [
            KeyValue::new("backend", backend.to_string()),
            KeyValue::new("proof_generated", proof_generated),
        ];
        self.wallet_prover_job_duration
            .record(duration.as_secs_f64() * MILLIS_PER_SECOND, &attributes);
    }

    #[cfg(not(feature = "wallet-integration"))]
    #[allow(unused_variables)]
    pub fn record_wallet_prover_job_duration(
        &self,
        _backend: &str,
        _proof_generated: bool,
        _duration: Duration,
    ) {
    }

    /// Record the witness size produced by a wallet prover.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_prover_witness_bytes(&self, backend: &str, witness_bytes: u64) {
        let attributes = [KeyValue::new("backend", backend.to_string())];
        self.wallet_prover_witness_bytes
            .record(witness_bytes, &attributes);
    }

    #[cfg(not(feature = "wallet-integration"))]
    #[allow(unused_variables)]
    pub fn record_wallet_prover_witness_bytes(&self, _backend: &str, _witness_bytes: u64) {}

    /// Record that a wallet prover backend was invoked and its outcome.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_prover_backend(&self, backend: &str, success: bool) {
        let attributes = [
            KeyValue::new("backend", backend.to_string()),
            KeyValue::new("result", if success { "success" } else { "failure" }),
        ];
        self.wallet_prover_backend_total.add(1, &attributes);
    }

    #[cfg(not(feature = "wallet-integration"))]
    #[allow(unused_variables)]
    pub fn record_wallet_prover_backend(&self, _backend: &str, _success: bool) {}

    /// Record a wallet prover failure grouped by error code.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_prover_failure(&self, backend: &str, code: &str) {
        let attributes = [
            KeyValue::new("backend", backend.to_string()),
            KeyValue::new("code", code.to_string()),
        ];
        self.wallet_prover_failures.add(1, &attributes);
    }

    #[cfg(not(feature = "wallet-integration"))]
    #[allow(unused_variables)]
    pub fn record_wallet_prover_failure(&self, _backend: &str, _code: &str) {}

    /// Record wallet signing latency grouped by mode, account type, backend, and result.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_sign_latency(
        &self,
        mode: WalletSignMode,
        account_type: WalletAccountType,
        backend: &str,
        duration: Duration,
        success: bool,
    ) {
        let attributes = [
            KeyValue::new("mode", mode.as_str().to_string()),
            KeyValue::new("account_type", account_type.as_str().to_string()),
            KeyValue::new("backend", backend.to_string()),
            KeyValue::new("result", if success { "ok" } else { "err" }),
        ];
        self.wallet_sign_latency
            .record(duration.as_secs_f64() * MILLIS_PER_SECOND, &attributes);
    }

    #[cfg(not(feature = "wallet-integration"))]
    #[allow(unused_variables)]
    pub fn record_wallet_sign_latency(
        &self,
        _mode: WalletSignMode,
        _account_type: WalletAccountType,
        _backend: &str,
        _duration: Duration,
        _success: bool,
    ) {
    }

    /// Record wallet signing failures grouped by mode, account type, backend, and code.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_sign_failure(
        &self,
        mode: WalletSignMode,
        account_type: WalletAccountType,
        backend: &str,
        code: &str,
    ) {
        let attributes = [
            KeyValue::new("mode", mode.as_str().to_string()),
            KeyValue::new("account_type", account_type.as_str().to_string()),
            KeyValue::new("backend", backend.to_string()),
            KeyValue::new("code", code.to_string()),
        ];
        self.wallet_sign_failures.add(1, &attributes);
    }

    #[cfg(not(feature = "wallet-integration"))]
    #[allow(unused_variables)]
    pub fn record_wallet_sign_failure(
        &self,
        _mode: WalletSignMode,
        _account_type: WalletAccountType,
        _backend: &str,
        _code: &str,
    ) {
    }

    /// Record the time taken to schedule a wallet rescan along with its outcome.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_rescan_duration(&self, scheduled: bool, duration: Duration) {
        let attributes = [KeyValue::new("scheduled", scheduled)];
        self.wallet_rescan_duration
            .record(duration.as_secs_f64() * MILLIS_PER_SECOND, &attributes);
    }

    #[cfg(not(feature = "wallet-integration"))]
    #[allow(unused_variables)]
    pub fn record_wallet_rescan_duration(&self, _scheduled: bool, _duration: Duration) {}

    /// Increment the wallet broadcast rejection counter grouped by reason.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_broadcast_rejected(&self, reason: &str) {
        let attributes = [KeyValue::new("reason", reason.to_string())];
        self.wallet_broadcast_rejected.add(1, &attributes);
    }

    #[cfg(not(feature = "wallet-integration"))]
    #[allow(unused_variables)]
    pub fn record_wallet_broadcast_rejected(&self, _reason: &str) {}

    /// Record that the wallet runtime loop has started processing events.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_runtime_watch_started(&self) {
        self.wallet_runtime_watch_active.record(1, &[]);
    }

    #[cfg(not(feature = "wallet-integration"))]
    pub fn record_wallet_runtime_watch_started(&self) {}

    /// Record that the wallet runtime loop has stopped processing events.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_runtime_watch_stopped(&self) {
        self.wallet_runtime_watch_active.record(0, &[]);
    }

    #[cfg(not(feature = "wallet-integration"))]
    pub fn record_wallet_runtime_watch_stopped(&self) {}

    /// Record that the wallet sync driver became active.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_sync_driver_started(&self) {
        self.wallet_sync_driver_active.record(1, &[]);
    }

    #[cfg(not(feature = "wallet-integration"))]
    pub fn record_wallet_sync_driver_started(&self) {}

    /// Record that the wallet sync driver has stopped.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_sync_driver_stopped(&self) {
        self.wallet_sync_driver_active.record(0, &[]);
    }

    #[cfg(not(feature = "wallet-integration"))]
    pub fn record_wallet_sync_driver_stopped(&self) {}

    /// Record the current wallet height observed by the sync process.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_sync_wallet_height(&self, height: u64) {
        self.wallet_sync_wallet_height.record(height, &[]);
        self.wallet_sync_progress.lock().wallet_height = Some(height);
    }

    #[cfg(not(feature = "wallet-integration"))]
    pub fn record_wallet_sync_wallet_height(&self, _height: u64) {}

    /// Record the latest chain tip height observed while syncing the wallet.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_sync_chain_tip_height(&self, height: u64) {
        self.wallet_sync_chain_tip_height.record(height, &[]);
        self.wallet_sync_progress.lock().chain_tip_height = Some(height);
    }

    #[cfg(not(feature = "wallet-integration"))]
    pub fn record_wallet_sync_chain_tip_height(&self, _height: u64) {}

    /// Record the lag between the wallet height and the observed chain tip in blocks.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_sync_lag_blocks(&self, lag_blocks: u64) {
        self.wallet_sync_lag_blocks.record(lag_blocks, &[]);
        self.wallet_sync_progress.lock().lag_blocks = Some(lag_blocks);
    }

    #[cfg(not(feature = "wallet-integration"))]
    pub fn record_wallet_sync_lag_blocks(&self, _lag_blocks: u64) {}

    /// Record the timestamp of the last successful wallet sync.
    #[cfg(feature = "wallet-integration")]
    pub fn record_wallet_last_successful_sync(&self, timestamp: SystemTime) {
        let Ok(duration) = timestamp.duration_since(SystemTime::UNIX_EPOCH) else {
            return;
        };
        self.wallet_last_successful_sync_timestamp
            .record(duration.as_secs(), &[]);
        self.wallet_sync_progress.lock().last_success_timestamp = Some(duration.as_secs());
    }

    #[cfg(feature = "wallet-integration")]
    pub fn wallet_sync_snapshot(&self) -> WalletSyncSnapshot {
        self.wallet_sync_progress.lock().clone()
    }

    #[cfg(not(feature = "wallet-integration"))]
    pub fn record_wallet_last_successful_sync(&self, _timestamp: SystemTime) {}

    /// Record the latency and result of an RPC handler invocation.
    pub fn record_rpc_request(&self, method: RpcMethod, result: RpcResult, duration: Duration) {
        self.rpc_request_latency
            .record_duration(method, result, duration);
        self.rpc_request_total.add(method, result, 1);
    }

    /// Record the outcome of a rate limit decision for an RPC handler.
    pub fn record_rpc_rate_limit(
        &self,
        class: RpcClass,
        method: RpcMethod,
        status: RpcRateLimitStatus,
        tenant: Option<&str>,
    ) {
        self.rpc_rate_limit_total
            .add(class, method, status, tenant, 1);
    }

    pub fn record_consensus_rpc_failure(&self, reason: ConsensusRpcFailure) {
        self.consensus_rpc_failures.add(reason, 1);
    }

    /// Record the duration of a WAL flush attempt.
    pub fn record_wal_flush_duration(&self, outcome: WalFlushOutcome, duration: Duration) {
        self.wal_flush_duration.record_duration(outcome, duration);
    }

    /// Record the number of bytes flushed to the WAL for the provided outcome.
    pub fn record_wal_flush_bytes(&self, outcome: WalFlushOutcome, bytes: u64) {
        self.wal_flush_bytes.record(outcome, bytes);
    }

    /// Increment the WAL flush counter for the provided outcome.
    pub fn increment_wal_flushes(&self, outcome: WalFlushOutcome) {
        self.wal_flush_total.add(outcome, 1);
    }

    /// Record the duration of a header flush attempt.
    pub fn record_header_flush_duration(&self, duration: Duration) {
        self.header_flush_duration
            .record(duration.as_secs_f64() * MILLIS_PER_SECOND, &[]);
    }

    /// Record the size of a flushed header.
    pub fn record_header_flush_bytes(&self, bytes: u64) {
        self.header_flush_bytes.record(bytes, &[]);
    }

    /// Increment the header flush counter.
    pub fn increment_header_flushes(&self) {
        self.header_flush_total.add(1, &[]);
    }

    /// Record the time it took to generate a proof for the given kind.
    pub fn record_proof_generation_duration(&self, kind: ProofKind, duration: Duration) {
        self.proofs.record_generation_duration(kind, duration);
    }

    /// Record the resulting proof size for the provided proving backend.
    pub fn record_proof_generation_size(&self, kind: ProofKind, bytes: u64) {
        self.proofs.record_generation_size(kind, bytes);
    }

    /// Increment the proof generation counter without emitting duration/size data.
    pub fn increment_proof_generation(&self, kind: ProofKind) {
        self.proofs.increment_generation(kind);
    }

    /// Record the duration of an entire consensus round.
    pub fn record_consensus_round_duration(&self, height: u64, round: u64, duration: Duration) {
        let attributes = [
            KeyValue::new("height", height as i64),
            KeyValue::new("round", round as i64),
        ];
        self.consensus_round_duration
            .record(duration.as_secs_f64() * MILLIS_PER_SECOND, &attributes);
    }

    /// Record the latency between round start and quorum formation.
    pub fn record_consensus_quorum_latency(&self, height: u64, round: u64, latency: Duration) {
        let attributes = [
            KeyValue::new("height", height as i64),
            KeyValue::new("round", round as i64),
        ];
        self.consensus_quorum_latency
            .record(latency.as_secs_f64() * MILLIS_PER_SECOND, &attributes);
    }

    /// Record the outcome of verifying the VRF portion of a consensus certificate.
    pub fn record_consensus_vrf_verification_success(&self, duration: Duration) {
        let attributes = [KeyValue::new("result", "success")];
        self.consensus_vrf_verifications_total.add(1, &attributes);
        self.consensus_vrf_verification_time
            .record(duration.as_secs_f64() * MILLIS_PER_SECOND, &attributes);
    }

    /// Record a failed VRF verification alongside the failure reason.
    pub fn record_consensus_vrf_verification_failure(
        &self,
        duration: Duration,
        reason: &'static str,
    ) {
        let attributes = [
            KeyValue::new("result", "failure"),
            KeyValue::new("reason", reason),
        ];
        self.consensus_vrf_verifications_total.add(1, &attributes);
        self.consensus_vrf_verification_time
            .record(duration.as_secs_f64() * MILLIS_PER_SECOND, &attributes);
    }

    /// Record a successful quorum verification.
    pub fn record_consensus_quorum_verification_success(&self) {
        let attributes = [KeyValue::new("result", "success")];
        self.consensus_quorum_verifications_total
            .add(1, &attributes);
    }

    /// Record a failed quorum verification with the supplied reason label.
    pub fn record_consensus_quorum_verification_failure(&self, reason: &'static str) {
        let attributes = [
            KeyValue::new("result", "failure"),
            KeyValue::new("reason", reason),
        ];
        self.consensus_quorum_verifications_total
            .add(1, &attributes);
    }

    /// Record a leader change for the provided round.
    pub fn record_consensus_leader_change<S: Into<String>>(
        &self,
        height: u64,
        round: u64,
        leader: S,
    ) {
        let leader = leader.into();
        let attributes = [
            KeyValue::new("height", height as i64),
            KeyValue::new("round", round as i64),
            KeyValue::new("leader", leader),
        ];
        self.consensus_leader_changes.add(1, &attributes);
    }

    /// Record a consensus witness gossip event for the provided topic label.
    pub fn record_consensus_witness_event<S: Into<String>>(&self, topic: S) {
        let topic = topic.into();
        let attributes = [KeyValue::new("topic", topic)];
        self.consensus_witness_events.add(1, &attributes);
    }

    /// Record a slashing event along with its reason label.
    pub fn record_consensus_slashing_event<S: Into<String>>(&self, reason: S) {
        let reason = reason.into();
        let attributes = [KeyValue::new("reason", reason)];
        self.consensus_slashing_events.add(1, &attributes);
    }

    /// Record a failed vote event with an optional reason label.
    pub fn record_consensus_failed_vote<S: Into<String>>(&self, reason: S) {
        let reason = reason.into();
        let attributes = [KeyValue::new("reason", reason)];
        self.consensus_failed_votes.add(1, &attributes);
    }

    /// Record a validator set or epoch transition along with the triggering height.
    pub fn record_validator_set_change(&self, epoch: u64, height: u64) {
        let epoch_attr = [KeyValue::new("epoch", epoch as i64)];
        self.validator_set_changes.add(1, &epoch_attr);
        self.validator_set_change_height.record(height, &epoch_attr);
    }

    /// Record the latency from a validator set change to the next observed quorum.
    pub fn record_validator_set_quorum_delay(&self, epoch: u64, height: u64, latency: Duration) {
        let attributes = [
            KeyValue::new("epoch", epoch as i64),
            KeyValue::new("height", height as i64),
        ];
        self.validator_set_quorum_delay
            .record(latency.as_secs_f64() * MILLIS_PER_SECOND, &attributes);
    }

    /// Record a timetoke root mismatch detected during gossip timetoke sync.
    pub fn record_timetoke_root_mismatch<S: Into<String>>(&self, source: S, peer: Option<String>) {
        let mut attributes = vec![KeyValue::new("source", source.into())];
        if let Some(peer) = peer {
            attributes.push(KeyValue::new("peer", peer));
        }
        self.timetoke_root_mismatches.add(1, &attributes);
    }

    pub fn record_consensus_vote_latency(
        &self,
        validator: &str,
        epoch: u64,
        slot: u64,
        backend: ProofVerificationBackend,
        latency: Duration,
    ) {
        let attributes = [
            KeyValue::new("validator", validator.to_string()),
            KeyValue::new("epoch", epoch as i64),
            KeyValue::new("slot", slot as i64),
            KeyValue::new(ProofVerificationBackend::KEY, backend.as_str()),
        ];
        self.consensus_vote_latency
            .record(latency.as_millis() as f64, &attributes);
    }

    /// Record the expected block production slot for the provided epoch.
    pub fn record_block_schedule_slot(&self, epoch: u64) {
        let attributes = [KeyValue::new("epoch", epoch as i64)];
        self.consensus_block_schedule_slots_total
            .add(1, &attributes);
    }

    pub fn record_proposer_slot_share(
        &self,
        expected_validator: &Address,
        observed_validator: &Address,
        backend: ProofVerificationBackend,
        epoch: u64,
        expected_weight: f64,
        observed_share: f64,
        deviation_pct: f64,
    ) {
        let attributes = [
            KeyValue::new("expected_validator", expected_validator.to_string()),
            KeyValue::new("validator", observed_validator.to_string()),
            KeyValue::new("epoch", epoch as i64),
            KeyValue::new(ProofVerificationBackend::KEY, backend.as_str()),
        ];
        self.consensus_proposer_slots_total.add(1, &attributes);
        self.consensus_proposer_expected_weight
            .record(expected_weight, &attributes);
        self.consensus_proposer_observed_share
            .record(observed_share, &attributes);
        self.record_proposer_deviation_value(observed_validator, backend, epoch, deviation_pct);
    }

    fn record_proposer_deviation_value(
        &self,
        validator: &str,
        backend: ProofVerificationBackend,
        epoch: u64,
        deviation_pct: f64,
    ) {
        let mut values = self.proposer_deviation_values.lock();
        let key = ProposerGaugeKey {
            validator: validator.to_string(),
            backend: backend.as_str().to_string(),
            epoch,
        };
        values.insert(key, deviation_pct);
    }

    /// Record the latest observed block height.
    pub fn record_block_height(&self, height: u64) {
        self.chain_block_height.record(height, &[]);
    }

    /// Record the observed block height lag for a remote validator.
    pub fn record_validator_height_lag(&self, validator: &str, lag: u64) {
        if lag == 0 {
            return;
        }

        self.validator_height_lag
            .record(lag, &[KeyValue::new("validator", validator.to_string())]);
    }

    /// Record queued block proposals and transactions waiting to be included in blocks.
    pub fn record_backlog(&self, block_backlog: usize, transaction_backlog: usize) {
        self.backlog_block_queue.record(block_backlog as u64, &[]);
        self.backlog_transaction_queue
            .record(transaction_backlog as u64, &[]);
    }

    /// Record metadata reconciliation for mempool entries during pruning cycles.
    pub fn record_mempool_metadata_reconciliation(&self, rehydrated: usize, orphaned: usize) {
        if rehydrated > 0 {
            self.mempool_metadata_rehydrated.add(rehydrated as u64, &[]);
        }
        if orphaned > 0 {
            self.mempool_metadata_orphans.add(orphaned as u64, &[]);
        }
    }

    /// Record the latest observed peer count on the networking layer.
    pub fn record_peer_count(&self, peers: usize) {
        self.network_peer_counts.record(peers as u64, &[]);
    }

    /// Record a reputation penalty emitted by the networking layer.
    pub fn record_reputation_penalty<S: Into<String>>(&self, label: S) {
        let label = label.into();
        let attributes = [KeyValue::new("label", label)];
        self.reputation_penalties.add(1, &attributes);
    }

    pub fn record_state_sync_stream_start(&self, active: u64) {
        self.state_sync_stream_starts.add(1, &[]);
        self.state_sync_active_streams.record(active, &[]);
    }

    pub fn record_state_sync_stream_finish(&self, active: u64) {
        self.state_sync_active_streams.record(active, &[]);
    }

    pub fn record_state_sync_chunk_served(&self) {
        self.state_sync_stream_chunks.add(1, &[]);
    }

    pub fn record_state_sync_stream_progress(&self, chunks_served: u64) {
        self.state_sync_stream_chunks_sent
            .record(chunks_served, &[]);
    }

    pub fn record_state_sync_stream_backpressure(&self) {
        self.state_sync_stream_backpressure.add(1, &[]);
    }

    pub fn record_state_sync_last_chunk_age(&self, age_seconds: f64) {
        self.state_sync_stream_last_chunk_age
            .record(age_seconds, &[]);
    }
}

impl WalletRuntimeMetrics for RuntimeMetrics {
    fn record_wallet_action(&self, action: WalletAction, outcome: WalletActionResult) {
        RuntimeMetrics::record_wallet_action(self, action, outcome);
    }

    fn record_wallet_prover_backend(&self, backend: &str, success: bool) {
        RuntimeMetrics::record_wallet_prover_backend(self, backend, success);
    }

    fn record_wallet_prover_witness_bytes(&self, backend: &str, bytes: u64) {
        RuntimeMetrics::record_wallet_prover_witness_bytes(self, backend, bytes);
    }

    fn record_wallet_prover_failure(&self, backend: &str, code: &str) {
        RuntimeMetrics::record_wallet_prover_failure(self, backend, code);
    }

    fn record_wallet_sign_latency(
        &self,
        mode: WalletSignMode,
        account_type: WalletAccountType,
        backend: &str,
        duration: Duration,
        success: bool,
    ) {
        RuntimeMetrics::record_wallet_sign_latency(
            self,
            mode,
            account_type,
            backend,
            duration,
            success,
        );
    }

    fn record_wallet_sign_failure(
        &self,
        mode: WalletSignMode,
        account_type: WalletAccountType,
        backend: &str,
        code: &str,
    ) {
        RuntimeMetrics::record_wallet_sign_failure(self, mode, account_type, backend, code);
    }
}

pub struct ProofMetrics {
    generation_duration: EnumF64Histogram<ProofKind>,
    generation_size: EnumU64Histogram<ProofKind>,
    generation_total: EnumCounter<ProofKind>,
    verification_duration: Histogram<f64>,
    global_verification_duration: Histogram<f64>,
    global_verification_size: Histogram<u64>,
    global_verification_failures: Counter<u64>,
    verification_outcomes: Counter<u64>,
    verification_success_ratio: Histogram<f64>,
    incompatible_proofs: Counter<u64>,
    verification_total_bytes: Histogram<u64>,
    verification_total_bytes_by_result: Histogram<u64>,
    verification_params_bytes: Histogram<u64>,
    verification_public_inputs_bytes: Histogram<u64>,
    verification_payload_bytes: Histogram<u64>,
    verification_stage_checks: Counter<u64>,
    cache_hits: Counter<u64>,
    cache_misses: Counter<u64>,
    cache_evictions: Counter<u64>,
    cache_queue_depth: Histogram<u64>,
    cache_max_queue_depth: Histogram<u64>,
    cache_persist_latency: Histogram<f64>,
    cache_load_latency: Histogram<f64>,
    verification_outcome_state:
        Arc<Mutex<BTreeMap<VerificationOutcomeKey, VerificationOutcomeState>>>,
}

impl ProofMetrics {
    fn new(meter: &Meter) -> Self {
        Self {
            generation_duration: EnumF64Histogram::new(
                meter
                    .f64_histogram("rpp.runtime.proof.generation.duration")
                    .with_description("Time spent generating proving artefacts in milliseconds")
                    .with_unit("ms")
                    .build(),
            ),
            generation_size: EnumU64Histogram::new(
                meter
                    .u64_histogram("rpp.runtime.proof.generation.size")
                    .with_description("Size of generated proofs in bytes")
                    .with_unit("By")
                    .build(),
            ),
            generation_total: EnumCounter::new(
                meter
                    .u64_counter("rpp.runtime.proof.generation.count")
                    .with_description("Total number of proofs generated by the runtime")
                    .with_unit("1")
                    .build(),
            ),
            verification_duration: meter
                .f64_histogram("rpp_stark_verify_duration_seconds")
                .with_description(
                    "Duration of proof verification for the RPP-STARK backend in seconds",
                )
                .with_unit("s")
                .build(),
            global_verification_duration: meter
                .f64_histogram("rpp.runtime.global_proof.verify_ms")
                .with_description("Duration of global proof verification in milliseconds")
                .with_unit("ms")
                .build(),
            global_verification_size: meter
                .u64_histogram("rpp.runtime.global_proof.bytes")
                .with_description("Serialized byte length for verified global proofs")
                .with_unit("By")
                .build(),
            global_verification_failures: meter
                .u64_counter("rpp.runtime.global_proof.failures")
                .with_description("Total failed global proof verifications")
                .with_unit("1")
                .build(),
            verification_outcomes: meter
                .u64_counter("rpp.runtime.proof.verification.outcomes")
                .with_description(
                    "Total proof verification outcomes grouped by backend, circuit, and result",
                )
                .with_unit("1")
                .build(),
            verification_success_ratio: meter
                .f64_histogram("rpp.runtime.proof.verification.success_ratio")
                .with_description(
                    "Success ratio for proof verification grouped by backend, circuit, and proof kind",
                )
                .with_unit("1")
                .build(),
            incompatible_proofs: meter
                .u64_counter("rpp.runtime.proof.incompatible")
                .with_description(
                    "Submissions rejected due to incompatible circuits or proof versions",
                )
                .with_unit("1")
                .build(),
            verification_total_bytes: meter
                .u64_histogram("rpp_stark_proof_total_bytes")
                .with_description("Total serialized byte length observed during proof verification")
                .with_unit("By")
                .build(),
            verification_total_bytes_by_result: meter
                .u64_histogram("rpp_stark_proof_total_bytes_by_result")
                .with_description("Total serialized byte length observed during proof verification, annotated with result outcome")
                .with_unit("By")
                .build(),
            verification_params_bytes: meter
                .u64_histogram("rpp_stark_params_bytes")
                .with_description("Parameter segment sizes emitted during proof verification")
                .with_unit("By")
                .build(),
            verification_public_inputs_bytes: meter
                .u64_histogram("rpp_stark_public_inputs_bytes")
                .with_description("Public input segment sizes emitted during proof verification")
                .with_unit("By")
                .build(),
            verification_payload_bytes: meter
                .u64_histogram("rpp_stark_payload_bytes")
                .with_description("Payload segment sizes emitted during proof verification")
                .with_unit("By")
                .build(),
            verification_stage_checks: meter
                .u64_counter("rpp_stark_stage_checks_total")
                .with_description("Verification stage outcomes observed for the RPP-STARK backend")
                .with_unit("1")
                .build(),
            cache_hits: meter
                .u64_counter("rpp.runtime.proof.cache.hits")
                .with_description("Gossip proof cache hits observed by the runtime")
                .with_unit("1")
                .build(),
            cache_misses: meter
                .u64_counter("rpp.runtime.proof.cache.misses")
                .with_description("Gossip proof cache misses observed by the runtime")
                .with_unit("1")
                .build(),
            cache_evictions: meter
                .u64_counter("rpp.runtime.proof.cache.evictions")
                .with_description("Gossip proof cache evictions observed by the runtime")
                .with_unit("1")
                .build(),
            cache_queue_depth: meter
                .u64_histogram("rpp.runtime.proof.cache.queue_depth")
                .with_description("Depth of the gossip proof cache queue")
                .with_unit("1")
                .build(),
            cache_max_queue_depth: meter
                .u64_histogram("rpp.runtime.proof.cache.max_queue_depth")
                .with_description("Peak depth observed for the gossip proof cache queue")
                .with_unit("1")
                .build(),
            cache_persist_latency: meter
                .f64_histogram("rpp.runtime.proof.cache.persist_latency")
                .with_description("Latency of persisting gossip proofs to storage in milliseconds")
                .with_unit("ms")
                .build(),
            cache_load_latency: meter
                .f64_histogram("rpp.runtime.proof.cache.load_latency")
                .with_description("Latency of loading gossip proofs from storage in milliseconds")
                .with_unit("ms")
                .build(),
            verification_outcome_state: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn record_generation_duration(&self, kind: ProofKind, duration: Duration) {
        self.generation_duration.record_duration(kind, duration);
        self.generation_total.add(kind, 1);
    }

    pub fn record_generation_size(&self, kind: ProofKind, bytes: u64) {
        self.generation_size.record(kind, bytes);
    }

    pub fn increment_generation(&self, kind: ProofKind) {
        self.generation_total.add(kind, 1);
    }

    pub fn observe_verification(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        circuit: &str,
        duration: Duration,
    ) {
        let attributes = verification_attributes(backend, kind, circuit);
        self.verification_duration
            .record(duration.as_secs_f64(), &attributes);
    }

    pub fn record_global_verification(
        &self,
        height: u64,
        vk_id: &str,
        version: &str,
        proof_bytes: u64,
        duration: Duration,
        success: bool,
    ) {
        let attributes = [
            KeyValue::new("height", height as i64),
            KeyValue::new("vk_id", vk_id.to_owned()),
            KeyValue::new("version", version.to_owned()),
            KeyValue::new("result", if success { "ok" } else { "err" }),
        ];

        self.global_verification_duration
            .record(duration.as_secs_f64() * 1000.0, &attributes);
        self.global_verification_size
            .record(proof_bytes, &attributes);

        if !success {
            self.global_verification_failures.add(1, &attributes);
        }
    }

    pub fn observe_verification_stage_duration(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        circuit: &str,
        stage: ProofVerificationStage,
        duration: Duration,
    ) {
        let attributes = verification_attributes_with_stage(backend, kind, circuit, stage);
        self.verification_duration
            .record(duration.as_secs_f64(), &attributes);
    }

    pub fn observe_verification_total_bytes(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        circuit: &str,
        bytes: u64,
    ) {
        let attributes = verification_attributes(backend, kind, circuit);
        self.verification_total_bytes.record(bytes, &attributes);
    }

    pub fn observe_verification_total_bytes_by_result(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        circuit: &str,
        outcome: ProofVerificationOutcome,
        bytes: u64,
    ) {
        let attributes = verification_attributes_with_outcome(backend, kind, circuit, outcome);
        self.verification_total_bytes_by_result
            .record(bytes, &attributes);
    }

    pub fn observe_verification_params_bytes(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        circuit: &str,
        bytes: u64,
    ) {
        let attributes = verification_attributes(backend, kind, circuit);
        self.verification_params_bytes.record(bytes, &attributes);
    }

    pub fn observe_verification_public_inputs_bytes(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        circuit: &str,
        bytes: u64,
    ) {
        let attributes = verification_attributes(backend, kind, circuit);
        self.verification_public_inputs_bytes
            .record(bytes, &attributes);
    }

    pub fn observe_verification_payload_bytes(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        circuit: &str,
        bytes: u64,
    ) {
        let attributes = verification_attributes(backend, kind, circuit);
        self.verification_payload_bytes.record(bytes, &attributes);
    }

    pub fn record_cache_events(
        &self,
        cache: &str,
        backend: Option<&str>,
        delta_hits: u64,
        delta_misses: u64,
        delta_evictions: u64,
    ) {
        let attributes = cache_attributes(cache, backend);
        if delta_hits > 0 {
            self.cache_hits.add(delta_hits, &attributes);
        }
        if delta_misses > 0 {
            self.cache_misses.add(delta_misses, &attributes);
        }
        if delta_evictions > 0 {
            self.cache_evictions.add(delta_evictions, &attributes);
        }
    }

    pub fn record_cache_depths(
        &self,
        cache: &str,
        backend: Option<&str>,
        depth: usize,
        max_depth: usize,
    ) {
        let attributes = cache_attributes(cache, backend);
        self.cache_queue_depth.record(depth as u64, &attributes);
        self.cache_max_queue_depth
            .record(max_depth as u64, &attributes);
    }

    pub fn record_cache_io_latencies(
        &self,
        cache: &str,
        backend: Option<&str>,
        load_latency_ms: Option<u64>,
        persist_latency_ms: Option<u64>,
    ) {
        let attributes = cache_attributes(cache, backend);
        if let Some(ms) = load_latency_ms {
            self.cache_load_latency.record(ms as f64, &attributes);
        }
        if let Some(ms) = persist_latency_ms {
            self.cache_persist_latency.record(ms as f64, &attributes);
        }
    }

    pub fn observe_verification_stage(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        circuit: &str,
        stage: ProofVerificationStage,
        outcome: ProofVerificationOutcome,
    ) {
        let attributes =
            verification_attributes_with_stage_and_outcome(backend, kind, circuit, stage, outcome);
        self.verification_stage_checks.add(1, &attributes);
    }

    pub fn record_verification_outcome(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        circuit: &str,
        outcome: ProofVerificationOutcome,
    ) {
        let attributes = verification_attributes_with_outcome(backend, kind, circuit, outcome);
        self.verification_outcomes.add(1, &attributes);

        let key = verification_outcome_key(backend, kind, circuit);
        let mut guard = self.verification_outcome_state.lock();
        let entry = guard
            .entry(key)
            .or_insert_with(VerificationOutcomeState::default);
        let ratio = entry.record(outcome);
        let ratio_attributes = verification_ratio_attributes(backend, kind, circuit);
        self.verification_success_ratio
            .record(ratio, &ratio_attributes);
    }

    pub fn record_incompatible_proof(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        circuit: &str,
        reason: &str,
    ) {
        let attributes = verification_attributes_with_reason(backend, kind, circuit, reason);
        self.incompatible_proofs.add(1, &attributes);
    }
}

fn verification_attributes(
    backend: ProofVerificationBackend,
    kind: ProofVerificationKind,
    circuit: &str,
) -> [KeyValue; 3] {
    [
        KeyValue::new(ProofVerificationBackend::KEY, backend.as_str()),
        KeyValue::new(ProofVerificationKind::KEY, kind.as_str()),
        KeyValue::new(PROOF_CIRCUIT_KEY, circuit.to_string()),
    ]
}

fn cache_attributes(cache: &str, backend: Option<&str>) -> Vec<KeyValue> {
    let mut attributes = vec![KeyValue::new("cache", cache.to_string())];
    if let Some(backend) = backend {
        attributes.push(KeyValue::new("backend", backend.to_string()));
    }
    attributes
}

fn verification_ratio_attributes(
    backend: ProofVerificationBackend,
    kind: ProofVerificationKind,
    circuit: &str,
) -> [KeyValue; 3] {
    [
        KeyValue::new(ProofVerificationBackend::KEY, backend.as_str()),
        KeyValue::new(ProofVerificationKind::KEY, kind.as_str()),
        KeyValue::new(PROOF_CIRCUIT_KEY, circuit.to_string()),
    ]
}

fn verification_attributes_with_outcome(
    backend: ProofVerificationBackend,
    kind: ProofVerificationKind,
    circuit: &str,
    outcome: ProofVerificationOutcome,
) -> [KeyValue; 4] {
    [
        KeyValue::new(ProofVerificationBackend::KEY, backend.as_str()),
        KeyValue::new(ProofVerificationKind::KEY, kind.as_str()),
        KeyValue::new(PROOF_CIRCUIT_KEY, circuit.to_string()),
        KeyValue::new(ProofVerificationOutcome::KEY, outcome.as_str()),
    ]
}

fn verification_attributes_with_reason(
    backend: ProofVerificationBackend,
    kind: ProofVerificationKind,
    circuit: &str,
    reason: &str,
) -> [KeyValue; 4] {
    [
        KeyValue::new(ProofVerificationBackend::KEY, backend.as_str()),
        KeyValue::new(ProofVerificationKind::KEY, kind.as_str()),
        KeyValue::new(PROOF_CIRCUIT_KEY, circuit.to_string()),
        KeyValue::new(PROOF_INCOMPATIBILITY_REASON_KEY, reason.to_string()),
    ]
}

fn verification_attributes_with_stage(
    backend: ProofVerificationBackend,
    kind: ProofVerificationKind,
    circuit: &str,
    stage: ProofVerificationStage,
) -> [KeyValue; 4] {
    [
        KeyValue::new(ProofVerificationBackend::KEY, backend.as_str()),
        KeyValue::new(ProofVerificationKind::KEY, kind.as_str()),
        KeyValue::new(PROOF_CIRCUIT_KEY, circuit.to_string()),
        KeyValue::new(ProofVerificationStage::KEY, stage.as_str()),
    ]
}

fn verification_attributes_with_stage_and_outcome(
    backend: ProofVerificationBackend,
    kind: ProofVerificationKind,
    circuit: &str,
    stage: ProofVerificationStage,
    outcome: ProofVerificationOutcome,
) -> [KeyValue; 5] {
    [
        KeyValue::new(ProofVerificationBackend::KEY, backend.as_str()),
        KeyValue::new(ProofVerificationKind::KEY, kind.as_str()),
        KeyValue::new(PROOF_CIRCUIT_KEY, circuit.to_string()),
        KeyValue::new(ProofVerificationStage::KEY, stage.as_str()),
        KeyValue::new(ProofVerificationOutcome::KEY, outcome.as_str()),
    ]
}

/// Guard that shuts down the underlying meter provider when dropped.
pub struct RuntimeMetricsGuard {
    provider: Option<SdkMeterProvider>,
    _callbacks: Vec<CallbackRegistration>,
}

impl RuntimeMetricsGuard {
    fn new(provider: SdkMeterProvider, callbacks: Vec<CallbackRegistration>) -> Self {
        Self {
            provider: Some(provider),
            _callbacks: callbacks,
        }
    }

    /// Flush any pending metric data and shutdown the provider, restoring the noop provider.
    pub fn flush_and_shutdown(&mut self) {
        if let Some(provider) = self.provider.take() {
            if let Err(err) = provider.force_flush() {
                warn!(
                    target: "telemetry",
                    "failed to flush OTLP metrics provider: {err}"
                );
            }
            if let Err(err) = provider.shutdown() {
                warn!(
                    target: "telemetry",
                    "failed to shutdown OTLP metrics provider: {err}"
                );
            }
            global::set_meter_provider(NoopMeterProvider::new());
        }
    }
}

impl Drop for RuntimeMetricsGuard {
    fn drop(&mut self) {
        self.flush_and_shutdown();
    }
}

/// Enumeration capturing the distinct phases of the consensus pipeline.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ConsensusStage {
    /// Stage responsible for proposing a block.
    Proposal,
    /// Stage executing the block contents.
    Execution,
    /// Stage verifying and voting on proposals.
    Validation,
    /// Stage finalising committed blocks.
    Commitment,
}

impl MetricLabel for ConsensusStage {
    const KEY: &'static str = "stage";

    fn as_str(&self) -> &'static str {
        match self {
            Self::Proposal => "proposal",
            Self::Execution => "execution",
            Self::Validation => "validation",
            Self::Commitment => "commitment",
        }
    }
}

/// Wallet RPC surface area that is traced via metrics.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum WalletRpcMethod {
    /// Runtime level liveness probes emitted internally.
    RuntimeStatus,
    /// JSON-RPC: `get_balance`.
    JsonGetBalance,
    /// JSON-RPC: `list_utxos`.
    JsonListUtxos,
    /// JSON-RPC: `list_txs`.
    JsonListTransactions,
    /// JSON-RPC: `derive_address`.
    JsonDeriveAddress,
    /// JSON-RPC: `create_tx`.
    JsonCreateTransaction,
    /// JSON-RPC: `sign_tx`.
    JsonSignTransaction,
    /// JSON-RPC: `prover.status`.
    JsonProverStatus,
    /// JSON-RPC: `prover.meta`.
    JsonProverMeta,
    /// JSON-RPC: `hw.enumerate`.
    JsonHwEnumerate,
    /// JSON-RPC: `hw.sign`.
    JsonHwSign,
    /// JSON-RPC: `backup.export`.
    JsonBackupExport,
    /// JSON-RPC: `backup.validate`.
    JsonBackupValidate,
    /// JSON-RPC: `backup.import`.
    JsonBackupImport,
    /// JSON-RPC: `watch_only.status`.
    JsonWatchOnlyStatus,
    /// JSON-RPC: `watch_only.enable`.
    JsonWatchOnlyEnable,
    /// JSON-RPC: `watch_only.disable`.
    JsonWatchOnlyDisable,
    /// JSON-RPC: `lifecycle.status`.
    JsonLifecycleStatus,
    /// JSON-RPC: `lifecycle.start`.
    JsonLifecycleStart,
    /// JSON-RPC: `lifecycle.stop`.
    JsonLifecycleStop,
    /// JSON-RPC: `multisig.get_scope`.
    #[cfg(feature = "wallet_multisig_hooks")]
    JsonMultisigGetScope,
    /// JSON-RPC: `multisig.set_scope`.
    #[cfg(feature = "wallet_multisig_hooks")]
    JsonMultisigSetScope,
    /// JSON-RPC: `multisig.get_cosigners`.
    #[cfg(feature = "wallet_multisig_hooks")]
    JsonMultisigGetCosigners,
    /// JSON-RPC: `multisig.set_cosigners`.
    #[cfg(feature = "wallet_multisig_hooks")]
    JsonMultisigSetCosigners,
    /// JSON-RPC: `multisig.export`.
    #[cfg(feature = "wallet_multisig_hooks")]
    JsonMultisigExport,
    /// JSON-RPC: `broadcast`.
    JsonBroadcast,
    /// JSON-RPC: `policy_preview`.
    JsonPolicyPreview,
    /// JSON-RPC: `get_policy`.
    JsonGetPolicy,
    /// JSON-RPC: `set_policy`.
    JsonSetPolicy,
    /// JSON-RPC: `estimate_fee`.
    JsonEstimateFee,
    /// JSON-RPC: `list_pending_locks`.
    JsonListPendingLocks,
    /// JSON-RPC: `release_pending_locks`.
    JsonReleasePendingLocks,
    /// JSON-RPC: `sync_status`.
    JsonSyncStatus,
    /// JSON-RPC: `rescan`.
    JsonRescan,
    /// JSON-RPC: `rescan.status`.
    JsonRescanStatus,
    /// JSON-RPC: `rescan.abort`.
    JsonRescanAbort,
    /// JSON-RPC: `zsi_prove`.
    #[cfg(feature = "wallet_zsi")]
    JsonZsiProve,
    /// JSON-RPC: `zsi_verify`.
    #[cfg(feature = "wallet_zsi")]
    JsonZsiVerify,
    /// JSON-RPC: `zsi_bind_account`.
    #[cfg(feature = "wallet_zsi")]
    JsonZsiBindAccount,
    /// JSON-RPC: `zsi_list`.
    #[cfg(feature = "wallet_zsi")]
    JsonZsiList,
    /// JSON-RPC: `zsi_delete`.
    #[cfg(feature = "wallet_zsi")]
    JsonZsiDelete,
    /// REST: `/wallet/state/root`.
    StateRoot,
    /// REST: `/wallet/ui/history`.
    UiHistory,
    /// REST: `/wallet/ui/send/preview`.
    UiSendPreview,
    /// REST: `/wallet/ui/receive`.
    UiReceive,
    /// REST: `/wallet/ui/node`.
    UiNode,
    /// REST: `/wallet/account`.
    Account,
    /// REST: `/wallet/balance/:address`.
    Balance,
    /// REST: `/wallet/reputation/:address`.
    Reputation,
    /// REST: `/wallet/tier/:address`.
    Tier,
    /// REST: `/wallet/history`.
    History,
    /// REST: `/wallet/send/preview`.
    SendPreview,
    /// REST: `/wallet/tx/build`.
    BuildTransaction,
    /// REST: `/wallet/tx/sign`.
    SignTransaction,
    /// REST: `/wallet/tx/prove`.
    ProveTransaction,
    /// REST: `/wallet/tx/submit`.
    SubmitTransaction,
    /// REST: `/wallet/receive`.
    ReceiveAddresses,
    /// REST: `/wallet/node`.
    NodeView,
    /// REST: `/wallet/uptime/scheduler`.
    UptimeSchedulerStatus,
    /// REST: `/wallet/uptime/scheduler/trigger`.
    UptimeSchedulerTrigger,
    /// REST: `/wallet/uptime/scheduler/offload`.
    UptimeSchedulerOffload,
    /// REST: `/wallet/uptime/proof`.
    UptimeProofGenerate,
    /// REST: `/wallet/uptime/submit`.
    UptimeSubmit,
    /// REST: `/wallet/pipeline/dashboard`.
    PipelineDashboard,
    /// REST: `/wallet/pipeline/telemetry`.
    PipelineTelemetry,
    /// REST: `/wallet/pipeline/stream`.
    PipelineStream,
    /// REST: `/wallet/pipeline/wait`.
    PipelineWait,
    /// REST: `/wallet/pipeline/shutdown`.
    PipelineShutdown,
    /// Any wallet RPC that does not match a known endpoint.
    Unknown,
}

impl MetricLabel for WalletRpcMethod {
    const KEY: &'static str = "method";

    fn as_str(&self) -> &'static str {
        match self {
            Self::RuntimeStatus => "runtime_status",
            Self::JsonGetBalance => "json_get_balance",
            Self::JsonListUtxos => "json_list_utxos",
            Self::JsonListTransactions => "json_list_transactions",
            Self::JsonDeriveAddress => "json_derive_address",
            Self::JsonCreateTransaction => "json_create_transaction",
            Self::JsonSignTransaction => "json_sign_transaction",
            Self::JsonProverStatus => "json_prover_status",
            Self::JsonProverMeta => "json_prover_meta",
            Self::JsonHwEnumerate => "json_hw_enumerate",
            Self::JsonHwSign => "json_hw_sign",
            Self::JsonBackupExport => "json_backup_export",
            Self::JsonBackupValidate => "json_backup_validate",
            Self::JsonBackupImport => "json_backup_import",
            Self::JsonWatchOnlyStatus => "json_watch_only_status",
            Self::JsonWatchOnlyEnable => "json_watch_only_enable",
            Self::JsonWatchOnlyDisable => "json_watch_only_disable",
            Self::JsonLifecycleStatus => "json_lifecycle_status",
            Self::JsonLifecycleStart => "json_lifecycle_start",
            Self::JsonLifecycleStop => "json_lifecycle_stop",
            #[cfg(feature = "wallet_multisig_hooks")]
            Self::JsonMultisigGetScope => "json_multisig_get_scope",
            #[cfg(feature = "wallet_multisig_hooks")]
            Self::JsonMultisigSetScope => "json_multisig_set_scope",
            #[cfg(feature = "wallet_multisig_hooks")]
            Self::JsonMultisigGetCosigners => "json_multisig_get_cosigners",
            #[cfg(feature = "wallet_multisig_hooks")]
            Self::JsonMultisigSetCosigners => "json_multisig_set_cosigners",
            #[cfg(feature = "wallet_multisig_hooks")]
            Self::JsonMultisigExport => "json_multisig_export",
            Self::JsonBroadcast => "json_broadcast",
            Self::JsonPolicyPreview => "json_policy_preview",
            Self::JsonGetPolicy => "json_get_policy",
            Self::JsonSetPolicy => "json_set_policy",
            Self::JsonEstimateFee => "json_estimate_fee",
            Self::JsonListPendingLocks => "json_list_pending_locks",
            Self::JsonReleasePendingLocks => "json_release_pending_locks",
            Self::JsonSyncStatus => "json_sync_status",
            Self::JsonRescan => "json_rescan",
            Self::JsonRescanStatus => "json_rescan_status",
            Self::JsonRescanAbort => "json_rescan_abort",
            #[cfg(feature = "wallet_zsi")]
            Self::JsonZsiProve => "json_zsi_prove",
            #[cfg(feature = "wallet_zsi")]
            Self::JsonZsiVerify => "json_zsi_verify",
            #[cfg(feature = "wallet_zsi")]
            Self::JsonZsiBindAccount => "json_zsi_bind_account",
            #[cfg(feature = "wallet_zsi")]
            Self::JsonZsiList => "json_zsi_list",
            #[cfg(feature = "wallet_zsi")]
            Self::JsonZsiDelete => "json_zsi_delete",
            Self::StateRoot => "state_root",
            Self::UiHistory => "ui_history",
            Self::UiSendPreview => "ui_send_preview",
            Self::UiReceive => "ui_receive",
            Self::UiNode => "ui_node",
            Self::Account => "account",
            Self::Balance => "balance",
            Self::Reputation => "reputation",
            Self::Tier => "tier",
            Self::History => "history",
            Self::SendPreview => "send_preview",
            Self::BuildTransaction => "build_transaction",
            Self::SignTransaction => "sign_transaction",
            Self::ProveTransaction => "prove_transaction",
            Self::SubmitTransaction => "submit_transaction",
            Self::ReceiveAddresses => "receive_addresses",
            Self::NodeView => "node_view",
            Self::UptimeSchedulerStatus => "uptime_scheduler_status",
            Self::UptimeSchedulerTrigger => "uptime_scheduler_trigger",
            Self::UptimeSchedulerOffload => "uptime_scheduler_offload",
            Self::UptimeProofGenerate => "uptime_proof_generate",
            Self::UptimeSubmit => "uptime_submit",
            Self::PipelineDashboard => "pipeline_dashboard",
            Self::PipelineTelemetry => "pipeline_telemetry",
            Self::PipelineStream => "pipeline_stream",
            Self::PipelineWait => "pipeline_wait",
            Self::PipelineShutdown => "pipeline_shutdown",
            Self::Unknown => "unknown",
        }
    }
}

impl MetricLabel for WalletAction {
    const KEY: &'static str = "action";

    fn as_str(&self) -> &'static str {
        match self {
            Self::BackupExport => "backup.export",
            Self::BackupValidate => "backup.validate",
            Self::BackupImport => "backup.import",
            Self::WatchOnlyStatus => "watch_only.status",
            Self::WatchOnlyEnable => "watch_only.enable",
            Self::WatchOnlyDisable => "watch_only.disable",
            #[cfg(feature = "wallet_multisig_hooks")]
            Self::MultisigGetScope => "multisig.get_scope",
            #[cfg(feature = "wallet_multisig_hooks")]
            Self::MultisigSetScope => "multisig.set_scope",
            #[cfg(feature = "wallet_multisig_hooks")]
            Self::MultisigGetCosigners => "multisig.get_cosigners",
            #[cfg(feature = "wallet_multisig_hooks")]
            Self::MultisigSetCosigners => "multisig.set_cosigners",
            #[cfg(feature = "wallet_multisig_hooks")]
            Self::MultisigExport => "multisig.export",
            #[cfg(feature = "wallet_zsi")]
            Self::ZsiProve => "zsi.prove",
            #[cfg(feature = "wallet_zsi")]
            Self::ZsiVerify => "zsi.verify",
            #[cfg(feature = "wallet_zsi")]
            Self::ZsiBindAccount => "zsi.bind_account",
            #[cfg(feature = "wallet_zsi")]
            Self::ZsiList => "zsi.list",
            #[cfg(feature = "wallet_zsi")]
            Self::ZsiDelete => "zsi.delete",
            Self::HwEnumerate => "hw.enumerate",
            Self::HwSign => "hw.sign",
        }
    }
}

impl MetricLabel for WalletActionResult {
    const KEY: &'static str = "outcome";

    fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "ok",
            Self::Error => "err",
        }
    }
}

/// Node RPC surface area exposed to operators and clients.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum NodeRpcMethod {
    Health,
    HealthLive,
    HealthReady,
    RuntimeMode,
    UiNode,
    UiReputation,
    UiBftMembership,
    ValidatorStatus,
    ValidatorProofs,
    ValidatorPeers,
    ValidatorTelemetry,
    ValidatorVrf,
    ValidatorRotateVrf,
    ValidatorSubmitUptime,
    P2pPeers,
    P2pCensorship,
    AdmissionPolicies,
    AdmissionPoliciesPending,
    AdmissionPoliciesApprove,
    AdmissionAudit,
    AdmissionBackups,
    P2pSnapshotStart,
    P2pSnapshotStatus,
    P2pSnapshotBreakerStatus,
    P2pSnapshotBreakerReset,
    P2pAccessLists,
    NodeStatus,
    MempoolStatus,
    UpdateMempoolLimits,
    ConsensusStatus,
    RolloutStatus,
    VrfSubmit,
    VrfThreshold,
    VrfStatus,
    ProofStatus,
    SubmitTransaction,
    SubmitIdentity,
    SubmitVote,
    SubmitUptimeProof,
    SlashingEvents,
    TimetokeSnapshot,
    TimetokeSync,
    TimetokeReplay,
    ReputationAudit,
    ReputationAuditStream,
    SlashingAuditStream,
    LatestBlock,
    BlockByHeight,
    AccountInfo,
    Unknown,
}

impl MetricLabel for NodeRpcMethod {
    const KEY: &'static str = "method";

    fn as_str(&self) -> &'static str {
        match self {
            Self::Health => "node_health",
            Self::HealthLive => "node_health_live",
            Self::HealthReady => "node_health_ready",
            Self::RuntimeMode => "node_runtime_mode",
            Self::UiNode => "node_ui_node",
            Self::UiReputation => "node_ui_reputation",
            Self::UiBftMembership => "node_ui_bft_membership",
            Self::ValidatorStatus => "node_validator_status",
            Self::ValidatorProofs => "node_validator_proofs",
            Self::ValidatorPeers => "node_validator_peers",
            Self::ValidatorTelemetry => "node_validator_telemetry",
            Self::ValidatorVrf => "node_validator_vrf",
            Self::ValidatorRotateVrf => "node_validator_vrf_rotate",
            Self::ValidatorSubmitUptime => "node_validator_submit_uptime",
            Self::P2pPeers => "node_p2p_peers",
            Self::P2pCensorship => "node_p2p_censorship",
            Self::AdmissionPolicies => "node_admission_policies",
            Self::AdmissionPoliciesPending => "node_admission_policies_pending",
            Self::AdmissionPoliciesApprove => "node_admission_policies_approve",
            Self::AdmissionAudit => "node_admission_audit_log",
            Self::AdmissionBackups => "node_admission_backups",
            Self::P2pSnapshotStart => "node_p2p_snapshot_start",
            Self::P2pSnapshotStatus => "node_p2p_snapshot_status",
            Self::P2pSnapshotBreakerStatus => "node_p2p_snapshot_breaker_status",
            Self::P2pSnapshotBreakerReset => "node_p2p_snapshot_breaker_reset",
            Self::P2pAccessLists => "node_p2p_access_lists",
            Self::NodeStatus => "node_status",
            Self::MempoolStatus => "node_mempool_status",
            Self::UpdateMempoolLimits => "node_update_mempool_limits",
            Self::ConsensusStatus => "node_consensus_status",
            Self::RolloutStatus => "node_rollout_status",
            Self::VrfSubmit => "node_vrf_submit",
            Self::VrfThreshold => "node_vrf_threshold",
            Self::VrfStatus => "node_vrf_status",
            Self::ProofStatus => "node_proof_status",
            Self::SubmitTransaction => "node_submit_transaction",
            Self::SubmitIdentity => "node_submit_identity",
            Self::SubmitVote => "node_submit_vote",
            Self::SubmitUptimeProof => "node_submit_uptime_proof",
            Self::SlashingEvents => "node_slashing_events",
            Self::TimetokeSnapshot => "node_timetoke_snapshot",
            Self::TimetokeSync => "node_timetoke_sync",
            Self::TimetokeReplay => "node_timetoke_replay",
            Self::ReputationAudit => "node_reputation_audit",
            Self::ReputationAuditStream => "node_reputation_audit_stream",
            Self::SlashingAuditStream => "node_slashing_audit_stream",
            Self::LatestBlock => "node_latest_block",
            Self::BlockByHeight => "node_block_by_height",
            Self::AccountInfo => "node_account_info",
            Self::Unknown => "node_unknown",
        }
    }
}

/// Snapshot and state-sync RPC handlers.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum SnapshotRpcMethod {
    SnapshotPlan,
    SnapshotJobs,
    SnapshotRebuild,
    SnapshotTrigger,
    SnapshotCancel,
    PruningStatus,
    PruningStatusStream,
    StateSyncPlan,
    StateSyncSessionStatus,
    StateSyncSessionStream,
    StateSyncHeadStream,
    StateSyncChunk,
    Unknown,
}

impl MetricLabel for SnapshotRpcMethod {
    const KEY: &'static str = "method";

    fn as_str(&self) -> &'static str {
        match self {
            Self::SnapshotPlan => "snapshot_plan",
            Self::SnapshotJobs => "snapshot_jobs",
            Self::SnapshotRebuild => "snapshot_rebuild",
            Self::SnapshotTrigger => "snapshot_trigger",
            Self::SnapshotCancel => "snapshot_cancel",
            Self::PruningStatus => "pruning_status",
            Self::PruningStatusStream => "pruning_status_stream",
            Self::StateSyncPlan => "state_sync_plan",
            Self::StateSyncSessionStatus => "state_sync_session_status",
            Self::StateSyncSessionStream => "state_sync_session_stream",
            Self::StateSyncHeadStream => "state_sync_head_stream",
            Self::StateSyncChunk => "state_sync_chunk",
            Self::Unknown => "snapshot_unknown",
        }
    }
}

/// RPC handlers grouped by logical subsystem.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum RpcMethod {
    /// Node RPC handlers exposed for operators and clients.
    Node(NodeRpcMethod),
    /// Wallet-centric RPC handlers.
    Wallet(WalletRpcMethod),
    /// Proof related RPC handlers.
    Proof(ProofRpcMethod),
    /// Snapshot/state-sync related handlers.
    Snapshot(SnapshotRpcMethod),
    /// Any other handler that is not explicitly categorised.
    Other,
}

/// RPC handlers grouped by read/write semantics.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum RpcClass {
    Read,
    Write,
}

impl MetricLabel for RpcMethod {
    const KEY: &'static str = "method";

    fn as_str(&self) -> &'static str {
        match self {
            Self::Node(method) => method.as_str(),
            Self::Wallet(method) => method.as_str(),
            Self::Proof(method) => method.as_str(),
            Self::Snapshot(method) => method.as_str(),
            Self::Other => "other",
        }
    }
}

impl MetricLabel for RpcClass {
    const KEY: &'static str = "class";

    fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// Aggregated outcomes for RPC invocations.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum RpcResult {
    Success,
    ClientError,
    ServerError,
}

/// Outcomes for rate-limit checks on RPC invocations.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum RpcRateLimitStatus {
    Allowed,
    Throttled,
}

#[derive(Clone, Copy, Debug)]
pub enum ConsensusRpcFailure {
    VerifierFailed,
    FinalityGap,
}

impl RpcRateLimitStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Throttled => "throttled",
        }
    }
}

impl MetricLabel for RpcRateLimitStatus {
    const KEY: &'static str = "status";

    fn as_str(&self) -> &'static str {
        self.as_str()
    }
}

impl MetricLabel for ConsensusRpcFailure {
    const KEY: &'static str = "reason";

    fn as_str(&self) -> &'static str {
        match self {
            Self::VerifierFailed => "verifier_failed",
            Self::FinalityGap => "finality_gap",
        }
    }
}

impl RpcResult {
    pub fn from_status(status: StatusCode) -> Self {
        if status.is_success() {
            Self::Success
        } else if status.is_client_error() {
            Self::ClientError
        } else {
            Self::ServerError
        }
    }

    pub const fn from_error() -> Self {
        Self::ServerError
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::ClientError => "client_error",
            Self::ServerError => "server_error",
        }
    }
}

impl MetricLabel for RpcResult {
    const KEY: &'static str = "result";

    fn as_str(&self) -> &'static str {
        self.as_str()
    }
}

/// Proof specific RPC handlers.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProofRpcMethod {
    /// Block proof retrieval endpoints.
    Block,
    /// Validator proof inspection endpoints.
    Validator,
    /// Wallet initiated proof operations.
    Wallet,
}

impl MetricLabel for ProofRpcMethod {
    const KEY: &'static str = "method";

    fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block_proof",
            Self::Validator => "validator_proof",
            Self::Wallet => "wallet_proof",
        }
    }
}

impl StorageMetricsFacade for RuntimeMetrics {
    fn record_header_flush_duration(&self, duration: Duration) {
        RuntimeMetrics::record_header_flush_duration(self, duration);
    }

    fn record_header_flush_bytes(&self, bytes: u64) {
        RuntimeMetrics::record_header_flush_bytes(self, bytes);
    }

    fn increment_header_flushes(&self) {
        RuntimeMetrics::increment_header_flushes(self);
    }

    fn record_wal_flush_duration(&self, outcome: StorageWalFlushOutcome, duration: Duration) {
        let outcome = WalFlushOutcome::from(outcome);
        RuntimeMetrics::record_wal_flush_duration(self, outcome, duration);
    }

    fn record_wal_flush_bytes(&self, outcome: StorageWalFlushOutcome, bytes: u64) {
        let outcome = WalFlushOutcome::from(outcome);
        RuntimeMetrics::record_wal_flush_bytes(self, outcome, bytes);
    }

    fn increment_wal_flushes(&self, outcome: StorageWalFlushOutcome) {
        let outcome = WalFlushOutcome::from(outcome);
        RuntimeMetrics::increment_wal_flushes(self, outcome);
    }
}

/// Outcomes emitted when flushing the write-ahead log.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum WalFlushOutcome {
    /// Flush completed successfully on the first attempt.
    Success,
    /// Flush required a retry but eventually succeeded.
    Retried,
    /// Flush failed permanently.
    Failed,
}

impl From<StorageWalFlushOutcome> for WalFlushOutcome {
    fn from(value: StorageWalFlushOutcome) -> Self {
        match value {
            StorageWalFlushOutcome::Success => WalFlushOutcome::Success,
            StorageWalFlushOutcome::Retried => WalFlushOutcome::Retried,
            StorageWalFlushOutcome::Failed => WalFlushOutcome::Failed,
        }
    }
}

impl MetricLabel for WalFlushOutcome {
    const KEY: &'static str = "outcome";

    fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Retried => "retried",
            Self::Failed => "failed",
        }
    }
}

/// Supported proving backends used by the runtime.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProofKind {
    /// Production STWO proving backend.
    Stwo,
    /// Production Plonky3 proving backend.
    Plonky3,
    /// Deterministic mock backend for tests.
    Mock,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProofVerificationBackend {
    Stwo,
    RppStark,
}

const PROOF_CIRCUIT_KEY: &str = "proof_circuit";
const PROOF_INCOMPATIBILITY_REASON_KEY: &str = "incompatibility_reason";

impl ProofVerificationBackend {
    pub const KEY: &'static str = "proof_backend";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stwo => "stwo",
            Self::RppStark => "rpp-stark",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProofVerificationKind {
    Transaction,
    State,
    Pruning,
    Consensus,
    Recursive,
}

impl ProofVerificationKind {
    pub const KEY: &'static str = "proof_kind";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transaction => "transaction",
            Self::State => "state",
            Self::Pruning => "pruning",
            Self::Consensus => "consensus",
            Self::Recursive => "recursive",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProofVerificationStage {
    Parse,
    Params,
    Public,
    Merkle,
    Fri,
    Adapter,
    Composition,
}

impl ProofVerificationStage {
    pub const KEY: &'static str = "stage";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::Params => "params",
            Self::Public => "public",
            Self::Merkle => "merkle",
            Self::Fri => "fri",
            Self::Adapter => "adapter",
            Self::Composition => "composition",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProofVerificationOutcome {
    Ok,
    Fail,
}

impl ProofVerificationOutcome {
    pub const KEY: &'static str = "result";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Fail => "fail",
        }
    }

    pub const fn from_bool(ok: bool) -> Self {
        if ok {
            Self::Ok
        } else {
            Self::Fail
        }
    }
}

type VerificationOutcomeKey = (String, String, String);

#[derive(Default)]
struct VerificationOutcomeState {
    success: u64,
    failure: u64,
}

impl VerificationOutcomeState {
    fn record(&mut self, outcome: ProofVerificationOutcome) -> f64 {
        match outcome {
            ProofVerificationOutcome::Ok => self.success = self.success.saturating_add(1),
            ProofVerificationOutcome::Fail => self.failure = self.failure.saturating_add(1),
        }

        let total = self.success.saturating_add(self.failure) as f64;
        if total > 0.0 {
            self.success as f64 / total
        } else {
            0.0
        }
    }
}

fn verification_outcome_key(
    backend: ProofVerificationBackend,
    kind: ProofVerificationKind,
    circuit: &str,
) -> VerificationOutcomeKey {
    (
        backend.as_str().to_string(),
        kind.as_str().to_string(),
        circuit.to_string(),
    )
}

impl MetricLabel for ProofKind {
    const KEY: &'static str = "backend";

    fn as_str(&self) -> &'static str {
        match self {
            Self::Stwo => "stwo",
            Self::Plonky3 => "plonky3",
            Self::Mock => "mock",
        }
    }
}

trait MetricLabel {
    const KEY: &'static str;

    fn as_str(&self) -> &'static str;
}

#[derive(Clone)]
struct EnumF64Histogram<L: MetricLabel> {
    histogram: Histogram<f64>,
    _marker: PhantomData<L>,
}

impl<L: MetricLabel> EnumF64Histogram<L> {
    fn new(histogram: Histogram<f64>) -> Self {
        Self {
            histogram,
            _marker: PhantomData,
        }
    }

    fn record_duration(&self, label: L, duration: Duration) {
        self.record(label, duration.as_secs_f64() * MILLIS_PER_SECOND);
    }

    fn record(&self, label: L, value: f64) {
        let attributes = [KeyValue::new(L::KEY, label.as_str())];
        self.histogram.record(value, &attributes);
    }
}

#[derive(Clone)]
struct EnumU64Histogram<L: MetricLabel> {
    histogram: Histogram<u64>,
    _marker: PhantomData<L>,
}

impl<L: MetricLabel> EnumU64Histogram<L> {
    fn new(histogram: Histogram<u64>) -> Self {
        Self {
            histogram,
            _marker: PhantomData,
        }
    }

    fn record(&self, label: L, value: u64) {
        let attributes = [KeyValue::new(L::KEY, label.as_str())];
        self.histogram.record(value, &attributes);
    }
}

#[derive(Clone)]
struct EnumCounter<L: MetricLabel> {
    counter: Counter<u64>,
    _marker: PhantomData<L>,
}

#[derive(Clone)]
struct RpcHistogram<M: MetricLabel, R: MetricLabel> {
    histogram: Histogram<f64>,
    _marker: PhantomData<(M, R)>,
}

impl<M: MetricLabel, R: MetricLabel> RpcHistogram<M, R> {
    fn new(histogram: Histogram<f64>) -> Self {
        Self {
            histogram,
            _marker: PhantomData,
        }
    }

    fn record_duration(&self, method: M, result: R, duration: Duration) {
        self.record(method, result, duration.as_secs_f64() * MILLIS_PER_SECOND);
    }

    fn record(&self, method: M, result: R, value: f64) {
        let attributes = [
            KeyValue::new(M::KEY, method.as_str()),
            KeyValue::new(R::KEY, result.as_str()),
        ];
        self.histogram.record(value, &attributes);
    }
}

#[derive(Clone)]
struct RpcCounter<M: MetricLabel, R: MetricLabel> {
    counter: Counter<u64>,
    _marker: PhantomData<(M, R)>,
}

impl<M: MetricLabel, R: MetricLabel> RpcCounter<M, R> {
    fn new(counter: Counter<u64>) -> Self {
        Self {
            counter,
            _marker: PhantomData,
        }
    }

    fn add(&self, method: M, result: R, value: u64) {
        let attributes = [
            KeyValue::new(M::KEY, method.as_str()),
            KeyValue::new(R::KEY, result.as_str()),
        ];
        self.counter.add(value, &attributes);
    }
}

#[derive(Clone)]
struct RpcRateLimitCounter<C: MetricLabel, M: MetricLabel, R: MetricLabel> {
    counter: Counter<u64>,
    _marker: PhantomData<(C, M, R)>,
}

impl<C: MetricLabel, M: MetricLabel, R: MetricLabel> RpcRateLimitCounter<C, M, R> {
    fn new(counter: Counter<u64>) -> Self {
        Self {
            counter,
            _marker: PhantomData,
        }
    }

    fn add(&self, class: C, method: M, result: R, tenant: Option<&str>, value: u64) {
        match tenant {
            Some(tenant) => {
                let attributes = [
                    KeyValue::new(C::KEY, class.as_str()),
                    KeyValue::new(M::KEY, method.as_str()),
                    KeyValue::new(R::KEY, result.as_str()),
                    KeyValue::new("tenant", tenant),
                ];
                self.counter.add(value, &attributes);
            }
            None => {
                let attributes = [
                    KeyValue::new(C::KEY, class.as_str()),
                    KeyValue::new(M::KEY, method.as_str()),
                    KeyValue::new(R::KEY, result.as_str()),
                ];
                self.counter.add(value, &attributes);
            }
        }
    }
}

#[derive(Clone)]
struct RpcClassCounter<C: MetricLabel, M: MetricLabel, R: MetricLabel> {
    counter: Counter<u64>,
    _marker: PhantomData<(C, M, R)>,
}

impl<C: MetricLabel, M: MetricLabel, R: MetricLabel> RpcClassCounter<C, M, R> {
    fn new(counter: Counter<u64>) -> Self {
        Self {
            counter,
            _marker: PhantomData,
        }
    }

    fn add(&self, class: C, method: M, result: R, value: u64) {
        let attributes = [
            KeyValue::new(C::KEY, class.as_str()),
            KeyValue::new(M::KEY, method.as_str()),
            KeyValue::new(R::KEY, result.as_str()),
        ];
        self.counter.add(value, &attributes);
    }
}

impl<L: MetricLabel> EnumCounter<L> {
    fn new(counter: Counter<u64>) -> Self {
        Self {
            counter,
            _marker: PhantomData,
        }
    }

    fn add(&self, label: L, value: u64) {
        let attributes = [KeyValue::new(L::KEY, label.as_str())];
        self.counter.add(value, &attributes);
    }
}

#[cfg(all(test, feature = "wallet-integration"))]
mod tests {
    use super::*;
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, MetricError};
    use std::collections::{HashMap, HashSet};
    use std::sync::{Mutex, OnceLock};

    #[test]
    fn registers_runtime_metrics_instruments() -> std::result::Result<(), MetricError> {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("runtime-test");
        let (metrics, _callbacks) = RuntimeMetrics::from_meter(&meter)?;

        metrics
            .record_consensus_stage_duration(ConsensusStage::Proposal, Duration::from_millis(10));
        metrics.record_wallet_rpc_latency(
            WalletRpcMethod::SubmitTransaction,
            Duration::from_millis(20),
        );
        metrics.record_rpc_request(
            RpcMethod::Wallet(WalletRpcMethod::RuntimeStatus),
            RpcResult::Success,
            Duration::from_millis(25),
        );
        metrics.record_wallet_fee_estimate_latency(Duration::from_millis(21));
        metrics.record_wallet_prover_job_duration("mock", true, Duration::from_millis(22));
        metrics.record_wallet_prover_witness_bytes("mock", 1024);
        metrics.record_wallet_prover_backend("mock", true);
        metrics.record_wallet_prover_failure("mock", "PROVER_INTERNAL");
        metrics.record_wallet_sign_latency(
            WalletSignMode::Online,
            WalletAccountType::Hot,
            "mock",
            Duration::from_millis(28),
            true,
        );
        metrics.record_wallet_sign_failure(
            WalletSignMode::Offline,
            WalletAccountType::Hardware,
            "ledger",
            "HW_REJECTED",
        );
        metrics.record_wallet_rescan_duration(true, Duration::from_millis(23));
        metrics.record_wallet_broadcast_rejected("NODE_REJECTED");
        metrics.record_wal_flush_duration(WalFlushOutcome::Success, Duration::from_millis(30));
        metrics.record_wal_flush_bytes(WalFlushOutcome::Success, 512);
        metrics.increment_wal_flushes(WalFlushOutcome::Success);
        metrics.record_header_flush_duration(Duration::from_millis(12));
        metrics.record_header_flush_bytes(256);
        metrics.increment_header_flushes();
        metrics.record_proof_generation_duration(ProofKind::Stwo, Duration::from_millis(40));
        metrics.record_proof_generation_size(ProofKind::Stwo, 1024);
        metrics.increment_proof_generation(ProofKind::Mock);
        metrics.record_consensus_round_duration(1, 2, Duration::from_millis(50));
        metrics.record_consensus_quorum_latency(1, 2, Duration::from_millis(15));
        metrics.record_consensus_leader_change(1, 2, "leader");
        metrics.record_consensus_witness_event("blocks");
        metrics.record_consensus_slashing_event("invalid_vote");
        metrics.record_consensus_failed_vote("timeout");
        metrics.record_block_height(42);
        metrics.record_peer_count(8);
        metrics.record_reputation_penalty("invalid_proof");
        metrics.proofs().observe_verification(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Transaction,
            ProofVerificationKind::Transaction.as_str(),
            Duration::from_millis(5),
        );
        metrics.proofs().observe_verification_total_bytes(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Transaction,
            ProofVerificationKind::Transaction.as_str(),
            2048,
        );
        metrics.proofs().observe_verification_params_bytes(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Transaction,
            ProofVerificationKind::Transaction.as_str(),
            256,
        );
        metrics.proofs().observe_verification_public_inputs_bytes(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Transaction,
            ProofVerificationKind::Transaction.as_str(),
            512,
        );
        metrics.proofs().observe_verification_payload_bytes(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Transaction,
            ProofVerificationKind::Transaction.as_str(),
            1280,
        );
        metrics.proofs().observe_verification_stage(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Transaction,
            ProofVerificationKind::Transaction.as_str(),
            ProofVerificationStage::Fri,
            ProofVerificationOutcome::Ok,
        );
        metrics.proofs().record_verification_outcome(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Transaction,
            ProofVerificationKind::Transaction.as_str(),
            ProofVerificationOutcome::Ok,
        );

        provider.force_flush().expect("force flush metrics");
        let exported = exporter.get_finished_metrics()?;

        let mut seen = HashMap::new();
        for resource in exported {
            for scope in resource.scope_metrics {
                for metric in scope.metrics {
                    seen.insert(metric.name.clone(), metric.unit.clone());
                }
            }
        }

        assert_eq!(
            seen.get("rpp.runtime.consensus.block_duration"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.wallet.rpc_latency"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.wallet.fee.estimate.latency_ms"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.wallet.prover.job.duration_ms"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.wallet.prover.witness.bytes"),
            Some(&"By".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.wallet.prover.jobs"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.wallet.prover.failures"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.wallet.sign.latency_ms"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.wallet.sign.failures"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.wallet.scan.rescan.duration_ms"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.wallet.broadcast.rejected"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.storage.wal_flush.duration"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.storage.wal_flush.bytes"),
            Some(&"By".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.proof.generation.duration"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.proof.generation.size"),
            Some(&"By".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.proof.generation.count"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp_stark_verify_duration_seconds"),
            Some(&"s".to_string())
        );
        assert_eq!(
            seen.get("rpp_stark_proof_total_bytes"),
            Some(&"By".to_string())
        );
        assert_eq!(seen.get("rpp_stark_params_bytes"), Some(&"By".to_string()));
        assert_eq!(
            seen.get("rpp_stark_public_inputs_bytes"),
            Some(&"By".to_string())
        );
        assert_eq!(seen.get("rpp_stark_payload_bytes"), Some(&"By".to_string()));
        assert_eq!(
            seen.get("rpp_stark_stage_checks_total"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.proof.verification.outcomes"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.proof.verification.success_ratio"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.consensus.round.duration"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.consensus.round.quorum_latency"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.consensus.round.leader_changes"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.consensus.witness.events"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.consensus.slashing.events"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.consensus.failed_votes"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.chain.block_height"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.network.peer_count"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.reputation.penalties"),
            Some(&"1".to_string())
        );

        Ok(())
    }

    #[test]
    fn runtime_metrics_provide_storage_handle() -> std::result::Result<(), MetricError> {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("runtime-storage-handle-test");
        let (metrics, _callbacks) = RuntimeMetrics::from_meter(&meter)?;
        let metrics = Arc::new(metrics);

        let handle: firewood_storage::StorageMetricsHandle = metrics.clone();
        handle.increment_header_flushes();
        handle.record_header_flush_duration(Duration::from_millis(3));
        handle.record_header_flush_bytes(256);
        handle.increment_wal_flushes(StorageWalFlushOutcome::Success);
        handle.record_wal_flush_duration(StorageWalFlushOutcome::Success, Duration::from_millis(7));
        handle.record_wal_flush_bytes(StorageWalFlushOutcome::Success, 1024);

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

        assert!(seen.contains("rpp.runtime.storage.header_flush.total"));
        assert!(seen.contains("rpp.runtime.storage.wal_flush.total"));
        assert!(seen.contains("rpp.runtime.storage.wal_flush.duration"));

        Ok(())
    }

    #[test]
    fn proof_outcomes_include_circuit_labels() -> std::result::Result<(), MetricError> {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("proof-outcome-metrics");
        let (metrics, _callbacks) = RuntimeMetrics::from_meter(&meter)?;
        let proof_metrics = metrics.proofs();

        proof_metrics.record_verification_outcome(
            ProofVerificationBackend::Stwo,
            ProofVerificationKind::Transaction,
            "transaction",
            ProofVerificationOutcome::Ok,
        );
        proof_metrics.record_verification_outcome(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Consensus,
            "consensus",
            ProofVerificationOutcome::Fail,
        );

        provider.force_flush()?;
        let exported = exporter.get_finished_metrics()?;

        let mut outcome_circuits = HashSet::new();
        let mut ratio_circuits = HashSet::new();

        for resource in exported {
            for scope in resource.scope_metrics {
                for metric in scope.metrics {
                    match metric.data {
                        opentelemetry_sdk::metrics::data::Data::Sum(sum)
                            if metric.name == "rpp.runtime.proof.verification.outcomes" =>
                        {
                            for point in sum.data_points {
                                let mut attrs = HashMap::new();
                                for attribute in point.attributes {
                                    attrs.insert(
                                        attribute.key.to_string(),
                                        attribute.value.to_string(),
                                    );
                                }
                                if let Some(circuit) = attrs.get(PROOF_CIRCUIT_KEY) {
                                    outcome_circuits.insert(circuit.clone());
                                }
                            }
                        }
                        opentelemetry_sdk::metrics::data::Data::Histogram(hist)
                            if metric.name == "rpp.runtime.proof.verification.success_ratio" =>
                        {
                            for point in hist.data_points {
                                let mut attrs = HashMap::new();
                                for attribute in point.attributes {
                                    attrs.insert(
                                        attribute.key.to_string(),
                                        attribute.value.to_string(),
                                    );
                                }
                                if let Some(circuit) = attrs.get(PROOF_CIRCUIT_KEY) {
                                    ratio_circuits.insert(circuit.clone());
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        assert!(outcome_circuits.contains("transaction"));
        assert!(outcome_circuits.contains("consensus"));
        assert!(ratio_circuits.contains("transaction"));
        assert!(ratio_circuits.contains("consensus"));

        Ok(())
    }

    #[test]
    fn metrics_missing_endpoint_emits_warning() {
        struct TestLogger {
            records: Mutex<Vec<String>>,
        }

        impl TestLogger {
            fn new() -> Self {
                Self {
                    records: Mutex::new(Vec::new()),
                }
            }

            fn clear(&self) {
                self.records.lock().expect("logger mutex").clear();
            }

            fn take(&self) -> Vec<String> {
                self.records
                    .lock()
                    .expect("logger mutex")
                    .drain(..)
                    .collect()
            }
        }

        impl log::Log for TestLogger {
            fn enabled(&self, metadata: &log::Metadata) -> bool {
                metadata.level() <= log::Level::Warn
            }

            fn log(&self, record: &log::Record) {
                if self.enabled(record.metadata()) {
                    self.records
                        .lock()
                        .expect("logger mutex")
                        .push(format!("{}", record.args()));
                }
            }

            fn flush(&self) {}
        }

        fn ensure_logger() -> &'static TestLogger {
            static LOGGER: OnceLock<&'static TestLogger> = OnceLock::new();
            LOGGER.get_or_init(|| {
                let logger = Box::leak(Box::new(TestLogger::new()));
                if log::set_logger(logger).is_ok() {
                    log::set_max_level(log::LevelFilter::Warn);
                }
                logger
            })
        }

        let logger = ensure_logger();
        logger.clear();

        let mut config = TelemetryConfig::default();
        config.enabled = true;
        config.warn_on_drop = true;

        let resource = Resource::new(Vec::new());
        let (_metrics, mut guard, _) =
            init_runtime_metrics(&config, resource).expect("init metrics without exporter");
        guard.flush_and_shutdown();

        let warnings = logger.take();
        assert!(
            warnings
                .iter()
                .any(|entry| entry.contains("telemetry metrics exporter disabled")),
            "expected warning about missing OTLP/HTTP endpoint, got {warnings:?}"
        );
    }
}
