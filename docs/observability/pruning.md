# Pruning observability

This guide describes the Grafana panels and alert rules recommended for the
pruning worker. Metrics originate from the node telemetry instrumentation and
share the `rpp.node.pruning.*` prefix.【F:rpp/node/src/telemetry/pruning.rs†L25-L116】
Every datapoint carries `shard` and `partition` labels so multi-shard
deployments can isolate alerts and dashboards per Firewood slice. Set
`RPP_PRUNING_SHARD` and `RPP_PRUNING_PARTITION` in the node environment to pin
the label values; they default to `primary` and `0` when unset.【F:rpp/node/src/telemetry/pruning.rs†L63-L117】

## Key metrics

- **`rpp.node.pruning.cycle_total`** – counter labelled by `shard`, `partition`,
  `reason`, and `result` that increments on every pruning attempt. Use stacked
  visualisations to spot growing failure counts per shard versus scheduled
  runs.【F:rpp/node/src/telemetry/pruning.rs†L25-L116】【F:rpp/node/src/services/pruning.rs†L391-L399】
- **`rpp.node.pruning.cycle_duration_ms`** – histogram capturing cycle runtime in
  milliseconds grouped by shard/partition. Plot p50/p95 to ensure runs finish
  before the cadence interval.【F:rpp/node/src/telemetry/pruning.rs†L25-L116】【F:rpp/node/src/services/pruning.rs†L391-L399】
- **`rpp.node.pruning.keys_processed`** – histogram counting how many pruning keys
  (block records and proofs) the worker handled during each cycle. Compare with
  `missing_heights` per shard/partition to estimate backlog progress.【F:rpp/node/src/telemetry/pruning.rs†L25-L116】【F:rpp/runtime/node.rs†L3200-L3207】
- **`rpp.node.pruning.time_remaining_ms`** – histogram estimating how long it will
  take to clear the remaining backlog based on the most recent throughput. Use it
  to spot stalls that fall behind the cadence for a given shard.【F:rpp/node/src/telemetry/pruning.rs†L25-L116】
- **`rpp.node.pruning.failures_total`** – counter labelled by `shard`,
  `partition`, `reason`, and `error` that increments when a cycle returns an
  error. Values classify storage, config, commitment, and proof failures for
  alert routing.【F:rpp/node/src/telemetry/pruning.rs†L63-L117】【F:rpp/node/src/services/pruning.rs†L391-L399】
- **`rpp.node.pruning.persisted_plan_total`** – counter labelled by shard,
  partition, and `persisted` to confirm whether the reconstruction plan hit disk
  for each cycle.【F:rpp/node/src/telemetry/pruning.rs†L63-L117】【F:rpp/runtime/node.rs†L3200-L3202】
- **`rpp.node.pruning.missing_heights`** – histogram with the number of heights
  still missing after a cycle, labelled by shard/partition. Any sustained
  increase signals storage drift.【F:rpp/node/src/telemetry/pruning.rs†L63-L117】【F:rpp/runtime/node.rs†L3200-L3207】
- **`rpp.node.pruning.stored_proofs`** – histogram showing how many pruning
  proofs synchronised to storage per cycle for each shard/partition.【F:rpp/node/src/telemetry/pruning.rs†L63-L117】【F:rpp/runtime/node.rs†L3200-L3207】
- **`rpp.node.pruning.io_bytes_written`, `io_duration_ms`, `io_throughput_bytes_per_sec`** –
  histograms tracking how much data and time each cycle spent persisting pruning
  artifacts. Correlate the throughput series with `missing_heights` and
  `time_remaining_ms` to confirm whether slow disks or budgets block backlog
  reduction.【F:rpp/node/src/telemetry/pruning.rs†L21-L125】【F:rpp/runtime/node.rs†L6245-L6430】
- **`rpp.node.pruning.retention_depth`** – histogram recording the effective
  retention depth applied to each run; build singe-stat panels to catch override
  mistakes by shard.【F:rpp/node/src/telemetry/pruning.rs†L63-L117】【F:rpp/node/src/services/pruning.rs†L356-L399】
- **`rpp.node.pruning.pause_transitions`** – counter labelled by shard,
  partition, and `state` that increments whenever operators pause or resume
  automation.【F:rpp/node/src/telemetry/pruning.rs†L63-L117】【F:rpp/node/src/services/pruning.rs†L356-L366】

## Suggested dashboard panels

1. **Cycle outcome overview** – stacked bar chart of
   `sum by (shard, partition, reason, result)(increase(rpp.node.pruning.cycle_total[5m]))`
   to contrast manual versus scheduled runs and highlight failures per shard.
2. **Cycle duration percentiles** – percentile panels based on
   `histogram_quantile(0.95, rate(rpp.node.pruning.cycle_duration_ms_bucket{shard="$shard",partition="$partition"}[15m]))`
   to ensure jobs complete before the next cadence tick for the selected shard.
3. **Missing heights trend** – single-stat or line chart fed by
   `last_over_time(rpp.node.pruning.missing_heights_sum{shard="$shard",partition="$partition"}[5m])`
   to visualise backlog growth.
4. **Throughput versus backlog** – combine
   `rate(rpp.node.pruning.keys_processed_bucket{shard="$shard",partition="$partition"}[5m])` with
   `last_over_time(rpp.node.pruning.missing_heights_sum{shard="$shard",partition="$partition"}[5m])`
   so operators can see whether proof persistence is catching up.
5. **Time-to-clear gauge** – single-stat showing
   `histogram_quantile(0.5, rate(rpp.node.pruning.time_remaining_ms_bucket{shard="$shard",partition="$partition"}[10m]))`
   to validate that the estimated completion time fits inside the cadence.
6. **Pause state timeline** – heatmap using
   `increase(rpp.node.pruning.pause_transitions{shard="$shard",partition="$partition",state="paused"}[1h])`
   and `increase(...{shard="$shard",partition="$partition",state="resumed"}[1h])` to document
   maintenance windows.

## Example alerts

- **Scheduled cycle failure streak:** trigger when
  `increase(rpp.node.pruning.cycle_total{shard="$shard",partition="$partition",reason="scheduled",result="failure"}[15m]) >= 3`.
  Pair the alert with the most recent `/snapshots/jobs` payload so on-call staff
  can review the missing heights immediately.
- **Plan persistence halted:** fire if
  `increase(rpp.node.pruning.persisted_plan_total{shard="$shard",partition="$partition",persisted="true"}[30m]) == 0`
  while `increase(rpp.node.pruning.cycle_total{shard="$shard",partition="$partition",result="success"}[30m]) > 0`.
- **Stalled pruning backlog:** page when
  `histogram_quantile(0.5, rate(rpp.node.pruning.time_remaining_ms_bucket{shard="$shard",partition="$partition"}[10m]))`
  exceeds the cadence window or when
  `increase(rpp.node.pruning.keys_processed_bucket{shard="$shard",partition="$partition"}[10m]) == 0` while
  `missing_heights_sum` remains non-zero.
- **Slow throughput:** warn if
  `rate(rpp.node.pruning.keys_processed_count{shard="$shard",partition="$partition"}[15m]) < 1` while the backlog stays
  above the retention depth, indicating degraded storage performance.
- **IO bottleneck while backlog persists:** alert when
  `avg_over_time(rpp.node.pruning.io_throughput_bytes_per_sec{shard="$shard",partition="$partition"}[10m])`
  drops below the expected budget and both `missing_heights_sum` and
  `time_remaining_ms_sum` remain non-zero. Use the pruning IO runbook to decide
  whether to pause exports, move the pruning directories, or raise the recorded
  IO budgets.【F:ops/alerts/storage/firewood.yaml†L70-L120】【F:docs/runbooks/observability.md†L115-L148】
- **Unexpected pause:** notify when
  `increase(rpp.node.pruning.pause_transitions{shard="$shard",partition="$partition",state="paused"}[10m]) > 0` without
  a matching resume within the same window.
- **Error classification for routing:** route pages based on
  `increase(rpp.node.pruning.failures_total{shard="$shard",partition="$partition"}[5m])` with `error` labels so storage
  regressions (for example `error="storage"`) reach the right owners.

Combine the alerts with log streaming for `"pruning cycle failed"` to accelerate
triage.【F:rpp/node/src/services/pruning.rs†L393-L400】 The pruning worker now
emits `event`-scoped markers (`pruning_cycle_start`, `pruning_checkpoint_saved`,
`pruning_batch_complete`, `pruning_cycle_finished`, `pruning_cycle_error`) with
`checkpoint_id`, `shard`, and `partition` labels. Parse those fields in log
pipelines (e.g. Loki labels) so dashboards can render a per-shard timeline of
starts, batches, persisted checkpoints, and any failures.【F:rpp/runtime/node.rs†L5929-L6073】
