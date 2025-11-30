use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct AlertRuleFile {
    groups: Vec<AlertGroup>,
}

#[derive(Debug, Deserialize)]
struct AlertGroup {
    rules: Vec<AlertRule>,
}

#[derive(Debug, Deserialize)]
struct AlertRule {
    alert: String,
    expr: String,
}

#[derive(Debug)]
struct IoSample {
    throughput_bps: f64,
    missing_heights: u64,
    eta_ms: u64,
}

#[test]
fn pruning_io_alerts_fire_on_sustained_slow_disks() -> Result<()> {
    let alerts: AlertRuleFile = serde_yaml::from_str(include_str!("../ops/alerts/storage/firewood.yaml"))
        .context("parse firewood alert definitions")?;

    let warning = find_alert(&alerts, "FirewoodPruningIoBottleneckWarning")?;
    let critical = find_alert(&alerts, "FirewoodPruningIoBottleneckCritical")?;

    let warning_threshold = parse_throughput_threshold(&warning.expr)
        .context("extract warning throughput threshold")?;
    let critical_threshold = parse_throughput_threshold(&critical.expr)
        .context("extract critical throughput threshold")?;

    assert!(
        warning_threshold > critical_threshold,
        "warning threshold should be larger than critical"
    );

    let healthy = IoSample {
        throughput_bps: 8_000_000.0,
        missing_heights: 0,
        eta_ms: 0,
    };
    assert!(!triggers(&warning, &healthy));
    assert!(!triggers(&critical, &healthy));

    let slow = IoSample {
        throughput_bps: critical_threshold * 0.25,
        missing_heights: 4,
        eta_ms: 120_000,
    };
    assert!(triggers(&warning, &slow), "warning alert should trigger on slow disks");
    assert!(
        triggers(&critical, &slow),
        "critical alert should trigger when throughput is far below the floor"
    );

    Ok(())
}

fn find_alert<'a>(alerts: &'a AlertRuleFile, name: &str) -> Result<&'a AlertRule> {
    alerts
        .groups
        .iter()
        .flat_map(|group| &group.rules)
        .find(|rule| rule.alert == name)
        .with_context(|| format!("missing alert {name}"))
}

fn triggers(rule: &AlertRule, sample: &IoSample) -> bool {
    let Some(threshold) = parse_throughput_threshold(&rule.expr) else {
        return false;
    };

    sample.throughput_bps < threshold && sample.missing_heights > 0 && sample.eta_ms > 0
}

fn parse_throughput_threshold(expr: &str) -> Option<f64> {
    let pattern = Regex::new(
        r"avg_over_time\(rpp_node_pruning_io_throughput_bytes_per_sec\[10m\]\)\s*<\s*([0-9.]+)",
    )
    .expect("valid regex");

    let captures = pattern.captures(expr)?;
    captures.get(1)?.as_str().parse().ok()
}
