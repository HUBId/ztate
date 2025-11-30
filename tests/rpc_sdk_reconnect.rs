use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use rpp_chain::orchestration::PipelineStage;
use tokio::process::Command;
use tokio::time::{sleep, timeout};

#[path = "support/mod.rs"]
mod support;

#[path = "mempool/helpers.rs"]
mod mempool_helpers;

use mempool_helpers::{enabled_backends, ProofBackend};
use support::cluster::{HarnessPipelineEvent, PipelineEventStream, ProcessTestCluster};

const STREAM_TIMEOUT: Duration = Duration::from_secs(20);
const STREAM_POLL: Duration = Duration::from_millis(250);
const CLIENT_WINDOW: Duration = Duration::from_secs(60);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sdk_clients_reconnect_when_consensus_restarts() {
    let _ = tracing_subscriber::fmt::try_init();

    for backend in enabled_backends() {
        if let Err(err) = run_restart_probe(&backend).await {
            panic!("sdk reconnect probe for {:?} failed: {err}", backend);
        }
    }
}

async fn run_restart_probe(backend: &ProofBackend) -> Result<()> {
    let label = backend_label(*backend);
    let log_dir = log_dir(&label)?;

    let mut cluster = match ProcessTestCluster::start_with(2, |config, _| {
        config.rollout.feature_gates.pruning = true;
        config.rollout.feature_gates.reconstruction = true;
        config.rollout.feature_gates.recursive_proofs = true;
        config.rollout.feature_gates.consensus_enforcement = true;
        if label == "plonky3" {
            config.rollout.feature_gates.malachite_consensus = true;
        }
        Ok(())
    })
    .await
    {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping reconnect probe: {err:?}");
            return Ok(());
        }
    };

    let nodes = cluster.nodes();
    let Some(primary) = nodes.get(0).and_then(|node| node.harness().ok()) else {
        eprintln!("skipping reconnect probe: missing primary harness");
        return Ok(());
    };

    let orchestrator = primary.orchestrator();
    let stream = orchestrator
        .subscribe_events()
        .context("subscribe to pipeline stream")?;

    let sse_transcript = log_dir.join("rust-sse.log");
    let mut rust_stream = StreamTranscript::new(&sse_transcript)?;

    let rpc_endpoint = format!("http://{}/wallet/account", primary.node().rpc_addr);
    let go_log = log_dir.join("go-client.log");
    let ts_log = log_dir.join("ts-client.log");

    let rust_task = tokio::spawn(monitor_rust_stream(stream, rust_stream));
    let go_task = tokio::spawn(run_go_client(&rpc_endpoint, &go_log));
    let ts_task = tokio::spawn(run_ts_client(&rpc_endpoint, &ts_log));

    let submitted = orchestrator
        .submit_transaction(
            "rpp1sdkxferx0000000000000000000000000000".to_string(),
            1_000,
            25,
            Some(format!("sdk restart probe backend={label}")),
        )
        .await
        .context("submit transaction via orchestrator")?;

    orchestrator
        .wait_for_stage(
            &submitted.hash,
            PipelineStage::LeaderElected,
            Duration::from_secs(45),
        )
        .await
        .context("wait for leader election")?;

    trigger_restart(&mut cluster).await?;

    orchestrator
        .wait_for_stage(
            &submitted.hash,
            PipelineStage::FirewoodCommitted,
            Duration::from_secs(90),
        )
        .await
        .context("wait for commit after restart")?;

    orchestrator
        .wait_for_stage(
            &submitted.hash,
            PipelineStage::RewardsDistributed,
            Duration::from_secs(90),
        )
        .await
        .context("wait for rewards after restart")?;

    let rust_ok = rust_task.await.context("join rust stream monitor")?;
    rust_ok.context("rust stream monitor failed")?;

    timeout(CLIENT_WINDOW, go_task)
        .await
        .context("go client exceeded window")?
        .context("go client join failed")?
        .context("go client errored")?;

    timeout(CLIENT_WINDOW, ts_task)
        .await
        .context("ts client exceeded window")?
        .context("ts client join failed")?
        .context("ts client errored")?;

    cluster.shutdown().await?;
    Ok(())
}

async fn monitor_rust_stream(
    mut stream: PipelineEventStream,
    mut transcript: StreamTranscript,
) -> Result<()> {
    let mut observed = 0usize;
    loop {
        match stream.next_event(STREAM_TIMEOUT).await? {
            Some(event) => {
                observed += 1;
                transcript.record(&event)?;
            }
            None => transcript.note("stream heartbeat timeout")?,
        }
        if observed >= 4 {
            return Ok(());
        }
        sleep(STREAM_POLL).await;
    }
}

async fn run_go_client(endpoint: &str, log_path: &Path) -> Result<()> {
    let script = r#"package main

import (
    "bufio"
    "fmt"
    "net/http"
    "os"
    "time"
)

func main() {
    if len(os.Args) < 3 {
        panic("endpoint and log path required")
    }
    endpoint := os.Args[1]
    logPath := os.Args[2]
    file, err := os.Create(logPath)
    if err != nil {
        panic(err)
    }
    defer file.Close()

    client := &http.Client{Timeout: 2 * time.Second}
    writer := bufio.NewWriter(file)
    defer writer.Flush()

    for i := 0; i < 40; i++ {
        resp, err := client.Get(endpoint)
        if err != nil {
            fmt.Fprintf(writer, "poll %d error: %v\n", i, err)
            writer.Flush()
            time.Sleep(750 * time.Millisecond)
            continue
        }
        fmt.Fprintf(writer, "poll %d status: %d\n", i, resp.StatusCode)
        resp.Body.Close()
        writer.Flush()
        time.Sleep(500 * time.Millisecond)
    }
}
"#;

    let dir = tempfile::tempdir().context("create go client tempdir")?;
    let source = dir.path().join("client.go");
    fs::write(&source, script).context("write go client script")?;

    let status = Command::new("go")
        .arg("run")
        .arg(&source)
        .arg(endpoint)
        .arg(log_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("execute go client")?;

    if !status.success() {
        return Err(anyhow!(
            "go client exited with {:?}; see {}",
            status.code(),
            log_path.display()
        ));
    }
    Ok(())
}

async fn run_ts_client(endpoint: &str, log_path: &Path) -> Result<()> {
    let script = r#"import { createWriteStream } from 'fs';
import { setTimeout as delay } from 'timers/promises';

const endpoint = process.argv[2];
const logPath = process.argv[3];
if (!endpoint || !logPath) {
  throw new Error('endpoint and log path are required');
}

const stream = createWriteStream(logPath, { flags: 'w' });

async function main() {
  for (let i = 0; i < 40; i++) {
    try {
      const res = await fetch(endpoint, { method: 'GET' });
      stream.write(`poll ${i} status: ${res.status}\n`);
    } catch (err) {
      stream.write(`poll ${i} error: ${err}\n`);
    }
    await delay(500);
  }
  stream.end();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
"#;

    let dir = tempfile::tempdir().context("create ts client tempdir")?;
    let source = dir.path().join("client.mjs");
    fs::write(&source, script).context("write ts client script")?;

    let status = Command::new("node")
        .arg(&source)
        .arg(endpoint)
        .arg(log_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("execute ts client")?;

    if !status.success() {
        return Err(anyhow!(
            "ts client exited with {:?}; see {}",
            status.code(),
            log_path.display()
        ));
    }
    Ok(())
}

async fn trigger_restart(cluster: &mut ProcessTestCluster) -> Result<()> {
    if let Some(node) = cluster.nodes_mut().get_mut(0) {
        let binary = cluster.binary().to_string();
        let client = cluster.client();
        node.respawn(&binary, &client, cluster.log_root())
            .await
            .context("restart primary node")?;
    }
    Ok(())
}

fn log_dir(label: &str) -> Result<PathBuf> {
    let path = PathBuf::from("logs")
        .join("sdk-reconnect")
        .join(format!("{label}-{}", Utc::now().timestamp()));
    fs::create_dir_all(&path).context("create sdk reconnect log dir")?;
    Ok(path)
}

fn backend_label(backend: ProofBackend) -> String {
    match backend {
        ProofBackend::Stwo => "stwo".to_string(),
        #[cfg(feature = "backend-plonky3")]
        ProofBackend::Plonky3 => "plonky3".to_string(),
        #[cfg(feature = "backend-rpp-stark")]
        ProofBackend::RppStark => "rpp-stark".to_string(),
    }
}

struct StreamTranscript {
    file: File,
}

impl StreamTranscript {
    fn new(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("create transcript directory")?;
        }
        let file = File::create(path).context("create transcript file")?;
        Ok(Self { file })
    }

    fn record(&mut self, event: &HarnessPipelineEvent) -> Result<()> {
        writeln!(self.file, "{event:?}").context("write pipeline event")
    }

    fn note(&mut self, message: &str) -> Result<()> {
        writeln!(self.file, "{message}").context("write note")
    }
}
