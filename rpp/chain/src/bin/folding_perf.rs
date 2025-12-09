use std::env;
use std::fs;
use std::time::Instant;

use rpp_chain::proof_backend::folding::{GlobalInstance, GlobalProof};
use rpp_chain::proof_backend::ProofVersion;
use rpp_chain::runtime::types::{verify_global_proof, Address, BlockHeader};
use serde::Serialize;

const DEFAULT_CHAIN_LENGTH: usize = 256;
const DEFAULT_PROOF_BYTES: usize = 4096;
const DEFAULT_OUTPUT: &str = "folding-perf.json";

#[derive(Serialize)]
struct FoldingRun {
    version: String,
    chain_length: usize,
    avg_proof_bytes: f64,
    max_proof_bytes: usize,
    verify_total_ms: f64,
    verify_per_proof_ms: f64,
    success_rate: f64,
}

#[derive(Serialize)]
struct FoldingReport {
    chain_length: usize,
    runs: Vec<FoldingRun>,
}

struct CutoverGuard(u64, u64);

impl Drop for CutoverGuard {
    fn drop(&mut self) {
        ProofVersion::configure_cutover(self.0, self.1);
    }
}

fn base_header(height: u64) -> BlockHeader {
    let hex_pad = || "00".repeat(32);
    BlockHeader::new(
        height,
        hex_pad(),
        hex_pad(),
        hex_pad(),
        hex_pad(),
        hex_pad(),
        hex_pad(),
        hex_pad(),
        hex_pad(),
        hex_pad(),
        hex_pad(),
        hex_pad(),
        hex_pad(),
        Address::from(hex_pad()),
        "tier-0".into(),
        0,
    )
}

fn build_chain(
    version: ProofVersion,
    chain_length: usize,
    proof_bytes: usize,
) -> Result<Vec<(BlockHeader, GlobalProof)>, Box<dyn std::error::Error>> {
    let vk_id = match version {
        ProofVersion::AggregatedV1 => b"vk-aggregated".to_vec(),
        ProofVersion::NovaV2 => b"vk-nova".to_vec(),
    };

    let mut chain = Vec::with_capacity(chain_length);

    for height in 0..chain_length {
        let state_commitment = vec![0x11; 32];
        let pruning_commitment = vec![0x22; 32];
        let instance =
            GlobalInstance::from_state_and_rpp(height as u64, state_commitment, pruning_commitment);

        let mut proof_payload = vec![0u8; proof_bytes + (height % 32)];
        for (idx, byte) in proof_payload.iter_mut().enumerate() {
            *byte = (idx % 251) as u8;
        }

        let proof = GlobalProof::new(instance.commitment.clone(), proof_payload, &vk_id, version)?;

        let header =
            base_header(height as u64).with_global_instance(&instance, Some(&proof.handle));
        chain.push((header, proof));
    }

    Ok(chain)
}

fn measure_chain(
    version: ProofVersion,
    chain_length: usize,
    proof_bytes: usize,
) -> Result<FoldingRun, Box<dyn std::error::Error>> {
    let (guard_height, guard_epoch) = ProofVersion::current_cutover();
    let _guard = CutoverGuard(guard_height, guard_epoch);

    match version {
        ProofVersion::AggregatedV1 => ProofVersion::configure_cutover(u64::MAX - 1, u64::MAX - 1),
        ProofVersion::NovaV2 => ProofVersion::configure_cutover(0, 0),
    }

    let chain = build_chain(version, chain_length, proof_bytes)?;

    let start = Instant::now();
    let mut successes = 0usize;
    for (header, proof) in &chain {
        if verify_global_proof(header, proof) {
            successes += 1;
        }
    }
    let elapsed = start.elapsed();

    let total_proof_bytes: usize = chain.iter().map(|(_, proof)| proof.proof_bytes.len()).sum();
    let max_proof_bytes = chain
        .iter()
        .map(|(_, proof)| proof.proof_bytes.len())
        .max()
        .unwrap_or(0);

    let avg_proof_bytes = total_proof_bytes as f64 / chain.len() as f64;
    let verify_total_ms = elapsed.as_secs_f64() * 1000.0;
    let verify_per_proof_ms = verify_total_ms / chain.len() as f64;
    let success_rate = successes as f64 / chain.len() as f64;

    Ok(FoldingRun {
        version: format!("{:?}", version),
        chain_length: chain.len(),
        avg_proof_bytes,
        max_proof_bytes,
        verify_total_ms,
        verify_per_proof_ms,
        success_rate,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let chain_length = env::var("FOLDING_PERF_CHAIN_LENGTH")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_CHAIN_LENGTH);
    let proof_bytes = env::var("FOLDING_PERF_PROOF_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_PROOF_BYTES);
    let output_path =
        env::var("FOLDING_PERF_OUTPUT").unwrap_or_else(|_| DEFAULT_OUTPUT.to_string());

    let aggregated = measure_chain(ProofVersion::AggregatedV1, chain_length, proof_bytes)?;
    let nova = measure_chain(ProofVersion::NovaV2, chain_length, proof_bytes)?;

    let report = FoldingReport {
        chain_length,
        runs: vec![aggregated, nova],
    };

    let json = serde_json::to_string_pretty(&report)?;
    fs::write(&output_path, &json)?;
    println!("Saved folding metrics to {output_path}\n{json}");

    Ok(())
}
