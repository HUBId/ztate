use prover_backend_interface::folding::{
    fold_pipeline_step, BlockWitness, FoldingBackend, GlobalInstance, GlobalProof,
    MockFoldingBackend,
};
use prover_backend_interface::{BackendResult, ProofVersion};

fn main() -> BackendResult<()> {
    init_tracing();

    let mut instance = GlobalInstance::from_state_and_rpp(0, b"state-0", b"rpp-0");
    let mut proof = GlobalProof::new(
        instance.commitment.clone(),
        b"proof-0",
        b"mock-folding-vk",
        ProofVersion::AggregatedV1,
    )?;

    println!(
        "I_boot index={} commitment={} (state={}, rpp={})",
        instance.index,
        hex::encode(&instance.commitment),
        hex::encode(&instance.state_commitment),
        hex::encode(&instance.rpp_commitment),
    );
    println!(
        "π_boot handle: commitment={} vk_id={} version={:?}",
        hex::encode(proof.handle.proof_commitment),
        std::str::from_utf8(proof.handle.vk_id.as_slice()).unwrap_or("<utf8-error>"),
        proof.handle.version,
    );

    for block in 1..=3 {
        let witness = BlockWitness::new(block, format!("demo-witness-{block}").into_bytes());

        let (next_instance, next_proof) =
            fold_pipeline_step(instance, proof, witness, &MockFoldingBackend)?;
        let verified = MockFoldingBackend.verify(&next_instance, &next_proof)?;

        println!(
            "Folded block {block}: I_{block} commitment={} / proof={} / vk_id={} / verified={}",
            hex::encode(&next_instance.commitment),
            hex::encode(next_proof.handle.proof_commitment),
            std::str::from_utf8(next_proof.handle.vk_id.as_slice()).unwrap_or("<utf8-error>"),
            verified,
        );

        instance = next_instance;
        proof = next_proof;
    }

    Ok(())
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt().with_target(true).try_init();
}
