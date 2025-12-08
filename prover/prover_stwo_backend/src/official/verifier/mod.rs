//! Verifier-side integration for STWO/STARK proofs.

use crate::errors::{ChainError, ChainResult};
use crate::proof_backend::ProofSystemKind;
use crate::proof_system::ProofVerifier;
use crate::types::ChainProof;

use super::aggregation::{RecursiveAggregator, StateCommitmentSnapshot};
use super::circuit::{
    consensus::ConsensusCircuit,
    identity::IdentityCircuit,
    pruning::PruningCircuit,
    recursive::{PrefixedDigest, RecursiveCircuit},
    state::StateCircuit,
    transaction::TransactionCircuit,
    uptime::UptimeCircuit,
    CircuitError, ExecutionTrace, StarkCircuit,
};
use super::conversions::field_to_secure;
use super::official_adapter::{BlueprintComponent, Component};
use super::params::{FieldElement, StarkParameters};
use super::proof::{ProofKind, ProofPayload, StarkProof};

use crate::stwo_official::core::channel::{Channel, MerkleChannel};
use crate::stwo_official::core::fri::FriProof as OfficialFriProof;
use crate::stwo_official::core::pcs::CommitmentSchemeVerifier;
use crate::stwo_official::core::proof::StarkProof as OfficialStarkProof;
use crate::stwo_official::core::vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use crate::stwo_official::core::verifier::{verify as stwo_verify, VerificationError};
use rpp_pruning::Envelope;

fn string_to_field(parameters: &StarkParameters, value: &str) -> FieldElement {
    let bytes = hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec());
    parameters.element_from_bytes(&bytes)
}

fn map_circuit_error(err: CircuitError) -> ChainError {
    ChainError::Crypto(err.to_string())
}

fn map_verification_error(err: VerificationError) -> ChainError {
    let message = match err {
        VerificationError::InvalidStructure(msg) => {
            format!("invalid proof structure: {msg}")
        }
        VerificationError::Merkle(inner) => {
            format!("merkle verification failed: {inner}")
        }
        VerificationError::OodsNotMatching => "oods check failed".to_string(),
        VerificationError::Fri(inner) => format!("fri verification failed: {inner}"),
        VerificationError::ProofOfWork => "proof of work verification failed".to_string(),
    };
    ChainError::Crypto(message)
}

fn encode_fri_proof(proof: &OfficialFriProof<Blake2sMerkleHasher>) -> ChainResult<Vec<u8>> {
    bincode::serialize(proof).map_err(|err| {
        ChainError::Crypto(format!("failed to encode fri proof for comparison: {err}"))
    })
}

fn ensure_matching_fri(
    commitment_fri: &OfficialFriProof<Blake2sMerkleHasher>,
    provided_fri: &OfficialFriProof<Blake2sMerkleHasher>,
) -> ChainResult<()> {
    let commitment_bytes = encode_fri_proof(commitment_fri)?;
    let provided_bytes = encode_fri_proof(provided_fri)?;
    if commitment_bytes != provided_bytes {
        tracing::error!("embedded fri proof mismatch between payloads");
        return Err(ChainError::Crypto("fri proof mismatch".into()));
    }
    Ok(())
}

fn expected_pruning_digests(envelope: &Envelope) -> (PrefixedDigest, Vec<PrefixedDigest>) {
    let binding = envelope.binding_digest().prefixed_bytes();
    let segments = envelope
        .segments()
        .iter()
        .map(|segment| segment.segment_commitment().prefixed_bytes())
        .collect();
    (binding, segments)
}

/// Lightweight verifier that recomputes commitments by replaying circuits.
#[derive(Clone)]
pub struct NodeVerifier {
    parameters: StarkParameters,
}

impl NodeVerifier {
    pub fn new() -> Self {
        Self {
            parameters: StarkParameters::blueprint_default(),
        }
    }

    pub fn with_parameters(parameters: StarkParameters) -> Self {
        Self { parameters }
    }

    fn check_commitment(&self, proof: &StarkProof) -> ChainResult<Vec<FieldElement>> {
        let inputs = proof
            .public_inputs
            .iter()
            .map(|input| string_to_field(&self.parameters, input))
            .collect::<Vec<_>>();
        let hasher = self.parameters.poseidon_hasher();
        let expected = hasher.hash(&inputs).to_hex();
        if expected != proof.commitment {
            return Err(ChainError::Crypto("proof commitment mismatch".into()));
        }
        Ok(inputs)
    }

    fn expect_kind(&self, proof: &StarkProof, kind: ProofKind) -> ChainResult<()> {
        if proof.kind != kind {
            return Err(ChainError::Crypto("proof kind mismatch".into()));
        }
        Ok(())
    }

    fn check_trace(&self, circuit_trace: ExecutionTrace, proof: &StarkProof) -> ChainResult<()> {
        if proof.trace != circuit_trace {
            return Err(ChainError::Crypto("proof trace mismatch".into()));
        }
        Ok(())
    }

    pub(crate) fn check_fri(
        &self,
        proof: &StarkProof,
        public_inputs: &[FieldElement],
        trace: &ExecutionTrace,
        air: &super::air::AirDefinition,
    ) -> ChainResult<()> {
        let component = BlueprintComponent::new(air, trace, &self.parameters).map_err(|err| {
            tracing::error!(error = %err, "failed to prepare verifier component");
            ChainError::Crypto(format!("component adapter error: {err}"))
        })?;

        let commitment_proof = proof.commitment_proof.to_official().ok_or_else(|| {
            tracing::error!("missing commitment scheme proof data");
            ChainError::Crypto("missing commitment proof".into())
        })?;

        if let Some(fri_proof) = proof.fri_proof.to_official() {
            ensure_matching_fri(&commitment_proof.fri_proof, &fri_proof)?;
        }

        let mut channel = <Blake2sMerkleChannel as MerkleChannel>::C::default();
        let secure_inputs = public_inputs
            .iter()
            .map(field_to_secure)
            .collect::<Vec<_>>();
        channel.mix_felts(&secure_inputs);
        commitment_proof.config.mix_into(&mut channel);

        let mut commitment_scheme =
            CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(commitment_proof.config);

        let log_sizes = component.trace_log_degree_bounds();
        if commitment_proof.commitments.len() != log_sizes.len() {
            tracing::error!(
                commitments = commitment_proof.commitments.len(),
                expected = log_sizes.len(),
                "commitment tree count mismatch"
            );
            return Err(ChainError::Crypto("commitment tree count mismatch".into()));
        }

        for (commitment, sizes) in commitment_proof.commitments.iter().zip(log_sizes.iter()) {
            commitment_scheme.commit(*commitment, sizes, &mut channel);
        }

        let components = component.verifier_components();
        let stark_proof = OfficialStarkProof(commitment_proof);

        stwo_verify(
            &components,
            &mut channel,
            &mut commitment_scheme,
            stark_proof,
        )
        .map_err(|err| {
            tracing::error!(error = %err, "fri verification failed");
            map_verification_error(err)
        })
    }

    fn compute_recursive_commitment(
        &self,
        witness: &super::circuit::recursive::RecursiveWitness,
        state_commitments: &StateCommitmentSnapshot,
    ) -> FieldElement {
        // TODO(fold_global): swap the legacy recursive hash recomputation with
        // a `fold_global` verification hook so the accumulator checks the folded
        // global instance rather than the pre-fold commitment chain.
        let aggregator = RecursiveAggregator::new(self.parameters.clone());
        aggregator.aggregate_commitment(
            witness.previous_commitment.as_deref(),
            &witness.identity_commitments,
            &witness.tx_commitments,
            &witness.uptime_commitments,
            &witness.consensus_commitments,
            &witness.state_commitment,
            state_commitments,
            &witness.pruning_binding_digest,
            &witness.pruning_segment_commitments,
            witness.block_height,
        )
    }
}

impl Default for NodeVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeVerifier {
    fn verify_transaction_stark(&self, proof: &StarkProof) -> ChainResult<()> {
        self.expect_kind(proof, ProofKind::Transaction)?;
        let public_inputs = self.check_commitment(proof)?;
        if let ProofPayload::Transaction(witness) = &proof.payload {
            let circuit = TransactionCircuit::new(witness.clone());
            circuit.evaluate_constraints().map_err(map_circuit_error)?;
            let trace = circuit
                .generate_trace(&self.parameters)
                .map_err(map_circuit_error)?;
            circuit
                .verify_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            let air = circuit
                .define_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            self.check_trace(trace.clone(), proof)?;
            self.check_fri(proof, &public_inputs, &trace, &air)
        } else {
            Err(ChainError::Crypto(
                "transaction proof payload mismatch".into(),
            ))
        }
    }

    fn verify_identity_stark(&self, proof: &StarkProof) -> ChainResult<()> {
        self.expect_kind(proof, ProofKind::Identity)?;
        let public_inputs = self.check_commitment(proof)?;
        if let ProofPayload::Identity(witness) = &proof.payload {
            let circuit = IdentityCircuit::new(witness.clone());
            circuit.evaluate_constraints().map_err(map_circuit_error)?;
            let trace = circuit
                .generate_trace(&self.parameters)
                .map_err(map_circuit_error)?;
            circuit
                .verify_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            let air = circuit
                .define_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            self.check_trace(trace.clone(), proof)?;
            self.check_fri(proof, &public_inputs, &trace, &air)
        } else {
            Err(ChainError::Crypto("identity proof payload mismatch".into()))
        }
    }

    fn verify_state_stark(&self, proof: &StarkProof) -> ChainResult<()> {
        self.expect_kind(proof, ProofKind::State)?;
        let public_inputs = self.check_commitment(proof)?;
        if let ProofPayload::State(witness) = &proof.payload {
            let circuit = StateCircuit::new(witness.clone());
            circuit.evaluate_constraints().map_err(map_circuit_error)?;
            let trace = circuit
                .generate_trace(&self.parameters)
                .map_err(map_circuit_error)?;
            circuit
                .verify_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            let air = circuit
                .define_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            self.check_trace(trace.clone(), proof)?;
            self.check_fri(proof, &public_inputs, &trace, &air)
        } else {
            Err(ChainError::Crypto("state proof payload mismatch".into()))
        }
    }

    fn verify_pruning_stark(&self, proof: &StarkProof) -> ChainResult<()> {
        self.expect_kind(proof, ProofKind::Pruning)?;
        let public_inputs = self.check_commitment(proof)?;
        if let ProofPayload::Pruning(witness) = &proof.payload {
            let circuit = PruningCircuit::new(witness.clone());
            circuit.evaluate_constraints().map_err(map_circuit_error)?;
            let trace = circuit
                .generate_trace(&self.parameters)
                .map_err(map_circuit_error)?;
            circuit
                .verify_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            let air = circuit
                .define_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            self.check_trace(trace.clone(), proof)?;
            self.check_fri(proof, &public_inputs, &trace, &air)
        } else {
            Err(ChainError::Crypto("pruning proof payload mismatch".into()))
        }
    }

    fn verify_recursive_stark(&self, proof: &StarkProof) -> ChainResult<()> {
        self.expect_kind(proof, ProofKind::Recursive)?;
        let public_inputs = self.check_commitment(proof)?;
        if let ProofPayload::Recursive(witness) = &proof.payload {
            let circuit = RecursiveCircuit::new(witness.clone());
            circuit.evaluate_constraints().map_err(map_circuit_error)?;
            let trace = circuit
                .generate_trace(&self.parameters)
                .map_err(map_circuit_error)?;
            circuit
                .verify_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            let air = circuit
                .define_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            self.check_trace(trace.clone(), proof)?;
            self.check_fri(proof, &public_inputs, &trace, &air)
        } else {
            Err(ChainError::Crypto(
                "recursive proof payload mismatch".into(),
            ))
        }
    }

    fn verify_uptime_stark(&self, proof: &StarkProof) -> ChainResult<()> {
        self.expect_kind(proof, ProofKind::Uptime)?;
        let public_inputs = self.check_commitment(proof)?;
        if let ProofPayload::Uptime(witness) = &proof.payload {
            let circuit = UptimeCircuit::new(witness.clone());
            circuit.evaluate_constraints().map_err(map_circuit_error)?;
            let trace = circuit
                .generate_trace(&self.parameters)
                .map_err(map_circuit_error)?;
            circuit
                .verify_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            let air = circuit
                .define_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            self.check_trace(trace.clone(), proof)?;
            self.check_fri(proof, &public_inputs, &trace, &air)
        } else {
            Err(ChainError::Crypto("uptime proof payload mismatch".into()))
        }
    }

    fn verify_consensus_stark(&self, proof: &StarkProof) -> ChainResult<()> {
        self.expect_kind(proof, ProofKind::Consensus)?;
        let public_inputs = self.check_commitment(proof)?;
        if let ProofPayload::Consensus(witness) = &proof.payload {
            let circuit = ConsensusCircuit::new(witness.clone());
            circuit.evaluate_constraints().map_err(map_circuit_error)?;
            let trace = circuit
                .generate_trace(&self.parameters)
                .map_err(map_circuit_error)?;
            circuit
                .verify_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            let air = circuit
                .define_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            self.check_trace(trace.clone(), proof)?;
            self.check_fri(proof, &public_inputs, &trace, &air)
        } else {
            Err(ChainError::Crypto(
                "consensus proof payload mismatch".into(),
            ))
        }
    }
}

impl NodeVerifier {
    pub fn verify_transaction_proof(&self, proof: &StarkProof) -> ChainResult<()> {
        self.verify_transaction_stark(proof)
    }
}

impl NodeVerifier {
    /// Verify a full bundle of proofs associated with a block.
    pub fn verify_bundle(
        &self,
        identity_proofs: &[ChainProof],
        tx_proofs: &[ChainProof],
        uptime_proofs: &[ChainProof],
        consensus_proofs: &[ChainProof],
        state_proof: &ChainProof,
        pruning_proof: &ChainProof,
        pruning_envelope: &Envelope,
        recursive_proof: &ChainProof,
        state_commitments: &StateCommitmentSnapshot,
        expected_previous_commitment: Option<&str>,
    ) -> ChainResult<String> {
        let identity_stark: Vec<StarkProof> = identity_proofs
            .iter()
            .map(|proof| proof.expect_stwo().map(|inner| inner.clone()))
            .collect::<ChainResult<Vec<_>>>()?;
        let tx_stark: Vec<StarkProof> = tx_proofs
            .iter()
            .map(|proof| proof.expect_stwo().map(|inner| inner.clone()))
            .collect::<ChainResult<Vec<_>>>()?;
        let uptime_stark: Vec<StarkProof> = uptime_proofs
            .iter()
            .map(|proof| proof.expect_stwo().map(|inner| inner.clone()))
            .collect::<ChainResult<Vec<_>>>()?;
        let consensus_stark: Vec<StarkProof> = consensus_proofs
            .iter()
            .map(|proof| proof.expect_stwo().map(|inner| inner.clone()))
            .collect::<ChainResult<Vec<_>>>()?;
        let state_stark = state_proof.expect_stwo()?.clone();
        let pruning_stark = pruning_proof.expect_stwo()?.clone();
        let recursive_stark = recursive_proof.expect_stwo()?.clone();

        for proof in &identity_stark {
            self.verify_identity_stark(proof)?;
        }
        for proof in &tx_stark {
            self.verify_transaction_stark(proof)?;
        }
        for proof in &uptime_stark {
            self.verify_uptime_stark(proof)?;
        }
        for proof in &consensus_stark {
            self.verify_consensus_stark(proof)?;
        }
        self.verify_state_stark(&state_stark)?;
        self.verify_pruning_stark(&pruning_stark)?;
        self.verify_recursive_stark(&recursive_stark)?;

        let witness = match &recursive_stark.payload {
            ProofPayload::Recursive(witness) => witness,
            _ => {
                return Err(ChainError::Crypto(
                    "recursive proof payload mismatch".into(),
                ));
            }
        };

        if witness.identity_commitments.len() != identity_stark.len() {
            return Err(ChainError::Crypto(
                "recursive witness identity commitment count mismatch".into(),
            ));
        }
        for (expected_commitment, proof) in witness.identity_commitments.iter().zip(&identity_stark)
        {
            if expected_commitment != &proof.commitment {
                return Err(ChainError::Crypto(
                    "recursive witness identity commitment mismatch".into(),
                ));
            }
        }

        if witness.tx_commitments.len() != tx_stark.len() {
            return Err(ChainError::Crypto(
                "recursive witness transaction commitment count mismatch".into(),
            ));
        }
        for (expected_commitment, proof) in witness.tx_commitments.iter().zip(&tx_stark) {
            if expected_commitment != &proof.commitment {
                return Err(ChainError::Crypto(
                    "recursive witness transaction commitment mismatch".into(),
                ));
            }
        }

        if witness.uptime_commitments.len() != uptime_stark.len() {
            return Err(ChainError::Crypto(
                "recursive witness uptime commitment count mismatch".into(),
            ));
        }
        for (expected_commitment, proof) in witness.uptime_commitments.iter().zip(&uptime_stark) {
            if expected_commitment != &proof.commitment {
                return Err(ChainError::Crypto(
                    "recursive witness uptime commitment mismatch".into(),
                ));
            }
        }

        if witness.consensus_commitments.len() != consensus_stark.len() {
            return Err(ChainError::Crypto(
                "recursive witness consensus commitment count mismatch".into(),
            ));
        }
        for (expected_commitment, proof) in
            witness.consensus_commitments.iter().zip(&consensus_stark)
        {
            if expected_commitment != &proof.commitment {
                return Err(ChainError::Crypto(
                    "recursive witness consensus commitment mismatch".into(),
                ));
            }
        }

        if witness.state_commitment != state_stark.commitment {
            return Err(ChainError::Crypto(
                "recursive witness state commitment mismatch".into(),
            ));
        }
        let (expected_binding, expected_segments) = expected_pruning_digests(pruning_envelope);
        if witness.pruning_binding_digest != expected_binding {
            tracing::error!(
                expected = %hex::encode(expected_binding),
                actual = %hex::encode(witness.pruning_binding_digest),
                "recursive witness pruning binding digest mismatch",
            );
            return Err(ChainError::Crypto(
                "recursive witness pruning binding digest mismatch".into(),
            ));
        }

        if witness.pruning_segment_commitments.len() != expected_segments.len() {
            tracing::error!(
                expected = expected_segments.len(),
                actual = witness.pruning_segment_commitments.len(),
                "recursive witness pruning segment commitment count mismatch",
            );
            return Err(ChainError::Crypto(
                "recursive witness pruning segment commitment count mismatch".into(),
            ));
        }
        for (index, (expected, actual)) in expected_segments
            .iter()
            .zip(witness.pruning_segment_commitments.iter())
            .enumerate()
        {
            if actual != expected {
                tracing::error!(
                    index,
                    expected = %hex::encode(expected),
                    actual = %hex::encode(actual),
                    "recursive witness pruning segment commitment mismatch",
                );
                return Err(ChainError::Crypto(
                    "recursive witness pruning segment commitment mismatch".into(),
                ));
            }
        }

        if witness.global_state_root != state_commitments.global_state_root {
            return Err(ChainError::Crypto(
                "recursive witness global state root mismatch".into(),
            ));
        }
        if witness.utxo_root != state_commitments.utxo_root {
            return Err(ChainError::Crypto(
                "recursive witness utxo root mismatch".into(),
            ));
        }
        if witness.reputation_root != state_commitments.reputation_root {
            return Err(ChainError::Crypto(
                "recursive witness reputation root mismatch".into(),
            ));
        }
        if witness.timetoke_root != state_commitments.timetoke_root {
            return Err(ChainError::Crypto(
                "recursive witness timetoke root mismatch".into(),
            ));
        }
        if witness.zsi_root != state_commitments.zsi_root {
            return Err(ChainError::Crypto(
                "recursive witness zsi root mismatch".into(),
            ));
        }
        if witness.proof_root != state_commitments.proof_root {
            return Err(ChainError::Crypto(
                "recursive witness proof registry root mismatch".into(),
            ));
        }

        if let Some(expected) = expected_previous_commitment {
            match &witness.previous_commitment {
                Some(actual) if actual == expected => {}
                Some(_) => {
                    return Err(ChainError::Crypto(
                        "recursive witness previous commitment mismatch".into(),
                    ));
                }
                None => {
                    return Err(ChainError::Crypto(
                        "recursive witness missing previous commitment".into(),
                    ));
                }
            }
        }

        let aggregated = self.compute_recursive_commitment(witness, state_commitments);
        let aggregated_hex = aggregated.to_hex();
        if aggregated_hex != witness.aggregated_commitment {
            return Err(ChainError::Crypto(
                "recursive witness aggregated commitment mismatch".into(),
            ));
        }

        if let Some(previous_input) = recursive_stark.public_inputs.get(0) {
            let expected_previous = witness.previous_commitment.clone().unwrap_or_default();
            if previous_input != &expected_previous {
                return Err(ChainError::Crypto(
                    "recursive proof public inputs do not encode previous commitment".into(),
                ));
            }
        }

        if let Some(aggregated_input) = recursive_stark.public_inputs.get(1) {
            if aggregated_input != &witness.aggregated_commitment {
                return Err(ChainError::Crypto(
                    "recursive proof public inputs do not encode aggregated commitment".into(),
                ));
            }
        }

        if let Some(tx_count_input) = recursive_stark.public_inputs.get(2) {
            let expected_tx_count = self
                .parameters
                .element_from_u64(witness.tx_commitments.len() as u64)
                .to_hex();
            if tx_count_input != &expected_tx_count {
                return Err(ChainError::Crypto(
                    "recursive proof public inputs do not encode transaction count".into(),
                ));
            }
        }

        Ok(aggregated_hex)
    }
}

impl ProofVerifier for NodeVerifier {
    fn system(&self) -> ProofSystemKind {
        ProofSystemKind::Stwo
    }

    fn verify_transaction(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_transaction_stark(proof.expect_stwo()?)
    }

    fn verify_identity(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_identity_stark(proof.expect_stwo()?)
    }

    fn verify_state(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_state_stark(proof.expect_stwo()?)
    }

    fn verify_pruning(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_pruning_stark(proof.expect_stwo()?)
    }

    fn verify_recursive(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_recursive_stark(proof.expect_stwo()?)
    }

    fn verify_uptime(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_uptime_stark(proof.expect_stwo()?)
    }

    fn verify_consensus(&self, proof: &ChainProof) -> ChainResult<()> {
        self.verify_consensus_stark(proof.expect_stwo()?)
    }
}
