use std::sync::Arc;

mod account;
mod block;
mod identity;
mod proofs;
mod transaction;
mod uptime;

pub type PruningProof = Arc<rpp_pruning::Envelope>;
pub use crate::identity_tree::IdentityCommitmentProof;
pub use account::{Account, IdentityBinding, Stake, WalletBindingChange};
pub use block::BlockPayload;
pub(crate) use block::StoredBlock;
pub use block::{
    canonical_pruning_from_block, canonical_pruning_from_parts, canonical_pruning_genesis,
    pruning_from_metadata, pruning_from_previous, pruning_genesis,
};
pub(crate) use block::{serde_pruning_proof, CanonicalPruningEnvelope};
pub use block::{
    verify_global_proof, Block, BlockHeader, BlockMetadata, ProofSystem, PruningCommitmentMetadata,
    PruningEnvelopeMetadata, PruningProofExt, PruningSegmentMetadata, PruningSnapshotMetadata,
    RecursiveProof, ReputationUpdate, TimetokeUpdate, ValidatedPruningEnvelope,
};
pub use identity::{
    AttestationOutcome, AttestedIdentityRequest, IdentityDeclaration, IdentityGenesis,
    IdentityProof, IDENTITY_ATTESTATION_GOSSIP_MIN, IDENTITY_ATTESTATION_QUORUM,
};
#[cfg(feature = "backend-rpp-stark")]
pub use proofs::RppStarkProof;
pub use proofs::{BlockProofBundle, ChainProof, TransactionProofBundle};
pub use transaction::{SignedTransaction, Transaction, TransactionEnvelope};
pub use uptime::{UptimeClaim, UptimeProof};

pub type Address = String;
pub type AccountId = Address;

#[cfg(test)]
mod interface_schemas {
    use super::{SignedTransaction, Transaction, TransactionEnvelope, UptimeClaim, UptimeProof};
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
    fn transaction_schema_roundtrip() {
        assert_roundtrip::<Transaction>(
            "runtime/transaction.jsonschema",
            "runtime/examples/transaction.json",
        );
    }

    #[test]
    fn signed_transaction_schema_roundtrip() {
        assert_roundtrip::<SignedTransaction>(
            "runtime/signed_transaction.jsonschema",
            "runtime/examples/signed_transaction.json",
        );
    }

    #[test]
    fn transaction_envelope_schema_roundtrip() {
        assert_roundtrip::<TransactionEnvelope>(
            "runtime/transaction_envelope.jsonschema",
            "runtime/examples/transaction_envelope.json",
        );
    }

    #[test]
    fn uptime_claim_schema_roundtrip() {
        assert_roundtrip::<UptimeClaim>(
            "runtime/uptime_claim.jsonschema",
            "runtime/examples/uptime_claim.json",
        );
    }

    #[test]
    fn uptime_proof_schema_roundtrip() {
        assert_roundtrip::<UptimeProof>(
            "runtime/uptime_proof.jsonschema",
            "runtime/examples/uptime_proof.json",
        );
    }
}
