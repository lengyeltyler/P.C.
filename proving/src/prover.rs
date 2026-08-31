use anyhow::Result;

use crate::abi::{derive_proof_input_hash, keccak256};
use crate::codec::encode_raw_unlock_proof_bytes;
use crate::constants::{
    STWO_UNLOCK_ARTIFACT_VERSION, STWO_UNLOCK_PROOF_TYPE, STWO_UNLOCK_PROOF_VERSION,
    STWO_UNLOCK_VERIFIER_KEY_LABEL,
};
use crate::types::{
    GenerateProofInput, UnlockProofArtifactEnvelope, UnlockPublicInputs, UnlockVerifierPackage,
};
use crate::unlock_statement::{prove_unlock_statement, UnlockStatementProof};

pub fn generate_proof(
    public_inputs: UnlockPublicInputs,
    phil_secret: [u8; 32],
    nullifier_seed: [u8; 32],
) -> Result<Vec<u8>> {
    let proof = prove_unlock_statement(&GenerateProofInput {
        public_inputs,
        phil_secret,
        nullifier_seed,
    })?;

    encode_raw_proof_blob(&proof)
}

pub fn generate_verifier_package(
    public_inputs: UnlockPublicInputs,
    phil_secret: [u8; 32],
    nullifier_seed: [u8; 32],
) -> Result<UnlockVerifierPackage> {
    let proof = prove_unlock_statement(&GenerateProofInput {
        public_inputs: public_inputs.clone(),
        phil_secret,
        nullifier_seed,
    })?;

    let proof_bytes = encode_raw_proof_blob(&proof)?;

    Ok(UnlockVerifierPackage {
        version: STWO_UNLOCK_PROOF_VERSION.to_string(),
        proof_type: STWO_UNLOCK_PROOF_TYPE.to_string(),
        proof_input_hash: derive_proof_input_hash(&public_inputs)?,
        public_inputs,
        proof_blob: proof_bytes,
    })
}

pub fn encode_raw_proof_blob(proof: &UnlockStatementProof) -> Result<Vec<u8>> {
    encode_raw_unlock_proof_bytes(proof)
}

pub fn build_proof_artifact_envelope(proof_bytes: Vec<u8>) -> UnlockProofArtifactEnvelope {
    UnlockProofArtifactEnvelope {
        artifact_version: STWO_UNLOCK_ARTIFACT_VERSION.to_string(),
        verifier_key_id: unlock_verifier_key_id(),
        proof_bytes,
    }
}

pub fn generate_proof_artifact_envelope(
    public_inputs: UnlockPublicInputs,
    phil_secret: [u8; 32],
    nullifier_seed: [u8; 32],
) -> Result<UnlockProofArtifactEnvelope> {
    let proof = prove_unlock_statement(&GenerateProofInput {
        public_inputs,
        phil_secret,
        nullifier_seed,
    })?;

    Ok(build_proof_artifact_envelope(encode_raw_proof_blob(
        &proof,
    )?))
}

pub fn serialize_proof_artifact(artifact: &UnlockProofArtifactEnvelope) -> Result<Vec<u8>> {
    Ok(bincode::serialize(artifact)?)
}

pub fn build_verifier_package_from_proof_bytes(
    public_inputs: UnlockPublicInputs,
    proof_bytes: Vec<u8>,
) -> Result<UnlockVerifierPackage> {
    Ok(UnlockVerifierPackage {
        version: STWO_UNLOCK_PROOF_VERSION.to_string(),
        proof_type: STWO_UNLOCK_PROOF_TYPE.to_string(),
        proof_input_hash: derive_proof_input_hash(&public_inputs)?,
        public_inputs,
        proof_blob: proof_bytes,
    })
}

pub fn build_verifier_package_from_artifact(
    public_inputs: UnlockPublicInputs,
    artifact: &UnlockProofArtifactEnvelope,
) -> Result<UnlockVerifierPackage> {
    build_verifier_package_from_proof_bytes(public_inputs, artifact.proof_bytes.clone())
}

pub fn unlock_verifier_key_id() -> [u8; 32] {
    keccak256(STWO_UNLOCK_VERIFIER_KEY_LABEL.as_bytes())
}
