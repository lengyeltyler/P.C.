use crate::abi::derive_proof_input_hash;
use crate::codec::decode_raw_unlock_proof_bytes;
use crate::constants::{
    STWO_UNLOCK_ARTIFACT_VERSION, STWO_UNLOCK_PROOF_TYPE, STWO_UNLOCK_PROOF_VERSION,
};
use crate::prover::unlock_verifier_key_id;
use crate::types::{UnlockProofArtifactEnvelope, UnlockPublicInputs, UnlockVerifierPackage};
use crate::unlock_statement::verify_unlock_statement;

pub fn verify_proof(proof_bytes: &[u8], public_inputs: UnlockPublicInputs) -> bool {
    let Some(proof) = decode_raw_unlock_proof_bytes(proof_bytes) else {
        return false;
    };

    verify_unlock_statement(&proof, &public_inputs).is_ok()
}

pub fn decode_proof_artifact(proof_blob: &[u8]) -> Option<UnlockProofArtifactEnvelope> {
    bincode::deserialize::<UnlockProofArtifactEnvelope>(proof_blob).ok()
}

pub fn verify_proof_artifact(proof_blob: &[u8], public_inputs: UnlockPublicInputs) -> bool {
    let Some(artifact) = decode_proof_artifact(proof_blob) else {
        return false;
    };

    if artifact.artifact_version != STWO_UNLOCK_ARTIFACT_VERSION {
        return false;
    }
    if artifact.verifier_key_id != unlock_verifier_key_id() {
        return false;
    }

    verify_proof(&artifact.proof_bytes, public_inputs)
}

pub fn verify_proof_package(proof_package: UnlockVerifierPackage) -> bool {
    if proof_package.version != STWO_UNLOCK_PROOF_VERSION {
        return false;
    }
    if proof_package.proof_type != STWO_UNLOCK_PROOF_TYPE {
        return false;
    }
    let Ok(expected_proof_input_hash) = derive_proof_input_hash(&proof_package.public_inputs)
    else {
        return false;
    };
    if proof_package.proof_input_hash != expected_proof_input_hash {
        return false;
    }

    verify_proof(&proof_package.proof_blob, proof_package.public_inputs)
}
