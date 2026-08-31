use anyhow::Result;
use serde_json::json;

use philcore_proving::fixtures::load_default_vector;
use philcore_proving::keccak_compat::prove_proof_input_hash;
use philcore_proving::prover::generate_proof;
use philcore_proving::types::{encode_hex, GenerateProofInput};
use philcore_proving::unlock_statement::prove_unlock_owner_path;

fn chunks_of_31(bytes_len: usize) -> usize {
    bytes_len.div_ceil(31)
}

fn main() -> Result<()> {
    let vector = load_default_vector()?;

    let full_unlock_proof = generate_proof(
        vector.public_inputs.clone(),
        vector.phil_secret,
        vector.nullifier_seed,
    )?;

    let proof_input_hash_slice_proof = prove_proof_input_hash(&vector)?;
    let proof_input_hash_slice_bytes = bincode::serialize(&proof_input_hash_slice_proof)?;

    let owner_path_input = GenerateProofInput {
        public_inputs: vector.public_inputs.clone(),
        phil_secret: vector.phil_secret,
        nullifier_seed: vector.nullifier_seed,
    };
    let owner_path_proof = prove_unlock_owner_path(&owner_path_input)?;
    let owner_path_proof_bytes = bincode::serialize(&owner_path_proof)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "proofType": vector.proof_type,
            "fullUnlockProofBytes": full_unlock_proof.len(),
            "fullUnlockProof31ByteChunks": chunks_of_31(full_unlock_proof.len()),
            "ownerPathProofBytes": owner_path_proof_bytes.len(),
            "ownerPathProof31ByteChunks": chunks_of_31(owner_path_proof_bytes.len()),
            "proofInputHashSliceProofBytes": proof_input_hash_slice_bytes.len(),
            "proofInputHashSlice31ByteChunks": chunks_of_31(proof_input_hash_slice_bytes.len()),
            "proofInputHashPreimageBytes": vector.proof_input_hash_preimage.len(),
            "proofInputHashPreimageWordCount": vector.proof_input_hash_preimage.len() / 32,
            "publicInputs": {
                "ownerCommitment": encode_hex(&vector.public_inputs.owner_commitment),
                "actionHash": encode_hex(&vector.public_inputs.action_hash),
                "policyHash": encode_hex(&vector.public_inputs.policy_hash),
                "nullifier": encode_hex(&vector.public_inputs.nullifier),
                "consumerDataHash": encode_hex(&vector.public_inputs.consumer_data_hash),
                "expiry": vector.public_inputs.expiry,
            },
            "proofInputHash": encode_hex(&vector.proof_input_hash_value),
            "proofInputHashPreimage": encode_hex(&vector.proof_input_hash_preimage),
        }))?
    );

    Ok(())
}
