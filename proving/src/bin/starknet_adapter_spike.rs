use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::json;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::{FriConfig, FriLayerProof, FriProof};
use stwo::core::pcs::quotients::CommitmentSchemeProof;
use stwo::core::pcs::{PcsConfig, TreeVec};
use stwo::core::poly::line::LinePoly;
use stwo::core::proof::StarkProof;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::verifier::MerkleDecommitmentLifted;

use philcore_proving::codec::decode_raw_unlock_proof_bytes;
use philcore_proving::fixtures::load_default_vector;
use philcore_proving::keccak_compat::prove_proof_input_hash;
use philcore_proving::prover::generate_proof;
use philcore_proving::types::{encode_hex, GenerateProofInput};
use philcore_proving::unlock_statement::prove_unlock_owner_path;

fn felt_hex_from_u64(value: u64) -> String {
    format!("0x{value:x}")
}

fn felt_hex_from_u128(value: u128) -> String {
    format!("0x{value:x}")
}

trait CairoArgsSerialize {
    fn serialize_args(&self, output: &mut Vec<String>);
}

impl CairoArgsSerialize for u32 {
    fn serialize_args(&self, output: &mut Vec<String>) {
        output.push(felt_hex_from_u64((*self).into()));
    }
}

impl CairoArgsSerialize for u64 {
    fn serialize_args(&self, output: &mut Vec<String>) {
        output.push(felt_hex_from_u64(*self));
    }
}

impl CairoArgsSerialize for usize {
    fn serialize_args(&self, output: &mut Vec<String>) {
        output.push(felt_hex_from_u64(*self as u64));
    }
}

impl CairoArgsSerialize for BaseField {
    fn serialize_args(&self, output: &mut Vec<String>) {
        output.push(felt_hex_from_u64(self.0.into()));
    }
}

impl CairoArgsSerialize for SecureField {
    fn serialize_args(&self, output: &mut Vec<String>) {
        for limb in self.to_m31_array() {
            limb.serialize_args(output);
        }
    }
}

impl CairoArgsSerialize for Blake2sHash {
    fn serialize_args(&self, output: &mut Vec<String>) {
        for word in self.0.chunks_exact(4) {
            let value = u32::from_le_bytes(word.try_into().expect("word-sized chunk"));
            value.serialize_args(output);
        }
    }
}

impl<H> CairoArgsSerialize for MerkleDecommitmentLifted<H>
where
    H: stwo::core::vcs_lifted::MerkleHasherLifted,
    H::Hash: CairoArgsSerialize,
{
    fn serialize_args(&self, output: &mut Vec<String>) {
        self.hash_witness.serialize_args(output);
    }
}

impl CairoArgsSerialize for LinePoly {
    fn serialize_args(&self, output: &mut Vec<String>) {
        let coeffs: Vec<SecureField> = self.iter().copied().collect();
        coeffs.serialize_args(output);
        output.push(felt_hex_from_u64(self.len().ilog2().into()));
    }
}

impl<H> CairoArgsSerialize for FriLayerProof<H>
where
    H: stwo::core::vcs_lifted::MerkleHasherLifted,
    H::Hash: CairoArgsSerialize,
{
    fn serialize_args(&self, output: &mut Vec<String>) {
        self.fri_witness.serialize_args(output);
        self.decommitment.serialize_args(output);
        self.commitment.serialize_args(output);
    }
}

impl<H> CairoArgsSerialize for FriProof<H>
where
    H: stwo::core::vcs_lifted::MerkleHasherLifted,
    H::Hash: CairoArgsSerialize,
{
    fn serialize_args(&self, output: &mut Vec<String>) {
        self.first_layer.serialize_args(output);
        self.inner_layers.serialize_args(output);
        self.last_layer_poly.serialize_args(output);
    }
}

impl CairoArgsSerialize for FriConfig {
    fn serialize_args(&self, output: &mut Vec<String>) {
        self.log_blowup_factor.serialize_args(output);
        self.log_last_layer_degree_bound.serialize_args(output);
        self.n_queries.serialize_args(output);
    }
}

impl CairoArgsSerialize for PcsConfig {
    fn serialize_args(&self, output: &mut Vec<String>) {
        self.pow_bits.serialize_args(output);
        self.fri_config.serialize_args(output);
    }
}

impl<H> CairoArgsSerialize for CommitmentSchemeProof<H>
where
    H: stwo::core::vcs_lifted::MerkleHasherLifted,
    H::Hash: CairoArgsSerialize,
{
    fn serialize_args(&self, output: &mut Vec<String>) {
        self.config.serialize_args(output);
        self.commitments.serialize_args(output);
        self.sampled_values.serialize_args(output);
        self.decommitments.serialize_args(output);
        self.queried_values.serialize_args(output);
        self.proof_of_work.serialize_args(output);
        self.fri_proof.serialize_args(output);
    }
}

impl<H> CairoArgsSerialize for StarkProof<H>
where
    H: stwo::core::vcs_lifted::MerkleHasherLifted,
    H::Hash: CairoArgsSerialize,
{
    fn serialize_args(&self, output: &mut Vec<String>) {
        self.0.serialize_args(output);
    }
}

impl<T: CairoArgsSerialize> CairoArgsSerialize for Vec<T> {
    fn serialize_args(&self, output: &mut Vec<String>) {
        self.len().serialize_args(output);
        for value in self {
            value.serialize_args(output);
        }
    }
}

impl<T: CairoArgsSerialize> CairoArgsSerialize for [T] {
    fn serialize_args(&self, output: &mut Vec<String>) {
        self.len().serialize_args(output);
        for value in self {
            value.serialize_args(output);
        }
    }
}

impl<T: CairoArgsSerialize, const N: usize> CairoArgsSerialize for [T; N] {
    fn serialize_args(&self, output: &mut Vec<String>) {
        for value in self {
            value.serialize_args(output);
        }
    }
}

impl<T: CairoArgsSerialize> CairoArgsSerialize for TreeVec<T> {
    fn serialize_args(&self, output: &mut Vec<String>) {
        self.0.serialize_args(output);
    }
}

fn split_be_u256(bytes: &[u8; 32]) -> (u128, u128) {
    let high = u128::from_be_bytes(bytes[..16].try_into().expect("high half"));
    let low = u128::from_be_bytes(bytes[16..].try_into().expect("low half"));
    (high, low)
}

fn serialize_public_inputs_args(
    public_inputs: &philcore_proving::types::UnlockPublicInputs,
    output: &mut Vec<String>,
) {
    for bytes in [
        &public_inputs.owner_commitment,
        &public_inputs.action_hash,
        &public_inputs.policy_hash,
        &public_inputs.nullifier,
        &public_inputs.consumer_data_hash,
    ] {
        let (high, low) = split_be_u256(bytes);
        output.push(felt_hex_from_u128(high));
        output.push(felt_hex_from_u128(low));
    }
    output.push(felt_hex_from_u64(public_inputs.expiry));
}

fn count_nested_columns<T>(tree_vec: &TreeVec<Vec<Vec<T>>>) -> usize {
    tree_vec.0.iter().map(Vec::len).sum()
}

fn write_json(path: &PathBuf, value: &serde_json::Value) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn main() -> Result<()> {
    let vector = load_default_vector()?;
    let output_dir = PathBuf::from("out/starknet_adapter_spike");
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    let full_unlock_proof_bytes = generate_proof(
        vector.public_inputs.clone(),
        vector.phil_secret,
        vector.nullifier_seed,
    )?;
    let full_unlock_path = output_dir.join("full_unlock_proof.bin");
    fs::write(&full_unlock_path, &full_unlock_proof_bytes)
        .with_context(|| format!("failed to write {}", full_unlock_path.display()))?;
    let full_unlock_proof = decode_raw_unlock_proof_bytes(&full_unlock_proof_bytes)
        .context("failed to decode authentic full unlock proof bytes")?;

    let owner_path_input = GenerateProofInput {
        public_inputs: vector.public_inputs.clone(),
        phil_secret: vector.phil_secret,
        nullifier_seed: vector.nullifier_seed,
    };
    let owner_path_proof = prove_unlock_owner_path(&owner_path_input)?;
    let proof_input_hash_slice = prove_proof_input_hash(&vector)?;

    let mut full_unlock_args = Vec::new();
    full_unlock_proof.proof.serialize_args(&mut full_unlock_args);
    serialize_public_inputs_args(&vector.public_inputs, &mut full_unlock_args);
    let full_unlock_args_path = output_dir.join("full_unlock_proof.cairo_args.json");
    write_json(&full_unlock_args_path, &json!(full_unlock_args))?;

    let mut proof_input_hash_slice_args = Vec::new();
    proof_input_hash_slice
        .proof
        .serialize_args(&mut proof_input_hash_slice_args);
    serialize_public_inputs_args(&vector.public_inputs, &mut proof_input_hash_slice_args);
    let proof_input_hash_slice_args_path =
        output_dir.join("proof_input_hash_slice.cairo_args.json");
    write_json(
        &proof_input_hash_slice_args_path,
        &json!(proof_input_hash_slice_args),
    )?;

    let mut owner_path_args = Vec::new();
    owner_path_proof.proof.serialize_args(&mut owner_path_args);
    serialize_public_inputs_args(&vector.public_inputs, &mut owner_path_args);
    let owner_path_args_path = output_dir.join("owner_path_only.cairo_args.json");
    write_json(&owner_path_args_path, &json!(owner_path_args))?;

    let (proof_input_hash_high, proof_input_hash_low) = split_be_u256(&vector.proof_input_hash_value);

    let summary_path = output_dir.join("summary.json");
    write_json(
        &summary_path,
        &json!({
            "proofType": vector.proof_type,
            "version": vector.version,
            "publicInputs": {
                "ownerCommitment": encode_hex(&vector.public_inputs.owner_commitment),
                "actionHash": encode_hex(&vector.public_inputs.action_hash),
                "policyHash": encode_hex(&vector.public_inputs.policy_hash),
                "nullifier": encode_hex(&vector.public_inputs.nullifier),
                "consumerDataHash": encode_hex(&vector.public_inputs.consumer_data_hash),
                "expiry": vector.public_inputs.expiry,
            },
            "proofInputHash": encode_hex(&vector.proof_input_hash_value),
            "expectedFactPayload": [
                felt_hex_from_u128(proof_input_hash_high),
                felt_hex_from_u128(proof_input_hash_low),
            ],
            "artifacts": {
                "fullUnlockProofBytesPath": full_unlock_path.display().to_string(),
                "fullUnlockCairoArgsPath": full_unlock_args_path.display().to_string(),
                "proofInputHashSliceCairoArgsPath": proof_input_hash_slice_args_path.display().to_string(),
                "ownerPathOnlyCairoArgsPath": owner_path_args_path.display().to_string(),
            },
            "fullUnlockProof": {
                "rawBytes": full_unlock_proof_bytes.len(),
                "cairoArgFelts": full_unlock_args.len(),
                "powBits": full_unlock_proof.proof.config.pow_bits,
                "friQueries": full_unlock_proof.proof.config.fri_config.n_queries,
                "commitments": full_unlock_proof.proof.commitments.0.len(),
                "sampledValueTrees": full_unlock_proof.proof.sampled_values.0.len(),
                "sampledValueColumns": count_nested_columns(&full_unlock_proof.proof.sampled_values),
                "decommitments": full_unlock_proof.proof.decommitments.0.len(),
                "queriedValueTrees": full_unlock_proof.proof.queried_values.0.len(),
                "queriedValueColumns": count_nested_columns(&full_unlock_proof.proof.queried_values),
                "friInnerLayers": full_unlock_proof.proof.fri_proof.inner_layers.len(),
                "proofOfWorkNonce": full_unlock_proof.proof.proof_of_work,
            },
            "proofInputHashSliceProof": {
                "rawBytes": bincode::serialize(&proof_input_hash_slice)?.len(),
                "cairoArgFelts": proof_input_hash_slice_args.len(),
                "powBits": proof_input_hash_slice.proof.config.pow_bits,
                "friQueries": proof_input_hash_slice.proof.config.fri_config.n_queries,
                "commitments": proof_input_hash_slice.proof.commitments.0.len(),
                "sampledValueTrees": proof_input_hash_slice.proof.sampled_values.0.len(),
                "sampledValueColumns": count_nested_columns(&proof_input_hash_slice.proof.sampled_values),
                "decommitments": proof_input_hash_slice.proof.decommitments.0.len(),
                "queriedValueTrees": proof_input_hash_slice.proof.queried_values.0.len(),
                "queriedValueColumns": count_nested_columns(&proof_input_hash_slice.proof.queried_values),
                "friInnerLayers": proof_input_hash_slice.proof.fri_proof.inner_layers.len(),
                "proofOfWorkNonce": proof_input_hash_slice.proof.proof_of_work,
            },
            "ownerPathOnlyProof": {
                "rawBytes": bincode::serialize(&owner_path_proof)?.len(),
                "cairoArgFelts": owner_path_args.len(),
                "powBits": owner_path_proof.proof.config.pow_bits,
                "friQueries": owner_path_proof.proof.config.fri_config.n_queries,
                "commitments": owner_path_proof.proof.commitments.0.len(),
                "sampledValueTrees": owner_path_proof.proof.sampled_values.0.len(),
                "sampledValueColumns": count_nested_columns(&owner_path_proof.proof.sampled_values),
                "decommitments": owner_path_proof.proof.decommitments.0.len(),
                "queriedValueTrees": owner_path_proof.proof.queried_values.0.len(),
                "queriedValueColumns": count_nested_columns(&owner_path_proof.proof.queried_values),
                "friInnerLayers": owner_path_proof.proof.fri_proof.inner_layers.len(),
                "proofOfWorkNonce": owner_path_proof.proof.proof_of_work,
            }
        }),
    )?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "summaryPath": summary_path.display().to_string(),
            "fullUnlockProofBytesPath": full_unlock_path.display().to_string(),
            "fullUnlockCairoArgsPath": full_unlock_args_path.display().to_string(),
            "proofInputHashSliceCairoArgsPath": proof_input_hash_slice_args_path.display().to_string(),
            "ownerPathOnlyCairoArgsPath": owner_path_args_path.display().to_string(),
        }))?
    );

    Ok(())
}
