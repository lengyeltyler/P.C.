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

use philcore_proving::fixtures::load_default_vector;
use philcore_proving::keccak_compat::{keccak_pad_rate_blocks, prove_proof_input_hash};
use philcore_proving::types::encode_hex;

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
        self.fold_step.serialize_args(output);
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

fn bits_from_bytes_le(bytes: &[u8]) -> Vec<u32> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for bit in 0..8 {
            bits.push(((byte >> bit) & 1) as u32);
        }
    }
    bits
}

fn split_be_u256(bytes: &[u8; 32]) -> (u128, u128) {
    let high = u128::from_be_bytes(bytes[..16].try_into().expect("high half"));
    let low = u128::from_be_bytes(bytes[16..].try_into().expect("low half"));
    (high, low)
}

fn write_json(path: &PathBuf, value: &serde_json::Value) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn main() -> Result<()> {
    let vector = load_default_vector()?;
    let output_dir = PathBuf::from("out/cairo_air_adapter_spike");
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    let proof_input_hash_slice = prove_proof_input_hash(&vector)?;
    let raw_proof_bytes = bincode::serialize(&proof_input_hash_slice)?;
    let raw_proof_path = output_dir.join("proof_input_hash_slice_proof.bin");
    fs::write(&raw_proof_path, &raw_proof_bytes)
        .with_context(|| format!("failed to write {}", raw_proof_path.display()))?;
    let padded_blocks = keccak_pad_rate_blocks(&vector.proof_input_hash_preimage);
    let block_bits = padded_blocks
        .iter()
        .map(|block| bits_from_bytes_le(block))
        .collect::<Vec<_>>();
    let expected_digest_bits = bits_from_bytes_le(&vector.proof_input_hash_value);

    let (proof_input_hash_high, proof_input_hash_low) = split_be_u256(&vector.proof_input_hash_value);

    let mut args = Vec::new();
    proof_input_hash_slice.proof.serialize_args(&mut args);
    block_bits.serialize_args(&mut args);
    expected_digest_bits.serialize_args(&mut args);
    args.push(felt_hex_from_u128(proof_input_hash_high));
    args.push(felt_hex_from_u128(proof_input_hash_low));

    let args_path = output_dir.join("proof_input_hash_slice_verify_args.json");
    write_json(&args_path, &json!(args))?;

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
            "proofInputHashPreimage": encode_hex(&vector.proof_input_hash_preimage),
            "proofInputHash": encode_hex(&vector.proof_input_hash_value),
            "expectedFactPayload": [
                felt_hex_from_u128(proof_input_hash_high),
                felt_hex_from_u128(proof_input_hash_low),
            ],
            "proofInputHashSliceProof": {
                "rawBytes": bincode::serialize(&proof_input_hash_slice)?.len(),
                "powBits": proof_input_hash_slice.proof.config.pow_bits,
                "friQueries": proof_input_hash_slice.proof.config.fri_config.n_queries,
                "friFoldStep": proof_input_hash_slice.proof.config.fri_config.fold_step,
                "commitments": proof_input_hash_slice.proof.commitments.0.len(),
                "sampledValueTrees": proof_input_hash_slice.proof.sampled_values.0.len(),
                "decommitments": proof_input_hash_slice.proof.decommitments.0.len(),
                "queriedValueTrees": proof_input_hash_slice.proof.queried_values.0.len(),
                "friInnerLayers": proof_input_hash_slice.proof.fri_proof.inner_layers.len(),
                "proofOfWorkNonce": proof_input_hash_slice.proof.proof_of_work,
            },
            "keccakClaim": {
                "blockCount": block_bits.len(),
                "blockBitLength": block_bits.first().map_or(0, Vec::len),
                "digestBitLength": expected_digest_bits.len(),
            },
            "artifacts": {
                "rawProofPath": raw_proof_path.display().to_string(),
                "verifyArgsPath": args_path.display().to_string(),
            }
        }),
    )?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "summaryPath": summary_path.display().to_string(),
            "verifyArgsPath": args_path.display().to_string(),
        }))?
    );

    Ok(())
}
