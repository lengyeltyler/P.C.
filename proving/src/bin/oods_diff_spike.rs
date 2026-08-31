use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use num_traits::Zero;
use serde_json::json;
use stwo::core::air::{Component, Components};
use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::circle::CirclePoint;
use stwo::core::constraints::coset_vanishing;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::FieldExpOps;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::{
    Blake2sM31MerkleChannel, Blake2sM31MerkleHasher,
};
use stwo::core::vcs_lifted::verifier::MerkleDecommitmentLifted;
use stwo_constraint_framework::TraceLocationAllocator;

use philcore_proving::constants::LOG_N_ROWS;
use philcore_proving::fixtures::load_default_vector;
use philcore_proving::keccak_compat::{
    keccak_pad_rate_blocks, keccak_preprocessed_column_ids, prove_proof_input_hash,
    KeccakCompatComponent, KeccakCompatEval, KeccakConstraintFamily,
};
use philcore_proving::types::encode_hex;

const MAX_CONSTRAINT_LOG_DEGREE_BOUND: u32 = LOG_N_ROWS + 1;
const FAMILY_NAMES: [&str; 11] = [
    "StateBoolean",
    "Absorb",
    "P01",
    "P23",
    "P0123",
    "C",
    "D",
    "RhoPi",
    "ChiAux",
    "StateTransition",
    "FinalDigest",
];

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

impl CairoArgsSerialize for u128 {
    fn serialize_args(&self, output: &mut Vec<String>) {
        output.push(felt_hex_from_u128(*self));
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

impl CairoArgsSerialize for stwo::core::poly::line::LinePoly {
    fn serialize_args(&self, output: &mut Vec<String>) {
        let coeffs: Vec<SecureField> = self.iter().copied().collect();
        coeffs.serialize_args(output);
        output.push(felt_hex_from_u64(self.len().ilog2().into()));
    }
}

impl<H> CairoArgsSerialize for stwo::core::fri::FriLayerProof<H>
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

impl<H> CairoArgsSerialize for stwo::core::fri::FriProof<H>
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

impl CairoArgsSerialize for stwo::core::fri::FriConfig {
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

impl<H> CairoArgsSerialize for stwo::core::pcs::quotients::CommitmentSchemeProof<H>
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

impl<H> CairoArgsSerialize for stwo::core::proof::StarkProof<H>
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

impl<T: CairoArgsSerialize> CairoArgsSerialize for stwo::core::pcs::TreeVec<T> {
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

fn field_bits_from_bytes_le(bytes: &[u8]) -> Vec<BaseField> {
    bits_from_bytes_le(bytes)
        .into_iter()
        .map(BaseField::from)
        .collect()
}

fn split_be_u256(bytes: &[u8; 32]) -> (u128, u128) {
    let high = u128::from_be_bytes(bytes[..16].try_into().expect("high half"));
    let low = u128::from_be_bytes(bytes[16..].try_into().expect("low half"));
    (high, low)
}

fn secure_field_words(value: SecureField) -> [u32; 4] {
    value.to_m31_array().map(|limb| limb.0)
}

fn secure_field_json(value: SecureField) -> serde_json::Value {
    let [a0, a1, a2, a3] = secure_field_words(value);
    json!([felt_hex_from_u64(a0.into()), felt_hex_from_u64(a1.into()), felt_hex_from_u64(a2.into()), felt_hex_from_u64(a3.into())])
}

fn circle_point_json(point: CirclePoint<SecureField>) -> serde_json::Value {
    json!({
        "x": secure_field_json(point.x),
        "y": secure_field_json(point.y),
    })
}

fn family_from_index(index: usize) -> KeccakConstraintFamily {
    match index {
        0 => KeccakConstraintFamily::StateBoolean,
        1 => KeccakConstraintFamily::Absorb,
        2 => KeccakConstraintFamily::P01,
        3 => KeccakConstraintFamily::P23,
        4 => KeccakConstraintFamily::P0123,
        5 => KeccakConstraintFamily::C,
        6 => KeccakConstraintFamily::D,
        7 => KeccakConstraintFamily::RhoPi,
        8 => KeccakConstraintFamily::ChiAux,
        9 => KeccakConstraintFamily::StateTransition,
        10 => KeccakConstraintFamily::FinalDigest,
        _ => panic!("invalid family index"),
    }
}

fn write_json(path: &PathBuf, value: &serde_json::Value) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn build_component(
    n_blocks: usize,
    block_bits: &[Vec<BaseField>],
    expected_digest_bits: &[BaseField],
    debug_max_family: Option<KeccakConstraintFamily>,
) -> KeccakCompatComponent {
    let eval = KeccakCompatEval {
        log_n_rows: LOG_N_ROWS,
        n_blocks,
        max_constraint_log_degree_bound: MAX_CONSTRAINT_LOG_DEGREE_BOUND,
        debug_max_family,
        debug_enable_state_transition_formula: true,
        debug_enable_state_transition_link: true,
        block_bits: block_bits.to_vec(),
        expected_digest_bits: expected_digest_bits.to_vec(),
    };

    KeccakCompatComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(
            &keccak_preprocessed_column_ids(n_blocks),
        ),
        eval,
        SecureField::zero(),
    )
}

fn extract_composition_oods_eval(
    proof: &stwo::core::proof::StarkProof<Blake2sM31MerkleHasher>,
    oods_point: CirclePoint<SecureField>,
    split_log_degree_bound: u32,
) -> Result<SecureField> {
    let left_and_right = proof
        .sampled_values
        .last()
        .context("missing composition sampled values")?;
    if left_and_right.len() != 8 {
        bail!(
            "expected 8 composition coordinate columns, found {}",
            left_and_right.len()
        );
    }
    let coordinate_evals = left_and_right
        .iter()
        .map(|samples| match samples.as_slice() {
            [eval] => Ok(*eval),
            _ => bail!("expected a single OODS sample per composition column"),
        })
        .collect::<Result<Vec<_>>>()?;

    let left = SecureField::from_partial_evals(coordinate_evals[..4].try_into().unwrap());
    let right = SecureField::from_partial_evals(coordinate_evals[4..].try_into().unwrap());
    Ok(left + oods_point.repeated_double(split_log_degree_bound - 1).x * right)
}

fn main() -> Result<()> {
    let vector = load_default_vector()?;
    let output_dir = PathBuf::from("out/oods_diff_spike");
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    let slice_proof = prove_proof_input_hash(&vector)?;
    let raw_proof_bytes = bincode::serialize(&slice_proof)?;
    let raw_proof_path = output_dir.join("proof_input_hash_slice_proof.bin");
    fs::write(&raw_proof_path, &raw_proof_bytes)
        .with_context(|| format!("failed to write {}", raw_proof_path.display()))?;

    let padded_blocks = keccak_pad_rate_blocks(&vector.proof_input_hash_preimage);
    let block_bits_u32 = padded_blocks
        .iter()
        .map(|block| bits_from_bytes_le(block))
        .collect::<Vec<_>>();
    let block_bits = padded_blocks
        .iter()
        .map(|block| field_bits_from_bytes_le(block))
        .collect::<Vec<_>>();
    let expected_digest_bits_u32 = bits_from_bytes_le(&vector.proof_input_hash_value);
    let expected_digest_bits = field_bits_from_bytes_le(&vector.proof_input_hash_value);

    let base_component = build_component(
        padded_blocks.len(),
        &block_bits,
        &expected_digest_bits,
        Some(KeccakConstraintFamily::FinalDigest),
    );

    let config = PcsConfig::default();
    let mut verifier_channel = Blake2sM31Channel::default();
    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
    let sizes = base_component.trace_log_degree_bounds();
    commitment_scheme.commit(slice_proof.proof.commitments[0], &sizes[0], &mut verifier_channel);
    commitment_scheme.commit(slice_proof.proof.commitments[1], &sizes[1], &mut verifier_channel);

    let composition_random_coeff = verifier_channel.draw_secure_felt();
    let split_log_degree_bound = base_component.max_constraint_log_degree_bound() - 1;
    commitment_scheme.commit(
        slice_proof.proof.commitments[2],
        &[split_log_degree_bound; 8],
        &mut verifier_channel,
    );
    let oods_point = CirclePoint::<SecureField>::get_random_point(&mut verifier_channel);

    let composition_oods_eval =
        extract_composition_oods_eval(&slice_proof.proof, oods_point, split_log_degree_bound)?;

    let components = Components {
        components: vec![&base_component as &dyn Component],
        n_preprocessed_columns: sizes[0].len(),
    };
    let quotient_eval = components.eval_composition_polynomial_at_point(
        oods_point,
        &slice_proof.proof.sampled_values,
        composition_random_coeff,
        split_log_degree_bound,
    );
    let denominator_inv =
        coset_vanishing(CanonicCoset::new(split_log_degree_bound).coset, oods_point).inverse();
    let raw_numerator = quotient_eval * denominator_inv.inverse();

    let mut cumulative_family_evals = Vec::with_capacity(FAMILY_NAMES.len());
    for family_index in 0..FAMILY_NAMES.len() {
        let component = build_component(
            padded_blocks.len(),
            &block_bits,
            &expected_digest_bits,
            Some(family_from_index(family_index)),
        );
        let quotient = Components {
            components: vec![&component as &dyn Component],
            n_preprocessed_columns: sizes[0].len(),
        }
        .eval_composition_polynomial_at_point(
            oods_point,
            &slice_proof.proof.sampled_values,
            composition_random_coeff,
            split_log_degree_bound,
        );
        cumulative_family_evals.push(quotient);
    }

    let (proof_input_hash_high, proof_input_hash_low) = split_be_u256(&vector.proof_input_hash_value);

    let mut args = Vec::new();
    slice_proof.proof.serialize_args(&mut args);
    block_bits_u32.serialize_args(&mut args);
    expected_digest_bits_u32.serialize_args(&mut args);
    proof_input_hash_high.serialize_args(&mut args);
    proof_input_hash_low.serialize_args(&mut args);
    composition_random_coeff.serialize_args(&mut args);
    oods_point.x.serialize_args(&mut args);
    oods_point.y.serialize_args(&mut args);
    composition_oods_eval.serialize_args(&mut args);
    denominator_inv.serialize_args(&mut args);
    quotient_eval.serialize_args(&mut args);
    cumulative_family_evals.serialize_args(&mut args);

    let args_path = output_dir.join("cairo_oods_compare_args.json");
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
            "proofInputHash": encode_hex(&vector.proof_input_hash_value),
            "expectedFactPayload": [
                felt_hex_from_u128(proof_input_hash_high),
                felt_hex_from_u128(proof_input_hash_low),
            ],
            "proofInputHashSliceProof": {
                "path": raw_proof_path.display().to_string(),
                "rawBytes": raw_proof_bytes.len(),
            },
            "oodsContext": {
                "compositionLogDegreeBound": MAX_CONSTRAINT_LOG_DEGREE_BOUND,
                "splitLogDegreeBound": split_log_degree_bound,
                "randomCoeff": secure_field_json(composition_random_coeff),
                "oodsPoint": circle_point_json(oods_point),
                "compositionOodsEval": secure_field_json(composition_oods_eval),
                "denominatorInv": secure_field_json(denominator_inv),
                "rawNumerator": secure_field_json(raw_numerator),
                "quotientEval": secure_field_json(quotient_eval),
                "matchesRustVerifierEquality": composition_oods_eval == quotient_eval,
            },
            "familyBoundaries": FAMILY_NAMES.iter().zip(cumulative_family_evals.iter()).map(|(family, eval)| {
                json!({
                    "family": family,
                    "quotientEval": secure_field_json(*eval),
                })
            }).collect::<Vec<_>>(),
            "artifacts": {
                "cairoArgs": args_path.display().to_string(),
            }
        }),
    )?;

    Ok(())
}
