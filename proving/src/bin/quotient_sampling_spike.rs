use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::json;
use stwo::core::air::{Component, Components};
use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::utils::get_lifting_log_size;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::verifier::COMPOSITION_LOG_SPLIT;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo_constraint_framework::TraceLocationAllocator;

use philcore_proving::fixtures::load_default_vector;
use philcore_proving::keccak_compat::{
    keccak_pad_rate_blocks, prove_proof_input_hash, KeccakCompatComponent, KeccakCompatEval,
};
use philcore_proving::types::encode_hex;

const LOG_N_ROWS: u32 = 8;
const MAX_CONSTRAINT_LOG_DEGREE_BOUND: u32 = LOG_N_ROWS + 1;

fn field_bits_from_bytes_le(bytes: &[u8]) -> Vec<BaseField> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for bit in 0..8 {
            bits.push(BaseField::from(((byte >> bit) & 1) as u32));
        }
    }
    bits
}

fn build_component(
    n_blocks: usize,
    block_bits: &[Vec<BaseField>],
    expected_digest_bits: &[BaseField],
) -> KeccakCompatComponent {
    let eval = KeccakCompatEval {
        log_n_rows: LOG_N_ROWS,
        n_blocks,
        max_constraint_log_degree_bound: MAX_CONSTRAINT_LOG_DEGREE_BOUND,
        debug_max_family: None,
        debug_enable_state_transition_formula: true,
        debug_enable_state_transition_link: true,
        block_bits: block_bits.to_vec(),
        expected_digest_bits: expected_digest_bits.to_vec(),
    };

    KeccakCompatComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(
            &philcore_proving::keccak_compat::keccak_preprocessed_column_ids(n_blocks),
        ),
        eval,
        SecureField::from_u32_unchecked(0, 0, 0, 0),
    )
}

fn split_be_u256(bytes: &[u8; 32]) -> (u128, u128) {
    let high = u128::from_be_bytes(bytes[..16].try_into().expect("high half"));
    let low = u128::from_be_bytes(bytes[16..].try_into().expect("low half"));
    (high, low)
}

fn felt_words(value: SecureField) -> [u32; 4] {
    value.to_m31_array().map(|limb| limb.0)
}

fn point_words(point: CirclePoint<SecureField>) -> [[u32; 4]; 2] {
    [felt_words(point.x), felt_words(point.y)]
}

fn classify_point(
    point: CirclePoint<SecureField>,
    oods_point: CirclePoint<SecureField>,
    prev_oods_point: CirclePoint<SecureField>,
    next_oods_point: CirclePoint<SecureField>,
    periodicity_point: CirclePoint<SecureField>,
) -> &'static str {
    if point == oods_point {
        "oods"
    } else if point == prev_oods_point {
        "prev"
    } else if point == next_oods_point {
        "next"
    } else if point == periodicity_point {
        "periodicity"
    } else {
        "other"
    }
}

fn write_json(path: &PathBuf, value: &serde_json::Value) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn main() -> Result<()> {
    let vector = load_default_vector()?;
    let output_dir = PathBuf::from("out/quotient_sampling_spike");
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    let slice_proof = prove_proof_input_hash(&vector)?;
    let padded_blocks = keccak_pad_rate_blocks(&vector.proof_input_hash_preimage);
    let block_bits = padded_blocks
        .iter()
        .map(|block| field_bits_from_bytes_le(block))
        .collect::<Vec<_>>();
    let expected_digest_bits = field_bits_from_bytes_le(&vector.proof_input_hash_value);
    let component = build_component(padded_blocks.len(), &block_bits, &expected_digest_bits);

    let config = PcsConfig::default();
    let mut verifier_channel = Blake2sM31Channel::default();
    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();

    commitment_scheme.commit(
        slice_proof.proof.commitments[0],
        &sizes[0],
        &mut verifier_channel,
    );
    commitment_scheme.commit(
        slice_proof.proof.commitments[1],
        &sizes[1],
        &mut verifier_channel,
    );

    let components = Components {
        components: vec![&component],
        n_preprocessed_columns: sizes[0].len(),
    };
    let split_composition_log_degree_bound =
        components.composition_log_degree_bound() - COMPOSITION_LOG_SPLIT;
    let lifting_log_size = get_lifting_log_size(
        &config,
        split_composition_log_degree_bound + config.fri_config.log_blowup_factor,
    );
    let max_log_degree_bound = lifting_log_size - config.fri_config.log_blowup_factor;

    let random_coeff = verifier_channel.draw_secure_felt();
    commitment_scheme.commit(
        slice_proof.proof.commitments[2],
        &[max_log_degree_bound; 8],
        &mut verifier_channel,
    );
    let oods_point = CirclePoint::<SecureField>::get_random_point(&mut verifier_channel);
    let trace_step = CanonicCoset::new(max_log_degree_bound).step();
    let prev_oods_point = oods_point + trace_step.mul_signed(-1).into_ef();
    let next_oods_point = oods_point + trace_step.into_ef();

    let mut sample_points = components.mask_points(oods_point, max_log_degree_bound, false);
    sample_points.push(vec![vec![oods_point]; 8]);

    let trace_log_sizes = &sizes[1];
    let trace_sample_points = &sample_points[1];
    let trace_sample_values = &slice_proof.proof.sampled_values[1];
    let lifting_domain_generator = CanonicCoset::new(lifting_log_size).step();

    let mut raw_sample_count_summary = BTreeMap::new();
    let mut trace_order_signatures = BTreeMap::<String, usize>::new();
    let mut first_three_sample_column = None;

    for (column_index, sample_values) in trace_sample_values.iter().enumerate() {
        *raw_sample_count_summary
            .entry(sample_values.len().to_string())
            .or_insert(0usize) += 1;
        if sample_values.len() != 3 {
            continue;
        }

        let log_size = trace_log_sizes[column_index];
        let periodicity_point =
            oods_point + lifting_domain_generator.repeated_double(log_size).into_ef();
        let points = &trace_sample_points[column_index];
        let labels = points
            .iter()
            .map(|point| classify_point(
                *point,
                oods_point,
                prev_oods_point,
                next_oods_point,
                periodicity_point,
            ))
            .collect::<Vec<_>>();
        let signature = labels.join(" -> ");
        *trace_order_signatures.entry(signature.clone()).or_insert(0) += 1;

        if first_three_sample_column.is_none() {
            first_three_sample_column = Some(json!({
                "columnIndex": column_index,
                "logSize": log_size,
                "sampleCount": sample_values.len(),
                "labels": labels,
                "pointWords": points.iter().map(|point| point_words(*point)).collect::<Vec<_>>(),
                "valueWords": sample_values.iter().map(|value| felt_words(*value)).collect::<Vec<_>>(),
                "oodsPointWords": point_words(oods_point),
                "prevOodsPointWords": point_words(prev_oods_point),
                "nextOodsPointWords": point_words(next_oods_point),
                "periodicityPointWords": point_words(periodicity_point),
            }));
        }
    }

    let (proof_input_hash_high, proof_input_hash_low) = split_be_u256(&vector.proof_input_hash_value);
    let summary_path = output_dir.join("summary.json");
    write_json(
        &summary_path,
        &json!({
            "proofType": vector.proof_type,
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
                format!("0x{proof_input_hash_high:x}"),
                format!("0x{proof_input_hash_low:x}")
            ],
            "maxLogDegreeBound": max_log_degree_bound,
            "liftingLogSize": lifting_log_size,
            "rawTraceSampleCountSummary": raw_sample_count_summary,
            "traceThreeSampleOrderSignatures": trace_order_signatures,
            "firstThreeSampleColumn": first_three_sample_column,
            "rustQuotientSemantics": {
                "buildSamplesWithRandomnessAndPeriodicity": "preserves explicit non-empty sample lists and only synthesizes a periodicity sample when the raw list length is exactly 2",
                "columnSampleBatchNewVec": "groups samples by actual point identity, not by tuple position"
            }
        }),
    )?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "summaryPath": summary_path.display().to_string()
        }))?
    );

    let _ = random_coeff;
    Ok(())
}
