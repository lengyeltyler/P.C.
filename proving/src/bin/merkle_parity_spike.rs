use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use num_traits::Zero;
use serde_json::json;
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::{CirclePolyDegreeBound, FriVerifier};
use stwo::core::pcs::utils::prepare_preprocessed_query_positions;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::core::vcs_lifted::MerkleHasherLifted;
use stwo_constraint_framework::TraceLocationAllocator;

use philcore_proving::fixtures::load_default_vector;
use philcore_proving::keccak_compat::{
    keccak_pad_rate_blocks, prove_proof_input_hash, KeccakCompatComponent, KeccakCompatEval,
    KeccakConstraintFamily, keccak_preprocessed_column_ids,
};
use philcore_proving::types::encode_hex;

const LOG_N_ROWS: u32 = 8;
const MAX_CONSTRAINT_LOG_DEGREE_BOUND: u32 = LOG_N_ROWS + 1;

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

impl CairoArgsSerialize for Blake2sHash {
    fn serialize_args(&self, output: &mut Vec<String>) {
        for word in self.0.chunks_exact(4) {
            let value = u32::from_le_bytes(word.try_into().expect("word-sized chunk"));
            value.serialize_args(output);
        }
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

fn hash_words_json(hash: Blake2sHash) -> serde_json::Value {
    let words = hash
        .0
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("word-sized chunk")))
        .map(|word| felt_hex_from_u64(word.into()))
        .collect::<Vec<_>>();
    json!(words)
}

fn row_json(row: &[BaseField]) -> serde_json::Value {
    json!(
        row.iter()
            .map(|value| felt_hex_from_u64(value.0.into()))
            .collect::<Vec<_>>()
    )
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
        debug_max_family: Some(KeccakConstraintFamily::FinalDigest),
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

fn hash_leaf(values: &[BaseField]) -> Blake2sHash {
    let mut hasher = Blake2sM31MerkleHasher::default();
    hasher.update_leaf(values);
    hasher.finalize()
}

#[derive(Clone)]
struct FirstStepTrace {
    child_position: usize,
    parent_position: usize,
    parity: usize,
    sibling_from_witness: bool,
    sibling_hash: Blake2sHash,
    parent_hash: Blake2sHash,
}

#[derive(Clone)]
struct CairoMerkleTrace {
    first_query_position: usize,
    first_row: Vec<BaseField>,
    first_leaf_hash: Blake2sHash,
    first_step: FirstStepTrace,
    computed_root: Blake2sHash,
}

fn simulate_cairo_merkle(
    tree_height: u32,
    query_positions: &[usize],
    queried_values_flat: &[BaseField],
    hash_witness: &[Blake2sHash],
    n_columns: usize,
) -> Result<CairoMerkleTrace> {
    if query_positions.is_empty() {
        bail!("empty query positions for Merkle trace");
    }
    if n_columns == 0 {
        bail!("tree has zero columns");
    }
    if queried_values_flat.len() != query_positions.len() * n_columns {
        bail!(
            "queried values length mismatch: got {}, expected {}",
            queried_values_flat.len(),
            query_positions.len() * n_columns
        );
    }

    let mut queried_chunks = queried_values_flat.chunks_exact(n_columns);
    let first_query_position = query_positions[0];
    let first_row = queried_chunks
        .next()
        .expect("first row chunk")
        .to_vec();
    let first_leaf_hash = hash_leaf(&first_row);

    let layer_idx = 1_usize << tree_height;
    let mut positions_and_hashes = VecDeque::new();
    positions_and_hashes.push_back((layer_idx + first_query_position, first_leaf_hash));

    let mut prev_pos = first_query_position;
    let mut prev_row = first_row.clone();
    for pos in query_positions.iter().copied().skip(1) {
        let row = queried_chunks
            .next()
            .expect("row chunk for remaining query")
            .to_vec();
        if prev_pos == pos {
            if prev_row != row {
                bail!("queried values at duplicate positions are inconsistent");
            }
        } else {
            positions_and_hashes.push_back((layer_idx + pos, hash_leaf(&row)));
        }
        prev_pos = pos;
        prev_row = row;
    }

    let mut hash_witness = VecDeque::from(hash_witness.to_vec());
    let (first_child_position, first_child_hash) =
        positions_and_hashes.pop_front().expect("first leaf hash");
    let first_parent_position = first_child_position >> 1;
    let first_parity = first_child_position & 1;
    if first_parent_position == 0 {
        bail!("unexpected zero-height tree");
    }

    let (first_sibling_hash, first_sibling_from_witness) = if first_parity == 1 {
        (
            hash_witness
                .pop_front()
                .context("witness too short for first odd-position leaf")?,
            true,
        )
    } else if let Some((maybe_sibling_position, _maybe_sibling_hash)) = positions_and_hashes.front()
    {
        if *maybe_sibling_position == first_child_position + 1 {
            let (_, sibling_hash) = positions_and_hashes
                .pop_front()
                .expect("sibling position existed");
            (sibling_hash, false)
        } else {
            (
                hash_witness
                    .pop_front()
                    .context("witness too short for first even-position leaf")?,
                true,
            )
        }
    } else {
        (
            hash_witness
                .pop_front()
                .context("witness too short for first even-position leaf without sibling")?,
            true,
        )
    };

    let first_parent_hash = if first_parity == 1 {
        Blake2sM31MerkleHasher::hash_children((first_sibling_hash, first_child_hash))
    } else {
        Blake2sM31MerkleHasher::hash_children((first_child_hash, first_sibling_hash))
    };

    positions_and_hashes.push_back((first_parent_position, first_parent_hash));

    while let Some((child_position, child_hash)) = positions_and_hashes.pop_front() {
        let parent_position = child_position >> 1;
        let parity = child_position & 1;

        if parent_position == 0 {
            if !hash_witness.is_empty() {
                bail!("witness too long after computing Merkle root");
            }

            return Ok(CairoMerkleTrace {
                first_query_position,
                first_row,
                first_leaf_hash,
                first_step: FirstStepTrace {
                    child_position: first_child_position,
                    parent_position: first_parent_position,
                    parity: first_parity,
                    sibling_from_witness: first_sibling_from_witness,
                    sibling_hash: first_sibling_hash,
                    parent_hash: first_parent_hash,
                },
                computed_root: child_hash,
            });
        }

        let parent_hash = if parity == 1 {
            let sibling_hash = hash_witness
                .pop_front()
                .context("witness too short while hashing odd-position node")?;
            Blake2sM31MerkleHasher::hash_children((sibling_hash, child_hash))
        } else if let Some((maybe_sibling_position, _maybe_sibling_hash)) = positions_and_hashes.front()
        {
            if *maybe_sibling_position == child_position + 1 {
                let (_, sibling_hash) = positions_and_hashes
                    .pop_front()
                    .expect("sibling position existed");
                Blake2sM31MerkleHasher::hash_children((child_hash, sibling_hash))
            } else {
                let sibling_hash = hash_witness
                    .pop_front()
                    .context("witness too short while hashing even-position node")?;
                Blake2sM31MerkleHasher::hash_children((child_hash, sibling_hash))
            }
        } else {
            let sibling_hash = hash_witness
                .pop_front()
                .context("witness too short while hashing final even-position node")?;
            Blake2sM31MerkleHasher::hash_children((child_hash, sibling_hash))
        };

        positions_and_hashes.push_back((parent_position, parent_hash));
    }

    bail!("failed to compute Merkle root from authentic proof data")
}

fn flatten_column_major(columns: &[Vec<BaseField>]) -> Vec<BaseField> {
    let mut flat = Vec::new();
    for column in columns {
        flat.extend(column.iter().copied());
    }
    flat
}

fn flatten_row_major(columns: &[Vec<BaseField>]) -> Vec<BaseField> {
    if columns.is_empty() {
        return Vec::new();
    }

    let n_queries = columns[0].len();
    let mut flat = Vec::with_capacity(columns.len() * n_queries);
    for row_idx in 0..n_queries {
        for column in columns {
            flat.push(column[row_idx]);
        }
    }
    flat
}

fn tree_label(tree_index: usize) -> &'static str {
    match tree_index {
        0 => "preprocessed",
        1 => "trace",
        2 => "composition",
        _ => "unknown",
    }
}

fn main() -> Result<()> {
    let vector = load_default_vector()?;
    let output_dir = PathBuf::from("out/merkle_parity_spike");
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    let slice_proof = prove_proof_input_hash(&vector)?;
    let raw_proof_bytes = bincode::serialize(&slice_proof)?;
    let raw_proof_path = output_dir.join("proof_input_hash_slice_proof.bin");
    fs::write(&raw_proof_path, &raw_proof_bytes)
        .with_context(|| format!("failed to write {}", raw_proof_path.display()))?;

    let padded_blocks = keccak_pad_rate_blocks(&vector.proof_input_hash_preimage);
    let block_bits = padded_blocks
        .iter()
        .map(|block| {
            bits_from_bytes_le(block)
                .into_iter()
                .map(BaseField::from)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let expected_digest_bits = bits_from_bytes_le(&vector.proof_input_hash_value)
        .into_iter()
        .map(BaseField::from)
        .collect::<Vec<_>>();

    let base_component = build_component(padded_blocks.len(), &block_bits, &expected_digest_bits);

    let config = slice_proof.proof.config;
    let mut verifier_channel = Blake2sM31Channel::default();
    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
    let sizes = base_component.trace_log_degree_bounds();
    commitment_scheme.commit(slice_proof.proof.commitments[0], &sizes[0], &mut verifier_channel);
    commitment_scheme.commit(slice_proof.proof.commitments[1], &sizes[1], &mut verifier_channel);

    let split_log_degree_bound = base_component.max_constraint_log_degree_bound() - 1;
    commitment_scheme.commit(
        slice_proof.proof.commitments[2],
        &[split_log_degree_bound; 8],
        &mut verifier_channel,
    );

    verifier_channel.mix_felts(&slice_proof.proof.sampled_values.clone().flatten_cols());
    let _random_coeff = verifier_channel.draw_secure_felt();

    let lifting_log_size = commitment_scheme
        .trees
        .last()
        .context("missing commitment scheme tree")?
        .height;
    let fri_bound =
        CirclePolyDegreeBound::new(lifting_log_size - config.fri_config.log_blowup_factor);
    let mut fri_verifier = FriVerifier::<Blake2sM31MerkleChannel>::commit(
        &mut verifier_channel,
        config.fri_config,
        slice_proof.proof.fri_proof.clone(),
        fri_bound,
    )?;
    if !verifier_channel.verify_pow_nonce(config.pow_bits, slice_proof.proof.proof_of_work) {
        bail!("authentic proof of work failed while reconstructing Merkle target");
    }
    verifier_channel.mix_u64(slice_proof.proof.proof_of_work);
    let query_positions = fri_verifier.sample_query_positions(&mut verifier_channel);
    let preprocessed_query_positions = prepare_preprocessed_query_positions(
        &query_positions,
        lifting_log_size,
        commitment_scheme.trees[0].height,
    );

    let mut failing_tree = None;

    for tree_index in 0..slice_proof.proof.queried_values.0.len() {
        let tree_query_positions = if tree_index == 0 {
            preprocessed_query_positions.clone()
        } else {
            query_positions.clone()
        };

        let tree_values = &slice_proof.proof.queried_values[tree_index];
        let current_flat = flatten_column_major(tree_values);
        let expected_flat = flatten_row_major(tree_values);
        let n_columns = tree_values.len();
        let current_trace = simulate_cairo_merkle(
            commitment_scheme.trees[tree_index].height,
            &tree_query_positions,
            &current_flat,
            &slice_proof.proof.decommitments[tree_index].hash_witness,
            n_columns,
        )?;
        let expected_trace = simulate_cairo_merkle(
            commitment_scheme.trees[tree_index].height,
            &tree_query_positions,
            &expected_flat,
            &slice_proof.proof.decommitments[tree_index].hash_witness,
            n_columns,
        )?;
        let root = slice_proof.proof.commitments[tree_index];

        if current_trace.computed_root != root {
            failing_tree = Some((
                tree_index,
                tree_query_positions,
                current_flat,
                expected_flat,
                current_trace,
                expected_trace,
            ));
            break;
        }
    }

    let (
        failing_tree_index,
        tree_query_positions,
        current_flat,
        _expected_flat,
        current_trace,
        expected_trace,
    ) = failing_tree.context("no failing authentic Merkle tree found")?;

    let current_root = current_trace.computed_root;
    let expected_root = expected_trace.computed_root;
    let authentic_root = slice_proof.proof.commitments[failing_tree_index];
    if expected_root != authentic_root {
        bail!("expected row-major Merkle reconstruction did not match authentic root");
    }

    let first_row_diverges = current_trace.first_row != expected_trace.first_row;
    if !first_row_diverges {
        bail!("first queried row did not diverge despite Merkle root mismatch");
    }
    if current_trace.first_leaf_hash == expected_trace.first_leaf_hash {
        bail!("first leaf hash unexpectedly matches despite row divergence");
    }

    let fact_high_low = split_be_u256(&vector.proof_input_hash_value);
    let args_path = output_dir.join("cairo_merkle_probe_args.json");
    let mut args = Vec::new();
    authentic_root.serialize_args(&mut args);
    commitment_scheme.trees[failing_tree_index]
        .height
        .serialize_args(&mut args);
    if failing_tree_index == 0 {
        sizes[0].serialize_args(&mut args);
    } else if failing_tree_index == 1 {
        sizes[1].serialize_args(&mut args);
    } else {
        vec![split_log_degree_bound; 8].serialize_args(&mut args);
    }
    tree_query_positions.serialize_args(&mut args);
    current_flat.serialize_args(&mut args);
    slice_proof.proof.decommitments[failing_tree_index]
        .hash_witness
        .serialize_args(&mut args);
    expected_trace.first_leaf_hash.serialize_args(&mut args);
    expected_trace.first_step.parent_hash.serialize_args(&mut args);
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
                felt_hex_from_u128(fact_high_low.0),
                felt_hex_from_u128(fact_high_low.1),
            ],
            "proofInputHashSliceProof": {
                "path": raw_proof_path.display().to_string(),
                "rawBytes": raw_proof_bytes.len(),
            },
            "queryContext": {
                "rawQueryPositions": query_positions,
                "failingTreeQueryPositions": tree_query_positions,
                "failingTreeIndex": failing_tree_index,
                "failingTreeLabel": tree_label(failing_tree_index),
                "treeHeight": commitment_scheme.trees[failing_tree_index].height,
                "columnCount": slice_proof.proof.queried_values[failing_tree_index].len(),
            },
            "rootParity": {
                "authenticRoot": hash_words_json(authentic_root),
                "expectedRowMajorComputedRoot": hash_words_json(expected_root),
                "currentAdapterComputedRoot": hash_words_json(current_root),
                "expectedRowMajorMatchesAuthenticRoot": expected_root == authentic_root,
                "currentAdapterMatchesAuthenticRoot": current_root == authentic_root,
            },
            "firstExactDivergence": {
                "kind": "queried_values_column_major_vs_row_major_leaf_packing",
                "queryPosition": current_trace.first_query_position,
                "childPosition": current_trace.first_step.child_position,
                "parentPosition": current_trace.first_step.parent_position,
                "parity": current_trace.first_step.parity,
                "siblingFromWitness": current_trace.first_step.sibling_from_witness,
                "siblingHash": hash_words_json(current_trace.first_step.sibling_hash),
                "currentAdapterFirstRow": row_json(&current_trace.first_row),
                "expectedRowMajorFirstRow": row_json(&expected_trace.first_row),
                "currentAdapterFirstLeafHash": hash_words_json(current_trace.first_leaf_hash),
                "expectedRowMajorFirstLeafHash": hash_words_json(expected_trace.first_leaf_hash),
                "currentAdapterFirstParentHash": hash_words_json(current_trace.first_step.parent_hash),
                "expectedRowMajorFirstParentHash": hash_words_json(expected_trace.first_step.parent_hash),
                "firstRowMatches": current_trace.first_row == expected_trace.first_row,
                "firstLeafMatches": current_trace.first_leaf_hash == expected_trace.first_leaf_hash,
                "firstParentMatches": current_trace.first_step.parent_hash == expected_trace.first_step.parent_hash,
            },
            "artifacts": {
                "cairoMerkleProbeArgsPath": args_path.display().to_string(),
            }
        }),
    )?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "summaryPath": summary_path.display().to_string(),
            "cairoMerkleProbeArgsPath": args_path.display().to_string(),
            "failingTreeIndex": failing_tree_index,
            "failingTreeLabel": tree_label(failing_tree_index),
        }))?
    );

    Ok(())
}
