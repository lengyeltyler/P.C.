use core::array::ArrayTrait;
use core::box::{BoxImpl, BoxTrait};
use core::num::traits::Zero;
use core::traits::TryInto;
use stwo_constraint_framework::{
    PreprocessedMaskValues, PreprocessedMaskValuesTrait,
};
use stwo_verifier_core::channel::{Channel, ChannelTrait};
use stwo_verifier_core::circle::ChannelGetRandomCirclePointTrait;
use stwo_verifier_core::fields::Invertible;
use stwo_verifier_core::fields::m31::{M31, m31};
use stwo_verifier_core::fields::qm31::{QM31, QM31Trait};
use stwo_verifier_core::fri::{FriConfig, FriLayerProof, FriProof};
use stwo_verifier_core::pcs::PcsConfig;
use stwo_verifier_core::pcs::verifier::{
    CommitmentSchemeProof, CommitmentSchemeVerifier, CommitmentSchemeVerifierImpl,
};
use stwo_verifier_core::poly::circle::{CanonicCosetImpl, CanonicCosetTrait};
use stwo_verifier_core::poly::line::LinePoly;
use stwo_verifier_core::vcs::blake2s_hasher::Blake2sHash;
use stwo_verifier_core::vcs::verifier::MerkleDecommitment;
use stwo_verifier_core::verifier::{Air, StarkProof as CoreStarkProof, verify};
use stwo_verifier_core::{ColumnSpan, Hash, TreeSpan};

const LOG_N_ROWS: u32 = 8;
const MAX_CONSTRAINT_LOG_DEGREE_BOUND: u32 = LOG_N_ROWS + 1;
const MIN_SECURITY_BITS: u32 = 10;
const N_BLOCKS: usize = 4;
const BLOCK_ROWS: usize = 25;
const KECCAK_ROUNDS: usize = 24;
const RATE_BITS: usize = 1088;
const STATE_BITS: usize = 1600;
const LANE_BITS: usize = 64;
const STATE_LANES: usize = 25;
const DIGEST_BITS: usize = 256;
const FAMILY_COUNT: usize = 11;
const FAMILY_STATE_BOOLEAN: u32 = 0;
const FAMILY_ABSORB: u32 = 1;
const FAMILY_P01: u32 = 2;
const FAMILY_P23: u32 = 3;
const FAMILY_P0123: u32 = 4;
const FAMILY_C: u32 = 5;
const FAMILY_D: u32 = 6;
const FAMILY_RHOPI: u32 = 7;
const FAMILY_CHI_AUX: u32 = 8;
const FAMILY_STATE_TRANSITION: u32 = 9;
const FAMILY_FINAL_DIGEST: u32 = 10;

const ROUND_SELECTOR_IDX: u32 = 0;
const FINAL_SELECTOR_IDX: u32 = 1;
const BLOCK_START_SELECTOR_BASE_IDX: u32 = 2;
const ROUND_CONSTANT_BASE_IDX: u32 = BLOCK_START_SELECTOR_BASE_IDX + N_BLOCKS;

const KECCAK_RHO_OFFSETS: [usize; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

#[derive(Copy, Drop, Serde)]
pub struct SecureFieldWords {
    a0: u32,
    a1: u32,
    a2: u32,
    a3: u32,
}

#[derive(Copy, Drop, Serde)]
pub struct Blake2sHashWords {
    w0: u32,
    w1: u32,
    w2: u32,
    w3: u32,
    w4: u32,
    w5: u32,
    w6: u32,
    w7: u32,
}

#[derive(Drop, Serde)]
pub struct MerkleDecommitmentMirror {
    hash_witness: Array<Blake2sHashWords>,
}

#[derive(Copy, Drop, Serde)]
pub struct FriConfigMirror {
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: u32,
    fold_step: u32,
}

#[derive(Copy, Drop, Serde)]
pub struct PcsConfigMirror {
    pow_bits: u32,
    fri_config: FriConfigMirror,
}

#[derive(Drop, Serde)]
pub struct FriLayerProofMirror {
    fri_witness: Array<SecureFieldWords>,
    decommitment: MerkleDecommitmentMirror,
    commitment: Blake2sHashWords,
}

#[derive(Drop, Serde)]
pub struct LinePolyMirror {
    coeffs: Array<SecureFieldWords>,
    log_size: u32,
}

#[derive(Drop, Serde)]
pub struct FriProofMirror {
    first_layer: FriLayerProofMirror,
    inner_layers: Array<FriLayerProofMirror>,
    last_layer_poly: LinePolyMirror,
}

#[derive(Drop, Serde)]
pub struct CommitmentSchemeProofMirror {
    config: PcsConfigMirror,
    commitments: Array<Blake2sHashWords>,
    sampled_values: Array<Array<Array<SecureFieldWords>>>,
    decommitments: Array<MerkleDecommitmentMirror>,
    queried_values: Array<Array<Array<u32>>>,
    proof_of_work: u64,
    fri_proof: FriProofMirror,
}

#[derive(Drop, Serde)]
pub struct StarkProofMirror {
    commitment_scheme_proof: CommitmentSchemeProofMirror,
}

#[derive(Drop, Serde)]
pub struct ProofInputHashSliceClaim {
    block_bits: Array<Array<u32>>,
    expected_digest_bits: Array<u32>,
    fact_high: u128,
    fact_low: u128,
}

#[derive(Copy, Drop, Serde)]
pub struct VerificationFactPayload {
    pub fact_high: u128,
    pub fact_low: u128,
}

#[derive(Drop, Serde)]
struct ExpectedOodsDebug {
    random_coeff: SecureFieldWords,
    ood_x: SecureFieldWords,
    ood_y: SecureFieldWords,
    composition_oods_eval: SecureFieldWords,
    denominator_inv: SecureFieldWords,
    quotient_eval: SecureFieldWords,
    cumulative_family_evals: Array<SecureFieldWords>,
}

#[derive(Drop, Serde)]
struct OodsComparisonResult {
    fact_high: u128,
    fact_low: u128,
    random_coeff_matches: u32,
    ood_point_matches: u32,
    composition_oods_eval_matches: u32,
    denominator_inv_matches: u32,
    quotient_eval_matches: u32,
    first_family_mismatch_index: u32,
    actual_first_family_eval: SecureFieldWords,
    expected_first_family_eval: SecureFieldWords,
    actual_composition_oods_eval: SecureFieldWords,
    expected_composition_oods_eval: SecureFieldWords,
    actual_denominator_inv: SecureFieldWords,
    expected_denominator_inv: SecureFieldWords,
    actual_quotient_eval: SecureFieldWords,
    expected_quotient_eval: SecureFieldWords,
    forced_transcript_composition_matches: u32,
    forced_transcript_denominator_matches: u32,
    forced_transcript_quotient_matches: u32,
    forced_first_family_mismatch_index: u32,
    forced_actual_first_family_eval: SecureFieldWords,
    forced_expected_first_family_eval: SecureFieldWords,
}

#[derive(Drop)]
struct KeccakCompatAir {
    block_bits: Array<Array<QM31>>,
    expected_digest_bits: Array<QM31>,
}

fn secure_field_from_words(words: @SecureFieldWords) -> QM31 {
    QM31Trait::from_fixed_array([
        m31((*words).a0), m31((*words).a1), m31((*words).a2), m31((*words).a3),
    ])
}

fn secure_field_to_words(value: QM31) -> SecureFieldWords {
    let [a0, a1, a2, a3] = value.to_fixed_array();
    SecureFieldWords {
        a0: a0.into(), a1: a1.into(), a2: a2.into(), a3: a3.into(),
    }
}

fn bool_to_u32(value: bool) -> u32 {
    if value { 1 } else { 0 }
}

fn family_enabled(max_family: u32, family: u32) -> bool {
    family <= max_family
}

fn hash_from_words(words: @Blake2sHashWords) -> Hash {
    Blake2sHash {
        hash: BoxImpl::new([
            (*words).w0, (*words).w1, (*words).w2, (*words).w3, (*words).w4, (*words).w5,
            (*words).w6, (*words).w7,
        ]),
    }
}

fn m31_array_from_u32s(values: @Array<u32>) -> Array<M31> {
    let mut result = array![];
    for value in values.span() {
        result.append(m31(*value));
    }
    result
}

fn queried_tree_from_mirror(tree: @Array<Array<u32>>) -> Array<M31> {
    let mut queried_tree = array![];
    let column_count = tree.len();
    if column_count == 0 {
        return queried_tree;
    }

    let first_column = tree.span()[0];
    let query_count = first_column.len();

    let mut query_index = 0;
    while query_index < query_count {
        let mut column_index = 0;
        while column_index < column_count {
            let column = tree.span()[column_index];
            assert!(column.len() == query_count, "inconsistent queried-value column length");
            queried_tree.append(m31(*column.span()[query_index]));
            column_index += 1;
        }
        query_index += 1;
    }

    queried_tree
}

fn hash_witness_from_mirror(mirror: @MerkleDecommitmentMirror) -> MerkleDecommitment<stwo_verifier_core::vcs::MerkleHasher> {
    let mut witness = array![];
    for hash_words in mirror.hash_witness.span() {
        witness.append(hash_from_words(hash_words));
    }
    MerkleDecommitment { hash_witness: witness.span() }
}

fn fri_layer_from_mirror(mirror: @FriLayerProofMirror) -> FriLayerProof {
    let mut fri_witness = array![];
    for words in mirror.fri_witness.span() {
        fri_witness.append(secure_field_from_words(words));
    }

    FriLayerProof {
        fri_witness: fri_witness.span(),
        decommitment: hash_witness_from_mirror(mirror.decommitment),
        commitment: hash_from_words(mirror.commitment),
    }
}

fn line_poly_from_mirror(mirror: @LinePolyMirror) -> LinePoly {
    let mut coeffs = array![];
    for words in mirror.coeffs.span() {
        coeffs.append(secure_field_from_words(words));
    }
    LinePoly { coeffs, log_size: *mirror.log_size }
}

fn fri_proof_from_mirror(mirror: @FriProofMirror) -> FriProof {
    let mut inner_layers = array![];
    for layer in mirror.inner_layers.span() {
        inner_layers.append(fri_layer_from_mirror(layer));
    }

    FriProof {
        first_layer: fri_layer_from_mirror(mirror.first_layer),
        inner_layers: inner_layers.span(),
        last_layer_poly: line_poly_from_mirror(mirror.last_layer_poly),
    }
}

fn pcs_config_from_mirror(mirror: @PcsConfigMirror) -> PcsConfig {
    PcsConfig {
        pow_bits: *mirror.pow_bits,
        fri_config: FriConfig {
            log_blowup_factor: *mirror.fri_config.log_blowup_factor,
            log_last_layer_degree_bound: *mirror.fri_config.log_last_layer_degree_bound,
            n_queries: (*mirror.fri_config.n_queries).try_into().unwrap(),
            fold_step: *mirror.fri_config.fold_step,
        },
    }
}

fn commitment_scheme_proof_from_mirror(mirror: @CommitmentSchemeProofMirror) -> CommitmentSchemeProof {
    let mut commitments = array![];
    for words in mirror.commitments.span() {
        commitments.append(hash_from_words(words));
    }

    let mut sampled_values = array![];
    for tree in mirror.sampled_values.span() {
        let mut sampled_tree = array![];
        for column in tree.span() {
            let mut sampled_column = array![];
            for words in column.span() {
                sampled_column.append(secure_field_from_words(words));
            }
            sampled_tree.append(sampled_column.span());
        }
        sampled_values.append(sampled_tree.span());
    }

    let mut decommitments = array![];
    for decommitment in mirror.decommitments.span() {
        decommitments.append(hash_witness_from_mirror(decommitment));
    }

    let mut queried_values = array![];
    for tree in mirror.queried_values.span() {
        let queried_tree = queried_tree_from_mirror(tree);
        queried_values.append(queried_tree.span());
    }

    CommitmentSchemeProof {
        config: pcs_config_from_mirror(mirror.config),
        commitments: commitments.span(),
        sampled_values: sampled_values.span(),
        decommitments,
        queried_values,
        proof_of_work_nonce: *mirror.proof_of_work,
        fri_proof: fri_proof_from_mirror(mirror.fri_proof),
    }
}

fn stark_proof_from_mirror(mirror: StarkProofMirror) -> CoreStarkProof {
    CoreStarkProof {
        commitment_scheme_proof: commitment_scheme_proof_from_mirror(@mirror.commitment_scheme_proof),
    }
}

fn qm31_bit(value: u32) -> QM31 {
    QM31Trait::from_fixed_array([m31(value), m31(0), m31(0), m31(0)])
}

fn xor_expr(a: QM31, b: QM31) -> QM31 {
    a + b - a * b * qm31_bit(2)
}

fn add_constraint(ref sum: QM31, random_coeff: QM31, constraint: QM31) {
    sum = sum * random_coeff + constraint;
}

fn add_constraint_if(ref sum: QM31, random_coeff: QM31, enabled: bool, constraint: QM31) {
    if enabled {
        add_constraint(ref sum, random_coeff, constraint);
    }
}

fn state_bit_index(x: usize, y: usize, z: usize) -> usize {
    (x + 5 * y) * LANE_BITS + z
}

fn lane5_bit_index(x: usize, z: usize) -> usize {
    x * LANE_BITS + z
}

fn block_start_selector_idx(index: usize) -> u32 {
    BLOCK_START_SELECTOR_BASE_IDX + index.into()
}

fn round_constant_idx(bit: usize) -> u32 {
    ROUND_CONSTANT_BASE_IDX + bit.into()
}

fn inverse_rho_pi(target_lane: usize) -> (usize, usize) {
    let mut source_lane = 0;
    while source_lane < STATE_LANES {
        let x = source_lane % 5;
        let y = source_lane / 5;
        let target_x = y;
        let target_y = (2 * x + 3 * y) % 5;
        let mapped_lane = target_x + 5 * target_y;
        if mapped_lane == target_lane {
            return (source_lane, *KECCAK_RHO_OFFSETS.span()[source_lane]);
        }
        source_lane += 1;
    }
    panic!("rho/pi inverse should always resolve a lane");
}

fn pop_single(ref trace_mask_values: ColumnSpan<Span<QM31>>) -> QM31 {
    let mask = *trace_mask_values.pop_front().unwrap();
    let [value]: [QM31; 1] = (*mask.try_into().unwrap()).unbox();
    value
}

fn pop_transition(ref trace_mask_values: ColumnSpan<Span<QM31>>) -> (QM31, QM31, QM31) {
    let mask = *trace_mask_values.pop_front().unwrap();
    let [prev, cur, next]: [QM31; 3] = (*mask.try_into().unwrap()).unbox();
    (prev, cur, next)
}

fn qbit_from_claim(block_bits: @Array<Array<QM31>>, block_index: usize, bit_index: usize) -> QM31 {
    let block = block_bits.span()[block_index];
    *block.span()[bit_index]
}

fn qdigest_bit(expected_digest_bits: @Array<QM31>, bit_index: usize) -> QM31 {
    *expected_digest_bits.span()[bit_index]
}

fn validate_claim(self: @KeccakCompatAir) {
    assert!(self.block_bits.len() == N_BLOCKS);
    for block in self.block_bits.span() {
        assert!(block.len() == RATE_BITS);
    }
    assert!(self.expected_digest_bits.len() == DIGEST_BITS);
}

fn validate_mask_usage(
    preprocessed_mask_values: PreprocessedMaskValues,
    trace_mask_values: ColumnSpan<Span<QM31>>,
    composition_mask_values: ColumnSpan<Span<QM31>>,
) {
    preprocessed_mask_values.validate_usage();
    assert!(trace_mask_values.is_empty());
    assert!(composition_mask_values.len() == 8);
}

fn extract_composition_oods_eval(
    mask_values: TreeSpan<ColumnSpan<Span<QM31>>>,
    oods_point: stwo_verifier_core::circle::CirclePoint<QM31>,
    composition_log_degree_bound: u32,
) -> QM31 {
    let mut trees = mask_values;
    let cols = *trees.pop_back().unwrap();
    let [c0, c1, c2, c3, c4, c5, c6, c7]: [Span<QM31>; 8] = (*cols.try_into().unwrap()).unbox();
    let [v0]: [QM31; 1] = (*c0.try_into().unwrap()).unbox();
    let [v1]: [QM31; 1] = (*c1.try_into().unwrap()).unbox();
    let [v2]: [QM31; 1] = (*c2.try_into().unwrap()).unbox();
    let [v3]: [QM31; 1] = (*c3.try_into().unwrap()).unbox();
    let [v4]: [QM31; 1] = (*c4.try_into().unwrap()).unbox();
    let [v5]: [QM31; 1] = (*c5.try_into().unwrap()).unbox();
    let [v6]: [QM31; 1] = (*c6.try_into().unwrap()).unbox();
    let [v7]: [QM31; 1] = (*c7.try_into().unwrap()).unbox();

    let left = QM31Trait::from_partial_evals([v0, v1, v2, v3]);
    let right = QM31Trait::from_partial_evals([v4, v5, v6, v7]);
    let mut split_x = oods_point.x;
    let mut i = 0;
    while i < composition_log_degree_bound - 2 {
        split_x = stwo_verifier_core::circle::CirclePointTrait::double_x(split_x);
        i += 1;
    }
    left + split_x * right
}

fn eval_keccak_raw_numerator_at_point(
    self: @KeccakCompatAir,
    mask_values: TreeSpan<ColumnSpan<Span<QM31>>>,
    random_coeff: QM31,
    max_family: u32,
) -> QM31 {
    validate_claim(self);

    let [preprocessed_columns, mut trace_columns, composition_columns]: [ColumnSpan<Span<QM31>>; 3] =
        (*mask_values.try_into().unwrap()).unbox();

    let mut sum = Zero::zero();
    let one = qm31_bit(1);
    let mut preprocessed_mask_values = PreprocessedMaskValuesTrait::new(preprocessed_columns);

    let round_active = preprocessed_mask_values.get_and_mark_used(ROUND_SELECTOR_IDX);
    let final_selector = preprocessed_mask_values.get_and_mark_used(FINAL_SELECTOR_IDX);

    let mut block_starts_arr = array![];
    let mut block_index = 0;
    while block_index < N_BLOCKS {
        block_starts_arr.append(
            preprocessed_mask_values.get_and_mark_used(block_start_selector_idx(block_index)),
        );
        block_index += 1;
    }
    let block_starts = block_starts_arr.span();

    let mut rc_bits_arr = array![];
    let mut rc_bit = 0;
    while rc_bit < LANE_BITS {
        rc_bits_arr.append(
            preprocessed_mask_values.get_and_mark_used(round_constant_idx(rc_bit)),
        );
        rc_bit += 1;
    }
    let rc_bits = rc_bits_arr.span();

    let mut state_prev_arr = array![];
    let mut state_cur_arr = array![];
    let mut state_next_arr = array![];
    let mut i = 0;
    while i < STATE_BITS {
        let (prev, cur, next) = pop_transition(ref trace_columns);
        state_prev_arr.append(prev);
        state_cur_arr.append(cur);
        state_next_arr.append(next);
        add_constraint_if(
            ref sum,
            random_coeff,
            family_enabled(max_family, FAMILY_STATE_BOOLEAN),
            cur * (cur - one),
        );
        i += 1;
    }
    let state_prev = state_prev_arr.span();
    let state_cur = state_cur_arr.span();
    let state_next = state_next_arr.span();

    let mut p01_arr = array![];
    let mut p23_arr = array![];
    let mut p0123_arr = array![];
    let mut c_arr = array![];
    let mut d_arr = array![];
    let mut j = 0;
    while j < (5 * LANE_BITS) {
        p01_arr.append(pop_single(ref trace_columns));
        j += 1;
    }
    j = 0;
    while j < (5 * LANE_BITS) {
        p23_arr.append(pop_single(ref trace_columns));
        j += 1;
    }
    j = 0;
    while j < (5 * LANE_BITS) {
        p0123_arr.append(pop_single(ref trace_columns));
        j += 1;
    }
    j = 0;
    while j < (5 * LANE_BITS) {
        c_arr.append(pop_single(ref trace_columns));
        j += 1;
    }
    j = 0;
    while j < (5 * LANE_BITS) {
        d_arr.append(pop_single(ref trace_columns));
        j += 1;
    }
    let p01 = p01_arr.span();
    let p23 = p23_arr.span();
    let p0123 = p0123_arr.span();
    let c = c_arr.span();
    let d = d_arr.span();

    let mut b_arr = array![];
    let mut chi_arr = array![];
    let mut base_state_arr = array![];
    let mut expected_state_arr = array![];
    let mut k = 0;
    while k < STATE_BITS {
        b_arr.append(pop_single(ref trace_columns));
        k += 1;
    }
    k = 0;
    while k < STATE_BITS {
        chi_arr.append(pop_single(ref trace_columns));
        k += 1;
    }
    k = 0;
    while k < STATE_BITS {
        base_state_arr.append(pop_single(ref trace_columns));
        k += 1;
    }
    k = 0;
    while k < STATE_BITS {
        expected_state_arr.append(pop_single(ref trace_columns));
        k += 1;
    }
    let b = b_arr.span();
    let chi = chi_arr.span();
    let base_state = base_state_arr.span();
    let expected_state = expected_state_arr.span();

    let mut bit = 0;
    while bit < STATE_BITS {
        let mut absorb_sum: QM31 = Zero::zero();
        let mut block = 0;
        while block < N_BLOCKS {
            let expected = if block == 0 {
                if bit < RATE_BITS {
                    qbit_from_claim(self.block_bits, block, bit)
                } else {
                    qm31_bit(0)
                }
            } else {
                let prev = *state_prev[bit];
                if bit < RATE_BITS {
                    xor_expr(prev, qbit_from_claim(self.block_bits, block, bit))
                } else {
                    prev
                }
            };
            absorb_sum += *block_starts[block] * (*state_cur[bit] - expected);
            block += 1;
        }
        add_constraint_if(
            ref sum,
            random_coeff,
            family_enabled(max_family, FAMILY_ABSORB),
            absorb_sum,
        );
        bit += 1;
    }

    let mut x = 0;
    while x < 5 {
        let mut z = 0;
        while z < LANE_BITS {
            let parity_index = lane5_bit_index(x, z);
            let a0 = *state_cur[state_bit_index(x, 0, z)];
            let a1 = *state_cur[state_bit_index(x, 1, z)];
            let a2 = *state_cur[state_bit_index(x, 2, z)];
            let a3 = *state_cur[state_bit_index(x, 3, z)];
            let a4 = *state_cur[state_bit_index(x, 4, z)];

            add_constraint_if(
                ref sum,
                random_coeff,
                family_enabled(max_family, FAMILY_P01),
                round_active * (*p01[parity_index] - xor_expr(a0, a1)),
            );
            add_constraint_if(
                ref sum,
                random_coeff,
                family_enabled(max_family, FAMILY_P23),
                round_active * (*p23[parity_index] - xor_expr(a2, a3)),
            );
            add_constraint_if(
                ref sum,
                random_coeff,
                family_enabled(max_family, FAMILY_P0123),
                round_active
                    * (*p0123[parity_index] - xor_expr(*p01[parity_index], *p23[parity_index])),
            );
            add_constraint_if(
                ref sum,
                random_coeff,
                family_enabled(max_family, FAMILY_C),
                round_active * (*c[parity_index] - xor_expr(*p0123[parity_index], a4)),
            );

            let left = *c[lane5_bit_index((x + 4) % 5, z)];
            let right = *c[lane5_bit_index((x + 1) % 5, (z + LANE_BITS - 1) % LANE_BITS)];
            add_constraint_if(
                ref sum,
                random_coeff,
                family_enabled(max_family, FAMILY_D),
                round_active * (*d[parity_index] - xor_expr(left, right)),
            );
            z += 1;
        }
        x += 1;
    }

    let mut target_lane = 0;
    while target_lane < STATE_LANES {
        let (source_lane, rotation) = inverse_rho_pi(target_lane);
        let source_x = source_lane % 5;
        let source_y = source_lane / 5;
        let target_x = target_lane % 5;
        let target_y = target_lane / 5;

        let mut z = 0;
        while z < LANE_BITS {
            let source_bit =
                *state_cur[state_bit_index(source_x, source_y, (z + LANE_BITS - rotation) % LANE_BITS)];
            let d_bit = *d[lane5_bit_index(source_x, (z + LANE_BITS - rotation) % LANE_BITS)];
            let target_index = state_bit_index(target_x, target_y, z);
            add_constraint_if(
                ref sum,
                random_coeff,
                family_enabled(max_family, FAMILY_RHOPI),
                round_active * (*b[target_index] - xor_expr(source_bit, d_bit)),
            );
            z += 1;
        }
        target_lane += 1;
    }

    x = 0;
    while x < 5 {
        let mut y = 0;
        while y < 5 {
            let mut z = 0;
            while z < LANE_BITS {
                let index = state_bit_index(x, y, z);
                let next1 = *b[state_bit_index((x + 1) % 5, y, z)];
                let next2 = *b[state_bit_index((x + 2) % 5, y, z)];
                let chi_expected = (one - next1) * next2;
                add_constraint_if(
                    ref sum,
                    random_coeff,
                    family_enabled(max_family, FAMILY_CHI_AUX),
                    round_active * (*chi[index] - chi_expected),
                );

                let chi_value = xor_expr(*b[index], *chi[index]);
                add_constraint_if(
                    ref sum,
                    random_coeff,
                    family_enabled(max_family, FAMILY_STATE_TRANSITION),
                    round_active * (*base_state[index] - chi_value),
                );
                let expected = if x == 0 && y == 0 {
                    xor_expr(*base_state[index], *rc_bits[z])
                } else {
                    *base_state[index]
                };
                add_constraint_if(
                    ref sum,
                    random_coeff,
                    family_enabled(max_family, FAMILY_STATE_TRANSITION),
                    round_active * (*expected_state[index] - expected),
                );
                add_constraint_if(
                    ref sum,
                    random_coeff,
                    family_enabled(max_family, FAMILY_STATE_TRANSITION),
                    round_active * (*state_next[index] - *expected_state[index]),
                );
                z += 1;
            }
            y += 1;
        }
        x += 1;
    }

    let mut digest_bit = 0;
    while digest_bit < DIGEST_BITS {
        add_constraint_if(
            ref sum,
            random_coeff,
            family_enabled(max_family, FAMILY_FINAL_DIGEST),
            final_selector
                * (*state_cur[digest_bit] - qdigest_bit(self.expected_digest_bits, digest_bit)),
        );
        digest_bit += 1;
    }

    validate_mask_usage(preprocessed_mask_values, trace_columns, composition_columns);
    sum
}

pub impl KeccakCompatAirImpl of Air<KeccakCompatAir> {
    fn eval_composition_polynomial_at_point(
        self: @KeccakCompatAir,
        point: stwo_verifier_core::circle::CirclePoint<QM31>,
        mask_values: TreeSpan<ColumnSpan<Span<QM31>>>,
        random_coeff: QM31,
    ) -> QM31 {
        let _ = point;
        eval_keccak_raw_numerator_at_point(self, mask_values, random_coeff, FAMILY_FINAL_DIGEST)
    }
}

fn make_air(claim: ProofInputHashSliceClaim) -> KeccakCompatAir {
    let mut block_bits = array![];
    for block in claim.block_bits.span() {
        let mut qblock = array![];
        for bit in block.span() {
            qblock.append(qm31_bit(*bit));
        }
        block_bits.append(qblock);
    }

    let mut expected_digest_bits = array![];
    for bit in claim.expected_digest_bits.span() {
        expected_digest_bits.append(qm31_bit(*bit));
    }

    KeccakCompatAir { block_bits, expected_digest_bits }
}

fn compare_oods(
    proof: StarkProofMirror, claim: ProofInputHashSliceClaim, expected: ExpectedOodsDebug,
) -> OodsComparisonResult {
    let fact_high = claim.fact_high;
    let fact_low = claim.fact_low;
    let proof = stark_proof_from_mirror(proof);
    let air = make_air(claim);
    let CoreStarkProof { commitment_scheme_proof } = proof;
    let pcs_config = commitment_scheme_proof.config;
    let commitments: @Box<[Hash; 3]> = commitment_scheme_proof.commitments.try_into().unwrap();
    let [preprocessed_commitment, trace_commitment, composition_commitment] = commitments.unbox();
    let sampled_oods_values = commitment_scheme_proof.sampled_values;

    let mut channel: Channel = Default::default();
    let mut commitment_scheme: CommitmentSchemeVerifier = CommitmentSchemeVerifierImpl::new();
    let log_blowup_factor = pcs_config.fri_config.log_blowup_factor;
    let split_log_degree_bound = MAX_CONSTRAINT_LOG_DEGREE_BOUND - 1;

    commitment_scheme.commit(preprocessed_commitment, [LOG_N_ROWS; 70].span(), ref channel, log_blowup_factor);
    commitment_scheme.commit(trace_commitment, [LOG_N_ROWS; 9600].span(), ref channel, log_blowup_factor);

    let composition_random_coeff = channel.draw_secure_felt();
    commitment_scheme.commit(
        composition_commitment,
        [split_log_degree_bound; 8].span(),
        ref channel,
        log_blowup_factor,
    );
    let ood_point = channel.get_random_point();

    let composition_oods_eval = extract_composition_oods_eval(
        sampled_oods_values, ood_point, MAX_CONSTRAINT_LOG_DEGREE_BOUND,
    );
    let denominator_inv = CanonicCosetImpl::new(split_log_degree_bound)
        .eval_vanishing(ood_point)
        .inverse();
    let raw_numerator = eval_keccak_raw_numerator_at_point(
        @air, sampled_oods_values, composition_random_coeff, FAMILY_FINAL_DIGEST,
    );
    let quotient_eval = raw_numerator * denominator_inv;

    let expected_random_coeff = secure_field_from_words(@expected.random_coeff);
    let expected_ood_x = secure_field_from_words(@expected.ood_x);
    let expected_ood_y = secure_field_from_words(@expected.ood_y);
    let expected_ood_point = stwo_verifier_core::circle::CirclePoint {
        x: expected_ood_x, y: expected_ood_y,
    };
    let expected_composition_oods_eval = secure_field_from_words(@expected.composition_oods_eval);
    let expected_denominator_inv = secure_field_from_words(@expected.denominator_inv);
    let expected_quotient_eval = secure_field_from_words(@expected.quotient_eval);

    let mut first_family_mismatch_index: u32 = FAMILY_COUNT.into();
    let mut actual_first_family_eval = secure_field_to_words(quotient_eval);
    let mut expected_first_family_eval = secure_field_to_words(expected_quotient_eval);
    let mut family_index = 0;
    while family_index < FAMILY_COUNT {
        let actual_family_eval = eval_keccak_raw_numerator_at_point(
            @air, sampled_oods_values, composition_random_coeff, family_index.into(),
        ) * denominator_inv;
        let expected_family_eval = secure_field_from_words(expected.cumulative_family_evals.span()[family_index]);
        if first_family_mismatch_index == FAMILY_COUNT.into() && actual_family_eval != expected_family_eval {
            first_family_mismatch_index = family_index.into();
            actual_first_family_eval = secure_field_to_words(actual_family_eval);
            expected_first_family_eval = secure_field_to_words(expected_family_eval);
        }
        family_index += 1;
    }

    let forced_composition_oods_eval = extract_composition_oods_eval(
        sampled_oods_values, expected_ood_point, MAX_CONSTRAINT_LOG_DEGREE_BOUND,
    );
    let forced_denominator_inv = CanonicCosetImpl::new(split_log_degree_bound)
        .eval_vanishing(expected_ood_point)
        .inverse();
    let forced_raw_numerator = eval_keccak_raw_numerator_at_point(
        @air, sampled_oods_values, expected_random_coeff, FAMILY_FINAL_DIGEST,
    );
    let forced_quotient_eval = forced_raw_numerator * forced_denominator_inv;

    let mut forced_first_family_mismatch_index: u32 = FAMILY_COUNT.into();
    let mut forced_actual_first_family_eval = secure_field_to_words(forced_quotient_eval);
    let mut forced_expected_first_family_eval = secure_field_to_words(expected_quotient_eval);
    family_index = 0;
    while family_index < FAMILY_COUNT {
        let forced_actual_family_eval = eval_keccak_raw_numerator_at_point(
            @air, sampled_oods_values, expected_random_coeff, family_index.into(),
        ) * forced_denominator_inv;
        let expected_family_eval = secure_field_from_words(expected.cumulative_family_evals.span()[family_index]);
        if forced_first_family_mismatch_index == FAMILY_COUNT.into() && forced_actual_family_eval != expected_family_eval {
            forced_first_family_mismatch_index = family_index.into();
            forced_actual_first_family_eval = secure_field_to_words(forced_actual_family_eval);
            forced_expected_first_family_eval = secure_field_to_words(expected_family_eval);
        }
        family_index += 1;
    }

    OodsComparisonResult {
        fact_high,
        fact_low,
        random_coeff_matches: bool_to_u32(composition_random_coeff == expected_random_coeff),
        ood_point_matches: bool_to_u32(ood_point.x == expected_ood_x && ood_point.y == expected_ood_y),
        composition_oods_eval_matches: bool_to_u32(composition_oods_eval == expected_composition_oods_eval),
        denominator_inv_matches: bool_to_u32(denominator_inv == expected_denominator_inv),
        quotient_eval_matches: bool_to_u32(quotient_eval == expected_quotient_eval),
        first_family_mismatch_index,
        actual_first_family_eval,
        expected_first_family_eval,
        actual_composition_oods_eval: secure_field_to_words(composition_oods_eval),
        expected_composition_oods_eval: secure_field_to_words(expected_composition_oods_eval),
        actual_denominator_inv: secure_field_to_words(denominator_inv),
        expected_denominator_inv: secure_field_to_words(expected_denominator_inv),
        actual_quotient_eval: secure_field_to_words(quotient_eval),
        expected_quotient_eval: secure_field_to_words(expected_quotient_eval),
        forced_transcript_composition_matches: bool_to_u32(forced_composition_oods_eval == expected_composition_oods_eval),
        forced_transcript_denominator_matches: bool_to_u32(forced_denominator_inv == expected_denominator_inv),
        forced_transcript_quotient_matches: bool_to_u32(forced_quotient_eval == expected_quotient_eval),
        forced_first_family_mismatch_index,
        forced_actual_first_family_eval,
        forced_expected_first_family_eval,
    }
}

pub fn verify_proof_input_hash_slice(
    proof: StarkProofMirror, claim: ProofInputHashSliceClaim,
) -> VerificationFactPayload {
    let fact_high = claim.fact_high;
    let fact_low = claim.fact_low;
    let proof = stark_proof_from_mirror(proof);
    let air = make_air(claim);
    let CoreStarkProof { commitment_scheme_proof } = proof;
    let pcs_config = commitment_scheme_proof.config;
    let commitments: @Box<[Hash; 3]> = commitment_scheme_proof.commitments.try_into().unwrap();
    let [preprocessed_commitment, trace_commitment, composition_commitment] = commitments.unbox();
    let log_blowup_factor = pcs_config.fri_config.log_blowup_factor;

    let mut channel: Channel = Default::default();
    let mut commitment_scheme: CommitmentSchemeVerifier = CommitmentSchemeVerifierImpl::new();

    commitment_scheme.commit(
        preprocessed_commitment, [LOG_N_ROWS; 70].span(), ref channel, log_blowup_factor,
    );
    commitment_scheme.commit(
        trace_commitment, [LOG_N_ROWS; 9600].span(), ref channel, log_blowup_factor,
    );

    verify(
        CoreStarkProof { commitment_scheme_proof },
        air,
        MAX_CONSTRAINT_LOG_DEGREE_BOUND,
        composition_commitment,
        commitment_scheme,
        ref channel,
        MIN_SECURITY_BITS,
    );

    VerificationFactPayload { fact_high, fact_low }
}

#[executable]
fn main(proof: StarkProofMirror, claim: ProofInputHashSliceClaim) -> VerificationFactPayload {
    verify_proof_input_hash_slice(proof, claim)
}
