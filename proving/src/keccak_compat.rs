use anyhow::{Context, Result};
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use std::panic::{catch_unwind, AssertUnwindSafe};
use stwo::core::air::Component;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::utils::{
    bit_reverse_index, circle_domain_index_to_coset_index, coset_index_to_circle_domain_index,
};
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::core::verifier::verify;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    AssertEvaluator, EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
    ORIGINAL_TRACE_IDX,
};

use crate::constants::{
    BLOCK_ROWS, DIGEST_BITS, DIGEST_LEN, IDENTITY_ROOT_PREIMAGE_LEN, KECCAK_RHO_OFFSETS,
    KECCAK_ROUNDS, KECCAK_ROUND_CONSTANTS, LANE_BITS, LOG_N_ROWS, NULLIFIER_PREIMAGE_LEN,
    OWNER_COMMITMENT_PREIMAGE_LEN, PROOF_INPUT_HASH_PREIMAGE_LEN, RATE_BITS, RATE_BYTES,
    RATE_LANES, STATE_BITS, STATE_LANES,
};
use crate::types::UnlockFixtureVector;

pub type KeccakCompatComponent = FrameworkComponent<KeccakCompatEval>;
pub type IdentityRootKeccakBytes = [u8; IDENTITY_ROOT_PREIMAGE_LEN + DIGEST_LEN];
pub type OwnerCommitmentKeccakBytes = [u8; OWNER_COMMITMENT_PREIMAGE_LEN + DIGEST_LEN];
pub type NullifierKeccakBytes = [u8; NULLIFIER_PREIMAGE_LEN + DIGEST_LEN];
pub type ProofInputHashKeccakBytes = [u8; PROOF_INPUT_HASH_PREIMAGE_LEN + DIGEST_LEN];

const P01_BITS: usize = 5 * LANE_BITS;
const P23_BITS: usize = 5 * LANE_BITS;
const P0123_BITS: usize = 5 * LANE_BITS;
const C_BITS: usize = 5 * LANE_BITS;
const D_BITS: usize = 5 * LANE_BITS;
const B_BITS: usize = STATE_BITS;
const CHI_BITS: usize = STATE_BITS;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeccakProof {
    pub proof: StarkProof<Blake2sM31MerkleHasher>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeccakConstraintFamily {
    StateBoolean,
    Absorb,
    P01,
    P23,
    P0123,
    C,
    D,
    RhoPi,
    ChiAux,
    StateTransition,
    FinalDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeccakConstraintFailure {
    pub physical_row: usize,
    pub logical_row: usize,
    pub family: KeccakConstraintFamily,
    pub lane: usize,
    pub bit: usize,
    pub actual: u8,
    pub expected: u8,
    pub note: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeccakAssertFailure {
    pub physical_row: usize,
    pub logical_row: usize,
    pub constraint_counter: usize,
    pub family: Option<KeccakConstraintFamily>,
    pub note: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeccakRowLayout {
    Sequential,
    CosetOrdered,
}

const DEFAULT_KECCAK_ROW_LAYOUT: KeccakRowLayout = KeccakRowLayout::CosetOrdered;

#[derive(Clone)]
pub struct KeccakCompatEval {
    pub log_n_rows: u32,
    pub n_blocks: usize,
    pub max_constraint_log_degree_bound: u32,
    pub debug_max_family: Option<KeccakConstraintFamily>,
    pub debug_enable_state_transition_formula: bool,
    pub debug_enable_state_transition_link: bool,
    pub block_bits: Vec<Vec<BaseField>>,
    pub expected_digest_bits: Vec<BaseField>,
}

#[derive(Clone, Copy)]
struct TransitionMask<F> {
    prev: F,
    cur: F,
    next: F,
}

#[derive(Clone)]
struct KeccakTraceColumns {
    state: Vec<Vec<BaseField>>,
    p01: Vec<Vec<BaseField>>,
    p23: Vec<Vec<BaseField>>,
    p0123: Vec<Vec<BaseField>>,
    c: Vec<Vec<BaseField>>,
    d: Vec<Vec<BaseField>>,
    b: Vec<Vec<BaseField>>,
    chi: Vec<Vec<BaseField>>,
    base_state: Vec<Vec<BaseField>>,
    expected_state: Vec<Vec<BaseField>>,
}

#[derive(Clone)]
pub(crate) struct RoundWitness {
    pub(crate) p01: [u64; 5],
    pub(crate) p23: [u64; 5],
    pub(crate) p0123: [u64; 5],
    pub(crate) c: [u64; 5],
    pub(crate) d: [u64; 5],
    pub(crate) b: [u64; STATE_LANES],
    pub(crate) chi: [u64; STATE_LANES],
    pub(crate) base_state: [u64; STATE_LANES],
    pub(crate) next: [u64; STATE_LANES],
}

impl KeccakTraceColumns {
    fn new(log_n_rows: u32) -> Self {
        let n_rows = 1 << log_n_rows;
        let zero_col = || vec![BaseField::zero(); n_rows];

        Self {
            state: (0..STATE_BITS).map(|_| zero_col()).collect(),
            p01: (0..P01_BITS).map(|_| zero_col()).collect(),
            p23: (0..P23_BITS).map(|_| zero_col()).collect(),
            p0123: (0..P0123_BITS).map(|_| zero_col()).collect(),
            c: (0..C_BITS).map(|_| zero_col()).collect(),
            d: (0..D_BITS).map(|_| zero_col()).collect(),
            b: (0..B_BITS).map(|_| zero_col()).collect(),
            chi: (0..CHI_BITS).map(|_| zero_col()).collect(),
            base_state: (0..STATE_BITS).map(|_| zero_col()).collect(),
            expected_state: (0..STATE_BITS).map(|_| zero_col()).collect(),
        }
    }

    fn into_evals(
        self,
        log_n_rows: u32,
    ) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let domain = CanonicCoset::new(log_n_rows).circle_domain();
        flatten_columns(vec![
            self.state,
            self.p01,
            self.p23,
            self.p0123,
            self.c,
            self.d,
            self.b,
            self.chi,
            self.base_state,
            self.expected_state,
        ])
        .into_iter()
        .map(|values| {
            let mut col = Col::<SimdBackend, BaseField>::zeros(1 << log_n_rows);
            for (row, value) in values.into_iter().enumerate() {
                col.set(row, value);
            }
            CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(domain, col)
        })
        .collect()
    }
}

impl FrameworkEval for KeccakCompatEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.max_constraint_log_degree_bound
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let round_active = eval.get_preprocessed_column(round_selector_id());
        let final_selector = eval.get_preprocessed_column(final_selector_id());
        let block_starts = (0..self.n_blocks)
            .map(|index| eval.get_preprocessed_column(block_start_selector_id(index)))
            .collect::<Vec<_>>();
        let rc_bits = (0..LANE_BITS)
            .map(|bit| eval.get_preprocessed_column(round_constant_bit_id(bit)))
            .collect::<Vec<_>>();

        let state = (0..STATE_BITS)
            .map(|_| {
                let [prev, cur, next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [-1, 0, 1]);
                TransitionMask { prev, cur, next }
            })
            .collect::<Vec<_>>();
        let p01 = next_mask_vec(&mut eval, P01_BITS);
        let p23 = next_mask_vec(&mut eval, P23_BITS);
        let p0123 = next_mask_vec(&mut eval, P0123_BITS);
        let c = next_mask_vec(&mut eval, C_BITS);
        let d = next_mask_vec(&mut eval, D_BITS);
        let b = next_mask_vec(&mut eval, B_BITS);
        let chi = next_mask_vec(&mut eval, CHI_BITS);
        let base_state = next_mask_vec(&mut eval, STATE_BITS);
        let expected_state = next_mask_vec(&mut eval, STATE_BITS);

        if self.enables(KeccakConstraintFamily::StateBoolean) {
            for witness in state.iter().map(|mask| mask.cur.clone()) {
                add_boolean_constraint(&mut eval, witness);
            }
        }

        if self.enables(KeccakConstraintFamily::Absorb) {
            for bit in 0..STATE_BITS {
                let mut absorb_sum = E::F::zero();
                for (block_index, block_selector) in block_starts.iter().enumerate() {
                    let expected = if block_index == 0 {
                        start_state_bit::<E>(&self.block_bits[block_index], bit)
                    } else {
                        continuation_state_bit::<E>(
                            state[bit].prev.clone(),
                            &self.block_bits[block_index],
                            bit,
                        )
                    };
                    absorb_sum += block_selector.clone() * (state[bit].cur.clone() - expected);
                }
                eval.add_constraint(absorb_sum);
            }
        }

        for x in 0..5 {
            for z in 0..LANE_BITS {
                let parity_index = lane5_bit_index(x, z);
                let a0 = state[state_bit_index(x, 0, z)].cur.clone();
                let a1 = state[state_bit_index(x, 1, z)].cur.clone();
                let a2 = state[state_bit_index(x, 2, z)].cur.clone();
                let a3 = state[state_bit_index(x, 3, z)].cur.clone();
                let a4 = state[state_bit_index(x, 4, z)].cur.clone();

                if self.enables(KeccakConstraintFamily::P01) {
                    eval.add_constraint(
                        round_active.clone() * (p01[parity_index].clone() - xor_expr(a0, a1)),
                    );
                }
                if self.enables(KeccakConstraintFamily::P23) {
                    eval.add_constraint(
                        round_active.clone() * (p23[parity_index].clone() - xor_expr(a2, a3)),
                    );
                }
                if self.enables(KeccakConstraintFamily::P0123) {
                    eval.add_constraint(
                        round_active.clone()
                            * (p0123[parity_index].clone()
                                - xor_expr(p01[parity_index].clone(), p23[parity_index].clone())),
                    );
                }
                if self.enables(KeccakConstraintFamily::C) {
                    eval.add_constraint(
                        round_active.clone()
                            * (c[parity_index].clone() - xor_expr(p0123[parity_index].clone(), a4)),
                    );
                }

                let left = c[lane5_bit_index((x + 4) % 5, z)].clone();
                let right =
                    c[lane5_bit_index((x + 1) % 5, (z + LANE_BITS - 1) % LANE_BITS)].clone();
                if self.enables(KeccakConstraintFamily::D) {
                    eval.add_constraint(
                        round_active.clone() * (d[parity_index].clone() - xor_expr(left, right)),
                    );
                }
            }
        }

        for target_lane in 0..STATE_LANES {
            let (source_lane, rotation) = inverse_rho_pi(target_lane);
            let source_x = source_lane % 5;
            let source_y = source_lane / 5;
            let target_x = target_lane % 5;
            let target_y = target_lane / 5;

            for z in 0..LANE_BITS {
                let source_bit = state
                    [state_bit_index(source_x, source_y, (z + LANE_BITS - rotation) % LANE_BITS)]
                .cur
                .clone();
                let d_bit =
                    d[lane5_bit_index(source_x, (z + LANE_BITS - rotation) % LANE_BITS)].clone();
                let target_index = state_bit_index(target_x, target_y, z);
                if self.enables(KeccakConstraintFamily::RhoPi) {
                    eval.add_constraint(
                        round_active.clone()
                            * (b[target_index].clone() - xor_expr(source_bit, d_bit)),
                    );
                }
            }
        }

        for x in 0..5 {
            for y in 0..5 {
                for z in 0..LANE_BITS {
                    let index = state_bit_index(x, y, z);
                    let next1 = b[state_bit_index((x + 1) % 5, y, z)].clone();
                    let next2 = b[state_bit_index((x + 2) % 5, y, z)].clone();
                    if self.enables(KeccakConstraintFamily::ChiAux) {
                        eval.add_constraint(
                            round_active.clone()
                                * (chi[index].clone() - (E::F::one() - next1) * next2),
                        );
                    }
                    let chi_value = xor_expr(b[index].clone(), chi[index].clone());
                    if self.enables(KeccakConstraintFamily::StateTransition) {
                        eval.add_constraint(
                            round_active.clone()
                                * (base_state[index].clone() - chi_value)
                                * bf(self.debug_enable_state_transition_formula as u8),
                        );
                        let expected = if x == 0 && y == 0 {
                            xor_expr(base_state[index].clone(), rc_bits[z].clone())
                        } else {
                            base_state[index].clone()
                        };
                        eval.add_constraint(
                            round_active.clone()
                                * (expected_state[index].clone() - expected)
                                * bf(self.debug_enable_state_transition_formula as u8),
                        );
                        eval.add_constraint(
                            round_active.clone()
                                * (state[index].next.clone() - expected_state[index].clone())
                                * bf(self.debug_enable_state_transition_link as u8),
                        );
                    }
                }
            }
        }

        if self.enables(KeccakConstraintFamily::FinalDigest) {
            for bit in 0..DIGEST_BITS {
                eval.add_constraint(
                    final_selector.clone()
                        * (state[bit].cur.clone() - self.expected_digest_bits[bit].into()),
                );
            }
        }

        eval
    }
}

impl KeccakCompatEval {
    fn enables(&self, family: KeccakConstraintFamily) -> bool {
        self.debug_max_family
            .map_or(true, |max_family| family <= max_family)
    }
}

fn flatten_columns(groups: Vec<Vec<Vec<BaseField>>>) -> Vec<Vec<BaseField>> {
    let mut columns = Vec::new();
    for group in groups {
        columns.extend(group);
    }
    columns
}

fn next_mask_vec<E: EvalAtRow>(eval: &mut E, count: usize) -> Vec<E::F> {
    (0..count).map(|_| eval.next_trace_mask()).collect()
}

fn xor_expr<F>(a: F, b: F) -> F
where
    F: Clone
        + One
        + std::ops::Add<F, Output = F>
        + std::ops::Sub<F, Output = F>
        + std::ops::Mul<BaseField, Output = F>
        + std::ops::Mul<F, Output = F>,
{
    a.clone() + b.clone() - (a * b) * BaseField::from(2_u32)
}

fn add_boolean_constraint<E: EvalAtRow>(eval: &mut E, bit: E::F) {
    eval.add_constraint(bit.clone() * (bit - E::F::one()));
}

fn start_state_bit<E: EvalAtRow>(block_bits: &[BaseField], bit: usize) -> E::F {
    if bit < RATE_BITS {
        block_bits[bit].into()
    } else {
        BaseField::zero().into()
    }
}

fn continuation_state_bit<E: EvalAtRow>(prev: E::F, block_bits: &[BaseField], bit: usize) -> E::F {
    if bit < RATE_BITS {
        xor_expr(prev, block_bits[bit].into())
    } else {
        prev
    }
}

fn state_bit_index(x: usize, y: usize, z: usize) -> usize {
    (x + 5 * y) * LANE_BITS + z
}

fn lane5_bit_index(x: usize, z: usize) -> usize {
    x * LANE_BITS + z
}

fn bf(value: u8) -> BaseField {
    BaseField::from(value as u32)
}

fn bits_from_bytes_le(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for bit in 0..8 {
            bits.push((byte >> bit) & 1);
        }
    }
    bits
}

pub(crate) fn field_bits_from_bytes_le(bytes: &[u8]) -> Vec<BaseField> {
    bits_from_bytes_le(bytes).into_iter().map(bf).collect()
}

pub(crate) fn set_lane_bits_row(columns: &mut [Vec<BaseField>], row: usize, lanes: &[u64]) {
    for (lane_index, lane) in lanes.iter().enumerate() {
        for bit in 0..LANE_BITS {
            columns[lane_index * LANE_BITS + bit][row] = bf(((lane >> bit) & 1) as u8);
        }
    }
}

fn logical_row_to_physical_row(row: usize, log_n_rows: u32, layout: KeccakRowLayout) -> usize {
    match layout {
        KeccakRowLayout::Sequential => row,
        KeccakRowLayout::CosetOrdered => bit_reverse_index(
            coset_index_to_circle_domain_index(row, log_n_rows),
            log_n_rows,
        ),
    }
}

fn physical_row_to_logical_row(row: usize, log_n_rows: u32) -> usize {
    circle_domain_index_to_coset_index(bit_reverse_index(row, log_n_rows), log_n_rows)
}

fn trace_neighbor_row(row: usize, offset: isize, log_n_rows: u32) -> usize {
    if offset == 0 {
        return row;
    }

    let domain_size = 1 << log_n_rows;
    let coset_index =
        circle_domain_index_to_coset_index(bit_reverse_index(row, log_n_rows), log_n_rows);
    let next_coset_index =
        (coset_index as isize + offset).rem_euclid(domain_size as isize) as usize;
    bit_reverse_index(
        coset_index_to_circle_domain_index(next_coset_index, log_n_rows),
        log_n_rows,
    )
}

fn write_lane_bits_row(
    columns: &mut [Vec<BaseField>],
    logical_row: usize,
    lanes: &[u64],
    log_n_rows: u32,
    layout: KeccakRowLayout,
) {
    let physical_row = logical_row_to_physical_row(logical_row, log_n_rows, layout);
    set_lane_bits_row(columns, physical_row, lanes);
}

fn inverse_rho_pi(target_lane: usize) -> (usize, usize) {
    for source_lane in 0..STATE_LANES {
        let x = source_lane % 5;
        let y = source_lane / 5;
        let target_x = y;
        let target_y = (2 * x + 3 * y) % 5;
        let mapped_lane = target_x + 5 * target_y;
        if mapped_lane == target_lane {
            return (source_lane, KECCAK_RHO_OFFSETS[source_lane]);
        }
    }
    unreachable!("rho/pi inverse should always resolve a lane")
}

pub fn keccak_pad_rate_blocks(message: &[u8]) -> Vec<[u8; RATE_BYTES]> {
    let mut padded = message.to_vec();
    padded.push(0x01);
    while padded.len() % RATE_BYTES != RATE_BYTES - 1 {
        padded.push(0x00);
    }
    padded.push(0x80);

    padded
        .chunks(RATE_BYTES)
        .map(|chunk| {
            let mut block = [0_u8; RATE_BYTES];
            block.copy_from_slice(chunk);
            block
        })
        .collect()
}

fn absorb_block(state: &mut [u64; STATE_LANES], block: &[u8; RATE_BYTES]) {
    for lane in 0..RATE_LANES {
        let lane_bytes: [u8; 8] = block[(lane * 8)..((lane + 1) * 8)]
            .try_into()
            .expect("rate is lane-aligned");
        state[lane] ^= u64::from_le_bytes(lane_bytes);
    }
}

pub(crate) fn round_witness(current: [u64; STATE_LANES], round: usize) -> RoundWitness {
    let mut p01 = [0_u64; 5];
    let mut p23 = [0_u64; 5];
    let mut p0123 = [0_u64; 5];
    let mut c = [0_u64; 5];
    let mut d = [0_u64; 5];
    let mut b = [0_u64; STATE_LANES];
    let mut chi = [0_u64; STATE_LANES];
    let mut base_state = [0_u64; STATE_LANES];

    for x in 0..5 {
        p01[x] = current[x] ^ current[x + 5];
        p23[x] = current[x + 10] ^ current[x + 15];
        p0123[x] = p01[x] ^ p23[x];
        c[x] = p0123[x] ^ current[x + 20];
    }

    for x in 0..5 {
        d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
    }

    for source_lane in 0..STATE_LANES {
        let x = source_lane % 5;
        let y = source_lane / 5;
        let target_x = y;
        let target_y = (2 * x + 3 * y) % 5;
        let target_lane = target_x + 5 * target_y;
        b[target_lane] =
            (current[source_lane] ^ d[x]).rotate_left(KECCAK_RHO_OFFSETS[source_lane] as u32);
    }

    let mut next = [0_u64; STATE_LANES];
    for y in 0..5 {
        for x in 0..5 {
            let lane = x + 5 * y;
            chi[lane] = (!b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y];
            base_state[lane] = b[lane] ^ chi[lane];
            next[lane] = base_state[lane];
        }
    }
    next[0] ^= KECCAK_ROUND_CONSTANTS[round];

    RoundWitness {
        p01,
        p23,
        p0123,
        c,
        d,
        b,
        chi,
        base_state,
        next,
    }
}

pub fn keccak_digest_from_state(state: &[u64; STATE_LANES]) -> [u8; DIGEST_LEN] {
    let mut bytes = [0_u8; DIGEST_LEN];
    for lane in 0..(DIGEST_LEN / 8) {
        bytes[(lane * 8)..((lane + 1) * 8)].copy_from_slice(&state[lane].to_le_bytes());
    }
    bytes
}

fn build_keccak_trace_columns_with_layout(
    blocks: &[[u8; RATE_BYTES]],
    log_n_rows: u32,
    layout: KeccakRowLayout,
) -> KeccakTraceColumns {
    let mut columns = KeccakTraceColumns::new(log_n_rows);
    let mut state = [0_u64; STATE_LANES];

    for (block_index, block) in blocks.iter().enumerate() {
        let base_row = block_index * BLOCK_ROWS;
        absorb_block(&mut state, block);
        write_lane_bits_row(&mut columns.state, base_row, &state, log_n_rows, layout);

        for round in 0..KECCAK_ROUNDS {
            let witness = round_witness(state, round);
            write_lane_bits_row(
                &mut columns.p01,
                base_row + round,
                &witness.p01,
                log_n_rows,
                layout,
            );
            write_lane_bits_row(
                &mut columns.p23,
                base_row + round,
                &witness.p23,
                log_n_rows,
                layout,
            );
            write_lane_bits_row(
                &mut columns.p0123,
                base_row + round,
                &witness.p0123,
                log_n_rows,
                layout,
            );
            write_lane_bits_row(
                &mut columns.c,
                base_row + round,
                &witness.c,
                log_n_rows,
                layout,
            );
            write_lane_bits_row(
                &mut columns.d,
                base_row + round,
                &witness.d,
                log_n_rows,
                layout,
            );
            write_lane_bits_row(
                &mut columns.b,
                base_row + round,
                &witness.b,
                log_n_rows,
                layout,
            );
            write_lane_bits_row(
                &mut columns.chi,
                base_row + round,
                &witness.chi,
                log_n_rows,
                layout,
            );
            write_lane_bits_row(
                &mut columns.base_state,
                base_row + round,
                &witness.base_state,
                log_n_rows,
                layout,
            );
            let mut expected_next = witness.base_state;
            expected_next[0] ^= KECCAK_ROUND_CONSTANTS[round];
            write_lane_bits_row(
                &mut columns.expected_state,
                base_row + round,
                &expected_next,
                log_n_rows,
                layout,
            );
            state = witness.next;
            write_lane_bits_row(
                &mut columns.state,
                base_row + round + 1,
                &state,
                log_n_rows,
                layout,
            );
        }
    }

    columns
}

fn build_keccak_trace_columns(blocks: &[[u8; RATE_BYTES]], log_n_rows: u32) -> KeccakTraceColumns {
    build_keccak_trace_columns_with_layout(blocks, log_n_rows, DEFAULT_KECCAK_ROW_LAYOUT)
}

fn build_keccak_eval(
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
) -> Result<(KeccakCompatEval, Vec<[u8; RATE_BYTES]>, u32)> {
    build_keccak_eval_with_degree_bound(preimage, expected_digest, LOG_N_ROWS + 1)
}

fn build_keccak_eval_with_degree_bound(
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
    max_constraint_log_degree_bound: u32,
) -> Result<(KeccakCompatEval, Vec<[u8; RATE_BYTES]>, u32)> {
    let blocks = keccak_pad_rate_blocks(preimage);
    let block_bits = blocks
        .iter()
        .map(|block| field_bits_from_bytes_le(block))
        .collect::<Vec<_>>();
    let expected_digest_bits = field_bits_from_bytes_le(expected_digest);

    anyhow::ensure!(
        !blocks.is_empty(),
        "keccak preimage must contain at least one block"
    );
    let used_rows = blocks.len() * BLOCK_ROWS;
    anyhow::ensure!(
        used_rows <= (1 << LOG_N_ROWS),
        "keccak trace requires {used_rows} rows but only {} are available",
        1 << LOG_N_ROWS
    );
    let log_n_rows = LOG_N_ROWS;

    Ok((
        KeccakCompatEval {
            log_n_rows,
            n_blocks: blocks.len(),
            max_constraint_log_degree_bound,
            debug_max_family: None,
            debug_enable_state_transition_formula: true,
            debug_enable_state_transition_link: true,
            block_bits,
            expected_digest_bits,
        },
        blocks,
        log_n_rows,
    ))
}

fn build_keccak_component(
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
) -> Result<(KeccakCompatComponent, Vec<[u8; RATE_BYTES]>, u32)> {
    build_keccak_component_with_degree_bound(preimage, expected_digest, LOG_N_ROWS + 1)
}

fn build_keccak_component_with_degree_bound(
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
    max_constraint_log_degree_bound: u32,
) -> Result<(KeccakCompatComponent, Vec<[u8; RATE_BYTES]>, u32)> {
    build_keccak_component_with_parameters(
        preimage,
        expected_digest,
        max_constraint_log_degree_bound,
        None,
        true,
        true,
    )
}

fn build_keccak_component_with_parameters(
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
    max_constraint_log_degree_bound: u32,
    debug_max_family: Option<KeccakConstraintFamily>,
    debug_enable_state_transition_formula: bool,
    debug_enable_state_transition_link: bool,
) -> Result<(KeccakCompatComponent, Vec<[u8; RATE_BYTES]>, u32)> {
    let (eval, blocks, log_n_rows) = build_keccak_eval_with_degree_bound(
        preimage,
        expected_digest,
        max_constraint_log_degree_bound,
    )?;
    let eval = KeccakCompatEval {
        debug_max_family,
        debug_enable_state_transition_formula,
        debug_enable_state_transition_link,
        ..eval
    };
    let component = KeccakCompatComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(
            &keccak_preprocessed_column_ids(blocks.len()),
        ),
        eval,
        SecureField::zero(),
    );

    Ok((component, blocks, log_n_rows))
}

pub fn build_keccak_trace(
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
) -> Result<Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>> {
    let (_, blocks, log_n_rows) = build_keccak_component(preimage, expected_digest)?;
    let columns = build_keccak_trace_columns(&blocks, log_n_rows);
    Ok(columns.into_evals(log_n_rows))
}

pub fn keccak_preprocessed_column_ids(n_blocks: usize) -> Vec<PreProcessedColumnId> {
    let mut ids = vec![round_selector_id(), final_selector_id()];
    ids.extend((0..n_blocks).map(block_start_selector_id));
    ids.extend((0..LANE_BITS).map(round_constant_bit_id));
    ids
}

fn build_keccak_preprocessed_columns(
    n_blocks: usize,
    log_n_rows: u32,
    layout: KeccakRowLayout,
) -> Vec<Vec<BaseField>> {
    let n_rows = 1 << log_n_rows;
    let used_rows = n_blocks * BLOCK_ROWS;
    let final_row = used_rows.saturating_sub(1);

    let mut columns = Vec::new();

    let mut round_selector = vec![BaseField::zero(); n_rows];
    let mut final_selector = vec![BaseField::zero(); n_rows];
    for row in 0..used_rows {
        if row % BLOCK_ROWS != BLOCK_ROWS - 1 {
            round_selector[logical_row_to_physical_row(row, log_n_rows, layout)] = BaseField::one();
        }
    }
    final_selector[logical_row_to_physical_row(final_row, log_n_rows, layout)] = BaseField::one();
    columns.push(round_selector);
    columns.push(final_selector);

    for block in 0..n_blocks {
        let mut selector = vec![BaseField::zero(); n_rows];
        selector[logical_row_to_physical_row(block * BLOCK_ROWS, log_n_rows, layout)] =
            BaseField::one();
        columns.push(selector);
    }

    for bit in 0..LANE_BITS {
        let mut rc_column = vec![BaseField::zero(); n_rows];
        for row in 0..used_rows {
            let round = row % BLOCK_ROWS;
            if round < KECCAK_ROUNDS {
                rc_column[logical_row_to_physical_row(row, log_n_rows, layout)] =
                    bf(((KECCAK_ROUND_CONSTANTS[round] >> bit) & 1) as u8);
            }
        }
        columns.push(rc_column);
    }

    columns
}

pub fn generate_keccak_preprocessed_trace(
    n_blocks: usize,
    log_n_rows: u32,
) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let n_rows = 1 << log_n_rows;
    let domain = CanonicCoset::new(log_n_rows).circle_domain();
    build_keccak_preprocessed_columns(n_blocks, log_n_rows, DEFAULT_KECCAK_ROW_LAYOUT)
        .into_iter()
        .map(|values| {
            let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);
            for (row, value) in values.into_iter().enumerate() {
                col.set(row, value);
            }
            CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(domain, col)
        })
        .collect()
}

fn round_selector_id() -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: "keccak_round_active".to_string(),
    }
}

fn final_selector_id() -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: "keccak_final_row".to_string(),
    }
}

fn block_start_selector_id(index: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("keccak_block_start_{index}"),
    }
}

fn round_constant_bit_id(bit: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("keccak_round_constant_bit_{bit}"),
    }
}

fn field_to_bit(value: BaseField) -> u8 {
    if value == BaseField::zero() {
        0
    } else if value == BaseField::one() {
        1
    } else {
        2
    }
}

fn column_bit(column: &[BaseField], row: usize) -> BaseField {
    column[row]
}

fn make_failure(
    physical_row: usize,
    log_n_rows: u32,
    family: KeccakConstraintFamily,
    lane: usize,
    bit: usize,
    actual: BaseField,
    expected: BaseField,
    note: impl Into<String>,
) -> KeccakConstraintFailure {
    KeccakConstraintFailure {
        physical_row,
        logical_row: physical_row_to_logical_row(physical_row, log_n_rows),
        family,
        lane,
        bit,
        actual: field_to_bit(actual),
        expected: field_to_bit(expected),
        note: note.into(),
    }
}

fn constraint_family_from_counter(counter: usize) -> Option<KeccakConstraintFamily> {
    let mut start = 0usize;
    let ranges = [
        (STATE_BITS, KeccakConstraintFamily::StateBoolean),
        (STATE_BITS, KeccakConstraintFamily::Absorb),
        (5 * LANE_BITS, KeccakConstraintFamily::P01),
        (5 * LANE_BITS, KeccakConstraintFamily::P23),
        (5 * LANE_BITS, KeccakConstraintFamily::P0123),
        (5 * LANE_BITS, KeccakConstraintFamily::C),
        (5 * LANE_BITS, KeccakConstraintFamily::D),
        (STATE_BITS, KeccakConstraintFamily::RhoPi),
        (STATE_BITS, KeccakConstraintFamily::ChiAux),
        (3 * STATE_BITS, KeccakConstraintFamily::StateTransition),
        (DIGEST_BITS, KeccakConstraintFamily::FinalDigest),
    ];
    for (width, family) in ranges {
        let end = start + width;
        if (start..end).contains(&counter) {
            return Some(family);
        }
        start = end;
    }
    None
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(message) => (*message).to_string(),
            Err(_) => "non-string panic payload".to_string(),
        },
    }
}

fn parse_constraint_counter_from_panic(message: &str) -> Option<usize> {
    let marker = "constraint #";
    let start = message.find(marker)? + marker.len();
    let digits = message[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits.parse().ok()
}

fn debug_first_keccak_failure_for_layout(
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
    layout: KeccakRowLayout,
) -> Result<Option<KeccakConstraintFailure>> {
    let (eval, blocks, log_n_rows) = build_keccak_eval(preimage, expected_digest)?;
    let trace = build_keccak_trace_columns_with_layout(&blocks, log_n_rows, layout);
    let preprocessed = build_keccak_preprocessed_columns(blocks.len(), log_n_rows, layout);
    let round_selector = &preprocessed[0];
    let final_selector = &preprocessed[1];
    let block_start_offset = 2;
    let rc_offset = block_start_offset + blocks.len();
    let n_rows = 1 << log_n_rows;

    for row in 0..n_rows {
        for bit in 0..STATE_BITS {
            let cur = column_bit(&trace.state[bit], row);
            let cur_bit = field_to_bit(cur);
            if cur_bit > 1 {
                return Ok(Some(make_failure(
                    row,
                    log_n_rows,
                    KeccakConstraintFamily::StateBoolean,
                    bit / LANE_BITS,
                    bit % LANE_BITS,
                    cur,
                    BaseField::zero(),
                    format!("state bit is not boolean under {:?} layout", layout),
                )));
            }
        }

        for block_index in 0..blocks.len() {
            if column_bit(&preprocessed[block_start_offset + block_index], row) == BaseField::one()
            {
                for bit in 0..STATE_BITS {
                    let actual = column_bit(&trace.state[bit], row);
                    let expected = if block_index == 0 {
                        if bit < RATE_BITS {
                            eval.block_bits[block_index][bit]
                        } else {
                            BaseField::zero()
                        }
                    } else {
                        let prev_row = trace_neighbor_row(row, -1, log_n_rows);
                        let prev = column_bit(&trace.state[bit], prev_row);
                        if bit < RATE_BITS {
                            xor_expr::<BaseField>(prev, eval.block_bits[block_index][bit])
                        } else {
                            prev
                        }
                    };
                    if actual != expected {
                        return Ok(Some(make_failure(
                            row,
                            log_n_rows,
                            KeccakConstraintFamily::Absorb,
                            bit / LANE_BITS,
                            bit % LANE_BITS,
                            actual,
                            expected,
                            format!("absorb/start-state mismatch for block {block_index} under {:?} layout", layout),
                        )));
                    }
                }
            }
        }

        if column_bit(round_selector, row) != BaseField::one() {
            if column_bit(final_selector, row) == BaseField::one() {
                for bit in 0..DIGEST_BITS {
                    let actual = column_bit(&trace.state[bit], row);
                    let expected = eval.expected_digest_bits[bit];
                    if actual != expected {
                        return Ok(Some(make_failure(
                            row,
                            log_n_rows,
                            KeccakConstraintFamily::FinalDigest,
                            bit / LANE_BITS,
                            bit % LANE_BITS,
                            actual,
                            expected,
                            format!("final digest mismatch under {:?} layout", layout),
                        )));
                    }
                }
            }
            continue;
        }

        for x in 0..5 {
            for z in 0..LANE_BITS {
                let parity_index = lane5_bit_index(x, z);
                let a0 = column_bit(&trace.state[state_bit_index(x, 0, z)], row);
                let a1 = column_bit(&trace.state[state_bit_index(x, 1, z)], row);
                let a2 = column_bit(&trace.state[state_bit_index(x, 2, z)], row);
                let a3 = column_bit(&trace.state[state_bit_index(x, 3, z)], row);
                let a4 = column_bit(&trace.state[state_bit_index(x, 4, z)], row);

                let expected_p01 = xor_expr::<BaseField>(a0, a1);
                let actual_p01 = column_bit(&trace.p01[parity_index], row);
                if actual_p01 != expected_p01 {
                    return Ok(Some(make_failure(
                        row,
                        log_n_rows,
                        KeccakConstraintFamily::P01,
                        x,
                        z,
                        actual_p01,
                        expected_p01,
                        format!("p01 parity mismatch under {:?} layout", layout),
                    )));
                }

                let expected_p23 = xor_expr::<BaseField>(a2, a3);
                let actual_p23 = column_bit(&trace.p23[parity_index], row);
                if actual_p23 != expected_p23 {
                    return Ok(Some(make_failure(
                        row,
                        log_n_rows,
                        KeccakConstraintFamily::P23,
                        x,
                        z,
                        actual_p23,
                        expected_p23,
                        format!("p23 parity mismatch under {:?} layout", layout),
                    )));
                }

                let expected_p0123 = xor_expr::<BaseField>(actual_p01, actual_p23);
                let actual_p0123 = column_bit(&trace.p0123[parity_index], row);
                if actual_p0123 != expected_p0123 {
                    return Ok(Some(make_failure(
                        row,
                        log_n_rows,
                        KeccakConstraintFamily::P0123,
                        x,
                        z,
                        actual_p0123,
                        expected_p0123,
                        format!("p0123 parity mismatch under {:?} layout", layout),
                    )));
                }

                let expected_c = xor_expr::<BaseField>(actual_p0123, a4);
                let actual_c = column_bit(&trace.c[parity_index], row);
                if actual_c != expected_c {
                    return Ok(Some(make_failure(
                        row,
                        log_n_rows,
                        KeccakConstraintFamily::C,
                        x,
                        z,
                        actual_c,
                        expected_c,
                        format!("c parity mismatch under {:?} layout", layout),
                    )));
                }

                let left = column_bit(&trace.c[lane5_bit_index((x + 4) % 5, z)], row);
                let right = column_bit(
                    &trace.c[lane5_bit_index((x + 1) % 5, (z + LANE_BITS - 1) % LANE_BITS)],
                    row,
                );
                let expected_d = xor_expr::<BaseField>(left, right);
                let actual_d = column_bit(&trace.d[parity_index], row);
                if actual_d != expected_d {
                    return Ok(Some(make_failure(
                        row,
                        log_n_rows,
                        KeccakConstraintFamily::D,
                        x,
                        z,
                        actual_d,
                        expected_d,
                        format!("d parity mismatch under {:?} layout", layout),
                    )));
                }
            }
        }

        for target_lane in 0..STATE_LANES {
            let (source_lane, rotation) = inverse_rho_pi(target_lane);
            let source_x = source_lane % 5;
            let source_y = source_lane / 5;
            let target_x = target_lane % 5;
            let target_y = target_lane / 5;

            for z in 0..LANE_BITS {
                let source_bit = column_bit(
                    &trace.state[state_bit_index(
                        source_x,
                        source_y,
                        (z + LANE_BITS - rotation) % LANE_BITS,
                    )],
                    row,
                );
                let d_bit = column_bit(
                    &trace.d[lane5_bit_index(source_x, (z + LANE_BITS - rotation) % LANE_BITS)],
                    row,
                );
                let expected = xor_expr::<BaseField>(source_bit, d_bit);
                let actual = column_bit(&trace.b[state_bit_index(target_x, target_y, z)], row);
                if actual != expected {
                    return Ok(Some(make_failure(
                        row,
                        log_n_rows,
                        KeccakConstraintFamily::RhoPi,
                        target_lane,
                        z,
                        actual,
                        expected,
                        format!("rho/pi mismatch under {:?} layout", layout),
                    )));
                }
            }
        }

        let next_row = trace_neighbor_row(row, 1, log_n_rows);
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..LANE_BITS {
                    let lane = x + 5 * y;
                    let index = state_bit_index(x, y, z);
                    let next1 = column_bit(&trace.b[state_bit_index((x + 1) % 5, y, z)], row);
                    let next2 = column_bit(&trace.b[state_bit_index((x + 2) % 5, y, z)], row);
                    let expected_chi = (BaseField::one() - next1) * next2;
                    let actual_chi = column_bit(&trace.chi[index], row);
                    if actual_chi != expected_chi {
                        return Ok(Some(make_failure(
                            row,
                            log_n_rows,
                            KeccakConstraintFamily::ChiAux,
                            lane,
                            z,
                            actual_chi,
                            expected_chi,
                            format!(
                                "quadraticized chi helper mismatch under {:?} layout",
                                layout
                            ),
                        )));
                    }

                    let chi_value =
                        xor_expr::<BaseField>(column_bit(&trace.b[index], row), actual_chi);
                    let actual_base = column_bit(&trace.base_state[index], row);
                    if actual_base != chi_value {
                        return Ok(Some(make_failure(
                            row,
                            log_n_rows,
                            KeccakConstraintFamily::StateTransition,
                            lane,
                            z,
                            actual_base,
                            chi_value,
                            format!("base-state mismatch under {:?} layout", layout),
                        )));
                    }

                    let expected_next = if x == 0 && y == 0 {
                        xor_expr::<BaseField>(
                            actual_base,
                            column_bit(&preprocessed[rc_offset + z], row),
                        )
                    } else {
                        actual_base
                    };
                    let actual_expected = column_bit(&trace.expected_state[index], row);
                    if actual_expected != expected_next {
                        return Ok(Some(make_failure(
                            row,
                            log_n_rows,
                            KeccakConstraintFamily::StateTransition,
                            lane,
                            z,
                            actual_expected,
                            expected_next,
                            format!("expected-state mismatch under {:?} layout", layout),
                        )));
                    };
                    let actual_next = column_bit(&trace.state[index], next_row);
                    if actual_next != expected_next {
                        return Ok(Some(make_failure(
                            row,
                            log_n_rows,
                            KeccakConstraintFamily::StateTransition,
                            lane,
                            z,
                            actual_next,
                            expected_next,
                            format!(
                                "next-state mismatch under {:?} layout (next physical row {})",
                                layout, next_row
                            ),
                        )));
                    }
                }
            }
        }
    }

    Ok(None)
}

pub fn debug_first_keccak_failure(
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
) -> Result<Option<KeccakConstraintFailure>> {
    debug_first_keccak_failure_for_layout(preimage, expected_digest, KeccakRowLayout::Sequential)
}

pub fn debug_first_keccak_failure_with_coset_layout(
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
) -> Result<Option<KeccakConstraintFailure>> {
    debug_first_keccak_failure_for_layout(preimage, expected_digest, KeccakRowLayout::CosetOrdered)
}

pub fn debug_first_keccak_assert_failure(
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
) -> Result<Option<KeccakAssertFailure>> {
    let (eval, blocks, log_n_rows) = build_keccak_eval(preimage, expected_digest)?;
    let trace_columns = build_keccak_trace_columns(&blocks, log_n_rows);
    let trace_columns = flatten_columns(vec![
        trace_columns.state,
        trace_columns.p01,
        trace_columns.p23,
        trace_columns.p0123,
        trace_columns.c,
        trace_columns.d,
        trace_columns.b,
        trace_columns.chi,
        trace_columns.base_state,
        trace_columns.expected_state,
    ]);
    let preprocessed =
        build_keccak_preprocessed_columns(blocks.len(), log_n_rows, DEFAULT_KECCAK_ROW_LAYOUT);
    let trace_refs = trace_columns.iter().collect::<Vec<_>>();
    let preprocessed_refs = preprocessed.iter().collect::<Vec<_>>();
    let trace = TreeVec::new(vec![preprocessed_refs, trace_refs]);

    for row in 0..(1 << log_n_rows) {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let assert_eval = AssertEvaluator::new(&trace, row, log_n_rows, SecureField::zero());
            eval.clone().evaluate(assert_eval);
        }));
        if let Err(payload) = result {
            let note = panic_message(payload);
            let constraint_counter =
                parse_constraint_counter_from_panic(&note).unwrap_or(usize::MAX);
            return Ok(Some(KeccakAssertFailure {
                physical_row: row,
                logical_row: physical_row_to_logical_row(row, log_n_rows),
                constraint_counter,
                family: constraint_family_from_counter(constraint_counter),
                note,
            }));
        }
    }

    Ok(None)
}

fn prove_component(
    component: &KeccakCompatComponent,
    preprocessed_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
) -> Result<KeccakProof> {
    prove_component_with_config(component, preprocessed_trace, trace, PcsConfig::default())
}

fn prove_component_with_config(
    component: &KeccakCompatComponent,
    preprocessed_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    config: PcsConfig,
) -> Result<KeccakProof> {
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(
            component.max_constraint_log_degree_bound() + config.fri_config.log_blowup_factor,
        )
        .circle_domain()
        .half_coset,
    );

    let prover_channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(preprocessed_trace);
    tree_builder.commit(prover_channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(prover_channel);

    let proof = prove::<SimdBackend, Blake2sM31MerkleChannel>(
        &[component],
        prover_channel,
        commitment_scheme,
    )
    .context("failed to prove keccak component")?;

    Ok(KeccakProof { proof })
}

fn verify_component(component: &KeccakCompatComponent, proof: &KeccakProof) -> Result<()> {
    let config = PcsConfig::default();
    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();

    commitment_scheme.commit(proof.proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.proof.commitments[1], &sizes[1], verifier_channel);
    verify(
        &[component as &dyn Component],
        verifier_channel,
        commitment_scheme,
        proof.proof.clone(),
    )
    .context("failed to verify keccak component")
}

pub fn prove_keccak_preimage(
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
) -> Result<KeccakProof> {
    let (component, blocks, log_n_rows) = build_keccak_component(preimage, expected_digest)?;
    let preprocessed_trace = generate_keccak_preprocessed_trace(blocks.len(), log_n_rows);
    let trace = build_keccak_trace_columns(&blocks, log_n_rows).into_evals(log_n_rows);
    prove_component(&component, preprocessed_trace, trace)
}

pub fn debug_prove_keccak_preimage_with_degree_bound(
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
    max_constraint_log_degree_bound: u32,
) -> Result<KeccakProof> {
    debug_prove_keccak_preimage_with_parameters(
        preimage,
        expected_digest,
        max_constraint_log_degree_bound,
        None,
    )
}

pub fn debug_prove_keccak_preimage_with_parameters(
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
    max_constraint_log_degree_bound: u32,
    lifting_log_size: Option<u32>,
) -> Result<KeccakProof> {
    let (component, blocks, log_n_rows) = build_keccak_component_with_parameters(
        preimage,
        expected_digest,
        max_constraint_log_degree_bound,
        None,
        true,
        true,
    )?;
    let preprocessed_trace = generate_keccak_preprocessed_trace(blocks.len(), log_n_rows);
    let trace = build_keccak_trace_columns(&blocks, log_n_rows).into_evals(log_n_rows);
    let mut config = PcsConfig::default();
    config.lifting_log_size = lifting_log_size;
    prove_component_with_config(&component, preprocessed_trace, trace, config)
}

pub fn debug_verify_keccak_preimage_with_degree_bound(
    proof: &KeccakProof,
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
    max_constraint_log_degree_bound: u32,
) -> Result<()> {
    let (component, _, _) = build_keccak_component_with_parameters(
        preimage,
        expected_digest,
        max_constraint_log_degree_bound,
        None,
        true,
        true,
    )?;
    verify_component(&component, proof)
}

pub fn debug_prove_keccak_preimage_through_family(
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
    max_constraint_log_degree_bound: u32,
    max_family: KeccakConstraintFamily,
) -> Result<KeccakProof> {
    let (component, blocks, log_n_rows) = build_keccak_component_with_parameters(
        preimage,
        expected_digest,
        max_constraint_log_degree_bound,
        Some(max_family),
        true,
        true,
    )?;
    let preprocessed_trace = generate_keccak_preprocessed_trace(blocks.len(), log_n_rows);
    let trace = build_keccak_trace_columns(&blocks, log_n_rows).into_evals(log_n_rows);
    prove_component(&component, preprocessed_trace, trace)
}

pub fn debug_prove_keccak_with_state_transition_parts(
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
    max_constraint_log_degree_bound: u32,
    debug_enable_state_transition_formula: bool,
    debug_enable_state_transition_link: bool,
) -> Result<KeccakProof> {
    let (component, blocks, log_n_rows) = build_keccak_component_with_parameters(
        preimage,
        expected_digest,
        max_constraint_log_degree_bound,
        None,
        debug_enable_state_transition_formula,
        debug_enable_state_transition_link,
    )?;
    let preprocessed_trace = generate_keccak_preprocessed_trace(blocks.len(), log_n_rows);
    let trace = build_keccak_trace_columns(&blocks, log_n_rows).into_evals(log_n_rows);
    prove_component(&component, preprocessed_trace, trace)
}

pub fn verify_keccak_preimage(
    proof: &KeccakProof,
    preimage: &[u8],
    expected_digest: &[u8; DIGEST_LEN],
) -> Result<()> {
    let (component, _, _) = build_keccak_component(preimage, expected_digest)?;
    verify_component(&component, proof)
}

fn concat<const PREIMAGE_LEN: usize, const TOTAL: usize>(
    preimage: &[u8; PREIMAGE_LEN],
    digest: &[u8; DIGEST_LEN],
) -> [u8; TOTAL] {
    let mut bytes = [0_u8; TOTAL];
    bytes[..PREIMAGE_LEN].copy_from_slice(preimage);
    bytes[PREIMAGE_LEN..PREIMAGE_LEN + DIGEST_LEN].copy_from_slice(digest);
    bytes
}

pub fn identity_root_bytes(vector: &UnlockFixtureVector) -> IdentityRootKeccakBytes {
    concat(&vector.identity_root_preimage, &vector.identity_root_hash)
}

pub fn owner_commitment_bytes(vector: &UnlockFixtureVector) -> OwnerCommitmentKeccakBytes {
    concat(
        &vector.owner_commitment_preimage,
        &vector.owner_commitment_hash,
    )
}

pub fn nullifier_bytes(vector: &UnlockFixtureVector) -> NullifierKeccakBytes {
    concat(&vector.nullifier_preimage, &vector.nullifier_hash)
}

pub fn proof_input_hash_bytes(vector: &UnlockFixtureVector) -> ProofInputHashKeccakBytes {
    concat(
        &vector.proof_input_hash_preimage,
        &vector.proof_input_hash_value,
    )
}

pub fn prove_identity_root(vector: &UnlockFixtureVector) -> Result<KeccakProof> {
    prove_keccak_preimage(&vector.identity_root_preimage, &vector.identity_root_hash)
}

pub fn verify_identity_root(proof: &KeccakProof, vector: &UnlockFixtureVector) -> Result<()> {
    verify_keccak_preimage(
        proof,
        &vector.identity_root_preimage,
        &vector.identity_root_hash,
    )
}

pub fn prove_owner_commitment(vector: &UnlockFixtureVector) -> Result<KeccakProof> {
    prove_keccak_preimage(
        &vector.owner_commitment_preimage,
        &vector.owner_commitment_hash,
    )
}

pub fn verify_owner_commitment(proof: &KeccakProof, vector: &UnlockFixtureVector) -> Result<()> {
    verify_keccak_preimage(
        proof,
        &vector.owner_commitment_preimage,
        &vector.owner_commitment_hash,
    )
}

pub fn prove_nullifier(vector: &UnlockFixtureVector) -> Result<KeccakProof> {
    prove_keccak_preimage(&vector.nullifier_preimage, &vector.nullifier_hash)
}

pub fn verify_nullifier(proof: &KeccakProof, vector: &UnlockFixtureVector) -> Result<()> {
    verify_keccak_preimage(proof, &vector.nullifier_preimage, &vector.nullifier_hash)
}

pub fn prove_proof_input_hash(vector: &UnlockFixtureVector) -> Result<KeccakProof> {
    prove_keccak_preimage(
        &vector.proof_input_hash_preimage,
        &vector.proof_input_hash_value,
    )
}

pub fn verify_proof_input_hash(proof: &KeccakProof, vector: &UnlockFixtureVector) -> Result<()> {
    verify_keccak_preimage(
        proof,
        &vector.proof_input_hash_preimage,
        &vector.proof_input_hash_value,
    )
}

pub fn verify_tampered_failure(proof: &KeccakProof, original: &UnlockFixtureVector) -> Result<()> {
    let mut digest = original.proof_input_hash_value;
    digest[DIGEST_LEN - 1] ^= 0x01;
    verify_keccak_preimage(proof, &original.proof_input_hash_preimage, &digest)
}
