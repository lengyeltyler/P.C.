use anyhow::{bail, Context, Result};
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use stwo::core::air::Component;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::core::verifier::verify;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator, ORIGINAL_TRACE_IDX,
};

use crate::abi::{
    derive_proof_input_hash, encode_identity_root_preimage, encode_nullifier_preimage,
    encode_owner_commitment_preimage, encode_proof_input_hash_preimage,
};
use crate::constants::{
    BLOCK_ROWS, DIGEST_BITS, KECCAK_ROUNDS, KECCAK_ROUND_CONSTANTS, LANE_BITS, LOG_N_ROWS,
    NULLIFIER_BLOCK0_START_ROW, NULLIFIER_BLOCK1_START_ROW, NULLIFIER_FINAL_ROW, OWNER_FINAL_ROW,
    OWNER_START_ROW, PROOF_INPUT_BLOCK0_START_ROW, PROOF_INPUT_BLOCK1_START_ROW,
    PROOF_INPUT_BLOCK2_START_ROW, PROOF_INPUT_BLOCK3_START_ROW, PROOF_INPUT_FINAL_ROW, RATE_BITS,
    STATE_BITS, STWO_UNLOCK_PROOF_TYPE, STWO_UNLOCK_PROOF_VERSION,
};
use crate::keccak_compat::{
    field_bits_from_bytes_le, keccak_digest_from_state, keccak_pad_rate_blocks, round_witness,
    set_lane_bits_row, RoundWitness,
};
use crate::types::{GenerateProofInput, UnlockPublicInputs};

const TOTAL_BLOCKS: usize = 8;
const PHIL_SECRET_BITS: usize = 256;
const NULLIFIER_SEED_BITS: usize = 256;
const P01_BITS: usize = 5 * LANE_BITS;
const P23_BITS: usize = 5 * LANE_BITS;
const P0123_BITS: usize = 5 * LANE_BITS;
const C_BITS: usize = 5 * LANE_BITS;
const D_BITS: usize = 5 * LANE_BITS;
const B_BITS: usize = STATE_BITS;
const CHI_BITS: usize = STATE_BITS;

pub type UnlockStatementComponent = FrameworkComponent<UnlockStatementEval>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnlockStatementProof {
    pub proof: StarkProof<Blake2sM31MerkleHasher>,
}

#[derive(Clone)]
pub struct UnlockStatementEval {
    pub scope: UnlockStatementScope,
    pub log_n_rows: u32,
    pub identity_block_const_bits: Vec<BaseField>,
    pub owner_block_const_bits: Vec<BaseField>,
    pub nullifier_block0_const_bits: Vec<BaseField>,
    pub nullifier_block1_const_bits: Vec<BaseField>,
    pub proof_input_block_bits: Vec<Vec<BaseField>>,
    pub public_owner_bits: Vec<BaseField>,
    pub public_nullifier_bits: Vec<BaseField>,
    pub public_proof_input_bits: Vec<BaseField>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockStatementScope {
    OwnerPathOnly,
    Full,
}

#[derive(Clone, Copy)]
struct TransitionMask<F> {
    prev: F,
    cur: F,
    next: F,
}

#[derive(Clone)]
struct UnlockTraceColumns {
    phil_secret: Vec<Vec<BaseField>>,
    nullifier_seed: Vec<Vec<BaseField>>,
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

impl UnlockTraceColumns {
    fn new(log_n_rows: u32) -> Self {
        let n_rows = 1 << log_n_rows;
        let zero_col = || vec![BaseField::zero(); n_rows];

        Self {
            phil_secret: (0..PHIL_SECRET_BITS).map(|_| zero_col()).collect(),
            nullifier_seed: (0..NULLIFIER_SEED_BITS).map(|_| zero_col()).collect(),
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
            self.phil_secret,
            self.nullifier_seed,
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

impl FrameworkEval for UnlockStatementEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let round_active = eval.get_preprocessed_column(unlock_round_selector_id());
        let block_starts = (0..TOTAL_BLOCKS)
            .map(|index| eval.get_preprocessed_column(unlock_block_start_selector_id(index)))
            .collect::<Vec<_>>();
        let owner_final = eval.get_preprocessed_column(owner_final_selector_id());
        let nullifier_final = eval.get_preprocessed_column(nullifier_final_selector_id());
        let proof_input_final = eval.get_preprocessed_column(proof_input_final_selector_id());
        let rc_bits = (0..LANE_BITS)
            .map(|bit| eval.get_preprocessed_column(unlock_round_constant_bit_id(bit)))
            .collect::<Vec<_>>();

        let phil_secret = next_mask_vec(&mut eval, PHIL_SECRET_BITS);
        let nullifier_seed = next_mask_vec(&mut eval, NULLIFIER_SEED_BITS);
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

        for bit in phil_secret
            .iter()
            .cloned()
            .chain(nullifier_seed.iter().cloned())
        {
            add_boolean_constraint(&mut eval, bit);
        }
        for witness in state.iter().map(|mask| mask.cur.clone()) {
            add_boolean_constraint(&mut eval, witness);
        }

        for bit in 0..STATE_BITS {
            let absorb = block_starts[0].clone()
                * (state[bit].cur.clone()
                    - identity_start_bit::<E>(&self.identity_block_const_bits, &phil_secret, bit))
                + block_starts[1].clone()
                    * (state[bit].cur.clone()
                        - owner_start_bit::<E>(&self.owner_block_const_bits, &state, bit))
                + block_starts[2].clone()
                    * (state[bit].cur.clone()
                        - nullifier_block0_start_bit::<E>(
                            &self.nullifier_block0_const_bits,
                            &nullifier_seed,
                            bit,
                        ))
                + block_starts[3].clone()
                    * (state[bit].cur.clone()
                        - continuation_state_bit::<E>(
                            state[bit].prev.clone(),
                            &self.nullifier_block1_const_bits,
                            &nullifier_seed,
                            64,
                            bit,
                        ))
                + block_starts[4].clone()
                    * (state[bit].cur.clone()
                        - start_state_bit::<E>(&self.proof_input_block_bits[0], bit))
                + block_starts[5].clone()
                    * (state[bit].cur.clone()
                        - continuation_constant_state_bit::<E>(
                            state[bit].prev.clone(),
                            &self.proof_input_block_bits[1],
                            bit,
                        ))
                + block_starts[6].clone()
                    * (state[bit].cur.clone()
                        - continuation_constant_state_bit::<E>(
                            state[bit].prev.clone(),
                            &self.proof_input_block_bits[2],
                            bit,
                        ))
                + block_starts[7].clone()
                    * (state[bit].cur.clone()
                        - continuation_constant_state_bit::<E>(
                            state[bit].prev.clone(),
                            &self.proof_input_block_bits[3],
                            bit,
                        ));
            eval.add_constraint(absorb);
        }

        for x in 0..5 {
            for z in 0..LANE_BITS {
                let parity_index = lane5_bit_index(x, z);
                let a0 = state[state_bit_index(x, 0, z)].cur.clone();
                let a1 = state[state_bit_index(x, 1, z)].cur.clone();
                let a2 = state[state_bit_index(x, 2, z)].cur.clone();
                let a3 = state[state_bit_index(x, 3, z)].cur.clone();
                let a4 = state[state_bit_index(x, 4, z)].cur.clone();

                eval.add_constraint(
                    round_active.clone() * (p01[parity_index].clone() - xor_expr(a0, a1)),
                );
                eval.add_constraint(
                    round_active.clone() * (p23[parity_index].clone() - xor_expr(a2, a3)),
                );
                eval.add_constraint(
                    round_active.clone()
                        * (p0123[parity_index].clone()
                            - xor_expr(p01[parity_index].clone(), p23[parity_index].clone())),
                );
                eval.add_constraint(
                    round_active.clone()
                        * (c[parity_index].clone() - xor_expr(p0123[parity_index].clone(), a4)),
                );

                let left = c[lane5_bit_index((x + 4) % 5, z)].clone();
                let right =
                    c[lane5_bit_index((x + 1) % 5, (z + LANE_BITS - 1) % LANE_BITS)].clone();
                eval.add_constraint(
                    round_active.clone() * (d[parity_index].clone() - xor_expr(left, right)),
                );
            }
        }

        for target_lane in 0..25 {
            let (source_lane, rotation) = inverse_rho_pi(target_lane);
            let source_x = source_lane % 5;
            let source_y = source_lane / 5;
            let target_x = target_lane % 5;
            let target_y = target_lane / 5;

            for z in 0..LANE_BITS {
                let source_z = (z + LANE_BITS - rotation) % LANE_BITS;
                let source_bit = state[state_bit_index(source_x, source_y, source_z)]
                    .cur
                    .clone();
                let d_bit = d[lane5_bit_index(source_x, source_z)].clone();
                let target_index = state_bit_index(target_x, target_y, z);
                eval.add_constraint(
                    round_active.clone() * (b[target_index].clone() - xor_expr(source_bit, d_bit)),
                );
            }
        }

        for x in 0..5 {
            for y in 0..5 {
                for z in 0..LANE_BITS {
                    let index = state_bit_index(x, y, z);
                    let next1 = b[state_bit_index((x + 1) % 5, y, z)].clone();
                    let next2 = b[state_bit_index((x + 2) % 5, y, z)].clone();
                    let chi_term = (E::F::one() - next1) * next2;
                    eval.add_constraint(round_active.clone() * (chi[index].clone() - chi_term));
                    let expected_base = xor_expr(b[index].clone(), chi[index].clone());
                    eval.add_constraint(
                        round_active.clone() * (base_state[index].clone() - expected_base),
                    );
                    let expected = if x == 0 && y == 0 {
                        xor_expr(base_state[index].clone(), rc_bits[z].clone())
                    } else {
                        base_state[index].clone()
                    };
                    eval.add_constraint(
                        round_active.clone() * (expected_state[index].clone() - expected),
                    );
                    eval.add_constraint(
                        round_active.clone()
                            * (state[index].next.clone() - expected_state[index].clone()),
                    );
                }
            }
        }

        for bit in 0..DIGEST_BITS {
            eval.add_constraint(
                owner_final.clone() * (state[bit].cur.clone() - self.public_owner_bits[bit].into()),
            );
            eval.add_constraint(
                nullifier_final.clone()
                    * (state[bit].cur.clone() - self.public_nullifier_bits[bit].into()),
            );
            eval.add_constraint(
                proof_input_final.clone()
                    * (state[bit].cur.clone() - self.public_proof_input_bits[bit].into()),
            );
        }

        eval
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

fn continuation_constant_state_bit<E: EvalAtRow>(
    prev: E::F,
    block_bits: &[BaseField],
    bit: usize,
) -> E::F {
    if bit < RATE_BITS {
        xor_expr(prev, block_bits[bit].into())
    } else {
        prev
    }
}

fn identity_start_bit<E: EvalAtRow>(
    block_bits: &[BaseField],
    phil_secret: &[E::F],
    bit: usize,
) -> E::F {
    if (256..512).contains(&bit) {
        phil_secret[bit - 256].clone()
    } else {
        start_state_bit::<E>(block_bits, bit)
    }
}

fn owner_start_bit<E: EvalAtRow>(
    block_bits: &[BaseField],
    state: &[TransitionMask<E::F>],
    bit: usize,
) -> E::F {
    if (256..512).contains(&bit) {
        state[bit - 256].prev.clone()
    } else {
        start_state_bit::<E>(block_bits, bit)
    }
}

fn nullifier_block0_start_bit<E: EvalAtRow>(
    block_bits: &[BaseField],
    nullifier_seed: &[E::F],
    bit: usize,
) -> E::F {
    if (1024..1088).contains(&bit) {
        nullifier_seed[bit - 1024].clone()
    } else {
        start_state_bit::<E>(block_bits, bit)
    }
}

fn continuation_state_bit<E: EvalAtRow>(
    prev: E::F,
    block_bits: &[BaseField],
    nullifier_seed: &[E::F],
    seed_offset: usize,
    bit: usize,
) -> E::F {
    if bit < 192 {
        xor_expr(prev, nullifier_seed[seed_offset + bit].clone())
    } else if bit < RATE_BITS {
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

fn inverse_rho_pi(target_lane: usize) -> (usize, usize) {
    for source_lane in 0..25 {
        let x = source_lane % 5;
        let y = source_lane / 5;
        let target_x = y;
        let target_y = (2 * x + 3 * y) % 5;
        let mapped_lane = target_x + 5 * target_y;
        if mapped_lane == target_lane {
            return (
                source_lane,
                crate::constants::KECCAK_RHO_OFFSETS[source_lane],
            );
        }
    }
    unreachable!("rho/pi inverse should always resolve a lane")
}

fn logical_row_to_physical_row(row: usize, log_n_rows: u32) -> usize {
    bit_reverse_index(
        coset_index_to_circle_domain_index(row, log_n_rows),
        log_n_rows,
    )
}

fn write_lane_bits_logical_row(
    columns: &mut [Vec<BaseField>],
    logical_row: usize,
    lanes: &[u64],
    log_n_rows: u32,
) {
    let physical_row = logical_row_to_physical_row(logical_row, log_n_rows);
    set_lane_bits_row(columns, physical_row, lanes);
}

impl UnlockStatementScope {
    fn used_final_row(self) -> usize {
        match self {
            Self::OwnerPathOnly => OWNER_FINAL_ROW,
            Self::Full => PROOF_INPUT_FINAL_ROW,
        }
    }

    fn active_block_start_rows(self) -> &'static [usize] {
        match self {
            Self::OwnerPathOnly => &[0, OWNER_START_ROW],
            Self::Full => &[
                0,
                OWNER_START_ROW,
                NULLIFIER_BLOCK0_START_ROW,
                NULLIFIER_BLOCK1_START_ROW,
                PROOF_INPUT_BLOCK0_START_ROW,
                PROOF_INPUT_BLOCK1_START_ROW,
                PROOF_INPUT_BLOCK2_START_ROW,
                PROOF_INPUT_BLOCK3_START_ROW,
            ],
        }
    }

    fn has_owner_final(self) -> bool {
        true
    }

    fn has_nullifier_final(self) -> bool {
        matches!(self, Self::Full)
    }

    fn has_proof_input_final(self) -> bool {
        matches!(self, Self::Full)
    }
}

fn bits_from_bytes_le(bytes: &[u8]) -> Vec<BaseField> {
    field_bits_from_bytes_le(bytes)
}

fn build_unlock_component_with_scope(
    public_inputs: &UnlockPublicInputs,
    scope: UnlockStatementScope,
) -> Result<UnlockStatementComponent> {
    let zero_secret = [0_u8; 32];
    let identity_block_const_bits = bits_from_bytes_le(
        &keccak_pad_rate_blocks(&encode_identity_root_preimage(&zero_secret))[0],
    );
    let owner_block_const_bits = bits_from_bytes_le(
        &keccak_pad_rate_blocks(&encode_owner_commitment_preimage(&zero_secret))[0],
    );

    let nullifier_blocks = keccak_pad_rate_blocks(&encode_nullifier_preimage(
        &public_inputs.owner_commitment,
        &public_inputs.action_hash,
        &public_inputs.policy_hash,
        &zero_secret,
    ));
    let proof_input_preimage = encode_proof_input_hash_preimage(
        STWO_UNLOCK_PROOF_VERSION,
        STWO_UNLOCK_PROOF_TYPE,
        public_inputs,
    )?;
    let proof_input_blocks = keccak_pad_rate_blocks(&proof_input_preimage);
    let proof_input_hash = derive_proof_input_hash(public_inputs)?;

    Ok(UnlockStatementComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(
            &unlock_preprocessed_column_ids(),
        ),
        UnlockStatementEval {
            scope,
            log_n_rows: LOG_N_ROWS,
            identity_block_const_bits,
            owner_block_const_bits,
            nullifier_block0_const_bits: bits_from_bytes_le(&nullifier_blocks[0]),
            nullifier_block1_const_bits: bits_from_bytes_le(&nullifier_blocks[1]),
            proof_input_block_bits: proof_input_blocks
                .iter()
                .map(|block| bits_from_bytes_le(block))
                .collect(),
            public_owner_bits: bits_from_bytes_le(&public_inputs.owner_commitment),
            public_nullifier_bits: bits_from_bytes_le(&public_inputs.nullifier),
            public_proof_input_bits: bits_from_bytes_le(&proof_input_hash),
        },
        SecureField::zero(),
    ))
}

fn build_unlock_component(public_inputs: &UnlockPublicInputs) -> Result<UnlockStatementComponent> {
    build_unlock_component_with_scope(public_inputs, UnlockStatementScope::Full)
}

pub fn build_unlock_component_for_debug(
    public_inputs: &UnlockPublicInputs,
) -> Result<UnlockStatementComponent> {
    build_unlock_component(public_inputs)
}

fn write_hash_trace(
    columns: &mut UnlockTraceColumns,
    start_row: usize,
    blocks: &[[u8; crate::constants::RATE_BYTES]],
) -> [u64; 25] {
    let mut state = [0_u64; 25];

    for (block_index, block) in blocks.iter().enumerate() {
        let base_row = start_row + block_index * BLOCK_ROWS;
        for lane in 0..crate::constants::RATE_LANES {
            let lane_bytes: [u8; 8] = block[(lane * 8)..((lane + 1) * 8)]
                .try_into()
                .expect("rate is lane-aligned");
            state[lane] ^= u64::from_le_bytes(lane_bytes);
        }
        write_lane_bits_logical_row(&mut columns.state, base_row, &state, LOG_N_ROWS);

        for round in 0..KECCAK_ROUNDS {
            let witness: RoundWitness = round_witness(state, round);
            write_lane_bits_logical_row(
                &mut columns.p01,
                base_row + round,
                &witness.p01,
                LOG_N_ROWS,
            );
            write_lane_bits_logical_row(
                &mut columns.p23,
                base_row + round,
                &witness.p23,
                LOG_N_ROWS,
            );
            write_lane_bits_logical_row(
                &mut columns.p0123,
                base_row + round,
                &witness.p0123,
                LOG_N_ROWS,
            );
            write_lane_bits_logical_row(&mut columns.c, base_row + round, &witness.c, LOG_N_ROWS);
            write_lane_bits_logical_row(&mut columns.d, base_row + round, &witness.d, LOG_N_ROWS);
            write_lane_bits_logical_row(&mut columns.b, base_row + round, &witness.b, LOG_N_ROWS);
            write_lane_bits_logical_row(
                &mut columns.chi,
                base_row + round,
                &witness.chi,
                LOG_N_ROWS,
            );
            write_lane_bits_logical_row(
                &mut columns.base_state,
                base_row + round,
                &witness.base_state,
                LOG_N_ROWS,
            );
            write_lane_bits_logical_row(
                &mut columns.expected_state,
                base_row + round,
                &witness.next,
                LOG_N_ROWS,
            );
            state = witness.next;
            write_lane_bits_logical_row(
                &mut columns.state,
                base_row + round + 1,
                &state,
                LOG_N_ROWS,
            );
        }
    }

    state
}

fn build_unlock_trace_with_scope(
    input: &GenerateProofInput,
    scope: UnlockStatementScope,
) -> Result<UnlockTraceColumns> {
    let mut columns = UnlockTraceColumns::new(LOG_N_ROWS);
    let n_rows = 1 << LOG_N_ROWS;

    let phil_secret_bits = bits_from_bytes_le(&input.phil_secret);
    let nullifier_seed_bits = bits_from_bytes_le(&input.nullifier_seed);
    for bit in 0..PHIL_SECRET_BITS {
        for row in 0..n_rows {
            columns.phil_secret[bit][row] = phil_secret_bits[bit];
        }
    }
    for bit in 0..NULLIFIER_SEED_BITS {
        for row in 0..n_rows {
            columns.nullifier_seed[bit][row] = nullifier_seed_bits[bit];
        }
    }

    let identity_blocks =
        keccak_pad_rate_blocks(&encode_identity_root_preimage(&input.phil_secret));
    let identity_final_state = write_hash_trace(&mut columns, 0, &identity_blocks);
    let identity_digest = keccak_digest_from_state(&identity_final_state);

    let owner_blocks = keccak_pad_rate_blocks(&encode_owner_commitment_preimage(&identity_digest));
    write_hash_trace(&mut columns, OWNER_START_ROW, &owner_blocks);

    if matches!(scope, UnlockStatementScope::Full) {
        let nullifier_blocks = keccak_pad_rate_blocks(&encode_nullifier_preimage(
            &input.public_inputs.owner_commitment,
            &input.public_inputs.action_hash,
            &input.public_inputs.policy_hash,
            &input.nullifier_seed,
        ));
        write_hash_trace(&mut columns, NULLIFIER_BLOCK0_START_ROW, &nullifier_blocks);

        let proof_input_preimage = encode_proof_input_hash_preimage(
            STWO_UNLOCK_PROOF_VERSION,
            STWO_UNLOCK_PROOF_TYPE,
            &input.public_inputs,
        )?;
        let proof_input_blocks = keccak_pad_rate_blocks(&proof_input_preimage);
        write_hash_trace(
            &mut columns,
            PROOF_INPUT_BLOCK0_START_ROW,
            &proof_input_blocks,
        );
    }

    Ok(columns)
}

fn build_unlock_trace(input: &GenerateProofInput) -> Result<UnlockTraceColumns> {
    build_unlock_trace_with_scope(input, UnlockStatementScope::Full)
}

fn unlock_preprocessed_column_ids() -> Vec<PreProcessedColumnId> {
    let mut ids = vec![
        unlock_round_selector_id(),
        owner_final_selector_id(),
        nullifier_final_selector_id(),
        proof_input_final_selector_id(),
    ];
    ids.extend((0..TOTAL_BLOCKS).map(unlock_block_start_selector_id));
    ids.extend((0..LANE_BITS).map(unlock_round_constant_bit_id));
    ids
}

fn generate_unlock_preprocessed_trace_with_scope(
    log_n_rows: u32,
    scope: UnlockStatementScope,
) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let n_rows = 1 << log_n_rows;
    let domain = CanonicCoset::new(log_n_rows).circle_domain();
    let mut columns = Vec::new();

    let mut round_selector = vec![BaseField::zero(); n_rows];
    for row in 0..scope.used_final_row() + 1 {
        if row % BLOCK_ROWS != BLOCK_ROWS - 1 {
            round_selector[logical_row_to_physical_row(row, log_n_rows)] = BaseField::one();
        }
    }
    columns.push(round_selector);

    let mut owner_final = vec![BaseField::zero(); n_rows];
    if scope.has_owner_final() {
        owner_final[logical_row_to_physical_row(OWNER_FINAL_ROW, log_n_rows)] = BaseField::one();
    }
    columns.push(owner_final);

    let mut nullifier_final = vec![BaseField::zero(); n_rows];
    if scope.has_nullifier_final() {
        nullifier_final[logical_row_to_physical_row(NULLIFIER_FINAL_ROW, log_n_rows)] =
            BaseField::one();
    }
    columns.push(nullifier_final);

    let mut proof_input_final = vec![BaseField::zero(); n_rows];
    if scope.has_proof_input_final() {
        proof_input_final[logical_row_to_physical_row(PROOF_INPUT_FINAL_ROW, log_n_rows)] =
            BaseField::one();
    }
    columns.push(proof_input_final);

    for index in 0..TOTAL_BLOCKS {
        let mut selector = vec![BaseField::zero(); n_rows];
        if let Some(&row) = scope.active_block_start_rows().get(index) {
            selector[logical_row_to_physical_row(row, log_n_rows)] = BaseField::one();
        }
        columns.push(selector);
    }

    for bit in 0..LANE_BITS {
        let mut rc_column = vec![BaseField::zero(); n_rows];
        for row in 0..scope.used_final_row() + 1 {
            let round = row % BLOCK_ROWS;
            if round < KECCAK_ROUNDS {
                rc_column[logical_row_to_physical_row(row, log_n_rows)] =
                    BaseField::from(((KECCAK_ROUND_CONSTANTS[round] >> bit) & 1) as u32);
            }
        }
        columns.push(rc_column);
    }

    columns
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

fn generate_unlock_preprocessed_trace(
    log_n_rows: u32,
) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    generate_unlock_preprocessed_trace_with_scope(log_n_rows, UnlockStatementScope::Full)
}

fn unlock_round_selector_id() -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: "unlock_round_active".to_string(),
    }
}

fn owner_final_selector_id() -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: "unlock_owner_final".to_string(),
    }
}

fn nullifier_final_selector_id() -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: "unlock_nullifier_final".to_string(),
    }
}

fn proof_input_final_selector_id() -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: "unlock_proof_input_final".to_string(),
    }
}

fn unlock_block_start_selector_id(index: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("unlock_block_start_{index}"),
    }
}

fn unlock_round_constant_bit_id(bit: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("unlock_round_constant_bit_{bit}"),
    }
}

fn prove_component(
    component: &UnlockStatementComponent,
    preprocessed_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
) -> Result<UnlockStatementProof> {
    let mut config = PcsConfig::default();
    config.lifting_log_size = Some(component.max_constraint_log_degree_bound());
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(
            config
                .lifting_log_size
                .expect("lifting log size should be set")
                + 1
                + config.fri_config.log_blowup_factor,
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
    .context("failed to prove unlock statement")?;

    Ok(UnlockStatementProof { proof })
}

fn canonical_preprocessed_commitment(
    component: &UnlockStatementComponent,
) -> stwo::core::vcs::blake2_hash::Blake2sHash {
    let mut config = PcsConfig::default();
    config.lifting_log_size = Some(component.max_constraint_log_degree_bound());
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(
            config
                .lifting_log_size
                .expect("lifting log size should be set")
                + 1
                + config.fri_config.log_blowup_factor,
        )
        .circle_domain()
        .half_coset,
    );
    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(generate_unlock_preprocessed_trace_with_scope(
        LOG_N_ROWS,
        component.scope,
    ));
    tree_builder.commit(channel);
    commitment_scheme.roots()[0]
}

fn verify_component(
    component: &UnlockStatementComponent,
    proof: &UnlockStatementProof,
) -> Result<()> {
    let mut config = PcsConfig::default();
    config.lifting_log_size = Some(component.max_constraint_log_degree_bound());
    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();

    if proof.proof.commitments.len() != 3 {
        bail!("unlock statement proof must contain exactly three commitment trees");
    }
    let expected_preprocessed = canonical_preprocessed_commitment(component);
    if proof.proof.commitments[0] != expected_preprocessed {
        bail!("unlock statement proof uses an unrecognized preprocessed program");
    }

    commitment_scheme.commit(proof.proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.proof.commitments[1], &sizes[1], verifier_channel);
    verify(
        &[component as &dyn Component],
        verifier_channel,
        commitment_scheme,
        proof.proof.clone(),
    )
    .context("failed to verify unlock statement")
}

pub fn prove_unlock_statement(input: &GenerateProofInput) -> Result<UnlockStatementProof> {
    let component = build_unlock_component(&input.public_inputs)?;
    let preprocessed_trace = generate_unlock_preprocessed_trace(LOG_N_ROWS);
    let trace = build_unlock_trace(input)?.into_evals(LOG_N_ROWS);
    prove_component(&component, preprocessed_trace, trace)
}

pub fn prove_unlock_owner_path(input: &GenerateProofInput) -> Result<UnlockStatementProof> {
    let component = build_unlock_component_with_scope(
        &input.public_inputs,
        UnlockStatementScope::OwnerPathOnly,
    )?;
    let preprocessed_trace = generate_unlock_preprocessed_trace_with_scope(
        LOG_N_ROWS,
        UnlockStatementScope::OwnerPathOnly,
    );
    let trace = build_unlock_trace_with_scope(input, UnlockStatementScope::OwnerPathOnly)?
        .into_evals(LOG_N_ROWS);
    prove_component(&component, preprocessed_trace, trace)
}

pub fn verify_unlock_statement(
    proof: &UnlockStatementProof,
    public_inputs: &UnlockPublicInputs,
) -> Result<()> {
    let component = build_unlock_component(public_inputs)?;
    verify_component(&component, proof)
}

pub fn verify_unlock_owner_path(
    proof: &UnlockStatementProof,
    public_inputs: &UnlockPublicInputs,
) -> Result<()> {
    let component =
        build_unlock_component_with_scope(public_inputs, UnlockStatementScope::OwnerPathOnly)?;
    verify_component(&component, proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::load_default_vector;

    fn zero_preprocessed_trace() -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>
    {
        let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
        (0..unlock_preprocessed_column_ids().len())
            .map(|_| {
                CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(
                    domain,
                    Col::<SimdBackend, BaseField>::zeros(1 << LOG_N_ROWS),
                )
            })
            .collect()
    }

    #[test]
    fn verifier_rejects_a_proof_for_a_zeroed_preprocessed_program() {
        let vector = load_default_vector().expect("fixture vector should load");
        let input = GenerateProofInput {
            public_inputs: vector.public_inputs.clone(),
            phil_secret: vector.phil_secret,
            nullifier_seed: vector.nullifier_seed,
        };
        let component =
            build_unlock_component(&input.public_inputs).expect("unlock component should build");
        let forged = prove_component(
            &component,
            zero_preprocessed_trace(),
            UnlockTraceColumns::new(LOG_N_ROWS).into_evals(LOG_N_ROWS),
        )
        .expect("the zero-selector program demonstrates why its commitment must be pinned");

        assert!(
            verify_component(&component, &forged).is_err(),
            "a proof for a different preprocessed program must fail closed"
        );
    }

    #[test]
    fn verifier_rejects_a_malformed_commitment_tree_count() {
        let vector = load_default_vector().expect("fixture vector should load");
        let input = GenerateProofInput {
            public_inputs: vector.public_inputs.clone(),
            phil_secret: vector.phil_secret,
            nullifier_seed: vector.nullifier_seed,
        };
        let component =
            build_unlock_component(&input.public_inputs).expect("unlock component should build");
        let mut proof = prove_unlock_statement(&input).expect("proof should build");
        proof.proof.0.commitments.0.pop();

        assert!(verify_component(&component, &proof).is_err());
    }

    #[test]
    fn serialized_proof_openings_demonstrate_the_current_witness_privacy_blocker() {
        let vector = load_default_vector().expect("fixture vector should load");
        let input = GenerateProofInput {
            public_inputs: vector.public_inputs.clone(),
            phil_secret: vector.phil_secret,
            nullifier_seed: vector.nullifier_seed,
        };
        let proof = prove_unlock_statement(&input).expect("proof should build");
        let trace_openings = &proof.proof.queried_values[1];
        let mut recovered_secret = [0_u8; 32];

        for bit in 0..PHIL_SECRET_BITS {
            let opened_values = &trace_openings[bit];
            assert!(!opened_values.is_empty(), "each secret column is opened");
            assert!(
                opened_values.iter().all(|value| *value == opened_values[0]),
                "the current trace copies every secret bit across all rows"
            );
            if opened_values[0] == BaseField::one() {
                recovered_secret[bit / 8] |= 1 << (bit % 8);
            } else {
                assert_eq!(opened_values[0], BaseField::zero());
            }
        }

        assert_eq!(
            recovered_secret, vector.phil_secret,
            "the pinned STWO proof format is not witness hiding for this trace layout"
        );
    }
}
