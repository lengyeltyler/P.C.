use anyhow::{Context, Result};
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use stwo::core::air::Component;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::core::verifier::verify;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

pub type FixedBytesComponent<const N: usize> = FrameworkComponent<FixedBytesEval<N>>;

#[derive(Clone)]
pub struct FixedBytesEval<const N: usize> {
    pub log_n_rows: u32,
    pub expected: [BaseField; N],
}

impl<const N: usize> FrameworkEval for FixedBytesEval<N> {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        for expected in self.expected {
            let value = eval.next_trace_mask();
            eval.add_constraint(value - expected.into());
        }
        eval
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FixedBytesProof {
    pub proof: StarkProof<Blake2sM31MerkleHasher>,
}

pub fn bytes_to_base_fields<const N: usize>(bytes: &[u8; N]) -> [BaseField; N] {
    core::array::from_fn(|index| BaseField::from(bytes[index] as u32))
}

pub fn generate_trace<const N: usize>(
    bytes: &[u8; N],
    log_n_rows: u32,
) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let domain = CanonicCoset::new(log_n_rows).circle_domain();
    bytes
        .iter()
        .map(|byte| {
            let mut column = Col::<SimdBackend, BaseField>::zeros(1 << log_n_rows);
            for row in 0..(1 << log_n_rows) {
                column.set(row, BaseField::from(*byte as u32));
            }
            CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(domain, column)
        })
        .collect()
}

pub fn prove_fixed_bytes<const N: usize>(
    bytes: &[u8; N],
    log_n_rows: u32,
) -> Result<FixedBytesProof> {
    let config = PcsConfig::default();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_n_rows + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let prover_channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(prover_channel);

    let trace = generate_trace(bytes, log_n_rows);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(prover_channel);

    let component = FixedBytesComponent::new(
        &mut TraceLocationAllocator::default(),
        FixedBytesEval {
            log_n_rows,
            expected: bytes_to_base_fields(bytes),
        },
        SecureField::zero(),
    );

    let proof = prove::<SimdBackend, Blake2sM31MerkleChannel>(
        &[&component],
        prover_channel,
        commitment_scheme,
    )
    .context("failed to prove fixed-bytes component")?;

    Ok(FixedBytesProof { proof })
}

pub fn verify_fixed_bytes<const N: usize>(
    proof: &FixedBytesProof,
    bytes: &[u8; N],
    log_n_rows: u32,
) -> Result<()> {
    let config = PcsConfig::default();
    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
    let component = FixedBytesComponent::new(
        &mut TraceLocationAllocator::default(),
        FixedBytesEval {
            log_n_rows,
            expected: bytes_to_base_fields(bytes),
        },
        SecureField::zero(),
    );

    let sizes = component.trace_log_degree_bounds();
    commitment_scheme.commit(proof.proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.proof.commitments[1], &sizes[1], verifier_channel);
    verify(
        &[&component as &dyn Component],
        verifier_channel,
        commitment_scheme,
        proof.proof.clone(),
    )
    .context("failed to verify fixed-bytes component")
}
