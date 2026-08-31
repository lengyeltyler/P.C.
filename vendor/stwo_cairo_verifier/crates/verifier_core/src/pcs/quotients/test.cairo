// Modified by Phil contributors from starkware-libs/stwo-cairo revision 0a5e70b.
// See vendor/stwo_cairo_verifier/PHIL_PROVENANCE.md and NOTICE.

use core::array;
use core::array::ArrayImpl;
use core::box::BoxImpl;
use core::num::traits::One;
use crate::circle::{
    CirclePoint, CirclePointIndexImpl, CirclePointQM31AddCirclePointM31Trait, CosetImpl,
};
use crate::fields::m31::m31;
use crate::fields::qm31::{QM31, qm31_const};
use crate::pcs::quotients::{
    ColumnSampleBatch, QuotientConstantsImpl, build_samples_with_randomness, fri_answers,
    sample_batches_for_degree_bound,
};
use crate::pcs::verifier::CommitmentSchemeVerifierImpl;
use crate::poly::circle::{CanonicCosetImpl, CircleDomainImpl, CircleEvaluationImpl};
use crate::utils::{
    DictImpl, group_columns_by_degree_bound, pad_and_transpose_columns_by_log_deg_bound_per_tree,
};
use super::{CanonicCosetTrait, accumulate_row_quotients};

/// Expected values were generated in the stwo repo at stwo/src/core/pcs/quotients, commit
/// 687bc9ae6b0a5d7c48db74e00c22e13bab0e63fe.
#[test]
fn test_fri_answers() {
    let log_blowup_factor = 2;
    let col0_degree_bound = 3;
    let col1_degree_bound = 5;
    let col2_degree_bound = col1_degree_bound;
    let oods_point = qm31_circle_gen();

    let sample0 = qm31_const::<0, 1, 2, 3>();
    let sample1 = qm31_const::<1, 2, 3, 4>();
    let col0_samples = array![sample1, sample0].span();
    let col1_samples = array![sample0].span();
    let col2_samples = array![sample1, sample0].span();
    let empty_span = array![].span();
    let samples_per_column_per_tree = array![
        empty_span, empty_span, array![col0_samples, col1_samples, col2_samples].span(),
    ]
        .span();
    let columns_by_degree_bound_per_tree = array![
        array![].span(), array![].span(),
        group_columns_by_degree_bound(
            array![col0_degree_bound, col1_degree_bound, col2_degree_bound].span(),
        ),
    ]
        .span();

    let columns_per_tree_by_degree_bound = pad_and_transpose_columns_by_log_deg_bound_per_tree(
        columns_by_degree_bound_per_tree,
    );

    let random_coeff = qm31_const::<9, 8, 7, 6>();
    let query_positions = array![4, 5].span();
    let empty_span = array![].span();
    let query_evals = array![
        empty_span, empty_span, array![m31(3), m31(7), m31(9), m31(2), m31(4), m31(10)].span(),
    ];

    let res = fri_answers(
        columns_per_tree_by_degree_bound,
        log_blowup_factor,
        oods_point,
        samples_per_column_per_tree,
        random_coeff,
        query_positions,
        query_evals,
        col1_degree_bound,
    );
    assert!(res.len() == 2);
    assert!(*res[0] == qm31_const::<1037270598, 1666156792, 1481464786, 376406587>());
    assert!(*res[1] == qm31_const::<362741309, 158709031, 140688744, 632848018>());
}

#[test]
fn test_accumulate_row_quotients() {
    let random_coeff = qm31_const::<4, 3, 2, 1>();
    let log_size = 5;
    let domain = CanonicCosetImpl::new(log_size);
    let queried_values_at_row = array![m31(5), m31(1)].span();
    let p0 = qm31_circle_gen();
    let p1 = qm31_circle_gen() + qm31_circle_gen();
    let sample_batches = array![
        ColumnSampleBatch {
            point: p0, cols_vals_and_pows: array![(0, qm31_const::<0, 1, 2, 3>(), One::one())],
        },
        ColumnSampleBatch {
            point: p1, cols_vals_and_pows: array![(1, qm31_const::<1, 2, 3, 4>(), random_coeff)],
        },
    ]
        .span();
    let quotient_constants = QuotientConstantsImpl::gen(sample_batches);

    let res = accumulate_row_quotients(
        sample_batches, queried_values_at_row, @quotient_constants, domain.circle_domain().at(0),
    );
    assert_eq!(res, qm31_const::<1090243653, 141518822, 29401430, 491190325>());
}

// Test used to benchmark step counts.
#[test]
fn test_fri_answers_with_1000_columns() {
    // NOTE: Forge fails if these are declared `const ...`.
    let log_degree_bound: u32 = 15;
    let n_queries: usize = 20;
    let n_columns: usize = 1000;
    let random_coeff = qm31_const::<9, 8, 7, 6>();
    assert!(n_columns >= 3, "First three columns are manually created");
    let mut query_positions = array![];
    for query_position in 0..n_queries {
        query_positions.append(query_position);
    }

    let sample0 = qm31_const::<0, 1, 2, 3>();
    let sample1 = qm31_const::<1, 2, 3, 4>();
    let sample2 = qm31_const::<2, 3, 4, 5>();

    let mut query_values = array![];
    for i in 0..n_queries {
        for _ in 0..n_columns {
            query_values.append(m31(i));
        }
    }

    let mut samples = array![];
    // Manually add samples for the first three columns.
    samples.append(array![sample0].span());
    samples.append(array![sample1].span());
    samples.append(array![sample0, sample2].span());
    for _ in 3..n_columns {
        samples.append(array![sample0].span())
    }

    let mut size_vector = array![];
    for _ in 0..n_columns {
        size_vector.append(log_degree_bound)
    }
    let columns_by_degree_bound_per_tree = array![
        array![].span(), group_columns_by_degree_bound(size_vector.span()), array![].span(),
    ]
        .span();
    let columns_per_tree_by_degree_bound = pad_and_transpose_columns_by_log_deg_bound_per_tree(
        columns_by_degree_bound_per_tree,
    );
    let mut queried_values_per_tree = array![array![].span(), query_values.span(), array![].span()];
    let oods_point = qm31_circle_gen();
    let log_blowup_factor = 1;
    let _res = fri_answers(
        columns_per_tree_by_degree_bound,
        log_blowup_factor,
        oods_point,
        array![array![].span(), samples.span(), array![].span()].span(),
        random_coeff,
        query_positions.span(),
        queried_values_per_tree,
        log_degree_bound,
    );
}

#[test]
fn test_build_samples_with_randomness_accepts_explicit_three_sample_columns() {
    let random_coeff = qm31_const::<9, 8, 7, 6>();
    let prev_sample = qm31_const::<1, 2, 3, 4>();
    let ood_sample = qm31_const::<0, 1, 2, 3>();
    let next_sample = qm31_const::<2, 3, 4, 5>();

    let samples_with_randomness = build_samples_with_randomness(
        array![
            array![
                array![prev_sample, ood_sample, next_sample].span(),
                array![ood_sample].span(),
            ]
                .span(),
        ]
            .span(),
        random_coeff,
    );

    assert!(samples_with_randomness.len() == 1);
    let tree_samples = *samples_with_randomness[0];
    assert!(tree_samples.len() == 2);

    let explicit_triple = *tree_samples[0];
    assert!(explicit_triple.len() == 3);
    let (prev_tag, actual_prev_sample, prev_rand) = *explicit_triple[0];
    let (oods_tag, actual_ood_sample, ood_rand) = *explicit_triple[1];
    let (next_tag, actual_next_sample, next_rand) = *explicit_triple[2];
    assert_eq!(prev_tag, 1);
    assert_eq!(oods_tag, 2);
    assert_eq!(next_tag, 3);
    assert_eq!(actual_prev_sample, prev_sample);
    assert_eq!(actual_ood_sample, ood_sample);
    assert_eq!(actual_next_sample, next_sample);
    assert_eq!(prev_rand, One::one());
    assert_eq!(ood_rand, random_coeff);
    assert_eq!(next_rand, random_coeff * random_coeff);

    let singleton = *tree_samples[1];
    assert!(singleton.len() == 1);
    let (singleton_tag, actual_singleton, singleton_rand) = *singleton[0];
    assert_eq!(singleton_tag, 2);
    assert_eq!(actual_singleton, ood_sample);
    assert_eq!(singleton_rand, random_coeff * random_coeff * random_coeff);
}

#[test]
fn test_sample_batches_for_degree_bound_groups_explicit_three_sample_columns_by_point_identity() {
    let random_coeff = qm31_const::<9, 8, 7, 6>();
    let prev_sample = qm31_const::<1, 2, 3, 4>();
    let ood_sample = qm31_const::<0, 1, 2, 3>();
    let next_sample = qm31_const::<2, 3, 4, 5>();
    let oods_point = qm31_circle_gen();
    let trace_step = CanonicCosetImpl::new(5).coset.step.mul(1).to_point();
    let prev_oods_point = oods_point.add_circle_point_m31(-trace_step);
    let next_oods_point = oods_point.add_circle_point_m31(trace_step);
    let periodicity_generator = trace_step + trace_step;

    let samples_with_randomness = build_samples_with_randomness(
        array![
            array![
                array![prev_sample, ood_sample, next_sample].span(),
                array![ood_sample].span(),
            ]
                .span(),
        ]
            .span(),
        random_coeff,
    );
    let column_indices_per_tree = array![array![0, 1].span()].span();
    let (sample_batches, n_columns_per_tree) = sample_batches_for_degree_bound(
        @column_indices_per_tree,
        samples_with_randomness,
        oods_point,
        prev_oods_point,
        periodicity_generator,
        trace_step,
    );

    assert_eq!(n_columns_per_tree.len(), 1);
    assert_eq!(*n_columns_per_tree[0], 2);
    assert_eq!(sample_batches.len(), 3);

    let first_batch = sample_batches[0];
    let second_batch = sample_batches[1];
    let third_batch = sample_batches[2];

    assert_eq!(*first_batch.point, prev_oods_point);
    assert_eq!(*second_batch.point, oods_point);
    assert_eq!(*third_batch.point, next_oods_point);

    assert_eq!(first_batch.cols_vals_and_pows.len(), 1);
    assert_eq!(second_batch.cols_vals_and_pows.len(), 2);
    assert_eq!(third_batch.cols_vals_and_pows.len(), 1);

    let (prev_column_index, prev_value, _) = *first_batch.cols_vals_and_pows[0];
    let (oods_column0, oods_value0, _) = *second_batch.cols_vals_and_pows[0];
    let (oods_column1, oods_value1, _) = *second_batch.cols_vals_and_pows[1];
    let (next_column_index, next_value, _) = *third_batch.cols_vals_and_pows[0];

    assert_eq!(prev_column_index, 0);
    assert_eq!(prev_value, prev_sample);
    assert_eq!(oods_column0, 0);
    assert_eq!(oods_value0, ood_sample);
    assert_eq!(oods_column1, 1);
    assert_eq!(oods_value1, ood_sample);
    assert_eq!(next_column_index, 0);
    assert_eq!(next_value, next_sample);
}

/// Returns a generator for the circle group over [`QM31`].
fn qm31_circle_gen() -> CirclePoint<QM31> {
    let x = qm31_const::<0x1, 0x0, 0x1C876E93, 0x1E9CA77B>();
    let y = qm31_const::<0x3B25121B, 0x26B12487, 0x2C1E6D83, 0x46B9D720>();
    CirclePoint { x, y }
}
