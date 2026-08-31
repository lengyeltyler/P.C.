use core::array::ArrayTrait;
use core::box::{BoxImpl, BoxTrait};
use core::num::traits::DivRem;
use core::traits::TryInto;
use stwo_verifier_core::fields::m31::{M31, m31};
use stwo_verifier_core::utils::{SpanExTrait, pow2};
use stwo_verifier_core::vcs::blake2s_hasher::{Blake2sHash, Blake2sMerkleHasher};

#[derive(Copy, Drop, Serde)]
struct Blake2sHashWords {
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
struct MerkleProbeInput {
    root: Blake2sHashWords,
    tree_height: u32,
    column_log_deg_bounds: Array<u32>,
    query_positions: Array<u32>,
    queried_values: Array<u32>,
    hash_witness: Array<Blake2sHashWords>,
    expected_first_leaf_hash: Blake2sHashWords,
    expected_first_parent_hash: Blake2sHashWords,
}

#[derive(Drop, Serde)]
struct MerkleProbeResult {
    first_query_position: u32,
    n_columns: u32,
    first_parity: u32,
    first_sibling_from_witness: u32,
    first_leaf_matches_expected: u32,
    first_parent_matches_expected: u32,
    root_matches: u32,
    first_leaf_hash: Blake2sHashWords,
    first_sibling_hash: Blake2sHashWords,
    first_parent_hash: Blake2sHashWords,
    computed_root: Blake2sHashWords,
}

fn bool_to_u32(value: bool) -> u32 {
    if value { 1 } else { 0 }
}

fn hash_from_words(words: @Blake2sHashWords) -> Blake2sHash {
    Blake2sHash {
        hash: BoxImpl::new([
            (*words).w0,
            (*words).w1,
            (*words).w2,
            (*words).w3,
            (*words).w4,
            (*words).w5,
            (*words).w6,
            (*words).w7,
        ]),
    }
}

fn hash_to_words(hash: Blake2sHash) -> Blake2sHashWords {
    let [w0, w1, w2, w3, w4, w5, w6, w7] = hash.hash.unbox();
    Blake2sHashWords { w0, w1, w2, w3, w4, w5, w6, w7 }
}

fn m31_array_from_u32s(values: @Array<u32>) -> Array<M31> {
    let mut result = array![];
    for value in values.span() {
        result.append(m31(*value));
    }
    result
}

fn hash_witness_from_words(words: @Array<Blake2sHashWords>) -> Array<Blake2sHash> {
    let mut witness = array![];
    for hash_words in words.span() {
        witness.append(hash_from_words(hash_words));
    }
    witness
}

#[executable]
fn main(input: MerkleProbeInput) -> MerkleProbeResult {
    let root = hash_from_words(@input.root);
    let expected_first_leaf_hash = hash_from_words(@input.expected_first_leaf_hash);
    let expected_first_parent_hash = hash_from_words(@input.expected_first_parent_hash);
    let n_columns = input.column_log_deg_bounds.len();

    let mut queried_values = m31_array_from_u32s(@input.queried_values).span();
    let mut positions_and_hashes: Array<(usize, Blake2sHash)> = array![];

    let mut query_positions_iter = input.query_positions.span().into_iter();
    let mut prev_pos = query_positions_iter.next().unwrap();
    let mut prev_queried_values = queried_values.pop_front_n(n_columns);
    let layer_idx = pow2(input.tree_height);
    let first_leaf_hash = Blake2sMerkleHasher::hash_node(None, prev_queried_values);

    positions_and_hashes.append((layer_idx + *prev_pos, first_leaf_hash));

    for pos in query_positions_iter {
        let column_values = queried_values.pop_front_n(n_columns);
        if prev_pos == pos {
            assert!(prev_queried_values == column_values, "duplicate query values must match");
        } else {
            positions_and_hashes.append((layer_idx + *pos, Blake2sMerkleHasher::hash_node(None, column_values)));
        }
        prev_pos = pos;
        prev_queried_values = column_values;
    }
    assert!(queried_values.is_empty(), "unexpected queried values remainder");

    let mut hash_witness = hash_witness_from_words(@input.hash_witness).span();

    let (first_child_position, first_child_hash) = positions_and_hashes.pop_front().unwrap();
    let (first_parent_position, first_parity) = first_child_position.div_rem(2);
    assert!(first_parent_position != 0, "unexpected zero-height tree");

    let (first_sibling_hash, first_sibling_from_witness) = if first_parity == 1 {
        (hash_witness.pop_front().unwrap().clone(), true)
    } else if let Some((maybe_sibling_position, maybe_sibling_hash)) =
        positions_and_hashes.span().first() {
        if *maybe_sibling_position == first_child_position + 1 {
            let _ = positions_and_hashes.pop_front();
            (maybe_sibling_hash.clone(), false)
        } else {
            (hash_witness.pop_front().unwrap().clone(), true)
        }
    } else {
        (hash_witness.pop_front().unwrap().clone(), true)
    };

    let first_parent_hash = if first_parity == 1 {
        Blake2sMerkleHasher::hash_node(
            Some((first_sibling_hash.clone(), first_child_hash.clone())),
            array![].span(),
        )
    } else {
        Blake2sMerkleHasher::hash_node(
            Some((first_child_hash.clone(), first_sibling_hash.clone())),
            array![].span(),
        )
    };

    positions_and_hashes.append((first_parent_position, first_parent_hash.clone()));

    let computed_root = loop {
        let (child_position, child_hash) = positions_and_hashes.pop_front().unwrap();
        let (parent_position, parity) = child_position.div_rem(2);

        if parent_position == 0 {
            break child_hash;
        }

        if parity == 1 {
            let parent_hash = Blake2sMerkleHasher::hash_node(
                Some((hash_witness.pop_front().unwrap().clone(), child_hash.clone())),
                array![].span(),
            );
            positions_and_hashes.append((parent_position, parent_hash));
            continue;
        }

        let sibling_hash = if let Some((maybe_sibling_position, maybe_sibling_hash)) =
            positions_and_hashes.span().first() {
            if *maybe_sibling_position == child_position + 1 {
                let _ = positions_and_hashes.pop_front();
                maybe_sibling_hash.clone()
            } else {
                hash_witness.pop_front().unwrap().clone()
            }
        } else {
            hash_witness.pop_front().unwrap().clone()
        };

        let parent_hash = Blake2sMerkleHasher::hash_node(
            Some((child_hash.clone(), sibling_hash)),
            array![].span(),
        );
        positions_and_hashes.append((parent_position, parent_hash));
    };

    MerkleProbeResult {
        first_query_position: *input.query_positions.span().first().unwrap(),
        n_columns: n_columns.try_into().unwrap(),
        first_parity: first_parity.try_into().unwrap(),
        first_sibling_from_witness: bool_to_u32(first_sibling_from_witness),
        first_leaf_matches_expected: bool_to_u32(first_leaf_hash == expected_first_leaf_hash),
        first_parent_matches_expected: bool_to_u32(first_parent_hash == expected_first_parent_hash),
        root_matches: bool_to_u32(computed_root == root),
        first_leaf_hash: hash_to_words(first_leaf_hash),
        first_sibling_hash: hash_to_words(first_sibling_hash),
        first_parent_hash: hash_to_words(first_parent_hash),
        computed_root: hash_to_words(computed_root),
    }
}
