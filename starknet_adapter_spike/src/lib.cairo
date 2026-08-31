use core::{integer::u128_byte_reverse, keccak::keccak_u256s_be_inputs};

#[derive(Copy, Drop, Serde)]
pub struct U256Parts {
    pub high: u128,
    pub low: u128,
}

#[derive(Copy, Drop, Serde)]
pub struct UnlockProofPublicInputsParts {
    pub owner_commitment: U256Parts,
    pub action_hash: U256Parts,
    pub policy_hash: U256Parts,
    pub nullifier: U256Parts,
    pub consumer_data_hash: U256Parts,
    pub expiry: u64,
}

#[derive(Drop, Serde)]
pub struct SecureFieldWords {
    pub a0: u32,
    pub a1: u32,
    pub a2: u32,
    pub a3: u32,
}

#[derive(Drop, Serde)]
pub struct Blake2sHashWords {
    pub w0: u32,
    pub w1: u32,
    pub w2: u32,
    pub w3: u32,
    pub w4: u32,
    pub w5: u32,
    pub w6: u32,
    pub w7: u32,
}

#[derive(Drop, Serde)]
pub struct MerkleDecommitmentMirror {
    pub hash_witness: Array<Blake2sHashWords>,
}

#[derive(Drop, Serde)]
pub struct FriConfigMirror {
    pub log_blowup_factor: u32,
    pub log_last_layer_degree_bound: u32,
    pub n_queries: u32,
}

#[derive(Drop, Serde)]
pub struct PcsConfigMirror {
    pub pow_bits: u32,
    pub fri_config: FriConfigMirror,
}

#[derive(Drop, Serde)]
pub struct FriLayerProofMirror {
    pub fri_witness: Array<SecureFieldWords>,
    pub decommitment: MerkleDecommitmentMirror,
    pub commitment: Blake2sHashWords,
}

#[derive(Drop, Serde)]
pub struct LinePolyMirror {
    pub coeffs: Array<SecureFieldWords>,
    pub log_size: u32,
}

#[derive(Drop, Serde)]
pub struct FriProofMirror {
    pub first_layer: FriLayerProofMirror,
    pub inner_layers: Array<FriLayerProofMirror>,
    pub last_layer_poly: LinePolyMirror,
}

#[derive(Drop, Serde)]
pub struct CommitmentSchemeProofMirror {
    pub config: PcsConfigMirror,
    pub commitments: Array<Blake2sHashWords>,
    pub sampled_values: Array<Array<Array<SecureFieldWords>>>,
    pub decommitments: Array<MerkleDecommitmentMirror>,
    pub queried_values: Array<Array<Array<u32>>>,
    pub proof_of_work: u64,
    pub fri_proof: FriProofMirror,
}

#[derive(Drop, Serde)]
pub struct StarkProofMirror {
    pub commitment_scheme_proof: CommitmentSchemeProofMirror,
}

#[derive(Drop, Serde)]
pub struct AdapterReplaySummary {
    pub pow_bits: u32,
    pub fri_queries: u32,
    pub commitment_count: u32,
    pub sampled_value_tree_count: u32,
    pub sampled_value_column_count: u32,
    pub decommitment_count: u32,
    pub queried_value_tree_count: u32,
    pub queried_value_column_count: u32,
    pub fri_inner_layer_count: u32,
    pub proof_of_work: u64,
    pub owner_commitment_high: u128,
    pub owner_commitment_low: u128,
    pub expiry: u64,
}

const DOMAIN_UNLOCK_PROOF_INPUTS: u256 = u256 {
    low: 40939354700605103392208583007457411596,
    high: 268639054636231164950625640019345971342,
};
const VERSION_OFFSET: u256 = u256 { low: 288, high: 0 };
const PROOF_TYPE_OFFSET: u256 = u256 { low: 352, high: 0 };
const VERSION_LENGTH_WORD: u256 = u256 { low: 2, high: 0 };
const VERSION_BYTES_WORD: u256 = u256 {
    low: 0,
    high: 157103326048688279556447227433212444672,
};
const PROOF_TYPE_LENGTH_WORD: u256 = u256 { low: 21, high: 0 };
const PROOF_TYPE_BYTES_WORD: u256 = u256 {
    low: 129491613427520172717528869986428256256,
    high: 153465948365993030244412564244095394659,
};

fn u256_from_parts(parts: @U256Parts) -> u256 {
    u256 { high: (*parts).high, low: (*parts).low }
}

fn u256_from_u64(value: u64) -> u256 {
    u256 { low: value.into(), high: 0 }
}

fn flip_endianness_u256(value: u256) -> u256 {
    u256 { low: u128_byte_reverse(value.high), high: u128_byte_reverse(value.low) }
}

fn locked_proof_input_words(public_inputs: @UnlockProofPublicInputsParts) -> Array<u256> {
    let mut words = array![];
    words.append(DOMAIN_UNLOCK_PROOF_INPUTS);
    words.append(VERSION_OFFSET);
    words.append(PROOF_TYPE_OFFSET);
    words.append(u256_from_parts(@(*public_inputs).owner_commitment));
    words.append(u256_from_parts(@(*public_inputs).action_hash));
    words.append(u256_from_parts(@(*public_inputs).policy_hash));
    words.append(u256_from_parts(@(*public_inputs).nullifier));
    words.append(u256_from_parts(@(*public_inputs).consumer_data_hash));
    words.append(u256_from_u64((*public_inputs).expiry));
    words.append(VERSION_LENGTH_WORD);
    words.append(VERSION_BYTES_WORD);
    words.append(PROOF_TYPE_LENGTH_WORD);
    words.append(PROOF_TYPE_BYTES_WORD);
    words
}

fn derive_locked_proof_input_hash(public_inputs: @UnlockProofPublicInputsParts) -> u256 {
    let words = locked_proof_input_words(public_inputs);
    flip_endianness_u256(keccak_u256s_be_inputs(words.span()))
}

fn proof_input_hash_payload(hash: u256) -> Array<felt252> {
    let mut payload = array![];
    payload.append(hash.high.into());
    payload.append(hash.low.into());
    payload
}

fn count_nested_secure_columns(values: @Array<Array<Array<SecureFieldWords>>>) -> u32 {
    let mut outer_index = 0;
    let mut count = 0;
    loop {
        if outer_index >= (*values).len() {
            break;
        }
        count += (*(*values).at(outer_index)).len();
        outer_index += 1;
    };
    count
}

fn count_nested_base_columns(values: @Array<Array<Array<u32>>>) -> u32 {
    let mut outer_index = 0;
    let mut count = 0;
    loop {
        if outer_index >= (*values).len() {
            break;
        }
        count += (*(*values).at(outer_index)).len();
        outer_index += 1;
    };
    count
}

#[executable]
fn main(proof: StarkProofMirror, public_inputs: UnlockProofPublicInputsParts) -> AdapterReplaySummary {
    let commitment_scheme_proof = proof.commitment_scheme_proof;

    assert(commitment_scheme_proof.commitments.len() > 0, 'no_commitments');
    assert(commitment_scheme_proof.decommitments.len() > 0, 'no_decommitments');

    let sampled_value_column_count =
        count_nested_secure_columns(@commitment_scheme_proof.sampled_values);
    let queried_value_column_count =
        count_nested_base_columns(@commitment_scheme_proof.queried_values);

    AdapterReplaySummary {
        pow_bits: commitment_scheme_proof.config.pow_bits,
        fri_queries: commitment_scheme_proof.config.fri_config.n_queries,
        commitment_count: commitment_scheme_proof.commitments.len(),
        sampled_value_tree_count: commitment_scheme_proof.sampled_values.len(),
        sampled_value_column_count,
        decommitment_count: commitment_scheme_proof.decommitments.len(),
        queried_value_tree_count: commitment_scheme_proof.queried_values.len(),
        queried_value_column_count,
        fri_inner_layer_count: commitment_scheme_proof.fri_proof.inner_layers.len(),
        proof_of_work: commitment_scheme_proof.proof_of_work,
        owner_commitment_high: public_inputs.owner_commitment.high,
        owner_commitment_low: public_inputs.owner_commitment.low,
        expiry: public_inputs.expiry,
    }
}
