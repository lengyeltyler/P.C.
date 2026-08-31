// STEP 3 LOCAL REFERENCE CIRCUIT ONLY.
// This proves knowledge of the Phil root secret for one exact scoped identity
// and one exceptional authorization envelope. It grants no runtime authority.

global IDENTITY_ROOT_DOMAIN: [u8; 32] = [
    173, 242, 93, 18, 172, 23, 116, 115,
    104, 52, 192, 17, 210, 255, 218, 47,
    50, 148, 65, 148, 242, 225, 143, 94,
    199, 96, 201, 180, 180, 234, 105, 62,
];

global SCOPED_OWNER_COMMITMENT_DOMAIN: [u8; 32] = [
    123, 203, 61, 111, 216, 9, 73, 145,
    178, 114, 93, 166, 245, 65, 100, 223,
    97, 242, 44, 33, 96, 33, 20, 224,
    185, 143, 172, 192, 167, 174, 85, 5,
];

global ROOT_PROOF_NULLIFIER_DOMAIN: [u8; 32] = [
    253, 11, 69, 206, 229, 23, 95, 42,
    99, 132, 86, 213, 90, 83, 122, 133,
    177, 221, 88, 228, 23, 196, 231, 56,
    194, 218, 23, 34, 40, 32, 77, 139,
];

fn lane_from_8_bytes(input: [u8; 8]) -> u64 {
    let mut lane: u64 = 0;
    for i in 0..8 {
        lane = lane | ((input[i] as u64) << ((8 * i) as u64));
    }
    lane
}

fn first_32_bytes(state: [u64; 25]) -> [u8; 32] {
    let mut output = [0; 32];
    for lane_index in 0..4 {
        for byte_index in 0..8 {
            output[lane_index * 8 + byte_index] =
                ((state[lane_index] >> ((8 * byte_index) as u64)) & 255) as u8;
        }
    }
    output
}

fn keccak256_64(input: [u8; 64]) -> [u8; 32] {
    let mut state = [0; 25];
    for lane_index in 0..8 {
        let mut lane_bytes = [0; 8];
        for byte_index in 0..8 {
            lane_bytes[byte_index] = input[lane_index * 8 + byte_index];
        }
        state[lane_index] = lane_from_8_bytes(lane_bytes);
    }
    state[8] = 1;
    state[16] = 0x8000000000000000;
    first_32_bytes(std::hash::keccakf1600(state))
}

fn keccak256_128(input: [u8; 128]) -> [u8; 32] {
    let mut state = [0; 25];
    for lane_index in 0..16 {
        let mut lane_bytes = [0; 8];
        for byte_index in 0..8 {
            lane_bytes[byte_index] = input[lane_index * 8 + byte_index];
        }
        state[lane_index] = lane_from_8_bytes(lane_bytes);
    }
    state[16] = 0x8000000000000001;
    first_32_bytes(std::hash::keccakf1600(state))
}

fn keccak256_160(input: [u8; 160]) -> [u8; 32] {
    let mut state = [0; 25];
    for lane_index in 0..17 {
        let mut lane_bytes = [0; 8];
        for byte_index in 0..8 {
            lane_bytes[byte_index] = input[lane_index * 8 + byte_index];
        }
        state[lane_index] = lane_from_8_bytes(lane_bytes);
    }
    state = std::hash::keccakf1600(state);

    for lane_index in 0..3 {
        let mut lane_bytes = [0; 8];
        for byte_index in 0..8 {
            lane_bytes[byte_index] = input[136 + lane_index * 8 + byte_index];
        }
        state[lane_index] = state[lane_index] ^ lane_from_8_bytes(lane_bytes);
    }
    state[3] = state[3] ^ 1;
    state[16] = state[16] ^ 0x8000000000000000;
    first_32_bytes(std::hash::keccakf1600(state))
}

fn u128_pair_to_bytes(high: u128, low: u128) -> [u8; 32] {
    let mut output = [0; 32];
    for i in 0..16 {
        let high_shift = (8 * (15 - i)) as u128;
        let low_shift = (8 * (15 - i)) as u128;
        output[i] = ((high >> high_shift) & 255) as u8;
        output[i + 16] = ((low >> low_shift) & 255) as u8;
    }
    output
}

fn u64_to_abi_word(value: u64) -> [u8; 32] {
    let mut output = [0; 32];
    for i in 0..8 {
        let shift = (8 * (7 - i)) as u64;
        output[i + 24] = ((value >> shift) & 255) as u8;
    }
    output
}

fn require_non_zero(value: [u8; 32]) {
    let mut aggregate: u8 = 0;
    for i in 0..32 {
        aggregate = aggregate | value[i];
    }
    assert(aggregate != 0);
}

fn main(
    phil_secret: [u8; 32],
    nullifier_seed: [u8; 32],
    scoped_owner_commitment_high: pub u128,
    scoped_owner_commitment_low: pub u128,
    scope_id_high: pub u128,
    scope_id_low: pub u128,
    scope_instance_high: pub u128,
    scope_instance_low: pub u128,
    scope_epoch: pub u64,
    authorization_envelope_digest_high: pub u128,
    authorization_envelope_digest_low: pub u128,
    root_proof_nullifier_high: pub u128,
    root_proof_nullifier_low: pub u128,
    proof_descriptor_hash_high: pub u128,
    proof_descriptor_hash_low: pub u128,
) {
    let scoped_owner_commitment = u128_pair_to_bytes(
        scoped_owner_commitment_high,
        scoped_owner_commitment_low,
    );
    let scope_id = u128_pair_to_bytes(scope_id_high, scope_id_low);
    let scope_instance = u128_pair_to_bytes(scope_instance_high, scope_instance_low);
    let authorization_envelope_digest = u128_pair_to_bytes(
        authorization_envelope_digest_high,
        authorization_envelope_digest_low,
    );
    let root_proof_nullifier = u128_pair_to_bytes(
        root_proof_nullifier_high,
        root_proof_nullifier_low,
    );
    let proof_descriptor_hash = u128_pair_to_bytes(
        proof_descriptor_hash_high,
        proof_descriptor_hash_low,
    );

    require_non_zero(phil_secret);
    require_non_zero(nullifier_seed);
    require_non_zero(scoped_owner_commitment);
    require_non_zero(scope_id);
    require_non_zero(scope_instance);
    require_non_zero(authorization_envelope_digest);
    require_non_zero(root_proof_nullifier);
    require_non_zero(proof_descriptor_hash);
    // PhilSecret is a non-zero element of the canonical 251-bit root range.
    // The five high bits of the first big-endian byte must therefore be zero.
    assert(phil_secret[0] < 8);
    assert(scope_epoch != 0);

    let mut identity_preimage = [0; 64];
    for i in 0..32 {
        identity_preimage[i] = IDENTITY_ROOT_DOMAIN[i];
        identity_preimage[i + 32] = phil_secret[i];
    }
    let identity_root = keccak256_64(identity_preimage);

    let mut scoped_preimage = [0; 160];
    let scope_epoch_word = u64_to_abi_word(scope_epoch);
    for i in 0..32 {
        scoped_preimage[i] = SCOPED_OWNER_COMMITMENT_DOMAIN[i];
        scoped_preimage[i + 32] = identity_root[i];
        scoped_preimage[i + 64] = scope_id[i];
        scoped_preimage[i + 96] = scope_instance[i];
        scoped_preimage[i + 128] = scope_epoch_word[i];
    }
    let derived_scoped_owner_commitment = keccak256_160(scoped_preimage);

    let mut nullifier_preimage = [0; 128];
    for i in 0..32 {
        nullifier_preimage[i] = ROOT_PROOF_NULLIFIER_DOMAIN[i];
        nullifier_preimage[i + 32] = derived_scoped_owner_commitment[i];
        nullifier_preimage[i + 64] = authorization_envelope_digest[i];
        nullifier_preimage[i + 96] = nullifier_seed[i];
    }
    let derived_root_proof_nullifier = keccak256_128(nullifier_preimage);

    // proof_descriptor_hash is a required public verifier/adaptor binding. It
    // cannot be derived in-circuit because the descriptor includes the VK and
    // generated Cairo verifier hashes, which are downstream of this circuit.
    assert(derived_scoped_owner_commitment == scoped_owner_commitment);
    assert(derived_root_proof_nullifier == root_proof_nullifier);
}
