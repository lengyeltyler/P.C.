use anyhow::{anyhow, Result};
use tiny_keccak::{Hasher, Keccak};

use crate::constants::{
    DOMAIN_IDENTITY_ROOT, DOMAIN_NULLIFIER, DOMAIN_OWNER_COMMITMENT, DOMAIN_UNLOCK_PROOF_INPUTS,
    STWO_UNLOCK_PROOF_TYPE, STWO_UNLOCK_PROOF_VERSION,
};
use crate::types::UnlockPublicInputs;

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    let mut keccak = Keccak::v256();
    keccak.update(bytes);
    keccak.finalize(&mut output);
    output
}

pub fn domain_hash(label: &str) -> [u8; 32] {
    keccak256(label.as_bytes())
}

fn encode_u256_word_from_usize(value: usize) -> [u8; 32] {
    let mut word = [0_u8; 32];
    let bytes = (value as u64).to_be_bytes();
    word[24..].copy_from_slice(&bytes);
    word
}

fn encode_u64_word(value: u64) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn encode_string_tail(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let padded_len = bytes.len().next_multiple_of(32);
    let mut encoded = Vec::with_capacity(32 + padded_len);
    encoded.extend_from_slice(&encode_u256_word_from_usize(bytes.len()));
    encoded.extend_from_slice(bytes);
    encoded.resize(32 + padded_len, 0);
    encoded
}

pub fn encode_identity_root_preimage(phil_secret: &[u8; 32]) -> [u8; 64] {
    let mut encoded = [0_u8; 64];
    encoded[..32].copy_from_slice(&domain_hash(DOMAIN_IDENTITY_ROOT));
    encoded[32..].copy_from_slice(phil_secret);
    encoded
}

pub fn encode_owner_commitment_preimage(identity_root: &[u8; 32]) -> [u8; 64] {
    let mut encoded = [0_u8; 64];
    encoded[..32].copy_from_slice(&domain_hash(DOMAIN_OWNER_COMMITMENT));
    encoded[32..].copy_from_slice(identity_root);
    encoded
}

pub fn encode_nullifier_preimage(
    owner_commitment: &[u8; 32],
    action_hash: &[u8; 32],
    policy_hash: &[u8; 32],
    nullifier_seed: &[u8; 32],
) -> [u8; 160] {
    let mut encoded = [0_u8; 160];
    encoded[..32].copy_from_slice(&domain_hash(DOMAIN_NULLIFIER));
    encoded[32..64].copy_from_slice(owner_commitment);
    encoded[64..96].copy_from_slice(action_hash);
    encoded[96..128].copy_from_slice(policy_hash);
    encoded[128..160].copy_from_slice(nullifier_seed);
    encoded
}

pub fn encode_proof_input_hash_preimage(
    version: &str,
    proof_type: &str,
    public_inputs: &UnlockPublicInputs,
) -> Result<[u8; 416]> {
    let version_tail = encode_string_tail(version);
    let proof_type_tail = encode_string_tail(proof_type);
    let head_words = 9;
    let version_offset = 32 * head_words;
    let proof_type_offset = version_offset + version_tail.len();

    let mut encoded = Vec::with_capacity(416);
    encoded.extend_from_slice(&domain_hash(DOMAIN_UNLOCK_PROOF_INPUTS));
    encoded.extend_from_slice(&encode_u256_word_from_usize(version_offset));
    encoded.extend_from_slice(&encode_u256_word_from_usize(proof_type_offset));
    encoded.extend_from_slice(&public_inputs.owner_commitment);
    encoded.extend_from_slice(&public_inputs.action_hash);
    encoded.extend_from_slice(&public_inputs.policy_hash);
    encoded.extend_from_slice(&public_inputs.nullifier);
    encoded.extend_from_slice(&public_inputs.consumer_data_hash);
    encoded.extend_from_slice(&encode_u64_word(public_inputs.expiry));
    encoded.extend_from_slice(&version_tail);
    encoded.extend_from_slice(&proof_type_tail);

    if encoded.len() != 416 {
        return Err(anyhow!(
            "unexpected proofInputHash preimage length: {}",
            encoded.len()
        ));
    }

    encoded
        .try_into()
        .map_err(|_| anyhow!("failed to encode proofInputHash preimage"))
}

pub fn derive_identity_root(phil_secret: &[u8; 32]) -> [u8; 32] {
    keccak256(&encode_identity_root_preimage(phil_secret))
}

pub fn derive_owner_commitment(phil_secret: &[u8; 32]) -> [u8; 32] {
    keccak256(&encode_owner_commitment_preimage(&derive_identity_root(
        phil_secret,
    )))
}

pub fn derive_nullifier(
    owner_commitment: &[u8; 32],
    action_hash: &[u8; 32],
    policy_hash: &[u8; 32],
    nullifier_seed: &[u8; 32],
) -> [u8; 32] {
    keccak256(&encode_nullifier_preimage(
        owner_commitment,
        action_hash,
        policy_hash,
        nullifier_seed,
    ))
}

pub fn derive_proof_input_hash(public_inputs: &UnlockPublicInputs) -> Result<[u8; 32]> {
    Ok(keccak256(&encode_proof_input_hash_preimage(
        STWO_UNLOCK_PROOF_VERSION,
        STWO_UNLOCK_PROOF_TYPE,
        public_inputs,
    )?))
}
