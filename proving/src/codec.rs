use anyhow::Result;
use bincode::Options;

use crate::constants::STWO_UNLOCK_RAW_PROOF_CODEC;
use crate::unlock_statement::UnlockStatementProof;

fn raw_unlock_proof_bincode_options() -> impl Options {
    bincode::DefaultOptions::new().reject_trailing_bytes()
}

pub fn raw_unlock_proof_codec() -> &'static str {
    STWO_UNLOCK_RAW_PROOF_CODEC
}

pub fn encode_raw_unlock_proof_bytes(proof: &UnlockStatementProof) -> Result<Vec<u8>> {
    Ok(raw_unlock_proof_bincode_options().serialize(proof)?)
}

pub fn decode_raw_unlock_proof_bytes(proof_bytes: &[u8]) -> Option<UnlockStatementProof> {
    raw_unlock_proof_bincode_options()
        .deserialize::<UnlockStatementProof>(proof_bytes)
        .ok()
}
