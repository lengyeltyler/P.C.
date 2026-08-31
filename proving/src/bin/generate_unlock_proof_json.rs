use std::io::{self, Read};

use anyhow::{Context, Result};
use serde_json::json;

use philcore_proving::codec::raw_unlock_proof_codec;
use philcore_proving::constants::STWO_UNLOCK_PROOF_TYPE;
use philcore_proving::prover::generate_proof;
use philcore_proving::types::{
    decode_hex_fixed, encode_hex, GenerateProofRequestJson, UnlockPublicInputs,
};

fn read_request() -> Result<GenerateProofRequestJson> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read stdin")?;
    Ok(serde_json::from_str(&input)?)
}

fn main() -> Result<()> {
    let request = read_request()?;
    let public_inputs = UnlockPublicInputs::try_from(request.public_inputs)?;
    let phil_secret = decode_hex_fixed(&request.phil_secret)?;
    let nullifier_seed = decode_hex_fixed(&request.nullifier_seed)?;
    let proof_bytes = generate_proof(public_inputs, phil_secret, nullifier_seed)?;

    println!(
        "{}",
        serde_json::to_string(&json!({
            "proofType": STWO_UNLOCK_PROOF_TYPE,
            "codec": raw_unlock_proof_codec(),
            "proofBlob": encode_hex(&proof_bytes),
        }))?
    );

    Ok(())
}
