use std::io::{self, Read};

use anyhow::{Context, Result};
use serde_json::json;

use philcore_proving::codec::raw_unlock_proof_codec;
use philcore_proving::constants::{STWO_UNLOCK_PROOF_TYPE, STWO_UNLOCK_PROOF_VERSION};
use philcore_proving::types::{
    decode_hex_vec, VerifyProofRequestJson, UnlockPublicInputs,
};
use philcore_proving::verifier::verify_proof;

fn read_request() -> Result<VerifyProofRequestJson> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read stdin")?;
    Ok(serde_json::from_str(&input)?)
}

fn main() -> Result<()> {
    let request = read_request()?;
    let proof_blob = decode_hex_vec(&request.proof_blob)?;
    let public_inputs = UnlockPublicInputs::try_from(request.public_inputs)?;
    let verified = verify_proof(&proof_blob, public_inputs);

    println!(
        "{}",
        serde_json::to_string(&json!({
            "verified": verified,
            "version": STWO_UNLOCK_PROOF_VERSION,
            "proofType": STWO_UNLOCK_PROOF_TYPE,
            "codec": raw_unlock_proof_codec(),
        }))?
    );

    Ok(())
}
