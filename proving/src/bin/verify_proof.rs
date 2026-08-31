use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use philcore_proving::fixtures::load_default_vector;
use philcore_proving::verifier::verify_proof;

fn main() -> Result<()> {
    let proof_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("proving/out/phase34-proof.bin"));

    let vector = load_default_vector()?;
    let proof_bytes = fs::read(&proof_path)
        .with_context(|| format!("failed to read {}", proof_path.display()))?;

    if !verify_proof(&proof_bytes, vector.public_inputs) {
        bail!("verification failed");
    }

    println!("verified");
    Ok(())
}
