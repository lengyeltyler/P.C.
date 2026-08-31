use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use philcore_proving::fixtures::load_default_vector;
use philcore_proving::prover::generate_proof;

fn main() -> Result<()> {
    let out_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("proving/out/phase34-proof.bin"));

    let vector = load_default_vector()?;
    let proof = generate_proof(
        vector.public_inputs.clone(),
        vector.phil_secret,
        vector.nullifier_seed,
    )?;

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&out_path, proof)
        .with_context(|| format!("failed to write {}", out_path.display()))?;
    println!("{}", out_path.display());
    Ok(())
}
