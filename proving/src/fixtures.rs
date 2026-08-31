use anyhow::Result;

use crate::abi::{
    derive_identity_root, derive_nullifier, derive_owner_commitment, derive_proof_input_hash,
    encode_identity_root_preimage, encode_nullifier_preimage, encode_owner_commitment_preimage,
    encode_proof_input_hash_preimage,
};
use crate::types::{UnlockFixtureVector, UnlockFixtureVectorJson};

const DEFAULT_VECTOR_JSON: &str = include_str!("../fixtures/unlock_keccak_vector.json");

pub fn load_default_vector() -> Result<UnlockFixtureVector> {
    let json: UnlockFixtureVectorJson = serde_json::from_str(DEFAULT_VECTOR_JSON)?;
    let vector: UnlockFixtureVector = json.try_into()?;
    assert_vector(&vector)?;
    Ok(vector)
}

pub fn assert_vector(vector: &UnlockFixtureVector) -> Result<()> {
    let identity_root = derive_identity_root(&vector.phil_secret);
    let owner_commitment = derive_owner_commitment(&vector.phil_secret);
    let nullifier = derive_nullifier(
        &vector.public_inputs.owner_commitment,
        &vector.public_inputs.action_hash,
        &vector.public_inputs.policy_hash,
        &vector.nullifier_seed,
    );
    let proof_input_hash = derive_proof_input_hash(&vector.public_inputs)?;

    anyhow::ensure!(
        vector.identity_root_preimage == encode_identity_root_preimage(&vector.phil_secret)
    );
    anyhow::ensure!(vector.identity_root_hash == identity_root);
    anyhow::ensure!(
        vector.owner_commitment_preimage == encode_owner_commitment_preimage(&identity_root)
    );
    anyhow::ensure!(vector.owner_commitment_hash == owner_commitment);
    anyhow::ensure!(
        vector.nullifier_preimage
            == encode_nullifier_preimage(
                &vector.public_inputs.owner_commitment,
                &vector.public_inputs.action_hash,
                &vector.public_inputs.policy_hash,
                &vector.nullifier_seed,
            )
    );
    anyhow::ensure!(vector.nullifier_hash == nullifier);
    anyhow::ensure!(
        vector.proof_input_hash_preimage
            == encode_proof_input_hash_preimage(
                &vector.version,
                &vector.proof_type,
                &vector.public_inputs
            )?
    );
    anyhow::ensure!(vector.proof_input_hash_value == proof_input_hash);
    anyhow::ensure!(vector.public_inputs.owner_commitment == vector.owner_commitment_hash);
    anyhow::ensure!(vector.public_inputs.nullifier == vector.nullifier_hash);
    Ok(())
}
