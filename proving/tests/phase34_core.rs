use philcore_proving::fixtures::load_default_vector;
use philcore_proving::keccak_compat::{
    prove_identity_root, prove_nullifier, prove_owner_commitment, prove_proof_input_hash,
    verify_identity_root, verify_nullifier, verify_owner_commitment, verify_proof_input_hash,
    verify_tampered_failure,
};
use philcore_proving::prover::generate_proof;
use philcore_proving::types::GenerateProofInput;
use philcore_proving::unlock_statement::{prove_unlock_owner_path, verify_unlock_owner_path};
use philcore_proving::verifier::verify_proof;

#[test]
fn loads_the_golden_fixture_vector() {
    let vector = load_default_vector().expect("fixture vector should load");
    assert_eq!(vector.version, "v1");
    assert_eq!(vector.proof_type, "stwo-unlock-keccak-v1");
}

#[test]
fn keccak_compat_component_proves_all_four_hash_vectors() {
    let vector = load_default_vector().expect("fixture vector should load");

    let identity_root_proof =
        prove_identity_root(&vector).expect("identityRoot proof should succeed");
    verify_identity_root(&identity_root_proof, &vector).expect("identityRoot proof should verify");

    let owner_commitment_proof =
        prove_owner_commitment(&vector).expect("ownerCommitment proof should succeed");
    verify_owner_commitment(&owner_commitment_proof, &vector)
        .expect("ownerCommitment proof should verify");

    let nullifier_proof = prove_nullifier(&vector).expect("nullifier proof should succeed");
    verify_nullifier(&nullifier_proof, &vector).expect("nullifier proof should verify");

    let proof_input_hash_proof =
        prove_proof_input_hash(&vector).expect("proofInputHash proof should succeed");
    verify_proof_input_hash(&proof_input_hash_proof, &vector)
        .expect("proofInputHash proof should verify");
}

#[test]
fn keccak_compat_component_rejects_tampered_bytes() {
    let vector = load_default_vector().expect("fixture vector should load");
    let proof = prove_proof_input_hash(&vector).expect("proofInputHash proof should succeed");
    assert!(verify_tampered_failure(&proof, &vector).is_err());
}

#[test]
fn minimal_unlock_statement_proof_round_trips() {
    let vector = load_default_vector().expect("fixture vector should load");
    let proof_bytes = generate_proof(
        vector.public_inputs.clone(),
        vector.phil_secret,
        vector.nullifier_seed,
    )
    .expect("proof generation should succeed");

    assert!(verify_proof(&proof_bytes, vector.public_inputs));
}

#[test]
fn unlock_owner_path_subcomponent_round_trips() {
    let vector = load_default_vector().expect("fixture vector should load");
    let input = GenerateProofInput {
        public_inputs: vector.public_inputs.clone(),
        phil_secret: vector.phil_secret,
        nullifier_seed: vector.nullifier_seed,
    };

    let proof =
        prove_unlock_owner_path(&input).expect("owner-path proof generation should succeed");
    verify_unlock_owner_path(&proof, &vector.public_inputs)
        .expect("owner-path proof should verify");
}

#[test]
fn unlock_owner_path_rejects_tampered_owner_commitment() {
    let vector = load_default_vector().expect("fixture vector should load");
    let input = GenerateProofInput {
        public_inputs: vector.public_inputs.clone(),
        phil_secret: vector.phil_secret,
        nullifier_seed: vector.nullifier_seed,
    };

    let proof =
        prove_unlock_owner_path(&input).expect("owner-path proof generation should succeed");
    let mut tampered = vector.public_inputs;
    tampered.owner_commitment[0] ^= 0x01;

    assert!(verify_unlock_owner_path(&proof, &tampered).is_err());
}

#[test]
fn wrong_phil_secret_produces_invalid_proof() {
    let vector = load_default_vector().expect("fixture vector should load");
    let mut wrong_secret = vector.phil_secret;
    wrong_secret[31] ^= 0x01;

    match generate_proof(
        vector.public_inputs.clone(),
        wrong_secret,
        vector.nullifier_seed,
    ) {
        Ok(proof_bytes) => assert!(!verify_proof(&proof_bytes, vector.public_inputs)),
        Err(_) => {}
    }
}

#[test]
fn wrong_nullifier_seed_produces_invalid_proof() {
    let vector = load_default_vector().expect("fixture vector should load");
    let mut wrong_seed = vector.nullifier_seed;
    wrong_seed[31] ^= 0x01;

    match generate_proof(vector.public_inputs.clone(), vector.phil_secret, wrong_seed) {
        Ok(proof_bytes) => assert!(!verify_proof(&proof_bytes, vector.public_inputs)),
        Err(_) => {}
    }
}

#[test]
fn verify_proof_rejects_tampered_public_inputs() {
    let vector = load_default_vector().expect("fixture vector should load");
    let proof_bytes = generate_proof(
        vector.public_inputs.clone(),
        vector.phil_secret,
        vector.nullifier_seed,
    )
    .expect("proof generation should succeed");

    let mut tampered_public_inputs = vector.public_inputs;
    tampered_public_inputs.action_hash[0] ^= 0x01;

    assert!(!verify_proof(&proof_bytes, tampered_public_inputs));
}

#[test]
fn verify_proof_rejects_tampered_consumer_data_hash() {
    let vector = load_default_vector().expect("fixture vector should load");
    let proof_bytes = generate_proof(
        vector.public_inputs.clone(),
        vector.phil_secret,
        vector.nullifier_seed,
    )
    .expect("proof generation should succeed");

    let mut tampered_public_inputs = vector.public_inputs;
    tampered_public_inputs.consumer_data_hash[0] ^= 0x01;

    assert!(!verify_proof(&proof_bytes, tampered_public_inputs));
}

#[test]
fn verify_proof_rejects_tampered_proof() {
    let vector = load_default_vector().expect("fixture vector should load");
    let mut proof_bytes = generate_proof(
        vector.public_inputs.clone(),
        vector.phil_secret,
        vector.nullifier_seed,
    )
    .expect("proof generation should succeed");
    proof_bytes.pop();

    assert!(!verify_proof(&proof_bytes, vector.public_inputs));
}
