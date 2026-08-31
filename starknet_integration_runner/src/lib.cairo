use phil_cairo_air_adapter_spike::{
    ProofInputHashSliceClaim, StarkProofMirror, VerificationFactPayload,
};
use phil_starknet_integration::verify_proof_input_hash_slice_fact;

#[executable]
fn main(proof: StarkProofMirror, claim: ProofInputHashSliceClaim) -> VerificationFactPayload {
    verify_proof_input_hash_slice_fact(proof, claim)
}
