# Phil V1 Step 3 Generated Starknet Verifier

This is the Garaga `1.0.1` generated UltraKeccakZK Honk verifier for the exact
verification key in `proofs/phil-v1-step3-noir/artifacts/vk`.

It is a local reference artifact only. It has no account, signer, RPC URL,
deployment script, transaction function, or Phil runtime reachability. The
local test declares the class only inside Starknet Foundry's isolated test
state, uses no fork or network endpoint, verifies the canonical synthetic
proof, checks all 13 packed public inputs are returned, and rejects a tampered
public input.

The generator and local build both pin Cairo/Scarb `2.14.0`. That exact local
result does not promote either compiler or the proof backend to production
status.

The generated files under `src/` must not be edited by hand. Any circuit,
verification-key, Garaga, Cairo, schema, or codec change requires regeneration,
new artifact hashes, new measurements, and independent review.
