# Phil V1 Step 3 Noir Root-Proof Reference

This directory contains a local-only, non-production Noir reference circuit for
Phil V1 exceptional root proofs. It proves knowledge of the Phil root secret
for one exact scoped identity and authorization digest. It does not prove device
possession, grant account authority, or expose an RPC, signer, declaration,
deployment, or transaction path.

## Exact compatibility lane

- Nargo `1.0.0-beta.16`
- Barretenberg `3.0.0-nightly.20251104`
- UltraKeccakZK Honk (`--scheme ultra_honk --oracle_hash keccak`, with zero
  knowledge enabled by default)
- Garaga `1.0.1`

The versions are selected because Garaga `1.0.1` supports this exact proof and
verification-key format. They are compatibility pins, not a production backend
selection.

## Contents

- `src/main.nr`: exact Phil scoped-identity and root-nullifier relation;
- `Prover.toml`: disclosed synthetic witness only;
- `fixtures/canonical-vector.json`: independently derived TypeScript vector;
- `artifacts/descriptor.json`: exact circuit/key/verifier/schema/codec binding;
- `artifacts/phil_v1_step3_root_proof.json`: compiled ACIR artifact;
- `artifacts/vk` and `vk_hash`: exact Barretenberg verification key artifacts;
- `artifacts/synthetic_proof` and `synthetic_public_inputs`: accepted synthetic
  reference proof; and
- the generated Cairo verifier under `starknet/phil-v1-step3-verifier`.

## Public-input codec

The seven logical public inputs are encoded as 13 native public values. Each
`bytes32` is split into big-endian high and low `u128` values; `scopeEpoch` is
one `u64` between the scope and authorization fields. This avoids unsafe
bytes-to-felt reduction while preserving the architecture's exact logical
order.

The descriptor hash is public and constrained non-zero in the circuit. The
reference adapter must additionally compare it with the exact admitted
descriptor hash. The descriptor cannot be derived inside the circuit because
it includes hashes of the verification key and generated verifier, which are
downstream products of the circuit.

## Local verification

From the repository root:

```text
npm run test:phil-v1-step3-root-proof-adapter
npm run test:phil-v1-step3-noir
npm run verify:phil-v1-step3-artifacts
```

The Noir test uses only the pinned tools in
`~/.cache/phil-v1-step3` (or `PHIL_STEP3_CACHE_DIR`). It checks the valid
witness, ten circuit-level mismatches, native proof verification, malformed
proof rejection, proof randomization, and absence of both disclosed private
literals from serialized proof artifacts.

No iPhone proving claim is made. No real secret may be placed in this tree.
