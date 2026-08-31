# Starknet Toolchain And Artifact Reproducibility

## Purpose

Phase M.6A.1 establishes the local reproducibility boundary for the Starknet verified-fact publication path.

This is not transaction preparation, deployment, production Runtime authority, or fact publication. It is a safe local build/check path for proving that the current Cairo/Rust artifacts can be rebuilt and inspected before a later configuration or transaction milestone.

## Pinned Toolchain

The single toolchain reference is:

```text
config/starknet-toolchain.json
```

Pinned versions:

- Scarb: `2.15.0`
- Cairo tools: `2.15.0`
- Rust nightly: `nightly-2025-07-14`
- Node.js: `>=22.0.0`

Evidence:

- `Scarb.toml` files use Cairo package dependencies such as `starknet = "2.15.0"` and `cairo_execute = "2.15.0"`.
- `Scarb.toml` package edition is `2024_07`.
- `package.json` uses `cargo +nightly-2025-07-14` for proving tests.
- `package.json` declares Node.js `>=22.0.0`.

Starknet Foundry is not required by the current M.6A.1 harness path.

## Toolchain Check

Run:

```bash
npm run check:starknet-toolchain
```

The checker:

- reports installed versions;
- reports expected versions;
- fails on missing or mismatched Scarb/Cairo tools;
- does not install tools;
- does not modify user configuration.

Current environment result when M.6A.1 was run:

```text
scarb: missing
cairo-execute: missing
cargo +nightly-2025-07-14: present
node >=22: present
npm: present
```

## Package Classification

Production-candidate package:

- `starknet_integration/`

Adapter/spike packages required by the candidate path:

- `cairo_air_adapter_spike/`
- `starknet_integration_runner/`

Research-only packages:

- `starknet_spike/`
- `starknet_adapter_spike/`
- `merkle_parity_spike/`

The research-only packages may inform future work, but compiling them does not make them production publication boundaries.

## Build Commands

After installing the pinned toolchain manually, run:

```bash
cd cairo_air_adapter_spike && scarb build && scarb test
cd ../starknet_integration && scarb build && scarb test
cd ../starknet_integration_runner && scarb build && scarb test
```

The clean orchestration command runs these in order:

```bash
npm run verify:starknet-artifacts
```

It stops before any transaction or deployment.

## Generated Artifact Locations

Expected generated artifacts:

```text
starknet_integration/target/dev/phil_starknet_integration.sierra.json
starknet_integration/target/dev/phil_starknet_integration.contract_class.json
proving/out/cairo_air_adapter_spike/proof_input_hash_slice_verify_args.json
proving/out/cairo_air_adapter_spike/summary.json
```

`target/` and `proving/out/` remain ignored build/generated directories.

## Proof Mirror And Claim Generation

The existing Rust generator is:

```bash
cd proving
cargo +nightly-2025-07-14 run --manifest-path Cargo.toml --bin cairo_air_adapter_spike
```

It emits:

```text
proving/out/cairo_air_adapter_spike/proof_input_hash_slice_proof.bin
proving/out/cairo_air_adapter_spike/proof_input_hash_slice_verify_args.json
proving/out/cairo_air_adapter_spike/summary.json
```

The generated summary records:

- `proofType`
- public inputs
- `proofInputHash`
- expected `[fact_high, fact_low]`
- safe proof-size and verifier-shape metadata

The generated files must not include `phil_secret`, `nullifierSeed`, private keys, vault keys, or real user material. The committed readiness manifest records hashes and safe metadata only; ordinary generated outputs remain ignored.

## Artifact Manifest

Generate or refresh:

```bash
npm run build:starknet-artifact-manifest
```

This writes:

```text
config/starknet-publication-readiness.json
```

Check without writing:

```bash
node scripts/starknet/generate-starknet-artifact-manifest.cjs --check
```

The manifest records:

- package and entrypoint;
- pinned toolchain versions;
- expected artifact paths;
- SHA-256 hashes for present non-secret artifacts;
- expected `[fact_high, fact_low]` message shape;
- account/deployment/address-binding status;
- readiness blockers;
- `production_approved = false`.

`deployment_ready` must remain false until toolchain, artifact, parity, syscall, and relay checks all pass in one run and the account/deployment model is accepted.

## Rust/Cairo Parity

The current parity check is bounded to safe generated output:

- `proofInputHash` is a 32-byte hex value;
- `expectedFactPayload` has exactly two felts;
- `fact_high = high128(proofInputHash)`;
- `fact_low = low128(proofInputHash)`;
- obvious secret-bearing field names are absent from the summary.

The full Rust proof blob is not submitted unchanged to Cairo. The candidate path uses a Cairo argument mirror for `StarkProofMirror` and `ProofInputHashSliceClaim`.

## Syscall Harness

Expected command:

```bash
cargo +nightly-2025-07-14 run \
  --manifest-path proving/Cargo.toml \
  --bin starknet-syscall-harness
```

The harness requires:

```text
starknet_integration/target/dev/phil_starknet_integration.sierra.json
proving/out/cairo_air_adapter_spike/proof_input_hash_slice_verify_args.json
proving/out/cairo_air_adapter_spike/summary.json
```

It verifies the contract-side `verify_proof_input_hash_slice` path under a Starknet syscall-capable runner.

## L1 Relay Harness

Expected command:

```bash
cargo +nightly-2025-07-14 run \
  --manifest-path proving/Cargo.toml \
  --bin starknet-l1-relay-harness
```

The harness calls:

```text
phil_starknet_integration::run_verify_proof_input_hash_slice_and_send_to_l1_via_contract_syscalls
```

It verifies:

- returned fact payload;
- emitted fact payload;
- relayed L2-to-L1 payload;
- exact `[fact_high, fact_low]` ordering;
- exact configured L1 recipient in the harness.

## Clean-Checkout Reproduction

Run:

```bash
npm run verify:starknet-artifacts
```

The script:

1. checks pinned tool versions;
2. builds relevant Cairo packages;
3. runs Scarb tests;
4. regenerates proof-input-hash slice args;
5. generates the readiness manifest;
6. runs Rust proving tests;
7. runs the syscall harness;
8. runs the L1 relay harness.

It fails on missing tools, artifact mismatch, or harness failure. It does not install tooling, deploy contracts, submit transactions, sign anything, or mutate chain state.

The runner package is classified explicitly:

```text
starknet_integration_runner:
  package_classification: executable_harness
  build_required: true
  scarb_test_applicable: false
  execution_harness_required: true
```

`scarb test` is not applicable to the runner under Scarb `2.15.0` because the executable must compile with gas disabled, while the test target pulls in a Starknet contract dependency that requires gas-enabled compilation. The replacement verification is mandatory execution through the real Rust syscall and L1 relay harnesses against generated artifacts.

## Current M.6A.1 Result

Successful in this environment:

- Scarb `2.15.0` and Cairo tools `2.15.0` were activated from official release assets under a local cache.
- `npm run check:starknet-toolchain` passed with Scarb `2.15.0`, `cairo-execute 2.15.0`, Rust nightly `nightly-2025-07-14`, Node `26.0.0`, and npm `11.12.1`.
- `cairo_air_adapter_spike` builds and `scarb test` runs successfully with zero tests.
- `starknet_integration` builds and `scarb test` passes the exact two-felt payload test.
- `starknet_integration_runner` builds and is classified as an executable harness.
- Scarb `2.15.0` produced contract-specific artifacts:
  - `starknet_integration/target/dev/phil_starknet_integration_phil_proof_input_hash_verifier.contract_class.json`
  - `starknet_integration/target/dev/phil_starknet_integration_phil_proof_input_hash_verifier.compiled_contract_class.json`
  - `starknet_integration/target/dev/phil_starknet_integration.sierra.json`
  - `starknet_integration/target/dev/phil_starknet_integration.starknet_artifacts.json`
- Rust proof-input-hash slice args regenerated under `proving/out/cairo_air_adapter_spike/`.
- `config/starknet-publication-readiness.json` generated with hashes for present safe artifacts.
- Manifest check passed.
- `starknet-syscall-harness` passed and returned/emitted the expected fact pair.
- `starknet-l1-relay-harness` passed and emitted the expected L2-to-L1 two-felt payload to the configured recipient.
- Rust proving tests passed.
- Representative Hardhat route and hash/identity tests passed.

Blocked in this environment:

- no M.6A.1 reproduction blocker remains under the documented executable-harness test model.

Remaining blockers:

- Starknet account/caller model is unresolved.
- No accepted production or testnet deployment is accepted.
- Runtime/Starknet Adapter transaction preparation is not implemented.

Artifact hashes observed in M.6A.1:

```text
contract Sierra class:
aba72cccd5500756f0422d508c10f30a19f1f585b336d23ee24603671aff206a

compiled class / CASM:
5f5d1da5dda4dff283c158395e7391d995822097baf5023aa899d9970831d31d

package Sierra:
9038b7aad1378893e147ba34051a8ca5742f61471c9f19982c32698b65709eaa

starknet artifacts manifest:
10b2679483e9e0725f2783363c56572bf4542b137c7fe143be8eb1cbb7220d07

proof-input-hash slice args:
c6e00a9dde4c8c8b3cc26ee7c50d1ddcb1458c7f143505917facbddb46328132

proof-input-hash slice summary:
22c9e65b05ff9e6d270340a9919894e6f7a17b0822fb8a3d9e0d979c3f1fd36c
```

Expected fact vector remained:

```text
proofInputHash:
0x8d5607b595200f66c7d24010dc79d646b0c7469cdaca5eecbbabb83d326413d2

fact_high:
0x8d5607b595200f66c7d24010dc79d646

fact_low:
0xb0c7469cdaca5eecbbabb83d326413d2
```

## Known Limitations

- The account/caller model is unresolved.
- No production or testnet deployment is accepted.
- The L1 recipient is an explicit Starknet entrypoint argument and must be bound by future configuration.
- The source L2 verifier address must match the L1 anchor constructor configuration.
- The readiness manifest is not deployment approval.
- The generated proof-input-hash slice args are local fixtures, not production Runtime authority.

## Negative Guarantees

M.6A.1 does not:

- prepare Starknet transactions
- sign or submit Starknet transactions
- prepare L1 or Base transactions
- deploy contracts
- modify Cairo semantics
- modify proof schemas
- modify public inputs
- modify `proofInputHash`
- modify `[fact_high, fact_low]`
- modify `ACTION_UNLOCK`
- create production Runtime authority
- mutate fact state, nullifier state, L1 state, or Base state
