# Starknet Verified-Fact Publication Boundary

> **Current security gate:** the contract and serialization material described
> here is retained architecture/research evidence. The current local STWO
> artifact contains reconstructable witness openings, cannot be finalized, and
> is rejected before any Starknet publication preparation or submission. No
> current product route supplies this boundary with an externally safe proof.

## Purpose

Phase M.6A resolves the missing boundary between a finalized local `ACTION_UNLOCK` proof artifact and the Starknet-side verified fact that later feeds the Ethereum L1 anchor.

This document is implementation-grounded. It records what the current repo actually supports and what remains missing before PhilCore can prepare a production Starknet transaction.

M.6A does not prepare L1 anchor transactions, relay to Base, call Base contracts, call `verifyAndConsume(...)`, consume nullifiers, modify proof schemas, modify public inputs, modify Cairo programs, or modify deployed configuration.

## Current Status

The current repo contains a dormant Starknet proof-input-hash publication
shape, but no safe production Runtime input or complete production path.

What exists:

- Rust `stwo-unlock-keccak-v1` generation and verification for explicit local synthetic research only; its serialized proof is secret-bearing.
- Rust exporters that serialize STWO proof material into Cairo argument mirrors.
- A Cairo AIR adapter for the `proofInputHash` slice proof.
- A Starknet contract package with entrypoints that verify the proof-input-hash slice and optionally send `[fact_high, fact_low]` to L1.
- Rust syscall harnesses that previously exercised the Starknet contract path and L2-to-L1 message shape.
- Local fixture summaries preserving the exact two-felt fact payload.

What is still missing:

- Accepted production Starknet deployment.
- Accepted Starknet account/caller model.
- Runtime/Starknet Adapter transaction-preparation boundary.
- Accepted reproducible Sierra/CASM publication artifacts from the pinned Scarb/Cairo toolchain.
- Message availability monitoring against a real Starknet network.
- Production finality, fee, nonce, and receipt policy.

Because these gaps are production blockers, M.6A does not add Runtime SDK types. Adding types now would make an unresolved transaction boundary look more stable than it is.

## M.6A.1 Reproducibility Boundary

M.6A.1 adds a pinned, non-installing local toolchain and artifact reproducibility path:

- `config/starknet-toolchain.json`
- `config/starknet-publication-readiness.json`
- `npm run check:starknet-toolchain`
- `npm run build:starknet-artifact-manifest`
- `npm run verify:starknet-artifacts`

See [Starknet Toolchain And Artifact Reproducibility](./STARKNET_TOOLCHAIN_AND_ARTIFACT_REPRODUCIBILITY.md).

The pinned local toolchain check currently finds Scarb/Cairo `2.15.0`, but the
environment-dependent publication artifact/configuration lane is not a
credential-free public gate. Tool availability does not remove the witness
privacy blocker or authorize publication.

## Exact Starknet Programs And Entrypoints

### Production-Candidate Integration Contract

Package:

```text
starknet_integration/
```

Contract module:

```text
phil_starknet_integration::phil_proof_input_hash_verifier
```

Relevant entrypoints:

```text
verify_proof_input_hash_slice(
  proof: StarkProofMirror,
  claim: ProofInputHashSliceClaim
) -> VerificationFactPayload
```

```text
verify_proof_input_hash_slice_and_send_to_l1(
  l1_recipient: felt252,
  proof: StarkProofMirror,
  claim: ProofInputHashSliceClaim
) -> VerificationFactPayload
```

The second entrypoint is the boundary needed by the cross-domain route. It verifies the proof-input-hash slice, registers the fact in Starknet contract storage, emits `ProofInputHashFactVerified`, sends the two-felt payload to L1, and returns the same payload.

The current source does not restrict caller identity. Production caller policy must be provided by account, deployment, or Runtime policy rather than by this contract code.

### Research-Only Public-Input Registry Spike

Package:

```text
starknet_spike/
```

Contract module:

```text
PhilProofInputHashFactRegistry
```

Entrypoint:

```text
mark_verified_and_send(
  l1_recipient: felt252,
  public_inputs: UnlockProofPublicInputs
) -> u256
```

This spike recomputes `proofInputHash` from public inputs, stores it, and sends the two-felt payload to L1. It does not verify a STWO proof. It must not be described as cryptographic proof verification.

## Proof Payload And Public Inputs

The Starknet integration path uses:

- `StarkProofMirror`
- `ProofInputHashSliceClaim`
- `VerificationFactPayload`

`StarkProofMirror` is a Cairo mirror of a STWO commitment-scheme proof. It is produced by Rust serialization helpers in `proving/src/bin/starknet_adapter_spike.rs` and consumed by `cairo_air_adapter_spike/src/lib.cairo`.

`ProofInputHashSliceClaim` contains:

- `block_bits: Array<Array<u32>>`
- `expected_digest_bits: Array<u32>`
- `fact_high: u128`
- `fact_low: u128`

The full local unlock proof artifact must not be submitted. Although the Cairo
research path verifies a `proofInputHash` slice rather than the full local
`ACTION_UNLOCK` blob, its proof material derives from the same unmasked trace
construction and is not an approved witness-hiding replacement.

The generated summary shape records:

```text
proofType = "stwo-unlock-keccak-v1"
proofInputHash = 0x8d5607b595200f66c7d24010dc79d646b0c7469cdaca5eecbbabb83d326413d2
expectedFactPayload = [
  0x8d5607b595200f66c7d24010dc79d646,
  0xb0c7469cdaca5eecbbabb83d326413d2
]
```

This preserves the locked fact ordering:

```text
[fact_high, fact_low] = high128(proofInputHash), low128(proofInputHash)
```

## STWO-To-Cairo Compatibility

### Current Rust Output

The local Rust prover currently outputs a raw local proof blob encoded with the repo's Rust bincode codec. The Rust proof tooling can also produce Cairo argument mirrors for:

- full unlock proof
- owner-path proof
- `proofInputHash` slice proof

The Starknet integration uses the `proofInputHash` slice proof path.

### Current Cairo Expectation

The Cairo verifier path expects structured Cairo arguments:

- `StarkProofMirror`
- `ProofInputHashSliceClaim`

It does not accept the raw Rust bincode proof blob unchanged.

### Existing Adapter Layer

The adapter/export layer exists in:

- `proving/src/bin/starknet_adapter_spike.rs`
- `cairo_air_adapter_spike/src/lib.cairo`
- `starknet_integration/src/lib.cairo`
- `starknet_integration_runner/src/lib.cairo`
- `proving/src/bin/starknet_syscall_harness.rs`
- `proving/src/bin/starknet_l1_relay_harness.rs`

The adapter serializes STWO proof structures into Cairo-friendly felt arguments and reconstructs verifier-core types in Cairo.

### Compatibility Status

| Layer | Status |
| --- | --- |
| Public tuple / `proofInputHash` derivation | Aligned and locked by existing tests. |
| `[fact_high, fact_low]` derivation | Aligned; high 128 bits then low 128 bits. |
| Cairo argument mirror | Exists for the slice proof path. |
| Cairo verifier invocation | Exists for the slice proof path through `verify_proof_input_hash_slice`. |
| L2-to-L1 message payload | Exists and preserves exact two-felt payload in harness evidence. |
| Raw full local proof blob submission | Not supported unchanged. |
| Full production Starknet deployment | Missing. |
| Runtime transaction preparation | Missing. |

Older research documents record intermediate verifier mismatches such as OODS, query packing, quotient sampling, and transcript divergences. Later Starknet syscall and relay reports record a narrower GO result for the `proofInputHash` slice path under a syscall-capable harness. M.6A therefore treats only the slice-proof publication path as the current production-candidate path.

## Starknet Contract And Caller Matrix

| Package / contract | Entrypoint | Mutability | Required caller | Inputs | State changed | Event | L2-to-L1 message | L1 destination source | Replay behavior | Fee/account requirement | Runtime may prepare? | Deployed? |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `starknet_integration::phil_proof_input_hash_verifier` | `verify_proof_input_hash_slice(proof, claim)` | External, state-changing | Any Starknet account under current code | `StarkProofMirror`, `ProofInputHashSliceClaim` | `verified_facts[fact] = true` | `ProofInputHashFactVerified(fact_high, fact_low)` | No | None | Repeated calls rewrite `true` and re-emit event | Starknet account pays fee | Not yet; account/deployment unresolved | No accepted deployment found |
| `starknet_integration::phil_proof_input_hash_verifier` | `verify_proof_input_hash_slice_and_send_to_l1(l1_recipient, proof, claim)` | External, state-changing | Any Starknet account under current code | `felt252 l1_recipient`, `StarkProofMirror`, `ProofInputHashSliceClaim` | `verified_facts[fact] = true` | `ProofInputHashFactVerified(fact_high, fact_low)` | Yes, payload `[fact_high, fact_low]` | Explicit `l1_recipient` argument | Repeated calls can attempt repeated messages unless governed externally | Starknet account pays fee | Future candidate after deployment/account model | No accepted deployment found |
| `starknet_spike::PhilProofInputHashFactRegistry` | `mark_verified_and_send(l1_recipient, public_inputs)` | External, state-changing | Any Starknet account under current code | `felt252 l1_recipient`, public inputs | `verified_proof_input_hash[hash] = true` | `ProofInputHashVerified(proof_input_hash)` | Yes, payload `[hash.high, hash.low]` | Explicit `l1_recipient` argument | Repeated calls can rewrite `true` and resend | Starknet account pays fee | No; research-only | No accepted deployment found |

## L2-To-L1 Message Shape

The L1 anchor expects:

```solidity
consumeProofInputHashFactFromL2(uint256 factHigh, uint256 factLow)
```

Internally, the L1 anchor consumes a Starknet message from:

```text
sourceL2Verifier
```

with payload:

```text
[factHigh, factLow]
```

The Starknet integration contract emits:

```text
send_message_to_l1_syscall(l1_recipient, [fact_high, fact_low])
```

Message binding:

- Sender Starknet contract: the deployed `phil_proof_input_hash_verifier` address.
- Destination L1 address: explicit `l1_recipient` passed to the Starknet entrypoint.
- Payload ordering: `fact_high`, then `fact_low`.
- Field widths: each fact half is a `u128` in Cairo and fits in the L1 `uint256[]` payload.
- Domain separator: none in the L2-to-L1 payload.
- Proof type: not included in the L2-to-L1 payload.
- `proofInputHash`: represented only as the two-felt split.
- L1 source check: `PhilL1ProofInputHashAnchor` passes configured `sourceL2Verifier` to Starknet messaging.
- Replay behavior: the L1 Starknet message consumption path is one-time for a given message; the Starknet contract can attempt repeated sends unless prevented by account/policy.

The current Cairo code emits the exact payload shape expected by the L1 anchor. The current repo does not include a production message-availability reader or deployed sender/address binding.

## Deployment And Address Binding

Expected production configuration must bind:

- Starknet network and chain ID.
- `phil_proof_input_hash_verifier` class/hash/address.
- Ethereum L1 `PhilL1ProofInputHashAnchor` address.
- L1 anchor `sourceL2Verifier` equal to the deployed Starknet verifier address.
- Starknet entrypoint `l1_recipient` equal to the deployed L1 anchor address.
- Proof type `stwo-unlock-keccak-v1`.
- Fact shape `[fact_high, fact_low]`.

Current status:

- No accepted production Starknet deployment manifest was found.
- No accepted testnet Starknet deployment address was found.
- No immutable L1 recipient is configured in Cairo; it is an explicit entrypoint argument.
- The L1 anchor stores `sourceL2Verifier` immutably in its constructor.
- Local fixtures use placeholder/test values such as `0x5048494c` for the contract address and `0x4c315f54525553545f414e43484f52` for the L1 recipient boundary.
- Generated Sierra/CASM artifacts are not present in the current checkout.

Spike addresses and local fixtures must not be treated as production deployment evidence.

## Starknet Account And Transaction Model

The future Starknet transaction sender model is unresolved. Realistic options are:

| Model | Signing authority | Fee payer | Censorship / liveness | PhilCore identity relationship | Risk |
| --- | --- | --- | --- | --- | --- |
| User-controlled Starknet account | User Starknet key/account | User | User can publish independently | Adds a Starknet account surface; proof infrastructure only | May feel like multi-chain wallet support if exposed poorly |
| PhilCore-managed Starknet account | PhilCore-controlled account key or smart account | User or PhilCore | Runtime can coordinate | Requires new key/account policy and likely Device Vault implications | Too large for M.6A |
| Proof publisher service | Service/operator | Service or user-funded | Service can censor or delay | Not identity authority; infrastructure publisher | Centralization/trust policy required |
| Permissionless relayer | Any relayer | Relayer/user incentive | More liveness | No direct identity authority | Needs fee/incentive design |
| Operator account | PhilCore operator | Operator | Centralized | Infrastructure-only | Acceptable only for testnet/alpha unless explicitly reviewed |

Recommended near-term model:

```text
Treat Starknet as proof infrastructure and begin with an explicit proof publisher / operator model for local and testnet only, while designing the Runtime boundary so it can later support user-paid or permissionless publication.
```

This avoids introducing multi-chain wallet behavior while still preserving the Starknet route. It must be clearly labeled infrastructure, not user-facing wallet authority.

## Fact Publication Semantics

For the current production-candidate integration contract:

```text
Starknet publication means the proof-input-hash slice proof was verified by the Cairo verifier path, the fact pair was registered in Starknet storage, and the exact fact pair was sent to L1.
```

Trust classification:

- `starknet_integration`: cryptographically verified on Starknet for the `proofInputHash` slice path, assuming the deployed Cairo verifier code matches the inspected source and the proof/claim serialization is exact.
- `starknet_spike`: research-only public-input assertion/recomputation, not proof verification.
- local fixture `proving/out/cairo_air_adapter_spike/summary.json`: local fixture only.
- local fixture `proving/out/starknet_l1_relay/harness_output.json`: local harness evidence only.

The full local `ACTION_UNLOCK` proof remains locally verified by Rust. The Starknet publication route currently proves the `proofInputHash` slice path that produces the fact pair.

## Missing Components

| Component | Rank | Notes |
| --- | --- | --- |
| Accepted production Starknet verifier deployment | Blocker | Required before any production publication. |
| Starknet account/caller model | Blocker | Must decide who signs and pays. |
| Runtime/Starknet Adapter transaction preparation | Blocker | Must prepare only Starknet publication, not L1/Base steps. |
| Generated Sierra/CASM artifact production and tracking | Blocker | Current checkout lacks target artifacts. |
| Scarb/Cairo toolchain availability | Blocker for local verification | Current environment lacks `scarb` and `cairo-execute`. |
| Proof serialization adapter hardening | Required before testnet | Existing serializer is spike/harness-oriented. |
| L1 recipient/address binding policy | Required before testnet | Current entrypoint accepts arbitrary `l1_recipient`. |
| Message availability reader | Required before testnet | Needed before L1 anchor preparation. |
| Fee/nonce/receipt/finality monitoring | Required before testnet | Required for Starknet transaction lifecycle. |
| Security review of verifier code and deployment config | Required before production | Must include transcript/FRI/query assumptions. |
| Permissionless relayer support | Optional improvement | Useful for liveness, not required for first testnet path. |

## Route Comparison

### Route A - Preserve Starknet -> L1 -> Base

- Completeness: most aligned with existing contracts and research code, but deployment/account/runtime boundaries are missing.
- Security: strongest current route if Starknet verifier deployment is reviewed and the L1 source binding is exact.
- Cost: involves Starknet tx, L1 anchor tx, L1 relay tx, and Base execution.
- Latency: cross-domain latency across Starknet, L1, and Base.
- Operational complexity: high, but already reflected in existing contracts.
- Relayer requirements: likely needed for usability.
- Censorship/failure modes: proof publisher, L1 anchor, and relay can each fail or delay.
- Compatibility with local STWO proof: compatible through the slice-proof adapter, not raw unchanged submission.
- Time to testnet: shortest credible route if tooling/deployment/account gaps are resolved.

### Route B - Direct Ethereum/L1 Verification

- Feasibility: requires new verifier/interface work.
- Verifier cost: likely high and not established.
- Contract complexity: substantial.
- Proof compatibility: unknown without new verifier work.
- Migration work: high; would alter the current route.

### Route C - Direct Base Verification

- Feasibility: not supported by current Base verifier contracts.
- Gas/verification constraints: likely hard; prior route uses mirrored facts for a reason.
- Required changes: new Base verifier/fact registry semantics and likely contract changes.
- Migration work: high.

### Route D - Temporary Permissioned Fact Publisher

- Security: weaker; fact becomes permissioned assertion unless backed by reviewed verification.
- Development usefulness: useful for alpha demos and testnet flow testing.
- Centralization: high.
- Migration/removal: must be explicit and time-bounded.
- Acceptability: alpha/testnet only unless separately reviewed and labeled.

Recommended route:

```text
Route A, with a tightly scoped M.6A.1 that turns the existing Starknet integration contract into a reproducible local build and deployment-readiness artifact before any transaction preparation.
```

## Recommended Next Sequence

### M.6A.1 - Starknet Toolchain And Artifact Reproducibility

- Build `cairo_air_adapter_spike`, `starknet_integration`, and `starknet_integration_runner`.
- Regenerate Sierra/CASM and proof-input-hash slice args from existing code.
- Run the syscall and L1 relay harnesses locally.
- Produce a checked, non-secret deployment-readiness manifest.
- Do not submit any Starknet transaction.
- Current status: complete under the executable-harness classification for `starknet_integration_runner`.

### M.6A.2 - Starknet Publication Configuration Boundary

- Define the publication contract reference, class hash, L1 anchor recipient, expected source sender, network, and account requirement as non-executing config.
- Validate address binding only.
- Do not sign or submit.
- Current status: draft configuration boundary added. See [Starknet Publication Configuration Boundary](./STARKNET_PUBLICATION_CONFIGURATION_BOUNDARY.md).

### M.6A.3 - Starknet Publication Transaction Preparation

- Prepare, but do not sign or submit, the exact Starknet call to `verify_proof_input_hash_slice_and_send_to_l1`.
- Require exact proof/claim/fact/message binding.
- Keep L1 and Base out of scope.
- Current status: controlled unsigned draft boundary added. See [Starknet Fact Publication Transaction Preparation Boundary](./STARKNET_FACT_PUBLICATION_TRANSACTION_PREPARATION_BOUNDARY.md).

### M.6A.4 - Starknet Publisher Authorization And Signing

- Authorize an isolated publisher signer for one exact prepared Starknet transaction hash.
- Produce a signed but unsubmitted artifact only.
- Keep submission, L2-to-L1 message emission, L1 anchoring, Base relay, and Base execution out of scope.
- Current status: controlled signing boundary added. See [Starknet Publisher Authorization And Signing Boundary](./STARKNET_PUBLISHER_AUTHORIZATION_AND_SIGNING_BOUNDARY.md).

### M.6A.5 - Starknet Submission And Receipt Monitoring

- Submit only one exact approved signed Starknet publication transaction through a bounded submitter.
- Verify accepted-on-L2 receipt evidence, `ProofInputHashFactVerified`, and the exact `[fact_high, fact_low]` L2-to-L1 message.
- Keep L1 message consumption, L1 anchoring, L1-to-Base relay, Base mirror updates, nullifier consumption, and Base execution out of scope.
- Current status: controlled submission and monitoring boundary added. See [Starknet Fact Publication Submission And Monitoring Boundary](./STARKNET_FACT_PUBLICATION_SUBMISSION_AND_MONITORING_BOUNDARY.md).

## Verification Notes

Current environment status:

- `scarb`: `2.15.0` activated from the official release asset.
- `cairo-execute`: `2.15.0` activated from the official Cairo release asset.
- `snforge`: not installed.
- Rust/Cargo: available.
- Node/npm: available.

Runner classification:

```text
starknet_integration_runner:
  package_classification: executable_harness
  build_required: true
  scarb_test_applicable: false
  execution_harness_required: true
```

`scarb test` is not applicable for the runner under Scarb `2.15.0` without changing its required gas-disabled executable compilation mode. The real syscall and L1 relay harnesses are mandatory and currently pass.

The current checkout has generated, ignored Scarb target artifacts for `starknet_integration`, including:

```text
starknet_integration/target/dev/phil_starknet_integration_phil_proof_input_hash_verifier.contract_class.json
starknet_integration/target/dev/phil_starknet_integration_phil_proof_input_hash_verifier.compiled_contract_class.json
starknet_integration/target/dev/phil_starknet_integration.sierra.json
```

The local Starknet syscall compatibility and L1 relay harnesses pass against those artifacts. Full clean orchestration passes under the documented package classification.

## Negative Guarantees

M.6A does not:

- modify Cairo programs
- modify Solidity contracts or ABIs
- modify proof schemas
- modify public inputs
- modify `proofInputHash`
- modify `[fact_high, fact_low]`
- submit Starknet transactions
- deploy Starknet contracts
- emit Starknet L2-to-L1 messages
- prepare L1 anchor transactions
- prepare L1-to-Base relay transactions
- call Base contracts
- call `verifyAndConsume(...)`
- consume nullifiers
- mutate fact state
- mutate L1 or Base state
- introduce multi-chain wallet functionality
