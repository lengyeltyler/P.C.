# Starknet Publication Configuration Boundary

Status: Draft M.6A.2 reference.

This document defines the non-executing configuration boundary required before PhilCore can later prepare an unsigned Starknet verified-fact publication transaction.

It does not prepare calldata, sign, submit, deploy, mutate Starknet state, anchor L1 messages, relay to Base, consume nullifiers, or create Runtime authority.

## Configuration Files

- `config/starknet-publication-config.schema.json`
- `config/starknet-publication-config.local.json`
- `config/starknet-publication-readiness.json`

The local configuration is a draft predeployment profile. It is valid for artifact binding and review, but it is not usable for transaction preparation.

## Artifact Binding

The configuration binds to the M.6A.1 reproducible artifacts:

- package: `phil_starknet_integration`
- contract: `phil_proof_input_hash_verifier`
- entrypoint: `verify_proof_input_hash_slice_and_send_to_l1`
- proof type: `stwo-unlock-keccak-v1`
- payload encoding: `proof-input-hash-slice-v1`

Current artifact hashes:

```text
contract Sierra class: aba72cccd5500756f0422d508c10f30a19f1f585b336d23ee24603671aff206a
compiled class / CASM: 5f5d1da5dda4dff283c158395e7391d995822097baf5023aa899d9970831d31d
package Sierra: 9038b7aad1378893e147ba34051a8ca5742f61471c9f19982c32698b65709eaa
starknet artifacts manifest: 10b2679483e9e0725f2783363c56572bf4542b137c7fe143be8eb1cbb7220d07
ABI hash: 05e3ea7ae63572ae50ae14b4410491acc71c66a3d331d19accdc7fd1ae03be88
entrypoint ABI hash: 873debabc8f16560bdc36476208c0c39b0c5b9ceeed986309536aa3f9ddef22e
```

Starknet class hash and compiled class hash derivation remain pending. The SHA-256 hashes above are reproducibility hashes, not deployed class identifiers.

## Network Profiles

The configuration defines `local_devnet`, `starknet_sepolia`, and `starknet_mainnet`.

Only `local_devnet` is enabled for draft validation. No profile is currently usable for transaction preparation because deployment address, L1 recipient, expected L2 sender, and account/caller decisions remain unresolved. Mainnet remains disabled.

## L1 Recipient Binding

The current Cairo entrypoint accepts `l1_recipient` as a caller-supplied argument:

```text
verify_proof_input_hash_slice_and_send_to_l1(
  l1_recipient: felt252,
  proof: StarkProofMirror,
  claim: ProofInputHashSliceClaim
) -> VerificationFactPayload
```

This is acceptable for local harness validation, but production transaction preparation must bind the recipient to the expected L1 anchor address through Runtime/Adapter configuration.

Current policy:

```text
configured_allowlist_required_before_transaction_preparation
```

Zero recipients are rejected. Arbitrary caller-supplied recipients must not be accepted by the future transaction-preparation boundary.

## Expected L2 Sender Binding

`PhilL1ProofInputHashAnchor` must be configured to trust the deployed Starknet publication contract as the expected L2 sender.

Current status:

```text
unresolved_until_deployment
```

The configuration cannot mark transaction preparation usable until a deployed publication contract address and matching L1 anchor sender binding are known.

## Account And Caller Model

Recommended model:

```text
permissionless_or_infrastructure_publisher
```

Rationale:

- Starknet publication is proof infrastructure, not user-facing wallet authority.
- Applications must not gain raw Starknet transaction authority.
- PhilCore should preserve the accepted framing that Ethereum/Base is the first authorization-execution environment while Starknet provides verified-fact availability infrastructure.

Rejected for now:

- requiring a user-controlled Starknet wallet as the product surface;
- treating PhilCore identity as direct Starknet account authority.

The model remains unresolved until fee payer, nonce owner, retry policy, and user-consent requirements are accepted.

## Fee And Nonce Model

Future transaction preparation must define publisher account address, nonce source, fee token, maximum fee policy, fee estimation, fee sponsorship, transaction version, resource bounds, expiry, and retry behavior.

Private keys, seed phrases, RPC credentials, and API keys are not allowed in configuration.

## Receipt And Finality Policy

Future monitoring must distinguish submitted, received, accepted on L2, rejected, reverted, L2-to-L1 message emitted, L1 message available, timeout, and duplicate transaction handling.

L1 anchoring must wait for the L2-to-L1 message to be available.

## Validation

Run:

```bash
npm run validate:starknet-publication-config
npm run verify:starknet-publication-artifact-binding
```

Validation checks:

- artifact hashes and paths match the readiness manifest;
- ABI and entrypoint hashes match the generated contract artifact;
- entrypoint inputs remain `l1_recipient, proof, claim`;
- proof type remains `stwo-unlock-keccak-v1`;
- message payload remains `[fact_high, fact_low]`;
- high/low ordering is preserved;
- zero L1 recipient is rejected;
- mainnet remains disabled;
- unresolved deployment is allowed only while transaction preparation is disabled;
- secret-shaped fields are rejected.

## Negative Guarantees

M.6A.2 does not:

- prepare Starknet calldata;
- sign or submit Starknet transactions;
- prepare L1 or Base transactions;
- deploy contracts;
- modify Cairo semantics;
- modify proof schemas or public inputs;
- modify `proofInputHash`;
- modify `[fact_high, fact_low]`;
- modify `ACTION_UNLOCK`;
- create Runtime authority;
- mutate fact, nullifier, L1, Base, or deployment state.

## Remaining Blockers

- Starknet class hash derivation and accepted class hash references.
- Publication contract deployment address.
- L1 anchor address.
- Expected L2 sender binding on L1.
- Accepted account/caller model.
- Fee, nonce, and receipt/finality policy approval.
- Future Starknet Adapter transaction-preparation boundary.

## M.6A.3 Follow-On

The unsigned transaction-preparation boundary is documented in [Starknet Fact Publication Transaction Preparation Boundary](./STARKNET_FACT_PUBLICATION_TRANSACTION_PREPARATION_BOUNDARY.md).

The default local predeployment config remains non-preparable. M.6A.3 tests use fixture-resolved config copies to prove calldata and unsigned account-envelope construction without treating those fixture values as deployment data.

## M.6A.4 Follow-On

The publisher authorization and signing boundary is documented in [Starknet Publisher Authorization And Signing Boundary](./STARKNET_PUBLISHER_AUTHORIZATION_AND_SIGNING_BOUNDARY.md).

The fixture signer is local-only and must not be treated as production key custody. Future production signing requires accepted deployment, publisher-account, fee-payer, nonce, RPC, and approval policy.
