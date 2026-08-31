# Starknet Fact Publication Transaction Preparation Boundary

Status: Draft M.6A.3 reference.

This document defines the controlled unsigned transaction-preparation boundary for the production-candidate Starknet fact-publication entrypoint.

It does not sign, submit, deploy, emit an L2-to-L1 message, consume an L1 message, anchor a fact, relay to Base, consume a nullifier, call Base, or create application execution authority.

## Actual Entrypoint

Contract package:

```text
phil_starknet_integration
```

Contract:

```text
phil_proof_input_hash_verifier
```

Entrypoint:

```text
verify_proof_input_hash_slice_and_send_to_l1(
  l1_recipient: felt252,
  proof: StarkProofMirror,
  claim: ProofInputHashSliceClaim
) -> VerificationFactPayload
```

Selector:

```text
0x2ea532910284e0d4916f9194d48869c0cd202ac5ba8fe81cdb35237b195e9de
```

## Calldata Model

The Rust proof-input-hash slice generator already produces the canonical Cairo argument fixture for:

```text
proof: StarkProofMirror
claim: ProofInputHashSliceClaim
```

The prepared call calldata is:

```text
[l1_recipient, ...proof_input_hash_slice_verify_args]
```

The helper verifies that the fixture hash matches `config/starknet-publication-readiness.json` before encoding. The full proof calldata is not included in audit drafts or ordinary summaries.

## Artifact And Configuration Revalidation

Preparation revalidates:

- Sierra class SHA-256;
- compiled class / CASM SHA-256;
- package Sierra SHA-256;
- Scarb artifacts manifest SHA-256;
- ABI hash;
- entrypoint ABI hash;
- entrypoint selector;
- proof type `stwo-unlock-keccak-v1`;
- message shape `[fact_high, fact_low]`;
- high/low ordering;
- enabled network profile;
- deployment address;
- L1 recipient;
- account/caller model;
- proof/claim/fact correlation.

The draft local predeployment config intentionally fails preparation with `deployment_address_missing`.

## Unsigned Account Envelope

The prepared artifact models an unsigned Starknet `INVOKE` transaction draft:

- transaction type: `INVOKE`;
- transaction version: `3`;
- one account execution call;
- explicit account address when available;
- no signature;
- `signable: false`;
- `submittable: false`.

The current recommended account model remains:

```text
permissionless_or_infrastructure_publisher
```

This treats Starknet publication as proof infrastructure. Applications must not receive publisher-account signing authority or raw Starknet transaction authority.

## Fee And Nonce

M.6A.3 defines read-only fixture interfaces for fee estimation and nonce reads.

Unresolved fee or nonce values are allowed only as explicit limitations:

- unresolved nonce means the draft is not signable;
- unresolved fee/resource bounds mean the draft is not signable;
- all fee, nonce, resource-bound, and freshness values must be revalidated before any future signing/submission boundary.

No nonce is reserved.

## Message Preview

The draft includes a safe message preview:

- destination L1 address;
- sender Starknet contract reference;
- payload length `2`;
- `fact_high`;
- `fact_low`.

It explicitly states:

```text
messageEmitted: false
messageAvailableOnL1: false
messageConsumedOnL1: false
```

## Diagnostic Command

Default draft config remains predeployment and should reject:

```bash
npm run diagnose:starknet-fact-publication-preparation -- --json
```

Local fixture-resolved diagnostic:

```bash
npm run diagnose:starknet-fact-publication-preparation -- --fixture-resolved --json
```

This uses fixture addresses only. It does not deploy, sign, submit, emit messages, anchor facts, or call Base.

## Negative Guarantees

M.6A.3 does not:

- sign Starknet transactions;
- submit Starknet transactions;
- deploy Starknet contracts;
- prepare L1 or Base transactions;
- consume L1 messages;
- anchor or relay facts;
- consume nullifiers;
- call Base `verifyAndConsume(...)`;
- modify Cairo contracts;
- modify proof schemas or public inputs;
- modify `proofInputHash`;
- modify `[fact_high, fact_low]`;
- expose private account keys or signing material;
- treat fixture/local addresses as production deployment.

## Remaining Blockers

- accepted Starknet publication deployment address;
- accepted Starknet class hash and compiled class hash references;
- accepted L1 anchor address;
- L1 `sourceL2Verifier` binding to the deployed Starknet contract;
- accepted publisher account/caller model;
- fee payer and nonce ownership policy;
- signing custody and user-consent requirements;
- future signing boundary.

## M.6A.4 Follow-On

The controlled signing boundary is documented in [Starknet Publisher Authorization And Signing Boundary](./STARKNET_PUBLISHER_AUTHORIZATION_AND_SIGNING_BOUNDARY.md).

M.6A.4 signs only an exact immutable transaction hash through a protected publisher boundary. It does not submit transactions, emit L2-to-L1 messages, anchor facts, call Base, or grant applications Starknet signing authority.

## M.6A.5 Follow-On

The controlled submission and receipt boundary is documented in [Starknet Fact Publication Submission And Monitoring Boundary](./STARKNET_FACT_PUBLICATION_SUBMISSION_AND_MONITORING_BOUNDARY.md).

M.6A.5 remains downstream of preparation and signing. It can submit only an exact approved signed publication transaction and can verify Starknet receipt evidence. It still does not prepare L1/Base transactions, consume the L2-to-L1 message, or create execution authority.
