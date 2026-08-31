# Starknet Publisher Authorization And Signing Boundary

Status: Draft M.6A.4 reference.

This document defines the controlled signing boundary for Starknet verified-fact publication transactions.

It consumes a valid unsigned M.6A.3 transaction draft and may produce a signed but unsubmitted transaction artifact. It does not submit transactions, deploy contracts, emit L2-to-L1 messages, consume L1 messages, anchor facts, relay to Base, consume nullifiers, call Base, or create application execution authority.

## Publisher Model

The recommended initial Beta/Testnet model is:

```text
infrastructure_operator
```

Under this model:

- the publisher account is proof-publication infrastructure;
- the signer is isolated behind a dedicated publisher boundary;
- the fee payer is the operator or delegated infrastructure;
- applications never receive the signer or raw transaction authority;
- the signer is authorized only for the exact approved publication transaction hash.

Other modes remain modeled but not recommended as the default:

- `permissionless_external_publisher`: possible later, with availability and censorship risk.
- `user_controlled_starknet_account`: not the current product surface and must not turn PhilCore into a general Starknet wallet.
- `sponsored_publisher`: possible later if sponsorship policy is accepted.
- `developer_fixture`: tests and local diagnostics only.
- `unsupported`: rejected.

## Key Custody

M.6A.4 implements only a deterministic developer fixture signer for tests and local diagnostics.

Production key custody remains unresolved. Future production candidates may include:

- local encrypted operator key for development or tightly scoped testnet use;
- hardware-backed or OS-backed signing if Starknet-compatible signing is actually implemented;
- remote signer or HSM for infrastructure publishing.

No production path may expose private keys, seed phrases, mnemonic material, or arbitrary signing APIs to applications.

## Transaction Hash

The transaction hash is the real Starknet `INVOKE` v3 transaction hash computed through Starknet.js.

The hash binds:

- transaction version `0x3`;
- sender account;
- Starknet chain ID;
- account execute calldata;
- nonce;
- resource bounds;
- tip;
- paymaster data;
- account deployment data;
- nonce data-availability mode;
- fee data-availability mode.

The signing boundary compares helper output against Starknet.js transaction-hash tooling in tests. No handwritten digest is treated as authority.

## Nonce And Fee Freshness

Before signing, the boundary requires:

- a resolved draft nonce;
- a fresh read-only nonce result equal to the draft nonce;
- explicit resource bounds;
- a fresh fee estimate reference;
- allowed fee token;
- maximum-fee policy;
- resource bounds no wider than policy;
- revalidation before any future submission.

The nonce is not reserved. A successful signature does not guarantee the nonce or fee remains usable later.

## Signing Presentation

The signer approval binds to an immutable presentation digest.

The presentation includes:

- network/profile;
- chain ID;
- publisher account;
- publication contract;
- entrypoint;
- calldata hash;
- `proofInputHash`;
- `fact_high`;
- `fact_low`;
- L1 recipient;
- nonce;
- fee token;
- resource bounds;
- transaction expiry;
- audit correlation.

Any mutation after presentation invalidates approval.

## Approval Model

Signing approval is separate from application user approval.

The application approval authorizes the original PhilCore action. This publisher approval authorizes proof infrastructure to spend Starknet fees and publish the verified fact.

Supported approval sources are modeled as:

- `automated_infrastructure_policy`;
- `operator_approval`;
- `publisher_service_authorization`;
- `developer_fixture_approval`.

M.6A.4 uses `developer_fixture_approval` only in tests and diagnostics.

## Signed Artifact

A successful artifact states:

```text
transactionSigned: true
transactionSubmitted: false
factVerifiedOnStarknet: false
l2ToL1MessageEmitted: false
l1MessageConsumed: false
chainStateMutated: false
submissionAllowedByApplications: false
```

The artifact contains:

- transaction hash;
- signature felts;
- signer descriptor;
- sender account;
- network/profile;
- chain ID;
- nonce;
- resource bounds;
- calldata hash;
- publication contract;
- entrypoint;
- `proofInputHash`;
- L1 recipient;
- issue time;
- expiry;
- audit correlation.

It does not contain private key material, seed phrases, full proof calldata, witness material, or submission authority.

## Signature Validation Limitation

Starknet account signature validation is account-contract specific. M.6A.4 validates:

- signature felt format;
- signer descriptor and account binding;
- signer public key binding where configured;
- exact transaction-hash correlation;
- signer response correlation.

It does not claim generic off-chain validation for every future Starknet account contract.

## Diagnostic Command

Default unresolved configuration should fail safely:

```bash
npm run diagnose:starknet-fact-publication-signing -- --json
```

Fixture-resolved local diagnostic:

```bash
npm run diagnose:starknet-fact-publication-signing -- --fixture-resolved --json
```

This uses a deterministic developer fixture signer. It signs a bounded local artifact only. It does not submit, deploy, emit messages, call L1, call Base, or mutate chain state.

## Negative Guarantees

M.6A.4 does not:

- submit Starknet transactions;
- call a Starknet RPC submission method;
- deploy Starknet contracts;
- emit L2-to-L1 messages;
- consume L1 messages;
- prepare L1 or Base transactions;
- expose private keys or seed phrases;
- allow arbitrary Starknet signing;
- allow applications to access signing methods;
- modify `ACTION_UNLOCK`;
- modify `proofInputHash`;
- modify `[fact_high, fact_low]`;
- modify `StarkProofMirror`;
- modify `ProofInputHashSliceClaim`;
- modify Cairo verifier behavior;
- modify proof or contract schemas.

## Remaining Blockers

- accepted Starknet deployment address and class hashes;
- accepted L1 anchor address;
- expected L2 sender binding on L1;
- accepted publisher account and fee-payer policy;
- production key custody;
- Starknet RPC and nonce/finality policy;
- controlled testnet submission boundary.

## M.6A.5 Follow-On

The controlled submission and receipt boundary is documented in [Starknet Fact Publication Submission And Monitoring Boundary](./STARKNET_FACT_PUBLICATION_SUBMISSION_AND_MONITORING_BOUNDARY.md).

M.6A.5 may submit one exact approved signed transaction through a bounded Starknet submitter and monitor its receipt. A successful receipt can observe the verification event and L2-to-L1 message, but it still does not consume the L1 message, anchor the fact on L1, relay to Base, consume a nullifier, or execute the authorization consumer.
