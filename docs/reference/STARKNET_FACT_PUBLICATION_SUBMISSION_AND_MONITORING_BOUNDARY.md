# Starknet Fact Publication Submission And Monitoring Boundary

Status: Draft M.6A.5 reference.

This document defines the controlled testnet/local-devnet boundary for submitting one already signed Starknet fact-publication transaction and monitoring its receipt.

M.6A.5 consumes the signed but unsubmitted artifact from M.6A.4. It may verify an existing deployment, validate publisher/account/funding/submission approval, submit the exact signed transaction through an explicit submitter, monitor receipt/finality, and verify the expected `ProofInputHashFactVerified` event plus the exact two-felt L2-to-L1 message.

It does not prepare, sign, or submit Ethereum L1 transactions, consume L2-to-L1 messages, relay to Base, call Base, consume nullifiers, call `verifyAndConsume(...)`, or create application execution authority.

## Mandatory Preflight

Before any live submission, the boundary must validate:

- Starknet Sepolia or explicitly configured local devnet profile;
- non-mainnet chain ID;
- RPC reference;
- reproducible class hash, compiled class hash, and ABI hash;
- existing accepted deployment or explicit deployment approval;
- configured nonzero L1 recipient;
- approved publisher account;
- protected key-custody model;
- sufficient testnet fee balance;
- fresh nonce and fee/resource bounds;
- explicit submission approval bound to the exact signed transaction hash.

If any prerequisite is missing, the submission path stops and returns a readiness report.

The current repository default config remains intentionally blocked:

```text
configurationApprovalStatus = draft
starknet_sepolia.enabled = false
publicationContractDeploymentStatus = not_deployed
publisher account = unresolved
```

## Existing Deployment Verification

The boundary verifies an existing Starknet publication deployment before submission.

Verification checks:

- configured contract address;
- configured network/profile and chain ID;
- reproducible class hash;
- compiled class hash;
- ABI hash;
- expected entrypoint;
- configured L1 recipient policy.

Code existing at an address is not sufficient by itself. The class hash and configuration must match the accepted PhilCore publication configuration.

## Submission Approval

Submission approval is separate from:

- user approval of the original PhilCore action;
- publisher signing approval;
- future L1 anchoring;
- future Base authorization execution.

The approval binds:

- transaction hash;
- sender account;
- network/profile;
- publication contract;
- calldata hash;
- `proofInputHash`;
- `fact_high`;
- `fact_low`;
- L1 recipient;
- nonce;
- resource bounds digest;
- expiry;
- audit correlation.

Without this approval, submission is blocked.

## Last-Moment Revalidation

Immediately before submission, the boundary revalidates:

- deployment/class hash binding;
- publication contract address;
- network and chain ID;
- publisher account approval and key-custody policy;
- fee funding status;
- current nonce;
- fee/resource freshness;
- exact transaction hash;
- exact signature binding;
- L1 recipient;
- duplicate-submission store.

If nonce or fee/resource bounds changed, the boundary does not mutate or resign the artifact. A new M.6A.4 signing cycle is required.

## Receipt Monitoring

Receipt monitoring is bounded and non-authoritative.

Recognized states include:

- `RECEIVED`;
- `ACCEPTED_ON_L2`;
- `ACCEPTED_ON_L1`, if returned by the Starknet receipt API;
- `REJECTED`;
- `REVERTED`;
- `NOT_RECEIVED`;
- timeout.

Acceptance on L2 does not prove the Ethereum L1 message is available or consumed.

Every successful receipt artifact states:

```text
transactionAcceptedOnL2: true
verificationEventObserved: true
l2ToL1MessageObserved: true
l1MessageAvailabilityConfirmed: false
l1MessageConsumed: false
l1FactAnchored: false
baseFactMirrored: false
nullifierConsumed: false
```

## Event And Message Evidence

After an accepted receipt, the boundary verifies:

- event contract address equals the publication contract;
- event key matches `ProofInputHashFactVerified`;
- event payload contains the expected `fact_high` and `fact_low`;
- L2-to-L1 message sender equals the publication contract;
- message recipient equals the configured L1 recipient;
- payload length is exactly `2`;
- payload ordering is exactly `[fact_high, fact_low]`.

The event is not treated as proof of L1 message availability. The message evidence is still not an L1 anchor.

## Diagnostic Commands

Default diagnostic:

```bash
npm run diagnose:starknet-fact-publication-submission
```

JSON diagnostic:

```bash
npm run diagnose:starknet-fact-publication-submission -- --json
```

Submission command:

```bash
npm run submit:starknet-fact-publication-testnet -- --submit
```

Monitoring command:

```bash
npm run monitor:starknet-fact-publication
```

The current command implementation reports readiness and blockers. It does not perform live submission unless accepted Sepolia deployment/account/RPC/key-custody/submission prerequisites exist.

## Audit Behavior

Sanitized audit drafts may record:

- deployment verification requested;
- deployment verified or rejected;
- account/funding check;
- submission approval accepted or rejected;
- nonce/fee revalidation;
- transaction submitted;
- receipt state changed;
- transaction accepted/reverted/rejected;
- verification event observed;
- L2-to-L1 message observed;
- monitoring timeout.

Audit details may include transaction hash, account reference, contract reference, `proofInputHash`, fact-pair reference, L1 recipient, receipt status, block reference, outcome, and audit correlation.

Audit details must not include private keys, seed phrases, raw witness material, full proof calldata, or unnecessary raw signatures.

## Negative Guarantees

M.6A.5 does not:

- submit Starknet mainnet transactions;
- use unapproved production keys;
- deploy using fixture configuration;
- prepare or submit Ethereum L1 anchor transactions;
- consume L2-to-L1 messages;
- prepare or submit L1-to-Base relay transactions;
- call Base contracts;
- consume PhilCore nullifiers;
- call `verifyAndConsume(...)`;
- modify `ACTION_UNLOCK`;
- modify `proofInputHash`;
- modify `[fact_high, fact_low]`;
- modify proof schemas, Cairo semantics, contract ABIs, or public-input schemas;
- expose arbitrary RPC submission authority to applications.

## Remaining Blockers

- accepted Starknet Sepolia deployment configuration;
- accepted deployed publication contract address;
- accepted L1 recipient binding;
- protected testnet publisher account;
- testnet funding check;
- production key-custody mechanism;
- live RPC receipt/finality policy;
- explicit external submission approval artifact.

Until those are present, live submission remains blocked.

## M.6B Follow-On

The Ethereum L1 message availability and fact-anchor preparation boundary is documented in [L1 Message Availability And Fact-Anchor Preparation Boundary](./L1_MESSAGE_AVAILABILITY_AND_FACT_ANCHOR_PREPARATION_BOUNDARY.md).

M.6B consumes Starknet receipt/message evidence and may prepare an unsigned Ethereum L1 `consumeProofInputHashFactFromL2(factHigh, factLow)` transaction draft. It still does not consume the L2-to-L1 message, anchor the fact, relay to Base, consume a nullifier, or execute the authorization consumer.

## M.6C Follow-On

The controlled Ethereum L1 anchor signing/submission boundary is documented in [L1 Fact-Anchor Signing, Submission, And Monitoring Boundary](./L1_FACT_ANCHOR_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md).

M.6C may sign one exact L1 anchor transaction and may submit it only with accepted live Sepolia message/deployment/relayer prerequisites. Fixture diagnostics remain non-mutating.
