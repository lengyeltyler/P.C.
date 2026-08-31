# L1 Fact-Anchor Signing, Submission, And Monitoring Boundary

Status: Draft M.6C reference.

This document defines the controlled Ethereum L1 boundary after M.6B unsigned fact-anchor preparation.

M.6C may sign, submit, and monitor exactly one `PhilL1ProofInputHashAnchor.consumeProofInputHashFactFromL2(factHigh, factLow)` transaction when all live Sepolia prerequisites are explicitly present.

The default repository path remains fixture/local and non-mutating. It does not relay to Base, call Base contracts, call `verifyAndConsume(...)`, consume a PhilCore nullifier, execute a consumer, or expose private keys.

## Actual Anchor Interface

The reused L1 anchor method is:

```solidity
consumeProofInputHashFactFromL2(uint256 factHigh, uint256 factLow)
```

The method builds payload `[factHigh, factLow]`, calls `starknetMessaging.consumeMessageFromL2(sourceL2Verifier, payload)`, writes `anchoredProofInputHashFact[factHigh][factLow] = true`, and emits:

```solidity
ProofInputHashFactAnchored(uint256 indexed sourceL2Verifier, uint256 indexed factHigh, uint256 indexed factLow)
```

The method is nonpayable. M.6C rejects nonzero value through the inherited M.6B draft.

## Relayer Model

Supported model labels:

- `infrastructure_relayer`
- `permissionless_external_relayer`
- `operator_account`
- `user_smart_account`
- `developer_fixture`
- `unsupported`

Recommended Beta/Testnet model:

```text
infrastructure_relayer or permissionless_external_relayer
```

The relayer pays L1 gas and owns the nonce. The relayer receives no PhilCore authorization authority. It can only consume an already-valid Starknet L2-to-L1 message through the exact anchor transaction.

`developer_fixture` is allowed only for unit tests and non-mutating diagnostics.

## Key Custody

Production key custody is not implemented in M.6C.

Acceptable future custody options include:

- external operator signer;
- HSM or cloud KMS;
- encrypted local testnet relayer key;
- macOS Keychain or Secure Enclave, if supported by a future platform boundary.

Plaintext environment variables are not the production custody model. Fixture private keys are test-only and must not be used for live public profiles unless explicitly designated as disposable Sepolia development accounts.

## Signing Presentation

Before signing, the boundary creates a signing presentation and digest bound to:

- Ethereum network/profile and chain ID;
- relayer account;
- anchor contract;
- method selector;
- Starknet sender;
- L1 recipient;
- message hash;
- `proofInputHash`;
- `fact_high`;
- `fact_low`;
- nonce;
- gas limit;
- fee envelope;
- expiry;
- audit correlation.

Approval binds to the exact presentation digest. Any mutation after presentation requires a new signing cycle.

## Last-Moment Revalidation

Before signing, M.6C revalidates:

- message availability;
- anchor deployment and messaging-core configuration;
- expected Starknet sender;
- chain ID;
- nonce;
- gas estimate;
- fee data;
- fee and gas caps;
- relayer balance status;
- approval digest;
- calldata hash and fact split;
- expiry.

Before submission, M.6C revalidates:

- message availability and not-consumed status;
- anchor deployment;
- nonce;
- gas;
- fees;
- submission approval;
- expiry;
- duplicate-submission guard.

These checks are snapshots. They are not durable reservations.

## Signed Artifact

A successful signed artifact states:

```text
transactionSigned: true
transactionSubmitted: false
messageConsumed: false
factAnchored: false
l1ToBaseRelayPrepared: false
baseStateChanged: false
nullifierConsumed: false
```

The artifact may contain a raw signed transaction for bounded submission through the M.6C submitter. It must not contain private keys, seed phrases, mnemonics, witness material, vault material, or unrestricted signer access.

## Submission Boundary

Submission accepts only the exact signed L1 fact-anchor artifact and an exact submission approval.

The submitter is not a generic Ethereum transaction API. It must not sign, mutate, or submit arbitrary transactions.

Live Sepolia submission requires all of:

- Ethereum Sepolia profile;
- actual Starknet Sepolia publication receipt;
- independently validated live message evidence;
- accepted L1 anchor deployment;
- verified anchor/messaging-core configuration;
- approved relayer;
- protected signer;
- sufficient fee balance;
- explicit submission approval;
- fresh nonce and fees.

If these prerequisites are absent, diagnostics report:

```text
live_l1_submission_performed: false
```

## Receipt Monitoring

Receipt monitoring recognizes pending, confirmed, reverted, rejected, and dropped/replaced-style outcomes where the reader exposes them.

After confirmation, M.6C validates:

- receipt status;
- confirmation threshold;
- event contract address;
- event signature;
- `sourceL2Verifier`;
- `fact_high`;
- `fact_low`;
- optional read-only anchor state if available.

If the anchor exposes no live read-only fact lookup, event evidence plus Starknet message-consumption evidence must be documented as the available proof. The repository contract does expose `anchoredProofInputHashFact(factHigh, factLow)`.

A successful receipt states separately:

```text
transactionConfirmed: true
l2ToL1MessageConsumed: true
l1FactAnchored: true
l1ToBaseRelayPrepared: false
l1ToBaseRelaySubmitted: false
baseFactMirrored: false
nullifierConsumed: false
consumerExecuted: false
```

## Duplicate And Idempotency Behavior

The L1 anchor consumes the Starknet message. Another caller may anchor first. Repeat submission may revert or fail once the message is consumed.

Process-local duplicate guards are only supplementary. Crash/restart recovery must reconcile through transaction hash, nonce, receipt, and message availability.

No blind retry is safe after ambiguous submission.

## Runtime And Adapter Boundary

Internal boundary methods:

- `requestL1FactAnchorTransactionSigning`
- `requestL1FactAnchorSubmission`
- `requestL1FactAnchorReceiptMonitoring`

Applications must not receive:

- relayer signer access;
- generic Ethereum signer access;
- arbitrary transaction submission access;
- unrestricted RPC mutation access.

## Diagnostics

```bash
npm run diagnose:l1-fact-anchor-signing -- --json
npm run submit:l1-fact-anchor-sepolia -- --json
npm run monitor:l1-fact-anchor -- --json
```

The current commands are non-mutating by default. `submit:l1-fact-anchor-sepolia` reports missing live Sepolia prerequisites and does not submit using fixture evidence.

## Negative Guarantees

M.6C does not:

- submit Ethereum mainnet transactions;
- use fixture evidence for live submission;
- relay to Base;
- call Base contracts;
- call `verifyAndConsume(...)`;
- consume PhilCore nullifiers;
- execute authorization consumers;
- expose private keys;
- turn PhilCore applications into Ethereum wallets;
- modify contracts or ABIs;
- modify proof schemas or public inputs;
- modify `ACTION_UNLOCK`;
- modify `proofInputHash`;
- modify `[fact_high, fact_low]`;
- modify fact ordering.

## Remaining Blockers

- accepted Ethereum Sepolia L1 anchor deployment;
- independently validated live Starknet Sepolia message evidence;
- accepted protected relayer signer;
- live Sepolia RPC/fee/balance policy;
- explicit live submission approval workflow;
- production receipt/finality policy;
- crash/restart reconciliation policy;
- L1-to-Base relay preparation and signing/submission live prerequisites.

## M.6D Follow-On

The L1-to-Base relay preparation boundary is documented in [L1-To-Base Fact Relay Preparation Boundary](./L1_TO_BASE_FACT_RELAY_PREPARATION_BOUNDARY.md).

M.6D consumes confirmed L1 anchoring evidence, verifies the fact remains anchored, validates relay/messenger/mirror configuration, and prepares an unsigned `relayProofInputHashFactToBase(baseMirror, factHigh, factLow)` transaction draft. It still does not sign, submit, send a cross-domain message, mirror the fact on Base, consume nullifiers, or execute consumers.

## M.6E Follow-On

The L1-to-Base relay signing, submission, and monitoring boundary is documented in [L1-To-Base Relay Signing, Submission, And Monitoring Boundary](./L1_TO_BASE_RELAY_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md).

M.6E signs only the exact M.6D relay draft, binds the caller-supplied `baseMirror` to an approved Base mirror configuration, optionally submits only with live Sepolia prerequisites and approval, monitors relay delivery, and verifies Base mirror state. It still stops before Base authorization execution and nullifier consumption.
