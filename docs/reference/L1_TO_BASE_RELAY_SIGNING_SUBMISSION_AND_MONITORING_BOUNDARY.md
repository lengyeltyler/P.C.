# L1-To-Base Relay Signing, Submission, And Monitoring Boundary

Status: Draft M.6E reference.

This document defines the controlled boundary after M.6D relay preparation for:

```solidity
relayProofInputHashFactToBase(address baseMirror, uint256 factHigh, uint256 factLow)
```

M.6E may consume one valid M.6D unsigned relay draft, bind the caller-supplied `baseMirror` to an approved Base mirror configuration, authorize a restricted cross-domain relayer, sign the exact immutable L1 relay transaction, submit it only when live Sepolia prerequisites are explicitly approved, monitor the L1 receipt, monitor cross-domain delivery, and verify the Base mirror state.

It does not call the Base mirror directly, call `verifyAndConsume(...)`, prepare final Base authorization execution, consume a PhilCore nullifier, execute a consumer, expose private keys, or provide applications with generic Ethereum/Base signing or submission authority.

## Actual Interfaces

The L1 relay method is implemented by:

```text
contracts/l1/PhilL1ToBaseProofInputHashMessenger.sol
```

It is external and nonpayable. It checks the L1 anchor mapping, calls the configured L1 cross-domain messenger adapter, and emits:

```solidity
ProofInputHashFactRelayedToBase(address indexed baseMirror, uint256 indexed factHigh, uint256 indexed factLow)
```

The Base mirror method remains:

```solidity
mirrorProofInputHashFact(uint256 factHigh, uint256 factLow)
```

Only the configured Base messenger may call it, and the messenger must report the configured authorized L1 remote sender.

## Approved Base Mirror Binding

`baseMirror` is caller supplied in the L1 relay method, so M.6E requires an approved mirror binding before signing or submission.

The binding includes:

- Base chain ID;
- approved Base mirror address;
- Base messenger address;
- authorized L1 remote sender;
- deployment/configuration version;
- optional code or ABI reference;
- fixture/live classification.

The signing presentation, signer request, submission approval, receipt monitoring, and Base mirror verification all compare against the approved mirror binding. A fixture mirror cannot be promoted to live public-network submission.

## Relayer And Custody Model

Supported relayer modes include:

- `infrastructure_cross_domain_relayer`
- `permissionless_external_relayer`
- `operator_account`
- `sponsored_relay_service`
- `developer_fixture`
- `unsupported`

Recommended Beta/Testnet model:

```text
infrastructure_cross_domain_relayer
```

The relayer pays L1 gas and owns the nonce. The relayer receives no PhilCore application authority and no right to alter the target mirror, fact pair, fee envelope, calldata, or transaction value after approval.

Production custody is not implemented in M.6E. Acceptable future custody models include an external operator signer, HSM/KMS, or encrypted testnet relayer key. Plaintext environment variables are not the production custody model.

## Signing Presentation

M.6E signs only after building a digest-bound presentation containing:

- L1 and Base chain IDs;
- relayer account;
- L1 relay contract;
- L1 messenger;
- Base messenger;
- approved Base mirror;
- authorized L1 remote sender;
- `factHigh`;
- `factLow`;
- `proofInputHash`;
- relay calldata hash;
- expected Base mirror calldata hash;
- nonce;
- gas limit;
- transaction value;
- max fee and priority fee;
- expiry;
- audit correlation.

Any mutation requires a new presentation, approval, and signature.

## Signed Relay Artifact

A successful signed artifact states:

```text
transactionSigned: true
transactionSubmitted: false
crossDomainMessageSent: false
baseMirrorCalled: false
baseFactMirrored: false
baseExecutionPrepared: false
nullifierConsumed: false
consumerExecuted: false
```

Fixture-derived artifacts include a limitation that they are not live-submission evidence.

## Submission Boundary

Submission accepts only the exact signed relay artifact and exact submission approval.

Before submission, M.6E revalidates anchored fact state, deployment/configuration, nonce, gas, fee data, approval, expiry, and duplicate-submission state. The submitter is restricted to this relay artifact and is not a generic Ethereum transaction API.

Live submission requires all of:

- Ethereum Sepolia;
- Base Sepolia;
- confirmed live L1 fact anchoring;
- accepted L1 relay, L1 messenger, Base messenger, and Base mirror deployments;
- approved protected relayer custody;
- sufficient balance;
- explicit submission approval.

Current diagnostics report:

```text
live_relay_submission_performed: false
```

because live evidence, accepted deployments, custody, and approval are unresolved.

## Monitoring Boundary

Receipt monitoring validates:

- confirmed L1 transaction receipt;
- `ProofInputHashFactRelayedToBase` event;
- fact pair and approved Base mirror;
- cross-domain message status from an explicit monitor;
- Base mirror state through a read-only reader.

A confirmed L1 relay receipt does not itself prove Base delivery. Base mirror verification is a separate read-only step.

Successful delivery evidence states:

```text
l1RelayConfirmed: true
crossDomainMessageRelayed: true
baseFactMirrored: true
baseAuthorizationExecutionPrepared: false
baseAuthorizationExecutionSubmitted: false
nullifierConsumed: false
consumerExecuted: false
```

## Messenger Authorization Invariants

M.6E preserves and tests:

- direct EOA calls to `mirrorProofInputHashFact(...)` fail;
- calls through the wrong Base messenger fail;
- calls with the wrong L1 remote sender fail;
- only the configured Base messenger plus authorized L1 remote sender can update the mirror.

Diagnostics must not weaken these restrictions.

## Duplicate And Idempotency Behavior

Duplicate relay submissions can create duplicate cross-domain messages and fees. The Base mirror mapping is idempotent, but repeated relay attempts are not free and should not be retried blindly after ambiguous L1 submission.

Process-local duplicate guards are only supplementary. Crash/restart recovery must reconcile through transaction hash, nonce, receipt, L1 event evidence, and Base mirror state.

## Runtime And Adapter Boundary

Internal methods:

- `requestL1ToBaseRelaySigning`
- `requestL1ToBaseRelaySubmission`
- `requestL1ToBaseRelayMonitoring`
- `requestBaseFactMirrorVerification`

Applications must not receive signer access, submitter access, raw messenger controls, direct Base mirror calls, or arbitrary L1/Base transaction authority.

## Diagnostics

```bash
npm run diagnose:l1-to-base-relay-signing -- --json
npm run submit:l1-to-base-relay-sepolia -- --json
npm run monitor:l1-to-base-relay -- --json
npm run verify:base-fact-mirror -- --json
```

The current commands are fixture/local and non-mutating for live networks. The submit command does not perform live Sepolia submission without live evidence, accepted deployments, protected custody, and approval.

## Negative Guarantees

M.6E does not submit to mainnet, use fixture anchoring evidence for live submission, redirect to arbitrary Base mirrors, call the Base mirror directly, call `verifyAndConsume(...)`, consume a nullifier, execute a consumer, prepare final Base execution, expose private keys, modify contracts, modify ABIs, modify proof schemas, modify public inputs, modify `proofInputHash`, or change fact ordering.

## Remaining Blockers

- confirmed live L1 fact-anchor receipt;
- accepted Ethereum Sepolia and Base Sepolia relay/messenger/mirror deployments;
- accepted protected relayer custody;
- live fee/finality policy;
- explicit live relay submission approval;
- Base Sepolia mirror monitoring evidence;
- future Base `verifyAndConsume(...)` execution preparation boundary.

## Downstream Boundary

After Base mirror verification succeeds, the next boundary is [Base Authorization Execution Preparation](./BASE_AUTHORIZATION_EXECUTION_PREPARATION_BOUNDARY.md). That boundary prepares the exact `PhilBaseActionGate.verifyAndConsume(...)` calldata only; it does not sign, submit, consume the PhilCore nullifier, or execute the authorization consumer.
