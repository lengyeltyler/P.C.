# L1 Message Availability And Fact-Anchor Preparation Boundary

Status: Draft M.6B reference.

This document defines the Ethereum L1 boundary after Starknet publication receipt monitoring and before L1 message consumption.

M.6B may independently check whether the exact Starknet L2-to-L1 message is available and may prepare the unsigned Ethereum transaction for:

```solidity
PhilL1ProofInputHashAnchor.consumeProofInputHashFactFromL2(
    uint256 factHigh,
    uint256 factLow
)
```

It does not consume the message, submit or sign an Ethereum transaction, anchor the fact, relay to Base, call the Base mirror, call `verifyAndConsume(...)`, consume a PhilCore nullifier, or execute an authorization consumer.

## Actual Interfaces

The L1 anchor contract is:

```text
contracts/l1/PhilL1ProofInputHashAnchor.sol
```

The anchor method is:

```solidity
consumeProofInputHashFactFromL2(uint256 factHigh, uint256 factLow)
```

The contract builds:

```solidity
payload = [factHigh, factLow]
```

and calls:

```solidity
starknetMessaging.consumeMessageFromL2(sourceL2Verifier, payload)
```

The repository interface for Starknet messaging is:

```solidity
consumeMessageFromL2(uint256 fromAddress, uint256[] calldata payload)
```

That interface is state-changing. It does not itself expose a read method. The repository mock used by tests additionally exposes:

```solidity
messageCount(bytes32 messageHash)
l2ToL1MessageHash(uint256 fromAddress, address toAddress, uint256[] payload)
```

M.6B uses that mock-compatible hash/count model for fixture/local read-only availability. A live production reader must use whatever read-only method the actual Starknet Ethereum messaging core supports, or clearly report that independent availability is unknown.

## Message Identity

The message identity binds:

- Starknet network/profile;
- Starknet publication contract as L2 sender;
- Starknet transaction hash;
- Starknet block reference when available;
- L1 anchor recipient;
- exact payload length `2`;
- exact payload `[fact_high, fact_low]`;
- `proofInputHash`;
- verification event reference;
- message hash/reference;
- audit correlation.

The locked payload ordering remains:

```text
[fact_high, fact_low]
```

The helper rejects high/low reversal, wrong sender, wrong recipient, wrong payload length, proof-input-hash split mismatch, and message-hash mismatch.

## Message Hash

The local/mock parity hash is:

```solidity
keccak256(abi.encodePacked(fromAddress, uint256(uint160(toAddress)), payload.length, payload))
```

M.6B tests compare the TypeScript helper against the actual `MockStarknetMessaging.l2ToL1MessageHash(...)` implementation.

## Evidence Classes

Evidence is explicitly classified:

- `live_starknet_receipt`
- `local_devnet_receipt`
- `fixture_receipt`
- `manual_reference`
- `unsupported`

Fixture and local evidence may be used for tests and diagnostics. Fixture evidence can create a non-production-signable draft but must not be promoted to live production authority.

## Availability Reads

The availability reader is read-only.

Outcomes include:

- `message_available`
- `message_not_available`
- `message_already_consumed`
- `message_state_unknown`
- `messaging_core_unavailable`
- `stale_read`

Availability reads are snapshots. They do not reserve the message and must be repeated before any future signing or submission.

## L1 Anchor Configuration

Configuration binds:

- Ethereum network/profile;
- Ethereum chain ID;
- L1 anchor address;
- Starknet messaging-core address;
- expected Starknet publication contract address;
- expected Starknet network/profile;
- anchor method selector;
- expected payload shape;
- deployment approval status.

Mainnet remains disabled by this boundary.

## Unsigned Transaction Draft

A successful transaction draft contains:

- L1 anchor address;
- Ethereum chain ID;
- method name and selector;
- exact calldata;
- calldata hash;
- `fact_high`;
- `fact_low`;
- `proofInputHash`;
- message hash/reference;
- Starknet transaction reference;
- zero value;
- gas/fee/nonce status;
- issue time and expiry;
- race/freshness warning.

The anchor method is treated as nonpayable. Nonzero value is rejected.

Every successful draft states:

```text
transactionPrepared: true
transactionSigned: false
transactionSubmitted: false
l2ToL1MessageConsumed: false
l1FactAnchored: false
l1ToBaseRelayPrepared: false
baseFactMirrored: false
nullifierConsumed: false
chainStateMutated: false
```

Fixture-derived drafts also state:

```text
liveMessageEvidence: false
productionSignable: false
```

## Caller And Fee Payer

The anchor method is any-caller once the Starknet message exists. The caller pays L1 gas but gains no PhilCore authorization authority.

Recommended Beta/Testnet model:

```text
permissionless_or_infrastructure_l1_relayer
```

PhilCore may coordinate or prepare the transaction, but applications must not receive arbitrary signing or submission authority.

## Diagnostics

```bash
npm run diagnose:l1-message-availability -- --json
npm run diagnose:l1-fact-anchor-preparation -- --json
```

Diagnostics are fixture/local and non-mutating by default.

## M.6C Follow-On

The controlled L1 signing, submission, and receipt-monitoring boundary is documented in [L1 Fact-Anchor Signing, Submission, And Monitoring Boundary](./L1_FACT_ANCHOR_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md).

M.6C may sign one exact prepared L1 anchor transaction and may submit/monitor it only when live Sepolia prerequisites are present. It still does not relay to Base, call Base contracts, call `verifyAndConsume(...)`, consume nullifiers, or execute consumers.

## Negative Guarantees

M.6B does not:

- consume Starknet L2-to-L1 messages;
- submit Ethereum L1 transactions;
- sign Ethereum transactions;
- anchor facts;
- relay to Base;
- call Base contracts;
- consume nullifiers;
- execute authorization consumers;
- modify `ACTION_UNLOCK`;
- modify `proofInputHash`;
- modify `[fact_high, fact_low]`;
- modify Starknet message ordering;
- modify L1 anchor ABI;
- modify proof or contract schemas.

## Remaining Blockers

- live Starknet Sepolia receipt/message evidence;
- accepted Ethereum Sepolia L1 anchor deployment;
- accepted Starknet messaging-core read-only availability method;
- approved L1 relayer account;
- gas/fee/nonce policy for live L1 submission;
- explicit L1 submission approval;
- future receipt monitoring for actual L1 anchoring.
