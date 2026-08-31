# L1-To-Base Fact Relay Preparation Boundary

Status: Draft M.6D reference.

This document defines the controlled Ethereum L1 preparation boundary for relaying an already anchored proof-input-hash fact to Base.

M.6D may consume a confirmed L1 fact-anchor receipt or explicitly classified fixture receipt, verify the fact is anchored on L1, validate relay/messenger/mirror configuration, encode the exact relay calldata, and produce an unsigned, unsubmitted L1 relay transaction draft.

It does not sign, submit, send a cross-domain message, call the Base mirror directly, claim Base mirroring, call `verifyAndConsume(...)`, consume a PhilCore nullifier, execute a consumer, or mutate L1/Base state.

## Actual Relay Interface

The reused L1 relay contract is:

```text
contracts/l1/PhilL1ToBaseProofInputHashMessenger.sol
```

The relay method is:

```solidity
relayProofInputHashFactToBase(address baseMirror, uint256 factHigh, uint256 factLow)
```

The method is external and nonpayable. It checks:

```solidity
trustAnchor.anchoredProofInputHashFact(factHigh, factLow)
```

Then it calls:

```solidity
crossDomainMessenger.sendMessage(
    baseMirror,
    abi.encodeCall(
        IPhilBaseProofInputHashMirror.mirrorProofInputHashFact,
        (factHigh, factLow)
    )
)
```

and emits:

```solidity
ProofInputHashFactRelayedToBase(address indexed baseMirror, uint256 indexed factHigh, uint256 indexed factLow)
```

## Base Mirror Payload

The Base mirror target method is:

```solidity
mirrorProofInputHashFact(uint256 factHigh, uint256 factLow)
```

The mirror contract checks:

```text
msg.sender == crossDomainMessenger
xDomainMessageSender() == authorizedL1Messenger
```

M.6D prepares a payload preview only:

```text
messageSent: false
baseMirrorCalled: false
baseFactMirrored: false
```

## Anchored-Fact Evidence

Evidence classes:

- `live_l1_receipt`
- `local_hardhat_receipt`
- `fixture_receipt`
- `manual_reference`
- `unsupported`

The evidence binds the anchor transaction, block reference, anchor contract, `ProofInputHashFactAnchored` event, fact pair, `proofInputHash`, Starknet message hash, expected Starknet sender, Ethereum chain ID, confirmations, and audit correlation.

Fixture/local evidence may be used for tests and diagnostics. Fixture/local evidence cannot produce a production-signable relay draft.

## Read-Only Fact Verification

The L1 anchor exposes:

```solidity
anchoredProofInputHashFact(uint256 factHigh, uint256 factLow) returns (bool)
```

M.6D verifies the exact fact pair through a read-only reader. Reads are snapshots and must be repeated before future relay signing/submission.

## Relay Configuration

Configuration binds the L1/Base network profile, L1 relay contract, L1 anchor contract, L1 cross-domain messenger adapter, canonical Base messenger, Base mirror, authorized L1 remote sender, relay and mirror selectors, message encoding version, gas policy, fee/value policy, and deployment approval status.

Mainnet remains disabled by this boundary.

## Fee, Value, And Gas Behavior

The actual `PhilL1ToBaseProofInputHashMessenger.relayProofInputHashFactToBase(...)` method is nonpayable, so M.6D enforces:

```text
value = 0
```

The underlying `PhilBaseCrossDomainMessengerAdapter.sendMessage(...)` calls the Base messenger with a configured `minGasLimit`. The current adapter method is nonpayable and does not expose a live fee quote in this boundary.

Future live relay submission must re-evaluate canonical bridge fee behavior before signing.

## Draft Semantics

A successful draft states:

```text
transactionPrepared: true
transactionSigned: false
transactionSubmitted: false
crossDomainMessageSent: false
baseMirrorCalled: false
baseFactMirrored: false
baseExecutionPrepared: false
nullifierConsumed: false
consumerExecuted: false
chainStateMutated: false
```

Fixture-derived drafts also state:

```text
liveAnchoredFactEvidence: false
productionSignable: false
```

The draft is a call specification, not relay authority.

## M.6E Signing, Submission, And Monitoring

M.6E adds the next controlled boundary for this exact draft. It may authorize a restricted relayer, bind the caller-supplied `baseMirror` to an approved Base mirror configuration, sign the exact immutable L1 relay transaction, optionally submit only with live Sepolia prerequisites and explicit approval, monitor the L1 receipt, monitor cross-domain delivery, and verify Base mirror state.

See [L1-To-Base Relay Signing, Submission, And Monitoring Boundary](./L1_TO_BASE_RELAY_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md).

M.6E still does not call the Base mirror directly, call `verifyAndConsume(...)`, consume a nullifier, execute a consumer, prepare final Base authorization execution, or provide applications with generic Ethereum/Base signing authority.

## Caller And Fee-Payer Model

Recommended Beta/Testnet model:

```text
infrastructure_or_permissionless_cross_domain_relayer
```

The caller pays L1 gas and owns the nonce. The caller receives no PhilCore application authorization authority.

Because the relay method accepts `baseMirror` as an argument, production configuration must bind the accepted Base mirror address exactly before signing. The Base mirror still protects itself with canonical messenger and authorized L1 remote sender checks.

## Diagnostics

```bash
npm run diagnose:l1-anchored-fact -- --json
npm run diagnose:l1-to-base-relay-preparation -- --json
```

Diagnostics are fixture/local and non-mutating by default.

## Negative Guarantees

M.6D does not sign or submit relay transactions, send cross-domain messages, call the Base mirror directly, claim Base mirroring, call `verifyAndConsume(...)`, consume PhilCore nullifiers, execute authorization consumers, mutate L1/Base state, or modify `ACTION_UNLOCK`, `proofInputHash`, `[fact_high, fact_low]`, relay ABI, Base mirror ABI, messenger authorization rules, proof schemas, or public inputs.

## Remaining Blockers

- confirmed live L1 anchoring evidence;
- accepted Sepolia L1 relay deployment;
- accepted L1 messenger and Base mirror deployment;
- accepted canonical Base messenger configuration;
- approved relay signer/custody model;
- fee/finality policy for live L1-to-Base relay submission;
- explicit relay submission approval;
- Base mirror monitoring evidence on Base Sepolia;
- future Base authorization execution preparation boundary.
