# Base Authorization Execution Signing, Submission, And Monitoring Boundary

Phase M.8 is the first controlled boundary that can cross from preparation into Base execution. It consumes a valid M.7 unsigned draft for:

```solidity
PhilBaseActionGate.verifyAndConsume(
  BaseActionAuthorization authorization,
  UnlockProofPackage proofPackage,
  bytes consumerData
) external payable returns (bytes)
```

The method selector remains `0xb1952061`.

## Scope

M.8 may authorize, sign, submit, and monitor exactly one prepared Base execution transaction when every prerequisite is present. A successful live transaction may consume the PhilCore nullifier, execute the authorization consumer, transfer the approved value, and mutate Base state.

M.8 must not provide a general Base wallet, arbitrary transaction signer, arbitrary message signer, generic RPC mutation API, or application-facing submitter.

## Caller Model

Initial Beta/Testnet model:

- preferred production direction: PhilCore-controlled ERC-4337 Smart Account;
- current bounded implementation: PhilCore-controlled EOA compatibility caller for local and controlled testnet work only;
- applications never receive signer or submitter access.

The EOA compatibility caller receives no PhilCore authorization authority beyond the exact signed transaction. It signs only the immutable `verifyAndConsume(...)` transaction bound to the M.7 draft and final execution approval.

## Custody Model

Local tests and diagnostics may use developer fixture keys. Fixture keys are not production custody.

Recommended testnet custody path:

- protected local testnet key or external operator wallet for early controlled Sepolia tests;
- migrate to PhilCore Smart Account / ERC-4337 execution for Beta product flow;
- do not use plaintext environment variables as the production custody model.

## Final Execution Approval

The final execution approval is distinct from the earlier platform action approval.

The earlier approval says: the user approved the intended action.

The M.8 approval says: this exact on-chain transaction may consume the nullifier and execute the consumer.

Approval binds to a presentation digest containing:

- Base chain/profile;
- caller;
- ActionGate, verifier, mirror, and consumer;
- method selector;
- calldata hash;
- proofInputHash;
- public nullifier;
- fact pair;
- capability, session, application, and owner references;
- target and consumer-data hash;
- transaction value;
- nonce, gas, and fee envelope;
- expiry and audit correlation.

Any mutation invalidates the approval and requires a new cycle.

## Required Revalidation

Immediately before signing and again before submission, M.8 revalidates:

- active authoritative Capability Grant;
- eligible User Session lifecycle state;
- finalized Authorization Package binding through the M.7 draft;
- mirrored fact presence;
- nullifier availability;
- ActionGate/verifier/mirror/consumer configuration;
- exact calldata hash;
- transaction value;
- caller account;
- nonce, gas, and fees;
- final execution approval;
- expiry.

If any signed field changes, signing must be rejected and restarted.

## Submission And Monitoring

Submission is restricted to the exact signed artifact. The submitter cannot submit arbitrary transactions.

Receipt monitoring validates:

- confirmed transaction receipt;
- `AuthorizationConsumed` event from the configured ActionGate;
- nullifier consumption through the ActionGate mapping getter;
- consumer execution evidence from the configured consumer;
- approved action match.

A confirmed receipt alone is not sufficient; nullifier and consumer evidence are independently checked.

## Atomicity And Replay

The actual ActionGate writes `consumedNullifier[nullifier] = true` before calling the consumer, but both operations are in the same transaction. If the consumer reverts, the nullifier write rolls back.

Local tests confirm:

- successful execution consumes exactly one nullifier;
- replay fails;
- missing mirrored fact does not consume the nullifier;
- wrong consumer data does not consume the nullifier;
- consumer revert rolls back nullifier consumption;
- direct consumer calls fail because `PhilUnlockConsumer` requires the ActionGate caller;
- approved value is forwarded exactly.

## Post-Execution Capability And Session State

M.8 does not durably mutate Capability Grant or User Session state.

Future work must define durable reconciliation for:

- use-count decrement or one-time grant exhaustion;
- post-execution audit persistence;
- session lifecycle refresh or lock behavior;
- transaction receipt reconciliation after crash/restart.

## ERC-4337 Follow-On

M.8 keeps the local/testnet EOA compatibility path explicit. M.9A proposes the first real ERC-4337 foundation for the preferred PhilCore Smart Account path: [PhilCore ERC-4337 Smart Account Foundation](./PHILCORE_ERC4337_SMART_ACCOUNT_FOUNDATION.md).

That foundation uses EntryPoint v0.7 and a minimal account whose `execute(address,uint256,bytes)` method rejects direct owner execution and only allows EntryPoint or self calls. It remains unaudited, proposed, and non-production-approved. It does not sign or submit UserOperations.

M.9 now defines the unsigned UserOperation preparation boundary: [PhilCore ERC-4337 UserOperation Preparation Boundary](./PHILCORE_ERC4337_USER_OPERATION_PREPARATION_BOUNDARY.md). M.10 should define signing separately; M.8 remains the EOA compatibility signing/submission path.

## Diagnostics

Non-mutating local diagnostics:

```bash
npm run diagnose:base-execution-signing
npm run submit:base-authorization-execution-sepolia
npm run monitor:base-authorization-execution
npm run verify:base-nullifier-consumption
npm run verify:base-consumer-execution
```

The current commands are fixture/local diagnostics. They report `live_base_execution_performed: false` unless complete live Base Sepolia prerequisites and explicit approval exist.

## Negative Guarantees

M.8 does not modify contracts, ABIs, proof schemas, public inputs, `ACTION_UNLOCK`, `proofInputHash`, or `[fact_high, fact_low]`.

M.8 does not submit to Base mainnet. It does not use fixture mirrored-fact evidence for live execution. It does not expose private keys, raw proof bytes, witness material, or full sensitive consumer data in audit drafts.
