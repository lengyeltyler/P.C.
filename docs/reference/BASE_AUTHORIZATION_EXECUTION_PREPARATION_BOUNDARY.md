# Base Authorization Execution Preparation Boundary

Phase M.7 defines the controlled preparation boundary for Base authorization execution through:

```solidity
function verifyAndConsume(
  BaseActionAuthorization calldata authorization,
  UnlockProofPackage calldata proofPackage,
  bytes calldata consumerData
) external payable returns (bytes memory result)
```

This boundary prepares an unsigned, unsubmitted Base transaction draft only. It does not sign, submit, consume a nullifier, execute a consumer, mutate Base state, create a UserOperation, call a bundler, or call a paymaster.

## Actual Contract Behavior

`PhilBaseActionGate.verifyAndConsume(...)` accepts:

- `BaseActionAuthorization`: `consumer`, `ownerCommitment`, `actionHash`, `policyHash`, `nullifier`, `consumerDataHash`, `expiry`.
- `UnlockProofPackage`: `version`, `proofType`, `publicInputs`, `proofInputHash`, `proofBlob`.
- `consumerData`: encoded consumer-specific data.

The method selector is `0xb1952061`. The method is payable.

The gate checks:

- consumer address has code;
- authorization expiry;
- `keccak256(consumerData) == consumerDataHash`;
- proof version and proof type;
- exact equality between authorization tuple and proof public inputs;
- recomputed `proofInputHash`;
- nullifier has not already been consumed.

For `proofType = "stwo-unlock-keccak-v1"`, the gate calls the configured unlock proof verifier. With the current Base mirrored verifier, the proof blob is ABI-encoded `(uint256 factHigh, uint256 factLow)`. The verifier recomposes the `proofInputHash` and checks the Base mirror state.

If verification succeeds, the gate sets `consumedNullifier[authorization.nullifier] = true`, then calls:

```solidity
authorization.consumer.consumePhilAuthorization{value: msg.value}(
  authorization,
  consumerData
)
```

If consumer execution reverts, the whole transaction reverts and the nullifier write rolls back. A successful transaction emits `AuthorizationConsumed`.

## Required Inputs

Preparation requires:

- confirmed Base mirrored-fact evidence;
- finalized non-executing Authorization Package;
- active authoritative Capability Grant;
- eligible User Session lifecycle snapshot;
- exact `consumerData`;
- ActionGate, verifier, mirror, messenger, remote-sender, and consumer configuration;
- read-only nullifier-state result;
- optional read-only simulation/gas estimate;
- nonce and fee references for draft completeness.

Fixture/local mirrored evidence may be used for tests and diagnostics, but it cannot produce a production-signable draft.

## Consumer Data And Value

For `PhilUnlockConsumer`, `consumerData` is an encoded `UnlockRequest`:

```solidity
struct UnlockRequest {
  address account;
  address target;
  uint256 value;
  bytes callData;
}
```

`PhilUnlockConsumer` requires `msg.sender == actionGate`, checks `msg.value == request.value`, recomputes the `actionHash`, and forwards the call/value to `request.target.onPhilUnlock(...)`.

The prepared transaction value is bound to the decoded authorized value. M.7 does not allow hidden value increases or arbitrary consumer-data mutation.

## Draft Semantics

A successful draft states:

- `transactionPrepared: true`
- `transactionSigned: false`
- `transactionSubmitted: false`
- `nullifierConsumed: false`
- `consumerExecuted: false`
- `baseStateMutated: false`
- `userOperationCreated: false`
- `applicationCanSubmitDirectly: false`

The draft is a call specification, not execution authority.

## Caller Model

The contract itself does not restrict the caller: any Base caller with a valid package can submit. Runtime must still treat signing/submission as a controlled Ethereum Adapter boundary.

Recommended Beta/Testnet model: PhilCore-controlled smart account or approved execution relayer, with explicit final execution approval, fresh mirrored-fact verification, fresh nullifier availability, and protected signer custody. Applications must not receive generic signing or submission authority.

## Diagnostics

Non-mutating local diagnostics:

```bash
npm run diagnose:base-authorization-execution-preparation
npm run simulate:base-authorization-execution
```

These commands use fixture/local inputs by default. They may prepare an unsigned draft and run fixture simulation, but they do not sign, submit, consume nullifiers, execute consumers, or mutate Base state.

## Remaining Blockers

- accepted live Base mirrored-fact evidence;
- accepted Base Sepolia ActionGate/verifier/mirror/consumer deployments;
- final caller/signer custody model;
- final execution approval boundary;
- signing, submission, and receipt monitoring boundary.

## Downstream Boundary

Phase M.8 defines the downstream controlled signing, submission, and monitoring boundary: [Base Authorization Execution Signing, Submission, And Monitoring](./BASE_AUTHORIZATION_EXECUTION_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md).

M.8 consumes one valid M.7 draft and requires fresh mirrored-fact, nullifier, capability, session, configuration, nonce, gas, fee, caller, and final approval checks before signing or submission.

Phase M.9A proposes the ERC-4337 Smart Account foundation that future UserOperation preparation should reuse: [PhilCore ERC-4337 Smart Account Foundation](./PHILCORE_ERC4337_SMART_ACCOUNT_FOUNDATION.md). It selects EntryPoint v0.7, a minimal PhilCore account/factory, an ECDSA Beta validator, and a local Hardhat fixture. It does not sign or submit UserOperations and remains proposed until accepted.

Phase M.9 adds the controlled preparation boundary for wrapping one valid M.7 draft into an unsigned EntryPoint v0.7 `PackedUserOperation`: [PhilCore ERC-4337 UserOperation Preparation Boundary](./PHILCORE_ERC4337_USER_OPERATION_PREPARATION_BOUNDARY.md). It does not sign, submit, invoke a bundler, invoke a paymaster, deploy an account, consume a nullifier, execute a consumer, or mutate Base state.
