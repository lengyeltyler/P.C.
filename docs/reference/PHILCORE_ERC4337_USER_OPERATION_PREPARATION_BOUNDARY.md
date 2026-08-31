# PhilCore ERC-4337 UserOperation Preparation Boundary

Architecture status: Current Ethereum/Base compatibility boundary. Its public
`ownerCommitment` metadata is not the accepted V1 public identity surface.
Future adapter work must use the scoped identity and authorization-envelope
contract in `docs/PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md` after the preceding
ACP-0003 gates pass.

Phase: M.9

This document defines the controlled preparation boundary for wrapping one valid M.7 Base authorization execution draft into an ERC-4337 v0.7 `PackedUserOperation` draft. It uses the proposed M.9A `PhilCore4337Account`, `PhilCore4337AccountFactory`, and EntryPoint v0.7 foundation.

ACP-0002 remains `Proposed`.

## Scope

The boundary may:

- validate the proposed PhilCore ERC-4337 foundation configuration;
- verify a deployed PhilCore account through read-only account state;
- resolve a counterfactual account through the actual factory model;
- wrap the exact M.7 `PhilBaseActionGate.verifyAndConsume(...)` call through `PhilCore4337Account.execute(address,uint256,bytes)`;
- bind the prepared target to the account's immutable approved ActionGate as defense in depth;
- construct an unsigned EntryPoint v0.7 `PackedUserOperation`;
- read the EntryPoint nonce through the default nonce key;
- evaluate gas, fees, and prefund through read-only or fixture interfaces;
- compute the canonical v0.7 UserOperation hash;
- run fixture/local simulation where explicitly supplied;
- create sanitized audit drafts and optional process-local draft records.

The boundary must not:

- sign the UserOperation;
- submit to a bundler;
- call `eth_sendUserOperation`;
- invoke a paymaster;
- deploy a live account;
- consume a nullifier;
- execute a live consumer;
- mutate live Base state;
- expose an ECDSA validator key, Device Vault material, witness material, or proof secrets;
- let applications construct arbitrary UserOperations.

## Actual Interfaces

Account:

```solidity
execute(address target, uint256 value, bytes calldata data)
```

Factory:

```solidity
createAccount(address owner, bytes32 ownerCommitment, uint256 salt)
getAddress(address owner, bytes32 ownerCommitment, uint256 salt)
```

EntryPoint:

- version: v0.7
- schema: `PackedUserOperation`
- hash: actual `EntryPoint.getUserOpHash(PackedUserOperation)` parity

## Preparation Flow

```text
Valid M.7 Base execution draft
  -> foundation/config validation
  -> deployed or counterfactual account resolution
  -> exact account execute(...) calldata
  -> EntryPoint nonce read
  -> v0.7 PackedUserOperation assembly
  -> gas/prefund read-only evaluation
  -> canonical UserOperation hash
  -> optional fixture/local simulation
  -> unsigned UserOperation draft
  -> audit draft
  -> stop
```

## Invariants

Every successful draft states:

- `entryPointVersion: "0.7"`
- `userOperationPrepared: true`
- `userOperationSigned: false`
- `userOperationSubmitted: false`
- `bundlerSubmissionPerformed: false`
- `paymasterInvoked: false`
- `smartAccountDeploymentPerformed: false`
- `nullifierConsumed: false`
- `consumerExecuted: false`
- `baseStateMutated: false`
- `applicationCanSubmitDirectly: false`

The draft stores `ownerCommitment` as public identity-binding metadata only. `ownerCommitment` is not signing authority.

## Packed Fields

The draft uses the v0.7 packed schema:

- `sender`
- `nonce`
- `initCode`
- `callData`
- `accountGasLimits`
- `preVerificationGas`
- `gasFees`
- `paymasterAndData`
- `signature`

`accountGasLimits` packs `verificationGasLimit` in the high 128 bits and `callGasLimit` in the low 128 bits. `gasFees` packs `maxPriorityFeePerGas` in the high 128 bits and `maxFeePerGas` in the low 128 bits.

`paymasterAndData` is empty. `signature` is empty.

## Simulation

Local simulation may use a fixture signer inside tests to exercise the actual EntryPoint path, but the Runtime preparation artifact remains unsigned. Fixture signatures are not exported as Runtime signatures and are not production authorization.

## Diagnostics

Non-submitting diagnostics:

```bash
npm run inspect:philcore-4337-account
npm run diagnose:philcore-user-operation-preparation
npm run simulate:philcore-user-operation
```

These commands use local/fixture data by default. They do not sign, submit, call a bundler, invoke a paymaster, deploy accounts, consume nullifiers, execute consumers, or mutate Base state.

## Future Boundary

M.10 should define the smallest controlled UserOperation authorization and signing boundary for the protected Beta ECDSA validator key. Bundler submission, paymaster invocation, live account deployment, and live Base mutation should remain disabled until separately reviewed.

M.10 is now defined in [PhilCore ERC-4337 UserOperation Signing Boundary](./PHILCORE_ERC4337_USER_OPERATION_SIGNING_BOUNDARY.md). It signs one exact M.9 draft through a protected Beta ECDSA signer interface and still stops before bundler submission, paymaster invocation, account deployment, nullifier consumption, consumer execution, or Base mutation.

M.11 is defined in [PhilCore ERC-4337 Bundler Submission And Monitoring Boundary](./PHILCORE_ERC4337_BUNDLER_SUBMISSION_AND_MONITORING_BOUNDARY.md). It consumes a signed M.10 artifact only after separate submission approval and last-moment revalidation.
