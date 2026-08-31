# PhilCore ERC-4337 Bundler Submission And Monitoring Boundary

Phase: M.11

This document defines the controlled boundary for submitting one exact M.10 signed EntryPoint v0.7 `PackedUserOperation` through a restricted bundler interface and monitoring the resulting UserOperation receipt.

ACP-0002 remains `Proposed`.

## Boundary

Implemented flow:

```text
Signed M.10 PackedUserOperation
  -> Runtime/account/bundler revalidation
  -> explicit submission approval
  -> exact packed v0.7 bundler serialization
  -> restricted UserOperation submission
  -> returned hash verification
  -> receipt monitoring
  -> EntryPoint/account/inner execution evidence
  -> bounded execution receipt
  -> stop
```

The boundary does not expose a generic bundler client to applications.

## Bundler Model

Supported profiles:

- `local_fixture`
- `local_entrypoint`
- `base_sepolia`
- `base_mainnet_disabled`

Default behavior is local and fixture-only. Base mainnet is rejected. Base Sepolia submission remains blocked until deployments, custody, funding, live mirrored fact evidence, approved bundler configuration, and explicit submission approval exist.

The restricted client may only:

- verify capabilities;
- submit the exact approved UserOperation;
- read an operation by hash;
- read a UserOperation receipt.

It must not expose arbitrary JSON-RPC, arbitrary `eth_sendUserOperation`, paymaster calls, EntryPoint controls, or generic transaction submission.

## Submission Approval

Submission approval is separate from signing approval. It is one-time, expiring, and bound to:

- one signed UserOperation;
- one UserOperation hash;
- one smart account;
- one EntryPoint;
- one bundler;
- one chain ID;
- one nonce;
- one callData hash;
- one gas and fee envelope;
- one Capability Grant;
- one User Session;
- one finalized Authorization Package;
- one audit correlation.

If any signed field or mutable prerequisite changes, PhilCore rejects submission. It does not rebuild, mutate, or resign the UserOperation.

## Serialization

M.11 serializes the signed v0.7 operation as the packed EntryPoint shape used by the local PhilCore foundation:

- `sender`
- `nonce`
- `initCode`
- `callData`
- `accountGasLimits`
- `preVerificationGas`
- `gasFees`
- `paymasterAndData`
- `signature`

Paymaster data must remain `0x`.

## Receipts

Receipt monitoring tracks:

- UserOperation hash;
- EntryPoint;
- sender;
- nonce;
- success flag;
- transaction hash;
- block reference;
- gas cost and gas used where available;
- paymaster, expected empty;
- bounded inner execution evidence.

A returned UserOperation hash mismatch is rejected.

## Inner Execution

A successful bounded execution receipt must separately state:

- `userOperationIncluded: true`
- `accountValidationSucceeded: true`
- `innerExecutionSucceeded: true`
- `nullifierConsumed: true`
- `consumerExecuted: true`
- `approvedActionMatched: true`
- `paymasterInvoked: false`

Bundler submission alone is not enough. EntryPoint inclusion, account/deployment state, nullifier consumption, and consumer execution are checked through explicit verification boundaries or local fixture verifiers.

N.1 security review tightened this boundary: successful receipt monitoring must receive explicit inner execution, nullifier, and consumer verifiers. A successful bundler receipt alone is rejected.

## Duplicate And Ambiguous Submission

M.11 includes only a process-local submitted-operation store and hash-first reconciliation model. It is not durable recovery.

Ambiguous submission must be reconciled by UserOperation hash, operation lookup, receipt lookup, nonce state, and operator review. PhilCore must not blindly retry after a request may have reached a bundler.

## Local Fixture

Tests include a local fixture bundler that invokes EntryPoint `handleOps(...)`. This proves the local ERC-4337 route without claiming a public bundler implementation or live Base execution.

## Disabled

Still disabled:

- Base mainnet;
- public Base Sepolia submission without approved prerequisites;
- paymasters and sponsorship;
- arbitrary UserOperation submission;
- generic bundler RPC exposure;
- application-facing bundler access;
- automatic rebuild/resign after mutable-state changes;
- ACP-0002 acceptance.

## Commands

```bash
npm run diagnose:philcore-4337-bundler
npm run submit:philcore-user-operation-local
npm run monitor:philcore-user-operation
npm run verify:philcore-user-operation-execution
```

These commands are safe/local by default. They do not submit to a public bundler.
