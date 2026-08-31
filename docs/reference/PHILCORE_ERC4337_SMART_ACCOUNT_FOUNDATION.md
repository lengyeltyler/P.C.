# PhilCore ERC-4337 Smart Account Foundation

Architecture status: Current Ethereum/Base compatibility implementation. It is
not Phil identity/data recovery and its public `ownerCommitment` metadata is
not the accepted V1 public identity surface. Future integration is ACP-0003
Step 6 after the preceding gates.

Phase: M.9A

This document defines the proposed local ERC-4337 foundation that future UserOperation preparation work should reuse. It does not authorize live deployment, UserOperation signing, bundler submission, paymaster use, nullifier consumption, or Base state mutation.

## Selection Summary

Selected EntryPoint:

- version: ERC-4337 EntryPoint v0.7
- package: `@account-abstraction/contracts@0.7.0`
- local fixture: deploy `EntryPoint` from the package artifact
- canonical v0.7 address reference: `0x0000000071727De22E5E9d8BAf0edAc6f37da032`
- UserOperation schema: `PackedUserOperation`

Selected account:

- contract: `PhilCore4337Account`
- foundation: custom minimal account inheriting the established v0.7 `BaseAccount`
- upgradeability: disabled
- batch execution: disabled
- paymaster: disabled
- session keys: disabled
- production approved: false

The account is intentionally small because PhilCore first needs one exact execution path for `PhilBaseActionGate.verifyAndConsume(...)`.

## Alternatives Evaluated

EntryPoint v0.6:

- matches historical PhilCore scripts;
- uses the older un-packed UserOperation schema;
- historical address is `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`;
- not selected for the Beta foundation because it would preserve legacy script assumptions instead of establishing the current account boundary.

EntryPoint v0.7:

- selected for the Beta foundation;
- uses `PackedUserOperation`;
- is available from the pinned `@account-abstraction/contracts@0.7.0` package;
- supports the local `EntryPoint.getUserOpHash(...)` parity test.

Established SimpleAccount-style implementation:

- useful reference implementation;
- rejected as the direct PhilCore account because upstream `SimpleAccount` permits owner-direct `execute(...)`, which would bypass the PhilCore Runtime authorization path.

Modular account standard:

- better long-term path for WebAuthn/P-256 validators, recovery modules, and session keys;
- deferred because it expands the audit and configuration surface before PhilCore has one working controlled execution path.

Custom PhilCore account:

- selected only as a minimal local/Beta foundation;
- built on established EntryPoint/BaseAccount interfaces;
- unaudited and not production-approved.

## Account ABI

The accepted execution surface for M.9A is:

```solidity
execute(address target, uint256 value, bytes calldata data)
```

Rules:

- only the configured EntryPoint may call `execute(...)`;
- direct owner calls are rejected;
- arbitrary applications cannot call `execute(...)`;
- target must equal the immutable approved ActionGate;
- calldata selector must equal `PhilBaseActionGate.verifyAndConsume(...)`;
- account-self execution through `execute(...)` is disabled;
- the signed UserOperation covers target, value, calldata, nonce, gas fields, fees, EntryPoint, and chain ID;
- failed inner execution reverts the account call;
- no delegatecall path is exposed;
- no batch method is exposed.

N.4/N.5 add explicit maintenance selectors outside generic execution:

```solidity
rotateExecutionOwner(address newOwner)
requestRecovery(address pendingOwner)
cancelRecovery(bytes32 requestId)
completeRecovery(bytes32 requestId, address expectedPendingOwner)
```

These selectors do not permit arbitrary external calls. Owner rotation and cancellation remain current-owner signed. Recovery request and completion are recovery-authority signed. Recovery authority may use recovery request/completion selectors only and cannot call `execute(...)`.

## Factory And Counterfactual Deployment

Factory:

```solidity
createAccount(address owner, bytes32 ownerCommitment, uint256 salt)
getAddress(address owner, bytes32 ownerCommitment, uint256 salt)
```

The factory uses CREATE2. The same initial owner, owner commitment, salt, EntryPoint, approved ActionGate, recovery authority, recovery timing configuration, and factory produce the same account address. Changing the initial owner, salt, approved ActionGate, recovery authority, or recovery timing configuration changes the address. Duplicate creation returns the existing account.

After deployment, `rotateExecutionOwner(...)` changes the current execution owner without changing the deployed account address.

## Validator And Identity Binding

Beta validator:

- conventional ECDSA owner;
- signature format: EIP-191 personal-sign over EntryPoint `getUserOpHash(...)`;
- validator key is not derived from `phil_secret`;
- validator key custody is implemented for local Alpha by the Device Vault ECDSA custody boundary;
- validator rotation and delayed recovery are implemented for local Alpha;
- recovery authority custody and approval evidence are implemented for local Alpha in N.5;
- recovery-authority rotation is locally implemented in N.8;
- Beta approval, production threshold/modular recovery, and external audit remain incomplete.

PhilCore identity relationship:

```text
phil_secret -> identityRoot -> ownerCommitment -> smart-account public binding metadata
```

`ownerCommitment` is stored on the account as public metadata. It is not an Ethereum address, not a private key, and not sufficient to sign UserOperations.

## Nonce, Funding, And Prefund

Nonce:

- managed by EntryPoint v0.7 `NonceManager`;
- default key tested through `getNonce(account, 0)`;
- no nonce reservation occurs in M.9A.

Funding:

- account may receive ETH;
- EntryPoint prefund behavior is inherited from v0.7 `BaseAccount`;
- paymaster sponsorship is disabled.

## Local Fixture

The local Hardhat fixture deploys:

1. EntryPoint v0.7 from `@account-abstraction/contracts`.
2. `PhilCore4337AccountFactory`.
3. `PhilCore4337Account`.
4. A test execution target.
5. Local ActionGate/consumer fixtures for the `verifyAndConsume(...)` integration test.

The tests prove:

- actual EntryPoint `getUserOpHash(...)` parity;
- deterministic CREATE2 address derivation;
- invalid owner rejection;
- direct owner `execute(...)` rejection;
- arbitrary owner-signed EntryPoint target rejection;
- wrong selector and account-self nesting rejection;
- valid ActionGate UserOperation execution through EntryPoint;
- invalid signature and wrong-domain rejection;
- mutated calldata and gas-field rejection;
- counterfactual deployment through EntryPoint `initCode`;
- local ActionGate `verifyAndConsume(...)` execution through the smart account;
- nullifier is consumed once and replay fails.

## Disabled Features

Disabled in M.9A:

- UserOperation signing boundary;
- bundler submission;
- paymaster invocation;
- sponsored gas;
- session keys;
- WebAuthn/P-256 on-chain validation;
- modular plugins;
- upgradeability;
- live Base Sepolia deployment;
- Base mainnet configuration.

## Security Limitations

This foundation is not production-approved.

Remaining work:

- security review of the custom account and factory;
- formal decision on validator custody in Device Vault;
- rotation and recovery model;
- production deployment process;
- bundler compatibility testing;
- optional future modular validator migration;
- M.9 UserOperation preparation boundary;
- M.10 UserOperation signing boundary.

## Relationship To M.9

M.9 may now resume using:

- EntryPoint v0.7;
- `PackedUserOperation`;
- `PhilCore4337Account.execute(address,uint256,bytes)`;
- `PhilCore4337AccountFactory.createAccount(...)`;
- EntryPoint `getNonce(...)`;
- EntryPoint `getUserOpHash(...)`;
- paymaster disabled;
- signature unresolved.

M.9 must still stop before UserOperation signing, bundler submission, paymaster invocation, nullifier consumption, consumer execution, or live Base mutation.

M.9 preparation is defined in [PhilCore ERC-4337 UserOperation Preparation Boundary](./PHILCORE_ERC4337_USER_OPERATION_PREPARATION_BOUNDARY.md). That boundary prepares an unsigned EntryPoint v0.7 `PackedUserOperation` draft only; ACP-0002 remains `Proposed`.

M.10 signing is defined in [PhilCore ERC-4337 UserOperation Signing Boundary](./PHILCORE_ERC4337_USER_OPERATION_SIGNING_BOUNDARY.md). It uses the account's actual EIP-191-over-EntryPoint-`userOpHash` validation semantics and produces a signed but unsubmitted artifact only.

M.11 bundler submission and monitoring is defined in [PhilCore ERC-4337 Bundler Submission And Monitoring Boundary](./PHILCORE_ERC4337_BUNDLER_SUBMISSION_AND_MONITORING_BOUNDARY.md). It adds a restricted local/fixture bundler boundary, explicit submission approval, returned-hash verification, and receipt monitoring while keeping paymasters disabled and ACP-0002 `Proposed`.
