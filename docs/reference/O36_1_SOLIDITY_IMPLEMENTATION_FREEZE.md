# O.36.1 Solidity Implementation Freeze

Status: `SUPERSEDED_IN_PART_BY_O37_1_AND_COMPLETED_BY_O37_4`.

The O.37.1 correction preserves this toolchain, closed capability surface,
20-field initialization, validator envelope, identity binding, storage
policy, and V1 isolation. It supersedes only recovery factor/configuration
version `1` and the incomplete factor evidence envelopes. A future separately
approved Solidity phase must apply the O.37.1 descriptor/configuration and
evidence version `2` specifications. See
[O.37.1 Implementation Readiness Review](./O37_1_IMPLEMENTATION_READINESS_REVIEW.md).

O.37.4 subsequently freezes the missing combined validator-plus-recovery
transport for recovery-configuration rotation, the action-selected
`PackedUserOperation.signature` formats, EntryPoint-exclusive nonce ownership,
and the commitment-only constructor boundary. It changes no function,
constructor, storage, validator-envelope, or capability surface in this
document. See [O.37.4 V2 ABI And Security Interface Freeze](./O37_4_ABI_FREEZE.md).

This document freezes implementation inputs for a future O.37 Solidity phase.
It is not Solidity, build configuration, bytecode, deployment authority, or
permission to update dependencies.

## Exact Toolchain

O.37 must use:

| Component | Exact version |
| --- | --- |
| Solidity | `0.8.27` |
| OpenZeppelin Contracts | `5.6.1` |
| Account Abstraction contracts | `0.7.0` |
| Hardhat | `2.28.4` |
| Hardhat ethers plugin | `3.0.8` |
| ethers | `6.17.0` |
| Node.js | the repository-pinned O.37 runtime, to be recorded before build |

OpenZeppelin `5.6.1` is selected as the exact stable release containing the
fixed `WebAuthn` and `P256` libraries. O.37 may import those libraries
directly; it must not inherit OpenZeppelin's generic account, modular account,
signer registry, proxy, or execution extensions. Official library behavior is
documented at:

- `https://docs.openzeppelin.com/contracts/5.x/api/utils/cryptography`;
- `https://github.com/OpenZeppelin/openzeppelin-contracts/releases/tag/v5.6.1`.

The repository currently declares `@account-abstraction/contracts` as
`^0.7.0` even though the lock resolves `0.7.0`, and currently has OpenZeppelin
`5.0.2`. O.37 must change both declarations to exact pins and regenerate the
lockfile in its own reviewed commit. O.36.1 does not install or modify a
dependency.

Account Abstraction remains v0.7. O.37 uses the exact v0.7
`BaseAccount`, `IEntryPoint`, and `PackedUserOperation` interfaces. It must not
silently adopt an OpenZeppelin account base whose default EntryPoint version
differs.

## Compiler And Build Settings

V2 compilation settings are exactly:

```text
optimizer.enabled = true
optimizer.runs = 200
viaIR = true
evmVersion = "cancun"
metadata.bytecodeHash = "ipfs"
metadata.appendCBOR = true
metadata.useLiteralContent = true
```

Warnings are errors unless individually explained and reviewed. No
experimental compiler, prerelease dependency, floating range, remote import,
or unpinned git dependency is allowed.

Hardhat must use compiler overrides:

- frozen V1 account/factory and existing Solidity remain on `0.8.24`;
- only named V2 account/factory and V2-only support files use `0.8.27`;
- V1 source, ABI, creation bytecode, runtime bytecode, and recorded hashes
  must remain unchanged.

O.37 must publish deterministic local artifacts for:

- full compiler input and output;
- ABI;
- storage layout;
- creation and runtime bytecode;
- source SHA-256;
- bytecode Keccak-256;
- compiler and dependency versions;
- CREATE2 derivation vectors.

No artifact is accepted if absolute paths, credentials, environment values, or
machine-specific metadata enter its reproducible binding.

## Frozen Common ABI Types

`IntentCoreHeaderV1` is the exact O.32 field order:

```text
uint8 specificationVersion
bytes32 securityModelId
uint8 actionType
bytes32 actionId
bytes32 purpose
bytes32 ownerCommitment
uint256 chainId
address entryPoint
address account
uint192 nonceKey
uint64 nonceSequence
uint64 validatorEpoch
uint64 recoveryEpoch
bytes32 applicationContextHash
bytes32 fundLifecycleDigest
uint256 maxTotalFeeWei
uint48 validAfter
uint48 validUntil
```

`AuthorizedIntentV1` contains:

```text
IntentCoreHeaderV1 core
bytes32 runtimeAuthorizationDigest
```

The account initialization structure is the exact O.35 ordered tuple:

1. EntryPoint;
2. deployment chain ID;
3. owner commitment;
4. identity-binding commitment;
5. factory binding;
6. account-version ID;
7. security-model ID;
8. confirmation target;
9. initial validator address;
10. validator verifier kind;
11. validator key-ID binding;
12. validator commitment;
13. validator epoch, exactly `1`;
14. primary-device recovery commitment;
15. hardware-security-key commitment;
16. independent recovery-factor commitment;
17. recovery-configuration hash;
18. recovery epoch, exactly `1`;
19. recovery delay, exactly `172800`;
20. recovery expiry, exactly `604800`.

The account constructor accepts that complete structure and is nonpayable.
There is no initializer.

## Required Account Functions

The external/public account surface is closed:

```text
validateUserOp(PackedUserOperation,bytes32,uint256)

confirmIntent(AuthorizedIntentV1,address,bytes32)
transferNative(AuthorizedIntentV1,address,uint256)
transferERC20(AuthorizedIntentV1,address,address,uint256)
safeTransferERC721(AuthorizedIntentV1,address,address,uint256,bytes)
safeTransferERC1155(AuthorizedIntentV1,address,address,uint256,uint256,bytes)
withdrawEntryPointDeposit(AuthorizedIntentV1,address,uint256)

rotateValidator(AuthorizedIntentV1,address,bytes32,bytes32,uint64)
requestRecovery(AuthorizedIntentV1,address,bytes32,bytes32,uint64,bytes32)
cancelRecovery(AuthorizedIntentV1,bytes32)
completeRecovery(bytes32)
expireRecovery(bytes32)

requestRecoveryConfigRotation(
  AuthorizedIntentV1,
  bytes32,
  bytes32,
  bytes32,
  bytes32,
  uint64
)
cancelRecoveryConfigRotation(AuthorizedIntentV1,bytes32)
completeRecoveryConfigRotation(bytes32)
expireRecoveryConfigRotation(bytes32)
```

The two extra `bytes32` validator fields in rotation/recovery are the proposed
key-ID binding and validator commitment. Action-specific intent hashes bind
the same data; calldata cannot add an unbound field.

Required views:

```text
entryPoint()
deploymentChainId()
ownerCommitment()
identityBindingCommitment()
factoryBinding()
accountVersionId()
securityModelId()
confirmationTarget()
activeValidator()
validatorVerifierKind()
validatorKeyIdBinding()
validatorCommitment()
validatorEpoch()
recoveryConfigHash()
recoveryEpoch()
recoveryRoleCommitments()
recoveryState()
pendingRecovery()
pendingRecoveryConfigRotation()
getIntentCoreHash(...)
getAuthorizedIntentHash(...)
getValidatorAuthorizationDigest(...)
getRecoveryAuthorizationDigest(...)
```

Required receive/interface functions:

```text
receive()
onERC721Received(...)
onERC1155Received(...)
onERC1155BatchReceived(...)
supportsInterface(bytes4)
```

Receiver functions return only standard magic values and cannot authorize,
execute, or mutate security state.

## Required Factory Functions

The version-specific factory constructor fixes canonical EntryPoint,
deployment chain, confirmation target, account version, security model, and
account creation code.

The external factory surface is:

```text
createAccount(AccountInitializationV1,bytes32 userSalt) returns (address)
getAddress(AccountInitializationV1,bytes32 userSalt) view returns (address)
deploymentSalt(AccountInitializationV1,bytes32 userSalt) pure returns (bytes32)
accountCreationCodeHash(AccountInitializationV1) pure returns (bytes32)
```

Creation is nonpayable. Exact existing code may be returned idempotently only
after all immutable and mutable initialization getters match. Wrong or
unexpected code fails. The factory has no receive, fallback, owner,
administrator, upgrade, recovery, execution, or withdrawal surface.

## Required Events

The account emits:

```text
IntentExecuted
NativeTransferred
ERC20Transferred
ERC721Transferred
ERC1155Transferred
EntryPointDepositWithdrawn
ValidatorRotated
RecoveryRequested
RecoveryCancelled
RecoveryCompleted
RecoveryExpired
RecoveryConfigRotationRequested
RecoveryConfigRotationCancelled
RecoveryConfigRotationCompleted
RecoveryConfigRotationExpired
```

The factory emits:

```text
AccountCreated
```

Events include indexed action/request/configuration identifiers, exact public
state transitions, asset/recipient/amount evidence where applicable, and
epochs. They contain no signature, WebAuthn assertion, credential ID,
attestation, local key reference, private proof material, policy record,
approval record, or presence record.

## Required Error Families

Custom errors must cover:

- wrong EntryPoint/caller/chain/account/factory;
- initialization zero, duplicate, unsupported, or inconsistent field;
- wrong identity binding;
- unsupported action, purpose, nonce lane, authority kind, or verifier;
- malformed/noncanonical validator and factor evidence;
- intent, Runtime digest, UserOperation hash, fee, validity, or epoch mismatch;
- invalid/malleable signature or factor commitment;
- recovery threshold, state, request ID, timing, replay, or freeze;
- execution lock and reentrancy;
- typed recipient, amount, token, data hash, return data, or balance delta;
- paymaster prohibition and prefund bound;
- duplicate CREATE2 deployment or unexpected existing code.

O.37 freezes exact error names and selectors before implementation logic is
reviewed. It must not use one generic authorization revert for all malformed
state.

## Storage Policy

Immutable or bytecode-fixed:

1. EntryPoint;
2. deployment chain;
3. owner commitment;
4. identity-binding commitment;
5. factory binding;
6. account-version ID;
7. security-model ID;
8. confirmation target;
9. recovery delay;
10. recovery expiry.

Mutable storage order:

1. active validator, verifier kind, validator epoch, freeze flags, execution
   lock;
2. validator key-ID binding;
3. validator commitment;
4. recovery-configuration hash;
5. primary-device factor commitment;
6. hardware-security-key commitment;
7. independent recovery-factor commitment;
8. recovery epoch and state;
9. complete pending validator-recovery fields;
10. complete pending recovery-configuration fields.

EntryPoint v0.7 owns keyed nonce sequences; the account stores no duplicate
nonce mapping. There is no storage gap, implementation slot, owner/admin slot,
module/selector mapping, allowance table, arbitrary capability root, or
general replay mapping. Pending state is complete or entirely zero.

O.37 must check compiler storage layout into versioned evidence and test every
slot against this policy.

## Forbidden ABI And Bytecode Capabilities

The ABI and inherited surface must not expose any equivalent of:

```text
execute
executeBatch
multicall
call
delegate
delegatecall
upgradeTo
upgradeToAndCall
installModule
uninstallModule
setImplementation
setOwner
setAdmin
transferOwnership
sweep
withdrawAll
approve
setAllowance
setRecoveryThreshold
setRecoveryDelay
setVerifier
```

Fallback reverts. No `SELFDESTRUCT`, `DELEGATECALL`, proxy slot, mutable
verifier selection, generic target/value/data call, token approval, batch
outflow, session key, module, plugin, aggregator, or paymaster path is allowed.

## O.37 Entry Conditions

Separate approval is required. O.37 must begin by confirming:

- this interface package remains unchanged;
- exact dependency pins and compiler are available;
- WebAuthn/P-256 malformed-input and gas tests are feasible;
- V1 hashes and worktree baseline match;
- no security assumption requires redesign.

Any interface, dependency, verifier, ABI, storage, or cryptographic change
returns to architecture review rather than being hidden in Solidity.
