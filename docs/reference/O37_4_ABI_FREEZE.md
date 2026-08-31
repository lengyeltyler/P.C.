# O.37.4 V2 ABI And Security Interface Freeze

Status: `COMPLETE_LOCAL_SECURITY_INTERFACE_FREEZE`.

O.37.4 resolves the authority transport ambiguity without changing the
closed O.36.1 account or factory function surface. This is an interface
freeze, not a Solidity implementation.

## Account Initialization

The nonpayable account constructor keeps the exact O.35 ordered 20-field
initialization tuple: canonical EntryPoint, deployment chain, owner and
identity commitments, factory, version/security identifiers, confirmation
target, validator address/kind/key-ID/commitment/epoch, three recovery role
commitments, recovery configuration hash/epoch/delay/expiry.

The three complete recovery descriptors are not constructor parameters.
Runtime validates them locally before deployment. Solidity checks the
nonzero/distinct role commitments, recomputes configuration version `2` at
threshold `2`, and requires initial validator and recovery epochs `1`.
CREATE2 binds the complete constructor arguments and public user salt. Adding
descriptors would change both ABI and deterministic address and is forbidden.

## Account Interface

The closed external/public surface remains:

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
  AuthorizedIntentV1,bytes32,bytes32,bytes32,bytes32,uint64
)
cancelRecoveryConfigRotation(AuthorizedIntentV1,bytes32)
completeRecoveryConfigRotation(bytes32)
expireRecoveryConfigRotation(bytes32)
```

Required views remain:

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

`receive`, the ERC-721 and ERC-1155 receiver callbacks, and
`supportsInterface(bytes4)` are the only additional required interfaces.
Fallback reverts.

## Factory Interface

The factory constructor fixes EntryPoint, deployment chain, confirmation
target, account version, security model, and account creation code. Its
closed surface remains:

```text
createAccount(AccountInitializationV1,bytes32 userSalt) returns (address)
getAddress(AccountInitializationV1,bytes32 userSalt) view returns (address)
deploymentSalt(AccountInitializationV1,bytes32 userSalt) pure returns (bytes32)
accountCreationCodeHash(AccountInitializationV1) pure returns (bytes32)
```

Creation is nonpayable. Idempotent return of existing code is permitted only
after every frozen getter matches. The factory has no receive, fallback,
owner, admin, upgrade, recovery, execution, or withdrawal surface.

## Evidence Interface

`PackedUserOperation.signature` is the only authority transport:

- direct O.36.1 validator envelope for actions `0`--`7`;
- direct O.37.1 recovery envelope for actions `8`, `9`, and `11`;
- O.37.4 combined envelope for action `10`.

All are standard ABI, exact-version, bounded, canonically re-encoded, and
action-selected. EntryPoint owns keyed nonce sequences; the account adds no
nonce storage.

## Forbidden Surface

The ABI, inheritance graph, storage, and bytecode must expose no equivalent
of:

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

No proxy, implementation/admin slot, `DELEGATECALL`, `SELFDESTRUCT`, generic
target/value/data execution, module, plugin, session key, token approval,
batch outflow, mutable verifier, registry, aggregator, ERC-1271 authority
fallback, or paymaster path is allowed.

## Resumption Gate

Solidity may resume only under separate approval and must implement this
freeze without interface drift. Compiler/dependency pins, storage layout,
ABI, source and bytecode hashes, CREATE2 vectors, malformed-evidence tests,
and integration fixtures remain work for that later phase.

## O.37.5 Downstream Code-Size Conflict

O.37.5 applied the frozen compiler and dependencies locally, then stopped
before retaining Solidity. Direct implementation produced account and
factory runtimes larger than Ethereum's EIP-170 limit. Every identified
reduction strategy changes a frozen verifier, call, ABI, proxy, library, or
factory boundary. See
[O.37.5 V2 Solidity Implementation Conflict Review](./O37_5_SOLIDITY_IMPLEMENTATION_CONFLICT_REVIEW.md).

Solidity may not resume until a separately approved architecture phase
selects and freezes a deployable code-size strategy.
