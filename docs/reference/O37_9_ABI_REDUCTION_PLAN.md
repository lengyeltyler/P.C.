# O.37.9 Compressed Account ABI Reduction Plan

Status: `COMPLETE_PROPOSED_ABI_FREEZE`.

This document defines the only proposed external surface for the future
`philcore-v2-minimal-account-v2`. It does not create a Solidity interface or
ABI artifact.

## Preserved Common Types

`IntentCoreHeaderV1`, `AuthorizedIntentV1`, and
`PackedUserOperation` retain their O.32/O.37.4 field order and meaning.
`PackedUserOperation.signature` remains the sole O.37.4 authority transport.

## Validation

```text
0x19822f7c
validateUserOp(PackedUserOperation,bytes32,uint256)
```

Only the canonical immutable EntryPoint may call it. It performs the complete
authorization pass and returns the exact ERC-4337 validity range.

## Typed EntryPoint-Only Actions

The canonical type spelling below expands `AuthorizedIntentV1` to:

```text
((uint8,bytes32,uint8,bytes32,bytes32,bytes32,uint256,address,address,
  uint192,uint64,uint64,uint64,bytes32,bytes32,uint256,uint48,uint48),
 bytes32)
```

| Selector | Function |
| --- | --- |
| `0x2a44a457` | `confirmIntent(AuthorizedIntentV1,bytes32 confirmationDigest)` |
| `0x1bc0b4cd` | `transferNative(AuthorizedIntentV1,address recipient,uint256 amountWei)` |
| `0x686e6c02` | `withdrawEntryPointDeposit(AuthorizedIntentV1,address recipient,uint256 amountWei)` |
| `0x7ba5d971` | `rotateValidator(AuthorizedIntentV1,address proposedValidator,bytes32 proposedKeyBinding,uint64 proposedEpoch)` |
| `0x3da53a09` | `requestRecovery(AuthorizedIntentV1,address proposedValidator,bytes32 proposedKeyBinding,uint64 proposedEpoch,bytes32 requestSalt)` |
| `0xfbd522b1` | `cancelRecovery(AuthorizedIntentV1,bytes32 requestId)` |
| `0x89ec84b9` | `settleRecovery(bytes32 requestId)` |
| `0x5938dae7` | `requestRecoveryConfigRotation(AuthorizedIntentV1,bytes32 proposedPrimary,bytes32 proposedHardware,bytes32 proposedIndependent,uint64 proposedEpoch)` |
| `0xd1dee8fe` | `cancelRecoveryConfigRotation(AuthorizedIntentV1,bytes32 requestId)` |
| `0xe7327faa` | `settleRecoveryConfigRotation(bytes32 requestId)` |

The confirmation target is the immutable account target and is not repeated
in calldata. Validator commitments and proposed recovery-configuration hashes
are derived onchain and are not redundant ABI arguments. They remain part of
the exact O.32 intent hash where required.

EntryPoint deposit withdrawal remains action `6` and is classified as native
ETH residual release.

## Deterministic Settlement

Each settlement function accepts only an exact stored request ID:

- before `executableAfter`: revert;
- at or after `executableAfter` and before `expiresAt`: complete the exact
  stored proposal;
- at or after `expiresAt`: expire and clear the exact request.

It accepts no authority evidence, recipient, amount, proposal, target, or
arbitrary data. This consolidates four permissionless functions into two
without changing delay, expiry, or completion semantics.

## Aggregate Views

| Selector | View |
| --- | --- |
| `0x8d4980bc` | `accountConfiguration()` |
| `0xa937a1b4` | `accountSecurityState()` |
| `0xfaeb4488` | `pendingRecovery()` |
| `0x1e7638ab` | `pendingRecoveryConfigRotation()` |

`accountConfiguration` returns the immutable account, identity, factory,
version, security-model, and confirmation bindings. Verifier binding remains
observable through the bound factory's `verifierBinding()` view.

`accountSecurityState` returns the validator, derived validator commitment,
epochs, three recovery commitments, derived recovery-configuration hash,
audit state, and execution lock.

The pending views return complete stored and derived proposal/timing values.
There are no individual constant, hash-helper, nonce, or redundant field
getters.

## Receive And Fallback

The account has one empty native-ETH `receive` function. Fallback always
reverts. Neither creates authority.

## Error And Event Shapes

The future implementation may expose only these error categories with
bounded numeric reason codes:

```text
UnauthorizedEntryPoint()
InvalidInitialization(uint8 reason)
InvalidUserOperation(uint8 reason)
InvalidIntent(uint8 reason)
InvalidRecoveryState(uint8 reason)
InvalidExecution(uint8 reason)
VerifierBindingInvalid(uint8 reason)
ExternalCallFailed(uint8 reason)
```

It uses at most two event signatures:

```text
ActionExecuted(
  bytes32 indexed actionId,
  uint8 indexed actionType,
  address indexed target,
  uint256 value,
  bytes32 postStateHash
)

AuthorityTransition(
  bytes32 indexed requestId,
  uint8 indexed actionType,
  uint64 validatorEpoch,
  uint64 recoveryEpoch,
  bytes32 postStateHash
)
```

The state commitment covers the complete relevant post-state. Logs contain no
private proof, approval, presence, credential, or Device Vault material.

## Explicitly Absent

The ABI must not contain any equivalent of:

```text
execute
executeBatch
multicall
call
delegatecall
approve
transferERC20
safeTransferERC721
safeTransferERC1155
onERC721Received
onERC1155Received
onERC1155BatchReceived
installModule
uninstallModule
setOwner
setAdmin
setVerifier
setImplementation
upgradeTo
upgradeToAndCall
setRecoveryThreshold
setRecoveryDelay
sweep
withdrawAll
```

There is no ERC-1271 fallback, aggregator, paymaster, adapter, batch, module,
plugin, session-key, proxy, admin, or generic execution surface.

## Acceptance

The future compiled account ABI must contain exactly 15 functions: one
validation function, ten typed action/transition functions, and four aggregate
views. Additional functions, selectors, callbacks, or payable entry points
other than `receive` stop implementation.
