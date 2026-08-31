# O.30 V2 Account Interface Specification

Status: conceptual ABI and execution rules only; no Solidity implementation.

## Superseded recovery-cancellation authority

Historical text in this document is preserved as design/audit history.
Current V2 actions 8–11 require the exact recovery-factor authority defined by
O.36.1/O.37.1. Actions 8, 9, and 11 use exact 2-of-3 current recovery factors.
Action 10 additionally requires the current validator plus exact 2-of-3 current
recovery factors. The validator never counts toward that recovery-factor
threshold, and validator-plus-one remains prohibited.

Canonical sources:

- [O.36.1 Recovery And Cancellation Semantics](./O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md)
- [O.37.1 V2 Recovery Lifecycle Update](./O37_1_RECOVERY_LIFECYCLE_UPDATE.md)

This document defines the required V2.0 surface. Function names may receive
minor Solidity-style normalization during implementation, but selector
meaning, caller boundary, fields, and prohibitions may not change without a
new architecture review.

## Common Types

Conceptual core header:

```text
IntentCoreHeader {
  uint8   specificationVersion
  bytes32 securityModelId
  uint8   actionType
  bytes32 actionId
  bytes32 purpose
  bytes32 ownerCommitment
  uint256 chainId
  address entryPoint
  address account
  uint192 nonceKey
  uint64  nonceSequence
  uint64  validatorEpoch
  uint64  recoveryEpoch
  bytes32 applicationContextHash
  bytes32 fundLifecycleDigest
  uint256 maxTotalFeeWei
  uint48  validAfter
  uint48  validUntil
}
```

The action functions conceptually receive:

```text
AuthorizedIntent {
  IntentCoreHeader core
  bytes32 runtimeAuthorizationDigest
}
```

The action-specific `intentCoreHash` is computed without the Runtime digest.
Runtime authorizes that stable core hash. The final `authorizedIntentHash`
then binds the core hash and nonzero Runtime authorization digest, avoiding a
circular hash dependency.

The Solidity implementation must use explicit structs and action-specific
functions. It must not accept an opaque application payload that is decoded
only by Runtime.

## EntryPoint-Only Action Surface

### `confirmIntent`

```text
confirmIntent(
  AuthorizedIntent intent,
  address confirmationTarget,
  bytes32 confirmationDigest
)
```

- action type: `CONFIRM`;
- nonce key: `0`;
- native value: zero;
- target equals immutable confirmation target;
- target calldata has one exact reviewed selector and field layout.

### `transferNative`

```text
transferNative(
  AuthorizedIntent intent,
  address payable recipient,
  uint256 amountWei
)
```

- action type: `NATIVE_TRANSFER`;
- nonce key: `0`;
- amount nonzero and no greater than account balance after prefund handling;
- recipient nonzero and not the account;
- external call has empty calldata;
- purpose distinguishes ordinary transfer, residual release, and migration.

### `transferERC20`

```text
transferERC20(
  AuthorizedIntent intent,
  address token,
  address recipient,
  uint256 amount
)
```

- action type: `ERC20_TRANSFER`;
- nonce key: `0`;
- calls only `transfer(address,uint256)`;
- rejects malformed/false results;
- checks exact account decrease and recipient increase;
- rejects fee-on-transfer or balance-changing behavior.

### `safeTransferERC721`

```text
safeTransferERC721(
  AuthorizedIntent intent,
  address token,
  address recipient,
  uint256 tokenId,
  bytes receiverData
)
```

- action type: `ERC721_SAFE_TRANSFER`;
- nonce key: `0`;
- `keccak256(receiverData)` equals the signed receiver-data hash;
- source is always `address(this)`;
- calls only the safe-transfer selector;
- verifies post-call ownership where the token exposes canonical behavior.

### `safeTransferERC1155`

```text
safeTransferERC1155(
  AuthorizedIntent intent,
  address token,
  address recipient,
  uint256 tokenId,
  uint256 amount,
  bytes receiverData
)
```

- action type: `ERC1155_SAFE_TRANSFER`;
- nonce key: `0`;
- `keccak256(receiverData)` equals the signed receiver-data hash;
- source is always `address(this)`;
- checks exact account and recipient balance deltas.

### `withdrawEntryPointDeposit`

```text
withdrawEntryPointDeposit(
  AuthorizedIntent intent,
  address payable recipient,
  uint256 amountWei
)
```

- action type: `ENTRYPOINT_DEPOSIT_WITHDRAWAL`;
- nonce key: `0`;
- calls only the immutable EntryPoint deposit-withdrawal interface;
- recipient and amount are exact and separately approved.

### `rotateValidator`

```text
rotateValidator(
  AuthorizedIntent intent,
  address proposedValidator,
  bytes32 proposedValidatorKeyIdBinding,
  uint64 proposedValidatorEpoch
)
```

- action type: `VALIDATOR_ROTATION`;
- nonce key: `1`;
- current execution validator signature required;
- proposed epoch equals current epoch plus one;
- unavailable while frozen or recovery/config rotation is active;
- performs no external call or value movement.

### `requestRecovery`

```text
requestRecovery(
  AuthorizedIntent intent,
  address proposedValidator,
  bytes32 proposedValidatorKeyIdBinding,
  uint64 proposedValidatorEpoch,
  bytes32 recoveryRequestSalt
)
```

- action type: `RECOVERY_REQUEST`;
- nonce key: `2`;
- signature envelope contains a canonical factor bitmap and two distinct
  current-factor signatures;
- proposed epoch equals current validator epoch plus one;
- request ID is recomputed from the complete request and current state;
- creates one pending request and freezes keys `0` and `1`;
- performs no external call or value movement.

Retired V2 alternative — see the supersession notice at the top of this document.

### `cancelRecovery`

```text
cancelRecovery(
  AuthorizedIntent intent,
  bytes32 recoveryRequestId
)
```

- action type: `RECOVERY_CANCEL`;
- nonce key: `2`;
- accepts two current factors or current validator plus one factor;
- current validator alone fails;
- clears exact pending request and unfreezes;
- performs no external call or value movement.

### `requestRecoveryConfigRotation`

```text
requestRecoveryConfigRotation(
  AuthorizedIntent intent,
  address proposedFactor0,
  address proposedFactor1,
  address proposedFactor2,
  bytes32 proposedRecoveryConfigHash,
  uint64 proposedRecoveryEpoch
)
```

- action type: `RECOVERY_CONFIG_ROTATION_REQUEST`;
- nonce key: `2`;
- current validator and two current factors required;
- factors are strictly increasing, unique, nonzero, and not the validator;
- proposed epoch equals current recovery epoch plus one;
- mutually exclusive with account recovery;
- ordinary actions remain available;
- performs no external call or value movement.

Retired V2 alternative — see the supersession notice at the top of this document.

### `cancelRecoveryConfigRotation`

```text
cancelRecoveryConfigRotation(
  AuthorizedIntent intent,
  bytes32 recoveryConfigRotationRequestId
)
```

- action type: `RECOVERY_CONFIG_ROTATION_CANCEL`;
- nonce key: `2`;
- current validator or two current factors may cancel;
- clears exact pending request;
- performs no external call or value movement.

## Permissionless Completion Surface

### `completeRecovery`

```text
completeRecovery(bytes32 recoveryRequestId)
```

Anyone may call after the delay and before expiry. The function has no
recipient, amount, arbitrary validator, or data argument. It installs only the
validator already fixed in the threshold-authorized request.

### `completeRecoveryConfigRotation`

```text
completeRecoveryConfigRotation(bytes32 rotationRequestId)
```

Anyone may call after the delay and before expiry. It installs only the factor
set already fixed in the cross-authorized request.

### `expireRecovery`

```text
expireRecovery(bytes32 recoveryRequestId)
```

Anyone may call only after the exact active recovery request expires. It
clears the request and unfreezes the account without changing the validator.

### `expireRecoveryConfigRotation`

```text
expireRecoveryConfigRotation(bytes32 rotationRequestId)
```

Anyone may call only after the exact active factor-rotation request expires.
It clears the request without changing factors or epochs.

Completion and expiry-cleanup functions:

- verify exact request ID and active state;
- enforce their exact early/mature/expired state;
- perform checks and clear pending state before final state activation;
- make no external call;
- transfer no value;
- increment the relevant epoch exactly once on completion and never on expiry
  cleanup;
- emit complete old/new state evidence.

## Receive Surface

Required:

```text
receive()
onERC721Received(...)
onERC1155Received(...)
onERC1155BatchReceived(...)
supportsInterface(...)
```

Receiver functions return only the required interface magic value. They do not
create intents, alter validators or recovery state, call external contracts,
or authorize later execution.

ERC-1155 batch receipt is supported because a third party may send a batch to
the account. V2.0 does not provide batch transfer out; each release requires a
separate typed transfer.

## Validation Surface

Required views:

```text
entryPoint()
accountVersionId()
securityModelId()
ownerCommitment()
factoryBinding()
activeValidator()
validatorKeyIdBinding()
validatorEpoch()
recoveryConfigHash()
recoveryEpoch()
recoveryFactors()
pendingRecovery()
pendingRecoveryConfigRotation()
getIntentCoreHash(...)
getAuthorizedIntentHash(...)
getAuthorizationDigest(...)
```

`validateUserOp` remains the ERC-4337 validation entry point inherited from
the account base. It must:

1. reject noncanonical EntryPoint, chain, account, nonce key, epoch, time, and
   action shape;
2. recompute action-specific intent hash from exact calldata;
3. recompute the complete UserOperation hash through EntryPoint semantics;
4. enforce fee upper bound and paymaster-disabled state;
5. validate the appropriate execution-validator or recovery-factor envelope;
6. return the exact EntryPoint validity range;
7. pay only bounded missing account prefund.

## Signature Envelopes

Execution/maintenance envelope:

```text
version
signatureKind = EXECUTION_VALIDATOR
validatorEpoch
validatorKeyIdBinding
r
s
v
```

Recovery-factor envelope:

```text
version
signatureKind = RECOVERY_FACTORS
recoveryEpoch
factorBitmap
signatureCount
ordered signatures
```

Combined validator-plus-factor cancellation envelope:

```text
version
signatureKind = VALIDATOR_PLUS_RECOVERY_FACTOR
validatorEpoch
recoveryEpoch
factorBitmap
validator signature
factor signature
```

Validator-plus-threshold factor-rotation envelope:

```text
version
signatureKind = VALIDATOR_PLUS_RECOVERY_THRESHOLD
validatorEpoch
recoveryEpoch
factorBitmap
validator signature
two ordered factor signatures
```

Signature count, bitmap population, order, factor membership, low-s form, and
envelope length are exact. Duplicate factors fail.

Recovery factors sign the recovery-specific EIP-712 digest binding the
authorized-intent hash, full UserOperation hash, current recovery
configuration hash and epoch, and exact factor bitmap. Combined cancellation
uses a separate type hash binding both validator and recovery epochs.
Recovery-config rotation uses a fourth type hash binding the current validator,
current/proposed recovery configurations and epochs, factor bitmap, authorized
intent, and UserOperation. Execution-validator, factor, combined-cancellation,
and config-rotation envelopes are not interchangeable.

## Events

Every successful typed action emits:

```text
IntentExecuted(
  bytes32 indexed actionId,
  bytes32 indexed authorizedIntentHash,
  uint8 indexed actionType,
  bytes32 purpose,
  uint192 nonceKey,
  uint64 nonceSequence,
  uint64 validatorEpoch,
  uint64 recoveryEpoch
)
```

Asset actions additionally emit exact token/recipient/identifier/amount
evidence. Validator and recovery actions emit old/new epochs and configuration
hashes. Events contain no private Runtime, proof, approval, presence, or Device
Vault material.

## External-Call Rules

- one execution lock covers every value/token external call;
- no external call from validator or recovery maintenance;
- no delegatecall;
- no calls to account-self;
- target and selector come from the typed function, not user calldata;
- external failure reverts action state and events;
- receiver callbacks cannot invoke EntryPoint-only action functions;
- gas griefing and return-data size are bounded during implementation review.

## Prohibited Surface

V2.0 must not define or inherit an externally usable equivalent of:

```text
execute
executeBatch
multicall
delegate
upgradeTo
upgradeToAndCall
sweep
withdrawAll
approveToken
setOwner
setAdmin
installModule
enableSessionKey
```

Renaming a prohibited behavior does not make it acceptable.
