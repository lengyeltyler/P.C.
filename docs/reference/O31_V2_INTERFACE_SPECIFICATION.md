# O.31 V2 Conceptual Interface Specification

Status: conceptual implementation interface; no Solidity or deployable ABI.

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

This document maps O.30 semantics to O.31 implementation units. Names and
signatures are pseudocode. A later Solidity phase must freeze exact ABI,
selectors, errors, events, and EIP-712 vectors before producing deployable
bytecode.

## Validation Interfaces

### ERC-4337 entry

```text
validateUserOperation(
  PackedUserOperation userOperation,
  bytes32 userOperationHash,
  uint256 missingAccountFunds
) -> validationData
```

Caller: immutable canonical EntryPoint only.

Required behavior:

1. reject wrong EntryPoint, chain, account, paymaster state, nonce key, or
   noncanonical encoding;
2. decode the exact action selector and payload;
3. call `validateIntent`;
4. call `validateAuthorityEpoch`;
5. verify the action-appropriate validator or recovery envelope;
6. bound missing prefund and return exact validity data.

No generic JSON-RPC, bundler, or application authority reaches this interface.

### Intent validation

```text
validateIntent(
  AuthorizedIntent authorizedIntent,
  bytes exactActionCalldata,
  bytes32 userOperationHash
) -> TypedValidationContext
```

The returned context contains only recomputed canonical hashes, action type,
purpose, nonce lane, epochs, validity, and exact typed payload. It is never
accepted from calldata.

It verifies:

- O.30 EIP-712 field order and action-specific type hash;
- selector/action/purpose/payload agreement;
- exact account, chain, EntryPoint, nonce, fee, time, application, and fund
  lifecycle bindings;
- exact calldata length and no appended bytes.

### Epoch validation

```text
validateAuthorityEpoch(
  uint64 suppliedValidatorEpoch,
  uint64 suppliedRecoveryEpoch,
  uint192 nonceKey
) -> EpochValidation
```

It rejects stale/future epochs, a frozen key `0` or `1`, and a key/action
mismatch. It does not mutate epochs.

### Execution-validator verification

```text
verifyExecutionAuthority(
  bytes32 authorizationDigest,
  ExecutionAuthorityEnvelope envelope
) -> ValidatorReference
```

It binds the current validator, key-ID binding, commitment, verifier kind, and
validator epoch. Initial local/test verification is canonical secp256k1 ECDSA.
Arbitrary-message, transaction, and caller authorization are absent.

### Recovery-factor verification

```text
verifyRecoveryAuthority(
  bytes32 recoveryDigest,
  uint8 factorBitmap,
  FactorWitness[] exactlyTwoWitnesses
) -> VerifiedFactorSet
```

It requires exactly two distinct role bits and two matching current
commitments. Witness order is canonical by role index:

```text
0 = PRIMARY_DEVICE
1 = HARDWARE_SECURITY_KEY
2 = RECOVERY_FACTOR
```

The verifier:

- recomputes each role commitment from the fixed descriptor and public witness;
- verifies the role's fixed cryptographic algorithm;
- rejects duplicate roles, duplicate public keys, wrong verifier kinds,
  malformed WebAuthn data, and same-domain aliases known to the configuration;
- binds chain, EntryPoint, account, complete UserOperation hash, request,
  validator/recovery epochs, factor bitmap, and validity.

## EntryPoint-Only Typed Execution

Every action below is callable only through the account's EntryPoint
execution path after successful validation.

```text
confirmIntent(AuthorizedIntent intent, address target, bytes32 digest)
```

- fixed immutable confirmation target;
- zero native value;
- nonce key `0`;
- no arbitrary confirmation calldata.

```text
transferNative(
  AuthorizedIntent intent,
  address payable recipient,
  uint256 amountWei
)
```

- exact nonzero recipient and amount;
- empty recipient calldata;
- nonce key `0`;
- ordinary transfer, residual release, or migration purpose only.

```text
transferERC20(
  AuthorizedIntent intent,
  address token,
  address recipient,
  uint256 amount
)
```

- fixed `transfer(address,uint256)` selector;
- exact return-data and sender/recipient balance-delta checks;
- fee-on-transfer and malformed tokens rejected;
- no approval or arbitrary token call.

```text
safeTransferERC721(
  AuthorizedIntent intent,
  address token,
  address recipient,
  uint256 tokenId,
  bytes receiverData
)
```

- fixed safe-transfer selector;
- `keccak256(receiverData)` equals the bound payload hash;
- no operator approval.

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

- exact single-token safe transfer;
- no outward batch;
- exact data hash.

```text
withdrawEntryPointDeposit(
  AuthorizedIntent intent,
  address payable recipient,
  uint256 amountWei
)
```

- exact recipient and amount;
- calls only the immutable EntryPoint deposit-withdrawal function;
- no unrestricted withdrawal or sweep.

## Validator Maintenance

```text
rotateValidator(
  AuthorizedIntent intent,
  ValidatorDescriptor proposedValidator,
  uint64 proposedValidatorEpoch
)
```

Caller: EntryPoint path, nonce key `1`.

Authority: current execution validator after normal Runtime proof, approval,
presence, and exact-purpose signing.

State:

- proposed validator, key-ID binding, verifier kind, and commitment are fixed
  by the intent;
- proposed epoch must be current plus one;
- recovery and recovery-config pending states must be absent;
- active validator and epoch change atomically;
- no value transfer or external call.

The old Device Vault record is revoked locally only after receipt and state
verification.

## Recovery Interfaces

The Runtime operation `initiateRecovery` maps to the account request surface:

```text
requestRecovery(
  AuthorizedIntent intent,
  ValidatorDescriptor proposedValidator,
  uint64 proposedValidatorEpoch,
  bytes32 recoveryRequestSalt,
  RecoveryAuthorityEnvelope authority
)
```

Caller: EntryPoint path, nonce key `2`; any relayer may transport the exact
factor-authorized UserOperation.

Authority: exactly 2-of-3 current role factors.

State:

- requires `NORMAL`, no pending config rotation;
- fixes one proposed validator and next epoch;
- records exact request ID and timing;
- immediately enters `CHALLENGE_DELAY`;
- freezes nonce keys `0` and `1`;
- emits commitment-only audit evidence;
- transfers no value and makes no external call.

Retired V2 alternative — see the supersession notice at the top of this document.

```text
cancelRecovery(
  AuthorizedIntent intent,
  bytes32 recoveryRequestId,
  RecoveryCancellationEnvelope authority
)
```


Caller: EntryPoint path, nonce key `2`.

Authority:

- any exact 2-of-3 current role factors; or
- current execution validator plus the hardware-security-key factor; or
- current execution validator plus the independent recovery factor.

Current validator alone fails. Current validator plus the primary-device
recovery credential fails because both belong to the primary-device domain.

State: consumes only the exact active request, clears pending state, unfreezes
keys `0` and `1`, changes no epoch, and moves no value.

```text
finalizeRecovery(bytes32 recoveryRequestId)
```

O.30 name: `completeRecovery`.

Caller: anyone.

Requirements:

- exact active request;
- current time is at or after `executableAfter` and before `expiresAt`;
- stored source epochs and security configuration still match;
- no caller-supplied validator or factor configuration.

State:

- clears pending state before activation;
- installs only the stored proposed validator;
- increments validator and recovery epochs exactly once;
- unfreezes the account;
- moves no value and calls no external contract.

```text
expireRecovery(bytes32 recoveryRequestId)
```

Caller: anyone after exact request expiry. It clears and unfreezes without
installing the proposed validator or changing epochs.

### Recovery configuration

```text
requestRecoveryConfigRotation(
  AuthorizedIntent intent,
  SecurityConfiguration proposedConfiguration,
  uint64 proposedRecoveryEpoch,
  RecoveryConfigAuthorityEnvelope authority
)
```

Caller: EntryPoint path, nonce key `2`.

Authority: current execution validator plus exactly two current role factors.
All signatures bind the complete proposed configuration. A validator signature
cannot double-count as the primary-device factor.

The proposed configuration must contain exactly one nonzero, unique
commitment for each fixed role. It cannot change threshold, timing, immutable
configuration, action selectors, or verifier code.

It is delayed, mutually exclusive with account recovery, and transfers no
value. Ordinary lane `0` remains available while this config-only request is
pending; validator maintenance is blocked.

Retired V2 alternative — see the supersession notice at the top of this document.

```text
cancelRecoveryConfigRotation(
  AuthorizedIntent intent,
  bytes32 requestId,
  RecoveryConfigCancellationEnvelope authority
)
```


Authority: current validator plus one non-primary role factor, or exact 2-of-3
current role factors. It clears only the exact request.

```text
finalizeRecoveryConfigRotation(bytes32 requestId)
```

O.30 name: `completeRecoveryConfigRotation`.

Caller: anyone after delay and before expiry. It installs only the stored
three-role configuration, increments recovery epoch exactly once, and makes no
external call.

```text
expireRecoveryConfigRotation(bytes32 requestId)
```

Caller: anyone after expiry. It clears without changing factors or epoch.

## Receive And View Surface

Receive-only:

```text
receive()
onERC721Received(...)
onERC1155Received(...)
onERC1155BatchReceived(...)
supportsInterface(...)
```

Receiver hooks return only required magic values and cannot authorize later
execution or change security state.

Required views:

```text
entryPoint()
deploymentChainId()
ownerCommitment()
factoryBinding()
accountVersionId()
securityModelId()
activeValidator()
validatorCommitment()
validatorKeyIdBinding()
validatorEpoch()
securityConfigurationHash()
recoveryEpoch()
recoveryRoleCommitments()
recoveryState()
pendingRecovery()
pendingRecoveryConfigRotation()
getIntentCoreHash(...)
getAuthorizedIntentHash(...)
getAuthorizationDigest(...)
getRecoveryDigest(...)
```

Views return public commitments and state, never local labels, private
material, attestation objects, encrypted recovery packages, approval
artifacts, or proof witnesses.

## Events

Conceptual events:

```text
IntentExecuted(actionId, authorizedIntentHash, actionType, assetEffectHash)
ValidatorRotated(oldCommitment, newCommitment, oldEpoch, newEpoch)
RecoveryRequested(requestId, proposedValidatorCommitment, executableAfter, expiresAt, factorBitmap)
RecoveryCancelled(requestId, cancellationAuthorityClass)
RecoveryCompleted(requestId, oldValidatorCommitment, newValidatorCommitment, newValidatorEpoch, newRecoveryEpoch)
RecoveryExpired(requestId)
RecoveryConfigRotationRequested(requestId, proposedSecurityConfigurationHash, executableAfter, expiresAt)
RecoveryConfigRotationCancelled(requestId)
RecoveryConfigRotationCompleted(requestId, oldConfigurationHash, newConfigurationHash, newRecoveryEpoch)
RecoveryConfigRotationExpired(requestId)
```

Events contain no signatures, raw WebAuthn assertion, credential ID, AAGUID,
device label, local key reference, recovery-package reference, proof witness,
or reusable approval authority.

## Prohibited Interface

The final ABI and all inherited/public surfaces must exclude:

```text
execute
executeBatch
call
multicall
delegatecall
upgradeTo
upgradeToAndCall
installModule
setImplementation
setOwner
setAdmin
sweep
withdrawAll
approveToken
setAllowance
setRecoveryThreshold
setRecoveryDelay
```

Fallback must revert. Account-self calls do not bypass EntryPoint or typed
validation. `tx.origin` is never an authority.

## Error Families

The implementation should use explicit custom-error families for:

- caller and EntryPoint binding;
- action shape and purpose;
- nonce lane and freeze;
- chain/account/epoch/validity/fee binding;
- validator and factor encoding/signature/commitment;
- recovery state, timing, request ID, and threshold;
- external token behavior and balance deltas;
- reentrancy and receiver behavior.

Errors must not include signatures, assertion bytes, secret material, complete
endpoint values, or local credential metadata.

## Stop Boundary

These interfaces are conceptual only. No selector is compiled or deployed in
O.31, and no public state is read or mutated.
