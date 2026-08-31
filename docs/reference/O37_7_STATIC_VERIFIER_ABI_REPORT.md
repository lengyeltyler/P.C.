# O.37.7 V2 Static Verifier ABI Report

Status: `COMPLETE_STATIC_VERIFIER_ONLY`.

The verifier has no constructor input, receive function, fallback function,
event, payable method, administration method, or mutable method.

## Functions

| Signature | Selector | Mutability |
| --- | --- | --- |
| `SUCCESS_MAGIC()` | `0x5ca217a9` | `view` |
| `VERIFIER_VERSION_ID()` | `0x861cbcc8` | `view` |
| `verifyAuthority(PhilCoreV2VerifierRequestV1,bytes)` | `0x943e9f75` | `view` |

The verifier version ID is:

```text
0x2e7f527e1c2212f8e2b14a62bc02e18dc7eb16cfcfe3a5f955c533eafb2cd402
```

Successful verification returns:

```text
0x15c57f54
```

Every failure reverts. There is no accepted Boolean supplied by Runtime.

## Request Order

`PhilCoreV2VerifierRequestV1` has this exact order:

```text
uint8 actionType
address account
uint256 chainId
address entryPoint
bytes32 accountVersionId
bytes32 securityModelId
bytes32 authorizedIntentHash
bytes32 userOpHash
address validator
bytes32 validatorKeyIdBinding
uint64 validatorEpoch
uint64 recoveryEpoch
bytes32 recoveryConfigHash
bytes32 requestId
uint48 validAfter
uint48 validUntil
bytes32 proposedValidatorCommitment
bytes32 proposedRecoveryConfigHash
uint64 proposedRecoveryEpoch
bytes32 primaryDeviceCommitment
bytes32 hardwareSecurityKeyCommitment
bytes32 recoveryFactorCommitment
```

The future account must construct this request from its immutable bindings,
current storage, and the exact UserOperation. The verifier requires
`request.account == msg.sender`.

The account-version and security-model IDs are request fields because the
verifier is stateless. The future minimal account must supply its immutable
values. They cannot be selected by Runtime or copied from evidence.

## Authority Transport

The second parameter is exactly one unchanged O.37.4 transport:

- direct 320-byte validator envelope for actions `1`, `2`, `6`, `7`;
- direct recovery envelope for actions `8`, `9`, `11`;
- combined validator-plus-recovery envelope for action `10`.

Actions `0`, `3`, `4`, `5`, and unknown actions are rejected by the minimal
profile. Canonical decode/re-encode equality is mandatory for every outer
and nested envelope.

The ABI contains 13 parameterless verification errors and no arbitrary
execution, registry, upgrade, ownership, withdrawal, token, or recovery-state
mutation surface.
