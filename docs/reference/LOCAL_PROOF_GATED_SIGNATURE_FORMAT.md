# Local-Proof-Gated Signature Format

Identifier: `local-proof-gated-v1`

## Signed Digest

The account computes:

```text
keccak256(abi.encode(
  keccak256("PHILCORE_LOCAL_PROOF_GATED_ACCOUNT_SIGNATURE_V1"),
  uint8(1),
  keccak256("local-proof-gated-v1"),
  chainId,
  entryPoint,
  account,
  canonicalPackedUserOperationHash,
  actionId,
  runtimeAuthorizationDigest,
  uint64(expiry),
  validatorKeyId
))
```

The Device Vault signs this 32-byte digest using the existing EIP-191
`personal_sign`-compatible operation. It must first recompute and validate the
canonical ERC-4337 v0.7 UserOperation hash. A signature cannot be reused for a
different operation, chain, EntryPoint, account, action, authorization, expiry,
or validator key.

## Envelope

The account signature is exactly 288 bytes:

```solidity
abi.encode(
  uint8 version,
  bytes32 securityModelId,
  bytes32 actionId,
  bytes32 authorizationDigest,
  uint64 expiry,
  bytes32 validatorKeyId,
  bytes32 r,
  bytes32 s,
  uint8 v
)
```

`abi.encode`, not packed string encoding, is used. The account checks the exact
length, fixed version/model, calldata equality, immutable key ID, low-S ECDSA
recovery, and expiry. The validation result carries the ERC-4337 validity
deadline.
