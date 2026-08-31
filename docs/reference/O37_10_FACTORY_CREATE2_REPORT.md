# O.37.10 Factory and CREATE2 Report

Status: `COMPLETE_LOCAL_DETERMINISTIC_DEPLOYMENT_PATH`.

`PhilCoreV2MinimalAccountFactoryV2` is the actual CREATE2 deployer. It accepts
only the canonical 20-field account initialization and a nonzero user salt.
It binds the fixed EntryPoint, chain, confirmation target, account version,
security model, verifier address, and verifier runtime hash.

The deployment salt remains:

```text
keccak256(abi.encode(
  PHILCORE_V2_CREATE2_SALT_V1,
  deploymentChainId,
  accountVersionId,
  securityModelId,
  ownerCommitment,
  identityBindingCommitment,
  userSalt
))
```

The address remains:

```text
last20(keccak256(
  0xff || factory || deploymentSalt ||
  keccak256(accountCreationCode || abi.encode(canonical20FieldTuple))
))
```

Tests independently reproduce the salt and address across 12 user-salt
vectors, verify exact predicted/deployed equality, and reject duplicate
deployment. Direct EOA construction fails because the constructor requires a
matching contract factory binding.

The factory returns exactly one immutable verifier address/code-hash pair.
The account requires exactly 64 canonical return bytes, a nonzero canonical
address and hash, matching `EXTCODEHASH`, one verifier `STATICCALL`, and the
exact 32-byte success result. Short, extended, absent/wrong code, revert, and
wrong-magic cases fail with no retry or alternate verifier.

The retained vectors use an explicitly synthetic local factory address.
They are not production account addresses. See
`config/solidity/O37_10_CREATE2_VECTORS.json`.
