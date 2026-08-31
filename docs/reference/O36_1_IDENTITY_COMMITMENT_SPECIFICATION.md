# O.36.1 Identity-Binding Commitment Specification

Status: `FROZEN_FOR_FUTURE_O37_SOLIDITY_IMPLEMENTATION`.

This specification closes O.36's identity-binding commitment gate without
changing Phil identity:

```text
phil_secret -> identityRoot -> ownerCommitment
```

Only the existing public `ownerCommitment` reaches this interface. The private
identity source and identity-root witness are not constructor inputs, calldata,
storage, logs, address vectors, or committed evidence.

## Exact Definition

The type string is:

```text
PhilCoreV2IdentityBinding(
  uint8 bindingVersion,
  bytes32 ownerCommitment,
  bytes32 ownerCommitmentSchemeId
)
```

with whitespace removed:

```text
PhilCoreV2IdentityBinding(uint8 bindingVersion,bytes32 ownerCommitment,bytes32 ownerCommitmentSchemeId)
```

Its type hash is:

```text
0x57f4660c20a425b4f07312eeeab81e83fc44cba5db3e7cc2fb8e1ef5d2d7afd8
```

The fields are:

- `bindingVersion = 1`;
- `ownerCommitment`: the nonzero canonical public Phil owner commitment;
- `ownerCommitmentSchemeId`:
  `keccak256(bytes("PHIL_OWNER_COMMITMENT_CANONICAL_V1"))`;
- exact scheme ID:
  `0xb891af6798d5e37aec3e66cdefd59ef16f633d0c539efd12ebfcf30d3cad6c4e`.

The exact commitment is:

```text
identityBindingCommitment = keccak256(
  abi.encode(
    IDENTITY_BINDING_TYPEHASH,
    uint8(1),
    ownerCommitment,
    OWNER_COMMITMENT_SCHEME_ID
  )
)
```

`abi.encodePacked`, string concatenation, JSON, address encoding, identity ID,
display name, chain ID, account address, account version, security model,
device commitment, and recovery configuration are not part of this hash.

## Relationship To Account Creation

The future V2 constructor stores both:

- `ownerCommitment`;
- `identityBindingCommitment`.

It recomputes the identity binding from the exact owner commitment and
constants and rejects a mismatch. The factory performs the same check before
derivation.

CREATE2 separately binds:

- deployment chain and EntryPoint;
- factory address and account creation code;
- account and security-model versions;
- owner and identity-binding commitments;
- initial validator and recovery configuration;
- confirmation target, timing, and public user salt.

The identity binding is deliberately chain-independent. Chain and adapter
separation belong to the factory and account derivation, not the Phil identity
anchor.

## Privacy Properties

The commitment:

- discloses no new private input beyond the already public owner commitment;
- does not expose or hash a passphrase, secret, raw identity root, credential
  identifier, device name, or recovery material;
- cannot be used as proof of knowledge of private identity material;
- is deterministic and therefore linkable wherever the same owner commitment
  is public.

The last property is intentional continuity, not anonymity. Runtime must not
describe the binding as unlinkable. A separate future privacy version would
require a new binding version and reviewed migration.

## Migration And Multi-Chain Behavior

For the same canonical owner commitment and scheme:

- the identity-binding commitment is identical across account versions;
- it is identical across chains;
- it is identical before and after validator or recovery rotation.

The resulting account addresses remain different because CREATE2 separately
binds chain, factory, version, code, initial security state, and salt.

A validator rotation, recovery completion, factor rotation, asset migration,
or device replacement cannot change owner or identity binding in an existing
account.

A different Phil identity or owner-commitment scheme produces a different
identity binding and requires a new account. A future cryptographic migration
from `PHIL_OWNER_COMMITMENT_CANONICAL_V1` must:

1. define a new scheme ID and, if semantics change, a new binding version;
2. create a new reviewed account/factory version and address;
3. use fresh typed migration authorization from the source account;
4. prove continuity through a separately reviewed Runtime/proof process;
5. never mutate the immutable binding in place.

## Rejections

Factory and account initialization reject:

- zero owner commitment;
- zero identity binding;
- unsupported binding version;
- unsupported owner-commitment scheme;
- identity binding that does not exactly recompute;
- use of the legacy address-and-salt owner commitment;
- any chain-, wallet-, validator-, device-, or recovery-derived substitute;
- any private identity material.
