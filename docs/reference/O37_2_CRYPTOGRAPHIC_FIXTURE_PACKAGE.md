# O.37.2 V2 Cryptographic Fixture Package

Classification: `TEST_FIXTURE_ONLY`.

Canonical package:
`config/cryptography/O37_2_V2_DETERMINISTIC_CRYPTOGRAPHIC_FIXTURES.json`.

The package is deterministic public test evidence. It contains no private
scalar, production key, real credential, protected witness, live endpoint, or
reusable production authority.

## Implementation Bindings

The package records SHA-256 bindings for:

- the O.37.2 fixture utility;
- O.32 intent source and public vectors;
- O.33 authorization source and public vectors;
- O.37.1 recovery-evidence source and public vectors;
- Account Abstraction `0.7.0` `UserOperationLib`.

These hashes make stale generated output detectable. The generator's
`--check` mode compares the entire checked-in JSON byte-for-byte.

## Validator Fixtures

| Fixture | Public identifier | Role |
| --- | --- | --- |
| execution validator | `0xCE1d8e9781034709E5a01B8f986C9CDC4Ab6e250` | accepted O.33 validator evidence |
| wrong validator | `0x75813cb5538691Ebcb5Da17767299C6163b80dAD` | wrong-signer rejection |
| proposed validator | `0xdC9728417F8747cA6878a33959E86248AD6b29d4` | recovery-request proposal |

The accepted execution key identifier is
`fixture_validator_o37_2_v1`. The identifier and its bytes32 commitment are
fixture bindings, not production Device Vault identifiers.

The validator set contains one accepted low-s signature and these rejected
vectors:

- wrong signer;
- zero `r`;
- zero `s`;
- invalid `v`;
- mathematically equivalent high-s signature;
- correct signature applied to a modified digest.

Each vector includes the expected failure code and canonical 320-byte
envelope.

## Recovery Fixtures

| Factor | Verifier | Generation | Public fixture |
| --- | --- | --- | --- |
| primary device | WebAuthn/P-256 | `1` | synthetic P-256 point and credential ID |
| hardware security key | WebAuthn/P-256 | `1` | distinct synthetic P-256 point and custody binding |
| recovery factor | secp256k1 | `1` | `0xB6dfc4ff19021dD12C0f880Fa11fc4993fec952E` |

No real WebAuthn enrollment or hardware interaction occurred. The two
WebAuthn roles have distinct public points, credential IDs, enrollment
commitments, attestation commitments, and custody domains.

The package includes two accepted 2-of-3 recovery evidence pairs:

- bitmap `0b011`: primary device plus hardware key;
- bitmap `0b101`: primary device plus independent recovery factor.

Each pair binds the O.37.1 complete descriptors, factor commitments, all
three current commitments, selected-factor order, configuration hash,
recovery epoch, exact authorization digest, exact UserOperation hash,
validity, delay, expiry, and proposed validator commitment.

The WebAuthn assertions include ABI-compatible authenticator data, canonical
client JSON, indices, P-256 public coordinates, and low-s signatures. The
secp256k1 factor includes an ABI-compatible signer and low-s signature.

O.37.1 negative vectors remain the canonical mutation corpus for invalid
bitmap, duplicate factor, changed generation, changed policy, wrong domain,
wrong role/verifier, stale epoch, and invalid rotation.

## Authorization Chain

The accepted native-transfer fixture connects:

- O.32 `intentCoreHash`;
- O.32 Runtime authorization digest;
- O.32 `authorizedIntentHash`;
- exact ABI `transferNative` calldata;
- ERC-4337 v0.7 UserOperation struct and EntryPoint hashes;
- O.33 validator struct hash and EIP-712 digest;
- canonical validator evidence;
- expected result `ACCEPTED`.

The recovery-request fixture connects the same O.32 chain to a recovery-lane
PackedUserOperation and both accepted O.37.1 evidence pairs.

## PackedUserOperation Fixtures

The accepted UserOperation hash is:

`0x189234186c3ef3b7831e66a4d5239837fac6d122f2bc962cfd6fd0593efbae02`.

It is an ERC-4337 v0.7 fixture for chain `31337` and the reserved fixture
EntryPoint. It is not estimated, signed for a live account, or submitted.

Rejected UserOperations mutate exactly one binding class:

- sender;
- keyed nonce lane;
- calldata;
- gas fees;
- chain;
- EntryPoint;
- authorization hash inside calldata.

Every rejected operation has a distinct expected UserOperation hash.
Replacing or removing the signature leaves the accepted UserOperation hash
unchanged, confirming the canonical v0.7 exclusion.

## ABI-Consumable Values

Future Solidity tests can consume:

- bytes32 intent, authorization, UserOperation, validator, recovery, and
  descriptor hashes;
- addresses and uint values as JSON strings;
- 320-byte validator evidence;
- complete WebAuthn evidence tuples;
- complete secp256k1 evidence tuples;
- outer recovery evidence envelopes;
- exact action calldata;
- packed 128-bit gas pairs.

All dynamic evidence blobs round-trip through the documented ABI tuples
without byte changes.

## Commands

```text
npm run generate:o37-2-deterministic-fixtures
npm run verify:o37-2-deterministic-fixtures
npm run test:o37-2-deterministic-fixtures
```

Generation is a deliberate repository update. CI and review should use the
verification command and fail on stale output rather than silently accepting
regenerated vectors.

## Security Boundary

The package asserts public-mutation count zero and records false for
canonical identity use, canonical validator use, Device Vault use,
environment-file use, real credential creation, production signatures,
production UserOperations, submission, Solidity, bytecode, deployment, RPC,
fund movement, and public mutation.

Those declarations are backed by conformance tests and source review; they
are not permission to perform any later action.
