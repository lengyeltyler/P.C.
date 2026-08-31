# O.37.2 V2 Deterministic Cryptographic Test Fixture Specification

Status: `TEST_FIXTURE_PACKAGE_COMPLETE_SOLIDITY_SEPARATELY_GATED`.

O.37.2 creates deterministic public test vectors for future V2 Solidity
conformance tests. It creates no Solidity, deployable bytecode, live
authority, credential, network request, transaction, or public mutation.

Every artifact in this phase is classified:

`TEST_FIXTURE_ONLY`

## Purpose

The package exercises the exact cryptographic boundary expected by a future
V2 account:

```text
typed intent
  -> Runtime authorization digest
  -> authorized-intent hash
  -> ERC-4337 v0.7 PackedUserOperation hash
  -> validator or recovery authority digest
  -> canonical public evidence
  -> expected accept/reject result
```

The fixtures are proof inputs for tests. They are not authority and must
never be accepted outside the isolated fixture domain.

## Fixture Domain

The fixture domain is deliberately non-production:

- chain ID: `31337`;
- EntryPoint fixture: `0x00000000000000000000000000000000000F4337`;
- account fixture: `0x00000000000000000000000000000000000F3702`;
- RP ID: `o37-2.fixture.philcore.invalid`;
- origin: `https://o37-2.fixture.philcore.invalid`;
- live-network classification: `false`.

The `.invalid` DNS suffix and reserved fixture addresses are defense-in-depth
labels. Consumers must also require the explicit classification and exact
fixture-version binding.

## Deterministic Generation

Private scalars are derived only while the local generator or test process is
running:

```text
SHA-256("PHILCORE_O37_2_TEST_FIXTURE_ONLY:" || roleLabel)
  mod (curveOrder - 1) + 1
```

The scalar is used in memory to derive public material and deterministic
signatures. It is not printed, serialized, returned in the public package, or
committed. This derivation is intentionally public and therefore provides no
secrecy; it is suitable only for reproducible tests.

The exact runtime remains the O.37.1 freeze:

- Node.js `26.0.0`;
- npm `11.12.1`;
- npm lockfile version `3`;
- ethers `6.17.0`;
- `@noble/curves` `1.2.0`.

The direct, exact noble-curves development dependency makes the P-256 fixture
implementation reproducible rather than relying on an incidental transitive
dependency.

## Isolated Identities

The package derives separate material for:

- an execution validator;
- a deliberately wrong validator;
- a proposed post-recovery validator;
- a primary-device WebAuthn/P-256 factor;
- a hardware-security-key WebAuthn/P-256 factor;
- an independent secp256k1 recovery factor.

Execution and recovery roles cannot share an address or public key. No
canonical PhilCore identity, validator, Device Vault material, real WebAuthn
credential, hardware device, or local environment file participates.

## Signature Rules

Validator evidence follows the frozen O.36.1 320-byte ABI envelope and binds:

- envelope, authority, and verifier versions;
- validator and validator-key-ID commitment;
- validator and recovery epochs;
- secp256k1 `r`, `s`, and `v`.

Verification requires nonzero `r` and `s`, `v` in `{27, 28}`, low `s`, and
exact recovery of the fixture validator for the exact O.33 digest.

WebAuthn evidence uses:

- `rpIdHash = SHA-256(UTF8(rpId))`;
- canonical `clientDataJSON`;
- the exact base64url recovery digest as challenge;
- exact challenge and type byte indices;
- authenticator flags `UP | UV`;
- `SHA-256(authenticatorData || SHA-256(clientDataJSON))`;
- low-s P-256 signatures.

The origin-policy commitment remains the explicit PhilCore policy hash; it is
not substituted for the WebAuthn RP-ID hash.

## PackedUserOperation Rules

The package uses the ERC-4337 v0.7 `PackedUserOperation` hash:

```text
structHash = keccak256(abi.encode(
  sender,
  nonce,
  keccak256(initCode),
  keccak256(callData),
  accountGasLimits,
  preVerificationGas,
  gasFees,
  keccak256(paymasterAndData)
))

userOpHash = keccak256(abi.encode(
  structHash,
  entryPoint,
  chainId
))
```

The signature is deliberately excluded from the UserOperation hash. All
other listed fields are exact hash inputs. `initCode` and
`paymasterAndData` are empty in the accepted fixture.

## Canonical Encoding

Cryptographic values use:

- standard `abi.encode`, never packed encoding;
- fixed `bytes32` digests and curve scalars;
- exact-width unsigned integers;
- checksummed addresses in the public presentation;
- canonical O.32 intent encodings;
- the frozen O.36.1 validator envelope;
- complete O.37.1 descriptor/context tuples and evidence version `2`.

JSON is only the public vector container. JSON bytes are never a
cryptographic preimage.

## Lifecycle

1. Generate in the exact pinned local runtime.
2. Commit only the public JSON package.
3. Verify byte-for-byte reproducibility with the check command.
4. Consume only in local conformance tests.
5. Reject any classification, domain, version, account, chain, EntryPoint,
   epoch, validity, signer, descriptor, or digest mismatch.
6. Replace the fixture version if the frozen interface changes.
7. Never promote, import, or reinterpret fixture material as production
   authority.

The fixture package can be retained indefinitely as public test evidence
because no secret protects it. Its signatures remain permanently unsafe for
any production or live-network use.

## Stop Boundary

O.37.2 does not implement contracts, produce bytecode, deploy, call RPC,
fund an address, access credentials, sign production authority, or submit a
UserOperation. A future Solidity implementation requires separate explicit
approval and a fresh baseline review.
