# O.32 V2 Cryptographic Foundation and Intent Verification Implementation

Status: `CRYPTOGRAPHIC_FOUNDATION_IMPLEMENTED_LOCAL_ONLY`.

O.37.1 compatibility: all intent, Runtime, validator/recovery authority,
nonce, epoch, and EIP-712 vectors in this phase remain byte-for-byte current.
The legacy factor/configuration commitment is historical for future Solidity;
O.37.1 descriptor/configuration version `2` flows through the unchanged
`recoveryConfigHash` authority field.

O.36.1 acceptance rule: `PhilCoreV2CombinedCancellation` is retained only as
a historical compatibility/negative-vector type. The V2 account must reject
that authority kind. Recovery and recovery-configuration cancellation require
the existing exact 2-of-3 recovery-factor authorization.

O.32 answers one question: **what exact action did PhilCore authorize?**
The answer is a deterministic chain of typed hashes shared by the Runtime,
Device Vault, validator, future account, and compatibility tests.

This phase implements local TypeScript hashing and validation utilities. It
does not implement Solidity, create deployable bytecode, enroll a credential,
generate a proof or signature, construct a UserOperation, call a live
contract, deploy, or move funds. Public mutations are zero.

## Baseline And Scope

The verified phase-start baseline was repository HEAD
`4f62f4ba7e5330e2253f308289fa1e75e320ce68` on
`codex/device-identity-v1`, with a clean tracked worktree.

The durable identity record remained coherent:

- identity: `identity_abab9766da60_24afd015`;
- display name: `My Phil`;
- validator: `0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa`;
- validator key ID: `validator_key_3c5b2ebebc4f3f3b`;
- validator key-ID contract binding:
  `0xb7bd562b139c95ebf020f445e6a3b3be82dfacf9e319d773b074da96e2b7b809`.

O.20 through O.31 source and evidence were reviewed. The known historical
O.22 source-binding mismatch remains: O.26.1 changed
`localProofGatedDeploymentPreparation.ts` after the O.22 proposal recorded its
source hash. The existing O.22 test correctly fails closed. O.32 does not
refresh or rely on that deployment authority. Continuing was safe because
this phase is local-only and creates no deployment, signing, or public
authority.

PhilCore remains device-first and chain-independent:

```text
identity -> exact intent authorization -> chain-specific execution
```

Ethereum fields constrain one execution environment; they do not define the
Phil identity.

## Version And Encoding Rules

The canonical identifiers are:

- intent specification version: `1`;
- account version label: `philcore-v2-account-v1`;
- security model label:
  `philcore-v2-typed-intent-local-proof-gated-v1`;
- EIP-712 name: `PhilCore V2 Account`;
- EIP-712 version: `1`.

Version labels are converted to `bytes32` with `keccak256(UTF-8(label))`.
All typed structures use an exact type string and field order. Structure
hashes use:

```text
keccak256(abi.encode(typeHash, field_1, ..., field_n))
```

Nested or variable material is reduced to a separately typed `bytes32`
commitment before inclusion. `abi.encodePacked`, JSON hashing, optional
fields, `personal_sign`, arbitrary typed-data requests, and implicit defaults
are prohibited.

The EIP-712 domain is exactly:

```text
EIP712Domain(
  string name,
  string version,
  uint256 chainId,
  address verifyingContract
)
```

`verifyingContract` is the V2 execution account. The final typed-data digest
is `keccak256(0x1901 || domainSeparator || structHash)`.

## Canonical Intent Core

Every intent has one exact header and one action-specific payload. The header
field order is fixed:

| Field | Purpose |
| --- | --- |
| `specificationVersion` | Rejects incompatible intent encodings. |
| `securityModelId` | Prevents authorization under a different security model. |
| `actionType` | Selects one fixed action schema. |
| `actionId` | Gives the requested action a unique application/Runtime identity. |
| `purpose` | Prevents valid authority from being repurposed. |
| `ownerCommitment` | Binds the device-first Phil identity without exposing its secret. |
| `chainId` | Prevents cross-chain replay. |
| `entryPoint` | Binds the intended ERC-4337 verification environment. |
| `account` | Prevents cross-account replay. |
| `nonceKey` | Selects the ordinary, maintenance, or recovery lane. |
| `nonceSequence` | Binds the exact sequence within that lane. |
| `validatorEpoch` | Invalidates authority from a prior validator generation. |
| `recoveryEpoch` | Invalidates authority from a prior recovery configuration/state. |
| `applicationContextHash` | Commits to application, origin, session, capability grant, and policy-decision identifiers. |
| `fundLifecycleDigest` | Commits to bounded funding, residual, and release assumptions. |
| `maxTotalFeeWei` | Caps the total fee the intent authorizes. |
| `validAfter` | Defines the earliest valid execution time. |
| `validUntil` | Defines the exact expiry. |

The extra context and lifecycle hashes are necessary because an amount and
recipient alone do not express the trusted application origin, capability,
policy decision, or bounded asset lifecycle. They are required, fixed-shape
structures rather than optional metadata.

Each action payload has its own type:

- confirmation: target and confirmation digest;
- native transfer: recipient and wei amount;
- ERC-20 transfer: token, recipient, and amount;
- ERC-721 safe transfer: token, recipient, token ID, and receiver-data hash;
- ERC-1155 safe transfer: token, recipient, token ID, amount, and
  receiver-data hash;
- EntryPoint deposit withdrawal: recipient and wei amount;
- validator rotation: proposed validator, key-ID binding, and next epoch;
- recovery request: proposed validator, key-ID binding, next epoch, and
  request salt;
- recovery cancellation: recovery request ID;
- recovery-configuration rotation request: proposed configuration and three
  factor commitments plus next recovery epoch;
- recovery-configuration rotation cancellation: rotation request ID.

Execution-time gas estimates, fee-market observations, bundler identity,
signature bytes, proof bytes, UserOperation serialization, transaction hash,
receipt, and block data are excluded. They are transient or belong to a later
authorization layer. Including them in the core would introduce circularity
or make a valid intent dependent on mutable transport data.

The core computation is:

```text
coreHeaderHash = keccak256(abi.encode(headerTypeHash, exact header fields))
intentCoreHash = keccak256(
  abi.encode(actionTypeHash, coreHeaderHash, exact action payload fields)
)
```

## Action, Purpose, Nonce, And Validity Constraints

The implementation rejects a payload whose kind does not match `actionType`.
It also rejects a purpose or nonce lane not allowed for that action.

- lane `0`: ordinary confirmation, transfer, NFT, and deposit-withdrawal
  actions;
- lane `1`: validator maintenance;
- lane `2`: recovery and recovery-configuration actions.

The ERC-4337 keyed nonce is composed as `(uint192 key << 64) |
uint64 sequence`. Keys and sequences are range checked and round-trip tested.
Ordinary and maintenance intents have a maximum 600-second lifetime; recovery
intents have a maximum 3,600-second lifetime. Empty or reversed validity
ranges are rejected.

Nonce consumption remains an EntryPoint/account responsibility. Recreating an
identical intent therefore recreates its hash, but must fail after its exact
keyed nonce is consumed. Both epochs must match current account state. A
validator or recovery transition increments the applicable epoch, making all
old digests unusable.

## Runtime Authorization

The Runtime contributes five exact commitments:

```text
PhilCoreV2RuntimeAuthorization(
  intentCoreHash,
  proofBindingHash,
  policyDecisionHash,
  approvalEvidenceHash,
  userPresenceEvidenceHash
)
```

`proofBindingHash` is itself typed and binds a proof-type identifier, public
proof-input hash, proof-artifact digest, and nullifier. It does not contain a
private witness.

- `policyDecisionHash` commits to the authoritative policy result;
- `approvalEvidenceHash` commits to the trusted presentation and exact
  decision;
- `userPresenceEvidenceHash` commits to fresh presence evidence;
- `proofBindingHash` commits to the proof result selected by the Runtime.

The chain is deliberately noncircular:

```text
runtimeAuthorizationDigest =
  hash(intentCoreHash, proof, policy, approval, presence)

authorizedIntentHash =
  hash(intentCoreHash, runtimeAuthorizationDigest)
```

Applications may request actions, but do not supply an already-authorized
digest. The trusted Runtime constructs these commitments after evaluation.

## Validator Authorization

The execution-validator structure is:

```text
PhilCoreV2Authorization(
  authorizedIntentHash,
  userOpHash,
  validator,
  validatorKeyIdBinding,
  validatorEpoch,
  recoveryEpoch
)
```

Its EIP-712 domain directly binds the chain and account. The
`authorizedIntentHash` transitively binds the EntryPoint, action, limits,
nonce, and identity. `userOpHash` binds the exact future ERC-4337 operation.
The validator address and domain-separated key-ID binding prevent substitution
of either the authority or its Device Vault reference. Both epochs reject old
authority after validator or recovery changes.

O.32 computes only digests and a public validator commitment. It does not
request the Device Vault to sign and does not create a UserOperation.

## Recovery Commitments

O.32 defines placeholders for the exact O.31 roles:

```text
0 PRIMARY_DEVICE
1 HARDWARE_SECURITY_KEY
2 RECOVERY_FACTOR
```

A factor commitment binds:

- account and security-model version IDs;
- fixed role and verifier kind;
- hash of public verification material;
- RP ID and origin-policy hashes when WebAuthn applies;
- user-verification policy;
- credential generation.

It contains no raw key, private key, secret, credential ID, assertion, or
protected witness. WebAuthn factors require nonzero RP/origin commitments and
user verification. Non-WebAuthn factors require zero WebAuthn policy fields.
The primary-device and hardware roles cannot use a generic threshold
commitment. The recovery role cannot masquerade as WebAuthn.

The configuration hash fixes version `1`, threshold `2`, and one distinct
commitment for each role. Only bitmaps `0b011`, `0b101`, and `0b110` are
valid. Recovery, combined cancellation, and configuration-rotation
authorizations use distinct typed structures and bind the account domain,
UserOperation hash, current recovery configuration, current epoch, and exact
two-role bitmap.

These are compatibility commitments only. Enrollment, factor verification,
delay enforcement, and state transitions require later separately approved
phases.

## Deterministic Compatibility Vectors

The checked-in vector package contains:

- exact type strings, type hashes, field order, domain values, header/action
  encodings, and stable hashes;
- a valid native-transfer intent and its complete authorization chain;
- amount, recipient, chain, account, expiry, nonce, validator-epoch, and
  recovery-epoch mutations;
- replay cases for consumed nonce, stale epochs, wrong account, and wrong
  chain;
- three role-bound recovery commitments, the 2-of-3 configuration hash, a
  valid recovery digest, an invalid factor commitment, and a stale recovery
  epoch;
- explicit false declarations for signatures, credentials, proofs,
  UserOperations, transactions, contracts, live calls, funds, and public
  mutations.

The package embeds SHA-256 bindings to both implementation modules and is
regenerated deterministically. `--check` fails if committed bytes differ from
the current implementation.

## Implementation Boundary

Canonical implementation:

- `apps/phil-device-sdk/src/v2Intent.ts`;
- `apps/phil-device-sdk/src/v2Authorization.ts`;
- `scripts/cryptography/generate-o32-v2-vectors.cjs`;
- `config/cryptography/O32_V2_CRYPTOGRAPHIC_TEST_VECTORS.json`.

O.32 completes only stage 0 and the local hashing portion of stage 1 in the
O.31 roadmap. Canonical onchain decoding, signature verification, account
state, Solidity, factory work, deployment, and live operation remain blocked
behind separate review and approval.
