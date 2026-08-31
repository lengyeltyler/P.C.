# Local-Proof-Gated Account Model

Status: experimental proposal for disposable Ethereum Sepolia testing only.

## Contracts

- `PhilCore4337LocalProofAccountV1`: non-upgradeable ERC-4337 v0.7 account.
- `PhilCore4337LocalProofAccountFactoryV1`: immutable, chain-bound CREATE2 factory.
- `PhilCoreLocalProofConfirmationTargetV1`: zero-value confirmation evidence.

The account has no generic `execute`, batch, delegatecall, upgrade, token,
withdrawal, admin, recovery, or paymaster path. EntryPoint can invoke only:

```solidity
executeLocalProofAuthorization(
    bytes32 actionId,
    bytes32 authorizationDigest,
    uint64 expiry
)
```

That function calls one immutable confirmation target with zero ETH. Exact
calldata length is enforced during validation, so appended calldata and
alternate selectors fail.

## Determinism And Correlation

CREATE2 derivation binds factory, EntryPoint, owner address, owner commitment,
confirmation target, validator key ID, expected chain ID, and salt. It excludes
`phil_secret`, passphrases, artwork traits, display names, World ID data, and
private keys.

Observers can correlate the public owner, owner commitment, validator key ID,
factory family, and repeated account activity. Disposable test identities must
therefore not be presented as private or unlinkable.

## Target Review

The O.17 `PhilCoreAuthorizationConfirmationTarget` remains correct for the
fact-enforced route: it accepts calls only from its immutable
`PhilUnlockConsumer`, records account/action/nullifier evidence, moves no value,
and has no owner, upgrade, withdrawal, arbitrary call, delegatecall, or
self-destruct path.

It cannot be called directly by the experimental account. O.18 therefore adds a
separate target that verifies the caller's `local-proof-gated-v1` label, chain,
and immutable target binding, then records account, action ID, and Runtime
authorization digest. This target is evidence, not authorization.

## Runtime Order

Intent, policy, approval, fresh presence, STWO proof generation, local proof
verification, final Runtime authorization digest, PackedUserOperation,
Device Vault recomputation, purpose-bound signing, then stop. Public deployment
and submission remain separately gated.

## UI Status

Technical mode must show `securityModel: local-proof-gated-v1`,
`starkVerificationLocation: local`, and `factEnforcedOnchain: false`.

User copy:

> PhilCore verified the proof on this Mac before signing. Ethereum verified the
> PhilCore account signature. Ethereum did not independently verify the STARK
> proof.

Supported preparation states range from `architecture_not_approved` through
`ready_for_deployment_approval`; live deployment/submission states remain
inactive until a later approved phase.

## O.19 Final Contract Review

All three sources compile with Solidity 0.8.24, optimizer enabled for 200 runs,
and `viaIR: true`.

| Contract | Deployment role | Mutable authority |
| --- | --- | --- |
| `PhilCoreLocalProofConfirmationTargetV1` | ordinary target deployment | none |
| `PhilCore4337LocalProofAccountFactoryV1` | ordinary factory deployment | none |
| `PhilCore4337LocalProofAccountV1` | direct CREATE2 account deployment by factory | owner signature only for the fixed action |

The factory does not use a proxy or reusable implementation. A standalone
account deployment is not a factory dependency and is excluded from the O.19
deployment plan.

The review confirms no upgrade, administrator, pause, withdrawal, delegatecall,
batch, arbitrary execution, paymaster, token movement, fact-enforcement claim,
or recovery path. The account can receive ETH for ERC-4337 prefund but has no
withdrawal function. It accepts only EntryPoint invocation of selector
`0x44413cab`, passes zero value to the immutable target, and validates the exact
versioned signature envelope and expiry. EntryPoint nonce handling provides
UserOperation replay protection.

Slither findings remain recorded individually in
`config/security/philcore-solidity-static-analysis.json`; every finding has an
explicit classification. O.19 does not waive lower-severity findings.

## O.28 Recovery Compatibility

O.28 confirms that V1 has no secure route to release native balance or
EntryPoint deposit after deployment. Its fixed zero-value confirmation call is
properly validator-gated but cannot bind or execute a residual recipient and
amount.

The live factory embeds the exact V1 creation code. Adding a release route
changes the CREATE2 init-code hash and counterfactual address, and requires a
new factory. The already-prefunded V1 address is therefore classified
`PREFUNDED_ADDRESS_INCOMPATIBLE_WITH_RECOVERY` and must not be deployed merely
because it holds ETH.

Future account funding is governed by the
[PhilCore Test-Fund Release Policy](../security/PHILCORE_TEST_FUND_RELEASE_POLICY.md).

## O.29 V2 Architecture Boundary

O.29 freezes V1 as a successful minimal prototype and selects a separate,
non-upgradeable V2 direction. V2 uses typed intent selectors for exact native,
token, NFT, confirmation, deposit-release, and maintenance actions rather than
a raw generic execution function.

Lost-validator recovery is a delayed threshold authority rotation. It moves no
assets. Residual-fund release remains an ordinary exact action requiring fresh
proof, approval, presence, Device Vault signing, nonce, expiry, and separate
public approval.

V2 requires a new implementation, factory, CREATE2 address, and infrastructure
binding. It does not modify V1 or recover the O.27 prefund. See
[O.29 Recovery-Capable Account V2 Architecture Design](./O29_RECOVERY_CAPABLE_ACCOUNT_V2_ARCHITECTURE.md).

O.30 refines that direction into action-specific EIP-712 intent types, exact
nonce/epoch rules, a fixed V2.0 capability surface, and delayed 2-of-3
authority recovery. It remains a specification only and does not alter the V1
local-proof-gated implementation.

## O.31 Implementation Architecture Boundary

O.31 maps the O.30 specification into fixed, non-installable account,
validation, validator, recovery, typed-execution, Runtime, Device Vault, and
factory modules. It preserves the non-upgradeable typed account and defines a
declared storage order, keyed nonce interactions, implementation/test order,
and audit/deployment gates without implementing Solidity.

Recovery remains exact 2-of-3, with one role in each required independent
domain: a purpose-separated primary-device recovery credential, an external
hardware security key, and an offline or secondary recovery factor. The daily
execution-validator key cannot occupy a recovery role. Recovery rotates
validator authority only and cannot move assets. See
[O.31 V2 Account Implementation Architecture And Module Design](./O31_V2_IMPLEMENTATION_ARCHITECTURE_AND_MODULE_DESIGN.md)
and
[O.31 V2 Three-Domain Recovery Architecture](./O31_V2_RECOVERY_ARCHITECTURE.md).

## O.32 Cryptographic Foundation Boundary

O.32 implements the local, deterministic V2 intent and authorization hashing
foundation. It fixes the intent header and action-specific encodings, Runtime
proof/policy/approval/presence digest, account-and-chain EIP-712 validator
digest, keyed nonce and epoch binding, and public-only commitments for the
three O.31 recovery roles.

O.32 remains below the contract and authority boundaries. It creates no
Solidity, deployable bytecode, credentials, proofs, signatures,
UserOperations, live calls, funding action, or public mutation. A later V2
account phase must reproduce the checked-in vectors exactly before it can add
canonical decoding or verifier behavior. See
[O.32 V2 Cryptographic Foundation And Intent Verification](./O32_V2_CRYPTOGRAPHIC_FOUNDATION_AND_INTENT_VERIFICATION.md)
and
[O.32 V2 Cryptographic Security Analysis](../security/O32_V2_CRYPTOGRAPHIC_SECURITY_ANALYSIS.md).

## O.33 Validator And Authorization Engine Boundary

O.33 consumes the O.32 primitives in a local validator and authorization
engine prototype. It reproduces every intent/Runtime/authority hash, checks
identity and execution-domain bindings, applies validator/recovery epochs,
models nonce and digest replay, enforces recovery freezes, and delegates the
final digest to a purpose-bound authority-verifier interface.

The engine receives only an evidence reference. It does not hold signature
bytes, sign, call Device Vault, create a UserOperation, execute a state
transition, or expose a wallet/administrator capability. Its included
verifier is deterministic and fixture-only. See
[O.33 V2 Validator And Authorization Engine Architecture](./O33_V2_VALIDATOR_AND_AUTHORIZATION_ENGINE_ARCHITECTURE.md)
and
[O.33 V2 Authorization Failure Model](../security/O33_V2_AUTHORIZATION_FAILURE_MODEL.md).

## O.34 Account Core Enforcement Boundary

O.34 adds the first local V2 account enforcement implementation. It fixes the
immutable account configuration, checks validator and recovery commitments,
models exact EntryPoint keyed-nonce sequences, consumes O.33 validation, and
produces only narrowly typed non-executable action drafts. Recovery request,
completion, and cancellation are modeled as local state transitions with
ordinary and maintenance lanes frozen while recovery is active.

The value-moving draft boundary enforces the O.28 rule that no funding may
proceed without an exact release-path and residual-handling commitment. This
is scaffolding only: O.34 creates no Solidity, UserOperation, signature,
external call, funding action, or public mutation. See
[O.34 V2 Account Core Architecture](./O34_V2_ACCOUNT_CORE_ARCHITECTURE.md)
and
[O.34 V2 Account Core Security Invariants](../security/O34_V2_ACCOUNT_CORE_SECURITY_INVARIANTS.md).

## O.35 Factory And Account Lifecycle Boundary

O.35 selects one non-upgradeable, non-administrative factory per reviewed V2
account version. The complete initial validator, three-role recovery
configuration, identity commitments, chain, EntryPoint, version, timing, and
public deployment salt are bound into constructor-only atomic initialization
and CREATE2 derivation.

The lifecycle separates local configuration, counterfactual derivation,
deployment eligibility, atomic deployment, independent activation
verification, later funding, migration, and non-destructive retirement.
Counterfactual funding and partial onchain initialization are prohibited.

Migration preserves identity continuity but creates a new factory, code
artifact, and account address. Assets can move only through fresh typed
source-account authorization. V1 has no such route, and V2 cannot claim the
O.27-prefunded V1 balance. See
[O.35 V2 Factory Architecture](./O35_V2_FACTORY_ARCHITECTURE.md),
[O.35 V2 Account Lifecycle](./O35_V2_ACCOUNT_LIFECYCLE.md),
[O.35 V2 Migration Design](./O35_V2_MIGRATION_DESIGN.md),
[O.35 V2 Factory And Lifecycle Security Analysis](../security/O35_V2_FACTORY_LIFECYCLE_SECURITY_ANALYSIS.md),
and
[O.35 V2 Factory And Lifecycle Test Plan](./O35_V2_FACTORY_LIFECYCLE_TEST_PLAN.md).

O.35 adds design evidence and local conformance tests only. It creates no
Solidity, bytecode, factory, account, credential, signature, UserOperation,
funding action, live infrastructure, or public mutation.

## O.36 Solidity Implementation Gate

O.36 was authorized to begin the first V2 Solidity account and factory
implementation. It stopped before contract source or bytecode because the
accepted architecture still lacks an approved chain-side hardware recovery
verifier, a frozen production validator envelope/verifier, and an exact
identity-binding commitment definition. The O.31 cancellation model also
remains unrepresented by the O.32/O.33 digest format.

Adding a partial account, placeholder verifier, or alternate factor model
would change security architecture during implementation. The fail-closed
decision and the prerequisites for a fresh implementation phase are recorded
in
[O.36 V2 Solidity Implementation Gate Review](./O36_V2_SOLIDITY_IMPLEMENTATION_GATE_REVIEW.md).

O.36 creates no Solidity, bytecode, factory, account, credential, signature,
UserOperation, funding action, live infrastructure, or public mutation.

## O.36.1 V2 Security Interface Freeze

O.36.1 resolves O.36's five architecture gates without implementing Solidity.
It fixes direct WebAuthn/P-256 primary and hardware recovery roles, a
purpose-bound secp256k1 independent role, exact 2-of-3 request/cancellation,
the production validator envelope, the typed identity-binding commitment,
and the O.37 compiler/dependency/ABI/storage boundary.

The retired validator-plus-one-factor cancellation path is rejected. Recovery
cannot move assets or call arbitrary contracts. See:

- [Hardware Recovery Specification](./O36_1_HARDWARE_RECOVERY_SPECIFICATION.md);
- [Validator Interface](./O36_1_VALIDATOR_INTERFACE_SPECIFICATION.md);
- [Identity Commitment](./O36_1_IDENTITY_COMMITMENT_SPECIFICATION.md);
- [Recovery Semantics](./O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md);
- [Solidity Implementation Freeze](./O36_1_SOLIDITY_IMPLEMENTATION_FREEZE.md);
- [Security Gate Resolution](../security/O36_1_SECURITY_GATE_RESOLUTION.md).

O.36.1 creates no Solidity, bytecode, account, deployment, credential,
signature, UserOperation, funding action, RPC call, or public mutation.

## O.37 V2 Solidity Implementation Conflict Gate

O.37 was authorized to implement the frozen V2 Solidity account and factory.
It stopped before Solidity after finding that the frozen recovery evidence
cannot reconstruct the frozen factor commitments. The WebAuthn evidence omits
the committed origin-policy hash and credential generation, while the
secp256k1 evidence omits the committed credential generation. The account
stores only factor commitments, so it has no other source for those values.

O.37 also requires valid authorization and replay tests while prohibiting the
creation of signatures and UserOperations. The accepted O.32/O.33 vectors
contain hashes and fixture evidence references but deliberately contain no
signature bytes or UserOperation fixture.

Changing evidence, storage, authority, or test-authority boundaries would
redesign the O.36.1 freeze. The exact conflict and required separately
reviewed resolution are recorded in
[O.37 V2 Solidity Implementation Conflict Review](./O37_V2_SOLIDITY_IMPLEMENTATION_CONFLICT_REVIEW.md).

O.37 creates no Solidity, bytecode, factory, account, credential, signature,
UserOperation, funding action, RPC call, or public mutation.

## O.37.1 Recovery Evidence And Descriptor Completion

O.37.1 corrects the incomplete O.36.1 recovery commitment boundary without
changing the three-domain exact 2-of-3 authority model. Descriptor version
`2` binds credential-ID hash, public material, RP/origin policy, verified
independence binding, WebAuthn policy, generation, role, verifier, account
version, security model, and recovery domain.

Complete descriptors travel in canonical one-time recovery evidence. The
account can therefore recompute each selected stored commitment while the
O.35 20-field constructor and commitment-only storage remain unchanged.
Configuration and evidence version `2` supersede only the incomplete O.36.1
factor/configuration and evidence definitions.

The initial registration sequence remains local and predeployment; onchain
creation stays atomic and fully initialized. Rotation requires the current
validator plus exact 2-of-3 current factors, a fresh replacement descriptor,
one-step generation and epoch increments, and delayed completion. Recovery
still cannot move assets or call arbitrary contracts.

See:

- [O.37.1 Cryptographic Descriptor Specification](./O37_1_CRYPTOGRAPHIC_DESCRIPTOR_SPECIFICATION.md);
- [O.37.1 Recovery Evidence Specification](./O37_1_RECOVERY_EVIDENCE_SPECIFICATION.md);
- [O.37.1 Recovery Lifecycle Update](./O37_1_RECOVERY_LIFECYCLE_UPDATE.md);
- [O.37.1 Implementation Readiness Review](./O37_1_IMPLEMENTATION_READINESS_REVIEW.md).

O.37.1 also pins Node `26.0.0`, npm `11.12.1`, lockfile version `3`, and
fail-closed runtime checks. It creates no Solidity, bytecode, account,
credential, signature, UserOperation, funding action, RPC call, or public
mutation.

## O.37.2 Deterministic Cryptographic Test Fixtures

O.37.2 creates the public test inputs that O.37 could not create under its
original authority boundary. The isolated package connects O.32 intent and
authorization hashes, O.33 validator and recovery digests, O.37.1 complete
descriptors, canonical validator and recovery evidence, and ERC-4337 v0.7
`PackedUserOperation` hashes.

All material is `TEST_FIXTURE_ONLY`. Deterministic private scalars exist only
in generator/test memory and are never committed. The package uses chain
`31337`, reserved fixture addresses, and an `.invalid` RP domain; it never
uses the canonical PhilCore identity, canonical validator, Device Vault, a
real WebAuthn credential, local environment configuration, or a live
network.

The fixtures include low-s secp256k1 and P-256 success cases, malformed and
mutated rejection cases, complete ABI-compatible recovery evidence, and
UserOperation field/replay mutations. O.37.2 also corrects the synthetic
O.37.1 WebAuthn `rpIdHash` to `SHA-256(UTF8(rpId))`.

See:

- [O.37.2 Deterministic Fixture Specification](./O37_2_DETERMINISTIC_FIXTURE_SPECIFICATION.md);
- [O.37.2 Cryptographic Fixture Package](./O37_2_CRYPTOGRAPHIC_FIXTURE_PACKAGE.md);
- [O.37.2 Solidity Test Readiness Review](./O37_2_SOLIDITY_TEST_READINESS_REVIEW.md).

O.37.2 creates no Solidity, bytecode, deployment, live account, production
credential, production signature, RPC call, funding action, UserOperation
submission, or public mutation. Any Solidity implementation remains
separately gated.

## O.37.3 Combined-Authority Implementation Conflict

O.37.3 began the separately approved V2 Solidity implementation review and
stopped before contract or dependency changes. Recovery-configuration
rotation requires the current validator plus exact 2-of-3 recovery factors,
but the accepted interface provides only a standalone 320-byte validator
envelope and a standalone two-factor recovery envelope. No canonical combined
ABI transport specifies how all three signatures reach
`PackedUserOperation.signature`.

O.37.2 likewise contains no combined config-rotation signature or
UserOperation fixture. Inventing an envelope, weakening the authority, adding
an ABI parameter, or injecting test state would change the frozen security
boundary. See
[O.37.3 V2 Solidity Implementation Conflict Review](./O37_3_SOLIDITY_IMPLEMENTATION_CONFLICT_REVIEW.md).

O.37.3 creates no Solidity, bytecode, dependency change, account, deployment,
credential, signature, UserOperation, RPC call, funding action, or public
mutation.

## O.37.4 Authority Transport Resolution

O.37.4 closes the combined-authority transport gap locally. Ordinary actions
continue to carry the direct O.36.1 validator envelope, recovery actions
continue to carry the direct O.37.1 exact-2-of-3 envelope, and
recovery-configuration rotation carries a canonical wrapper containing both.
The validator signs the O.32 configuration-rotation digest while the two
ordered recovery factors sign the separate O.32 recovery digest, with both
bound to the same account, chain, intent, UserOperation hash, epochs,
configuration proposal, and bitmap.

EntryPoint v0.7 remains the sole owner of keyed nonce sequence state.
PhilCore checks lane/action/intent parity and stores no duplicate nonce.
Initialization remains the frozen 20-field constructor containing recovery
commitments and configuration hash; complete descriptors remain protected
Runtime enrollment data until their public verification fields are needed as
one-time evidence.

See:

- [O.37.4 Authority Transport Specification](./O37_4_AUTHORITY_TRANSPORT_SPECIFICATION.md);
- [O.37.4 ERC-4337 Integration Specification](./O37_4_ERC4337_INTEGRATION_SPECIFICATION.md);
- [O.37.4 Recovery Configuration Rotation Specification](./O37_4_RECOVERY_ROTATION_SPECIFICATION.md);
- [O.37.4 V2 ABI And Security Interface Freeze](./O37_4_ABI_FREEZE.md);
- [O.37.4 Authority Transport Threat Analysis](../security/O37_4_AUTHORITY_TRANSPORT_THREAT_ANALYSIS.md).

O.37.4 creates deterministic test-only signatures and digest bindings, but no
credential, production signature, UserOperation, Solidity, bytecode, RPC
call, deployment, funding action, or public mutation. Solidity remains
separately gated.

## O.37.5 Solidity Code-Size Conflict

O.37.5 began the approved local V2 account/factory implementation with the
exact frozen Solidity `0.8.27`, Cancun, optimizer, viaIR, OpenZeppelin
`5.6.1`, and Account Abstraction `0.7.0` boundary. The direct implementation
compiled successfully but the account and factory runtime artifacts exceeded
Ethereum's EIP-170 `24576`-byte limit.

External verification, linked delegatecall libraries, proxies, reduced ABI,
alternate factory creation, and an unfrozen native-P256 dependency would
change accepted security or CREATE2 assumptions. O.37.5 therefore removed
the partial Solidity and toolchain changes and stopped fail-closed. See
[O.37.5 V2 Solidity Implementation Conflict Review](./O37_5_SOLIDITY_IMPLEMENTATION_CONFLICT_REVIEW.md).

No deployment, RPC, account, fund movement, credential, production
signature, UserOperation, or public mutation occurred.

## O.37.6 Deployable Minimal Architecture

O.37.6 resolves the O.37.5 architecture question without creating Solidity.
It selects a new native-ETH-only minimal account version, one stateless
authority verifier reached by code-hash-pinned `STATICCALL`, and one
non-upgradeable version-specific factory.

The account retains EntryPoint validation, typed native/confirmation
execution, validator and exact-2-of-3 recovery state, delays, epochs, freezes,
and mutation rules. The verifier performs exact O.32/O.37.1/O.37.4
cryptography onchain but has no storage, admin, registry, callback, upgrade,
or execution power. ERC20/ERC721/ERC1155 capabilities are absent and may
return only in a separate future account version.

Historical O.37.4 transport and full-profile evidence remain unchanged. The
minimal profile has a new account-version ID and CREATE2 address and does not
claim ABI compatibility with the full profile. EntryPoint remains the sole
nonce owner; no proxy, delegatecall, module, generic execute, paymaster, or
hidden authority is introduced.

See:

- [O.37.6 Code Size Architecture Review](./O37_6_CODE_SIZE_ARCHITECTURE_REVIEW.md);
- [O.37.6 Minimal Account Architecture](./O37_6_MINIMAL_ACCOUNT_ARCHITECTURE.md);
- [O.37.6 Factory Size Strategy](./O37_6_FACTORY_SIZE_STRATEGY.md);
- [O.37.6 Code Size Security Impact Review](../security/O37_6_CODE_SIZE_SECURITY_IMPACT_REVIEW.md);
- [O.37.6 Implementation Roadmap](./O37_6_IMPLEMENTATION_ROADMAP.md).

O.37.6 creates no Solidity, bytecode, deployment, RPC call, funding action,
credential, signature, UserOperation, or public mutation.

## O.37.7 Static Authority Verifier

O.37.7 implements only the fixed verifier selected by O.37.6. The
`PhilCoreV2StaticAuthorityVerifier` has empty storage and one verification
entry point. It requires caller/account equality, derives the frozen
validator and recovery digests, verifies unchanged O.37.4 transport, and
returns one versioned success magic value.

The runtime is `12645` bytes under the frozen Solidity `0.8.27`, Cancun,
optimizer-200, viaIR build. It retains OpenZeppelin's P-256 native path with
Solidity fallback and fits the O.37.6 `20480`-byte hard maximum with `7835`
bytes of reserve.

The verifier is not an account and has no state, admin, upgrade, registry,
fund, recovery-transition, validator-management, or execution authority. A
future account must derive every request field from its own immutable and
current state, pin verifier address and code hash, call with `STATICCALL`,
and independently enforce all EntryPoint and mutation rules.

See:

- [O.37.7 Static Verifier Size Report](./O37_7_STATIC_VERIFIER_SIZE_REPORT.md);
- [O.37.7 Static Verifier ABI Report](./O37_7_STATIC_VERIFIER_ABI_REPORT.md);
- [O.37.7 Static Verifier Security Boundary](../security/O37_7_STATIC_VERIFIER_SECURITY_BOUNDARY.md).

No V2 account, factory, deployment script, persistent deployment, external
RPC, Sepolia interaction, funding, credential, new signature, UserOperation,
or public mutation is created by O.37.7.

## O.37.8 Minimal Account Implementation Conflict

O.37.8 compiled the O.37.6 minimal account boundary locally and stopped
fail-closed before retaining Solidity. The smallest security-preserving
candidate measured `19454` runtime bytes and `21755` creation bytes, exceeding
the frozen account gates by `4094` and `3323` bytes respectively.

The phase also found that its requested direct account-immutable verifier
binding conflicts with O.37.6's factory-sourced immutable verifier binding and
exact 20-field constructor. No architecture change was inferred.

The oversized account, interface, ABI, storage layout, bytecode, and build
configuration were removed. O.37.8 retains only deterministic conflict
evidence and the
[implementation conflict review](./O37_8_MINIMAL_ACCOUNT_IMPLEMENTATION_CONFLICT_REVIEW.md).
No factory, deployment, chain interaction, funding, credential, signature,
UserOperation, public mutation, or push occurred.

## O.37.9 Compressed Minimal Account Architecture

O.37.9 resolves O.37.8 without retaining Solidity. It selects the future
`philcore-v2-minimal-account-v2` and version-specific factory V2, keeps the
exact 20-field constructor, and makes the factory the sole immutable source
of the O.37.7 verifier address and runtime code hash.

The account performs one exact factory `STATICCALL`, checks verifier code
identity, and then performs the existing verifier `STATICCALL`. It stores no
verifier, registry, admin, proxy, module, session, or duplicate nonce.

Compression removes duplicate execution-side common authorization checks,
consolidates public views and permissionless settlement, derives redundant
commitments and timestamps, and reduces error/event shapes. EntryPoint nonce
ownership, O.37.4 authority transport, exact-2-of-3 recovery, native transfer,
EntryPoint deposit release, confirmation, validator rotation, and recovery
transitions remain onchain.

The architecture projects `14814` runtime bytes and `16507` creation bytes.
These values are planning targets, not compiler evidence. A later separately
approved implementation must stop if fresh compilation exceeds either frozen
budget.

See:

- [O.37.9 Minimal Account Compression Review](./O37_9_MINIMAL_ACCOUNT_COMPRESSION_REVIEW.md);
- [O.37.9 Verifier Binding Resolution](./O37_9_VERIFIER_BINDING_RESOLUTION.md);
- [O.37.9 Storage Boundary](./O37_9_STORAGE_BOUNDARY.md);
- [O.37.9 ABI Reduction Plan](./O37_9_ABI_REDUCTION_PLAN.md).

O.37.9 creates no account, factory, bytecode, deployment, blockchain
interaction, funding, credential, signature, UserOperation, public mutation,
or push.

## O.37.10 Minimal Account, Factory, and Local Lifecycle

O.37.10 implements `philcore-v2-minimal-account-v2` and its version-specific
CREATE2 factory. The account has exactly the O.37.9 15-function ABI and
slots `0` through `14`; the factory is the only immutable source of the
unchanged O.37.7 verifier address and runtime hash.

The account runtime is `13811` bytes and its creation bytecode is `15630`
bytes. The factory runtime is `18317` bytes. All fit the reviewed limits. An
ephemeral Hardhat lifecycle verifies real EntryPoint replay protection, real
validator authority, native transfer, confirmation, validator rotation,
delayed exact-2-of-3 recovery semantics, configuration rotation, deposit
release, verifier-binding failures, and deterministic CREATE2 addresses.

The version remains native-ETH-only. ERC20/ERC721/ERC1155 surfaces are absent,
and unsolicited tokens may be permanently stranded. There is still no admin,
proxy, upgrade, delegatecall, generic execute, mutable verifier, module,
session, paymaster, aggregator, or duplicate nonce storage.

See the
[O.37.10 implementation report](./O37_10_V2_MINIMAL_ACCOUNT_IMPLEMENTATION_REPORT.md)
and
[deployment-readiness review](./O37_10_DEPLOYMENT_READINESS_REVIEW.md).
The package is locally deployable but not Sepolia-ready. O.37.10 performs no
external RPC, public deployment, funding, production signing, public
UserOperation submission, public mutation, or push.
