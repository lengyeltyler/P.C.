# PhilCore Core Boundary

## Accepted Step 1 Reconciliation

[Phil V1 Secure Identity Architecture](./PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md)
is the controlling contract for the V1 identity, privacy, data, recovery,
device, authorization, proof-admission, adapter, and algorithm-migration
boundaries. This document continues to classify current repository modules and
byte-stable compatibility behavior. Where older wording below treats a root
commitment, STWO proof, Ethereum/Base route, or account recovery as the target
product architecture, that wording is superseded by the secure-identity
architecture and ACP-0003.

Step 1 changes documentation only. No runtime, contract, proof, schema, device,
deployment, signing, RPC, or network behavior was changed.

## Product Frame

PhilCore is a Personal Security Operating System.

PhilCore is a device-first cryptographic identity, encrypted-data, and
authorization system. It establishes a private, user-owned identity root,
exposes pairwise scoped identities, and uses replaceable device approval,
policy, capabilities, and exceptional root proofs to authorize credentials,
wallets, applications, and AI agents without exposing root secrets.

Ethereum/Base is the first real execution adapter. It is not the identity layer.

User-facing modules are applications. Chain, network, protocol, or execution-specific implementation modules are adapters.

This document classifies the current repository into product boundaries. It does not propose application-code changes, module moves, refactors, contract changes, proof-code changes, schema changes, or behavioral changes.

## Current V2 Execution Boundary

`PhilCoreV2MinimalAccountV2` is the current narrow Ethereum smart-account
security model. It accepts only reviewed typed actions and intentionally omits
generic execution, delegatecall, batching, approvals, modules, session keys,
proxy upgrades, and paymaster extensibility. V1 and N-series accounts remain
separate legacy/compatibility or historical scopes.

V2 recovery uses fixed primary-device, hardware-security-key, and independent
roles with exact 2-of-3 authority. The active execution validator is not a
recovery factor and cannot veto a valid validator-recovery quorum. The roles
must be independently custodied and failure-separated in practice; protocol
cryptography cannot prove that operational property. Authoritative detail is
in the [V2 implementation report](./reference/O37_10_V2_MINIMAL_ACCOUNT_IMPLEMENTATION_REPORT.md),
[current recovery semantics](./reference/O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md),
and [V2 formal threat model](./security/O30_V2_FORMAL_THREAT_MODEL.md).

## Locked Invariants

The accepted V1 invariants are:

- `phil_secret -> identityRoot -> rootOwnerCommitment`, preserving existing
  `ownerCommitment` bytes as a compatibility alias;
- root values are protected, while public relationships use scoped
  commitments;
- identity/data recovery is separate from account recovery and reconstructs
  only the encrypted continuity-package key;
- hardware-backed device approval is replaceable and never becomes identity;
- routine actions require a narrow capability, device signature, policy,
  replay protection, limits, and an adapter binding;
- exceptional root operations additionally require an admitted witness-hiding
  proof bound to the complete authorization envelope;
- proof validity or a device signature alone never authorizes an action;
- adapters never receive root, data-vault, or recovery keys; and
- every cryptographic suite and verifier is immutably versioned for migration.

`ACTION_UNLOCK`, its six-field tuple, `proofInputHash`,
`stwo-unlock-keccak-v1`, `[fact_high, fact_low]`, WebAuthn/passkey work, and the
Ethereum/Base route remain byte-stable implementation evidence. They are
compatibility or quarantined research surfaces, not the accepted V1 public
identity or authorization architecture.

## Dependency Diagram

```text
Identity Root
  -> Device Vault
      -> Trust Manager
          -> Authorization Engine
              -> Security Policy Engine
              -> Proof System
              -> Applications Layer
              -> PhilCore Runtime API
              -> Adapter Layer
                -> Ethereum Adapter
                  -> Base contracts
                  -> smart-account/session artifacts
              -> Future AI Permissions Layer
      -> Recovery Manager
      -> Audit Log

Audit Log observes:
  Device Vault
  Trust Manager
  Authorization Engine
  Security Policy Engine
  Recovery Manager
  Ethereum Adapter
  Proof System

Proof System depends on:
  Identity Root public commitment semantics
  Authorization Engine public tuple semantics

Ethereum Adapter depends on:
  Authorization Engine packages
  Proof System facts
  Security Policy Engine decisions
```

## Runtime Layers

PhilCore has three runtime layers:

```text
Layer 1 - Identity Layer
  Answers: "Who are you?"
  Includes: Identity Root, Device Vault, Trust Manager

Layer 2 - Decision Layer
  Answers: "Should this happen?"
  Includes: Authorization Engine, Security Policy Engine, Proof System, Recovery Manager

Layer 3 - Execution Layer
  Answers: "How does it happen?"
  Includes: Applications Layer, Adapter Layer, PhilCore Runtime API, Ethereum Net, NFT Manager App,
  Ethereum Adapter, Base profile/config, future applications, future adapters
```

Ethereum/Base belongs in the Execution Layer, not the Identity Layer.

## 1. Identity Root

### Purpose

Identity Root defines the canonical Phil identity:

```text
phil_secret -> identityRoot -> ownerCommitment
```

It is the local, user-owned cryptographic root from which public Phil identity commitments are derived. It is not a wallet, chain account, World ID credential, passkey, or Ethereum EOA.

### Current Files And Modules

- `apps/phil-device-sdk/src/identity.ts`
- `apps/phil-device-sdk/src/hashes.ts`
- `apps/phil-device-sdk/src/commitments.ts`
- `docs/reference/PHIL_IDENTITY_MODEL.md`
- `contracts/base/PhilAuthorizationHashing.sol`
- `proving/src/abi.rs`
- `proving/src/types.rs`

### Current Status

Implemented locally and treated as canonical. The SDK can generate or normalize `phil_secret`, derive `identityRoot`, and derive `ownerCommitment`. The legacy owner commitment path still exists only behind explicit test-only opt-in.

The current AIR constrains the canonical secret-to-commitment relation, but its
serialized STWO openings expose direct secret-bit trace columns. It is not a
privacy-preserving proof of knowledge. The implementation is retained only for
explicit local synthetic research and emits an
`EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT`. Runtime validators reject real
Device Vault providers, ordinary generation, finalization, publication, and
execution preparation until a reviewed witness-hiding construction replaces
that layout. The identity derivation itself is stable.

### What Should Remain Unchanged

- The derivation order and semantics.
- The non-zero, Stark-friendly private root normalization.
- Canonical `rootOwnerCommitment` bytes from `identityRoot`, preserving the
  existing `ownerCommitment` name as a compatibility alias.
- Public identity surface separation from private root material.
- Legacy owner commitment remaining explicit test-only behavior.

### What May Need Future Renaming Or Reframing

- Product docs should say "Identity Root" rather than presenting identity primarily through Base or wallet workflows.
- Existing code may retain `ownerCommitment`; new product-facing language must
  not call it a universal public Phil identity anchor.
- Legacy address/salt naming should stay clearly marked as legacy/test-only.

### What Should Not Be Implemented Yet

- No alternate canonical identity source.
- No chain-specific identity root.
- No multi-chain identity registry.
- No production recovery rewrite.
- No claim that Ethereum accounts or passkeys are the Phil identity root.

### Security Assumptions

- `phil_secret` is generated and kept locally.
- `phil_secret` must never be placed in public artifacts, logs, contracts, bridge payloads, backups in plaintext, or normal app metadata.
- `identityRoot` and `rootOwnerCommitment` are protected by default. Any narrow
  disclosure requires an explicit, purpose-bound ceremony under the accepted
  architecture.

### Dependencies

- Depends on local entropy and device-side secret protection.
- Feeds Device Vault, Authorization Engine, Proof System, Trust Manager, and Ethereum Adapter.

## 2. Device Vault

### Purpose

Device Vault is the local protected storage and key-management boundary. It stores encrypted Phil identity metadata, credential registry snapshots, recovery state, audit history, storage-key lifecycle metadata, and encrypted backup blobs. It must not expose root secrets.

### Current Files And Modules

- `apps/phil-device-sdk/src/deviceIdentityStorage.ts`
- `apps/phil-device-sdk/src/deviceIdentityIndexedDbStorage.ts`
- `apps/phil-device-sdk/src/deviceIdentityKeyLifecycle.ts`
- `apps/phil-device-sdk/src/deviceIdentity.ts`
- `docs/reference/PHIL_DEVICE_IDENTITY_V1.md`
- `ARCHITECTURE.md`
- `STATUS.md`

### Current Status

Implemented as a local-first encrypted storage baseline.

Current support includes:

- AES-256-GCM encrypted local registry storage.
- Owner-bound associated data.
- Node file and in-memory test backends.
- Browser IndexedDB/WebCrypto encrypted storage.
- Encrypted backup import/export.
- Storage-key and backup-key lifecycle metadata.
- Rotation with rollback behavior.
- Explicit local/dev key providers and future platform-provider scaffolds.

This is not yet a production vault.

### What Should Remain Unchanged

- Encrypted-at-rest registry design.
- Owner-bound associated data.
- Plaintext secret-field rejection.
- Backup import/export integrity checks.
- Key lifecycle status model: active, retiring, retired, revoked.
- Rollback-on-failure rotation behavior.
- Explicit unsafe-for-production labels on local/dev key providers.

### What May Need Future Renaming Or Reframing

- `deviceIdentityStorage` may eventually be product-framed as Device Vault storage.
- `deviceIdentityKeyLifecycle` may eventually be framed as Vault Key Lifecycle.
- "Registry storage" docs should explain that the registry is a vault payload, not the whole vault.

### What Should Not Be Implemented Yet

- No new production OS keychain provider in this milestone.
- No Secure Enclave/mobile storage implementation in this milestone.
- No cloud sync service.
- No social recovery custody.
- No plaintext fallback storage.
- No automatic migration to a new storage format.

### Security Assumptions

- Registry plaintext is only available transiently after successful local decryption.
- Encryption keys must be protected by the local runtime or injected securely.
- Local/dev passphrase providers are not production custody.
- Encrypted backups are portable but still sensitive.
- Metadata listing should remain minimal and avoid leaking credential labels where possible.

### Dependencies

- Depends on Identity Root for owner binding.
- Supports Trust Manager, Recovery Manager, Audit Log, and Authorization Engine.

## 3. Trust Manager

### Purpose

Trust Manager is the accepted product-facing term for the boundary that controls credentials, devices, and passkeys that can authorize Phil identity actions. Credentials may include passkeys, platform authenticators, hardware security keys, Secure Enclave-backed credentials, mobile secure hardware credentials, and local dev credentials.

Credentials authorize Phil actions. They do not replace the Phil identity root.

### Current Files And Modules

- `apps/phil-device-sdk/src/deviceIdentity.ts`
- `apps/phil-device-sdk/src/deviceIdentityWebAuthn.ts`
- `apps/phil-device-sdk/src/deviceIdentityLifecycle.ts`
- `apps/phil-device-sdk/src/deviceIdentityStorage.ts`
- `apps/phil-device-sdk/src/deviceIdentityIndexedDbStorage.ts`
- `docs/reference/PHIL_DEVICE_IDENTITY_V1.md`
- `scripts/base/run-phil-device-identity-demo.cjs`
- `test/unit/device-identity*.test.cjs` where present

Source files are not renamed yet. Existing `deviceIdentity*` and credential-registry names remain implementation names until a future no-behavior-change terminology pass.

### Current Status

Implemented locally with a mature model:

- Local deterministic test provider.
- WebAuthn/passkey provider path.
- ES256/P-256 registration and assertion verification.
- Explicit attestation policy modes.
- Multi-credential registry.
- Credential statuses: active, pending, revoked, recovery-only, archived.
- Rotation overlap.
- Anti-lockout warnings.
- Local audit events.
- Hardware-backed provider scaffolds that fail explicitly when unsupported.

### What Should Remain Unchanged

- Provider interface shape: public metadata, digest authorization, no private material export.
- WebAuthn/passkey registration and assertion verifier work.
- Explicit attestation policy behavior.
- Multi-credential-per-Phil-identity model.
- Credential rotation as overlap, not destruction.
- Recovery-only credential concept.
- Unsupported hardware provider scaffolds failing explicitly.

### What May Need Future Renaming Or Reframing

- `PhilDeviceIdentityProvider` may eventually be framed as a Credential Provider.
- `deviceIdentityLifecycle` may eventually be framed as Trust Manager state.
- "Device Identity" should be clarified as the device/credential authorization boundary, not the Phil root identity itself.

### What Should Not Be Implemented Yet

- No trusted attestation-root validation unless PhilCore chooses to claim authenticator hardware provenance.
- No production Secure Enclave implementation yet.
- No mobile secure hardware implementation yet.
- No non-ES256 WebAuthn expansion yet.
- No credential cloud sync.
- No automatic final-credential revocation behavior that can lock out the user.

### Security Assumptions

- Credentials authorize actions; they are not the root Phil identity.
- Active credentials can authorize ordinary actions.
- Recovery-only credentials require stronger recovery flow semantics.
- Revoked, archived, pending, and recovery-only credentials must not authorize ordinary actions.
- WebAuthn private key material remains inside the authenticator.

### Dependencies

- Depends on Identity Root for `ownerCommitment` binding.
- Depends on Device Vault for encrypted persistence.
- Feeds Authorization Engine.
- Feeds Recovery Manager.
- Emits Audit Log events.

## 4. Authorization Engine

### Purpose

Authorization Engine turns an intended user action into a Phil authorization object. It binds identity, action, policy, nullifier, consumer data, expiry, and proof package semantics.

Today, its primary concrete action is `ACTION_UNLOCK`.

### Current Files And Modules

- `apps/phil-device-sdk/src/authorization.ts`
- `apps/phil-device-sdk/src/execute.ts`
- `apps/phil-device-sdk/src/hashes.ts`
- `apps/phil-device-sdk/src/nullifier.ts`
- `apps/phil-device-sdk/src/proof/publicInputs.ts`
- `contracts/base/interfaces/IPhilAuthorizationTypes.sol`
- `contracts/base/PhilBaseActionGate.sol`
- `contracts/base/PhilAuthorizationHashing.sol`
- `contracts/base/PhilUnlockConsumer.sol`
- `contracts/base/PhilMintPassConsumer.sol`
- `docs/reference/PROOF_INPUT_SCHEMA.md`
- `docs/reference/ACTION_UNLOCK_PROOF_SPEC.md`

### Current Status

Implemented for the locked Base-facing unlock flow. It assembles:

- owner commitment
- unlock request
- consumer data
- action hash
- policy hash
- nullifier
- authorization digest
- proof package

It correctly rejects raw owner-commitment injection and requires canonical Phil identity or explicit legacy test-only inputs.

### What Should Remain Unchanged

- `ACTION_UNLOCK` semantics.
- Authorization public tuple.
- `proofInputHash` derivation.
- `nullifier` replay semantics.
- `consumerDataHash` binding.
- Expiry field semantics.
- Legacy owner commitment guardrails.
- Base action gate validation behavior.

### What May Need Future Renaming Or Reframing

- `BaseActionAuthorization` should remain as the current contract-facing type, but product docs may introduce a higher-level `PhilAuthorization` concept.
- `authorization.ts` may eventually become the core Authorization Engine module.
- `execute.ts` may eventually be framed as execution payload assembly for an adapter.

### What Should Not Be Implemented Yet

- No generalized multi-action policy language yet.
- No multi-chain authorization schema.
- No AI-agent delegation logic yet.
- No changes to `ACTION_UNLOCK`.
- No changes to the proof public input tuple.
- No changes to nullifier semantics.

### Security Assumptions

- Authorization is valid only when bound to the correct owner commitment, action hash, policy hash, nullifier, consumer data hash, and expiry.
- Nullifiers prevent replay.
- Consumer data must hash to the committed value.
- Authorization packages are not equivalent to root secret possession unless backed by credential authorization and, where required, proof verification.

### Dependencies

- Depends on Identity Root.
- Depends on Trust Manager for device authorization.
- Depends on Security Policy Engine for policy decisions.
- Feeds Proof System and Ethereum Adapter.
- Emits Audit Log events in future product framing.

## 5. Security Policy Engine

### Purpose

Security Policy Engine decides whether a requested action should be authorized under local Phil security rules.

It should eventually handle target allowlists, spending limits, credential strength, expiry, recovery state, action class, risk level, required user verification, multi-step approvals, and agent delegation constraints.

### Current Files And Modules

Current policy behavior is distributed across:

- `apps/phil-device-sdk/src/authorization.ts`
- `apps/phil-device-sdk/src/commitments.ts`
- `apps/phil-device-sdk/src/deviceIdentityLifecycle.ts`
- `apps/phil-device-sdk/src/deviceIdentityWebAuthn.ts`
- `apps/phil-device-sdk/src/proof/publicInputs.ts`
- `contracts/base/PhilBaseActionGate.sol`
- `contracts/base/PhilUnlockConsumer.sol`
- `contracts/base/PhilMintPassConsumer.sol`
- `scripts/base/build-*`
- `docs/reference/PHIL_DEVICE_IDENTITY_V1.md`

### Current Status

Not yet a first-class boundary.

Policy exists implicitly as:

- credential lifecycle authorization requirements
- expiry checks
- consumer-data checks
- proof package shape checks
- nullifier consumption
- WebAuthn user verification expectations
- recovery stronger-than-ordinary-authentication flags
- local artifact readiness checks

### What Should Remain Unchanged

- Existing implicit checks.
- Credential lifecycle requirements.
- Explicit confirmation for destructive credential actions.
- Expiry and nullifier enforcement.
- WebAuthn challenge and origin binding.
- Proof/public-input validation.

### What May Need Future Renaming Or Reframing

- `buildUnlockPolicy` may eventually be one policy primitive under a broader Security Policy Engine.
- Credential management authorization requirements should be framed as local policy rules.
- Contract-level checks should be framed as adapter enforcement, not the whole policy engine.

### What Should Not Be Implemented Yet

- No broad policy DSL.
- No remote policy server.
- No multi-chain policy abstraction.
- No AI-agent policy engine yet.
- No production risk scoring.
- No automatic user-behavior profiling.

### Security Assumptions

- Policy decisions should happen locally by default.
- Policy commitments may be public through `policyHash`, but sensitive policy details should not be exposed unnecessarily.
- Contract-level policy checks are necessary but not sufficient for complete local user security.

### Dependencies

- Depends on Identity Root, Trust Manager, Device Vault, and Recovery Manager.
- Feeds Authorization Engine and Ethereum Adapter.
- Emits Audit Log events.

## 6. Ethereum Adapter

### Purpose

Ethereum Adapter is the first real execution adapter. It turns Phil authorizations into Ethereum/Base execution flows, smart-account artifacts, proof fact consumption, and contract calls.

Ethereum/Base is a module controlled by PhilCore. It is not PhilCore's identity layer.

### Current Files And Modules

- `contracts/base/*`
- `contracts/l1/*`
- `scripts/base/*`
- `test/unit/*.test.cjs`
- `hardhat.config.cjs`
- `hardhat.shared.cjs`
- `config/*`
- current Ethereum/Base references under `docs/reference/` and
  `docs/security/`

### Current Status

Implemented as a local-first Ethereum/Base path:

- Base authorization hashing.
- Base action gate.
- Mint-pass consumer.
- Unlock consumer.
- Mirrored proof-input-hash verifier.
- L1 trust anchor.
- L1-to-Base proof-input-hash messaging.
- Local wallet artifact chain.
- Local smart-account deploy artifact chain.
- Local bundler stub.
- Local no-send session matrix.
- Local device-signing session integration.

External public deployment and production bundler paths are not complete.

### What Should Remain Unchanged

- Base contract tuple semantics.
- `PhilBaseActionGate` nullifier consumption.
- Mirrored proof-input-hash fact model.
- L1 trust anchor semantics.
- Local no-send session matrix.
- Existing smart-account artifact chain.
- Current Base as first execution path.

### What May Need Future Renaming Or Reframing

- `scripts/base` should eventually be product-framed as Ethereum Adapter tooling.
- Wallet artifacts should be framed as Ethereum wallet module artifacts.
- Smart-account artifacts should be framed as Ethereum smart-account adapter artifacts.
- Docs should avoid implying PhilCore is a wallet project.
- `BaseActionAuthorization` may be framed as the Base/Ethereum representation of a Phil authorization.

### What Should Not Be Implemented Yet

- No multi-chain adapter.
- No abstract chain registry.
- No new chain support.
- No production mainnet path without a security review.
- No live bundler/paymaster expansion in this milestone.
- No changes to existing contract semantics.

### Security Assumptions

- Ethereum contracts see public authorization data and facts, not root secrets.
- Base should verify tuple consistency, fact presence, expiry, and nullifier freshness.
- Ethereum execution remains subject to Ethereum/Base cryptographic assumptions.
- Smart-account signing must be scoped to an explicit digest and session context.

### Dependencies

- Depends on Authorization Engine.
- Depends on Proof System for verified facts.
- Depends on Security Policy Engine for local approval.
- Depends on Trust Manager for local signing/authorization.
- Emits Audit Log events.

## 7. Proof System

### Purpose

Proof System provides proof-backed authorization. It proves statements about Phil identity and authorization inputs without exposing root secrets, then produces a verification artifact or compact verified fact.

Today the main proof family is `stwo-unlock-keccak-v1`.

### Current Files And Modules

- `proving/src/*`
- `proving/src/bin/*`
- `proving/tests/*`
- `proving/fixtures/*`
- `starknet_integration/*`
- `starknet_integration_runner/*`
- `starknet_adapter_spike/*`
- `starknet_spike/*`
- `cairo_air_adapter_spike/*`
- `merkle_parity_spike/*`
- `vendor/stwo_cairo_verifier/*`
- `apps/phil-device-sdk/src/proof/*`
- `docs/reference/PROOF_INPUT_SCHEMA.md`
- `docs/reference/ACTION_UNLOCK_PROOF_SPEC.md`
- current proof and Starknet references under `docs/reference/`

### Current Status

Implemented locally and experimentally across Rust, TypeScript schemas, Solidity verifier boundaries, and Cairo/Starknet spike paths.

The repo preserves:

- STWO proof package shape.
- public input tuple.
- `proofInputHash`.
- raw proof artifact slot.
- two-felt fact encoding.
- candidate Starknet verification/relay direction.

Direct trustless Base verification of the current frozen raw proof boundary has been ruled out as the active path.

### What Should Remain Unchanged

- Current STARK/proof work.
- Proof package shape.
- `proofInputHash` derivation.
- `proofBlob` as artifact slot.
- STWO unlock proof type label.
- two-felt fact encoding.
- Starknet-as-verification-layer candidate framing.

### What May Need Future Renaming Or Reframing

- Proof docs should describe proofs as one authorization backend, not PhilCore's whole product identity.
- Starknet should be framed as the first candidate proof-verification environment, not an identity layer.
- "proof-gated identity" should become "proof-backed authorization" in product-facing docs.

### What Should Not Be Implemented Yet

- No new proof family.
- No proof public input shape change.
- No direct Base verifier revival for the frozen raw proof boundary.
- No production Starknet deployment claim.
- No post-quantum marketing claim beyond careful "post-quantum-oriented" architecture language.

### Security Assumptions

- A verified proof fact is meaningful only if produced by the expected verifier for the expected statement and public inputs.
- `proofInputHash` is a commitment to public inputs and package metadata; it is not a substitute for actual proof verification.
- Root secrets must remain witness material and never become public inputs.

### Dependencies

- Depends on Identity Root semantics.
- Depends on Authorization Engine public tuple.
- Feeds Ethereum Adapter through verified facts.
- Emits Audit Log events in future product framing.

## 8. Recovery Manager

### Purpose

Recovery Manager governs credential loss, credential replacement, recovery approvals, recovery-only credentials, and future social/hardware recovery paths.

Recovery should preserve Phil identity continuity without exposing or replacing the root identity casually.

### Current Files And Modules

- `apps/phil-device-sdk/src/deviceIdentityLifecycle.ts`
- `apps/phil-device-sdk/src/deviceIdentityStorage.ts`
- `apps/phil-device-sdk/src/deviceIdentityIndexedDbStorage.ts`
- `apps/phil-device-sdk/src/deviceIdentityKeyLifecycle.ts`
- `docs/reference/PHIL_DEVICE_IDENTITY_V1.md`
- `ARCHITECTURE.md`
- `STATUS.md`

### Current Status

Framework-first and local.

Current model includes:

- recovery states: normal, recovery-pending, recovery-approved, recovery-completed
- mechanisms: secondary active credential, recovery credential, future committee, future hardware path
- stronger-than-ordinary-authentication requirement flags
- recovery audit events
- encrypted persistence of recovery state

Production recovery enforcement is not complete.

### What Should Remain Unchanged

- Recovery state model.
- Recovery-only credential label.
- Stronger-than-ordinary-authentication requirement.
- Anti-lockout warnings.
- Recovery audit events.
- Encrypted persistence of recovery state.

### What May Need Future Renaming Or Reframing

- Recovery state inside credential lifecycle should eventually be framed as Recovery Manager state.
- Future social/hardware mechanisms should remain labels until real ceremonies are designed.

### What Should Not Be Implemented Yet

- No social recovery committee implementation.
- No hardware recovery ceremony.
- No production recovery enforcement rewrite.
- No remote recovery service.
- No automatic root rotation.
- No recovery path that exports `phil_secret`.

### Security Assumptions

- Recovery must be stronger than ordinary authorization.
- Recovery should avoid permanent lockout and unauthorized takeover.
- Recovery metadata can be encrypted and backed up.
- Root secrets must not be exposed during recovery.

### Dependencies

- Depends on Identity Root, Device Vault, Trust Manager, Security Policy Engine, and Audit Log.
- Feeds Trust Manager and Authorization Engine after recovery completion.

## 9. Audit Log

### Purpose

Audit Log records local security-relevant events for identity, vault, credential, policy, recovery, proof, and execution actions.

It should eventually become a first-class tamper-evident local history, but today it is an immutable-style local event trail inside registry state.

### Current Files And Modules

- `apps/phil-device-sdk/src/deviceIdentityLifecycle.ts`
- `apps/phil-device-sdk/src/deviceIdentityStorage.ts`
- `apps/phil-device-sdk/src/deviceIdentityIndexedDbStorage.ts`
- `apps/phil-device-sdk/src/deviceIdentityKeyLifecycle.ts`
- `docs/reference/PHIL_DEVICE_IDENTITY_V1.md`
- `ARCHITECTURE.md`
- `STATUS.md`

### Current Status

Implemented locally for credential lifecycle, recovery, registry storage, import/export, tamper detection, storage-key lifecycle, and backup-key lifecycle events.

Not yet tamper-proof, replicated, externally anchored, or independently queryable.

### What Should Remain Unchanged

- Immutable-style local audit event model.
- Owner commitment binding.
- Storage events.
- Credential events.
- Recovery events.
- Key lifecycle events.
- Volatile handling for failed-load/tamper-detected cases where the registry cannot be safely modified.

### What May Need Future Renaming Or Reframing

- Audit events should eventually be product-framed as the PhilCore Audit Log.
- Credential registry audit trail may become one stream within a broader audit log.

### What Should Not Be Implemented Yet

- No on-chain audit log.
- No public audit feed.
- No remote telemetry.
- No cloud audit replication.
- No user-behavior surveillance.

### Security Assumptions

- Audit logs may contain sensitive metadata and should remain local/encrypted by default.
- Audit logs are useful for local state integrity and user review, but are not yet tamper-proof evidence.
- Failed authentication/tamper events may need volatile local recording because encrypted state cannot be trusted.

### Dependencies

- Depends on Device Vault for persistence.
- Observes Trust Manager, Recovery Manager, Authorization Engine, Security Policy Engine, Ethereum Adapter, and Proof System.

## 10. Future AI Permissions Layer

### Purpose

Future AI Permissions Layer will allow AI agents to request and use narrowly scoped permissions from PhilCore without receiving root secrets, unrestricted wallet authority, vault keys, or broad credential power.

This is a future boundary only.

### Current Files And Modules

No dedicated files or modules yet.

Adjacent current concepts:

- `apps/phil-device-sdk/src/authorization.ts`
- `apps/phil-device-sdk/src/deviceIdentity.ts`
- `apps/phil-device-sdk/src/deviceIdentityLifecycle.ts`
- `apps/phil-device-sdk/src/hashes.ts`
- `contracts/base/PhilBaseActionGate.sol`
- `scripts/base/*session*`

### Current Status

Not implemented.

The existing authorization, policy, session, and audit concepts provide the future substrate, but no AI-specific permission system exists.

### What Should Remain Unchanged

- Root secrets are never exposed.
- Device credentials authorize bounded actions.
- Policies and action hashes define scope.
- Sessions should be explicit and auditable.
- Ethereum/Base remains only one execution path.

### What May Need Future Renaming Or Reframing

- Smart-account dispatch sessions may become useful precedent for future delegated agent sessions.
- Authorization Engine may eventually support actor classes such as user, device, app, and agent.

### What Should Not Be Implemented Yet

- No AI agent permissions.
- No delegated autonomous wallet control.
- No agent key custody.
- No background agent spending.
- No broad "approve all" agent model.
- No remote agent policy server.

### Security Assumptions

- Agents must receive explicit, narrow, revocable, auditable permissions.
- Agents must never receive `phil_secret`, vault keys, raw private keys, or unrestricted wallet authority.
- Agent actions should be bound to policy, expiry, target, action class, and audit trail.

### Dependencies

- Will depend on Identity Root, Trust Manager, Authorization Engine, Security Policy Engine, Device Vault, Audit Log, and execution adapters.

## Do Not Touch Yet

- `phil_secret -> identityRoot -> ownerCommitment`
- `ACTION_UNLOCK`
- proof public input tuple
- `proofInputHash` derivation
- `proofType = "stwo-unlock-keccak-v1"`
- `[fact_high, fact_low]` shape
- existing STARK/proof code
- WebAuthn/passkey provider work
- encrypted registry storage
- IndexedDB/WebCrypto storage
- storage-key and backup-key lifecycle
- credential lifecycle statuses
- recovery state model
- local audit event model
- Base action gate tuple semantics
- nullifier replay protection
- Base mirrored fact verifier path
- L1 trust-anchor semantics
- local smart-account deploy/session artifact chain
- local device-signing session matrix
- local bundler stub behavior

## Future Refactor Candidates

These are candidates only. They should not be refactored as part of this document milestone.

- Product-frame `apps/phil-device-sdk/src/identity.ts` as Identity Root.
- Product-frame encrypted registry/key lifecycle modules as Device Vault.
- Product-frame `deviceIdentityLifecycle.ts` as Trust Manager plus Recovery Manager state.
- Product-frame distributed policy checks as Security Policy Engine.
- Introduce a high-level `PhilAuthorization` concept above `BaseActionAuthorization`.
- Product-frame `scripts/base/*` as Ethereum Adapter tooling.
- Product-frame wallet artifacts as Ethereum wallet module artifacts.
- Product-frame smart-account deploy artifacts as Ethereum smart-account adapter artifacts.
- Product-frame local audit events as PhilCore Audit Log.
- Clarify Starknet as proof-verification infrastructure, not identity infrastructure.
- Reserve AI permissions as a future layer over existing authorization/session primitives.

## Recommended Smallest Next Code Milestone

The smallest next code milestone should be:

```text
Add a no-behavior-change TypeScript boundary index or type-only facade for the core SDK.
```

Recommended shape:

- no runtime behavior changes
- no file moves
- no module refactors
- no contract changes
- no proof changes
- no schema changes
- no Ethereum flow changes

The facade should only group existing exports conceptually under:

- Identity Root
- Device Vault
- Trust Manager
- Authorization Engine
- Proof System

This should happen only after this document is accepted. The first implementation pass should be small enough that tests prove nothing behavioral changed.
