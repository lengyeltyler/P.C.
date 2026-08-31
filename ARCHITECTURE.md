# PhilCore Architecture

PhilCore is a Personal Security Operating System.

This file is a short architecture entry point. The accepted architecture source of truth lives in:

- [PhilCore Core Boundary](./docs/PHILCORE_CORE_BOUNDARY.md)
- [PhilCore Runtime Lifecycle](./docs/PHILCORE_RUNTIME_LIFECYCLE.md)
- [PhilCore Functional Specification v1](./docs/PHILCORE_FUNCTIONAL_SPEC_V1.md)
- [PhilCore Technical Specification v1](./docs/PHILCORE_TECHNICAL_SPEC_V1.md)
- [Phil V1 Secure Identity Architecture](./docs/PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md)
- [Architecture Change Control](./docs/ARCHITECTURE_CHANGE_CONTROL.md)
- [Canonical Documentation](./docs/CANONICAL_DOCS.md)

## Accepted Architecture Correction

The accepted documents above predate the finding that the current STWO
artifact exposes its witness. That artifact is already quarantined and cannot
reach real-secret generation, finalization, publication, signing, or
execution.

[ACP-0003](./docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md)
records the accepted correction: preserve a private chain-independent identity
root; derive scoped public identities; keep encrypted data and identity
recovery under user control; use hardware-backed device approval and narrow
capabilities for routine actions; reserve witness-hiding root proofs for
exceptional authority changes; and treat Starknet, Ethereum/Base, and later
networks as adapters.

ACP-0003 Step 1 is accepted and complete. It selected no production proof
backend and changed no runtime, contract, schema, device, or network behavior.
The Step 2 local device-and-recovery candidate is implemented, but Step 2 is
not accepted until separately authorized physical-iPhone evidence and an
independent review pass. Step 3 remains blocked.

## Architecture Frame

PhilCore is device-first. It establishes and protects a local user-owned identity root:

```text
phil_secret -> identityRoot -> rootOwnerCommitment
```

This identity root is not an Ethereum account, EOA, passkey, World ID credential, or chain-specific account.

PhilCore runtime concepts:

- Applications create intents.
- PhilCore Runtime API evaluates intents.
- User Session coordinates runtime state and owns no secrets.
- Device Vault protects encrypted local state.
- Trust Manager evaluates trusted credentials/devices.
- Security Policy Engine decides whether an action should be allowed.
- Authorization Engine creates bounded authorization packages after approval.
- Proof System supports proof-backed authorization when policy or adapter path requires it.
- Adapters execute approved packages only.
- Audit Log records security-relevant events locally and encrypted by default.

## Runtime Layers

```text
Identity Layer
  Identity Root
  Device Vault
  Trust Manager

Decision Layer
  Authorization Engine
  Security Policy Engine
  Proof System
  Recovery Manager

Execution Layer
  Applications Layer
  PhilCore Runtime API
  Adapter Layer
  Ethereum Net
  Ethereum Adapter
  Base profile/config
```

Ethereum/Base belongs in the Execution Layer, not the Identity Layer.

## Ethereum-First Path

Ethereum Net is the first user-facing execution application.

Ethereum Adapter is the first internal execution adapter. Base remains a profile/config under Ethereum Adapter unless future complexity justifies a separate Base Adapter.

PhilCore's preferred Ethereum authority model is ERC-4337 Account Abstraction using PhilCore-controlled Smart Accounts.

The Desktop Alpha previously composed this path through local STWO proof generation and ERC-4337 fixture execution. That product route is now stopped at proof generation: the current proof exposes its witness, so ordinary generation and Device Vault providers are rejected and the artifact cannot be finalized or passed to publication or execution preparation. Only explicit process-local synthetic research generation and local verification remain.

EOAs are compatibility paths. Existing MetaMask or other EOAs may connect, be monitored, fund PhilCore accounts, migrate assets, and participate in interoperability. PhilCore cannot become mandatory final authority over an ordinary EOA while that EOA's private key remains its controlling signer.

## Current V2 Account Security Model

`PhilCoreV2MinimalAccountV2` is the current narrow ERC-4337 account model.
Its authority surface is a fixed set of typed actions; it intentionally
forbids generic execution, delegatecall, batching, approvals, modules,
session keys, proxy upgrades, and paymaster extensibility. V1 and N-series
accounts remain separate legacy/compatibility or historical scopes and do not
override V2 semantics.

Recovery uses fixed primary-device, hardware-security-key, and independent
roles with exact 2-of-3 factor bitmaps `3`, `5`, and `6`. The execution
validator never counts toward the recovery threshold and cannot veto a valid
validator-recovery quorum. The security model assumes independent custody and
failure separation of the three roles. Credential metadata and native policy
can restrict synchronized credentials where observable, but cryptography alone
cannot establish real-world custody independence.

Authoritative detail:

- [V2 Minimal Account Implementation Report](./docs/reference/O37_10_V2_MINIMAL_ACCOUNT_IMPLEMENTATION_REPORT.md)
- [V2 Recovery And Cancellation Semantics](./docs/reference/O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md)
- [V2 Recovery Lifecycle Update](./docs/reference/O37_1_RECOVERY_LIFECYCLE_UPDATE.md)
- [V2 Formal Threat Model](./docs/security/O30_V2_FORMAL_THREAT_MODEL.md)

## Locked Compatibility Surfaces

These surfaces remain byte stable for current tests and migration analysis,
but cannot create new V1 product authority:

- `phil_secret -> identityRoot -> ownerCommitment`
- `ACTION_UNLOCK`
- proof public input tuple
- `proofInputHash`
- `proofType = "stwo-unlock-keccak-v1"`
- `[fact_high, fact_low]`
- Base tuple semantics for current unlock authorization
- WebAuthn/passkey architecture
- encrypted registry/key lifecycle architecture
- current STARK/proof work

## Current Implementation Map

- `apps/phil-device-sdk/src/identity.ts`: Phil identity root helpers.
- `apps/phil-device-sdk/src/deviceIdentity*.ts`: device identity, WebAuthn/passkey, Trust Manager-adjacent credential lifecycle, encrypted storage, IndexedDB/WebCrypto storage, and key lifecycle.
- `apps/phil-device-sdk/src/authorization.ts`: current authorization assembly helpers.
- `apps/phil-device-sdk/src/proof/*`: proof public-input and STWO schema helpers.
- `contracts/base/*`: Base-side authorization, mirror, verifier, gate, and consumer contracts.
- `contracts/l1/*`: L1 trust anchor and L1/Base messenger contracts.
- `proving/src/*`: Rust proof core for the locked `ACTION_UNLOCK` statement.
- `scripts/base/*`: Ethereum/Base local artifact builders, local runners, bundler stub, and smart-account deploy/session drills.
- `starknet_*`, `cairo_air_adapter_spike/`, `merkle_parity_spike/`: active proof/Starknet/Cairo research.

## Security Posture

PhilCore is not production-ready security software yet. It has strong local-first foundations, but still requires production platform key management, real hardware/mobile integrations, recovery hardening, external review, and audited deployments before production use.

PhilCore does not claim full post-quantum security. STARK/proof work supports a post-quantum-oriented authorization direction, but current WebAuthn and Ethereum/Base execution depend on non-post-quantum primitives.

## Historical Documentation

Older internal phase reports, decision logs, and master reports are excluded
from the public candidate. They do not supersede the accepted architecture
documents listed above.
