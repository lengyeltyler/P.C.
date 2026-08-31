# PhilCore Status

PhilCore is a local-first implementation baseline for a Personal Security Operating System.

The accepted source of truth is:

- [PhilCore Core Boundary](./docs/PHILCORE_CORE_BOUNDARY.md)
- [PhilCore Runtime Lifecycle](./docs/PHILCORE_RUNTIME_LIFECYCLE.md)
- [PhilCore Functional Specification v1](./docs/PHILCORE_FUNCTIONAL_SPEC_V1.md)
- [PhilCore Technical Specification v1](./docs/PHILCORE_TECHNICAL_SPEC_V1.md)
- [Phil V1 Secure Identity Architecture](./docs/PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md)
- [Canonical Documentation](./docs/CANONICAL_DOCS.md)

## Current Product Frame

PhilCore is device-first. The identity invariant is:

```text
phil_secret -> identityRoot -> rootOwnerCommitment
```

Applications create intents. The PhilCore Runtime API evaluates intents. Trust Manager evaluates trusted credentials/devices. Security Policy Engine and Authorization Engine gate sensitive actions. Adapters execute approved packages.

Ethereum Net is the first user-facing execution application. Ethereum Adapter is the first execution adapter. ERC-4337 Smart Accounts are the preferred Ethereum authority model. EOAs are compatibility paths.

The current narrow account implementation is `PhilCoreV2MinimalAccountV2`.
V2 permits only its reviewed typed action surface and forbids generic wallet
execution and unsafe extensibility. Its recovery model uses three fixed,
independently custodied roles with exact 2-of-3 authority; the execution
validator is not a recovery factor and cannot veto a valid recovery quorum.
See the [V2 implementation report](./docs/reference/O37_10_V2_MINIMAL_ACCOUNT_IMPLEMENTATION_REPORT.md)
and [V2 formal threat model](./docs/security/O30_V2_FORMAL_THREAT_MODEL.md).
V1 and N-series account material remains separate legacy/compatibility or
historical scope.

## Implemented And Working Locally

- Locked Phil identity derivation:
  - `phil_secret -> identityRoot -> ownerCommitment`
- Locked `ACTION_UNLOCK` proof relation. Its current STWO artifact is not
  witness hiding, is not a privacy-preserving `phil_secret` PoK, and is
  quarantined to explicit local synthetic research.
- Selected local Alpha Noir/Barretenberg UltraKeccakZK root-proof route with
  exact tool hashes, descriptor/key binding, named-pipe-only prover input and
  witness transport, real proof generation, and repeated native verification.
- `proofType = "stwo-unlock-keccak-v1"` proof-family wiring.
- Canonical `proofInputHash` derivation and fixture parity.
- Two-felt `[fact_high, fact_low]` fact encoding.
- TypeScript SDK helpers for identity, commitments, hashes, nullifiers, authorization, proof inputs, and execution payload assembly.
- Phil Device Identity v1 provider abstraction with non-exportable private-material behavior.
- Local deterministic test provider.
- Browser-mediated WebAuthn/passkey provider path with ES256/P-256 registration/assertion verification.
- Explicit WebAuthn attestation policy.
- Trust Manager-adjacent credential lifecycle registry with active, pending, revoked, recovery-only, and archived credential states.
- Credential rotation overlap, anti-lockout warnings, and immutable-style local audit events.
- Encrypted local registry storage with AES-256-GCM, owner-bound associated data, file/in-memory backends, and encrypted backup import/export.
- Browser IndexedDB/WebCrypto encrypted registry storage.
- Storage-key and backup-key lifecycle framework with key-version statuses and rollback-on-failure behavior.
- Local Device Identity end-to-end demo with mocked WebAuthn automation, encrypted registry persistence/reload, digest authorization, and local-device-signed session matrix.
- Base authorization hashing and verifier interfaces.
- Base mirrored fact verifier path.
- Base action gate and mint-pass consumer path.
- L1 trust anchor and L1/Base mirror contracts.
- Local onboarding, mint-intent, wallet input, wallet artifact, smart-account target/init/deploy artifact chain.
- Smart-account deploy UserOperation, userOp hash, signature request, signed userOp, and downstream no-send submission artifacts.
- Local bundler stub with accepted, rejected, and transport-error modes.
- Local response matrix, submission drill, drill matrix, deploy-session runner, and local-device-signed session matrix.
- Local fixture regeneration command: `npm run generate:local-fixtures`.

## Implemented But Only Locally Proven

- Desktop Alpha product journey with user-facing Home, Identity, Trust, Recovery, Ethereum, Activity, Settings, and separated Developer mode.
- The normal protected local action generates and verifies a real Noir private
  proof, requests a separate signing approval and fresh Mac presence, and then
  completes one bounded local ERC-4337 fixture action. Nothing is submitted
  publicly and no real funds are used.
- The shipped local Alpha UI and preload cannot invoke the historical
  Sepolia/STWO preparation channels. Real Desktop composition requires native
  Mac user presence, and the bounded operation nullifier is reserved and
  durably recorded before and after local execution.
- The local identity artwork generator is the pinned owner-controlled
  Philenator revision `f174dedda16a354c592e3252d9b0b5805bab59c4`; its full
  color is retained while product chrome remains black and white.
- Local Alpha QA checklist for normal protected-action release-candidate rehearsal, including interruption, accessibility, Activity, package, and no-public-network checks.
- Renderer presentation layer that translates internal Runtime/proof/ERC-4337 states into plain-language labels while preserving raw values under technical details.
- Starknet -> L1 -> Base proof/fact relay model.
- L1 trust-anchor recording.
- L1 -> Base mirror boundary.
- Base-local mirrored fact state.
- Local smart-account deploy-session matrix.
- Local-device-signed deploy-session matrix.
- Deterministic local dev signing key flow.
- WebAuthn/passkey provider with mocked browser tests rather than production platform ceremonies.
- Encrypted registry storage and key lifecycle as local-first scaffolding rather than production vault/keychain integration.
- Device Identity demo flow with mocked WebAuthn calls and local no-send bundler outcomes.
- Native iPhone companion with Secure Enclave-backed, ThisDeviceOnly device
  approval and recovery-key behavior proven in bounded local physical tests;
  this is not production admission or distribution.

These are useful and real local flows, but they are not production deployments.

## Not Yet Externally Proven

- Production-approved and externally audited privacy-preserving proof of
  knowledge of `phil_secret`. The local Alpha route is functioning, but Noir is
  beta, Barretenberg is a compatibility-pinned nightly, and no public verifier
  deployment has been authorized.
- Production PhilCore Runtime API.
- Production Applications Layer.
- Production Ethereum Net application.
- Production Ethereum Adapter submission path.
- Public Starknet verifier deployment that verifies Phil's exact locked proof family end to end.
- Live L1 trust anchor and Base mirror deployment with public chain transactions.
- Production bundler integration.
- Receipt handling, paymaster logic, retry logic, and polling.
- Full production mint execution.
- Trusted attestation-root validation for WebAuthn direct attestation.
- Production-wide platform key management, broad device admission, recovery
  operations, signed distribution, and external mobile/storage audit beyond
  the currently bounded iPhone 17/iOS 26.6 local evidence envelope.
- Non-ES256 WebAuthn registration/assertion algorithms.
- External proof of the iPhone companion across additional devices, OS
  versions, interruption/resource envelopes, and production release channels.
- Social recovery committees, hardware recovery ceremonies, and externally reviewed credential-loss procedures.
- Formal audit or external security review.
- Long-running service operations, monitoring, and incident response.

## Known Publication Baseline Choices

- Generated artifacts under `proving/out/` are local outputs and are ignored.
- Chain/build outputs such as `artifacts/`, `cache/`, and Cairo/Rust `target/` directories are ignored.
- Source, scripts, tests, fixtures, current source-of-truth docs, and historical research docs are kept as the baseline.
- Example vectors and deterministic test values are not production secrets.
- Historical phase reports and decision logs are preserved for context but are not current source of truth.

## Local Validation

Useful checks:

```bash
npm run generate:local-fixtures
npm run test:unit
npm run test:proving
npm run typecheck
npm run demo:device-identity
npm run --silent run:local-device-signing-session-matrix-integration
```

`npm run test` runs unit and proving tests together.

## Current Technical Debt

- Root docs have now been reframed, but some historical archive documents still use older Base/proof/wallet-first language.
- Historical phase reports, master reports, research work logs, and decision
  logs are excluded from the public candidate.
- `docs/CANONICAL_DOCS.md` is the public documentation index.
- Runtime API, Intent, Capability, User Session, Application Manifest, Adapter Manifest, Audit Event, and Assurance Level foundations are implemented for local/runtime-boundary use; production service operation and public-network execution remain incomplete.
- Production platform vault/keychain integration is not implemented.
- Production recovery ceremony is not implemented.
- Production Ethereum/Base submission path is not implemented.
- The current `ACTION_UNLOCK` STWO artifact is structurally quarantined because
  queried trace openings recover `phil_secret`. Only explicit local synthetic
  research generation and local verification remain; ordinary generation,
  Device Vault witness use, finalization, publication, and execution preparation
  reject the artifact.

## Recommended Next Implementation Milestone

The six-step local architecture/composition route and the bounded physical
iPhone routine-authorization test are complete. The current gate is:

```text
LOCAL ALPHA: reconcile the Desktop and iPhone presentation, freeze the exact
package/source candidate, independently review it, and run the public-source
release-readiness gate without publishing.
```

The evidence and six-step sequence are recorded in the
[Phil V1 Architecture Feasibility Gate](./docs/reference/PHIL_V1_ARCHITECTURE_FEASIBILITY_GATE.md)
and
[ACP-0003](./docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md).

Step 1 accepted the private stable root, scoped public identities, encrypted
user-controlled data, independent device approval, exceptional root proofs,
routine revocable capabilities, identity/data recovery, network adapters, and
algorithm agility while leaving the production proof backend unselected.

Step 2 now has local scoped-identity/data encryption, authenticated continuity
recovery, exact `2-of-3` package-key unwrapping, recovery lifecycle controls,
device-approval binding, and Secure Enclave production source. Targeted tests,
Simulator/generic-iOS builds, and a bounded iPhone 17/iOS 26.6 ceremony pass.
The exact disposable key was deleted and proven absent.

Steps 1-6 are complete as bounded local gates. The exact Step 6C physical test
completed one enrolled-iPhone approval and verified the harmless local receipt;
both sides then removed their disposable routine key material. This does not
authorize production secrets, meaningful assets, external signers, publishing,
deployment, RPC mutation, or any public network.
