# Security

PhilCore is a Personal Security Operating System, but this repository is not production-ready security software yet. Treat it as a research and local-first implementation baseline until contracts, proof paths, signing flows, recovery flows, storage paths, and deployment procedures receive external review.

Current architecture source of truth:

- [PhilCore Core Boundary](./docs/PHILCORE_CORE_BOUNDARY.md)
- [PhilCore Runtime Lifecycle](./docs/PHILCORE_RUNTIME_LIFECYCLE.md)
- [PhilCore Functional Specification v1](./docs/PHILCORE_FUNCTIONAL_SPEC_V1.md)
- [PhilCore Technical Specification v1](./docs/PHILCORE_TECHNICAL_SPEC_V1.md)
- [Phil V1 Secure Identity Architecture](./docs/PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md)

The evidence-backed replacement direction for the quarantined proof route is
documented in the
[Phil V1 Architecture Feasibility Gate](./docs/reference/PHIL_V1_ARCHITECTURE_FEASIBILITY_GATE.md)
and accepted
[ACP-0003 roadmap](./docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md).
Step 1 is complete. It selected no production proof backend and authorized no
runtime, contract, schema, device, signing, deployment, or network activity.

The separately authorized Step 2 local candidate is documented in the
[implementation report](./docs/reference/PHIL_V1_STEP2_DEVICE_RECOVERY_IMPLEMENTATION_REPORT.md)
and
[device/recovery threat model](./docs/security/PHIL_V1_STEP2_DEVICE_RECOVERY_THREAT_MODEL.md).
It is not production approved: physical Secure Enclave behavior and independent
review remain missing, so Step 3 is blocked.

## Current Security Posture

Accepted target security surfaces:

- protected private root plus pairwise scoped public commitments
- separate identity/data recovery and account recovery
- replaceable hardware-backed device approval
- routine scoped capabilities and exceptional witness-hiding root proofs
- one chain-agnostic authorization envelope
- isolated, capability-declaring network/protocol adapters
- immutable algorithm and verifier suite identifiers

Locked compatibility surfaces:

- `phil_secret -> identityRoot -> ownerCommitment`
- `ACTION_UNLOCK`
- `proofType = "stwo-unlock-keccak-v1"`
- verified `proofInputHash`
- `[fact_high, fact_low]`
- Base tuple semantics
- Ethereum/Base as the first execution path, not the identity layer
- ERC-4337 Smart Accounts as the preferred Ethereum authority model
- EOAs as compatibility paths

Current local-first limitations:

- no audited production deployment
- no production key-management system
- no production-approved hardware signer, passkey, Secure Enclave, or mobile recovery integration; native iOS source and one narrow historical physical-device disposable-key observation exist, but current end-to-end recovery is not physically validated
- no trusted WebAuthn attestation-root validation, production key-management system for credential registry storage, or production recovery enforcement
- no public external bundler flow in the local drills
- no production incident-response process

## Secrets Policy

Do not commit real secrets. This includes:

- private keys
- mnemonics
- Phil secrets
- RPC credentials
- API tokens
- production deployment addresses that imply private operational context

Use `.env` locally. Keep `.env.example` placeholder-only.

## Local Dev Signing

The local device-signing runner is for local development only. Any deterministic local dev key or locally generated signature in docs/artifacts must be treated as test material, never as a production signing key.

Phil Device Identity v1 marks the local deterministic provider as not production safe. Its provider API refuses private-material export, but that does not make the deterministic local key secure. It is only a CI/dev fallback that preserves the current local-device-signed matrix.

The WebAuthn/passkey provider is a browser-mediated provider path. It can call browser WebAuthn APIs and now verifies ES256/P-256 registration and assertion structures. Registration verification covers the PhilCore registration challenge, origin, rpIdHash, user-presence/user-verification flags, attested credential data, credential ID, COSE public-key extraction, algorithm allowlist, initial sign counter, transports, and explicit attestation policy. Assertion verification covers the PhilCore-derived challenge, origin, rpIdHash, user-presence/user-verification flags, signature, and counter behavior.

This is still not a complete production WebAuthn system. Attestation policy defaults to `none`, which accepts registration without trusted attestation-chain validation. `permissive` parses metadata but does not validate trusted roots. `direct` is scaffolded and fails until trusted root validation is implemented. PhilCore must not claim verified hardware provenance from these modes today.

Non-ES256 algorithms, phishing-resistant UX, production recovery enforcement, incident response, and external review remain required.

WebAuthn credentials authorize Phil identity actions. They are not the Phil identity root and must not permanently replace `phil_secret -> identityRoot -> ownerCommitment`.

Phil Device Identity v1.3 adds a local credential lifecycle registry. It supports multiple active credentials, explicit destructive confirmations, anti-lockout warnings, rotation overlap, recovery states, and immutable-style audit events. Phil Device Identity v1.5 persists that registry in encrypted local storage with AES-256-GCM, owner-bound associated data, and fail-closed tamper detection. Phil Device Identity v1.6 adds browser-oriented IndexedDB/WebCrypto encrypted storage. Phil Device Identity v1.7 adds local storage-key and backup-key lifecycle metadata, rollback-protected rotation, active/retiring/retired/revoked key statuses, and rotation audit events. This improves local modeling, but it is not a production recovery system or production vault.

The storage layers do not store `phil_secret`, authenticator private keys, raw recovery secrets, private Ethereum keys, or mnemonics. They store public credential metadata, recovery state, and audit events inside encrypted envelopes. The Node local dev passphrase key provider uses scrypt and the browser local passphrase key provider uses WebCrypto PBKDF2/SHA-256; both are explicitly unsafe for production. Browser storage uses IndexedDB for encrypted blobs and WebCrypto for AES-GCM, but IndexedDB is not invulnerable and should not be described as a production vault. Production storage still needs platform keychain or secure hardware key management, mobile storage providers, backup availability policy, reviewed key ceremonies, and external review.

The v1.8 Device Identity demo runner is a local composition proof, not a production ceremony. It uses mocked WebAuthn browser calls so command-line validation can run without UI or hardware, but it still runs the real registration verifier, assertion verifier, encrypted registry save/load path, and local-device-signed session matrix. Its output artifact is intentionally limited to safe public metadata and summary booleans, and the runner rejects obvious secret-bearing field names in the JSON result. The encrypted demo registry under `proving/out/` is generated local output and remains ignored by git.

Recovery is stronger than ordinary sign-in. The local SDK policy requires a stronger-than-ordinary authorization flag for recovery start, approval, and completion. Production recovery still needs concrete hardware/browser checks, notification and delay policy, replay-resistant audit persistence, user education, incident response, and external review. Social recovery committees are intentionally not implemented in this pass.

## Desktop Protected Actions

The normal Desktop Alpha protected action is a presentation layer over the existing Runtime authorization path. The renderer can start the fixed local action and display Runtime-projected state, but it cannot create approval grants, choose arbitrary targets, access signing keys, pass proof witnesses, or submit public-network mutations. Approval is digest-bound, one-time, expires, and is invalidated by lock/restart when it cannot be proven current. Rejection, cancellation, user-presence failure, proof failure, signing failure, or local execution failure stops before later authority is used.

Desktop Secure Enclave/platform-authenticator providers remain
production-oriented scaffolds. Separately, the native iOS companion contains
real Security.framework key-generation and recovery-signing source. One
historical physical-device disposable-key test observed Secure Enclave
classification, non-exportability, and deletion at an older source baseline.
The current recovery integration has not received complete simulator or
physical-device validation, no production recovery credential was created,
and neither a public key nor an on-chain descriptor proves Apple hardware
origin. See [Secure Enclave Validation Status](./docs/security/SECURE_ENCLAVE_VALIDATION_STATUS.md).

The current dependency-advisory source of truth and the historical-report
boundary are documented in
[Dependency Advisory Status](./docs/security/DEPENDENCY_ADVISORY_STATUS.md).

Generated local artifacts under `proving/out/` are ignored by git.

## Reporting Issues

**PRIVATE VULNERABILITY REPORTING: ENABLED**

Report suspected vulnerabilities confidentially through
[GitHub Security — Report a vulnerability](https://github.com/lengyeltyler/PhilCore/security/advisories/new).
Private Vulnerability Reporting was enabled and verified on 2026-08-31.
Do not disclose exploit details in public issues, discussions, pull requests,
commits, or social channels. This availability check did not submit a test report
and does not imply a response-time guarantee or a professional security audit.
