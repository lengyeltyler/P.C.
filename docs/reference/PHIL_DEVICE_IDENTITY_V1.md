# Phil Device Identity v1

Status: Current device-provider compatibility implementation. The accepted V1
device role is a replaceable hardware-backed approval factor defined in
[Phil V1 Secure Identity Architecture](../PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md).
It is never the Phil identity or identity/data recovery authority.

Phil Device Identity v1 is the local identity boundary for authorizing Phil smart-account execution without exposing the Phil secret.

It does not replace the locked Phil identity model:

```text
phil_secret -> identityRoot -> ownerCommitment
```

The Phil secret remains private root material. `identityRoot` and
`ownerCommitment` are also protected by default under the accepted
architecture. New public app and network relationships use
`scopedOwnerCommitment` plus the minimum scoped device key identifiers,
credential identifiers, and authorization signatures they require. Existing
SDK public-root fields are compatibility surfaces, not a universal Phil ID.

## What It Separates

The SDK modules at `apps/phil-device-sdk/src/deviceIdentity.ts`, `apps/phil-device-sdk/src/deviceIdentityWebAuthn.ts`, `apps/phil-device-sdk/src/deviceIdentityLifecycle.ts`, and `apps/phil-device-sdk/src/deviceIdentityStorage.ts` separate:

- identity derivation
- device key storage
- authorization digest signing
- proof authorization payload handling
- exportable public identity metadata
- non-exportable Phil secret and private key handling
- credential lifecycle, rotation, recovery state, and local audit records
- WebAuthn registration verification and attestation policy
- encrypted local registry persistence and backup/import/export

Provider objects expose `getPublicMetadata()`, `authorizeDigest(...)`, and `exportPrivateMaterial()`. The export method always throws. Normal app code should not need raw `phil_secret` or raw private key bytes after initialization.

## Phil Identity vs Ethereum Wallet Identity

Phil identity is rooted in `phil_secret` and produces an `ownerCommitment` for proof-gated authorization.

WebAuthn credentials are not the Phil root identity. A passkey authorizes or controls Phil identity actions; it must remain rotatable and recoverable, and it should not permanently replace or define `phil_secret -> identityRoot -> ownerCommitment`.

Ethereum wallets and smart accounts are execution accounts. They can submit transactions, pay gas, and hold chain assets, but they are not the root Phil identity. MetaMask or EOA signers can be supported for compatibility, and smart accounts can be authorized by Phil, but Phil identity should not be reduced to an Ethereum EOA.

This distinction lets PhilCore aim toward a portable cryptographic identity substrate that can authorize execution across changing chains and account systems.

## Credential Lifecycle v1.3

Phil Device Identity v1.3 adds a local-first credential registry model. One Phil identity may have many credentials at the same time:

- Mac passkey
- iPhone passkey
- hardware security key
- local dev credential
- future Secure Enclave or mobile secure-hardware credential

The registry records credential metadata:

- `credentialId`
- `providerKind`
- `algorithm`
- `label`
- `createdAt`
- `lastUsedAt`
- `status`
- `signCount`
- `deviceType`
- transport and authenticator attachment information
- `priority`

Supported credential statuses are:

- `active`
- `pending`
- `revoked`
- `recovery-only`
- `archived`

Ordinary Phil identity actions may be authorized by any `active` credential. Revoked, archived, pending, and recovery-only credentials cannot authorize ordinary actions. Recovery-only credentials are reserved for the stronger recovery path.

Credential management actions are typed in the SDK:

- `addCredential`
- `revokeCredential`
- `archiveCredential`
- `rotateCredential`
- `renameCredential`
- `listCredentials`

The exported authorization requirements document the local policy for each action. Destructive actions require explicit confirmation. Revoking or archiving the final active credential emits anti-lockout warnings instead of silently pretending the identity remains usable.

## Rotation

Rotation is modeled as overlap, not destruction:

```text
old credential
-> authorize rotation
-> register new credential
-> activate new credential
-> optionally archive old credential
```

The old credential is not automatically destroyed. This is deliberate: users may need both credentials active during migration, browser sync, hardware replacement, or recovery testing.

Rotation preserves Phil identity continuity because the identity remains `phil_secret -> identityRoot -> ownerCommitment`; only the authorizing credential set changes.

## Recovery

The recovery model is framework-first and local today. Supported recovery states are:

- `normal`
- `recovery-pending`
- `recovery-approved`
- `recovery-completed`

Supported mechanism labels are:

- `secondary-active-credential`
- `recovery-credential`
- `future-recovery-committee`
- `future-hardware-recovery-path`

Social recovery committees are not implemented in this pass. The interface leaves room for that later without changing the Phil identity root or proof/fact semantics.

Recovery is intentionally stronger than ordinary authentication. Starting, approving, and completing recovery require `strongerThanOrdinaryAuthentication` in the local policy. Future production work should replace that local assertion with concrete multi-step verification, delay policies, notification rules, hardware checks, and external review.

## Audit Trail

The registry emits immutable-style local audit events for:

- credential added
- credential renamed
- credential revoked
- credential archived
- credential rotated
- credential used
- recovery started
- recovery approved
- recovery completed

The audit model is local-first. It is useful for SDK state transitions and tests, but it is not yet a tamper-proof replicated log or on-chain governance record.

## Encrypted Local Registry Storage v1.5

Phil Device Identity v1.5 adds a durable encrypted local registry storage baseline. The storage layer persists the credential registry snapshot, lifecycle state, recovery state, and audit trail without storing Phil secrets or private authenticator material.

The plaintext registry format is versioned:

- `format: "phil-device-identity-registry"`
- `version: 1`
- `ownerCommitment`
- `identityRootHash`
- `createdAt`
- `updatedAt`
- `credentials[]`
- `recoveryState`
- `auditEvents[]`
- `storageMetadata`

The encrypted envelope is also versioned:

- `format: "phil-device-identity-registry-encrypted"`
- `version: 1`
- `encryption.algorithm: "aes-256-gcm"`
- random 16-byte salt for passphrase-derived keys
- random 12-byte IV per encryption
- GCM authentication tag
- associated data bound to registry format, version, and owner commitment
- ciphertext

The storage layer rejects missing registries, corrupted JSON envelopes, unsupported versions, owner-commitment mismatches, identity-root hash mismatches, tampered ciphertext, invalid authentication tags, wrong passphrases/keys, invalid plaintext structure, and forbidden secret-bearing field names.

Key providers are explicit:

- `local-dev-passphrase-scrypt-device-registry-key-test-only-v1`: derives AES-256 keys with scrypt. Default local parameters are `N=32768`, `r=8`, `p=1`, `keyLength=32`. This provider is clearly marked unsafe for production.
- `injected-raw-aes256-device-registry-key-v1`: accepts injected 32-byte key material.
- future platform keychain provider scaffold.
- future Secure Enclave key provider scaffold.

The current file storage backend writes an encrypted JSON blob for Node/local development. The in-memory backend is for tests. Browser IndexedDB storage is added in v1.6. Mobile secure storage, OS keychain integration, and production backup key custody remain future provider boundaries.

Backups are encrypted blobs. Import validates format, version, owner reference, and AEAD integrity, preserves audit history, and refuses to overwrite an existing registry unless `replaceExisting: true` is provided.

Storage-specific audit events include:

- registry created
- registry loaded
- registry saved
- registry migrated
- registry exported
- registry imported
- registry load failed
- registry tamper detected

Successful storage events are persisted inside the encrypted registry audit trail. Failed-load and tamper-detected events are emitted to a volatile local storage-audit buffer because the encrypted registry cannot be safely modified when it cannot be authenticated.

This is not yet a production vault. It is a local-first encrypted-at-rest baseline with documented key-management assumptions.

## Browser IndexedDB Storage v1.6

Phil Device Identity v1.6 adds a browser-oriented encrypted storage boundary in `apps/phil-device-sdk/src/deviceIdentityIndexedDbStorage.ts`.

The IndexedDB model is:

- database: `phil_device_identity`
- object store: `registries`
- object store: `registry_metadata`

Each registry record is keyed by `ownerCommitment`, so one browser profile can store encrypted registry blobs for multiple Phil identities. The `registries` store contains only encrypted registry blobs and update timestamps. The `registry_metadata` store contains minimal metadata: owner commitment, encrypted format, version, encrypted flag, and update timestamp. The provider does not persist plaintext registry records or credential labels in IndexedDB.

The browser storage layer uses WebCrypto:

- AES-GCM with 256-bit keys
- random 12-byte IV per encryption
- GCM authentication tag
- associated data bound to registry format, version, and owner commitment
- SHA-256 through `crypto.subtle.digest`
- PBKDF2/SHA-256 browser passphrase key derivation for local/dev browser flows

Browser key providers are explicit:

- `browser-passphrase-pbkdf2-device-registry-key-local-v1`: local/dev passphrase provider using PBKDF2/SHA-256. It is marked unsafe for production.
- `browser-injected-raw-aes256-device-registry-key-v1`: imports injected 32-byte AES key material into non-exportable WebCrypto keys.
- future browser platform-keychain provider scaffold.
- future browser Secure Enclave provider scaffold.
- future mobile secure-storage provider scaffold.

Unsupported environments fail clearly. The browser storage path requires IndexedDB plus WebCrypto `crypto.subtle` and `getRandomValues`. It does not silently downgrade to plaintext `localStorage`.

Browser backup export/import uses encrypted blobs. Import validates integrity, owner binding, and registry version, preserves audit history, and refuses overwrite unless replacement is explicit.

This remains an unaudited local-first browser storage layer. IndexedDB is not a production vault by itself; production work still needs platform key management, browser/mobile key lifecycle integration, backup availability policy, phishing-resistant UX, and external review.

## Storage-Key And Backup-Key Lifecycle v1.7

Phil Device Identity v1.7 adds a local-first key lifecycle framework in `apps/phil-device-sdk/src/deviceIdentityKeyLifecycle.ts`. This layer protects the encrypted credential registry; it does not alter Phil identity derivation, credential authorization, `ACTION_UNLOCK`, proof semantics, `proofInputHash`, fact encoding, or Base tuple semantics.

Storage and backup key metadata is versioned. Key versions may be:

- `active`: the current preferred key for writes.
- `retiring`: an older overlapping key that may still load data during migration windows.
- `retired`: no longer accepted for default loads.
- `revoked`: explicitly distrusted and rejected by default.

The rotation flow is fail-closed:

1. Load and authenticate the current encrypted registry with the active key.
2. Add rotation-started audit context.
3. Re-encrypt the preserved registry snapshot with the next key.
4. Write lifecycle envelope metadata such as `keyVersion`, `encryptionAlgorithm`, `createdAt`, `updatedAt`, and `migrationVersion`.
5. Verify the new encryption can be loaded before completing.
6. Mark the old key `retiring` and the new key `active`.
7. Advance the local lifecycle `migrationVersion`, so a stale pre-rotation blob cannot be replayed against the post-rotation lifecycle.

If re-encryption, writing, or verification fails, the original encrypted blob is restored. The old key is not destroyed automatically. Retired and revoked keys fail before decrypt by default.

Multi-version loading accepts `active` and `retiring` keys only. When lifecycle metadata is present in the encrypted envelope, the loader uses the declared `keyVersion` and rejects mismatches. Legacy blobs without lifecycle metadata remain loadable only while the local lifecycle is still at its initial migration version.

Backup-key rotation follows the same local-first pattern for encrypted backup blobs. It re-encrypts the backup with a new backup key, adds `backupLifecycle` metadata, verifies importability with the new key, and preserves registry audit history. Backup key rotation does not become an identity recovery ceremony by itself.

Storage-key audit event types now include:

- storage-key created
- storage-key rotation started
- storage-key rotation completed
- storage-key rotation failed
- storage-key retired
- storage-key revoked

The current implementation is intentionally local-first. Production work still needs OS keychain or secure hardware custody, user notification and delay rules, backup availability checks, externally reviewed recovery procedures, and mobile provider integration.

## v1.8 Local End-To-End Demo

Phil Device Identity v1.8 adds `scripts/base/run-phil-device-identity-demo.cjs`, exposed as:

```bash
npm run generate:local-fixtures
npm run demo:device-identity
```

The demo writes:

```text
proving/out/phil_device_identity_demo/phil_device_identity_demo_result.json
```

It proves the v1 pieces compose locally: create a Phil identity, register a mocked WebAuthn passkey, verify registration, add the credential to the lifecycle registry, persist and reload the encrypted registry, produce and verify a WebAuthn assertion over the PhilCore signable digest, authorize that digest, and run the existing local-device-signing deploy-session matrix.

Real in this demo:

- Phil identity derivation and owner commitment calculation
- WebAuthn registration verifier logic
- WebAuthn assertion verifier logic
- ES256/P-256 signature verification
- challenge binding to the PhilCore signable digest
- credential lifecycle add/audit behavior
- AES-256-GCM encrypted registry persistence and reload
- existing local deploy/session matrix compatibility

Mocked in this demo:

- browser `navigator.credentials.create()` and `navigator.credentials.get()`
- the platform authenticator/passkey hardware boundary
- local-only storage key custody
- local no-send bundler outcomes

The output artifact intentionally includes only safe public metadata and summary booleans. It excludes Phil secrets, private signing material, mnemonics, raw recovery material, authenticator private material, and storage encryption material. The runner scans its own JSON output and fails if obvious secret-bearing field names appear.

## Providers

Implemented now:

- local deterministic dev provider: `local-dev-deterministic-device-identity-test-only-v1`
- WebAuthn/passkey provider: `webauthn-passkey-device-identity-v1`

Scaffolded now:

- Secure Enclave/platform authenticator provider
- future mobile secure hardware provider

The WebAuthn provider is a browser-mediated passkey provider path. It builds W3C-style `PublicKeyCredentialCreationOptions` and `PublicKeyCredentialRequestOptions`, uses `navigator.credentials.create()` for registration, uses `navigator.credentials.get()` for assertions, and derives assertion challenges from the PhilCore signable digest. Node tests use a mock `navigator.credentials` implementation.

Registration challenges are tied to PhilCore registration intent. The default registration challenge is derived from the Phil identity owner commitment, and callers may supply an explicit PhilCore registration-intent digest. Registration should not use arbitrary disconnected strings as authority.

The v1.4 registration verifier checks:

- `clientDataJSON.type === "webauthn.create"`
- challenge equals the expected PhilCore registration challenge
- origin equals the configured relying-party origin
- cross-origin registrations are rejected unless explicitly allowed
- `authenticatorData.rpIdHash === SHA-256(rpId)`
- user presence flag is set
- user verification flag is set when `userVerification = "required"`
- attested credential data is present
- credential ID matches the returned raw credential ID
- ES256/P-256 COSE public key is extracted and normalized to SPKI
- initial sign counter is captured
- transports are carried into safe public metadata

Supported registration algorithm today: ES256/P-256 only, COSE `EC2` key type, curve `P-256`, algorithm `-7`. The browser creation options advertise only ES256 so browsers do not select algorithms this verifier cannot check.

Attestation policy is explicit:

- `none`: default; parse registration data and accept without requiring trusted attestation-chain validation.
- `permissive`: parse attestation metadata and warn that trusted roots are not validated.
- `direct`: scaffolded policy mode; currently fails because trusted attestation-root validation is not implemented.

PhilCore does not currently claim verified authenticator hardware provenance, audited attestation trust roots, or production-ready authenticator trust decisions.

The WebAuthn assertion verifier now checks:

- `clientDataJSON.type === "webauthn.get"`
- challenge equals the PhilCore-derived signable digest challenge
- origin equals the configured relying-party origin
- cross-origin assertions are rejected
- `authenticatorData.rpIdHash === SHA-256(rpId)`
- user presence flag is set
- user verification flag is set when `userVerification = "required"`
- ES256/P-256 assertion signature over `authenticatorData || SHA-256(clientDataJSON)` using the stored SPKI public key
- sign counter advance, zero-counter warning, rollback failure, and clone-suspected failure

Supported assertion signature algorithm today: ES256/P-256 with the SPKI public key captured by the registration verifier. COSE public-key parsing is implemented for the ES256 registration key path only. Non-ES256 registration and assertion algorithms are not implemented yet.

The remaining scaffolded hardware providers return public metadata and fail authorization with explicit unsupported-platform errors until real OS/browser/mobile integration is added. They do not fake production security.

## Current Smart-Account Binding

The local signing runner still consumes the existing smart-account deploy signature request:

```text
smartAccountDeploySignatureRequest.signerPayload.signableDigest
```

`scripts/base/run-local-smart-account-deploy-signing.cjs` now authorizes that same digest through the local Device Identity v1 provider, verifies it matches the previous deterministic local signing result, and then reuses the existing signed-userOp builder. There is no parallel incompatible signing path.

## Security Posture

Phil Device Identity v1 is a local identity baseline with hardware-provider interfaces and a production-oriented scaffold. It is not externally audited, not production-ready, and does not cryptographically prove hardware origin.

The local deterministic provider is local only, test only, and not production safe. Never use its deterministic key material for production assets, production accounts, or real-user secrets.

The WebAuthn provider performs real browser API registration/assertion calls when run in a WebAuthn-capable browser. Registration verification covers challenge, origin, rpIdHash, user-presence/user-verification flags, attested credential data, ES256 COSE key extraction, initial sign counter, and explicit local attestation policy. Assertion verification covers challenge, origin, rpIdHash, user-presence/user-verification flags, ES256 signature, and counter behavior. The v1.3 lifecycle registry models credential storage metadata, rotation, recovery state, anti-lockout warnings, and audit events locally. The v1.5 storage layer encrypts that registry at rest for Node/local development, and v1.6 adds browser-oriented IndexedDB/WebCrypto storage. Production readiness still requires trusted attestation-root validation if hardware provenance is desired, production key management, platform/mobile secure storage providers, phishing-resistant UX, threat modeling, and external review.

## Quantum-Resistance Direction

PhilCore's long-term goal is a portable cryptographic identity substrate that can authorize execution across changing chains and account systems.

STARK-style proof systems may help at the proof layer, but Ethereum/Base execution still depends on chain-level cryptography. WebAuthn is not itself a post-quantum signature provider. Future post-quantum providers should remain pluggable through the Device Identity v1 provider interface without changing the locked Phil proof/fact semantics.

## Local Checks

Useful local commands:

```bash
npm run generate:local-fixtures
npm run typecheck
npx hardhat test test/unit/phil-identity.test.cjs
npx hardhat test test/unit/local-device-signing.test.cjs
npm run --silent run:local-device-signing-session-matrix-integration
```

Fresh checkouts need the ignored `proving/out/` artifacts regenerated before tests that consume local relay or signing artifacts can pass. `npm run generate:local-fixtures` regenerates the local Starknet relay harness fixture, proof summary, smart-account deploy signature request, attempt runner, and Device Identity v1 local signing result.

`npm run test:proving` is separate and requires Rust/Cargo plus the repo rust toolchain.
