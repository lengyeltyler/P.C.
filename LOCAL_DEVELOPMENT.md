# Local Development

PhilCore is easiest to work on as a local-first repo. Most flows emit JSON artifacts under `proving/out/`; that directory is generated and ignored by git.

For current architecture and terminology, start with:

- [Canonical Documentation](./docs/CANONICAL_DOCS.md)
- [PhilCore Core Boundary](./docs/PHILCORE_CORE_BOUNDARY.md)
- [PhilCore Runtime Lifecycle](./docs/PHILCORE_RUNTIME_LIFECYCLE.md)
- [PhilCore Functional Specification v1](./docs/PHILCORE_FUNCTIONAL_SPEC_V1.md)
- [PhilCore Technical Specification v1](./docs/PHILCORE_TECHNICAL_SPEC_V1.md)

PhilCore is now framed as a Personal Security Operating System. Ethereum/Base is the first execution path, not the identity layer.

## Requirements

- Node.js 26.0.0 (exact; `.node-version` and `package.json` are authoritative)
- npm 11.12.1 (exact; `package.json` is authoritative)
- Rust with the toolchain in `proving/rust-toolchain.toml`
- Cairo/Scarb tooling for Cairo and Starknet packages
- Optional: `gh` for GitHub publication tasks

The deterministic CI lanes use the same exact Node.js and npm versions. Do
not substitute a newer 26.x or 11.x release without a reviewed toolchain
change.

## Setup

```bash
npm install
cp .env.example .env
npm run generate:local-fixtures
```

The `.env.example` file is intentionally placeholder-only. Do not commit real keys or RPC credentials.

`npm run generate:local-fixtures` regenerates ignored local JSON under `proving/out/`, including the Starknet relay harness fixture, smart-account deploy signature request, attempt runner, and local Device Identity signing result. Run it after a fresh checkout or after deleting `proving/out/`.

## Public deterministic validation

```bash
npm ci
npm run ci:install-starknet-toolchain
source scripts/starknet/activate-pinned-toolchain.sh
npm run ci:validate-classification
npx hardhat test --no-compile ./test/unit/ci-classification.test.cjs
npx hardhat test --no-compile ./test/unit/ci-starknet-toolchain-installer.test.cjs
npm run typecheck
npx hardhat compile
npm run desktop:bundle-preload
npm run ci:lane:product-runtime
npm run ci:lane:solidity
npm run ci:lane:desktop
npm run ci:lane:proving
npm run verify:starknet-artifacts
npm run ci:lane:evidence
npm run ci:lane:historical-evidence
```

These are the credential-free, non-deploying validation paths used by the
deterministic workflow. The Starknet installer accepts only the versions and
archive hashes committed in `config/ci/starknet-toolchain-assets.json`; it does
not float to newer releases. `verify:starknet-artifacts` builds and tests the
applicable Cairo packages, runs the Rust proof tests, and runs local syscall and
L1-message harnesses without submitting anything to a public network.

The historical-evidence lane is green only when each approved historical
non-zero result matches its exact failure identity. It does not regenerate or
silently accept stale legacy evidence.

Do not use the broad `npm run test:unit` or `npm run test` aggregate as the
public deterministic gate. Those convenience commands mix required tests with
local-fixture, private-configuration, physical-ceremony, and prohibited
public-network categories. `config/ci/classification.json` is the authoritative
per-test classification:

- `environment_dependent` contains 43 local/integration items. These require
  generated `proving/out` state, ignored sanitized publication configuration,
  or other local deployment artifacts. In particular, the Starknet publication
  preparation, submission, configuration, and publisher-signing unit files are
  intentionally outside the public deterministic lane.
- `physical_ceremony_manual` contains 10 iPhone, WebAuthn, and user-presence
  items that require real hardware or an interactive ceremony.
- `public_network_prohibited` contains five live bundler, deployment, or
  submission items and is never part of ordinary readiness validation.

Private credentials, fake production credentials, and owner-specific paths are
not required by any public deterministic lane. Local integration testing may
start with `npm run generate:local-fixtures` and placeholder-only
`.env.example`, but real credentials remain uncommitted and are never a
prerequisite for the public gate.

`npm run ci:verify-clean-tree` is a disposable-checkout CI hygiene check that
removes ignored generated outputs before confirming the tree. Do not use it in
a working checkout that contains local artifacts you intend to keep.

## Desktop Local Alpha

Run the local-only desktop shell:

```bash
npm run desktop:dev
```

The user-facing Alpha journey, terminology rules, local-only Ethereum behavior, and Developer mode boundary are documented in [PhilCore Desktop Alpha Product Journey](./docs/application/PHILCORE_DESKTOP_ALPHA_PRODUCT_JOURNEY.md).

Build and test the local desktop artifact:

```bash
npm run desktop:build-local
npm run desktop:test
npm run desktop:test:e2e
npm run desktop:security
npm run desktop:test-real-local-authorization
npm run desktop:demo-real-local-authorization
npm run desktop:diagnose-local-proof
npm run desktop:diagnose-local-4337
npm run desktop:user-presence:build
npm run desktop:user-presence:test
npm run desktop:user-presence:diagnose
npm run desktop:package-local
npm run desktop:package-adhoc
npm run desktop:verify-package
npm run desktop:audit-package-size
npm run desktop:sbom
npm run desktop:test-packaged
npm run desktop:test-packaged-user-shell
npm run desktop:test-clean-environment
npm run desktop:diagnose-storage
npm run desktop:diagnose-identity
npm run desktop:diagnose-vault
npm run desktop:diagnose-platform-auth
npm run desktop:diagnose-keychain
npm run desktop:test-platform-unlock
npm run desktop:test-approval
npm run desktop:demo-approval
npm run desktop:demo-recovery-approval
npm run desktop:diagnose-fresh-auth
```

Reset only PhilCore Desktop Local Alpha test data for a genuine first-run QA pass:

```bash
# Normal local launch
npm run desktop:dev

# Dry-run the reset and print the exact local Alpha paths that would be removed
npm run desktop:reset-local-alpha-data

# Perform the guarded reset after reviewing the printed paths
PHILCORE_DESKTOP_RESET_LOCAL_ALPHA_APPROVED=1 npm run desktop:reset-local-alpha-data

# Launch again into a fresh first-run state
npm run desktop:dev
```

The reset command removes only `philcore-desktop-preferences.json` and `philcore-local-identities` under the PhilCore Desktop Local Alpha app-data directory. It does not delete source code, packaged application files, unrelated Electron app data, or Keychain items. Protected Mac unlock credentials created by a macOS platform adapter may require separate platform cleanup if external Keychain records were created.

The desktop app is Electron-based with `contextIsolation`, disabled renderer Node integration, a sandboxed renderer, a narrow preload bridge, and durable encrypted local identity/Device Vault state. The normal sidebar contains only Home, Activity, and Settings. Home opens Ethereum's supported local demonstration; the other bundled chains remain Preview destinations. That action uses the same canonical Runtime operation as the diagnostic Developer path: Runtime-generated digest-bound approval, trust and policy checks, fresh user presence where required, real Rust/STWO proof generation, real local proof verification, local fixture fact availability, ERC-4337 UserOperation preparation, Device Vault signing, local EntryPoint execution, nullifier consumption, and consumer verification. Rejection, cancellation, expiry, lock, and restart fail closed and do not leave reusable approval authority. The O.12 QA checklist records the manual matrix for interruption, Activity, accessibility, package, and local-only release-candidate rehearsal. The UI labels platform, release, and fixture evidence honestly; it does not claim Touch ID unless a biometric-only LocalAuthentication policy succeeds, does not claim Secure Enclave custody, and does not claim notarization, Starknet publication, L1 anchoring, public Base relay, or public bundler submission. CLI diagnostics are fixture/availability evidence by default; real OS prompts require explicit diagnostic invocation. The desktop app exposes no public RPC configuration, public bundler, paymaster, generic wallet controls, arbitrary contract calls, private-key export, root secret material, vault key, wrapping key, decrypted registry plaintext, approval authority, or public transaction submission. See [PhilCore Desktop User-First Shell](./docs/application/PHILCORE_DESKTOP_USER_FIRST_SHELL.md), [PhilCore Desktop Alpha Foundation](./docs/application/PHILCORE_DESKTOP_ALPHA_FOUNDATION.md), [PhilCore Desktop Local Identity And Device Vault](./docs/application/PHILCORE_DESKTOP_LOCAL_IDENTITY_AND_VAULT.md), [PhilCore Desktop Platform Authentication](./docs/application/PHILCORE_DESKTOP_PLATFORM_AUTHENTICATION.md), [PhilCore Desktop Approval And Presentation](./docs/application/PHILCORE_DESKTOP_APPROVAL_AND_PRESENTATION.md), [PhilCore Desktop Real Local Authorization](./docs/application/PHILCORE_DESKTOP_REAL_LOCAL_AUTHORIZATION.md), [PhilCore Desktop Alpha QA Checklist](./docs/application/PHILCORE_DESKTOP_ALPHA_QA_CHECKLIST.md), [PhilCore Desktop Packaging](./docs/application/PHILCORE_DESKTOP_PACKAGING.md), [PhilCore Desktop Local Alpha Release](./docs/application/PHILCORE_DESKTOP_LOCAL_ALPHA_RELEASE.md), [PhilCore Desktop Release-Candidate Hardening](./docs/application/PHILCORE_DESKTOP_RELEASE_CANDIDATE_HARDENING.md), [PhilCore macOS User-Presence Boundary](./docs/security/PHILCORE_MACOS_USER_PRESENCE_BOUNDARY.md), and [PhilCore Desktop Security Boundary](./docs/application/PHILCORE_DESKTOP_SECURITY_BOUNDARY.md).

The packaged action lifecycle can be exercised with `npm run desktop:test-packaged-action-lifecycle`. It verifies that missing Mac protection is caught before user-presence progress, every blocking step is cancellable and bounded, late results are ignored, restart clears interrupted authority, and a real local proof/signing/EntryPoint action still completes without public-network mutation.

The complete O.15 first-run and returning-user product walkthrough is
`npm run desktop:test-packaged-user-shell`. It uses a temporary identity,
captures local screenshots, runs the real local protected action, and performs
no public-network mutation.

## Security Checks

```bash
npm run security:setup-slither
npm run security:full
npm run security:audit-package-check
```

`npm run security:full` runs the pinned Slither analysis, PhilCore custom contract invariants, and npm advisory triage. `npm run security:audit-package-check` validates the local audit-readiness manifest and confirms the Base Sepolia Beta gate has not been falsely passed.

The current meaningful-assets policy is local fixtures only. Base Sepolia Beta remains blocked, and production/meaningful assets are prohibited until external audit and gate approval. See [PhilCore Meaningful Assets Policy](./docs/security/PHILCORE_MEANINGFUL_ASSETS_POLICY.md).

## Starknet Artifact Reproducibility

The verified-fact publication route has a pinned, non-installing Starknet toolchain check:

```bash
source scripts/starknet/activate-pinned-toolchain.sh
npm run check:starknet-toolchain
```

The expected Scarb/Cairo version is `2.15.0`. The checker first resolves the repository-configured pinned cache paths under `~/.cache/philcore/toolchains/`, then falls back to the shell PATH. It reports installed versions and fails clearly if tools are missing; it does not install or modify local tools.

The clean artifact reproduction command is:

```bash
npm run verify:starknet-artifacts
```

It checks tools, builds the Cairo packages, regenerates local proof-input-hash slice args, writes `config/starknet-publication-readiness.json`, and runs the Rust syscall/L1 relay harnesses. It does not deploy contracts or submit transactions.

See [Starknet Toolchain And Artifact Reproducibility](./docs/reference/STARKNET_TOOLCHAIN_AND_ARTIFACT_REPRODUCIBILITY.md).

Validate the non-executing Starknet publication configuration:

```bash
npm run validate:starknet-publication-config
npm run verify:starknet-publication-artifact-binding
```

The local publication config is a draft predeployment profile. It binds generated artifacts and message shape but does not permit transaction preparation.

Run the unsigned Starknet publication preparation diagnostic:

```bash
npm run diagnose:starknet-fact-publication-preparation -- --json
npm run diagnose:starknet-fact-publication-preparation -- --fixture-resolved --json
```

The fixture-resolved mode is local-only. It prepares an unsigned, unsubmitted transaction draft and does not emit a message, call L1, call Base, or mutate chain state.

Run the controlled Starknet publisher signing diagnostic:

```bash
npm run diagnose:starknet-fact-publication-signing -- --json
npm run diagnose:starknet-fact-publication-signing -- --fixture-resolved --json
```

The fixture-resolved mode uses a deterministic developer fixture signer only. It creates a signed but unsubmitted artifact and does not emit a message, submit a transaction, call L1, call Base, or mutate chain state.

Run the controlled Starknet submission readiness diagnostic:

```bash
npm run diagnose:starknet-fact-publication-submission -- --json
npm run submit:starknet-fact-publication-testnet -- --submit --json
npm run monitor:starknet-fact-publication -- --json
```

The current repository config is intentionally blocked for live submission. These commands report missing Sepolia deployment/account/RPC/key-custody/submission-approval prerequisites and do not deploy, submit, consume L1 messages, relay to Base, execute Base, or consume nullifiers.

Run the Ethereum L1 message availability and fact-anchor preparation diagnostics:

```bash
npm run diagnose:l1-message-availability -- --json
npm run diagnose:l1-fact-anchor-preparation -- --json
```

These diagnostics use fixture/local evidence by default. They may prepare an unsigned `consumeProofInputHashFactFromL2(factHigh, factLow)` calldata draft, but they do not consume the L2-to-L1 message, sign or submit an L1 transaction, anchor the fact, relay to Base, execute Base, or consume nullifiers.

Run the controlled Ethereum L1 fact-anchor signing diagnostics:

```bash
npm run diagnose:l1-fact-anchor-signing -- --json
npm run submit:l1-fact-anchor-sepolia -- --json
npm run monitor:l1-fact-anchor -- --json
```

The current commands use fixture/local evidence and report `live_l1_submission_performed: false` unless accepted live Sepolia message, deployment, relayer, signer, fee, and approval prerequisites exist. They do not relay to Base, call Base, execute `verifyAndConsume(...)`, or consume nullifiers.

Run the Ethereum L1-to-Base relay preparation diagnostics:

```bash
npm run diagnose:l1-anchored-fact -- --json
npm run diagnose:l1-to-base-relay-preparation -- --json
```

These diagnostics use fixture/local anchored-fact evidence by default. They may prepare an unsigned `relayProofInputHashFactToBase(baseMirror, factHigh, factLow)` calldata draft, but they do not sign, submit, send a cross-domain message, call the Base mirror, mirror the fact, execute Base, or consume nullifiers.

Run the controlled Ethereum L1-to-Base relay signing/submission/monitoring diagnostics:

```bash
npm run diagnose:l1-to-base-relay-signing -- --json
npm run submit:l1-to-base-relay-sepolia -- --json
npm run monitor:l1-to-base-relay -- --json
npm run verify:base-fact-mirror -- --json
```

The current commands use fixture/local anchored-fact evidence and report `live_relay_submission_performed: false` unless accepted live L1 anchoring evidence, Sepolia/Base Sepolia deployments, protected relayer custody, and explicit submission approval exist. They do not call the Base mirror directly, execute `verifyAndConsume(...)`, consume nullifiers, or execute consumers.

Run the controlled Base authorization execution preparation diagnostics:

```bash
npm run diagnose:base-authorization-execution-preparation
npm run diagnose:base-authorization-execution-preparation -- --json
npm run simulate:base-authorization-execution
```

These diagnostics use fixture/local mirrored-fact evidence by default. They may prepare an unsigned `PhilBaseActionGate.verifyAndConsume(...)` transaction draft and report fixture simulation/gas/fee/nonce references, but they do not sign, submit, create a UserOperation, consume nullifiers, execute consumers, or mutate Base state.

Run the controlled Base authorization execution signing/submission/monitoring diagnostics:

```bash
npm run diagnose:base-execution-signing
npm run diagnose:base-execution-signing -- --json
npm run submit:base-authorization-execution-sepolia -- --json
npm run monitor:base-authorization-execution -- --json
npm run verify:base-nullifier-consumption -- --json
npm run verify:base-consumer-execution -- --json
```

These commands are fixture/local diagnostics by default and report `live_base_execution_performed: false`. They do not submit to Base Sepolia without live mirrored-fact evidence, accepted deployments, protected signer custody, funding/RPC, and explicit final execution approval. They never submit to Base mainnet.

Run the proposed local ERC-4337 Smart Account foundation tests:

```bash
npx hardhat test test/unit/philcore-erc4337-smart-account-foundation.test.cjs
```

These tests deploy a local EntryPoint v0.7 fixture, a proposed minimal PhilCore account/factory, and local ActionGate fixtures. They execute local `handleOps(...)` calls only. They do not sign or submit UserOperations to a bundler, invoke paymasters, deploy live accounts, or mutate live Base state.

Run the controlled ERC-4337 UserOperation preparation diagnostics:

```bash
npm run inspect:philcore-4337-account
npm run diagnose:philcore-user-operation-preparation
npm run simulate:philcore-user-operation
npx hardhat test test/unit/philcore-erc4337-user-operation-preparation.test.cjs
```

These commands prepare an unsigned EntryPoint v0.7 `PackedUserOperation` draft from fixture/local inputs. They do not sign, submit to a bundler, invoke a paymaster, deploy live accounts, consume nullifiers, execute consumers, or mutate live Base state.

Run the controlled ERC-4337 UserOperation signing diagnostics:

```bash
npm run diagnose:philcore-user-operation-signing
npm run inspect:signed-philcore-user-operation
npx hardhat test test/unit/philcore-erc4337-user-operation-signing.test.cjs
```

These commands use local fixture signing only. They produce a signed but unsubmitted EntryPoint v0.7 `PackedUserOperation` artifact and do not call a bundler, invoke a paymaster, deploy live accounts, consume nullifiers, execute consumers, or mutate live Base state.

Run the local Device Vault ECDSA validator custody diagnostic:

```bash
npm run diagnose:device-vault-ecdsa-custody
npm run inspect:device-vault-validator
npm run test:device-vault-ecdsa-signing
```

These commands create a local encrypted validator record, sign one fixture UserOperation hash through a one-time process-local signing session, redact signature/private material from diagnostic output, and submit nothing.

Run the restricted ERC-4337 rotation/recovery tests:

```bash
npm run test:erc4337-recovery
npm run diagnose:recovery-authority-rotation -- --json
```

These tests exercise local owner rotation, delayed recovery, recovery-authority rotation, freeze/cancel/complete behavior, and Device Vault rotation coordination. The diagnostic is config-backed and non-mutating. These commands do not deploy live accounts, access Device Vault secrets, sign UserOperations, or submit public UserOperations.

## Important Local Flows

Build the local smart-account deploy signature request:

```bash
npm run --silent build:smart-account-deploy-signature-request
```

Produce a real local dev signature over the existing signing payload:

```bash
npm run generate:local-fixtures
npm run --silent run:local-smart-account-deploy-signing
```

Run the local-device-signed deploy-session matrix:

```bash
npm run --silent run:local-device-signing-session-matrix-integration
```

Run the focused regression for local device signing and session integration:

```bash
npx hardhat test test/unit/local-device-signing.test.cjs test/unit/local-device-signing-session-integration.test.cjs
```

## Local Bundler Stub

The local bundler stub is a controlled no-send HTTP server. It supports:

- `accepted`
- `rejected`
- `transport-error`

Example:

```bash
npm run --silent run:local-bundler-stub -- --mode accepted --out-dir ./proving/out/local_bundler_stub
```

The higher-level drill and session runners usually start and stop the stub for you.

## Local Submission Drill

Single-mode drill:

```bash
npm run --silent run:local-smart-account-deploy-drill -- \
  --smart-account-deploy-attempt-runner ./proving/out/smart_account_deploy_attempt_runner/smart_account_deploy_attempt_runner.json \
  --mode accepted
```

Drill matrix:

```bash
npm run --silent run:local-smart-account-deploy-drill-matrix -- \
  --smart-account-deploy-attempt-runner ./proving/out/smart_account_deploy_attempt_runner/smart_account_deploy_attempt_runner.json
```

Top-level deploy session matrix:

```bash
npm run --silent run:local-smart-account-deploy-session -- \
  --smart-account-deploy-attempt-runner ./proving/out/smart_account_deploy_attempt_runner/smart_account_deploy_attempt_runner.json \
  --matrix
```

## Local Device Signing Session Matrix

This is currently the best high-signal local workflow:

```bash
npm run generate:local-fixtures
npm run --silent run:local-device-signing-session-matrix-integration
```

It consumes:

- `proving/out/local_device_signing/local_device_signing_result.json`
- `proving/out/smart_account_deploy_signature_request/smart_account_deploy_signature_request.json`

It emits:

- `proving/out/local_device_signing_session_integration/local_device_signing_session_matrix_result.json`

The result proves that the accepted, rejected, and transport-error local session matrix used the real locally produced signature.

## Device Identity v1

The local signing runner now uses Phil Device Identity v1 from `apps/phil-device-sdk/src/deviceIdentity.ts`.

The default local provider is deterministic and test-only:

- local only
- CI/dev only
- not hardware-backed
- not production safe
- must never protect production accounts, production assets, or real-user secrets

The WebAuthn/passkey provider builds browser `navigator.credentials.create()` and `navigator.credentials.get()` flows. Registration challenges are bound to PhilCore registration intent, and assertion challenges are bound to PhilCore signable digests. Node unit tests use a mock `navigator.credentials`; they do not exercise a real platform authenticator.

The WebAuthn registration verifier checks mocked ES256/P-256 registration data in unit tests, including challenge, origin, rpIdHash, user-presence/user-verification flags, attested credential data, credential ID extraction, COSE public-key extraction, algorithm allowlist, sign-count initialization, transports, and attestation policy.

The WebAuthn assertion verifier checks mocked ES256/P-256 SPKI assertions in unit tests, including challenge, origin, rpIdHash, user-presence/user-verification flags, signature, and sign counter behavior. Non-ES256 registration/assertion algorithms are not implemented yet.

The lifecycle registry lives in `apps/phil-device-sdk/src/deviceIdentityLifecycle.ts`. It models one Phil identity with multiple credentials, including active, pending, revoked, recovery-only, and archived statuses. Unit tests cover multiple active credentials, add/revoke/rotate flows, lost-device handling, recovery-pending and recovery-completed flows, anti-lockout warnings, and audit events.

The encrypted registry storage layer lives in `apps/phil-device-sdk/src/deviceIdentityStorage.ts`. It persists the lifecycle snapshot using a versioned encrypted envelope:

- format: `phil-device-identity-registry-encrypted`
- version: `1`
- encryption: AES-256-GCM
- associated data: registry format, version, and owner commitment
- local dev passphrase key derivation: scrypt with random salt, default `N=32768`, `r=8`, `p=1`, `keyLength=32`

Unit tests cover file-backed save/load, missing registries, corrupted envelopes, unsupported versions, wrong owner commitment, wrong passphrase, modified ciphertext, encrypted backup import/export, and overwrite protection.

The storage-key lifecycle layer lives in `apps/phil-device-sdk/src/deviceIdentityKeyLifecycle.ts`. It is local-first scaffolding for key-version metadata and policy, not production platform key management. It models storage and backup key versions with `active`, `retiring`, `retired`, and `revoked` statuses. Rotation decrypts the current encrypted registry, re-encrypts with the next key, writes `keyLifecycle` or `backupLifecycle` envelope metadata, verifies the new encryption before completing, and restores the original encrypted blob if rotation fails. Active and retiring keys may load by policy; retired and revoked keys fail closed by default.

Storage-key and backup-key lifecycle tests cover successful rotation, rollback on simulated failure, backup-key rotation, envelope metadata, export/import after rotation, and retired/revoked load rejection.

## Device Identity End-To-End Demo

The v1.8 local demo runner composes the Device Identity stack and the existing session matrix:

```bash
npm run generate:local-fixtures
npm run demo:device-identity
```

It emits:

- `proving/out/phil_device_identity_demo/phil_device_identity_demo_result.json`
- `proving/out/phil_device_identity_demo/phil_device_identity_demo_registry.enc.json`
- session-matrix support artifacts under `proving/out/phil_device_identity_demo/session_matrix/`

The demo uses deterministic mocked WebAuthn browser calls so it can run from the command line. It still exercises the actual ES256 registration verifier, ES256 assertion verifier, signable-digest challenge binding, sign-counter handling, credential lifecycle audit trail, encrypted registry save/load, and the existing local-device-signed deploy-session matrix.

The JSON result contains safe public metadata and summary booleans only. It intentionally does not include Phil secrets, mnemonic material, raw recovery material, authenticator signing material, or storage encryption material. The runner fails if obvious secret-bearing field names appear in the result.

The browser IndexedDB storage layer lives in `apps/phil-device-sdk/src/deviceIdentityIndexedDbStorage.ts`. It uses IndexedDB object stores `registries` and `registry_metadata`, stores encrypted blobs keyed by owner commitment, and uses WebCrypto AES-GCM/PBKDF2 helpers. Unit tests use a mocked IndexedDB implementation and WebCrypto, so they do not require browser UI or manual interaction.

The local dev passphrase key providers are test-only and unsafe for production. Future work must add mobile secure storage, real platform keychain/Secure Enclave key providers, trusted attestation-root validation if hardware provenance is claimed, user notification/delay rules, and reviewed recovery ceremonies.

The Secure Enclave/platform authenticator and mobile secure-hardware providers are still scaffolds. They expose public metadata and fail cleanly with unsupported-platform errors until real platform integration is implemented.

## Generated Artifacts

Ignored generated directories include:

- `proving/out/`
- `proving/target/`
- `**/target/`
- `artifacts/`
- `cache/`
- `node_modules/`

Regenerate artifacts locally instead of committing them unless a future pass deliberately curates a small fixture set.

## PhilCore ERC-4337 Local Diagnostics

The current ERC-4337 runtime path is local/fixture-first:

```bash
npm run diagnose:philcore-user-operation-preparation
npm run diagnose:philcore-user-operation-signing
npm run diagnose:philcore-4337-bundler
npm run monitor:philcore-user-operation
```

The M.11 bundler diagnostic uses a restricted local fixture boundary. It does not submit to a public bundler, invoke a paymaster, expose signer material, accept ACP-0002, or mutate live Base state.

## PhilCore Recovery Authority Local Diagnostics

N.5 adds local-only recovery authority custody and workflow checks:

```bash
npm run diagnose:recovery-authority-custody
npm run demo:philcore-recovery-request
npm run demo:philcore-recovery-cancel
npm run demo:philcore-recovery-complete
npm run verify:philcore-recovery-state
npm run test:recovery-authority-custody
```

These commands are local/fixture diagnostics. They do not deploy live accounts, submit public UserOperations, invoke paymasters, execute ActionGate consumers, consume nullifiers, print recovery private keys, or mutate live Base state.

## Solidity Static Analysis

N.6 adds a reproducible repository-local Slither environment plus PhilCore-specific contract invariant checks:

```bash
npm run security:setup-slither
npm run security:slither
npm run security:philcore-contract-invariants
npm run security:npm-audit
npm run security:full
```

`security:setup-slither` is the only command that installs the pinned local Python environment under `.security-tools/`. Ordinary analysis commands do not silently install tools. N.6 records Slither and dependency triage evidence in `config/security/` and summarizes it in `docs/security/PHILCORE_SOLIDITY_STATIC_ANALYSIS_N6.md`.

Base Sepolia Beta remains blocked until the remaining high tooling advisories are remediated or formally accepted, recovery-authority rotation is resolved or accepted for disposable testnet accounts, deployment evidence exists, and external audit/independent review is complete.

## Ethereum Sepolia O.17 Readiness

These commands are local and non-mutating:

```bash
npm run ethereum-sepolia:inspect
npm run ethereum-sepolia:prepare-manifest
npm run ethereum-sepolia:verify-manifest
npm run ethereum-sepolia:preflight
npx hardhat test test/unit/ethereum-sepolia-readiness.test.cjs test/unit/philcore-authorization-confirmation-target.test.cjs
```

The proposed manifest is
`config/ethereum-sepolia/ETHEREUM_SEPOLIA_DEPLOYMENT_MANIFEST_PROPOSED.json`.
It contains no accepted deployment addresses or credentials.

The reserved deployment and UserOperation commands deliberately have no
network transport in O.17 and return nonzero:

```bash
npm run ethereum-sepolia:deploy-test-target -- --submit
npm run ethereum-sepolia:submit-first-userop -- --submit
```

Do not set the public-network approval variables during readiness testing.

## Ethereum Sepolia O.18-O.20 Local-Proof Account Preparation

These commands inspect the experimental `local-proof-gated-v1` proposal without
public mutation:

```bash
npm run ethereum-sepolia:inspect-local-proof-account
npm run ethereum-sepolia:verify-local-proof-bytecode
npm run ethereum-sepolia:diff-local-proof-manifest
npm run ethereum-sepolia:prepare-local-proof-evidence
npm run ethereum-sepolia:local-proof-preflight
npx hardhat test test/unit/local-proof-gated-deployment-preparation.test.cjs test/unit/philcore-local-proof-gated-account.test.cjs test/unit/runtime-local-proof-gated-account.test.cjs
```

The O.20 evidence command loads only `.env.sepolia.local`, validates its mode
and canonical public identity binding, and redacts the RPC URL in evidence. No
provider is selected automatically.

Address calculation additionally requires disposable public proposal inputs:
`PHILCORE_SEPOLIA_DEPLOYER_ADDRESS`, `PHILCORE_SEPOLIA_DEPLOYER_NONCE`,
`PHILCORE_SEPOLIA_VALIDATOR_ADDRESS`,
`PHILCORE_SEPOLIA_OWNER_COMMITMENT`,
`PHILCORE_SEPOLIA_VALIDATOR_KEY_ID`, and
`PHILCORE_SEPOLIA_ACCOUNT_SALT`. These values are public references, not
private keys. The validator key reference is converted to the contract's
domain-separated `bytes32` binding by the reviewed helper.

Deployment, funding, and submission commands remain dry-run blockers with
separate stage gates. Do not set any public mutation approval variable during
O.20 preparation.

## Ethereum Sepolia O.20 read-only preparation

The guarded local-proof preparation command reads only
`.env.sepolia.local`. The file is ignored by `.env.*`, must have mode `0600`,
and is validated against the canonical public desktop identity index before
any RPC request. Values from this exact file override ambient values for its
eight preparation fields. RPC and bundler endpoints are redacted in output.

```bash
npm run ethereum-sepolia:prepare-local-proof-evidence
```

The command exposes read-only RPC and bundler methods only. It does not accept
the proposed manifest or authorize deployment, funding, signing, transaction
submission, or UserOperation submission.

## O.21.1 Runtime-connected unsigned UserOperation preparation

With the canonical O.20 `.env.sepolia.local` profile present, launch the
desktop and open **Ethereum**:

```bash
npm run desktop:dev
```

Unlock the exact identity bound by the profile, then choose **Create Ethereum
Test Account Action**. PhilCore asks for one digest-bound approval, generates a
fresh ACTION_UNLOCK proof through the main-process protected witness provider,
verifies it locally, creates the Runtime authorization digest, prepares a
counterfactual ERC-4337 v0.7 operation, recalculates its hash, validates every
binding, and stops.

## Composed Sepolia mint candidate

The current bounded candidate is documented in
`docs/reference/PHIL_SEPOLIA_MINT_COMPOSED_DEMO_V1.md`. These commands compile
and validate it locally without deployment, funding, or submission:

```bash
npm run compile:phil-sepolia-mint
npm run test:phil-sepolia-mint-authorization
npm run test:phil-sepolia-mint-composition
npm run test:phil-sepolia-mint-device-request
npm run test:phil-sepolia-mint-device-host
npm run test:phil-sepolia-mint-replay-store
npm run test:phil-sepolia-mint-user-operation
npm run test:phil-sepolia-mint-product-workflow
npm run test:phil-sepolia-mint-runtime-capability
npm run test:phil-sepolia-mint-product-reachability
npm run test:phil-sepolia-local-composed-contracts
```

The read-only chain and bundler preflight requires the ignored, mode-`0600`
`.env.sepolia.local` and writes only sanitized public evidence:

```bash
set -a
source ./.env.sepolia.local
set +a
node scripts/ethereum-sepolia/prepare-phil-sepolia-mint-demo.cjs
```

This script has no signer and no transaction or UserOperation submission path.
Its configuration leaves `publicMutationEnabled` and `submissionEnabled` set to
`false`.

In Desktop, unlock an identity with a recovery authority and an enrolled
physical routine iPhone key, open **Ethereum**, and choose **Prepare zero-value
Sepolia mint**. The UI generates and verifies Noir, shows an expiring QR code,
and stops after the exact iPhone-approved UserOperation is signed locally. The
result is stored mode-`0600` under the app data directory. There is no renderer
channel for public mutation.

Do not connect or operate the iPhone from command-line tooling. Physical Face ID
approval is performed only in the packaged PhilCore Companion UI. Deployment,
funding, and submission require a fresh candidate review and explicit final
confirmation of the literal mutations.

Successful public artifacts are mode `0600` files below:

```text
~/Library/Application Support/PhilCore Desktop Local Alpha/
  philcore-local-identities/
  ethereum-sepolia/
  unsigned-user-operations/
```

Run the focused real-proof integration and tamper tests with:

```bash
npm run desktop:test-sepolia-userop-preparation
npx hardhat test test/unit/runtime-connected-unsigned-user-operation.test.cjs
```

The desktop path performs read-only Sepolia checks. It has no signing endpoint,
bundler submitter, deployment operation, funding operation, or public mutation
approval. See
`docs/reference/RUNTIME_CONNECTED_LOCAL_PROOF_PREPARATION.md`.
