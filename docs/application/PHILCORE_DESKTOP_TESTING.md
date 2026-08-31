# PhilCore Desktop Testing

Status: local test suite implemented.

Architecture status: The O.5 end-to-end STWO success path below is historical
regression evidence. Current source structurally rejects ordinary and Device
Vault proof generation, finalization, publication, signing, and execution for
the secret-bearing artifact. It is not the accepted V1 authorization path.

Phase: O.5

## Commands

```bash
npm run desktop:build-local
npm run desktop:test
npm run desktop:test:e2e
npm run desktop:test-real-local-authorization
npm run desktop:security
npm run desktop:demo-real-local-authorization
npm run desktop:diagnose-local-proof
npm run desktop:diagnose-local-4337
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

`desktop:build-local` copies the local Electron source into a local artifact directory and writes a manifest. It is not a signed package.

`desktop:test` runs bridge, Runtime-host, encrypted storage/restart/tamper, platform-auth fixture, approval, real local authorization, and renderer-security tests.

The historical O.5 `desktop:test:e2e` acceptance launched Electron in local E2E
mode, created a durable encrypted local identity, enrolled fixture platform
unlock through approval, restarted, reopened the same identity, ran the then
active local STWO authorization workflow, required fresh auth for the exact
UserOperation signing presentation, verified local EntryPoint execution, and
locked. Current release/security validation expects that secret-bearing route
to fail closed before authority use.

`desktop:security` checks renderer isolation assumptions.

The diagnostic commands print sanitized local storage, identity, vault, platform-auth, Keychain, proof, and local ERC-4337 boundary status. CLI diagnostics do not prove real macOS Keychain UI; fixture evidence is explicitly labeled.

## Coverage

O.2 tests cover:

- bridge allowlist;
- malformed request rejection;
- secret-shaped key detection;
- local identity creation;
- local Alpha passphrase authentication;
- encrypted Device Vault unlock;
- app restart and reopen;
- ciphertext tamper failure;
- identity-index tamper failure;
- locked reset confirmation;
- local authorization workflow;
- non-secret preference persistence;
- recovery-authority rotation fixture state;
- Electron renderer isolation settings;
- CSP presence;
- preload bridge shape;
- no secret-shaped renderer tokens;
- Electron E2E launch and restart.
- platform protection enrollment;
- platform unlock after restart;
- platform cancellation/denial/missing/corrupt failure modes;
- passphrase fallback after platform enrollment;
- platform protection disablement;
- fresh-auth evidence for a local signing presentation.
- digest-bound presentation and approval artifact handling.
- approval replay, denial, cancellation, lock, and restart invalidation.
- historical synthetic local STWO proof generation and verification regression coverage;
- current ordinary-path rejection of the secret-bearing STWO artifact before signing;
- local mirrored-fact fixture labeling without current product authority;
- historical ERC-4337 preparation, signing, EntryPoint, nullifier, and consumer regression coverage behind explicit fixtures;
- reset fresh-auth/passphrase reauthentication guardrail.

## Current Gaps

- no screenshot comparison yet;
- no packaged-app signing test;
- no real platform WebAuthn desktop prompt;
- no public-network test by design.
- no automated real Touch ID prompt;
- no production WebAuthn/passkey desktop RP/origin yet.
