# Fixture Authentication Lifecycle Bridge

## Purpose

The Fixture Authentication Lifecycle Bridge is a test-only bridge for controlled User Session lifecycle testing.

It can verify explicit developer fixture authentication evidence and use the resulting verified fixture reference to permit a narrow lifecycle transition in tests.

It is not production authentication.

## Fixture Flow

```text
Lifecycle unlock request
  -> Developer fixture authentication request
  -> Explicit fixture evidence artifact
  -> Fixture evidence verification
  -> Verified fixture lifecycle evidence reference
  -> Controlled test lifecycle transition
  -> Audit event draft
  -> Stop
```

Supported fixture transitions are intentionally narrow:

- `unlocking + unlock_succeeded -> unlocked`
- `resuming + resume_succeeded -> unlocked`

Recovery transitions are not supported by this bridge.

## What Verification Means

Fixture verification means only that explicit developer/test inputs matched the expected:

- session ID
- lifecycle transition request ID
- owner commitment
- challenge reference
- provider ID
- audit correlation ID
- fixture assurance
- freshness and replay constraints

The verified reference is marked:

- `fixtureOnly: true`
- `verified: true`
- `productionAuthenticationPerformed: false`
- `vaultUnlocked: false`
- `biometricVerificationPerformed: false`
- `platformWebAuthnPerformed: false`
- `grantsAuthority: false`
- `persisted: false`

## What It Does Not Do

The bridge does not invoke browser WebAuthn, platform biometrics, Secure Enclave, Android Keystore, Device Vault, World ID, proof code, or execution adapters.

It does not load production credentials, unlock Device Vault, create session keys, mutate active capabilities, create authorization packages, persist evidence, or persist session state.

An `unlocked` lifecycle state reached through this bridge is a fixture-only lifecycle state. Device Vault remains locked.

## Replay Handling

The optional fixture evidence consumption store is process-local and ephemeral. It supports one-time consumption per evidence ID for tests and rejects repeated consumption.

It is not a production replay registry and must not be used as durable security state.

## Lifecycle Boundary

The lifecycle state machine remains authoritative for state changes. Provider adapters cannot mutate lifecycle state directly.

The fixture bridge calls the lifecycle transition helper only after fixture evidence is explicitly verified and the requested transition is one of the supported fixture transitions.

## Alpha 0 Diagnostic Mode

The Alpha 0 shell includes a diagnostic fixture sequence:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence fixture_unlock
```

The shell output must visibly show fixture-only authentication, no production authentication, Device Vault not unlocked, no active capability, no authorization, and no persistence.

## Future Work

Phase J.4 should evaluate integrating the existing real WebAuthn assertion verifier into the session lifecycle using explicit in-memory credential/public-key inputs, still without Device Vault storage or production UI.
