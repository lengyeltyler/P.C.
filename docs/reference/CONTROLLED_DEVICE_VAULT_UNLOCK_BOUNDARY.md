# Controlled Device Vault Unlock Boundary

## Purpose

Phase K.1 introduces a controlled Device Vault unlock boundary for Runtime Session Lifecycle integration.

This boundary verifies an explicitly supplied in-memory encrypted Device Identity registry envelope against explicitly supplied in-memory unlock material. It reuses the existing encrypted registry/key lifecycle validation helpers and produces only bounded runtime artifacts.

## Flow

```text
partially_unlocked User Session
  -> explicit in-memory vault envelope
  -> explicit in-memory unlock material
  -> existing encrypted registry validation
  -> DeviceVaultUnlockResult
  -> controlled partially_unlocked -> unlocked transition
  -> derived UserSessionContext
  -> sanitized Audit Event Drafts
  -> stop
```

## What It Does

- Authenticates the supplied encrypted registry envelope using the existing registry validation path.
- Confirms owner/session/audit correlation metadata.
- Enforces that the session is already `partially_unlocked`.
- Produces an opaque process-local vault handle metadata object.
- Allows a bounded lifecycle transition from `partially_unlocked` to `unlocked`.
- Creates sanitized audit event drafts.

## What It Does Not Do

- It does not expose `phil_secret`.
- It does not expose raw vault keys.
- It does not return decrypted registry plaintext.
- It does not load application credentials into Runtime applications.
- It does not create active capabilities.
- It does not create session keys.
- It does not create Authorization Packages.
- It does not execute policy, trust decisions, proofs, adapters, World ID, or Ethereum transactions.
- It does not persist Runtime session state or audit events.

## Security Boundary

The unlock request must carry public identity correlation and explicit in-memory unlock inputs only.

The result may state that protected state is available through an opaque process-local handle. The handle is metadata only:

- process-local
- non-serializable
- non-exportable
- not application-accessible
- contains no plaintext
- contains no raw vault key
- contains no `phil_secret`

## Replay Scope

Vault unlock result consumption is protected by an optional process-local consumption store.

This prevents accidental duplicate consumption inside the current process only. It is not durable replay prevention and is not persisted.

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_webauthn_vault_unlock
```

This diagnostic verifies explicit in-memory WebAuthn test input, reaches `partially_unlocked`, unlocks an explicit in-memory encrypted registry test envelope, and reaches `unlocked`.

It remains non-authoritative: no active capability, authorization, session key, adapter execution, proof execution, vault persistence, or application credential loading occurs.
