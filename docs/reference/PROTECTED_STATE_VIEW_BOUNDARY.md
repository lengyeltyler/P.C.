# Protected State View Boundary

## Purpose

Phase K.2 introduces the first controlled read-only boundary for protected state after Device Vault unlock.

The Runtime may request exactly one explicit non-secret view from an unlocked Device Vault. This is least-privilege visibility, not raw vault access.

## Flow

```text
unlocked User Session
  -> opaque Device Vault handle metadata
  -> explicit protected-state view request
  -> existing encrypted registry load path
  -> non-secret summary view
  -> sanitized Audit Event Draft
  -> stop
```

## Supported Views

Initial supported views:

- `identity_summary`
- `credential_summary`
- `device_summary`
- `recovery_summary`
- `audit_summary`
- `registry_summary`
- `key_lifecycle_summary`
- `runtime_summary`

Every view returns summary metadata only and must explicitly state:

- `containsSecrets = false`
- `containsCredentials = false`
- `containsPrivateKeys = false`
- `containsAuthorization = false`
- `containsSessionKeys = false`

## Least Privilege

There is no generic "read everything" helper. Every request must name one view type.

Credential-related views may return counts and grouping summaries. They do not return credential records, credential IDs, public keys, private material, raw WebAuthn data, or application credentials.

Audit-related views may return counts and event-type summaries. They do not return raw audit event details or secret-bearing evidence.

## Required Validation

Protected state view requests require:

- an unlocked lifecycle snapshot
- a valid opaque vault handle
- owner commitment correlation
- session correlation
- audit correlation when supplied
- a supported view type

Requests reject:

- expired handles
- replayed handle/view pairs when process-local replay tracking is supplied
- invalid handles
- owner mismatches
- session mismatches
- unsupported views

## Vault Unlocked vs. State Visible

Vault unlocked means protected local state is available to PhilCore through a controlled runtime boundary.

State visible means a specific non-secret summary was requested and returned.

Vault unlock does not imply that applications can read raw vault contents, credentials, keys, backups, session keys, authorization packages, or registry plaintext.

## What This Does Not Do

- It does not expose `phil_secret`.
- It does not expose vault keys.
- It does not expose decrypted registry plaintext.
- It does not load application credentials.
- It does not expose WebAuthn private material.
- It does not expose recovery secrets.
- It does not expose private signing keys.
- It does not create capabilities.
- It does not create session keys.
- It does not create Authorization Packages.
- It does not execute policy, Trust Manager, Proof System, adapters, or transactions.
- It does not persist anything.

## Collection And Review

The optional Protected State View Collector is process-local only.

It stores returned summary view objects for local inspection and testing. It is not persistence, not an audit log, not a credential registry, and not a cache of raw protected state.

Read-only helpers may summarize and group collected views by view, session, outcome, and owner. They do not mutate views or infer authority.

## Public Credential Directory

The public credential directory is a narrower follow-on boundary for enumerating allowlisted public credential descriptors from an unlocked vault.

It is distinct from protected-state summary views and from raw credential records. It may return selected public descriptor fields, but it must not expose credential private material, raw WebAuthn data, raw public keys, encrypted records, registry plaintext, Trust Decisions, or authority.

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_protected_state_view
```

This diagnostic performs explicit WebAuthn verification, reaches `partially_unlocked`, performs the controlled Device Vault unlock against an explicit in-memory test envelope, requests `identity_summary`, and stops.

It remains non-authoritative: secrets remain protected, credentials are not loaded into applications, applications receive no authority, and nothing is persisted.
