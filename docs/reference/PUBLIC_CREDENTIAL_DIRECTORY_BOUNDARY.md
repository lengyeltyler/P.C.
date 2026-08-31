# Public Credential Directory Boundary

## Purpose

Phase K.3 introduces a controlled public credential directory for an unlocked Device Vault.

The directory may enumerate explicitly permitted public credential descriptors. It is not credential loading, authentication, Trust Manager evaluation, credential lifecycle mutation, or application authority.

## Flow

```text
unlocked User Session
  -> valid unlocked vault handle
  -> explicit credential-directory request
  -> controlled registry read
  -> sanitized public credential descriptors
  -> Audit Event Draft
  -> stop
```

## Public Descriptors vs. Credential Records

A public credential descriptor is an allowlisted summary object. It is not the original credential record and must not be constructed by spreading internal registry records.

Permitted descriptor fields include:

- credential ID or safe public reference
- display label
- provider kind
- public key algorithm identifier
- public lifecycle classification
- device reference
- created timestamp
- last-used timestamp, when already stored as safe metadata
- recovery-only marker
- ordinary-evaluation eligibility classification
- recovery-evaluation eligibility classification
- user-verification capability metadata
- public counter metadata when already treated as non-secret
- public key fingerprint/reference, not raw public key material

Every descriptor must explicitly state:

- `containsPrivateMaterial = false`
- `containsRawAssertionData = false`
- `containsVaultKeys = false`
- `containsPhilSecret = false`
- `providesTrustDecision = false`
- `grantsAuthority = false`

## Supported Operations

Initial operations:

- `list_credentials`
- `get_credential_descriptor`
- `summarize_credentials`

There is no generic registry read operation.

Supported filters:

- provider kind
- lifecycle status
- device ID
- recovery-only
- ordinary-use eligibility

Requests are bounded by a conservative result limit. Over-limit requests are rejected instead of silently exporting a large directory.

## Lifecycle Classification

The directory may classify public lifecycle status:

- `active`
- `pending`
- `recovery-only`
- `rotated`
- `revoked`
- `archived`
- `unknown`

It may expose conservative metadata such as `eligibleForOrdinaryEvaluation`, `eligibleForRecoveryEvaluation`, and `requiresStrongerVerification`.

These are classifications only. They are not Trust Manager decisions and must not be treated as authentication, approval, or authority.

## Privacy Boundary

The descriptor construction model is allowlist-first.

It must not expose:

- credential private material
- raw WebAuthn assertions
- registration payloads
- attestation objects
- authenticator data
- `clientDataJSON`
- assertion signatures
- encrypted credential blobs
- vault keys
- `phil_secret`
- recovery secrets
- PINs, passwords, or passphrases
- key-derivation material
- unrestricted metadata maps
- complete registry plaintext
- raw public keys unless a later reviewed runtime need justifies it

## Runtime API Boundary

Applications must access the public credential directory only through the PhilCore Runtime API.

Applications do not receive:

- the vault handle
- the registry object
- the registry plaintext
- private credential material
- Trust Manager authority
- Authorization Packages

Future Trust Manager evaluation may consume a selected public credential reference through a separate reviewed boundary.

That separate reviewed boundary is [Selected Credential Public Material](./SELECTED_CREDENTIAL_PUBLIC_MATERIAL_BOUNDARY.md). The directory remains descriptor-only; verifier-ready public material is materialized only after selecting exactly one credential and passing the K.4 validation boundary.

## Access Model

Directory reads normally do not consume the vault handle permanently, because read-only credential directory access must remain practical during an unlocked session.

Access is still bounded, audited, and validated against:

- unlocked lifecycle state
- `deviceVaultUnlocked: true`
- protected state availability
- owner commitment
- session ID
- audit correlation, when supplied
- unexpired handle
- supported operation and filters

## Collection

The optional Public Credential Directory Result Collector is process-local only.

It stores sanitized directory results for local inspection and testing. It is not persistence, not a credential registry, not a Trust Manager cache, and not an authority source.

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_public_credential_directory
```

This diagnostic verifies explicit WebAuthn test input, reaches `partially_unlocked`, unlocks an explicit in-memory test vault, lists public credential descriptors, prints a sanitized summary, and stops.

It does not load private credential material, execute assertions, make Trust Decisions, create capabilities, create Authorization Packages, call proofs, call adapters, or persist state.

The related `production_selected_credential_public_material` diagnostic composes this directory with a single selected-credential materialization request. It prints a sanitized verification-profile summary and does not print public key bytes.
