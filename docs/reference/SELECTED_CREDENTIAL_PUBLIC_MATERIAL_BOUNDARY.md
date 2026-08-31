# Selected Credential Public Material Boundary

## Purpose

Phase K.4 introduces a controlled boundary for selecting exactly one credential from the Public Credential Directory and materializing only the verification-ready public data required by a future Trust Manager verification step.

This is not private credential loading, authentication, WebAuthn execution, signature verification, a Trust Decision, credential export, bulk credential access, or application authority.

## Flow

```text
unlocked User Session
  -> Public Credential Directory
  -> select exactly one credential ID
  -> validate unlocked vault/session/owner correlation
  -> materialize allowlisted verification-ready public data
  -> return bounded result and process-local handle metadata
  -> Audit Event Draft
  -> stop
```

## Directory Descriptor vs. Selected Public Material

The Public Credential Directory returns lightweight descriptors for browsing and selection. Selected Credential Public Material is narrower and deeper: it returns one selected credential's bounded verification profile for a later Trust Manager operation.

The selected material is still not the underlying credential record. It must not be created by spreading registry records or returning arbitrary metadata maps.

## Strict Allowlist

Permitted selected-profile fields include:

- credential ID and safe credential reference
- provider kind
- public key algorithm
- public key fingerprint
- verifier-required public verification key material in normalized SPKI hex form
- supported verification method
- credential lifecycle status
- recovery-only designation
- device reference
- owner commitment
- creation timestamp
- public sign-counter metadata when already treated as non-secret
- verification profile version

Every result explicitly states:

- `containsPrivateMaterial = false`
- `containsVaultKey = false`
- `containsPhilSecret = false`
- `containsRawAssertionPayload = false`
- `containsRawRegistrationPayload = false`
- `containsAuthorization = false`
- `grantsAuthority = false`
- `verificationPerformed = false`

## Public Key Handling

The existing production WebAuthn assertion verifier requires the credential public verification key. For this reason, K.4 may include normalized public SPKI key material for one selected WebAuthn credential only.

This public key material is:

- bounded to one selected credential
- represented in one normalized format
- validated for supported algorithm and expected public-key size range
- paired with a fingerprint
- omitted from audit draft details and Alpha shell JSON/text output

K.4 does not expose private keys, symmetric keys, raw WebAuthn assertion payloads, registration payloads, attestation objects, encrypted records, vault keys, or `phil_secret`.

## Supported Operation

The only supported operation is:

- `materialize_selected_credential_public_data`

The request must supply exactly one credential ID. Wildcards, ranges, all-credential selectors, bulk export, and arbitrary registry queries are rejected.

## Validation

Requests require:

- lifecycle state `unlocked`
- `deviceVaultUnlocked: true`
- protected state availability
- valid unlocked vault handle
- unexpired handle
- matching session ID
- matching owner commitment
- matching audit correlation, when supplied
- a matching Public Credential Directory result
- exactly one credential ID
- supported provider kind
- supported lifecycle status
- supported verification algorithm and public material format

Ordinary verification accepts active WebAuthn passkey credentials. Recovery-only credentials require explicit recovery context. Revoked and archived credentials are rejected.

## Opaque Handle And Access Model

K.4 creates bounded process-local verification handle metadata for the selected profile. The handle metadata is not a credential, not storage, not a session capability, and not authority.

The access model is intentionally non-destructive: selected public material may be read more than once during a valid unlocked session. It is bounded by session, owner, credential, audit correlation, and expiry. Future lifecycle work should invalidate selected-material handles on lock, close, vault-handle expiry, or explicit clear.

## Trust Manager Boundary

Future Trust Manager verification may consume either:

- the selected verification profile, or
- the selected verification handle metadata plus an explicit authentication request.

Trust Manager must not receive:

- the vault handle
- registry plaintext
- arbitrary credential records
- private material
- a way to enumerate other credentials

No Trust Decision is made in K.4.

The reviewed K.5 bridge is [Trust Manager Verification Input](./TRUST_MANAGER_VERIFICATION_INPUT_BOUNDARY.md). It converts one selected profile plus one explicit production authentication request into a bounded Trust Manager input without giving Trust Manager Device Vault access or credential enumeration.

## Audit Behavior

Audit Event Drafts may include:

- safe credential reference
- provider kind
- lifecycle status
- session ID
- owner commitment reference
- outcome
- audit correlation
- whether a verification handle was created

Audit drafts must not include public key bytes, raw COSE data, assertion payloads, registration payloads, credential record contents, vault material, private data, or unrestricted metadata.

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_selected_credential_public_material
```

This diagnostic verifies explicit WebAuthn test input, reaches `partially_unlocked`, unlocks an explicit in-memory test vault, lists the Public Credential Directory, selects one credential, materializes bounded public verification material, prints a sanitized profile summary, and stops.

It does not perform authentication for runtime authority, invoke browser WebAuthn UI, execute assertions, make Trust Decisions, create capabilities, create Authorization Packages, call proofs, call adapters, verify World ID, or persist state.
