# Trust Manager Verification Input Boundary

## Purpose

Phase K.5 creates the controlled bridge from one selected credential verification profile and one explicit production authentication request into a bounded Trust Manager verification input.

This is not a Trust Decision, authentication, WebAuthn execution, signature verification, credential loading, Device Vault access, capability authority, or persistence.

## Flow

```text
unlocked User Session
  -> selected credential verification profile
  -> explicit production authentication request
  -> correlation and lifecycle validation
  -> Trust Manager verification input
  -> Audit Event Draft
  -> stop
```

## Input Sources

The bridge requires explicit inputs:

- selected credential verification profile
- selected credential verification handle metadata
- production authentication request
- current lifecycle snapshot
- User Session context
- application ID
- session ID
- owner commitment
- credential ID
- provider ID
- authentication purpose
- challenge reference
- required assurance
- expiry
- audit correlation ID

It does not load missing data from Device Vault, encrypted storage, the credential registry, WebAuthn, World ID, Proof System, or adapters.

## Correlation Rules

The bridge validates:

- profile credential ID matches the authentication request and explicit credential ID
- provider kind and provider ID match
- public-key algorithm supports the requested verification method
- session ID matches lifecycle, User Session context, selected handle, and authentication request
- owner commitment matches User Session context, selected handle, and authentication request
- application ID matches the authentication request
- challenge reference matches
- authentication purpose matches
- selected credential handle is unexpired
- authentication request and challenge are unexpired
- lifecycle state is `unlocked`
- Device Vault and protected-state metadata are present
- credential lifecycle is eligible for the purpose
- recovery-only credentials are used only for explicit recovery purposes
- requested assurance is supported by the selected credential profile

All mismatches are rejected before any verification or trust evaluation.

## Verification Input Allowlist

The constructed input may include only verifier-relevant public material and safe references:

- credential safe reference
- selected profile ID
- selected handle ID
- provider kind and provider ID
- public-key algorithm
- public-key fingerprint
- normalized public verification key required by the future WebAuthn verifier
- challenge reference
- user-presence and user-verification requirements
- public counter metadata
- lifecycle classification
- authentication purpose
- requested assurance
- session/application/owner correlation
- expiry
- audit correlation

It must not include:

- credential record
- Device Vault handle
- raw vault key
- `phil_secret`
- private keys
- encrypted credential blob
- raw assertion response
- raw registration payload
- arbitrary metadata map
- recovery secret
- Authorization Package

## Trust Manager Boundary

Trust Manager receives only the bounded verification input. It does not receive a vault handle, registry plaintext, credential records, or a way to enumerate other credentials.

The fixture consumer introduced with this boundary accepts input shape only. It does not read Device Vault, invoke WebAuthn, mutate User Session, persist input, create a Trust Decision, or return authority.

## Expiry And Invalidation

Verification inputs are:

- process-local
- session-bound
- application-bound
- owner-bound
- credential-bound
- challenge-bound
- purpose-bound
- assurance-bound
- expiry-bound
- non-serializable in the runtime model

Future lifecycle work should invalidate them when the session locks, closes, or the selected credential handle expires. K.5 does not claim durable invalidation without persistence.

The reviewed K.6 bridge is [Trust Manager Production Verification](./TRUST_MANAGER_PRODUCTION_VERIFICATION_BOUNDARY.md). It consumes one bounded verification input plus one explicit WebAuthn assertion and reuses the existing verifier, still without creating a Trust Decision or application authority.

## Audit Behavior

Audit Event Drafts may include credential safe reference, provider kind, algorithm, authentication purpose, session ID, application ID, owner commitment reference, outcome, challenge reference, assurance requirement, and audit correlation.

Audit drafts must not include public key bytes, raw assertion data, credential record fields, vault material, private data, or unrestricted metadata.

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_trust_manager_verification_input
```

This diagnostic composes production WebAuthn verification from explicit test input, partial unlock, controlled vault unlock, public credential directory, selected credential public material, and Trust Manager verification input construction.

It does not invoke WebAuthn UI, perform authentication for authority, create a Trust Decision, expose vault access to Trust Manager, grant capability authority, create Authorization Packages, verify World ID, execute proofs, call adapters, submit transactions, or persist state.
