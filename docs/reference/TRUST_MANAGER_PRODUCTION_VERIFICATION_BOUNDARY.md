# Trust Manager Production Verification Boundary

## Purpose

Phase K.6 allows Trust Manager to consume one bounded `TrustManagerVerificationInput` and one explicitly supplied WebAuthn assertion payload, then reuse the existing production WebAuthn assertion verifier.

The result may state whether the explicit assertion passed or failed configured verification checks for the bounded input. It is not a Trust Decision, authentication for application authority, capability grant, Authorization Package, session mutation, Device Vault access, or persistence.

## Flow

```text
Trust Manager Verification Input
  -> explicit WebAuthn assertion payload
  -> correlation and assertion-shape validation
  -> existing WebAuthn assertion verifier
  -> Trust Manager Production Verification Result
  -> Audit Event Draft
  -> optional process-local collection
  -> stop
```

## Explicit Inputs

The bridge requires:

- one bounded Trust Manager verification input
- one explicit WebAuthn assertion
- expected challenge
- expected origin
- expected RP ID
- previous public sign counter
- verification timestamp and expiry
- audit correlation ID

The bridge does not retrieve assertions, keys, credentials, counters, or metadata from browser APIs, platform UI, Device Vault, encrypted storage, credential registries, networks, Proof System, World ID, or adapters.

## Existing Verifier Reuse

K.6 reuses the existing production WebAuthn assertion verifier from the device identity layer. It does not duplicate cryptographic verification logic.

The bounded verification input supplies the selected credential's normalized public verification material and public counter metadata. The explicit assertion supplies the signed WebAuthn payload. The bridge calls the existing verifier and normalizes its output into Trust Manager evidence form.

## Verification Semantics

A successful result means only:

> The explicitly supplied WebAuthn assertion passed the configured verification checks for this bounded Trust Manager input.

Successful results may include:

- `assertionCryptographicallyVerified = true`
- `challengeBindingVerified = true`
- `originVerified = true`
- `rpIdHashVerified = true`
- `signatureVerified = true`
- user-presence and user-verification flags
- counter assessment
- `productionVerifierUsed = true`

They must also state:

- `trustDecisionCreated = false`
- `capabilityGranted = false`
- `authorizationCreated = false`
- `deviceVaultAccessed = false`
- `credentialLoadedFromVault = false`
- `counterPersisted = false`
- `persisted = false`

Do not call the user trusted or the application authorized based on K.6 output.

## Counter Handling

K.6 reports the existing verifier's counter assessment:

- previous counter
- returned counter
- advanced
- unchanged-zero
- unsupported
- rollback
- clone-suspected

Counter findings are never persisted in K.6. The credential registry is not mutated. Advanced counters may indicate future persistence is required, but that persistence belongs to a later reviewed milestone.

Rollback or clone-suspected outcomes fail or restrict verification according to existing verifier semantics.

## Replay And Collection

The optional `EphemeralTrustManagerVerificationConsumptionStore` prevents reuse of one verification input/assertion combination within the current process.

This replay protection is process-local only. It is not durable production replay protection.

The optional result collector is also process-local. It stores bounded verification results for inspection and tests, not Trust Decisions or authority.

## Trust Decision Boundary

K.6 defines future integration artifacts:

- `TrustManagerVerifiedEvidenceReference`
- `TrustManagerVerifiedEvidenceSummary`
- `TrustManagerTrustDecisionInput`

A successful verification result may become evidence for a future Trust Decision. It is not itself the Trust Decision. Applications cannot consume it as authority.

Phase K.7 consumes successful K.6 evidence to create a bounded Trust Decision candidate. That candidate is still not authoritative; it preserves counter-persistence, policy-review, user-approval, and context-specific World ID requirements for later milestones.

Phase K.8 may persist the verified credential counter through a separate controlled Device Vault/registry boundary. That receipt still does not make the K.6 result or K.7 candidate authoritative.

## Audit Behavior

Audit Event Drafts may include:

- credential safe reference
- provider kind
- algorithm
- authentication purpose
- session/application IDs
- outcome
- counter assessment category
- audit correlation

Audit drafts must not include public key bytes, signature bytes, authenticator data, `clientDataJSON`, vault material, private material, credential records, or raw assertion payloads.

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_trust_manager_assertion_verification
```

This diagnostic composes controlled session unlock, Device Vault unlock, public credential directory, selected credential public material, Trust Manager verification input, and explicit assertion verification.

It does not invoke browser WebAuthn UI, invoke biometrics, access Device Vault from Trust Manager, enumerate credentials, persist counters, create Trust Decisions, grant capabilities, create Authorization Packages, verify World ID, execute proofs, call adapters, submit transactions, or persist state.
