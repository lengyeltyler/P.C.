# Bounded Trust Decision Candidates

## Purpose

Phase K.7 creates a bounded Trust Decision candidate from one successful Trust Manager production verification result plus explicit lifecycle, session, application, purpose, and assurance context.

A candidate means only:

> The supplied production assertion evidence and public lifecycle/context data are structurally sufficient for future authoritative Trust Manager review.

It is not an authoritative Trust Decision, capability grant, policy approval, user approval, Authorization Package, Device Vault permission, World ID verification, proof execution, adapter execution, or persistence event.

## Flow

```text
Trust Manager Production Verification Result
  -> explicit credential lifecycle state
  -> explicit session/application/purpose context
  -> candidate eligibility evaluation
  -> Bounded Trust Decision Candidate
  -> Audit Event Draft
  -> optional process-local collection
  -> stop
```

## Inputs

The request must explicitly supply:

- a successful `TrustManagerProductionVerificationResult`
- credential lifecycle status
- credential ID and provider kind
- owner commitment
- session ID and lifecycle state
- application ID
- authentication purpose
- requested assurance
- verification timestamp and expiry
- audit correlation ID
- recovery context, where applicable
- canonical Phil activation context, where applicable

The candidate boundary never loads missing data from Device Vault, encrypted storage, browser APIs, platform UI, credential registries, Proof System, World ID, or adapters.

## Eligibility

K.7 validates that the production verification result is successful, unexpired, not replayed, produced by the production verifier, and correlated with the supplied credential, owner, session, application, purpose, and audit correlation.

Credential lifecycle handling is conservative:

- `active`: eligible for candidate construction, subject to other requirements
- `pending`: unsupported or pending resolution
- `revoked`: ineligible
- `archived`: ineligible
- `rotated`: ineligible for new ordinary use
- `recovery-only`: eligible only in explicit recovery context
- `unknown`: unsupported or pending resolution

Lifecycle status alone does not imply trust.

## Counter Persistence

K.6 reports counter advancement but does not persist counters. K.7 preserves that limitation.

If a successful production verification result has an advanced counter and `counterPersisted = false`, the candidate uses `counter_persistence_required`. This blocks future authoritative Trust Decision activation until a later reviewed milestone implements controlled counter persistence.

K.7 does not mutate credential lifecycle state or persist counters.

Phase K.8 provides that controlled counter persistence boundary. It may attach a non-authoritative counter-resolution artifact to a candidate, but it still does not create an authoritative Trust Decision or grant authority.

Phase K.9 may consume a successful candidate plus a verified counter persistence receipt to create a bounded authoritative Trust Manager decision. The K.9 decision remains Trust Manager authority only; it still does not grant capabilities, approve policy, collect user approval, create Authorization Packages, or allow execution.

## World ID

World ID remains context-specific.

Ordinary runtime Trust Decision candidates do not require or verify World ID. Canonical Phil activation candidates preserve a future `world_id_enrollment` requirement, but K.7 does not verify World ID or include World ID proof data.

## Non-Authority Guarantees

Every candidate explicitly states:

- `productionAssertionVerified = true`
- `credentialLifecycleMutationPerformed = false`
- `counterPersisted = false`
- `activeTrustDecisionCreated = false`
- `capabilityGranted = false`
- `sessionKeyCreated = false`
- `authorizationCreated = false`
- `vaultAccessGranted = false`
- `persisted = false`
- `worldIdVerified = false`

Applications must not consume a candidate as authority. Future authoritative Trust Decision creation requires a separate reviewed milestone with counter/state persistence, policy review, and user approval boundaries.

## Audit And Collection

K.7 may create sanitized Audit Event Drafts and may place candidates into an optional process-local collector.

Audit drafts and candidates may include safe references and summaries such as credential safe reference, provider kind, lifecycle classification, authentication purpose, assurance classification, session/application IDs, candidate outcome, counter status, and audit correlation.

They must not include raw WebAuthn assertion data, signatures, authenticator data, `clientDataJSON`, raw public-key bytes, credential records, vault handles, vault material, private keys, Authorization Packages, session keys, or World ID proof data.

The collector is ephemeral and process-local. It is not persistence and cannot convert candidates into active Trust Decisions.

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_trust_decision_candidate
```

This diagnostic composes controlled session unlock, Device Vault unlock, public credential directory, selected credential public material, Trust Manager verification input, production assertion verification, and bounded Trust Decision candidate construction.

It does not grant capabilities, create an authoritative Trust Decision, create Authorization Packages, persist counters, verify World ID, execute proofs, call adapters, submit transactions, or persist state.
