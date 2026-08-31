# Credential Counter Persistence Boundary

## Purpose

Phase K.8 introduces the smallest controlled mutation boundary needed after a successful production WebAuthn verification and bounded Trust Decision candidate:

```text
Successful Trust Manager Production Verification Result
  -> Bounded Trust Decision Candidate with counter_persistence_required
  -> validate current stored credential counter
  -> update only the selected credential counter
  -> verify owner/session/credential/audit binding
  -> produce Counter Persistence Receipt
  -> Audit Event Draft
  -> stop
```

This boundary does not create an authoritative Trust Decision, grant capabilities, create session keys, create Authorization Packages, run policy or user approval, verify World ID, execute proofs, call adapters, or submit transactions.

## Mutation Scope

Exactly one credential ID is targeted.

The only credential field K.8 may mutate is the selected credential's `signCount`. It must not mutate credential lifecycle status, labels, public keys, private material, transport metadata, other credentials, User Session active capabilities, or application authority.

The mutation uses the existing encrypted Device Identity registry storage path. The decrypted registry is used only inside the helper and is never returned to applications or callers.

## Counter Rules

K.8 reuses the existing WebAuthn counter semantics reported by K.6:

- returned counter greater than stored counter: eligible for persistence
- returned counter equal to zero with `unchanged-zero`: accepted without mutation
- returned counter lower than stored counter: rejected
- rollback or clone-suspected result: rejected
- unsupported counter behavior: represented explicitly and not persisted
- stale expected stored counter: rejected

A successful counter update never decreases the stored counter.

## Stale Write And Atomicity

The current encrypted registry storage abstraction supports read and write, but not a true atomic compare-and-swap operation.

K.8 therefore implements the narrowest safe approximation currently available:

- validate expected stored counter
- optionally validate the encrypted registry hash supplied by the caller
- load through the existing authenticated encrypted store
- rewrite only the selected credential counter
- save through the existing encrypted store
- reload and verify the persisted counter

This is not claimed to be full multi-process atomicity. A future production storage layer should provide a real compare-and-swap or transactional write primitive before authoritative Trust Decisions depend on counter persistence.

## Receipt

A successful receipt may include:

- receipt ID
- credential safe reference
- previous stored counter
- persisted counter
- counter behavior classification
- registry hash before/after
- registry audit count before/after
- persistence timestamp
- owner/session/application/audit correlation
- storage backend classification
- integrity verification status

The receipt must explicitly state:

- `counterPersisted`
- `trustDecisionCreated = false`
- `capabilityGranted = false`
- `authorizationCreated = false`
- `privateMaterialExposed = false`
- `registryPlaintextExposed = false`

It must not include credential records, private keys, public-key bytes, raw assertion payloads, vault keys, registry plaintext, encrypted registry blobs, or vault material.

## Replay Model

K.8 uses an optional process-local replay store. The chosen retry model is conservative rejection: once an operation ID is consumed in the current process, a retry is rejected as replayed.

Retries must never increment or mutate the counter a second time incorrectly.

## Candidate Resolution

K.8 adds a non-authoritative counter-resolution artifact:

```text
Bounded Trust Decision Candidate
  -> Counter Persistence Receipt
  -> TrustDecisionCandidateCounterResolution
```

The resolution artifact says the counter requirement was satisfied and attaches a receipt reference. It still does not create an active Trust Decision, grant a capability, create authorization, or persist authority.

Phase K.9 may consume the receipt and counter-resolution artifact to create a bounded authoritative Trust Manager decision. The receipt itself remains a counter persistence artifact and must not be treated as application authority.

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_credential_counter_persistence
```

This diagnostic uses explicit local/test encrypted registry fixtures. It does not touch real user data.
