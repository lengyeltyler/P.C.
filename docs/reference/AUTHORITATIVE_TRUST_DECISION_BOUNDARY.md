# Authoritative Trust Decision Boundary

## Purpose

Phase K.9 introduces the smallest authoritative Trust Manager decision boundary.

An authoritative Trust Decision means only:

> PhilCore Trust Manager has accepted one bounded trust request for one session, credential, application, purpose, assurance level, owner commitment, audit correlation, and validity window.

It is authoritative only inside the Trust Manager boundary. It is not application authority.

## Required Evidence Chain

A decision requires explicit supplied inputs:

- one successful production Trust Manager WebAuthn verification result
- one bounded Trust Decision candidate
- one verified credential counter persistence receipt, or accepted zero-counter receipt
- current credential lifecycle status
- current User Session lifecycle snapshot
- explicit owner, session, application, credential, provider, purpose, assurance, issue time, expiry, and audit correlation

The boundary does not load missing inputs from Device Vault, encrypted storage, browser APIs, World ID, Proof System, adapters, or applications.

## Binding

Every decision is bound to exactly one:

- production verification result
- Trust Decision candidate
- counter persistence receipt
- credential
- session
- owner commitment
- application
- authentication purpose
- assurance request
- audit correlation
- validity window

The decision is not reusable across another session, credential, application, purpose, owner, challenge, capability, action, or time window.

## What The Decision May State

A valid decision may state:

- `trustDecisionCreated = true`
- `productionAssertionVerified = true`
- `credentialCounterCommitted = true`, or accepted zero-counter semantics
- `credentialLifecycleEligible = true`
- `sessionContextEligible = true`
- `assuranceSatisfied = true`
- `validForSpecifiedPurposeOnly = true`

It must also state:

- `capabilityGranted = false`
- `policyApproved = false`
- `userApprovalCollected = false`
- `authorizationCreated = false`
- `sessionKeyCreated = false`
- `executionAllowed = false`
- `worldIdVerified = false`
- `vaultMaterialExposed = false`
- `persistedAsAuthority = false`

## Counter And Replay

For advanced WebAuthn counters, the persisted counter must match the verified returned counter. For authenticators with accepted zero-counter behavior, the receipt must explicitly use zero-counter semantics.

K.9 includes process-local evidence consumption only. This rejects reuse of the same evidence chain within the current process, but it is not a durable replay or revocation system.

## World ID

World ID remains context-specific.

Ordinary runtime authentication does not require World ID automatically. Canonical Phil activation preserves an unresolved World ID requirement until a real enrollment verification integration exists. K.9 does not verify World ID.

## Future Consumer

The Security Policy Engine may later consume a bounded authoritative Trust Decision as one input to a separate policy decision.

Applications must not consume the decision directly as authority. No direct method may convert it into a capability grant, session key, Authorization Package, proof execution, adapter call, or transaction submission.

Phase L.1 introduces that separate Security Policy Engine decision boundary. The policy decision may accept the Trust Decision as evidence, but it still cannot grant capabilities, collect user approval, create Authorization Packages, or allow execution.

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_authoritative_trust_decision
```

This diagnostic uses explicit local/test storage. It does not expose raw credential material, vault material, registry plaintext, raw assertion material, or real user data.
