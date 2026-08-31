# Platform User Approval Decision Boundary

## Purpose

Phase L.2 introduces the smallest production-oriented User Approval boundary.

A Platform User Approval Decision means only:

```text
PhilCore accepted an explicit user decision for one exact Trust Decision, Policy Decision, application, action, scope, target, value, session, presentation digest, and validity window.
```

It is not a capability grant, Authorization Package, signing approval, execution approval, session key, proof execution, adapter call, or transaction submission.

## Flow

```text
Authoritative Trust Decision
  -> Authoritative Security Policy Decision requiring approval
  -> exact platform approval request
  -> explicit platform-bound approval artifact
  -> bounded Platform User Approval Decision
  -> sanitized Audit Event Draft
  -> optional process-local collection
  -> stop
```

## Exact Binding

The approval request and artifact bind to exactly one:

- Authoritative Trust Decision
- Authoritative Security Policy Decision
- application
- User Session
- owner commitment
- capability
- action type
- target reference
- value or amount when applicable
- effective scope
- effective duration
- approval surface
- approval challenge/reference
- audit correlation
- validity window

The approval cannot be reused for a different request, target, value, scope, duration, application, session, or presentation digest.

## Presentation Digest

The approval request includes a digest over the exact user-visible action summary. The artifact must bind to the same digest.

Hidden target, value, scope, duration, network, or capability changes after presentation cause rejection.

## Platform Artifact

The artifact is explicit input. It may record:

- approval artifact ID
- approval request ID
- approval surface
- user outcome
- decision timestamp
- presentation digest
- challenge/reference
- session ID
- application ID
- owner commitment
- safe device/provider references
- user-presence/user-verification indicators
- audit correlation
- expiry

It must not contain biometric templates, private keys, raw platform secrets, vault material, credential records, authorization packages, adapter payloads, or transaction payloads.

## Fixture Separation

`developer_fixture` remains separate from production-oriented platform approval.

Fixture artifacts do not create production Platform User Approval Decisions. There is no silent fallback from production surfaces to fixture surfaces.

If native UI APIs are unavailable, Alpha 0 accepts an explicitly labeled in-memory local platform artifact for diagnostics only. It does not claim real operating-system consent.

## Decision Semantics

Approved, denied, cancelled, and expired artifact outcomes can produce bounded decision records when the artifact is otherwise valid.

Only `user_approved` may be eligible for future capability activation review. Denied, cancelled, expired, malformed, replayed, or digest-mismatched artifacts are not eligible.

Every decision must state:

- `capabilityGranted = false`
- `authorizationCreated = false`
- `sessionKeyCreated = false`
- `executionAllowed = false`
- `proofExecuted = false`
- `adapterExecuted = false`
- `transactionSubmitted = false`
- `vaultAccessed = false`
- `worldIdVerified = false`
- `persistedAsAuthority = false`

## Replay And Storage

L.2 includes process-local artifact consumption and an optional in-memory decision store.

These are ephemeral guardrails only:

- no durable replay guarantee
- no durable approval database
- no session capability mutation
- no application-direct authority
- no Authorization Package conversion

## Capability Grant Consumer

The L.3 Authoritative Scoped Capability Grant boundary may consume an approved Platform User Approval Decision as one required input.

Applications must not consume approval decisions directly as authority. A Platform User Approval Decision alone is still not a capability grant, and no direct method may create an Authorization Package from this boundary.

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_platform_user_approval_decision --approval-outcome approve
```

Supported diagnostic outcomes are:

- `approve`
- `deny`
- `cancel`
- `expired`
- `digest_mismatch`

The diagnostic uses explicit in-memory local inputs and does not invoke native UI, store biometric data, call adapters, execute proofs, submit transactions, or persist authority.
