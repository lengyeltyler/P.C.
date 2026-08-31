# Authoritative Scoped Capability Grant Boundary

Status: Current process-local implementation boundary, not the accepted durable
V1 capability contract.

The target `PhilCapabilityGrantV1`, capability ID, epoch, delegation,
revocation, device-approval, authorization-envelope, and adapter bindings are
frozen in
[Phil V1 Secure Identity Architecture](../PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md).
Step 1 did not implement them. This L.3 boundary remains useful evidence but
cannot create durable or adapter authority.

## Purpose

Phase L.3 introduces the smallest active capability boundary.

An Authoritative Capability Grant means only:

```text
PhilCore has granted one application a narrowly scoped runtime capability for one owner, session, capability, scope, restriction set, and validity window.
```

It is not an action authorization, Authorization Package, session key, signing approval, proof execution, adapter execution, transaction submission, or unrestricted wallet authority.

## Flow

```text
Authoritative Trust Decision
  -> Authoritative Security Policy Decision
  -> approved Platform User Approval Decision
  -> exact capability activation request
  -> Authoritative Scoped Capability Grant
  -> optional process-local active session capability state
  -> sanitized Audit Event Draft
  -> stop
```

## Required Gates

Capability activation requires explicit supplied inputs:

- one `AuthoritativeTrustDecision`
- one `AuthoritativePolicyDecision`
- one approved `PlatformUserApprovalDecision`
- current lifecycle snapshot
- current non-secret User Session context
- owner commitment
- session ID
- application ID
- capability name
- effective scope
- effective duration
- target/value/action restrictions
- issue time, expiry, and audit correlation

PhilCore does not load missing values from Device Vault, credential registries, policy storage, adapters, or proof systems in this boundary.

## Binding And Scope

Every grant is bound to exactly one owner, session, application, capability, effective scope, validity window, Trust Decision, Policy Decision, User Approval Decision, and audit correlation.

A grant is not reusable across owners, sessions, applications, capabilities, scopes, or time windows.

Least-privilege restrictions must be preserved:

- `request_transaction_preparation` does not imply `request_transaction_submission`.
- `request_message_signature` does not imply transaction signing.
- `view_transactions` does not imply contract calls.
- `request_contract_call` must preserve target and action restrictions.

## Runtime State

L.3 may create process-local active session capability state.

This state is intentionally narrow:

- it is in-memory only
- it is session-bound
- it can be revoked
- it can expire
- it is cleared by session lock/close semantics
- it does not persist authority
- it does not create session keys
- it does not create Authorization Packages

## Replay, Revocation, And Expiry

L.3 includes process-local replay protection for activation evidence and a process-local grant store.

These are runtime guardrails only:

- no durable replay guarantee
- no durable capability database
- no durable revocation registry
- no adapter authority
- no action authorization

Revocation or expiry invalidates the process-local grant for future consumers. Future durable capability storage would require a separate architecture review.

## Future Consumers

The Authorization Decision Candidate boundary may consume an active capability grant as one input.

The grant must still be paired with an exact action intent and current runtime context before any Authorization Package can be considered. Applications and adapters must not treat a capability grant as executable authority.

The current M.1 consumer creates only an `AuthorizationDecisionCandidate`. It does not assemble `ACTION_UNLOCK`, create `proofInputHash`, create an Authorization Package, execute proofs, sign, issue session keys, call adapters, submit transactions, or persist authority.

Phase M.7 also consumes an active authoritative capability grant as one required input for [Base Authorization Execution Preparation](./BASE_AUTHORIZATION_EXECUTION_PREPARATION_BOUNDARY.md). The grant must remain active, unexpired, unrevoked, and bound to the same owner, session, and application as the finalized Authorization Package. The prepared draft remains unsigned and unsubmitted; the grant is not converted into direct wallet or adapter authority.

Phase M.8 revalidates the same active grant immediately before signing and again before submission. M.8 does not durably decrement, revoke, or exhaust the grant; post-execution durable capability reconciliation remains future work.

Phase M.9A proposes the ERC-4337 Smart Account foundation for future UserOperation preparation. Capability grants remain upstream authority evidence; a Smart Account UserOperation does not replace Trust, Policy, User Approval, Capability Grant, or Authorization Package requirements. See [PhilCore ERC-4337 Smart Account Foundation](./PHILCORE_ERC4337_SMART_ACCOUNT_FOUNDATION.md).

## Negative Guarantees

Every grant must preserve:

- `actionAuthorized = false`
- `authorizationCreated = false`
- `authorizationPackageCreated = false`
- `sessionKeyCreated = false`
- `executionAllowed = false`
- `proofExecuted = false`
- `adapterExecuted = false`
- `transactionSubmitted = false`
- `vaultAccessed = false`
- `worldIdVerified = false`
- `persistedAsAuthority = false`

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_authoritative_capability_activation --approval-outcome approve
```

Supported approval outcomes remain:

- `approve`
- `deny`
- `cancel`
- `expired`
- `digest_mismatch`

Only the approved path creates a scoped process-local active capability grant. Denied, cancelled, expired, malformed, digest-mismatched, replayed, or mismatched evidence creates no grant.
