# Authorization Decision Candidate Boundary

## Purpose

Phase M.1 introduces the first bounded Authorization Engine boundary.

An Authorization Decision Candidate means only:

```text
An active scoped capability grant and one exact action intent are structurally eligible for future Authorization Package construction.
```

It is not an Authorization Package, action authorization, `ACTION_UNLOCK` assembly, `proofInputHash`, proof execution, signature, session key, adapter execution, transaction submission, vault access, or persistent authority.

## Flow

```text
Authoritative Scoped Capability Grant
  -> exact action intent
  -> current lifecycle snapshot and User Session context
  -> action/capability/scope/target/value/duration/network checks
  -> Authorization Decision Candidate
  -> sanitized Audit Event Draft
  -> stop
```

## Required Inputs

The candidate boundary accepts explicit runtime inputs only:

- active `AuthoritativeCapabilityGrant`
- exact action intent
- action type
- lifecycle snapshot
- non-secret User Session context
- owner commitment
- session ID
- application ID
- target, method, value, scope, duration, chain/network context where applicable
- issue time, expiry, and audit correlation

PhilCore does not load credentials, access Device Vault, invoke WebAuthn, call policy/trust engines, create proofs, sign, call adapters, or persist candidate authority in this boundary.

## Action Binding

M.1 creates an action digest preview for bounded runtime comparison only.

The preview is not:

- `ACTION_UNLOCK`
- `proofInputHash`
- a proof public input tuple
- a signature digest
- adapter calldata
- transaction calldata
- executable authority

It exists to show that future Authorization Package construction must bind exact action data, including action type, owner, session, application, required capability, target, method, value, scope, duration, chain/network context, consumer-data reference, validity window, and audit correlation.

## Capability Mapping

The candidate must preserve least-privilege capability mapping:

- `transaction_submission` requires `request_transaction_submission`
- `transaction_preparation` requires `request_transaction_preparation`
- `message_signature` requires `request_message_signature`
- `contract_call` requires `request_contract_call`
- `smart_account_deployment` requires `request_smart_account_deployment`

A preparation capability does not imply submission authority. Read capabilities do not imply write capabilities. A capability grant alone is still not action authorization.

## Scope And Runtime Checks

M.1 rejects candidate creation when supplied inputs widen or mismatch the active capability grant:

- missing, revoked, expired, inactive, or malformed grant
- locked or mismatched session context
- owner, session, application, or audit-correlation mismatch
- requested capability mismatch
- target not permitted
- method not permitted
- value exceeds the grant restriction
- scope widening
- duration beyond grant restriction
- chain or network mismatch
- candidate expiry beyond grant expiry
- changed action digest that requires a fresh user approval
- replayed candidate evidence in the process-local consumption store

These checks are eligibility checks for future package construction only. They do not authorize execution.

## Proof Requirement Classification

The candidate may classify whether proof is expected later:

- `proof_not_required`
- `proof_required_by_policy`
- `proof_required_by_capability`
- `proof_required_by_action`
- `proof_requirement_unresolved`

This classification does not execute the Proof System and does not create `proofInputHash`.

## Ephemeral Stores

M.1 includes optional process-local helpers:

- an authorization candidate consumption store for replay detection
- an in-memory Authorization Decision Candidate store for inspection

These stores are intentionally ephemeral:

- no Device Vault access
- no encrypted registry access
- no durable persistence
- no active capability mutation
- no Authorization Package creation
- no adapter authority

## Future Consumer Preview

The fixture consumer can accept a candidate for future package-construction preview only.

It returns preview data with:

- `authorizationPackageCreated = false`
- `actionUnlockAssembled = false`
- `proofInputHashCreated = false`
- `proofExecuted = false`
- `adapterExecutionAllowed = false`

Production Authorization Package construction remains future work.

## M.2 Package Draft Consumer

Phase M.2 may consume a valid candidate to assemble a bounded `AuthorizationPackageDraft`.

That draft may assemble the locked `ACTION_UNLOCK` public tuple and canonical `proofInputHash`, but it still does not generate a proof, verify a fact, consume a nullifier, authorize an action, call adapters, submit transactions, or persist authority.

## Negative Guarantees

Every candidate must preserve:

- `authorizationPackageCreated = false`
- `actionAuthorized = false`
- `proofInputHashCreated = false`
- `proofExecuted = false`
- `signatureCreated = false`
- `sessionKeyCreated = false`
- `adapterExecutionAllowed = false`
- `transactionSubmitted = false`
- `vaultAccessed = false`
- `worldIdVerified = false`
- `persistedAsAuthority = false`

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_authorization_decision_candidate
```

Supported diagnostic scenarios:

- `exact`
- `capability_mismatch`
- `scope_widening`
- `target_mismatch`
- `value_limit_exceeded`
- `additional_approval_required`

Only the exact scenario creates a bounded candidate. Failure scenarios produce diagnostics only and still do not create Authorization Packages, `ACTION_UNLOCK`, `proofInputHash`, signatures, session keys, adapter calls, transaction submissions, or persisted authority.
