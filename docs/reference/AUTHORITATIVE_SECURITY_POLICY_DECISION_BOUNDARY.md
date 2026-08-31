# Authoritative Security Policy Decision Boundary

## Purpose

Phase L.1 introduces the smallest authoritative Security Policy Engine decision boundary.

An authoritative Security Policy Decision means only:

> PhilCore Security Policy Engine evaluated one bounded request against one explicitly supplied policy set and issued a policy result for that exact request context.

It is authoritative only inside the Security Policy Engine boundary. It is not application authority.

## Flow

```text
Authoritative Trust Decision
  -> explicit capability/action request
  -> explicit policy set
  -> deterministic rule evaluation
  -> Authoritative Security Policy Decision
  -> Audit Event Draft
  -> optional process-local collection
  -> stop
```

No capability grant, user approval, Authorization Package, proof, adapter call, signing operation, or transaction submission follows automatically.

## Required Inputs

The request must explicitly supply:

- an authoritative Trust Decision
- a capability request, capability draft, or intent reference
- an explicit policy set and version
- current User Session lifecycle snapshot
- owner, session, application, capability, action, target, scope, duration, value, purpose, assurance, issue time, expiry, and audit correlation

L.1 does not load policies from storage and does not infer hidden rules.

## Rule Precedence

Rules are evaluated deterministically. A permissive rule never overrides an applicable deny or unresolved requirement.

```text
deny
  > require recovery context
  > require World ID enrollment
  > require production authentication
  > require stronger trust
  > require user approval
  > target/value/scope/duration restrictions
  > allowed for user approval
  > allowed for capability activation review
```

## Decision Semantics

A valid decision may state:

- `policyDecisionCreated = true`
- `trustDecisionAccepted = true`
- `rulesEvaluated = true`
- `effectiveScope`
- `effectiveDurationSeconds`
- `effectiveValueLimit`
- `effectiveTargetRestrictions`
- `requiresUserApproval`
- `eligibleForCapabilityActivationReview`

It must also state:

- `capabilityGranted = false`
- `userApprovalCollected = false`
- `authorizationCreated = false`
- `sessionKeyCreated = false`
- `executionAllowed = false`
- `proofExecuted = false`
- `adapterExecuted = false`
- `worldIdVerified = false`
- `persistedAsAuthority = false`

## World ID

World ID remains context-specific.

Canonical Phil activation produces `requires_world_id_enrollment` until a future real uniqueness verification integration exists. Ordinary runtime actions do not require World ID automatically.

## Replay And Storage

L.1 includes optional process-local evidence consumption and decision collection. These are ephemeral runtime guardrails only:

- no durable replay guarantee
- no durable policy database
- no persistent revocation model
- no application-direct authority

A future production storage boundary must be reviewed before any durable policy-state claims are made.

## Future Consumers

The Platform User Approval boundary may consume a policy decision that requires or allows explicit user approval.

The L.3 Authoritative Scoped Capability Grant boundary may consume a policy decision as one required input, together with an authoritative Trust Decision, approved Platform User Approval Decision, lifecycle snapshot, and exact activation request.

Applications must not consume the decision directly as authority. The policy decision alone still cannot create a capability grant, user approval, Authorization Package, proof execution, adapter execution, or transaction submission.

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_authoritative_policy_decision
```

This diagnostic uses local/demo fixtures only. It does not expose raw credential material, vault material, registry plaintext, raw assertion material, or real user data.
