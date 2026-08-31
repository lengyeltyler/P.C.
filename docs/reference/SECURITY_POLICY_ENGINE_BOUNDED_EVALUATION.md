# Security Policy Engine Bounded Evaluation

## Purpose

Bounded Security Policy Evaluation is the first policy behavior in PhilCore. It consumes explicit inputs only:

- a Capability Grant Draft
- a Bounded Trust Evaluation Result
- an explicit Runtime Policy Set
- runtime, application, session, capability, scope, and action context

The result is non-authoritative. It does not grant capabilities, approve users, create authorization packages, execute actions, verify World ID, or persist policy state.

## Flow

```text
Capability Grant Draft
  -> Bounded Trust Evaluation Result
  -> Explicit Policy Rules
  -> Bounded Policy Evaluation Result
  -> Audit Event Draft
  -> Optional Ephemeral Collection
  -> Stop
```

## Rule Precedence

Policy rules are evaluated deterministically. A permissive rule must not override a restrictive rule.

```text
deny
  > require recovery context
  > require World ID enrollment
  > require production possession verification
  > require stronger trust
  > require user approval
  > scope/duration restriction
  > eligible for future authorization
```

## Trust Limitations

The Security Policy Engine preserves bounded Trust limitations:

- fixture-only evidence cannot satisfy production possession requirements
- `eligibleForPolicyReview` is not trust approval
- `providesTrustDecision: false` remains respected
- pending trust resolution must not be treated as complete
- revoked or archived lifecycle evidence cannot proceed as ordinary eligibility
- recovery-only evidence requires explicit recovery context

## World ID Boundary

World ID requirements are context-specific. Canonical Phil activation may require World ID enrollment. Ordinary unlock or Ethereum runtime actions should not require World ID unless an explicit policy and context require it.

Policy results may say `requires_world_id_enrollment`; they must not claim World ID verification. Human uniqueness remains separate from device possession trust and wallet signing.

## Current Non-Goals

This milestone does not load policies from storage, call remote policy services, persist policy results, request user approval, create `CapabilityGrant`, create authorization packages, call Proof System, call adapters, access Device Vault, execute WebAuthn, verify World ID, or modify contracts/schemas.

Phase L.1 adds a separate authoritative Security Policy Engine decision boundary. It consumes an authoritative Trust Decision and an explicit policy set, but it still does not grant capabilities, collect user approval, create Authorization Packages, or allow execution.
