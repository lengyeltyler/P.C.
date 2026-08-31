# Capability Activation Candidates

## Purpose

Capability Activation Candidates are non-authoritative objects derived from a correlated chain of runtime artifacts:

```text
Capability Grant Draft
  -> Bounded Trust Evaluation
  -> Bounded Policy Evaluation
  -> User Approval Request Draft
  -> Approved User Decision Fixture
  -> Capability Activation Candidate
  -> Audit Event Draft
  -> Optional Ephemeral Collection
  -> Stop
```

A candidate means only that the supplied artifacts are structurally correlated and may proceed to a future capability activation step. It is not an active capability.

## Boundary Rules

- Candidates are not `CapabilityGrant` objects.
- Candidates do not mutate User Session active capabilities.
- Candidates do not issue session keys.
- Candidates do not create authorization packages.
- Candidates do not invoke biometrics, WebAuthn, World ID, Device Vault, Proof System, adapters, contracts, or storage.
- Candidates are not persisted.
- Fixture approval is not production consent.

## Limitation Preservation

Candidates must preserve Trust Manager and Security Policy Engine limitations, including fixture-only evidence, missing production authentication, scope restrictions, duration restrictions, recovery context, production possession requirements, and future authorization requirements.

Restrictive policy outputs must not be widened by a candidate.

## World ID Boundary

World ID remains context-specific. Ordinary runtime capability requests do not automatically require World ID. Canonical Phil activation with unresolved World ID enrollment must not produce an activation candidate until a future real integration verifies that requirement.

## Future Work

Production capability activation now begins with the L.3 Authoritative Scoped Capability Grant boundary after authoritative trust, policy, and approved platform user approval have been established.

That grant is still not action authorization. Authorization Package creation, session-key issuance, proof execution, adapter execution, transaction submission, durable capability persistence, and audit persistence remain separate future milestones.
