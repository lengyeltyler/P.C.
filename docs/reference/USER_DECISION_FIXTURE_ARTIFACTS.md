# User Decision Fixture Artifacts

## Purpose

User Decision Fixture Artifacts are local/test-only records of an explicit fixture outcome against a `UserApprovalRequestDraft`.

Allowed fixture outcomes are:

- `approve`
- `deny`
- `cancel`
- `expired`

An `approve` fixture means only that a local test fixture selected approve. It is not production user consent.

## Flow

```text
User Approval Request Draft
  -> Explicit Local Fixture Outcome
  -> User Decision Fixture Artifact
  -> Audit Event Draft
  -> Optional Ephemeral Collection
  -> Stop
```

No capability activation, authorization package, signing, proof, adapter execution, transaction submission, storage write, or persistence follows from this artifact.

## Boundary Rules

- Artifacts are fixture-only and process-local.
- Artifacts do not invoke UI, biometrics, WebAuthn, World ID, Device Vault, Proof System, adapters, contracts, or storage.
- Artifacts do not authenticate the user.
- Artifacts do not grant capability authority.
- Artifacts do not create authorization packages.
- Artifacts must preserve correlation with the approval draft, bounded policy result, bounded trust result, capability grant draft, application, session when available, owner commitment when available, and audit correlation.
- Secret-shaped, private-material, production-consent, authority, authorization, and execution fields are rejected or redacted by the runtime guardrails.

## Production Consent Boundary

Production-oriented user-decision capture is defined separately in [Platform User Approval Decision Boundary](./PLATFORM_USER_APPROVAL_DECISION_BOUNDARY.md).

Fixture artifacts remain local/test-only and must not be treated as production platform approval.

This reference does not change contracts, proof schemas, Device Vault behavior, Trust Manager behavior, Security Policy Engine behavior, Authorization Engine behavior, or Runtime API execution.
