# Trust Manager Bounded Evaluation Results

## Purpose

Bounded Trust Evaluation Results are the first combined Trust Manager result objects. They combine explicit, non-authoritative evidence:

- public credential/device metadata classification
- fixture-only possession evaluation
- explicit credential lifecycle status
- request, session, application, credential, device, and owner-commitment correlation

The result is still non-authoritative.

## Flow

```text
Trust Evaluation Draft
  -> Public Trust Metadata Evaluation Result
  -> Fixture-Only Possession Evaluation Result
  -> Explicit Credential Lifecycle Status
  -> Bounded Trust Evaluation Result
  -> Audit Event Draft
  -> Optional Ephemeral Result Collection
  -> Stop
```

## Meaning

A successful bounded result means only:

```text
The supplied non-authoritative evidence is structurally sufficient to proceed to future policy review or stronger production verification.
```

It does not mean the user is production-authenticated, the credential is trusted, the device is fully trusted, policy approved the action, user approval occurred, a capability was granted, authorization was created, execution is allowed, World ID enrollment occurred, or human uniqueness was proven.

## Lifecycle Boundary

Credential lifecycle eligibility is not the same as trust.

- `active` may be eligible for future policy review.
- `pending` and `unknown` require credential resolution.
- `revoked`, `archived`, and `rotated` are ineligible.
- `recovery-only` is ineligible for ordinary actions, but may proceed only in an explicit recovery context.

## Fixture Boundary

Fixture-only possession evidence remains fixture-only. It may show that explicit test fixture checks passed, but it does not perform browser/platform WebAuthn, production possession verification, production authentication, counter persistence, credential loading, vault access, or storage access.

## World ID Boundary

World ID human-uniqueness enrollment is separate from device/credential trust. Missing World ID enrollment is not a Trust Manager failure for ordinary runtime requests.

If the bounded evaluation context is canonical Phil activation, the result may set `requiresWorldIdEnrollment: true`. It must not claim that World ID was verified.

## Non-Goals

This result does not create a Trust Decision, policy decision, user approval, `CapabilityGrant`, authorization package, proof, adapter execution, persistence, or contract/schema behavior.
