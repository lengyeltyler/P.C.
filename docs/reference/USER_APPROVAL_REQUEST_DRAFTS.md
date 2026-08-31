# User Approval Request Drafts

## Purpose

User Approval Request Drafts are presentation artifacts derived from bounded policy results. They mean only:

```text
The request has reached a state where explicit human approval may be required.
```

They do not mean the user approved, the request is authorized, a capability is granted, execution is allowed, trust is established, a signature was created, or a transaction was submitted.

## Flow

```text
Capability Grant Draft
  -> Bounded Trust Evaluation
  -> Bounded Policy Evaluation
  -> User Approval Request Draft
  -> Audit Event Draft
  -> Optional Ephemeral Collection
  -> Stop
```

## Boundary Rules

- Drafts contain public, redacted, user-presentable information only.
- Drafts preserve Trust Manager and Security Policy Engine limitations.
- Drafts may preserve scope or duration restrictions from policy.
- Drafts may disclose fixture-only evidence, missing production authentication, recovery context, or future World ID enrollment requirements.
- Drafts do not invoke UI, biometrics, WebAuthn, Device Vault, Proof System, adapters, or storage.
- Drafts do not collect consent or represent a user decision.

## Approval Surfaces

Approval surfaces are conceptual only:

- `desktop`
- `mobile`
- `browser_extension`
- `hardware_confirmation`
- `recovery_surface`
- `developer_fixture`
- `unsupported`

No platform prompt or UI is implemented by this boundary.

## Production Approval Boundary

Production-oriented platform approval is defined separately in [Platform User Approval Decision Boundary](./PLATFORM_USER_APPROVAL_DECISION_BOUNDARY.md).

Request drafts still do not collect a user decision, create authority, or invoke native UI.

## World ID Boundary

World ID enrollment requirements remain separate from ordinary approval. A draft may disclose that canonical activation requires World ID enrollment, but it must not claim World ID was verified.

## Current Non-Goals

This milestone does not implement user decisions, authentication, capability grants, authorization packages, execution, persistence, production WebAuthn, World ID verification, contract changes, or schema changes.
