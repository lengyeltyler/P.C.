# Runtime API Validation Facade

The Runtime API validation facade is a developer-facing scaffold for the PhilCore Runtime API shape.

It is validation-only. It wraps conceptual Runtime API requests into runtime request envelopes, runs the validation-only intake pipeline, and returns runtime result envelopes.

Facade results may include an audit event draft. Audit event drafts are local objects that describe the request shape validation outcome. They are not persisted, not signed, not proof of execution, and not evidence of authorization.

It is not the production Runtime API implementation.

It does not:

- authorize actions
- evaluate Trust Manager behavior
- evaluate Security Policy Engine behavior
- sign messages or transactions
- create authorization packages
- call the Proof System
- call adapters
- read or write storage
- mutate sessions, registries, or runtime state
- persist audit events

Use this facade to stabilize request shapes before real runtime behavior is wired. Validation success means only that the request shape is well formed; it does not mean PhilCore approved the requested action.

Audit event drafts exist to prepare the future Audit Log pipeline. They should be treated as draft records only until a real audit persistence boundary is implemented and reviewed.

## Runtime-Only Audit Draft Collector

The validation facade may optionally receive an in-memory Audit Draft Collector. When present, newly created audit event drafts are placed into that collector after validation shape checks complete.

The collector is intentionally ephemeral and process-local. It is not the future Audit Log, it does not persist records, and it must not touch Device Vault, encrypted storage, proof generation, adapters, Trust Manager, Security Policy Engine, or Authorization Engine behavior.

Its purpose is to validate Runtime API flow before audit persistence is introduced. Collection means only that a draft object was held in memory; it does not mean the request was authorized, executed, signed, proven, submitted, or stored.

## Ephemeral User Session Context

The validation facade may optionally receive a User Session context. At this stage the context is non-secret runtime metadata used only to correlate request validation and audit event drafts with a session.

User Session context does not unlock the vault, authenticate the user, evaluate trust or policy, authorize actions, call proof code, call adapters, or persist session state. It must not contain `phil_secret`, raw vault keys, raw private keys, or unrestricted signing authority.

## Redaction Guardrails

Runtime metadata and audit draft details include defensive redaction guardrails for obvious secret-shaped field names such as `phil_secret`, private keys, seed phrases, passwords, passphrases, vault keys, signing keys, and recovery secrets.

These guardrails are hygiene only. They are not complete production DLP, secret scanning, or permission enforcement. Root secrets should never be supplied to runtime metadata in the first place.

Audit event draft details are redacted before future persistence work is introduced, but redaction does not authorize, approve, execute, sign, prove, submit, or store any request.

## Ephemeral User Session Store

The validation facade may optionally receive an Ephemeral User Session Store. The store is process-local only and holds at most one User Session context snapshot for request and audit correlation.

The store does not authenticate, unlock the vault, persist session state, authorize actions, evaluate trust or policy, call proof code, call adapters, or execute requests. A directly supplied User Session context takes precedence over the store snapshot for facade requests.

## Capability Grant Drafts

For structurally valid capability requests, the validation facade may return an ephemeral Capability Grant Draft. A draft means only that the request shape is valid and may proceed to future Trust Manager, Security Policy Engine, and user approval evaluation.

Capability Grant Drafts are not grants. They provide no authority, do not mutate active session capabilities, are not persisted, cannot be executed, and must not be converted into `CapabilityGrant` without a future reviewed authorization path.

## Capability Grant Draft Collector

The validation facade may optionally receive an in-memory Capability Grant Draft Collector. The collector is process-local and ephemeral, stores draft objects only, and is not a capability registry.

Collected drafts provide no authority, are not persisted, do not mutate User Session capabilities, and are not converted into `CapabilityGrant`.

## Capability Draft Review Helpers

Capability draft review helpers provide read-only summaries and groupings for collected `CapabilityGrantDraft` objects. They can inspect counts, sessions, applications, capabilities, statuses, expired drafts, and pending drafts.

Review helpers do not mutate collectors or drafts, do not recommend approval, do not infer trust or policy, do not create authority, and do not convert drafts into `CapabilityGrant`.

## Authoritative Capability Activation

The facade may expose the L.3 Authoritative Scoped Capability Grant path when supplied explicit authoritative Trust, Policy, and approved Platform User Approval decisions. This is no longer validation-only, but the behavior is still bounded to process-local capability activation.

A scoped capability grant is not action authorization. The facade does not create Authorization Packages, session keys, proofs, adapter calls, transactions, vault access, World ID verification, or durable persistence. Optional grant storage is process-local only and exists so future Authorization Engine work can inspect active capabilities.
