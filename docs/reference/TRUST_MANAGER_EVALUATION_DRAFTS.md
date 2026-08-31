# Trust Manager Evaluation Drafts

Trust Evaluation Drafts are validation-only runtime objects.

They mean only that a future Trust Manager request is structurally valid and contains enough public/runtime metadata to proceed to later evaluation.

They are not trust decisions. They do not mean a device is trusted, a credential is trusted, a user is authenticated, WebAuthn succeeded, policy approved, a capability was granted, authorization was created, or execution is allowed.

Drafts may contain:

- capability grant draft references
- application and session correlation
- owner commitment, when already known
- credential IDs and lifecycle status references
- provider kind references
- public device metadata
- requested trust level references
- redacted runtime metadata

Drafts must not contain:

- `phil_secret`
- vault keys
- private keys
- signing keys
- WebAuthn private material
- raw assertion secrets
- passwords or passphrases
- recovery secrets
- active trust decisions
- authorization packages

Credentials are not loaded. WebAuthn is not invoked. Device Vault and encrypted storage are not accessed.

Real Trust Manager evaluation begins in a later milestone.

## Ephemeral Draft Collector

The in-memory Trust Evaluation Draft collector is process-local and ephemeral.

It stores draft objects only. Drafts are not trust decisions, do not resolve credentials, do not invoke WebAuthn, are not persisted, and do not mutate User Session or active capabilities.

## Read-Only Review Helpers

Review helpers inspect draft collections only. Summaries are not trust decisions, grouping does not imply security ranking, and no credentials or devices are resolved.

Review helpers do not mutate collectors, drafts, User Session, or active capabilities.
