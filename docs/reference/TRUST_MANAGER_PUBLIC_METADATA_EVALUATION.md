# Trust Manager Public Metadata Evaluation

Public Trust Metadata Evaluation is the first read-only Trust Manager evaluation behavior.

It evaluates explicitly supplied public credential and device metadata only. It does not load credentials, access Device Vault, access encrypted storage, authenticate a user, verify possession, verify signatures, or invoke WebAuthn.

`metadata_sufficient` means only that the supplied public metadata is structurally sufficient to proceed to a future stronger Trust Manager evaluation.

This evaluation does not create a `TrustDecision`, does not grant authority, does not grant capabilities, does not create authorization packages, does not call adapters, and does not persist anything.

Classifications may include:

- `metadata_sufficient`
- `metadata_missing`
- `metadata_malformed`
- `provider_unsupported`
- `credential_status_ineligible`
- `device_status_ineligible`
- `pending_credential_resolution`
- `pending_device_resolution`
- `pending_possession_verification`
- `pending_authenticator_verification`

These classifications are not authentication results and are not proof that a credential or device is cryptographically trusted.

## Ephemeral Collection

Public metadata evaluation collection is process-local and ephemeral. It stores classification results only, performs no credential or device resolution, creates no authority, and persists nothing.

## Read-Only Review Helpers

Review helpers inspect collected classifications only. `metadata_sufficient` is not trust, summaries do not rank credentials or devices, and helpers do not recommend approval.

Review does not mutate collectors, User Session, active capabilities, credentials, devices, or trust state.
