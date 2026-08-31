# PhilCore Desktop Fresh Authentication

Status: local Alpha fresh-authentication evidence boundary implemented; not production-approved.

Phase: O.4

## Boundary

Fresh authentication evidence is a process-local Runtime artifact used to bind a recent platform-authentication event to a sensitive desktop presentation.

It may include:

- evidence ID;
- identity ID;
- session ID;
- presentation ID;
- presentation digest;
- method classification;
- issue time;
- expiry;
- limitations.

It must not include:

- Keychain values;
- wrapping keys;
- vault keys;
- private keys;
- recovery private keys;
- `phil_secret`;
- proof witnesses.

## Current Method Classification

O.4 classifies the current desktop evidence as:

- `safe_storage_keychain_access` when the production-candidate macOS `safeStorage` adapter is active;
- `developer_fixture` for automated local tests and diagnostics.

Neither classification means Touch ID, Secure Enclave custody, or guaranteed biometric verification.

## Consumption Rules

Fresh evidence is checked when consuming sensitive approval artifacts. It must match:

- selected identity;
- active User Session;
- presentation digest when supplied;
- expiry window.

Missing, stale, mismatched, or digest-unbound evidence is rejected for signing and recovery-sensitive flows.

## Expiry And Lock

Fresh evidence is process-local and expires quickly. Lock, restart, and process teardown invalidate pending evidence and approval authority.

## Production Gaps

Remaining before production:

- reviewed WebAuthn/passkey user-verification path or stronger native LocalAuthentication integration;
- signed and notarized desktop packaging;
- external audit;
- production recovery model acceptance;
- public-network operational controls.
