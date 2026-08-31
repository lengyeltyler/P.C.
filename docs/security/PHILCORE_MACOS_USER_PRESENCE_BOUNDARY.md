# PhilCore macOS User-Presence Boundary

Status: Phase O.8.

## Selected Model

PhilCore uses a minimal Swift helper built on macOS `LocalAuthentication`. The helper is main-process only and is invoked through a fixed path with bounded JSON stdin. The renderer cannot invoke it directly.

Rejected for O.7:

- native Node/Electron module, because it adds rebuild and dependency risk;
- WebAuthn platform credential, because the desktop RP/origin and enrollment model need a separate design;
- Secure Enclave key custody claims, because O.7 does not implement that custody model.

## Evidence

Fresh-auth evidence binds:

- identity;
- session;
- action/purpose;
- presentation digest;
- provider;
- macOS policy;
- issue time;
- expiry;
- audit correlation through the existing approval workflow.

Evidence never contains biometric data, raw authentication material, Keychain secrets, private keys, vault keys, recovery keys, `phil_secret`, or proof witnesses.

## Classification

`device_owner_authentication` is reported as `device_owner_authentication_verified` because macOS does not disclose the exact factor used by the broad policy.

`device_owner_authentication_with_biometrics` may be reported as `touch_id_biometric_verified` when that stricter policy succeeds. O.7 does not require that stricter policy by default.

`safe_storage_keychain_access` remains a local Alpha protection signal, but it does not satisfy release-candidate signing when native user presence is required.

## Failure Rules

- cancellation prevents signing;
- stale evidence is rejected;
- evidence from another identity, session, or presentation is rejected;
- helper hash mismatch is rejected;
- unsupported platform or missing helper fails closed in release-candidate mode;
- passphrase fallback is explicit and audited.

## Manual Test Matrix

Manual macOS testing should cover:

- Touch ID available;
- Touch ID success under biometric-only policy;
- user cancellation;
- device password fallback under broad device-owner policy;
- no biometric enrollment;
- screen locked;
- multiple macOS user sessions.

Automated tests use a fixture provider and must not claim real biometric execution.

O.8 added `npm run desktop:user-presence:manual-evidence`, which invokes the
same main-process provider boundary and writes only sanitized evidence metadata.
The 2026-07-16 machine run successfully evaluated
`device_owner_authentication`; macOS did not disclose the satisfying factor, so
Touch ID is not claimed. Cancellation, expiry, replay, presentation-digest,
identity/session/action mismatch, and renderer-boundary cases remain covered by
the fixture-backed security tests. A human operator did not separately attest
that the prompt was visibly observed, and the evidence says so.
