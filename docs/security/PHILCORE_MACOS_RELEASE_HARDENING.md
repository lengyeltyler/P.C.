# PhilCore macOS Release Hardening

Status: Phase O.6 local Alpha.

O.6 prepares PhilCore Desktop for local macOS Alpha distribution. It does not submit to Apple, notarize an app, enable public networks, or grant production approval.

## Hardened Runtime And Entitlements

Signed release candidates use `apps/philcore-desktop/build/entitlements.mac.plist`.

Entitlement review:

- `com.apple.security.cs.allow-jit`: required for Electron/Chromium runtime compatibility.
- `com.apple.security.cs.allow-unsigned-executable-memory`: required for Electron/Chromium runtime compatibility.
- `com.apple.security.cs.disable-library-validation`: required for Electron runtime/native-module compatibility review.
- App sandbox: not enabled in O.6.
- Network client/server: not requested for local Alpha.
- Keychain access groups: not requested.
- User-selected files/downloads: not requested.

Unsigned local Alpha builds are clearly labeled unsigned. Signed builds require `PHILCORE_DESKTOP_SIGNING_IDENTITY`; missing credentials fail closed.

## Notarization

`npm run desktop:notarize-check` validates whether external credential references are present. It does not upload.

`npm run desktop:notarize` refuses unless explicitly approved and remains non-operational in O.6. No Apple credentials are committed or requested.

## Packaged Security

Package verification checks renderer isolation, CSP, navigation blocking, preload allowlisting, proof binary hashes, secret-like files, public-network disablement, and production approval status.

## Logging And Crash Policy

Packaged logging is sanitized by policy. Logs must not contain `phil_secret`, private keys, wrapping keys, vault keys, recovery keys, proof witnesses, decrypted registries, Apple credentials, full passphrases, or unrestricted signed payloads.

Remote crash upload is not enabled. OS-level crash dumps may contain process memory; O.6 does not claim otherwise.

## User-Presence Review

Decision:

- `safeStorage` is sufficient for local encrypted key custody and local Alpha convenience unlock.
- Stronger user-presence evidence is required before public-network signing or recovery.
- Native LocalAuthentication/Keychain access-control integration is preferred before Base Sepolia.
- WebAuthn user verification remains a strong candidate for fresh authentication.
- Hardware-backed recovery remains recommended for production-grade recovery.

Touch ID is not claimed in O.6 unless a future native implementation provides direct user-presence evidence.

## Current Release Decision

Local Alpha distribution: acceptable for controlled local testing.

Base Sepolia Beta: blocked.

Production: blocked.
