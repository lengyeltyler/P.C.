# O.42.1 Packaged WebAuthn and iPhone Readiness

Readiness: **A. Platform WebAuthn still blocked**.

## Packaged validation

The local package contains Electron 41.10.3 and preserves:

- RP ID `recovery.philcore.localhost`;
- origin `https://recovery.philcore.localhost:18443`;
- context isolation;
- renderer sandboxing;
- protected-window DevTools exclusion;
- disabled crash upload;
- no external network service.

An ad-hoc package starts in a clean isolated user-data directory and shows
the secure origin. It has no WebAuthn keychain entitlement and is
intentionally reported as `PACKAGED_IDENTITY_MISMATCH`.

A Developer ID package was statically signed with the exact Team ID,
bundle, hardened runtime, and proposed entitlement. All 32 code objects
passed strict signature verification. The launch was then rejected by
macOS because no eligible provisioning profile was embedded. That package
was not notarized and is not retained as a successful release artifact.

The disposable flow
`O42_1_DISPOSABLE_PLATFORM_WEBAUTHN_TEST_ONLY` is implemented. It creates
and asserts only in memory, requires UV, reads BE/BS from authenticator
data, returns no raw credential ID, and never stores PhilCore authority.
It was not executed because the stable signed identity did not pass launch.

## iPhone Role 1

The present desktop service binds only `127.0.0.1`. On an iPhone,
`.localhost` resolves to the iPhone, not the Mac. No LAN listener, TLS
exception, browser security bypass, QR endpoint, or unreviewed companion
server was added.

More importantly, Apple describes Safari/iPhone passkeys as stored in and
synced through iCloud Keychain. WebAuthn defines a sync-capable credential
as backup eligible (`BE=true`), while PhilCore's exact Consumer Platform
policy requires `BE=false` and `BS=false`.

Authoritative references:

- [Apple Passkeys](https://developer.apple.com/passkeys/)
- [Apple “Meet passkeys”](https://developer.apple.com/videos/play/wwdc2022/10092/)
- [WebAuthn Level 3 backup flags](https://www.w3.org/TR/webauthn-3/#sctn-credential-backup)

Therefore iPhone Safari cannot currently be accepted as Role 1. A future
review may consider another Mac, a policy-compliant external security key,
or a native device-bound design such as an independently specified
Secure-Enclave/App-Attest architecture. None is silently substituted here.

## Preflight V3

Preflight V3 separately reports:

- Primary Mac Role 0: `BLOCKED`;
- iPhone Role 1: `BLOCKED`;
- Complete Standard ceremony: `BLOCKED`.

Role 0 is not created while Role 1 is nonviable. The real O.42 ceremony did
not resume.
