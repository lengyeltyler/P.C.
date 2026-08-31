# O.42.1 Platform WebAuthn Root Cause and Electron Compatibility

Canonical phase: **O.42.1 macOS Electron Platform WebAuthn Enablement,
Packaged Identity Repair, and Ceremony Resume**.

Classification:
`LOCAL_INTERACTIVE_DESKTOP_WEBAUTHN_COMPATIBILITY_AND_ENROLLMENT_REPAIR`.

## Proven cause

O.42 was a runtime compatibility/configuration failure, not a user denial.
Every prompt that appeared was authorized. No WebAuthn creation prompt was
shown because:

1. the installed and packaged runtime was Electron 39.8.10;
2. that runtime has no `app.configureWebAuthn` API;
3. Electron did not add the macOS Touch ID WebAuthn authenticator until the
   Electron 41.5.0 backport / Electron 42.0.0 release;
4. Electron 41.5.0 had a macOS prompt crash fixed in 41.6.0;
5. the O.42 startup sequence did not configure WebAuthn before `app.ready`;
6. the app signature did not include the required keychain access group.

The exact pinned update is Electron **41.10.3**, the current patched release
in the minimum compatible major. The declaration and lock resolution are
exact. No Chromium feature flag or certificate bypass is used.

Authoritative references:

- [Electron 42 WebAuthn announcement](https://www.electronjs.org/blog/electron-42-0)
- [Electron 41.5.0 feature backport](https://releases.electronjs.org/release/v41.5.0)
- [Electron 41.6.0 prompt crash fix](https://releases.electronjs.org/release/v41.6.0)
- [Electron app API](https://www.electronjs.org/docs/latest/api/app)

The installed 41.10.3 type declarations independently state that
`configureWebAuthn` must be called before readiness, that the credential is
device-bound, and that the configured group must be present in the
`keychain-access-groups` entitlement.

## Startup behavior

`platform-webauthn.cjs` executes synchronously at module startup, before
`app.whenReady()`. It produces exactly one safe result:

- `SUPPORTED_AND_CONFIGURED`;
- `SUPPORTED_CONFIGURATION_FAILED`;
- `UNSUPPORTED_RUNTIME`;
- `UNSUPPORTED_PLATFORM`;
- `PACKAGED_IDENTITY_MISMATCH`.

Configuration is refused when it is late, the bundle is not
`com.philcore.desktop.localalpha`, or the signing Team ID is not
`B342738S82`. The sole credential group is:

`B342738S82.com.philcore.desktop.localalpha.webauthn`

The unpackaged runtime can exercise the API surface, but it is explicitly
not a stable production credential identity.

## Current remaining blocker

The real Developer ID launch proved that a matching provisioning profile is
also mandatory. macOS rejected the executable with
`No matching profile found` when the restricted application/keychain
entitlements were signed without an embedded eligible profile. Static
`codesign --verify` passed, demonstrating why launch validation is required.

No matching local profile is installed. Signed packaging now fails closed
unless `PHILCORE_DESKTOP_PROVISIONING_PROFILE` identifies an exact,
unexpired profile for the Team ID, application identifier, and sole
WebAuthn group. The profile is validated and embedded before signing.
Ad-hoc builds use a separate entitlement file with no WebAuthn group and
therefore cannot masquerade as a production credential identity.

No Apple account or developer-portal mutation was attempted.
