# O.42.1 macOS Identity and Certificate Migration

## Frozen application identity

| Property | Value |
| --- | --- |
| Bundle identifier | `com.philcore.desktop.localalpha` |
| Team ID | `B342738S82` |
| Application identifier | `B342738S82.com.philcore.desktop.localalpha` |
| WebAuthn keychain group | `B342738S82.com.philcore.desktop.localalpha.webauthn` |
| Wildcards | none |
| Cross-application group | none |
| Application sandbox change | none |

The top-level Developer ID app alone receives the application identifier
and WebAuthn keychain group. Helpers do not. Existing Chromium hardened
runtime allowances are unchanged.

[Apple documents](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups)
the `keychain-access-groups` entitlement as the list of groups available to
an app. Apple also documents that an application identifier is the Team ID
plus bundle ID.

## Origin envelope schema 2

The encrypted loopback TLS certificate envelope now binds:

- bundle identifier;
- Team ID;
- WebAuthn keychain group;
- a SHA-256 identity binding;
- the canonical RP and origin;
- the exact public certificate fingerprint.

First install creates one certificate. Exact-identity restart reuses it.
An application update that can decrypt the existing envelope preserves the
same certificate. A legacy or changed identity may be rebound only when the
credential record count is exactly zero, and the same certificate/private
key are re-encrypted rather than regenerated.

If any recovery credential exists, an identity mismatch fails closed. An
expired certificate with credentials also fails closed. Corruption,
fingerprint mismatch, inaccessible safeStorage, an invalid schema, or an
invalid credential count never triggers silent regeneration.

Owner-specific local observations are withheld from this public export.
The original observations remain in unchanged engineering history outside this
clean export. Repository transition has not yet occurred. No fresh physical
acceptance or protected-state verification is claimed by this document.
