# O.43 Native iPhone Companion Implementation and Readiness

> Historical phase record (2026-07-31). Later source and a narrow
> physical-device disposable-key observation supersede several readiness
> statements below. See
> [`docs/security/SECURE_ENCLAVE_VALIDATION_STATUS.md`](../security/SECURE_ENCLAVE_VALIDATION_STATUS.md)
> for the current, bounded status. This record is preserved rather than
> rewritten as if later validation had occurred during O.43.

## 1. Phase result

- Canonical phase: **O.43 Native PhilCore iPhone Companion Foundation and
  Secure Enclave Recovery Credential**
- Classification: `LOCAL_ONLY_NATIVE_IOS_COMPANION_IMPLEMENTATION`
- Result: source, deterministic fixtures, desktop transport, static-verifier
  changes, and synthetic tests implemented; Apple build and physical-device
  gates remain blocked by the local development environment
- Public mutations: `ZERO`
- Push performed: no

This phase does not authorize a production credential ceremony. No production
Role 1 credential or recovery signature was created.

## 2. Baseline

- Repository: `<repository-root>`
- Branch: `codex/device-identity-v1`
- Initial HEAD: `c81deff878906cfa38443abfc8ca6ef03c68c916`
- Initial tracked worktree: clean
- Upstream: `origin/main`; local branch was 139 commits ahead at the baseline
  check
- Fetch, pull, merge, rebase, and reset: not performed
- O.20 through O.42.1 documentation and evidence: reviewed
- Existing desktop Runtime, recovery-enrollment host, bridge, renderer,
  entitlements, packaging, and O.39 fixtures: reviewed

Unchanged V1 source SHA-256:

| Contract | SHA-256 |
| --- | --- |
| Account | `39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a` |
| Factory | `59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9` |

Initial V2 runtime Keccak-256:

| Contract | Initial runtime hash |
| --- | --- |
| Verifier | `0x665910b9989f3b83c3f025314fb127755d5abfc46e66ee386fbcbbfefc864dd7` |
| Account | `0x4681ca917e3b5c3fff72bb6020f3fb278a43ab893beb05e36865b50422f64519` |
| Factory | `0x15eca82e16f99f3ea5d9f8443871fc059bb050a8f30856d017be49d0e97c0d95` |

No security discrepancy was found. The expected verifier hash changed only
after the reviewed native Role 1 verifier-kind implementation.

## 3. Native iOS app

- Project:
  `apps/philcore-ios-companion/PhilCoreCompanion.xcodeproj`
- Language/UI: Swift and SwiftUI
- Recommended build tool: stable Xcode 26.6 with Swift 6.3; the project
  currently uses Swift language mode 5
- Minimum iOS target: iOS 17.0
- Bundle identifier: `com.philcore.ios.companion.localalpha`
- Apple Team ID: `B342738S82`
- Version: `0.1.0 (43)`
- Keychain access group:
  `$(AppIdentifierPrefix)com.philcore.ios.companion.localalpha`
- App Store/TestFlight identity: explicitly deferred

Implemented areas:

- welcome and device status;
- disposable credential test;
- camera-based QR scanning;
- request validation and fingerprint comparison;
- explicit user-confirmation control;
- encrypted desktop pairing;
- recovery-approval safety boundary;
- enrolled public metadata and generation status;
- credential deletion control;
- foreground invalidation.

The repository includes unit and UI test targets. The UI test walks the
Status, Pair, Recovery, and Settings safety-critical surfaces.

The current Mac has Command Line Tools only. `xcodebuild` cannot load an iOS
SDK, Simulator, or this Xcode project, so no simulator or physical build is
claimed. The checked-in screenshots are clearly marked synthetic renderings,
not simulator captures:

- `docs/reference/images/o43/iphone-small-status-synthetic.png`
- `docs/reference/images/o43/iphone-large-pairing-synthetic.png`

Their modeled sizes are 393 × 852 and 430 × 932. Actual small/large simulator
models must be recorded after Xcode installation.

## 4. Secure Enclave credential

### API and algorithm

The app uses Security.framework to create an EC P-256 private key. On a
physical device the creation attributes include:

```text
kSecAttrTokenIDSecureEnclave
kSecAttrAccessibleWhenUnlockedThisDeviceOnly
kSecAttrSynchronizable = false
SecAccessControl: privateKeyUsage | userPresence
```

The key signs exactly 32-byte digests with
`ecdsaSignatureDigestX962SHA256`. Public X9.63 P-256 material may be exported;
the private key may not.

The app separately evaluates
`LocalAuthentication.deviceOwnerAuthentication`, which allows biometric
approval or device-passcode fallback, and supplies the approved `LAContext`
to the Keychain signing operation. No biometric data enters PhilCore.
Cancellation and denial are distinct application failures. Moving the app
out of the foreground invalidates the context and cancels pending pairing
transport.

### Simulator and disposable behavior

The Simulator fallback is a software-backed, non-synchronizable P-256 key
tagged:

```text
O43_DISPOSABLE_IOS_SECURE_ENCLAVE_RECOVERY_TEST_ONLY
```

It is marked `simulatorOnly=true` and `secureEnclaveBacked=false`. Production
descriptor construction rejects it, as does the Solidity policy. A physical
disposable test uses Secure Enclave but remains in a disposable enrollment
state.

Generation starts at 1. Replacement requires a new key and an incremented
generation. The exact generation is bound into pairing, custody commitment,
descriptor, and recovery configuration.

No disposable key was created on this Mac because no iOS runtime or physical
iPhone was available. Therefore key creation, restart retention, device
restart, biometric signing, non-exportability, and deletion are implemented
but not physically validated. Production readiness remains blocked.

### Reinstall, backup, and migration

App uninstall is not accepted as cryptographic deletion because Keychain
items can survive uninstall. Before uninstall, the user must delete the
credential inside the app and invalidate or rotate the desktop descriptor. A
reinstall signed by the same Team and access group may regain a surviving
item.

`ThisDeviceOnly` and explicit non-synchronization prevent migration through
iCloud Keychain or restoration to another device. Device replacement uses a
new generation and the normal two-surviving-factor rotation ceremony. Device
erase destroys the Secure Enclave key.

## 5. Recovery protocol

- Role: `1`
- New verifier kind: `4`, `NATIVE_DEVICE_P256`
- Descriptor version: `1`
- Recovery domain:
  `keccak256("PHILCORE_NATIVE_DEVICE_P256_ROLE1_V1")`
- Outer O.37.4 recovery envelope: version `2`, unchanged
- Recovery configuration: version `3`, unchanged
- Exact threshold: 2-of-3
- Valid bitmaps: `3`, `5`, `6`
- Validator exclusion: preserved

The descriptor binds:

- account and security version;
- Role 1 and verifier kind 4;
- P-256 public-material hash;
- credential-identifier commitment;
- exact application identity;
- device-custody commitment;
- exact local-approval policy;
- optional App Attest commitment;
- credential generation;
- Secure Enclave requirement;
- simulator classification.

The exact application identity is:

```text
PHILCORE_IOS_NATIVE_ROLE1_V1|B342738S82|com.philcore.ios.companion.localalpha
```

The exact local-approval policy is:

```text
PHILCORE_LOCAL_APPROVAL_V1|DEVICE_OWNER_AUTHENTICATION|FOREGROUND_ONLY|EXACT_DIGEST
```

The public-material commitment is:

```text
keccak256(abi.encode(
  keccak256("PhilCoreV2NativeDeviceP256PublicMaterial(bytes32 qx,bytes32 qy)"),
  qx,
  qy
))
```

The factor commitment is:

```text
keccak256(abi.encode(
  nativeDescriptorTypeHash,
  every normalized descriptor field in canonical order
))
```

The native evidence is exactly 640 bytes and contains the descriptor,
factor commitment, P-256 coordinates, and P-256 ECDSA `r` and `s`. The
signature covers the existing exact recovery digest, which already binds the
chain, account, action, account/security version, current recovery
configuration and epoch, requested change, validity window, and request ID.

Deterministic fixtures cover all three exact pairs and negative cases for
application identity, Team ID, bundle ID, key, generation, account, recovery
epoch, simulator/software classification, local-approval policy, pairing
transcript, and role substitution. Historical O.39 fixtures are preserved.

## 6. Solidity impact

Only `PhilCoreV2StaticAuthorityVerifier` changes. The account and factory
sources, runtime hashes, ABIs, and storage remain unchanged.

| Contract | Runtime bytes | Current runtime Keccak-256 |
| --- | ---: | --- |
| `PhilCoreV2StaticAuthorityVerifier` | 14,625 | `0xa1936c0e1a5ad05b5e894cb8575d38e264d5f0827098398217b63ad32eab62b6` |
| `PhilCoreV2MinimalAccountV2` | 13,811 | `0x4681ca917e3b5c3fff72bb6020f3fb278a43ab893beb05e36865b50422f64519` |
| `PhilCoreV2MinimalAccountFactoryV2` | 18,317 | `0x15eca82e16f99f3ea5d9f8443871fc059bb050a8f30856d017be49d0e97c0d95` |

The verifier is below EIP-170's 24,576-byte runtime limit. All three creation
artifacts are below EIP-3860's 49,152-byte limit. The verifier remains
stateless with zero storage slots. No contract ABI or account storage layout
changes.

The new verifier branch:

- accepts native P-256 Role 1 for exact bitmaps 3 and 6;
- preserves the existing primary + offline path, bitmap 5;
- rejects unsupported descriptor versions and kinds;
- pins the application and approval policy hashes;
- requires Secure Enclave classification and rejects simulator
  classification;
- checks the descriptor commitment and exact P-256 signature.

The focused verifier/account/factory/O.39/O.43 lifecycle run completed with
45 passing tests. A fresh isolated compile reproduced all three runtime hashes
exactly. Pinned Slither 0.10.4 found zero High or Critical issue in the changed
verifier; the reviewed Medium/Informational results are recorded in the O.43
security analysis.

No deployment was attempted. The verifier's new hash is local readiness
evidence, not a deployed-address claim.

## 7. Pairing

### Transport

The initial transport is direct private-LAN HTTP with application-layer
authenticated encryption. Desktop selects one RFC1918 IPv4 interface and
will not bind loopback, `0.0.0.0`, or a public address. The endpoint is one
narrow POST path with a 96 KiB body limit.

Direct IP was selected over Multipeer Connectivity for the first
cross-platform Electron/iOS implementation. Bonjour is not required.
`NSAllowsLocalNetworking` and a local-network usage description are declared.
The macOS firewall may ask the user to allow incoming connections for the
signed PhilCore Desktop app.

### QR and session

The QR contains safe public, expiring enrollment material only:

- protocol version;
- high-entropy 256-bit session ID;
- five-minute expiry;
- private local endpoint;
- desktop ephemeral P-256 ECDH public key;
- 256-bit challenge;
- PhilCore identity commitment;
- account/security versions;
- recovery epoch and requested generation;
- exact application identity.

It contains no private authority, recovery secret, desktop private key,
validator key, or long-lived bearer token.

Both sides canonicalize one newline-delimited transcript. The comparison
fingerprint is its first 96 SHA-256 bits, displayed as six groups of four
hexadecimal digits.

Encryption uses ephemeral P-256 ECDH, HKDF-SHA256 with the transcript hash as
salt, and AES-256-GCM with direction-specific associated data. Sessions are
single-use, expire after five minutes, and are canceled explicitly or when
the iOS app backgrounds. The desktop verifies the encrypted response,
transcript signature, descriptor fields, application identity, custody,
generation, and independence aliases before encrypted local persistence.

Desktop and deterministic cross-platform tests pass. Physical iPhone
validation remains blocked.

## 8. Mobile interface

- Welcome/status explains independent Role 1, non-execution authority,
  on-device private key, and exact 2-of-3.
- Device status shows support, local approval, app version, public
  fingerprint, enrollment state, generation, and last local test.
- Pairing scans a QR, validates it, displays the anti-substitution
  fingerprint, requires an explicit exact-match toggle, supports expiry and
  cancellation, and reports success only after the desktop acknowledgement.
- Recovery approval reserves a classified human-readable surface for account,
  network, action, recovery epoch, expiry, and exact digest. Opaque or
  unclassified requests are rejected by design.
- Settings shows only safe public metadata and provides deletion.
- SwiftUI supplies Dynamic Type, safe areas, light/dark adaptation, and
  standard accessibility behavior. Critical copy and scanner cancellation
  have explicit accessibility labels.

Remaining UX work is evidence-gated: actual small and large simulator
screenshots, VoiceOver traversal, permission-prompt flow, keyboard focus,
extreme Dynamic Type, physical camera scanning, local-network permission,
Face ID/passcode prompts, and background/foreground transitions.

## 9. Apple signing and physical installation

Environment inspection found:

- one `Developer ID Application` identity for Team `B342738S82`;
- no `Apple Development` identity;
- no iOS development provisioning profile;
- no full Xcode installation;
- no available iOS Simulator tooling;
- no connected iPhone.

Developer ID Application signing is for macOS distribution and cannot sign an
iPhone development build. The iOS project is configured for automatic
development signing with Team `B342738S82`, but no signing or developer-portal
operation has been attempted.

### Exact next step: install the build environment

On the Mac:

1. Install the current stable Xcode 26.6 from the Mac App Store. Do not select
   an Xcode beta for this gate.
2. Launch Xcode once.
3. Accept the license and allow Xcode to install its requested iOS platform
   components.
4. Open
   `apps/philcore-ios-companion/PhilCoreCompanion.xcodeproj`.
5. Stop there and report either **“Xcode installed and project opened”** or
   the exact visible error.

Do not paste an Apple ID password, two-factor code, certificate private key,
provisioning-profile contents, iPhone passcode, or any other secret into
Codex.

After the project opens, the next automated gate is an unsigned Simulator
build/test. Only after it passes should the user connect an iPhone. Team
selection, automatic-signing effects, device registration, Developer Mode,
trust prompts, and the disposable biometric ceremony must be reviewed before
each user action. Automatic signing may create or update a development
certificate, provisioning profile, and registered-device association in the
Apple developer account; that portal-side mutation requires explicit user
approval first.

TestFlight, App Store submission, release archive distribution, and a final
production bundle identity are deferred.

## 10. App Attest assessment

Decision:

```text
DEFERRED_OPTIONAL_ENROLLMENT_ATTESTATION
```

App Attest can provide server-validated evidence that an attestation key
belongs to a legitimate instance of a registered app on supported Apple
hardware. It requires App ID capability configuration, an Apple service call
during attestation, server-side validation, environment management, and
support/failure handling. It therefore adds Apple-account, online-service,
privacy, and availability dependencies.

O.43 does not claim Apple hardware authenticity merely from a public key or
descriptor boolean. The current verifier proves configured membership,
policy bindings, and exact signature validity.

A future acceptable design may validate App Attest once during enrollment
and commit the reviewed result into `appAttestCommitment`. The recovery event
must remain independently verifiable with the P-256 public key and must not
depend on Apple network availability. Unsupported devices or Apple service
failure must fail closed for attested enrollment without disabling an
already-valid offline recovery ceremony.

Apple references:

- [Establishing your app's integrity](https://developer.apple.com/documentation/DeviceCheck/establishing-your-app-s-integrity)
- [Preparing to use App Attest](https://developer.apple.com/documentation/DeviceCheck/preparing-to-use-the-app-attest-service)
- [`DCAppAttestService.isSupported`](https://developer.apple.com/documentation/devicecheck/dcappattestservice/issupported)
- [`NSAllowsLocalNetworking`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowslocalnetworking)
- [Xcode support and current releases](https://developer.apple.com/support/xcode)

## 11. Security

The detailed threat matrix is in
`docs/security/O43_NATIVE_IPHONE_SECURITY_AND_THREAT_ANALYSIS.md`.

Summary:

- private-key export: no export path; hardware non-exportability still needs
  physical proof;
- iCloud sync: explicitly disabled;
- biometric handling: LocalAuthentication result and approved context only;
  no biometric data is read or stored;
- malicious QR: strict URI/schema/version/private-IP/expiry/binding checks;
- hostile LAN: selected interface, narrow endpoint, size limit,
  application-level authenticated encryption, stable errors, and no request
  logging;
- replay: single-use session and expiry;
- logs/crash data: no secret payload logging; Electron crash upload remains
  disabled; no iOS crash SDK added;
- screenshots: synthetic public data only;
- known unmitigated Critical findings: none in implemented source/synthetic
  gates;
- known unmitigated High findings: none in implemented source/synthetic gates.

The absence of a known High/Critical source finding is not physical
validation. The unexecuted Apple gates are explicit blockers.

## 12. Readiness

| Area | Classification | Reason |
| --- | --- | --- |
| Native iOS foundation | `BLOCKED` | full Xcode, SDK build, simulator tests, and display validation not available |
| Secure Enclave Role 1 | `BLOCKED` | physical key creation, approval, retention, non-exportability, restart, and deletion not run |
| Desktop pairing | `BLOCKED` | protocol and desktop tests pass, but native build and physical LAN flow are unvalidated |
| Recovery ceremony | `BLOCKED` | production credential prohibited; post-enrollment mobile recovery transport remains foundation-only |

These classifications are deliberately conservative. The exact next
operational step is the Xcode installation/open-project sequence in section 9.

## 13. Build, test, files, and stop boundary

### Repeatable local commands after full Xcode is installed

List available destinations:

```sh
xcodebuild \
  -project apps/philcore-ios-companion/PhilCoreCompanion.xcodeproj \
  -scheme PhilCoreCompanion \
  -showdestinations
```

Run simulator tests without signing:

```sh
xcodebuild test \
  -project apps/philcore-ios-companion/PhilCoreCompanion.xcodeproj \
  -scheme PhilCoreCompanion \
  -destination 'platform=iOS Simulator,name=<installed small iPhone>' \
  CODE_SIGNING_ALLOWED=NO
```

Repeat with one installed larger iPhone Simulator. Record exact model,
runtime, appearance, and accessibility settings. Physical build commands and
archive steps are intentionally withheld until signing effects are reviewed
with the user.

### Main deliverables

- iOS Xcode project, SwiftUI app, QR scanner, credential manager,
  LocalAuthentication manager, unit tests, and UI tests;
- native descriptor SDK and deterministic cross-platform fixtures;
- desktop private-interface LAN host, encrypted descriptor store, QR helper,
  bridge, renderer, recovery-state integration, and tests;
- static-verifier native P-256 path and Solidity tests;
- protocol, security analysis, synthetic screenshots, readiness report, and
  machine-readable evidence.

Machine-readable evidence:

- `config/cryptography/O43_NATIVE_IPHONE_RECOVERY_FIXTURES.json`
- `config/solidity/O43_NATIVE_IPHONE_IMPLEMENTATION_EVIDENCE.json`

### Stop boundary

Confirmed:

- no public deployment;
- no public transaction;
- no Sepolia or external RPC access;
- no external bundler submission;
- no public funds moved;
- no production account deployed;
- no production credential or recovery signature created;
- no production secret committed;
- no private Secure Enclave key exported;
- no Apple Developer portal mutation;
- no TestFlight or App Store action;
- no push.
