# PhilCore iPhone Companion — Local Alpha

This native SwiftUI application is the O.43 foundation for PhilCore Role 1.
It is intentionally narrow: it creates and uses a device-bound P-256
recovery credential, pairs with PhilCore Desktop over an authenticated local
channel, and displays exact recovery approvals.

The local-alpha application identity is:

- bundle identifier: `com.philcore.ios.companion.localalpha`;
- Apple Team ID: `B342738S82`;
- keychain access group:
  `B342738S82.com.philcore.ios.companion.localalpha`;
- minimum target: iOS 17.0;
- signing: Apple Development, selected locally in Xcode.

No provisioning profile, certificate, private key, protected enrollment
record, or pairing artifact belongs in this repository.

Open `PhilCoreCompanion.xcodeproj` after a full Xcode installation is
available. The project uses automatic development signing, but it does not
perform App Store, TestFlight, or Apple Developer portal operations on its
own. Simulator credentials are software-backed, disposable, marked
`simulatorOnly`, and cannot produce a production descriptor.

Secure Enclave private keys are non-exportable and stored through the
Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and
`userPresence | privateKeyUsage`. Signing therefore requires Face ID,
Touch ID, or the device passcode. Metadata is safe public data only.
Erasing the device destroys the key. App deletion alone is **not** treated as
cryptographic deletion: iOS Keychain items can survive uninstall and may be
available again to a reinstall signed by the same Team ID with the same bundle
and access-group identity. Users must use the in-app deletion control and
complete desktop invalidation/rotation before uninstalling. Encrypted device
backups and iCloud Keychain do not migrate `ThisDeviceOnly` items. Replacement
uses a new key and an incremented generation through the desktop
recovery-rotation flow.
