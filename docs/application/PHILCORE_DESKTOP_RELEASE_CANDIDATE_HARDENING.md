# PhilCore Desktop Release-Candidate Hardening

Status: Phase O.9 completed for a guarded Developer ID signed, notarized,
stapled trusted-tester artifact. Distribution to testers has not occurred.

O.8 repaired Electron framework sealing, added explicit inner-to-outer signing,
and proved strict signature validity before and after ZIP extraction. It did not
perform Developer ID signing, notarization, stapling, or trusted distribution.

## Scope

O.8 keeps the desktop app local-only while preparing the next signed release-candidate path. It does not enable public Starknet, Ethereum L1, Base, bundler, paymaster, or production asset behavior.

## Package Profiles

| Profile | Purpose | Signing | Notarization | Public network |
| --- | --- | --- | --- | --- |
| `local_alpha_unsigned` | Local Alpha testing | none | none | disabled |
| `local_alpha_adhoc` | Same-machine package testing | ad-hoc | none | disabled |
| `release_candidate_signed` | Developer ID signed tester candidate | external Developer ID required | optional explicit command | disabled |
| `release_candidate_notarized` | Notarized tester candidate | external Developer ID required | real Apple notarization required | disabled |
| `production` | Production distribution | disabled | disabled | disabled |

The bundle identifier remains `com.philcore.desktop.localalpha` through O.7. This avoids silent Keychain or app-data migration during local Alpha. A production identifier decision must be made before public notarized distribution.

## Native User Presence

O.7 selects a small Swift `LocalAuthentication` helper instead of a third-party native Node module. The helper receives only:

- request version;
- operation name;
- a user-facing reason;
- an allowlisted macOS policy.

It returns only a bounded outcome classification. It does not receive or return private keys, Keychain item names, vault records, biometric templates, proofs, UserOperations, or arbitrary commands.

Automated tests use a fixture provider. Real Touch ID or device-owner authentication must be exercised manually with:

```bash
npm run desktop:user-presence:build
npm run desktop:user-presence:diagnose -- --prompt
```

O.7 does not claim Secure Enclave custody. It reports Touch ID only when the requested policy is biometric-only and the macOS API succeeds. The default broad policy is reported as device-owner authentication.

The O.8 manual command is `npm run desktop:user-presence:manual-evidence`.
It writes sanitized safe metadata under `apps/philcore-desktop/release/evidence/`.
Success under the broad policy does not reveal whether biometrics or password
fallback satisfied macOS, and therefore must not be labeled Touch ID.

## Signing And Notarization

Developer ID signing requires an external identity:

```bash
PHILCORE_DESKTOP_SIGNING_IDENTITY="Developer ID Application: ..." npm run desktop:package-signed
```

The identity must resolve uniquely in the active keychain. The signed path uses
the hardened runtime and timestamping and fails closed for missing or ambiguous
identities. Credentials and certificate material never belong in repository files.

Notarization requires both explicit approval and an externally configured
`notarytool` keychain profile. After an accepted result, stapling and Gatekeeper
assessment remain separate guarded commands. No O.8 manifest claims those steps.

## O.8 Sealing Root Cause And Order

The custom packager used `fs.cpSync` without `verbatimSymlinks`. Node rewrote
Electron framework links such as `Versions/Current -> A` into absolute links to
the repository's `node_modules/electron` tree. Inspection of the failed bundle
confirmed those absolute targets and `codesign` rejected the framework as
unsealed. No unexpected root file caused the failure.

Packaging now preserves relative symlinks, removes broken/debris links and
extended metadata before signing, normalizes custom executable permissions,
finalizes embedded metadata after standalone tools are signed, signs nested
Mach-O objects and bundles deepest-first, signs the application last, verifies,
creates the ZIP, extracts it, and verifies again. Nothing mutates the app after
the top-level signature.

Entitlements are assigned narrowly: standalone tools receive an empty plist;
Electron helper apps receive JIT and unsigned-executable-memory allowances;
ad-hoc Electron helpers additionally disable library validation because ad-hoc
signatures have no shared Team ID and otherwise cannot map the Electron framework;
Developer ID helpers retain library validation because they share the supplied team;
the top-level Electron app additionally receives the reviewed library-validation
exception. Frameworks receive no application entitlement set.

Notarization is disabled by default and requires a separate explicit command plus external credentials. The project must never commit Apple certificates, API keys, app-specific passwords, or Team credentials.

## Distribution Policy

Local Alpha packages are for invited testers using disposable test data only. Meaningful assets are not allowed. Testers should verify the ZIP checksum from the release manifest before opening the app. Unsigned packages may be blocked by Gatekeeper.

Bug reports and diagnostic exports must use sanitized output only. No private keys, vault keys, recovery keys, `phil_secret`, proof witnesses, or biometric data should be included.

## Known Limitations

- Unsigned local Alpha is not a trusted macOS distribution artifact.
- External audit remains incomplete.
- ACP-0002 remains proposed.
- Base Sepolia Beta remains blocked.
- The local O.5 workflow still includes local fixture infrastructure, which keeps package size larger than a future production package.

## O.9 Apple Trust Procedure

Run `npm run desktop:apple-readiness` first. A non-ready result is an intentional
fail-closed outcome. With exactly one externally selected Developer ID identity,
`npm run desktop:package-signed` rebuilds from a fresh unsigned assembly, signs
with hardened runtime and secure timestamps, and verifies authority, Team ID,
timestamps, and nested signatures.

Notarization requires an externally configured `notarytool` keychain profile and
`PHILCORE_DESKTOP_NOTARIZE_APPROVED=1`. Rejection must be retained and diagnosed;
stapling is prohibited unless the saved live result is `Accepted`. After
acceptance, run the stapling and Gatekeeper commands, then
`npm run desktop:prepare-trusted-tester`. That final command validates the
working app and extracted ZIP before creating the controlled release directory.

O.9 Apple trust evidence is complete for the guarded tester artifact:

- Developer ID signing and strict nested verification succeeded;
- Apple notarization was accepted;
- stapling and staple validation succeeded;
- Gatekeeper accepted the working app and extracted final ZIP copy;
- the repository-independent trusted-tester verifier passed.

The sealed app's embedded manifest remains immutable build metadata. Post-staple
hashes and Apple trust status are recorded externally in
`config/release/philcore-desktop-o9-release-evidence.json`; the final ZIP hash is
not written back into the already sealed app.
