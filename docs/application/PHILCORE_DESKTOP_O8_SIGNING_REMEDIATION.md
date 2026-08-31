# PhilCore Desktop O.8 Signing Remediation

Status: ad-hoc signing and ZIP preservation demonstrated; Developer ID and Apple
distribution steps prepared but not executed.

## Nested signing inventory

Discovery walks the completed app without following symlinks and recognizes
Mach-O executables, dynamic libraries, `.node` modules, frameworks, helper apps,
and XPC services. The observed package contained Electron Framework, Mantle,
ReactiveObjC and Squirrel frameworks; four Electron helper apps; Chromium
libraries and crash handler; native Hardhat modules and esbuild; the Swift
user-presence helper; and the prover and verifier. The inventory is persisted in
the release manifest. `codesign --deep` is used only for final verification.

## Operational order

1. Build and assemble every resource.
2. Preserve framework-relative symlinks and remove prohibited metadata/debris.
3. Set executable permissions and sign standalone nested code.
4. Write embedded hashes, inventory, and truthful release claims.
5. Sign frameworks and helper bundles deepest-first.
6. Sign the top-level application last.
7. Strictly verify the app and each discovered code object.
8. Create the ZIP, extract it into a temporary directory, and strictly verify it.

## Distribution workflow

Developer ID packaging accepts only `PHILCORE_DESKTOP_SIGNING_IDENTITY`, verifies
one exact active-keychain match, applies hardened runtime and timestamping, and
fails closed otherwise. Notarization accepts only an external notarytool keychain
profile plus explicit live-upload approval, preserves the safe submission ID and
status, and requires acceptance before stapling. Stapling validation and
Gatekeeper assessment are separate commands.

No Apple credential, identity, certificate, private material, or password is
stored in the repository or printed by these workflows.

## Remaining blockers

Developer ID signing, notarization, stapling, Gatekeeper acceptance, and trusted
tester distribution have not occurred. External audit and production readiness
remain incomplete. ACP-0002 remains Proposed and Base Sepolia Beta remains blocked.
