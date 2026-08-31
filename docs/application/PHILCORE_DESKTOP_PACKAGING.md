# PhilCore Desktop Packaging

Status: Phase O.6 local Alpha.

PhilCore Desktop uses a custom macOS packager for O.6. Electron Builder 26.15.3 and Electron Forge were evaluated, but the current O.5 path still needs an explicit local-alpha resource set: desktop source, SDK runtime source, Hardhat local fixture dependencies, contract artifacts, and bundled ACTION_UNLOCK prover/verifier binaries. A custom packager matches the existing desktop build convention and keeps every release claim explicit.

## Application Identity

- Product name: PhilCore Desktop Local Alpha
- Executable: PhilCore Desktop Local Alpha
- Bundle identifier: `com.philcore.desktop.localalpha`
- Version: `0.1.0`
- Build number: `0.6.0-local-alpha`
- Channel: local Alpha
- Minimum macOS: 13.0
- Current target: Apple Silicon macOS app and zip
- Intel and universal targets: deferred

Changing the bundle identifier later may affect Keychain and application-data behavior.

## Profiles

- Development: unpackaged Electron, DevTools allowed, local diagnostics allowed.
- Local Alpha: packaged `.app` and `.zip`, unsigned by default, DevTools disabled by default, public-network mutation disabled.
- Signed Release Candidate: configuration prepared for hardened runtime and externally supplied Developer ID signing identity.
- Production: not enabled.

## Commands

- `npm run desktop:package-local`
- `npm run desktop:verify-package`
- `npm run desktop:sbom`
- `npm run desktop:test-packaged`
- `npm run desktop:test-clean-environment`
- `npm run desktop:package-signed`
- `npm run desktop:verify-signature`
- `npm run desktop:notarize-check`

Live notarization is not part of normal packaging.

## Packaged Resources

The local Alpha package includes desktop code, SDK runtime code, Hardhat fixture dependencies, contract artifacts, bundled proof binaries, and release/SBOM metadata.

The renderer cannot choose executable paths. Packaged proof binaries are resolved by the main process and integrity-hashed in `config/release/philcore-desktop-local-alpha.json`.

## Local Alpha Package Pruning

The local Alpha app remains a repository-independent local fixture package, so Hardhat, Ethers, the Darwin arm64 EDR native module, `tsx`, and esbuild's Darwin arm64 runtime binary are retained. Package-time filtering removes native modules that cannot execute on the target Apple Silicon package, Solidity analyzer packages used only by Hardhat's compile/parse path, the TypeScript compiler package, `solc`, Hardhat build-info and debug artifacts, node module type declarations, and esbuild's duplicate root binary.

The package verifier reads the manifest embedded inside the `.app`. It requires
one full 40-character commit identity, a clean source tree at build time, an
exact match to the currently reviewed commit, and an exact packaged-app byte
count. Packaging does not rewrite the tracked source manifest, and verification
evidence is written beside the local release artifact rather than into tracked
source. The verifier also asserts that the retained Darwin arm64 EDR and esbuild binaries
are present, incompatible EDR packages are absent, Solidity analyzer and
compiler-only packages are absent, and required proof/helper/local fixture
artifacts remain present. Pruning does not remove local proving, Device Vault
signing, native user presence, Hardhat local fixture execution, or any
public-network mutation guard. Those resources support bounded diagnostics and
explicitly hypothetical regression fixtures; their presence does not make the
ordinary current product path reach signing or execution.

## Current Limitation

This is a local Alpha distribution package, not a production app. It includes
local fixture infrastructure without requiring the PhilCore repository, Cargo,
or public networks at runtime. The ordinary protected-action journey stops at
the current secret-bearing STWO quarantine before signing or execution.
