# PhilCore Desktop Local Alpha Release

Status: local-only installable Alpha.

The O.6 local Alpha release path produces an installable macOS app for local PhilCore testing. It is not notarized, not production-approved, and not suitable for meaningful assets.

## What Works

- clean packaged launch;
- local identity creation;
- encrypted local Device Vault;
- restart and unlock;
- digest-bound local approval and Protected Mac enrollment;
- disposable routine iPhone authorization where separately enrolled;
- structural rejection of ordinary Ethereum authorization at the quarantined
  secret-bearing STWO boundary before signing or execution;
- bundled proof binaries retained only for bounded synthetic research and
  historical regression compatibility, not current product authority.

## What Is Disabled

- public Starknet publication;
- Ethereum L1 anchoring;
- L1-to-Base relay;
- public Base submission;
- public bundler submission;
- paymasters;
- meaningful assets;
- production approval.
- ordinary STWO-backed signing, nullifier consumption, or execution.

## Install And Uninstall

The local package is created under `apps/philcore-desktop/release/local-alpha/`.

The unsigned Apple Silicon package is pruned at package time. It keeps the local Hardhat fixture runtime, Darwin arm64 EDR, esbuild runtime needed by the current `tsx/cjs` config hook, contract artifacts, and bundled proof/helper binaries. It excludes incompatible native EDR platforms, Solidity analyzer packages, TypeScript, `solc`, Hardhat build-info/debug artifacts, and duplicate esbuild binary data. Package verification fails if these boundaries drift.

Deleting the app does not delete local identity data. Identity records live under the app data directory selected by Electron/macOS, or the `PHILCORE_DESKTOP_USER_DATA_DIR` test override. Local identity reset requires fresh authentication or passphrase reauthentication plus digest-bound reset confirmation.

Manual removal of all app data should be treated as destructive and is not performed automatically.

## Updates

Updates are manual in O.6. There is no auto-download, no auto-install, and no signed-update channel. Identity data is expected to remain locked and reopenable across package replacement when the bundle identity and app data location are preserved.

## Release Status UI

The desktop shows version, local Alpha channel, bundle identifier, signing status, notarization status, public-network status, ACP-0002 status, Base Sepolia gate status, and audit status.
