# Third-Party Notices and License Scope

The root [MIT License](./LICENSE) applies to Phil-owned software and associated
documentation unless a file or component carries a different notice. It does
not relicense third-party material, and it does not automatically license Phil
names, trademarks, logos, mascot artwork, or other brand assets.

## Source with a different license

The Solidity files below retain their existing `GPL-3.0` SPDX identifiers and
are not offered under the repository-level MIT license. A copy of the GPL
version 3 license text is included at
[`LICENSES/GPL-3.0-only.txt`](./LICENSES/GPL-3.0-only.txt):

- `contracts/base/erc4337/PhilCore4337Account.sol`
- `contracts/base/erc4337/PhilCore4337AccountFactory.sol`
- `contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol`
- `contracts/base/PhilSepoliaMintPassConsumerV1.sol`
- `contracts/base/PhilSepoliaLocalComposedActionGateV1.sol`
- `contracts/base/erc4337/PhilSepoliaMintAccountV1.sol`
- `contracts/base/erc4337/PhilSepoliaMintAccountFactoryV1.sol`
- `contracts/base/erc4337/interfaces/IPhilSepoliaMintAccountFactoryV1.sol`
- `contracts/base/erc4337/interfaces/IPhilSepoliaLocalComposedActionGateV1.sol`
- `contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol`
- `contracts/base/erc4337/v2/IPhilCoreV2MinimalAccountV2.sol`
- `contracts/base/erc4337/v2/IPhilCoreV2StaticAuthorityVerifier.sol`
- `contracts/base/erc4337/v2/PhilCoreV2MinimalAccountFactoryV2.sol`
- `contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol`
- `contracts/base/erc4337/v2/PhilCoreV2StaticAuthorityVerifier.sol`
- `contracts/test/PhilCoreV2MinimalAccountTestMocks.sol`

All other file-level SPDX identifiers remain controlling for those files.

## STWO Cairo Verifier

`vendor/stwo_cairo_verifier/` is derived from StarkWare's public
`starkware-libs/stwo-cairo` repository and is redistributed under the Apache
License, Version 2.0. It is not Phil-owned MIT code. The imported base revision
is `0a5e70b73f397d84c683310382c4e61dc2729f13`; upstream later applied an
explicit repository-wide Apache-2.0 grant in commit
`77718b381a05e889e2cd5222aab20625859bd5c0` while the relevant verifier lineage,
including all five Phil-modified files, continued in the licensed codebase.

A copy of Apache-2.0 is included at
[`LICENSES/Apache-2.0.txt`](./LICENSES/Apache-2.0.txt). Redistributions must
retain the component's [`NOTICE`](./vendor/stwo_cairo_verifier/NOTICE), its
upstream attribution, and the modification notices in the five changed files.
See
[`vendor/stwo_cairo_verifier/PHIL_PROVENANCE.md`](./vendor/stwo_cairo_verifier/PHIL_PROVENANCE.md).

## Visual assets and marks

The Desktop catalog excludes uncleared chain-logo and third-party-project
artwork and uses generic text tiles instead. The 3D Phil and Avastar poses are
exact cell extractions from owner-supplied sprite sheets and are included with
direct authorization from their owner, Tyler Lengyel, for use in Phil and
PhilCore. They remain separately controlled brand artwork and are not granted
under the repository MIT software license.
See [`docs/reference/ASSET_RIGHTS.md`](./docs/reference/ASSET_RIGHTS.md).

## Pixelify Sans

The Desktop and iPhone presentation layers bundle unmodified Pixelify Sans font
files from the Pixelify Sans Project Authors. Pixelify Sans is distributed
under the SIL Open Font License, Version 1.1, and is not relicensed by the root
MIT license. The required license text is included at
[`LICENSES/OFL-1.1-Pixelify-Sans.txt`](./LICENSES/OFL-1.1-Pixelify-Sans.txt).
The Desktop WOFF2 is the byte-identical Latin variable font from
`@fontsource-variable/pixelify-sans@5.3.0` (SHA-256
`4a5633a0c9c1b73abd133a56d3716c2d8df2ed03cb987346f72194aeb224f382`).
The iPhone TTF is the byte-identical Google Fonts file at commit
`9ce5017522020232f525003b39971ddb67e33243` (SHA-256
`9ba86cd010a4de309d263ceff8e8044092c9db7efda869620cb9ff1c4389e8a5`).

## Package dependencies

Dependencies recorded in npm, Cargo, and Scarb manifests and lockfiles remain
under their respective upstream licenses. This file is not a substitute for a
release SBOM or the license texts that a dependency's license requires a
distributor to reproduce.


## Electron, Chromium, and embedded Node.js

The Desktop distribution embeds Electron 41.10.3 and the Chromium/Node.js
runtime it contains. Electron remains MIT-licensed by its contributors. The
archive includes `LICENSES/Electron-MIT.txt` and Electron's generated
`LICENSES/Chromium-Third-Party-Notices.html`, which carries the component
notices supplied with that exact Electron distribution. Phil does not claim
ownership of Electron, Chromium, Node.js, or their dependencies.

Electron also embeds the Squirrel.Mac, Mantle, and ReactiveObjC frameworks.
Their original MIT notices are included as `LICENSES/Squirrel.Mac-LICENSE.txt`,
`LICENSES/Mantle-LICENSE.txt`, and `LICENSES/ReactiveObjC-LICENSE.txt`.
`LICENSES/Electron-Native-Framework-Provenance.json` binds each notice to the
exact revision selected by Electron 41.10.3; Electron's own MIT notice does
not replace these upstream attributions.

## Native proof and platform components

The Desktop package includes version-bound native tools and helpers:

- Nargo `1.0.0-beta.16`, from `noir-lang/noir`, under MIT; its exact notice is
  `LICENSES/Noir-Nargo-MIT.txt`.
- Barretenberg `3.0.0-nightly.20251104`, from
  `AztecProtocol/aztec-packages`, under Apache-2.0; the exact governing text is
  `LICENSES/Apache-2.0.txt`.
- Phil's Rust/STWO prover/verifier is built from `proving/Cargo.lock`, including
  STWO revision `76dd75715ce87e2fe2258083480b6228c23bb70b`; the Phil crate is MIT and
  upstream STWO licensing remains Apache-2.0.
- `PhilCoreUserPresenceHelper` and `PhilCoreQRCode` are Phil source compiled
  against Apple system frameworks and remain under the root MIT license.

The generated final package SBOM binds every shipped dependency and native file
to the app directory hash. These versions are local verification tools. They do
not make Noir or P-256 verification on-chain and do not activate STWO as a
production authorization prover.

### Exact native dependency and notice coverage

`LICENSES/native-dependency-inventory.json` records the selected macOS arm64
Nargo, Barretenberg AVM-transpiler, and EDR dependency graphs, exact versions,
source archives/revisions, features, license expressions, and notice references.
It separately lists build-only dependencies. A selected dependency may be
removed by the linker; the inventory conservatively retains notices for the
selected graph and does not classify an entire upstream workspace as shipped.

`LICENSES/native-supplemental-inventory.json` covers Barretenberg's selected
C++ libraries and vendored/generated implementations, Rust standard libraries,
Zig/LLVM libraries and compiler runtime, and esbuild's Go runtime. Exact native
C/assembly crate sources retain their additional file-level notices, including
ring, libm, secp256k1, BLST, C-KZG and mimalloc. Generated MIME data and
Wagyu-derived code retain their upstream attributions. Unspecified original
copy revisions are not represented as byte-identical upstream matches.

`LICENSES/native-proving-selected-inventory.json` reconciles the two Phil
proving tools with their 236-package selected normal graph. The existing
312-entry build notice collection remains a conservative superset. Apple
system frameworks and libraries are external system dependencies, not bundled
third-party implementations. Electron's own full distribution notices remain
controlling for its embedded Chromium/Node components.

The reviewed `LICENSES/native-notice-coverage.json` pins the exact native input
hashes, dependency inventories, and required notice/source hashes. Packaging
rejects changed inputs, missing notices, changed inventories, and unexpected
native files. Signing legitimately changes executable bytes. The final
distribution separately carries `native-notice-coverage-final.json`, freezing
the final signed executable hashes against the same reviewed inventory and
notices; it is not an automatic refresh of the approved input policy.

### Corresponding source for MPL components

The native graph selects MPL-covered `im` 15.1.0, `bitmaps` 2.1.0,
`sized-chunks` 0.6.5, `archery` 1.2.1, `rpds` 1.1.1, `webpki-roots` 0.26.8,
and `option-ext` 0.2.0. Their complete, unmodified published source archives
are included in `LICENSES/native-corresponding-source/<name>-<version>.crate`.
These are gzip-compressed tar archives, available without a network request
inside the application's `Contents/Resources/app/` directory. Their hashes
match every consuming build lock. The pre-existing `indent` 0.1.1 and
`vector-map` 1.0.2 source directories remain available in the same directory.

Those covered source files retain their MPL terms and notices. A copy of the
license is at `LICENSES/MPL-2.0.txt`. No Phil license or distribution term
limits recipients' rights in this source. Separate files in the larger work
retain their respective licenses; the repository MIT license does not override
MPL or any other file-level grant. These notices concern local native tools
and do not change which proof systems or blockchain flows the product enables.
