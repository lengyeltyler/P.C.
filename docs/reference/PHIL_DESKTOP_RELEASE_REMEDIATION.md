# Desktop release remediation, 2026-08-31

Release assembly removes the development platform-key and user-presence
factories, their fixed keys, and the existing E2E branches. Before any storage
or authentication module loads, the packaged entry rejects inherited E2E,
development/UI-test, or native-presence-helper overrides and test-auth CLI
selectors with `PHILCORE_RELEASE_TEST_SELECTOR_REJECTED` (exit 78).
Unpackaged development tests retain their existing explicit fixtures.

`npm run desktop:test-packaged` now checks the actual release binary's rejection,
fixture-provider absence, exact dependency inventory, and distribution notices.
The older `test-packaged*.cjs` scenario scripts are historical fixture-driven
harnesses and cannot establish a modern Release pass. Do not enable their E2E
selectors in a release to make them pass. Existing development E2E coverage and
`test-packaged-runtime.cjs` serve separate purposes: the latter reuses six
existing regression files against an exact copy of the packaged modules and
dependencies, keeps Mocha outside the app, and verifies that the app is unchanged.
Neither is owner-present physical acceptance.

The package retains Hardhat's required local provider, while removing compiler,
test, CLI, Sentry/analytics and obsolete fork tooling. The task registry change
is recorded in the embedded runtime inventory. The normal product configuration,
request/nonce/review/rejection/persistence code, UI, device providers, and iOS
source are not changed by this remediation. A test-only clock mismatch was fixed
by giving the request and transport the same wall clock, as production does.

Desktop must be rebuilt because release bytes and notices change. The existing
canonical release family and version remain; policy does not require a marketing
version increment for a new source/hash-bound candidate. iOS build 58 is unchanged
and does not require rebuilding or reinstalling. Physical reacceptance is not
required for removing the prohibited launch path and unused tooling when the
final normal-path regression and artifact-equivalence evidence pass. Prior
physical evidence remains bound to its original app hashes; the new freeze must
reference it with this impact assessment, not relabel the old run as a new one.

Native notices identify Electron 41.10.3, nargo 1.0.0-beta.16, Barretenberg
3.0.0-nightly.20251104, the pinned Cargo/STWO graph, EDR, esbuild, and Phil's
macOS helpers. The exact SBOM hashes all native files after signing/stapling.
The conservative Cargo build graph includes compile-time dependencies and is
not a claim that every crate is linked in each binary. MPL crate source is
included under `LICENSES/native-corresponding-source`. GPL source remains
GPL; the root MIT notice does not relicense Account Abstraction or Phil's
GPL contracts. Reproduce/get full corresponding source from the exact release
source commit in the public repository, its lockfile, Solidity configs and build
scripts; do not substitute the latest branch for that commit.

Current Phil character artwork remains covered by the owner's recorded grant.
The historical Bitcoin/Ethereum/Solana SVG provenance question remains a
release blocker until its source/permission basis is established or separately
dispositioned. A signed package or passing CI does not resolve that question.
No publication, tag, mainnet use, or production-custody approval is implied.
