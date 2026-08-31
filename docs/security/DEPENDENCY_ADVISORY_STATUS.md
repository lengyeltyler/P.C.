# Dependency advisory status

Status date: 2026-08-31

The declared production npm graph is not the Desktop runtime graph. Desktop
needs Hardhat's in-process execution engine, EDR, tsx/esbuild, and contract
artifacts even though the root manifest classifies them as development packages.
The old blanket assertion that all dev dependencies were excluded was false.

The unchanged lockfile audit reports 20 package groups: 8 high, 2 moderate,
10 low, 0 critical. The declared production audit (`--omit=dev`) reports zero.
These are separate observations; neither proves the shipped Desktop is safe.

The release selection in
`apps/philcore-desktop/scripts/runtime-package-inventory.cjs` removes compiler,
Mocha, CLI, analytics, Sentry, legacy fork, and unrelated Solidity tooling.
It retains the provider, prebuilt artifacts, native EDR, runtime transpilation,
and their required dependencies. Hardhat's packaged task registry is explicitly
modified; the modification and upstream/output hashes accompany the app.
Product request, signing, transport, nonce, and recovery state machines are not
changed by dependency pruning.

Every advisory group has an exact-version disposition in
`config/security/desktop-runtime-advisory-disposition.json`, including fixed
versions and source-based vulnerable-sink reachability. The fixed local action
uses hardhat/31337, prohibits forking, and exposes no arbitrary compiler, archive,
YAML, Mocha serialization, remote RPC URL, or Undici WebSocket input. Retained
ethers-v5 utilities are not Phil's real custody path. This is bounded source
analysis, not a general exploitation proof or professional audit.

Run the triage with `PHILCORE_DESKTOP_AUDIT_APP` pointing to the final app to
validate the actual package. Without that input its report explicitly covers
only the proposed selection and cannot accept a release artifact. The final
sidecar SBOM is generated after signing/stapling and hashes the complete app,
all package versions, native files, notices, and symlinks. The dated SBOM in
`config/release` is historical and must not be used for release acceptance.

New advisory IDs, changed reviewed versions, or a changed lockfile fail closed.
High/critical exploitable runtime findings must remain zero. Build tools may
only process the trusted pinned repository on disposable/non-elevated runners;
no hosted compiler or third-party project processing is approved. A Hardhat 3
migration or cryptographic replacement requires separate review. Source changes
that expose a previously unreachable sink invalidate this disposition.
