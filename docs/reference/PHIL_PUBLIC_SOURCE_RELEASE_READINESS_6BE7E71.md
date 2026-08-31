# Phil Public-Source Release Readiness — `6be7e71`

Status: Ready for a source-only public release with explicit local-alpha and
nonproduction labels; not published

Date: 2026-08-23

## Exact Reviewed State

```text
branch:        codex/phil-v1-efficient-route
commit:        6be7e711fce75f748761597187b0e29edc61ba5e
tree:          c5bfcabe185a0718fef5cc9a3d77fe6b7662a175
app source:    80e5379c75302942220e884d05a8b9f434545755
app tree:      e2d556fcc204e77919aeb76dfba2d78c53eac1c7
review verdict: ACCEPT_CROSS_DEVICE_CORRECTIVE_CANDIDATE
```

The later commits are evidence-only wrappers and deterministic manifest
maintenance. They do not change the accepted Desktop or iPhone application
authority implementation or the frozen local-alpha artifacts.

## Source-Release Verdict

```text
PUBLIC SOURCE RELEASE READY: YES, SOURCE ONLY
LOCAL ALPHA CROSS-DEVICE MILESTONE ACCEPTED: YES
BETA BINARY RELEASE READY: NO
PRODUCTION ASSET EXECUTION READY: NO
PRODUCTION PROOF BACKEND SELECTED: NO
IOS PROVING VERIFIED: NO
STWO AUTHORIZATION ENABLED: NO
PUBLICATION PERFORMED: NO
```

The source may be published only with the existing local-alpha,
nonproduction, no-meaningful-assets, and proof-quarantine disclosures intact.
This verdict does not approve the ignored Desktop zip or signed iPhone app for
public distribution.

## Completed Release Checks

- Cross-device candidate review: accepted with no candidate-blocking finding.
- Runtime: Node `26.0.0`, npm `11.12.1`, lockfile version 3.
- Deterministic classification: passed with 93 product-runtime, 47 Solidity,
  44 Desktop, 6 proving, and 19 deterministic-evidence classified items.
- Classification regression suite: 42 passed.
- Product-runtime lane: 1,335 passed, including the focused native iPhone
  Simulator suite.
- Solidity ERC-4337 lane: passed.
- Desktop lane: passed, including protected enrollment, routine
  authorization, complete product flow, packaged boundaries, and the PhilUI
  presentation lock.
- Proving lane: passed, including 60 Step 4 Cairo tests and 11 Rust tests.
- Deterministic-evidence lane: passed; the Step 6C-2 record now accounts for
  all 63 focused tests.
- PhilCore contract invariants: all 27 passed.
- Production dependency audit: zero vulnerabilities across 60 production
  dependencies.
- Font and notice delivery: Desktop and iPhone Pixelify Sans files are covered
  by the OFL; required notice files are embedded and their hashes are frozen.
- Public-source filename scan: no tracked private-key, certificate, wallet,
  credential, or non-example environment file was found.
- Public-source content scan: the 14 secret-shaped matches are confined to the
  empty `.env.example`, explicitly synthetic local diagnostic constants,
  tests, and the committed dependency-exposure record. No production or user
  credential was identified.
- Worktree: clean after all command-generated reports were restored to the
  reviewed commit.

The evidence lane initially exposed stale Step 4, Step 6C, and Step 6C-2
manifest hashes and an outdated 60-test count. Commit `6be7e71` regenerates
those records with the pinned toolchain and records the literal 63-test total.

## Required Public Labels And Exclusions

A source publication must preserve these statements prominently:

1. Phil is a bounded local alpha, not a production wallet or asset custodian.
2. STWO output is an experimental secret-bearing proof artifact and remains
   structurally rejected from final authorization.
3. The frozen Desktop app is unsigned and unnotarized. The iPhone app is an
   Apple Development build, not an App Store or external-distribution build.
4. No public RPC, deployment, transaction, network mutation, production
   secret, meaningful asset, or public proof publication is authorized.
5. Post-quantum support is an algorithm-agile migration architecture, not an
   active post-quantum authorization claim.
6. Noir/Barretenberg and RISC Zero remain evaluated candidates; neither is a
   selected Phil V1 production backend, and native iPhone proving remains
   unverified.

Ignored build output, local `.env` files, signed local apps, provisioning
profiles, derived data, release zips, Rust targets, and user data must remain
excluded from the public source commit.

## Residual Security Debt

The current dependency audit reports 20 development-tooling advisories: 10
low, 2 moderate, and 8 high. Five high findings remain Beta-blocking in the
triage policy (`adm-zip`, `brace-expansion`, `hardhat`, `immutable`, and
`js-yaml`). They are absent from the production dependency audit. Closing the
Hardhat chain requires a separately reviewed major-version migration; this
source-release gate does not silently accept it as production risk.

Slither produced 154 detector results, of which 42 require triage. Four are
production-blocking under the existing conservative classifier:

- one Step 6C `executeAuthorized` checks-effects-interactions heuristic; and
- three locked-ether findings covering the Step 6C account and local/test
  targets.

The accepted app candidate did not modify those contracts. The existing
adversarial EntryPoint test demonstrates that target reentry fails, and the
local-alpha Desktop lifecycle cannot reach signing or execution while the
proof quarantine remains active. These facts make the findings disclosed
production-review debt, not permission to claim the contracts are production
ready. A later production gate must either remediate them or close each with a
specific reviewed classifier and regression proof.

## Publication Boundary

This record prepares a source-only release. It does not push a branch, create
or merge a pull request, change repository visibility, upload a release,
distribute either app artifact, notarize code, use a device, contact a public
network, or authorize any chain activity.
