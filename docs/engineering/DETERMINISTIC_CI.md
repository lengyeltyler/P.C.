# Deterministic Public CI

## Purpose

Honest, deterministic GitHub Actions CI that cannot become green by silently excluding, ignoring, or regenerating failing evidence.

- Every unit test, desktop test file, proving target, and relevant `test:` / `verify:` / `check:` script is classified exactly once.
- Required lanes run only commands expected to pass on a clean runner.
- Historical stale/known failures use a **1:1 manifest bijection** with exact exit codes, Mocha failure identities, body hashes, or structured error digests.
- Physical iPhone / WebAuthn user-presence / Apple signing-notarization / public-network ceremonies are never automated passes.

Mocha Spec `normalizeFailureText` removes terminal reporter durations only on successful-test lines (`✔` / `✓` / `√`) and on `N passing` summary lines (`(Nms)`, `(Ns)`, or already-normalized `(<ms>)`). This collapses host-dependent medium/slow timing presence and ms-vs-s summary units without touching failure bodies, failing/pending summaries, or unrelated output.

## Merge-blocking jobs

Workflow: `.github/workflows/deterministic-ci.yml`

| Job | Timeout | Contents |
| --- | ---: | --- |
| `classification-static` | 20m | Classification + execution-map validation, classifier tests, `typecheck`, `compile`, clean-tree proof |
| `product-runtime` | 20m | Required product/Runtime Hardhat unit lane plus iOS Simulator suite on `macos-26` |
| `solidity-erc4337` | 20m | Solidity / ERC-4337 / ERC-7562 Hardhat unit lane (`fetch-depth: 0` for historical commit ancestry) |
| `desktop` | 30m | Classified `desktop_test_file` list on `macos-14` (not `npm run desktop:test`) |
| `proving` | 30m | ABI Hardhat tests + `cargo +nightly-2025-07-14 test --test phase34_core` via runner `rustup` |
| `evidence-check` | 30m | Pinned Scarb/cairo-execute 2.15.0 + Rust nightly; green evidence `--check`; exact historical identities (`fetch-depth: 0`) |

`npm test` / `npm run test:unit` remain `environment_dependent` mixed aggregates — not merge gates.

## Desktop lane

The hosted Desktop job provisions disposable build outputs before executing classified Desktop files:

- Hardhat artifacts (`npx hardhat compile`)
- the sandbox-safe preload bundle (`npm run desktop:bundle-preload` → `apps/philcore-desktop/build/preload/preload.cjs`)
- the pinned release ACTION_UNLOCK prover/verifier binaries (built and exported as `PHILCORE_ACTION_UNLOCK_PROVER_BIN` / `PHILCORE_ACTION_UNLOCK_VERIFIER_BIN`)

`npm run ci:lane:desktop` is **not** self-provisioning. Locally, run the same prerequisites (Hardhat compile, `desktop:bundle-preload`, and exported prover/verifier binaries) before the classified lane, or rely on the hosted Desktop job.

CI then runs only files classified `desktop` (includes `desktop-e2e` and `desktop-o9-distribution`). It excludes physical/manual:

- `desktop-native-iphone-pairing.test.cjs`
- `desktop-platform-webauthn.test.cjs`
- `desktop-user-presence.test.cjs`

`script:desktop:test` is classified `environment_dependent` because the production aggregate mixes physical suites and omits required files. Automated desktop tests are compatibility checks, not completed physical ceremonies.

## What remains manual / non-required

| Lane | Why |
| --- | --- |
| `environment_dependent` | Exact reproduced deps (e.g. missing `proving/out`, Starknet config ENOENT, Sepolia readiness assertions, `compiler_build_info_ambiguous`, O40 initializer mismatch) |
| `physical_ceremony_manual` | Physical iPhone pairing, WebAuthn user-presence, enrollment ceremonies |
| `public_network_prohibited` | Live bundler, monitoring, submission, funding, public-network operations |
| `historical_known_baseline` | Exact approved non-zero identities (stale evidence / O.31 path portability) — not a green product gate |

## Local commands

```bash
npm run ci:validate-classification
npm run ci:classification-tests
npm run typecheck
npm run ci:lane:product-runtime
npm run ci:lane:solidity
npm run ci:lane:desktop
npm run ci:lane:proving
npm run ci:lane:evidence
npm run ci:lane:historical-evidence
npm run ci:verify-clean-tree
```

The required `product-runtime` command includes the iOS Simulator suite and
therefore must run on macOS with Xcode. It is not a runnable Linux lane.

## Toolchain pins

- Node `26.0.0`, npm `11.12.1`
- Lockfile install via `npm ci`
- Rust: runner preinstalled `rustup` installs exact `nightly-2025-07-14` (no `curl | sh`)
- Starknet (evidence job): official Scarb/Cairo **2.15.0** assets via `scripts/ci/install-pinned-starknet-toolchain.cjs` with pinned SHA-256 digests (`config/ci/starknet-toolchain-assets.json`), installed to `~/.cache/philcore/toolchains/{scarb,cairo}-v2.15.0/bin` and activated with `scripts/starknet/activate-pinned-toolchain.sh`
- Solidity and evidence jobs use `actions/checkout` with `fetch-depth: 0` so historical commit ancestry checks resolve
- GitHub Actions pinned to immutable commit SHAs
- `permissions: contents: read`
- Concurrency cancels superseded runs
- Lane runners use allowlisted argv arrays (`shell: false`)

## Expected hosted cost (approximate)

Cold parallel wall clock is dominated by proving + desktop (~30 min). Warm caches reduce Node install time.

## Environmental limitations

- Stale evidence is **not** regenerated by CI.
- O.31 remains historical until its hardcoded-path fixture is repaired in a separate authorized change.
- Solidity lane runs each unit file in an isolated Hardhat process so AA22/expiry-sensitive suites that are independently green are not invalidated by earlier chain-time advances.
- `desktop-e2e.test.cjs` requires a working Electron GUI session. Some local agent hosts trap Electron (`SIGTRAP` / exit 133); hosted `macos-14` is the merge gate for that file. Other classified desktop files are ordinary Node compatibility tests.
- Hosted results apply only to the exact commit tested; contributors should
  inspect the required jobs for their pull request or `main` commit rather
  than treating an earlier green run as evidence for a changed tree.
- No secrets, wallets, signing keys, public RPCs, bundlers, or real funds.

## Classification source of truth

- `config/ci/classification.json`
- `config/ci/historical-failure-manifest.json`
- Validator: `scripts/ci/validate-classification.cjs`
