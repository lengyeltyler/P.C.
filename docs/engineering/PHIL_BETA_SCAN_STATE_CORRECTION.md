# Physical acceptance: scan-state correction

## Rejected release retained

**RELEASE CANDIDATE REJECTED DURING PHYSICAL ACCEPTANCE — UI STATE PROJECTION BUG**

The existing frozen release record and artifacts are historical evidence and must not be overwritten. This correction is not a new release freeze or physical-acceptance PASS.

- Rejected release source: `0004c5e19d119f1ad0376d26da51e68c5a14cb91`.
- Source tree: `1e8bb50d5f30ec98a6fefd780ba46935d8437ba6`.
- Combined release record SHA-256: `63e5e820ef517a1b248f836f1052ad00b2e14045a7f7203c1f97d831f6337898`.
- Final Desktop ZIP SHA-256: `d83368989d3932c52c693a5bdefee7002408ab92299292b7c9e488608d06fd2e`.
- Stapled Desktop app digest: `aa2fce60d8f9ea1ac81bb2cfd3295d66ed86b250d618377fce4216ec934e5c56`.
- iOS 0.1.0 (56) app digest: `a0e380d55ac7d496bcf9d193d0b53947e8bc2618ce153e26c54dee1ea4c5128b`.

## Reproduction contract

Exercise real `CompanionModel.acceptRoutineScannedValue` with a prior enrollment presentation and a suspended synthetic authorization handshake. No real device, signing key, provider, or blockchain is needed.

Baseline transition: prior enrollment fingerprint presentation → enrollment `cancel()` publishes `.cancelled` → unfiltered enrollment observer replaces shared `routineStatus` → new authorization client enters `.exchangingKeys` privately and awaits transport → shared UI still renders `Request cancelled` until the await completes.

The regression test observes all shared status publications and inspects the suspended loading state, rather than only checking the final result after awaiting the scan.

Baseline reproduction on iOS 26.5 Simulator failed before product edits: `cancelled` was observed where `exchangingKeys` was required. After correction, that same test passes.

## Bounded correction

- `CompanionModel` assigns a fresh presentation-flow UUID before cleaning up the superseded enrollment/routine flow. Status observers and post-await publications must match that active identity. Internal idle reset is not a user-visible terminal event.
- Enrollment startup resets through the previous observer before attaching the new observer. Routine loading publishes immediately; real client stages then drive the current presentation.
- `RoutineAuthorizationClient` checks the existing operation generation before handling asynchronous errors, just as it already checks successful completions. A superseded completion cannot fail or clear the replacement request.
- Explicit current cancellation, rejection, background invalidation, and their terminal diagnostic recording remain effective. Current-request expiry and failures are not suppressed.
- No Desktop product source, QR/transport validation, fingerprint comparison, canonical verifier, signing arguments, key manager, Device Vault, replay policy, or recovery implementation was changed. The two Step 6C-2 generated reference files refresh only changed-source hashes/byte lengths and the enclosing fixture hash; protocol vectors, historical test-count contracts, and P2/P3/P5 evidence are unchanged.

## Validation (2026-08-30)

- Final iOS unit/UI run: **190 passed, 5 skipped, 1 failed**. All **38 routine authorization tests** and **7 UI tests** passed, including the new active-cancellation UI smoke test. The five skips are the physical-device approval ceremony, not simulated physical evidence.
- The one failure is unchanged `PhilCoreCompanionTests.testDisposableKeyExportBoundary`, throwing `keyCreationFailed`. A separate build/test of exact base `0004c5e19d119f1ad0376d26da51e68c5a14cb91` reproduces the same failure under the same unsigned simulator configuration. The entire iOS suite is therefore not claimed green; this is a reproduced baseline issue outside the correction.
- Ten added model/client tests exercise superseded enrollment cancellation, immediate loading, genuine cancellation and diagnostic recording, rejection, current expiry/errors, rapid repeated scans with out-of-order completions, routine-to-enrollment isolation, stale approval submission completion, stale enrollment callbacks, and background fail-closed behavior.
- Desktop aggregate passed after supplying its existing compile/prover prerequisites and releasing the occupied local test port. Focused Desktop routine/Pass A/B/C/D locks: **35 passed**. Additional local routine host/composition/product-flow suites passed.
- Classification, TypeScript typecheck, contract compilation, Desktop build, and the deterministic evidence lane passed. Generated evidence was verified again after its source-hash refresh.
- An unsigned iOS **Release** validation build passed with `CODE_SIGNING_ALLOWED=NO`. Test-routing arguments, synthetic scan transport/signer names, and fixture application entry points were absent from its executable. Existing DEBUG-exclusion claim locks also passed. This is not a distributable artifact or release freeze.
- Earlier simulator launch/preflight and debugger/diagnostic-tool warnings are retained in disposable logs; they are not counted as passing tests. AppIntents/test-framework stripping warnings did not prevent the Release build.
- Frozen Desktop ZIP, stapled app, iOS app, combined release record, and protected `pqREADME.md` hashes were reverified unchanged, using each release's recorded digest algorithm.
- Exact-head hosted CI and the redacted pre-publication secret scan are recorded on the draft PR and in the final execution report; they must not be inferred from the local results above.

## Independent review

Fresh reviewer `/root/independent_scan_state_review` had no implementation role. Verdict: **PASS**, with no unresolved High/Medium findings. One low diagnostic-recording regression was corrected and independently rechecked.

- Reviewed four-file Swift source/test diff SHA-256: `8f20edf03f2a7fd6edc151f7042c39a2b572eab2a15d8e697f6c416ca3afc981`.
- Independent report SHA-256: `d26eb5dc103a5a75e20507cb117e89f773ed6f79e40f8ffb21086dde91a91eb2`.

The review confirms active-flow ownership, genuine active cancellation, and unchanged approval/security rules. It does not claim physical Face ID/QR acceptance. Late signer callbacks and a fully suspended asynchronous enrollment replacement were source-reviewed, not separately exercised by the new runtime tests.

## Boundaries

No frozen artifacts, canonical Beta evidence, entitlements, cryptographic validation, signing policy, recovery authority, or public-chain state may be changed. Validation builds are disposable, unsigned and separate from the final release locations. A corrected physical build requires a later release ceremony.
