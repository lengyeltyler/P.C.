# PhilCore Release Validation Corrective Report

Status: isolated local corrective candidate. No physical-device operations or final release ceremonies are authorized by this document.

## Starting identity and protected state

Canonical `origin/main` was verified remotely at `1a1d69942e8fd2accf570088ca80a19a6fe80e6c`, tree `7269ea4f62a01e8a21f9bd9760a009652adcb4d2`. The original checkout was on `codex/phil-beta-ui-release` at `1e18639b699c8c7d3d6c80eec4da77578501c637`; its local `main` was stale. Implementation uses a separate worktree and `codex/release-validation-corrective` based on canonical main. The original checkout and frozen release artifacts were not changed.

Recent canonical fixes were scan supersession (`b231e52`, merge `1a1d699`), Apple team keychain authorization (`37b49ca`, merge `0004c5e`), and signing/notarization artifact continuity (`da2c56d`, merge `3ee168d`). These were inspected rather than assumed to close multi-request acceptance.

Protected `pqREADME.md` remains unchanged at SHA-256 `7702166308feec4d81733842f0d7da4034c64fab2381bb353bd2a769b99b24c8`.

## Cause and correction

Foundation `Data.removeFirst(8)` preserves its start index. The original Swift nonce helper then wrote absolute indices 24–31, inserting sequence 1 eight bytes too early and reconstructing `2^64`. Nonce zero concealed this defect. Before correction, the unchanged Desktop producer and unchanged Swift verifier passed nonce 0 and failed nonce 1; passive expiry left state 2 and blocked the next request.

The corrected helper constructs a fresh `Data(uint192Key.suffix(24)) + Data(uint64Sequence.suffix(8))`. Decimal parsing accepts ASCII digits only, rejects noncanonical representations and overflow, and uses bounded integer arithmetic. Binding comparisons remain strict. Tests cover 0, 1, 2, 3, 255, 256, 65535, `2^32-1`, `2^32`, `2^64-1`, maximal uint192 key, overflow, negative/Unicode/decimal/exponent/leading-zero/number/boolean representations. The existing committed `successfulNonce1` request now exercises the independent Swift consumer.

Each canonical equality has an explicit source-controlled field label. A mismatch remains the existing fail-closed `routine_binding_mismatch`, with a separate safe `bindingField` diagnostic (for example `action.userOpNonce`). Values, request bodies, signatures, QR codes and private keys are not recorded. Field diagnostics survive safe diagnostic persistence and are visible in failure guidance. Terminal acknowledgment identities/outcome have individual `terminalAck.<field>` labels; signer/DER/response and enrollment key-record failures have safe field or operation-stage fallback labels. Malformed schemas retain their separate malformed-request classification. No raw bound value is displayed.

The composed test also exposed double hashing in the old synthetic Swift signer and receiver. Both were corrected to use the production prehashed P-256 signing/verification semantics. A mutually consistent synthetic producer/consumer is not independent integration evidence.

## Terminal protocol and lifecycle

The new fixed `/philcore/routine/v1/terminal` route has its own explicitly versioned, exact schema:

```json
{"protocolVersion":1,"purpose":"PHIL_ROUTINE_TERMINAL_RESULT_V1","sessionId":"<bytes32>","requestId":"<bytes32>","outcome":"rejected|cancelled"}
```

It uses the established session traffic key and separate AEAD domains `IPHONE_TO_DESKTOP_ROUTINE_TERMINAL_V1` and `DESKTOP_TO_IPHONE_ROUTINE_TERMINAL_ACK_V1`. The acknowledgment echoes the identities/outcome with purpose `PHIL_ROUTINE_TERMINAL_ACK_V1`. Neither carries approval, a signature, execution parameters or retry permission. An acknowledgment is sent only after durable precommit cancellation/rejection. Rejection uses the existing CANCELLED journal state with the distinct durable `PHIL_ROUTINE_PHONE_REJECTED_V1` reason hash; public status projects `terminalReason: rejected` only for that reason.

Complete/terminal HTTP frames now require `X-PhilCore-Routine-Request`. The header is only a routing hint; AEAD independently binds the request/session. A stale response targets its own retired request instead of whichever request is currently active. Older clients lacking this routing contract are not supported by the corrected host; both applications must be frozen together.

Host begin, status, cancellation and HTTP operations share one serialized lifecycle. Passive status polling and next-request admission advance expiry. Committed/unknown outcomes cannot become cancellation or expiry. Invalid transport becomes a durable pre-submission failure where allowed. Deny never signs or executes; cancellation during an in-flight handshake waits for that exchange and the authenticated terminal acknowledgment.

A submitted approval cannot be silently superseded or reported cancelled. Lost/ambiguous completion remains `routine_submission_outcome_unknown`, prevents replacement scans, and requires Desktop reconciliation. Ordinary background cleanup does not relabel an already completed outcome. Restored ambiguity is reinstated in the client itself, survives background and cancellation, and blocks key creation/deletion and new scans. Durable committed, invalid-receipt or unknown records block Desktop begin, deletion and replacement even when their transport has ended or the host has restarted.

Desktop sends HTTP 204 only for durable COMPLETED state 9, never verified execution failure or unresolved receipt state. That positive HTTP reply is not cryptographically authenticated, so the phone now says “Approval sent” and directs the user to Desktop for the verified result; it does not claim independent receipt verification. The composed harness independently checks Desktop's durable state. Unknown-state screens do not offer retry/reset. Negative acknowledgments are authenticated, and terminal-decision progress does not imply signing.

## Persistent acceptance test

`RoutineAuthorizationTests.testRoutineAuthorizationLongitudinalAcceptance` is required by the canonical Simulator runner, which supervises a separate real Desktop backend and a dedicated iOS Simulator. Missing backend or missing longitudinal result is a failure, never a skip. One model, enrollment, signing-key abstraction, Desktop runtime and account are retained through:

1. Real routine enrollment proof and authenticated acceptance, with protected Desktop persistence.
2. Q1: nonce 0, scan callback, fingerprint, reconstructed review, approve, execute, verified receipt.
3. Q2: nonce 1, distinct request/session, same model/account/key, review, Deny, authenticated Desktop rejection; no additional signature/execution.
4. Q3: passive expiry with no phone completion packet; old scan expires.
5. A fresh request: cancellation before review and authenticated Desktop acknowledgment.
6. Q4: nonce 1 remains unconsumed; fresh review, approval and second execution.
7. Product reinitialization and iOS model reconstruction without deleting protected stores or replacing the key.
8. Q5: the product's new local runtime/account starts at nonce 0; preserved pairing, new review and third verified execution.

It also replays Q1's response after Q2 starts, verifies isolation and tracks exactly six routine requests, three post-enrollment signatures, three local executions and one deliberate reinitialization. Existing suspended-callback regressions, no-retry/commit/reconciliation tests and transport tamper tests remain mandatory.

**PHYSICAL EQUIVALENCE: MEDIUM.** Actual production Swift model/client/verifier/URLSession, Desktop host/coordinator/store/provisioning and local-chain execution run. Substitutes are:

| Substitute | Reason | Production path retained |
| --- | --- | --- |
| Camera callback input | Automated optical aiming is not a software guarantee | Real QR decoder, model admission and scanner ownership regressions |
| Software P-256 signer with false hardware/presence flags | Simulator has no physical Secure Enclave/user presence | Real proof, signature normalization, bindings and server verification |
| OS credential wrapping provider | Automated test must not access owner credentials | Real encrypted storage, generation rules, durable writes and restoration |
| Boundary clock control | Exercise expiry without conversational pauses | Actual expiry checks, journal transitions and next-request admission |
| Model/product reinitialization | Deterministic lifecycle recovery without killing the test supervisor | Same durable Desktop stores, new local-chain runtime/account and retained signing-key abstraction |

No review/accepted/denied phase, completed receipt, trusted-state boolean, or success HTTP response is injected into this harness. The Desktop identity is created/unlocked through the production runtime host with a test-owned identity. Hardware signing and optical scanning still require the later bounded physical delta.

## CI and release gate

`unit:phil-v1-step6c-desktop.test.cjs` was classified in the Desktop lane but omitted by its runner. The runner now schedules unit tests and directly executed package items as well as Desktop files, rejects unknown unscheduled kinds, and still deduplicates aliases. Classifier regressions verify that the coordinator command appears exactly once. The PR workflow runs this lane without `continue-on-error` for same-repository PRs (the existing fork restriction remains). A nonzero suite exit terminates the lane. The classified product-runtime package invokes the actual Simulator longitudinal runner; its failure also terminates that lane.

Run the consolidated local prerequisite with the repository-pinned Node/npm:

```text
node scripts/release/run-routine-prephysical-gate.cjs
```

It executes typechecking, classification, compilation, focused wire/record/journal/transport/enrollment/security tests, preload preparation, the complete classified Desktop lane (including the coordinator), and the actual iOS Simulator longitudinal suite. The Simulator runner also builds iOS in Release configuration and checks that test signer, orchestration and DEBUG screenshot markers are absent from the executable. This unsigned Simulator build is not a signed release candidate.

Security-critical invariants remain mandatory. Screenshot/copy fixtures remain visual or source-boundary evidence. They do not count as product progression. No tests were deleted in bulk, and no existing security lane was removed.

## Baseline and orchestration

The normal Desktop bridge exposes a typed, no-input `routineAuthorization.baseline()` observation. `captureRoutineAcceptanceBaseline()` combines it with the current renderer state and packaged source identity. Baseline preparation may initialize the ordinary local runtime and advance overdue precommit expiry; it creates no request or protected action. The phone writes the safe `philcore.routineAcceptanceBaselineV1` preferences record on initialization and current presentation changes. The record contains phase, pending-state classification, public pairing correlation, hardware/presence policy, build/source identity and capture time; it is not authority.

Future authorized tooling must collect those live observations and exact installed-build readback; it must not invent a capture or substitute a fixture. The Desktop observation includes its main `desktopProcessId`; the checker independently resolves that running process's application path and hashes the actual running bundle. The iOS collector must supply `deviceIdentifier` plus `installedArtifactReadback: {source: "installed-device-bundle-readback", deviceIdentifier, appPath, observedAt}` from a fresh authorized readback of the installed device bundle into a separate local directory. Matching labels or a second copy of the frozen source are not installed-state evidence. The collector's provenance is a trusted operator/tool input, not cryptographic remote attestation. If genuine installed-bundle readback is unavailable, this gate remains FAIL; there is no metadata-only fallback.

Then run:

```text
node scripts/release/routine-acceptance-baseline.cjs <capture.json> <freeze.json>
```

The version-1 freeze names `sourceCommit`, `sourceTree`, `configuration: Release`, `fixtureInjection: false`, and Desktop/iOS `appPath` plus `directorySha256`; iOS also names `build`. Both directory hashes use the existing release lineage hash including file modes and symlinks. This baseline view supplements the combined signed/notarized freeze record; it does not replace signature, Gatekeeper or installed-device verification.

The checker requires observations at most 30 seconds old, compatible clocks, zero pending/unknown authority, no active ID/QR/stale presentation, nonce 0 for the freshly initialized local runtime, idle iOS, matching enrollment generation/fingerprint and source/build identities, physical hardware policy, and matching frozen, running and installed-readback artifacts. Missing evidence fails closed. The test-only artifact-skip API returns `BASELINE SCHEMA ONLY: PASS`, never physical baseline PASS; the CLI always verifies artifacts and uses the current clock. No physical baseline PASS is claimed during this corrective task.

`routine-acceptance-procedure.cjs` provides the full owner instruction before issuance, owns the request-generation callback and checks freshness/contamination before invoking it, admits only a fresh request with at least 110 seconds left, permits Q2 only after authoritative Q1 success, and accepts only acknowledged Q2 rejection as completion. It rechecks baseline freshness immediately before Q1 generation, forbids concurrent generation, and stops on unknown state, wrong request or timing contamination. Q2 stays in the same successful logical session instead of resetting nonce/pairing. Expected negative transitions in automation continue only after convergence. Procedure interference may reset transient test state only after proving no submission and discarding the contaminated scenario. A new product defect means STOP AND DEBUG; rebuilding is for source/build-input changes.

## Release implications and final owner delta

Production source changed. A new Desktop package, Developer ID signing/notarization/stapling/Gatekeeper verification, new iOS build (project default advanced to 58), later authorized iOS installation, and a new combined freeze are required. None was performed here. Build 57 remains preserved evidence, not the corrected candidate.

After all automated/review gates and the new freeze/baseline pass, the owner performs only launch/pairing verification, Q1 scan/fingerprint/review/approval with normal user presence, Q2 scan/fingerprint/review/Deny, and final stable-state confirmation. Estimated hands-on time: eight minutes, hard cap ten. No pause to report is inserted inside a request timer. No additional P2/P3/P5 public-chain execution is required.

## Validation and independent review

One independent consolidated review returned **PASS** after identifying and verifying the durable-outcome, false-success, restored-ambiguity, diagnostic/copy, and baseline-linkage corrections described above. Its answer to the central question is **yes for source acceptance and preparation of a new release candidate**. No actionable source findings remain. The same reviewer independently ran 7 host tests and 9 UI/baseline/orchestration tests, all passing. This was one review covering the complete correction, with verification of its findings, not separate micro-reviews.

| Validation | Result |
| --- | --- |
| Original producer → unchanged Swift verifier | Nonce 0 PASS, nonce 1 FAIL before correction |
| Original passive expiry | State 2 remained active; next begin failed `ROUTINE_ACTIVE_SESSION_EXISTS` |
| Only old nonce helper restored in new full harness | Expected FAIL: 3 of 43 XCTest methods failed, including Q2 `action.userOpNonce` after Q1 success |
| Only old local-only Deny behavior restored | Expected FAIL: 3 of 46 XCTest methods failed; Desktop stayed state 2, no rejected reason, next request blocked |
| Corrected Swift suite | 46 tests PASS, including the real persistent multi-request journey |
| Longitudinal acceptance | 6 requests, 3 post-enrollment signatures, 3 local executions, 1 reinitialization, zero public mutations |
| Focused wire, records, journal, transport, enrollment, synthetic security and classifier tests | 74 PASS |
| Full classified Desktop lane | PASS, including existing proof/runtime coverage and the formerly omitted 12-test coordinator suite exactly once |
| New Desktop outcome regressions | 7 host tests PASS; unknown and bad receipt remain blocked; verified failed execution never receives success 204 |
| Baseline/orchestration/UI tests | 9 PASS |
| Typecheck, compilation, classification, preload, whitespace checks | PASS |
| iOS Release fixture exclusion | PASS in unsigned Simulator configuration; no physical release claim |
| Consolidated local pre-physical gate | PASS |
| Fresh independent consolidated review | PASS |
| New hosted CI run | NOT RUN; PR scheduling and failure propagation verified in source/dry-run/local lane |
| Physical installed readback/baseline | NOT PERFORMED; no physical baseline PASS |

The full local gate ran under Node 26.0.0/npm 11.12.1. A rerun encountered a missing executable in the shared Electron dependency; it was an `ENOENT` environment failure, not counted as a pass. The existing cached pinned Electron 41.10.3 archive was extracted into a task-only runtime directory and the complete gate then passed. No frozen dependency directory was repaired or overwritten.

The remote repository is public. No push, PR, hosted workflow, merge, signing, notarization, stapling, Gatekeeper release ceremony, physical installation, owner scan, Face ID, public-chain submission, or combined release freeze was performed. CI enforcement here means the corrected candidate's canonical PR runner executes and fails on the required suite; it is not a claim that this unmerged candidate has already passed hosted CI.

The temporary defect controls were restored immediately, followed by the corrected Simulator/Release rerun. Local evidence is preserved separately from production artifacts. Full-suite totals are intentionally not fabricated by summing mixed custom/node/Hardhat reporters.

## Final verdicts

```text
NONCE 1 RECONSTRUCTS EXACTLY AS 1: YES
SUCCESS -> SECOND REQUEST -> REVIEW: PASS
SUCCESS -> SECOND REQUEST -> REJECT: PASS
EXPIRY -> FRESH REQUEST: PASS
PHONE REJECTION PROPAGATES TO DESKTOP: PASS
STALE TERMINAL STATE CONTAMINATES NEXT REQUEST: NO
BINDING MISMATCH FIELD DIAGNOSTIC AVAILABLE: YES
LONGITUDINAL MULTI-REQUEST TEST: PASS
PREVIOUSLY OMITTED REQUIRED CI SUITE NOW ENFORCED: YES
AUTOMATED PRE-PHYSICAL RELEASE GATE: PASS
INDEPENDENT CONSOLIDATED REVIEW: PASS
SOURCE CORRECTION COMPLETE: YES
READY TO BUILD ONE FINAL RELEASE CANDIDATE: YES
READY FOR PHYSICAL RETEST RIGHT NOW: NO
```
