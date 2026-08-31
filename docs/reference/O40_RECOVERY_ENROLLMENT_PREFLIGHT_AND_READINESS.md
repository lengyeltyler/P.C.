# O.40 Recovery Enrollment Preflight and Readiness

Canonical phase: **O.40 Real Three-Domain Recovery Enrollment Ceremony and
Production Initialization Completion**.

Classification: `LOCAL_INTERACTIVE_ENROLLMENT_AND_INITIALIZATION`.

Result: `STOPPED_FAIL_CLOSED_BEFORE_CREDENTIAL_CREATION`.

Readiness: **A — Initialization still blocked**.

## Baseline and historical hash resolution

The phase began at
`7a7722bdec6fbff0a484d865ff0fc9af7bc352f5` on
`codex/device-identity-v1` with a clean tracked worktree. The frozen V1
source hashes remain:

- account:
  `39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a`;
- factory:
  `59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9`.

O.38 accepted these verifier/account/factory runtime hashes:

- `0x4597c97018b1fe4b941a035275e229ea5c163db9801545217aa3a93614b1b5be`;
- `0x4f0ea630700c155eb69d7661161abebdcf74dc734127131ad2dfa48dd141e3c5`;
- `0x4359422db2c5320d3c7914a414766fff29779fa45859e0fe28b4af0a67860e90`.

O.39 incorrectly reported the following as its initial hashes:

- `0x4597f14309786bf27cbe50d4193cce030ad34a9e9b0de8acb7d93602cfa0b5be`;
- `0x4f0e49bc58069857b49fc62e24c2bf149277d21c1f73583a5d2012813db1e3c5`;
- `0x4359e7e5de4e81ad62c72bded6173bcdd6e9fa1a7bde376160f6b91436530e90`.

O.40 exported the tracked state at O.38 commit
`25bffe61ff008a85e29c24a32e8ca2f5550c4855`, performed a clean dependency
install and compile outside the active worktree, and reproduced the accepted
O.38 values exactly. The O.39 phase began from that package. No tracked
artifact has the incorrectly reported values. They were manually entered
reporting transcriptions, not a malformed compiler prefix, stale artifact,
uncontrolled compiler drift, or repository corruption.

The O.39 machine evidence now preserves the erroneous strings under an
explicit `Incorrect` field and separately records the accepted O.38 and
actual O.39 pre-change values. The current O.39 post-change package also
reproduced in a clean tracked-only copy:

| Contract | Runtime bytes / hash | Creation bytes / hash |
| --- | --- | --- |
| Verifier | 13,048 / `0x665910b9989f3b83c3f025314fb127755d5abfc46e66ee386fbcbbfefc864dd7` | 13,074 / `0xe77412fbb2d5c2e3bc44881822442e38d3fcc7f2e2dd992742111db6f4511494` |
| Account | 13,811 / `0x4681ca917e3b5c3fff72bb6020f3fb278a43ab893beb05e36865b50422f64519` | 15,630 / `0x7fa7fd5dd4a886e6df8ca13223c5dd3cb167c358e0abf9b0297c2a4624cb4882` |
| Factory | 18,317 / `0x15eca82e16f99f3ea5d9f8443871fc059bb050a8f30856d017be49d0e97c0d95` | 18,692 / `0xe069c2fe769777cb53c785a05f57aee1b73188a8ea343d0d097503806fe9af84` |

Solidity remains 0.8.27, Cancun, optimizer 200, `viaIR`, with unchanged
dependency versions. ABI and storage-layout hashes match the O.39 evidence.

## Enrollment-environment preflight

The synthetic preflight runs before any production credential operation. It
evaluates Standard and Enhanced profiles against the same hard requirements
and produces `READY`, `READY_WITH_USER_WARNINGS`, or `BLOCKED`.

| Boundary | Current observation | Result |
| --- | --- | --- |
| RP ID and origin | no recovery RP/origin is configured | blocked |
| application origin | desktop uses `loadFile`, therefore a file origin | blocked |
| WebAuthn probe | intentionally not run without the canonical secure RP/origin | blocked |
| direct attestation | required by O.39; verifier explicitly rejects direct mode because trust-root validation is not implemented | blocked |
| credential storage | Electron safeStorage exists, but no O.39 recovery-credential adapter or opaque-reference bridge is integrated | blocked |
| Standard Role 1 | no request-bound, expiring secondary-device handoff exists | blocked |
| Enhanced Role 1 | no reviewed hardware-key ceremony is integrated | blocked |
| offline factor UI | no dedicated no-log reveal or restoration input exists | blocked |
| logging | the pure O.39 foundation does not log raw IDs, but end-to-end crash/debug-log exclusion is not established | blocked |
| backup policy | BE and BS are parsed and both must be false | understood, actual authenticator not probed |

Both profile preflights are `BLOCKED`. No RP ID, origin, or authenticator
availability was guessed. A `file://` origin was not silently replaced with
localhost, and direct-attestation policy was not weakened.

The direct-attestation conflict is decisive: the enrollment finalizer
requires `attestationVerified`, the fixed policy requests direct attestation,
and the only current registration verifier always returns an error for
direct mode. A production observation satisfying all three statements
cannot be produced by the current code. Resolving it requires an explicit
trust-root/metadata policy and a stable application origin, not a local
one-line defect fix.

Safe local changes in O.40 add a deterministic preflight evaluator, negative
tests, corrected historical evidence, and a current V3 preparation-only
guard. They do not add an ad hoc origin, caller-asserted attestation, raw
credential storage, or secret-bearing UI.

## Why the ceremony did not pause for user action

The common preflight fails before the Standard/Enhanced choice matters.
Prompting Touch ID, a secondary device, or a hardware key would create a
credential that cannot pass the frozen O.39 production policy or be retained
through an approved storage boundary. O.40 therefore did not request a Role
1 choice and did not create Role 0, Role 1, or Role 2 material.

No offline factor was generated or displayed, no restoration input was
accepted, and no production salt was generated. There are no credential
fingerprints, recovery commitments, recovery configuration, protected local
package, or public initialization manifest to report. Synthetic O.39 values
were not substituted.

## Initialization and infrastructure boundary

The 20-field schema remains structurally current. Fifteen fields are known
from canonical identity, fixed protocol constants, and the selected target.
The factory binding plus four enrollment-derived fields remain unavailable:

1. `factoryBinding`;
2. `primaryDeviceRecoveryCommitment`;
3. `hardwareSecurityKeyCommitment` (the retained ABI name for Role 1);
4. `independentRecoveryFactorCommitment`;
5. `recoveryConfigurationHash`.

The external user salt was not generated because there is no complete
enrollment package to bind. Future verifier and factory addresses are also
unset, so no account address is calculated or invented.

The historical O.23R target
`0x334577B0feB9e1f49d4ca4ff6dAcc6f8732594D7` is classified
`SELECTED_PENDING_FRESH_LIVE_VERIFICATION`. Repository evidence records
runtime hash
`0x33dedb191e724449780bd2ef2abbd77a2692bb154525553fcdebf11a915327ad`
and the expected confirmation interface. O.40 did not access Sepolia, so a
later phase must freshly verify chain, code, receipt, and behavior before
deployment approval.

The O.40 guarded preparation tool binds the current V3 account version and
post-O.39 contract hashes. It reads no credentials or RPC and reports
`INITIALIZATION_BLOCKED`; its broadcast path is absent and `--broadcast`
fails closed.

## Verification and security result

The focused O.40 suite has nine passing tests. It covers both ready
profiles, user warnings, file/RP/origin substitution, protected storage,
logging, clipboard, permissions, offline display/restore, missing
attestation trust, both Role 1 ceremony paths, source-bound current
observations, preparation-only operation, and broadcast rejection.

The complete O.32–O.40 local regression has 238 passing tests and zero
failures. A clean tracked-only copy completed `npm ci`, compiled 60 Solidity
files, repeated all 238 tests, passed TypeScript, and verified deterministic
O.39/O.40 evidence. The O.37.9 test calls `git ls-files`, so the copy used a
new local Git index containing exactly the copied files; it had no remote
and did not fetch.

Repository static analysis completed with no unresolved High or Critical
finding. Solidity is unchanged by O.40, so the reviewed O.39 V2 set of 23
detector occurrences and zero unmitigated High/Critical disposition remains
unchanged. Tracked-file and O.40-diff secret scans pass.

The production dependency audit reports zero vulnerabilities. The complete
pinned development tree still reports 10 Low, 2 Moderate, 8 High, and 0
Critical advisories. The canonical repository triage classifies those Highs
as build/tooling rather than production-runtime exposure, but its Beta gate
remains blocked pending acceptance or remediation. O.40 does not change the
frozen Hardhat/dependency versions and does not hide this separate readiness
blocker.

No production credential, raw credential ID, private key, recovery code,
production signature, user salt, RPC URL, or environment value was created
or committed. `.env.sepolia.local` was not accessed.

## Readiness decision

**A — Initialization still blocked.**

Remaining blockers are:

1. choose and integrate a stable canonical HTTPS RP ID/origin;
2. implement and review direct-attestation trust-root/metadata validation,
   or explicitly version and review a different attestation security model;
3. integrate encrypted recovery-credential storage with opaque references
   and restrictive ignored local records;
4. implement a substitution-resistant Standard secondary-device handoff
   and/or reviewed Enhanced hardware-key ceremony;
5. implement dedicated no-log offline reveal and restoration inputs;
6. prove crash/debug/terminal secret exclusion end to end;
7. resolve or explicitly accept the existing development-tooling High
   advisories through the repository security gate;
8. then rerun the real three-factor ceremony, independence review,
   restoration drill, configuration derivation, and initialization gate.

No public deployment, transaction, external RPC, external bundler request,
fund movement, production account creation, or push occurred. External audit
remains required before meaningful real-value use.
