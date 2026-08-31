# Phil V1 Step 2 Independent Review — `786ab61`

Status: Independently rejected; accepted corrections and new blocker preserved;
superseded by accepted candidate `fe583b6aef84a8636736b2041db2a56046a5972e`

Date: 2026-08-21

Reviewer: Claude Sonnet 5, same separate read-only Claude Code session

Reviewed commit: `786ab618a7f3479324778108eed29eb27dca5b01`

## Boundary And Reproducibility

The reviewer independently verified the exact commit and a clean working tree
before and after review. It re-read the complete review packet, the preserved
`ac49f01` rejection, the complete corrective diff, and every changed source,
test, and documentation file. It made no edits and used no phone, real secret,
recovery material, signer, external prover, RPC, hosted CI, public network,
publication, deployment, or transaction.

The reviewer ran:

```text
npm run test:phil-v1-step2-device-recovery  # 11 passing
npx tsc --noEmit                            # passed, no output
npm run benchmark:phil-v1-step2-recovery   # 200 create / 600 restore; local synthetic only
git diff --check                            # passed
```

It also completed unsigned, Simulator-only app and test-target builds with a
command-scoped `DEVELOPER_DIR`; both succeeded. Those builds established source
and test compilation but did not exercise Secure Enclave behavior.

## Verdict

```text
REJECT_STEP_2_BLOCKING_FINDINGS
```

## Accepted Corrections

### F1 — recovery-set replacement lifecycle: resolved

The reviewer independently confirmed that replacement now requires the same
operation-bound request lifecycle as completion, including notification,
delay, expiry, cancellation, bundle binding, and audit binding. An identity
recovery request cannot be substituted for a replacement request, and the
replacement result no longer returns an extra plaintext package.

It also independently confirmed the adjudication nuance: the continuity bundle
plus any two valid shares always permits immediate offline decryption by design.
The lifecycle controls govern Phil's official transition and cannot stop raw
offline decryption after two-factor compromise. The corrected threat model now
states that boundary honestly.

### F3 — mandatory approval-nonce replay store: resolved

The reviewer confirmed that the nonce store is mandatory in the type and that
the runtime boundary fails closed when it is missing or malformed.

### Original F2 — rollback after metadata failure: source-corrected

The reviewer accepted the rollback of the exact just-created Secure Enclave key
when metadata persistence fails. Its induced metadata-failure branch remains
honestly disclosed and unadmitted. The reviewer classified that unexercised
branch as a residual that can remain unadmitted for this foundation gate, not a
blocker by itself.

## New Blocking Finding — Active Metadata Rotation Regression

The correction removed the prior metadata delete before `SecItemAdd`, which
preserved an existing record on failure but exposed a different defect. The
active metadata slot has fixed generic-password service and account primary
keys. A later generation therefore reached `errSecDuplicateItem` instead of
replacing the active record, after which rollback deleted the new key. The
manager could not complete a second generation unless another caller first
deleted the active candidate, a constraint absent from its contract.

The static test also locked in the absence of the old delete without requiring
safe replacement semantics.

Corrective requirement:

- update the existing fixed metadata item atomically;
- add only when the active item does not exist;
- handle an add/update race without deleting the prior active record;
- retain fail-closed rollback of the just-created key when persistence fails;
  and
- revise the static test to require safe update/add behavior while continuing
  to forbid a delete/add gap.

This correction is Keychain API logic and does not require renewed physical
device evidence. The induced metadata-failure cleanup remains a separately
disclosed, unadmitted residual.

## Other Review Results

The reviewer found no other functional regression. It continued to accept the
cryptographic composition, recovery lifecycle, protected-runtime boundary, and
device-admission policy. It recorded the pre-acceptance request-ID ABI layout
change without a domain-label bump and the Node version delta as informational,
non-blocking residuals.

## Authority

This rejected review authorizes corrective local work and exact-candidate
re-review only. It does not accept Step 2, start Step 3, connect an iPhone,
select a proof backend, publish, deploy, use an RPC, or use real authority.
