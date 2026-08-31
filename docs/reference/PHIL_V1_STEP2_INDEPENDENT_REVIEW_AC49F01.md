# Phil V1 Step 2 Independent Review — `ac49f01`

Status: Independently rejected; findings preserved; superseded by accepted
candidate `fe583b6aef84a8636736b2041db2a56046a5972e`

Date: 2026-08-21

Reviewer: Claude Sonnet 5, separate read-only Claude Code session

Reviewed commit: `ac49f01c329a8396b23acd28b4a9736219a1e355`

## Boundary And Reproducibility

The reviewer independently verified the exact commit and a clean working tree
before and after review. It read the complete review packet and required source
and documentation scope. It made no edits and used no phone, real secret,
recovery material, signer, external prover, RPC, hosted CI, public network,
publication, deployment, or transaction.

The reviewer ran:

```text
npm run test:phil-v1-step2-device-recovery  # 11 passing
npx tsc --noEmit                            # passed, no output
npm run benchmark:phil-v1-step2-recovery   # 200 create / 600 restore; local synthetic only
git diff --check                            # passed
```

The review environment used Node 26.5.1 rather than the declared Node 26.0.0.
That was recorded as informational toolchain drift, not a correctness finding.

## Verdict

```text
REJECT_STEP_2_BLOCKING_FINDINGS
```

## Findings

### F1 — High / blocking: replacement bypassed the official recovery lifecycle

`replacePhilIdentityDataRecoverySetV1` accepted a bundle, any valid share pair,
time, and an opaque nonzero destructive-approval digest, then immediately
restored the package and rotated the set. Unlike the normal completion path,
it did not require an operation-bound request, notifications, delay, expiry,
or cancellation state. That contradicted the finalization ledger's claim that
replacement shared those controls.

Adjudication nuance: any two recovery factors intentionally permit immediate
offline decryption of the encrypted continuity package; no local delay can
cryptographically prevent that threshold failure. Creating a new local bundle
also does not invalidate an independently held old bundle. The review therefore
overstated replacement as a new plaintext leak and automatic owner lockout.
The actual blocking defect remains valid: Phil's official replacement
transition bypassed its claimed lifecycle gate.

Corrective requirement:

- bind the request to `recovery_set_replacement` rather than allowing an
  identity-recovery request to be substituted;
- enforce the same notification, delay, expiry, cancellation, bundle, and
  destructive-approval request binding before replacement;
- bind the replacement audit/completion to that request; and
- do not return an extra plaintext continuity package from the replacement
  result.

### F2 — Medium: Secure Enclave key could outlive metadata failure

The manager persisted a permanent Secure Enclave key before saving its public
metadata. If metadata persistence failed, the method returned an error but did
not delete the just-created key, leaving an undiscoverable orphan unless the
same generation was retried.

Corrective requirement: on metadata failure, delete the exact just-created
tag before propagating the metadata error; do not delete an existing metadata
record before a replacement metadata write succeeds.

### F3 — Low / non-blocking: replay store was optional

`verifyPhilDeviceApprovalEvidenceV1` rejected replay only when its caller chose
to provide `consumedApprovalNonces`. The function is dormant, and the durable
store remains later composed-runtime work, but the verification API could be
called without any replay-set check.

Corrective requirement: make a nonce store mandatory and fail with an explicit
error when it is absent or malformed.

## Independently Accepted Areas

The reviewer accepted the pairwise HKDF/AES-GCM construction itself, canonical
encodings, public-secret redaction, corruption/mixed-set/rollback rejection,
post-recovery epoch/revocation transitions, device-approval binding, protected
runtime non-reachability, restricted device admission, and Step 2/Step 3 scope
separation. The iOS boundary was accepted aside from F2.

## Authority

This rejected review authorizes corrective local work and exact-candidate
re-review only. It does not accept Step 2, start Step 3, connect an iPhone,
select a proof backend, publish, deploy, use an RPC, or use real authority.
