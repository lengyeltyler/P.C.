# Phil V1 Step 6B Bounded Corrective Implementation Report

Status: Implemented; independent re-review required

Date: 2026-08-22

## Scope

This correction addresses only the committed-coverage blocker in the
[independent rejection of `8b72646`](../reference/PHIL_V1_STEP6B_INDEPENDENT_REVIEW_8B72646.md).

The production candidate
`contracts/base/erc4337/PhilV1Step6BLocalAccount.sol` is byte-for-byte
unchanged, retaining SHA-256
`3bd20a05efcb2d552d767267822210bedf04a6661eca18c6dba11fad50ca174c`.
No identity, envelope, device, capability, policy, nonce, P-256, account,
network, recovery, proof, or post-quantum semantic changed.

## Correction

The local EntryPoint harness adds two test-only methods:

- `validateOnlyFor`, which invokes the real account while allowing tests to
  supply an exact caller-selected hash, sender, and missing-funds value; and
- `executeOnly`, which invokes the real account execution entrypoint from the
  pinned EntryPoint address and bubbles the account's exact revert.

Neither helper is production code or an EntryPoint implementation.

The focused suite grows from seven to fourteen tests and now directly covers:

- malformed, zero, high-S, and wrong-key P-256 evidence;
- exact sender, nonce, both packed gas limits, pre-verification gas, both
  packed fee fields, `initCode`, paymaster data, calldata, userOp hash,
  caller, and missing-funds failures;
- the validation-data intersection of action and device-approval windows;
- every immutable envelope/device/proof/capability/policy/approval rejection
  class documented by the candidate;
- action-format zero, relation, target, calldata, validity, and fee-overflow
  branches;
- constructor trust anchors and invalid P-256 points;
- validation-time and execution-time expiry, nonce, consumed-authorization,
  independent-key, and terminal-`uint64` behavior; and
- target-revert atomic rollback.

Every substitution asserts the intended production custom error rather than
accepting an arbitrary revert.

## Authority Accounting

```text
STEP 6B FIRST CANDIDATE ACCEPTED: NO
STEP 6B CORRECTIVE CANDIDATE IMPLEMENTED: YES
STEP 6B CORRECTIVE CANDIDATE ACCEPTED: NO
PRODUCTION ACCOUNT SOURCE CHANGED: NO
STEP 6 COMPLETE: NO
OFFICIAL ENTRYPOINT INTEGRATION VERIFIED: NO
BASE NETWORK AUTHORIZATION PATH AVAILABLE: NO
PRODUCTION AUTHORITY: NO
EXTERNAL RPC OR PUBLIC-NETWORK ACTIVITY: NO
START STEP 6C: NO
```

The correction is ready only for an independent read-only review of its exact
commit and tree.

## Independent Review Result

Exact corrective candidate `58731cf65a30ab4646d5fd698044b99c289931a5`
was independently rejected because the before-`validAfter` test mined its
transaction at `validAfter` and reached the later approval-start predicate.
Every other original coverage finding was closed. See
[the review record](../reference/PHIL_V1_STEP6B_CORRECTIVE_INDEPENDENT_REVIEW_58731CF.md).
