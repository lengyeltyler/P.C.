# PhilCore Controlled Sepolia Beta Independent AI Review Record

Status: **rejected; corrective candidate required**

Review date: 2026-08-25

Reviewer: Claude Sonnet 5, independent read-only AI security review

Reviewed commit: `729435182e34f3c78262d289066136e3aa092566`

Reviewed tree: `a301991abc8f8f5e1a93ea0484c893686d83cd88`

Full report SHA-256:
`5313fae77022b61ce748b72d5ed6617a64e1dc7f34398c8426ef0874c83f49bc`

The reviewer verified the exact source identity and read all 34 files in the
frozen scope. The environment had no installed dependencies, so the reviewer
performed source-level analysis and independently checked the recorded
evidence rather than rerunning the test suite.

## Blocking result

`H-1` (HIGH) found that the composed ActionGate accepted the same public
one-time authorization fields from any account registered by the permissionless
factory. A throwaway registered account could copy a pending legitimate
operation's envelope digest, nullifier, device nonce, expiry, and recipient,
consume them first, and force the legitimate operation to fail.

Required correction:

- bind the deployed ActionGate to the one predicted counterfactual Beta
  account;
- reject every other factory-registered account;
- preserve one-time replay protection for the authorized account; and
- add an adversarial copied-calldata regression test.

The review also recorded `M-1` (MEDIUM): the gate did not structurally enforce
the profile's current-execution-owner recipient policy. The corrective
candidate addresses both findings together by resolving the authorized
account's current execution owner on chain.

The remaining findings were LOW: permissionless recovery-authority-rotation
completion, nonce-key-0 as a convention rather than a protocol restriction,
and raw local-pairing HTTP buffering before its later size check. They were not
classified as controlled-Beta blockers, but remain recorded residual work.

## Original verdict

```text
CLAUDE INDEPENDENT AI SECURITY REVIEW: REJECTED
UNRESOLVED CRITICAL: 0
UNRESOLVED HIGH: 1
CONTROLLED SEPOLIA BETA BLOCKED BY THIS REVIEW: YES
PROFESSIONAL EXTERNAL AUDIT: NOT ESTABLISHED
```

This record does not accept the correction. Acceptance requires a new exact
commit/tree and a fresh independent read-only re-review.
