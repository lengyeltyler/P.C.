# Phil V1 Step 4 Independent Review Of eaaae44

Status: Rejected

Date: 2026-08-22

Reviewed commit: `eaaae447a01bf901fc4183338da88b7406981a4e`

Reviewed tree: `f3d8a857a03fc81168a7409339c66f53884e6c83`

Independent verdict: `REJECT_STEP_4_CORRECTIVE_EXACT_CANDIDATE`

## Findings

### Medium: zero approval timestamp remained noncanonical

The TypeScript approval format requires both `approvedAt` and
`approvalExpiresAt` to be positive `uint64` values. The reviewed Cairo
candidate rejected a zero approval nonce but did not reject
`approval.approved_at == 0` at the format stage. When the envelope also used
`valid_after == 0`, an enrolled device could sign the alternate Cairo digest
and pass the remaining time predicates while the canonical TypeScript format
rejected the same evidence.

### Medium: policy-ceiling rejection branches lacked executed tests

The constructor correctly asserted that the reference action value and fee did
not exceed their policy ceilings. The committed tests exercised only the
separate envelope value and fee limits; they did not execute either exact
policy-ceiling rejection branch required by the frozen minimum matrix.

## Prior-finding closure verified

The review independently verified that all five findings against predecessor
`895320f4060ab809b9dab564fcedc1118dfb5780` were closed:

- the accepted Step 3 verifier became a compiled constant with no constructor
  or storage substitution surface;
- zero approval nonce was rejected at format stage;
- format, revocation, binding, epoch, time/limit, replay, signature, proof, and
  proof-input checks followed the frozen precedence;
- all three replay maps were independently addressed and rejected through
  their real storage selectors; and
- constructor validation rejected off-curve P-256 coordinates and terminal
  initial nonce configuration.

## Evidence independently reproduced

- exact commit, tree, parent, branch, and clean tracked state;
- byte-identical accepted Step 3 verifier source, vector, and proof calldata;
- all three TypeScript tests, deterministic artifact verification, typecheck,
  offline build, and all 56 then-committed Cairo tests;
- exact Step 3 and Step 4 Sierra/compiled class identities and sizes;
- valid composition gas and syscall resources;
- exact replay selectors, 13 proof public values, P-256 behavior, atomic replay
  writes, and absence of arbitrary runtime authority; and
- no physical device, secret, network, RPC, deployment, transaction, external
  prover, publication, backend selection, or Step 5 work.

Passing evidence did not cure the remaining format-parity defect or the missing
minimum policy-ceiling tests.

## Verdict

```text
STEP 4 ACCEPTED: NO
SECOND CORRECTIVE CANDIDATE REQUIRED: YES
START STEP 5: NO
```
