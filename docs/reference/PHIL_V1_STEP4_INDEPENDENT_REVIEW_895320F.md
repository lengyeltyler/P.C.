# Phil V1 Step 4 Independent Review Of 895320f

Status: Rejected

Date: 2026-08-21

Reviewed commit: `895320f4060ab809b9dab564fcedc1118dfb5780`

Reviewed tree: `a2629fcb56eaf0b67be6dce74161492760e80ba5`

Independent verdict: `REJECT_STEP_4_EXACT_CANDIDATE`

## Findings

### High: accepted verifier was not pinned

The reviewed constructor accepted `root_verifier_class_hash` as configuration,
stored it, and dispatched the proof call directly to that stored class. The
test harness supplied and checked the accepted Step 3 verifier, but the
contract did not enforce that identity. A substitute class implementing the
same selector could therefore return chosen public inputs without verifying
the accepted proof.

### Medium: zero approval nonce was accepted

The TypeScript approval format required a nonzero approval nonce. The Cairo
candidate hashed and replay-checked zero without rejecting it, so a correctly
signed zero-nonce approval could pass.

### Medium: rejection precedence differed from the frozen gate

Replay checks ran before approval format, identity, suite, presentation, epoch,
and time checks. This did not create a state write, but it violated the frozen
failure ordering and could disclose consumed replay state for malformed
approvals.

### Medium: independent replay coverage was incomplete

The success test observed all three replay flags, but repeated execution failed
at the sequential account nonce. The suite did not independently exercise the
envelope-digest, root-nullifier, and approval-nonce rejection branches. It also
lacked zero-nonce, invalid-coordinate, approval-precedence, and terminal-nonce
cases.

### Low: immutable denial-of-service configurations were admitted

Off-curve device coordinates were deferred until action execution, and
`next_nonce` could be initialized to `u64::MAX`. With no configuration mutator,
either configuration could permanently prevent successful authorization.

## Evidence independently reproduced

- exact commit, tree, parent, and clean tracked state;
- byte-identical accepted Step 3 verifier sources, vector, and calldata;
- exact Step 3 and Step 4 Sierra/compiled class identities and sizes;
- deterministic generator output and all three TypeScript tests;
- all 48 then-committed Cairo tests and the reported valid-call resources;
- envelope/digest endian parity and P-256 fixture validity; and
- absence of arbitrary execution, upgrade, signer, device, RPC, STWO, product-
  runtime, deployment, transaction, or Step 5 authority.

Passing evidence did not cure the unpinned-verifier bypass or the other unmet
gate requirements.

## Verdict

```text
STEP 4 ACCEPTED: NO
CORRECTIVE CANDIDATE REQUIRED: YES
START STEP 5: NO
```
