# Phil V1 Step 6A Independent Review: `33570bb`

Status: Rejected; bounded corrective candidate required

Date: 2026-08-22

## Exact Target

```text
candidate commit: 33570bb39a334c0ef079fd82c714912ab94b18f4
candidate tree:   b2e559d2f13d7e479ade432fa69a481f6ff7176e
candidate parent: 71136a760c13072a6659a44b38110eae35182223
```

The review was independent and read-only. It made no edit, commit, install,
device connection, secret use, external-prover call, RPC or bundler contact,
simulation, signature, deployment, UserOperation, transaction, publication,
backend selection, or Step 6B change.

## Findings

### High: committed rejection coverage is incomplete

The production source independently failed closed for every probed case, but
the committed eight-test matrix does not execute all mandatory and documented
rejection branches.

The manifest tests omit substitutions of:

- adapter version;
- scope canonicalization;
- action codec;
- replay model;
- fee model;
- device-signature suite;
- implementation hash; and
- audit-status hash.

The action tests omit rebuilt account, target, target-calldata, and nonce
substitutions; fee overflow; malformed and noncanonical values; and tampering
of the stored call commitment, UserOperation nonce, and maximum-fee value.

The reviewer independently exercised the omitted branches and they rejected.
The finding is therefore deterministic committed-evidence incompleteness, not
a reproduced source fail-open. Mandatory review question 19 is still false for
the exact candidate.

### Medium: canonical roadmap status is contradictory

The roadmap header and current-status section say Step 6 was authorized and
Step 6A was implemented, while its ordered table still labels Step 6 “Not
started; separate authorization required.” Mandatory review question 20 is
therefore false for the exact candidate.

This review-record commit corrects only the current status documentation. It
does not alter the rejected candidate or close the missing-test finding.

## Verified External Facts

- [Base's network documentation](https://docs.base.org/base-chain/quickstart/connecting-to-base)
  identifies Base mainnet as chain ID 8453.
- [Base's preinstall documentation](https://docs.base.org/base-chain/specs/protocol/execution/evm/preinstalls)
  lists ERC-4337 v0.7.0 EntryPoint at
  `0x0000000071727De22E5E9d8BAf0edAc6f37da032`.
- [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) defines a 192-bit nonce
  key and 64-bit sequence, binds `userOpHash` to EntryPoint and chain ID, and
  leaves signature validation to the account.
- [Base Account's ERC-4337 use](https://docs.base.org/base-account/overview/what-is-base-account)
  does not establish compatibility with Phil's validator.

## Reproduced Evidence

- Candidate commit, tree, parent, and review range matched exactly.
- Typecheck and deterministic artifact verification passed.
- All 8 Step 6A, 4 Step 3, 3 Step 4, and 14 Step 5 tests passed.
- Source and fixture SHA-256 values independently matched the manifest.
- Every domain, manifest, action, account, nonce, intent, envelope, device-
  approval, and final authorization hash independently matched.
- Independently constructed malformed and substitution probes failed closed.
- Existing EVM/runtime compatibility paths were byte-stable and had no import
  or call-graph reachability from the candidate.
- The repository remained clean.

The independently recomputed primary hashes were:

```text
source sha256:     16a547a833e8fbe459ce3ac8faef75336a593a3e2c2ea8968cbe981569dd8d3d
fixture sha256:    0c820940e709ed09a65117e9ce2342de88825cebce51796146ef849d6b0a4f89
manifest:          0x163dcb7e0bad5098a57ef06d7f08f2414e0610f7846d5690dc1d7961a8a987db
action:            0x7ae7dd7164e0e79a49f63a3067cd158045bb572f4e985cacee9dcd9f1130a778
account binding:   0x372dda6be00b746c53e7a75090517030294bc6c6e7bdd00be54fd7b39b3f2d77
nonce domain:      0x8bc940add966d65d1b202be0354155bf50dcdeffa7886647d14d9c3c163e3f4e
intent:            0x535129076bfb94658df1488750ba2652022024fd3d790c416ee7ecda43f89909
envelope:          0x7186691da4e0ba447af2ad906d0f951b583ab43b3f0af1ad9b9aee13d06ea6c5
device approval:   0x2f432f014881cb28365f41ed51de3a79c1243c3412a0db6b81580e4fbbc05e70
authorization:     0x1bc4a14b212ddc84987bfbdb2a01c707cc81971c01bebdb15c90b8ee9b73b589
```

## Mandatory-Question Result

Questions 1-18 passed, subject to the documented local-only boundary. Question
19 failed because committed rejection coverage is incomplete. Question 20
failed because the exact candidate's roadmap status is contradictory.

## Verdict

```text
REJECT_STEP_6A_EXACT_CANDIDATE
```

```text
CURRENT PHIL CLAIM: ALGORITHM AGILE ONLY
STEP 6A LOCAL BINDING ACCEPTED: NO
STEP 6 COMPLETE: NO
DEVICE SIGNATURE VERIFIED BY STEP 6A: NO
BASE NETWORK AUTHORIZATION PATH AVAILABLE: NO
POST-QUANTUM CAPABILITY: NONE
PRODUCTION PROOF BACKEND SELECTED: NO
PUBLIC DEPLOYMENT AUTHORIZED: NO
START STEP 6B: NO
```

The efficient next move is a bounded corrective Step 6A candidate that adds
the missing deterministic rejection coverage while preserving the source and
all authority boundaries. That new exact candidate requires another independent
read-only review.
