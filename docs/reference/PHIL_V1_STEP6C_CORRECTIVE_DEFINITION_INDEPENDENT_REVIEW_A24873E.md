# Phil V1 Step 6C Corrective Definition Independent Review Of a24873e

Status: Rejected

Date: 2026-08-22

## Exact Candidate

```text
commit: a24873eb4ead424748c94ac7df9c38bbaf096a18
tree: 8c7e7c9ba97874209e52aaa597bc375b144bb292
parent: fdf3c2e0263d66e6381ed9e16caf01d2d80c5718
branch: codex/phil-v1-efficient-route
```

The fresh independent review was strictly read-only. It made no file or Git
mutation, installation, cleanup, network/RPC call, hosted-CI request, device or
secret/signing action, deployment, transaction, publication, or public-chain
action. The exact branch and clean worktree were verified before and after.

## Verdict

```text
REJECT_CORRECTIVE_STEP_6C_DEFINITION_EXACT_CANDIDATE
```

No Step 6C implementation, physical-device, network, or deployment authority
follows from this candidate.

## Findings

### High 1: deployed target code is outside the signed admitted state

The account configuration, policy, catalog, and presentation bind only the
target address. The receipt requires a target code hash later, but no signed
record supplies the expected value. The source-only implementation hash and
unsigned broader artifact manifest cannot prove which runtime is installed at
the approved address.

Required correction: place the exact deployed target runtime code hash in the
signed configuration/policy/presentation graph, freeze its catalog binding,
store it in the account, and compare `target.codehash` before validation and
execution as well as in the receipt.

### High 2: post-commit crash evidence cannot identify the official operation

The journal stores only the local serialized-operation hash. It omits the
official EntryPoint `userOpHash`, sender/nonce tuple, exact operation bytes,
target pre-state, and pre-submission local block identity. A failed account
execution rolls account/target events back, leaving only the EntryPoint event
keyed by the distinct official hash. State-6 recovery therefore cannot identify
that exact failure or later verify its outcome.

Required correction: durably commit the exact packed operation bytes, local and
official hashes, EntryPoint, sender, nonce, target pre-state, and local block
scan anchor before the external effect. Reconciliation must search and verify
the exact official event/receipt and never resubmit ambiguous work.

### High 3: `executeAuthorized` ABI and selector remain ambiguous

The packet names nested structs without publishing their complete Solidity
tuple declarations or canonical selector. The inherited SDK envelope includes
`formatVersionHash`, while the Step 6B Solidity calldata struct omits it. The
approval name also points to a TypeScript interface rather than one frozen
Solidity declaration. Multiple selectors and byte encodings satisfy the prose.

Required correction: define distinct complete Solidity calldata structs,
canonical tuple signature, numerical selector, argument order, strict decode/
re-encode rule, and field mapping to every SDK digest.

### High 4: QR, HTTP frame, base64url, and journal-AAD bytes are incomplete

The QR bootstrap lists types without a serialization. HTTP methods, body/frame
schemas, expected statuses, and canonical base64url padding are absent. The
journal AAD names an undefined journal domain. Different Swift/Desktop
implementations can therefore authenticate different bytes.

Required correction: freeze exact QR bytes and textual wrapper, byte order and
length, canonical unpadded base64url, HTTP methods/content types/status/error
handling, encrypted frame bytes, and the exact journal AAD domain and
concatenation.

## Positive Confirmations

- The original seven rejection findings were materially corrected.
- The four earlier working-draft preflight blockers were materially corrected.
- The acyclic graph, local/public split, sole EntryPoint nonce, immutable Step
  5 epoch-1 boundary, normal EntryPoint deployment, authority epochs,
  response-hash ordering, and deterministic manifest labels remain sound.
- Candidate changes were documentation/reference-manifest evidence only;
  implementation, tests, package inputs, and classification inputs matched the
  parent.
- Typecheck, Step 6B compilation, all 43 focused Step 3-through-6B tests, all
  four artifact verifiers, JSON/diff integrity, and 381 local links passed.
- The exact seventeen classification failures reproduced unchanged and remain
  a baseline failure, not a passing gate.

## Second Corrective Working-Draft Preflight

A strictly read-only working-draft preflight of the second correction confirmed
the four rejection findings materially closed and independently recomputed
selector `0x5a99466a`, but found two narrow contradictions: a 65,536-byte
ciphertext plus 33-byte frame exceeded the HTTP body cap, and late exact failed
evidence had no `outcome_unknown -> failed_execution` transition. The packet
now separates the 65,503-byte plaintext/ciphertext cap from the 65,536-byte
HTTP body cap and permits only exact late-evidence transitions `25 -> 23` for a
verified failure or `25 -> 8` for verified success. This is working-draft
preflight evidence, not candidate acceptance.

A second strictly read-only preflight returned `PREFLIGHT_CLOSED`: both narrow
contradictions were closed, `git diff --check` passed, and no new critical/high
issue or repository mutation was found. The exact second corrective commit and
tree then received a fresh independent verdict: exact candidate `227bd48`, tree
`cd5a734`, was accepted with no critical/high finding. See
[the acceptance record](./PHIL_V1_STEP6C_SECOND_CORRECTIVE_DEFINITION_INDEPENDENT_REVIEW_227BD48.md).

## Required Next Gate

Only a bounded second corrective definition candidate closing all four high
findings could receive another independent read-only review. That gate passed
for `227bd48`; Step 6C nevertheless remains unimplemented and Step 6 remains
incomplete.
