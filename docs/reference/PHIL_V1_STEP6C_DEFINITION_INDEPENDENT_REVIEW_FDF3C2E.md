# Phil V1 Step 6C Definition Independent Review Of fdf3c2e

Status: Rejected

Date: 2026-08-22

## Exact Candidate

```text
commit: fdf3c2e0263d66e6381ed9e16caf01d2d80c5718
tree: 648e3533125aea77b8401456b3ff0a99bed66103
parent: d7603983ca15f721e06cd0c7d65c414abee56a4f
branch: codex/phil-v1-efficient-route
```

The independent review was strictly read-only. It performed no edit, Git
mutation, installation, cleanup, network/RPC access, physical-device action,
secret/signing action, deployment, publication, or public-chain activity. The
worktree was clean before and after.

## Verdict

```text
REJECT_STEP_6C_DEFINITION_EXACT_CANDIDATE
```

The candidate is not sufficiently exact or internally consistent to authorize
Step 6C-1 implementation. No implementation authority follows from it.

## Findings

### Critical 1: cyclic request and presentation hashes

The presentation includes `requestId`; the request includes the presentation
and `humanPresentationHash`; and `requestId` is defined as the hash of every
request field except itself. The nested copy is not excluded, so the graph is
a fixed-point cycle. An implicit exception would leave cryptographic bytes
ambiguous.

Required correction: publish an acyclic construction DAG, exact construction
order, and literal ABI types. No hashed record may contain a value derived from
itself. The final signed digest must cover every security-relevant request
field.

### Critical 2: the iPhone cannot independently derive the displayed action

The request transports hashes and a prebuilt presentation, but not the raw
action, calldata, authorization envelope, unsigned approval, adapter/account
configuration, capability/policy projection, or catalog records required to
prove the display describes those hashes. It also signs no local-vs-public
execution-environment classification; chain ID `8453` and the Base network
hash could be reused against an identically configured public account.

Required correction: transport canonical raw structured records and exact
catalog/admission bindings; define every presentation equality; sign a
structured local environment identity; and use a local composition domain that
cannot be mistaken for Base mainnet.

### Critical 3: official EntryPoint nonce and account sequence can diverge

Official EntryPoint v0.7 consumes its nonce during validation and records a
failed account execution without reverting the whole bundle. The Step 6B
account increments its own sequence only inside execution, so target failure
rolls the account sequence back while the EntryPoint nonce remains advanced.
The next operation can be permanently blocked on that key.

Required correction: freeze one authoritative EntryPoint-compatible nonce
design and require a failed-execution-then-fresh-success liveness test.

### High 1: in-place Step 5 registry mutation would invalidate accepted trust

The packet proposed adding a scheme to the accepted complete epoch-1 registry
without a new version or migration. That changes the registry hash underneath
accepted capability, policy, and trusted-state bindings.

Required correction: preserve epoch 1 and either define a separate versioned
profile or an exact epoch-2 transition. No accepted registry may be edited in
place.

### High 2: copied runtime code is not a constructor-faithful EntryPoint

Copying normally deployed runtime bytecode to the canonical address preserves
the embedded `SenderCreator` immutable but not constructor-initialized storage,
including the OpenZeppelin reentrancy slot. Code-hash equality alone therefore
does not prove an equivalent deployment.

Required correction: deploy EntryPoint normally under a signed local profile,
or reproduce and verify every constructor effect and immutable dependency.

### High 3: cancellation and crash recovery are contradictory

The state machine allowed cancellation after submission even though a
submitted operation cannot reliably be stopped. It required durable
consumption before submission without specifying the journal, atomic ordering,
restart reconciliation, or precedence among cancellation, expiry, lock,
policy drift, and receipt arrival.

Required correction: define an atomic point of no return, serialized cancel/
submit behavior, durable journal schema and ordering, every restart state, an
outcome-unknown state, and deterministic error precedence.

### High 4: cross-language and receipt bytes remain underspecified

The packet omitted literal format domains and ABI types for several records,
catalog hashing, transport normalization, Unicode/length rules, clock/skew and
`uint64`/`uint48` conversion, event/log binding, state-query encoding, and
receipt identity. Reasonable implementations could produce different bytes or
different success decisions.

Required correction: freeze all domain labels, types, order, normalization,
wire representation, time rules, event and state evidence, transaction/block
identity, and error precedence in the primary packet.

## Positive Confirmations

- The candidate changed exactly ten documentation/status/manifest files and no
  implementation, test, dependency, device, Step 5, Step 6A, or Step 6B source.
- Accepted Step 2, Step 5, Step 6A, and Step 6B identities were unchanged.
- Separating Apple's digest-mode DER profile from Step 6B's raw low-S format is
  directionally correct.
- The strict DER, P-256 range/curve, X9.63, and low-S rules are suitable once
  placed in an acyclic exact record design.
- Routine/root-proof/recovery/STWO/legacy separation and production/network
  non-claims are consistently preserved.
- Step 6C completion remains honestly limited to local composition evidence.
- Step 4 manifest reconciliation reproduced exact SHA-256
  `cb120c3277ba472535ecc78151a6f9ad5f1e9b6356b1dbefef276e1618758f58`.

## Reproduced Checks

```text
npm run typecheck                                      PASS
npm run compile:phil-v1-step6b-account                 PASS
Step 3-6B focused tests                                43 PASS
npm run verify:phil-v1-step6a-artifacts                PASS
npm run verify:phil-v1-step4-artifacts                 PASS
changed-document local links                           9 files, 0 broken
jq empty reference-manifest.json                       PASS
git diff --check                                       PASS
npm run ci:validate-classification                     BASELINE FAIL
```

The classification validator reported the already documented seventeen
unclassified Step 3-through-6B scripts/tests. Candidate `fdf3c2e` changed none
of the validator inputs, package scripts, registry, or validator source. The
failure is pre-existing, is not a candidate regression, and is not a passing
gate.

## Corrective Working-Draft Preflight

The same independent reviewer later examined the uncommitted corrective
working draft strictly read-only. The reviewer confirmed the original seven
findings were materially addressed, but identified four remaining blockers
before the correction could be frozen:

1. application display was not yet bound to the envelope principal and scope,
   and the recovery/validator epochs were not frozen through account and
   policy state;
2. the actual account `UserOperation.callData`, its relation to the complete
   SDK action, and the harmless target calldata/state transition were not
   literal;
3. one response-AEAD sentence circularly named `responseHash` as AAD even
   though the transport section used only direction/session/request AAD; and
4. EntryPoint, adapter, implementation, and audit manifest identities were not
   all mechanically derived.

The corrective packet now addresses these four items with signed
application/principal/scope/epoch anchors; one exact account action tuple,
selector, calldata, and target transition; post-decryption response hashing
under one exact AAD rule; and deterministic non-cyclic version, source-set, and
audit identities. This statement is not acceptance. The resulting exact
commit and tree still require a fresh independent review.

A second strictly read-only preflight of the completed working correction
returned `PREFLIGHT_CLOSED`: all four items above were literally closed, no new
critical/high inconsistency was found, `git diff --check` passed, and no file or
Git mutation occurred. This remains pre-commit drafting evidence, not the
required exact-candidate verdict.

That resulting exact candidate was `a24873e`; fresh independent review rejected
it for four later high-severity gaps recorded in
[the corrective review](./PHIL_V1_STEP6C_CORRECTIVE_DEFINITION_INDEPENDENT_REVIEW_A24873E.md).

## Required Next Gate

Only a bounded corrective definition candidate addressing all seven rejection
findings and four corrective-preflight blockers may proceed to another
independent read-only review. Step 6C implementation,
physical-device work, RPC, deployment, and production authority remain
unauthorized.
