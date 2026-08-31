# Phil V1 Step 6C Routine Authorization Threat Model

Status: Step 6C complete as a bounded local architecture/composition gate; exact complete physical evidence 0461ac7/tree c14838c independently accepted; public-network and production authority remain false

Date: 2026-08-22

## Security Goal

Step 6C must establish one bounded fact: a harmless local account action can
execute only when the accepted Phil envelope, policy, capability, device,
human presentation, packed UserOperation, official local EntryPoint behavior,
and final receipt all describe the same request.

The person is not expected to inspect cryptographic bytes. Phil carries that
burden by canonicalizing the action inside a protected coordinator, showing
the same deterministic facts on the iPhone, requiring Secure Enclave user
presence, enforcing the bindings again in the account, and preserving an
auditable receipt.

## Protected Assets

- the private Phil root and identity/data recovery material, which must never
  enter this routine path;
- the routine Secure Enclave private key;
- the admitted device enrollment, adapter manifest, capability, policy,
  epochs, replay state, and local account configuration;
- the canonical human presentation and the digest it represents;
- the pending authorization session and transport keys;
- the exact packed UserOperation and EntryPoint simulation result; and
- the final receipt and audit chain.

The local target value is disclosed synthetic test data and is not protected.

## Trust Boundaries

The Step 6C candidate may trust only:

- the protected Desktop main-process/runtime boundary for admitted state,
  canonicalization, replay persistence, orchestration, and audit;
- the iOS app's protected routine-approval module, Keychain access controls,
  LocalAuthentication result, and Secure Enclave private-key operation;
- pinned reviewed source, toolchains, dependencies, and deterministic artifact
  hashes;
- the exact Step 6C local account and harmless target code;
- official EntryPoint v0.7 behavior from the pinned package in its normal local
  constructor deployment; and
- the in-process test chain only as local evidence.

The requesting app, Desktop renderer, iPhone display input before independent
validation, local network, pairing QR contents, bundler-shaped caller, target
return data, legacy Alpha state, repository history, and all external networks
are untrusted.

## Threats, Required Controls, And Residual Risk

| Threat | Required Step 6C control | Required evidence | Residual risk after local acceptance |
| --- | --- | --- | --- |
| Renderer or app changes target, value, fee, calldata, network, or expiry | Protected coordinator accepts a typed request, canonicalizes every field, selects admitted state internally, and rejects unknown/extra fields | One positive vector plus single-field substitution and unknown-field tests at every boundary | A future application catalog and permission-administration system are absent |
| User sees one action but signs another | Desktop and iPhone independently derive the same presentation record and hash from canonical bytes; six stable labels are constructor-admitted; the dynamic parameter summary is derived from the strictly decoded target boolean; response binds request digest and presentation hash | Cross-language vector and changed-label/schema/summary/address/value/fee/expiry tests | Human misunderstanding and deceptive but correctly identified apps remain product risks |
| App label is valid but belongs to a different principal or scope | Frozen application ID derives the principal; scope instance binds application, environment, and account; account configuration, policy, presentation, envelope, and constructor storage agree on principal/scope and all authority epochs | Application/principal/scope/account/environment and each epoch substituted independently | A future app-admission and scope-rotation ceremony remains outside this local gate |
| Hash cycle or unsigned outer request leaves fields unbound | Literal acyclic DAG: raw records, presentation, envelope, core, approval nonce, device digest, request ID, then SHA-256 signing digest; presentation contains no request-derived value | Construction-order proof and one-field-at-a-time final-digest changes | Future schema additions require a new format identity and renewed graph review |
| Local approval is replayed as public Base authority | Signed environment uses chain `31337`, local-only network/adapter IDs, normally deployed local EntryPoint, and three false authority booleans; Base chain/hash/canonical address are rejected | Every local/public identity and classification substitution | An entirely compromised trusted Desktop and iPhone can misrepresent their own environment |
| Accepted Step 5 registry trust anchor changes in place | Epoch-1 source/hash remains byte-identical; a separate local V2 profile inherits it without migrating existing authority | Parent/candidate blob identity and registry/profile hash vectors | Migration of a real epoch-1 profile remains unimplemented exceptional work |
| Routine request reaches root proof, STWO, recovery, or generic signer | Dedicated routine operation class and typed modules; zero proof fields; separate key tags, protocol contexts, endpoints, and IPC methods; source reachability tests | Static import/call graph checks and runtime sentinel tests | Repository history retains quarantined compatibility code |
| Apple and Solidity sign different digests | Acyclic request graph ends in `requestId`; V2 SHA-256 prehash is exactly the 32-byte domain plus `requestId`; byte-exact Swift/TypeScript/Solidity vectors | Both valid directions and every core/request/domain substitution | Physical Secure Enclave behavior is unverified until the ceremony |
| DER ambiguity, negative integer, padding abuse, high-S malleability, or raw-length confusion | Strict minimal DER parser; curve-range checks; deterministic low-S normalization; fixed 64-byte raw wire output | Canonical, malformed, boundary, high-S, zero, order, length, and trailing-byte matrix | Custom parser correctness requires independent review and should be minimized |
| Public-key substitution or malformed curve point | V2 enrollment binds device/key IDs, epoch, provider profile, suite, wire encoding, X9.63 bytes, fingerprint, and P-256 coordinates; every consumer validates the curve point | Wrong prefix, length, fingerprint, coordinate, device, key, epoch, and suite tests | Platform attestation and proof of genuine Secure Enclave origin are not established by public-key bytes alone |
| Lost, forged, or cross-language-incompatible enrollment success splits iPhone and Desktop generations | Enrollment QR binds a Desktop ephemeral P-256 acceptance key; Desktop signs the already-derived bootstrap/proof digest, destroys the key, releases the response only after protected persistence, and replays the cached response only until expiry; iPhone uses true prehashed Security-framework verification, commits only after verification, and otherwise retains activated-pending state after publication | Exact TypeScript response verified in Swift, double-hash negative witness, low/high-S DER matrix, lost first response, forged signature, retry/restart recovery, pre-publication rollback, generation-2 full-flow, expiry, and Desktop idempotent-replay tests | A permanently interrupted local session can require a fresh enrollment ceremony, while physical-device interruption behavior remains unverified |
| Pairing endpoint or local-network attacker intercepts/replays a request | Ephemeral authenticated key agreement, encrypted frames, transcript/context binding, comparison fingerprint, RFC1918 endpoint restrictions, expiry, sequence, and exact-once session consumption | MITM/key/context/endpoint/ciphertext/order/replay/timeout tests | Compromised Desktop or iPhone can still betray its own trusted boundary |
| Swift and Desktop serialize different QR, HTTP, frame, or journal-AAD bytes | Exact 216-byte authorization and 192-byte enrollment QR layouts and wrappers, canonical unpadded base64url, strict JSON, methods/media/status rules, binary encrypted frame, direction AAD, and ABI-encoded journal AAD | Cross-language byte vectors plus every length/order/padding/method/status/media/AAD substitution | Future transport versions require new magic, context, and independent admission |
| Circular or inconsistent response authentication makes the signed reply unverifiable | Request and response AEAD use only the frozen direction/session/request AAD; response hash is computed from strict plaintext after successful decryption and then verified against protected request state | Wrong direction/session/request AAD, ciphertext/tag, response field, and post-decrypt hash tests | Transport implementation and OS networking still require product and physical evidence |
| Cancel, background, lock, disconnect, or timeout races submission | Before the durable submission-commit CAS, cancellation invalidates the request; after it, cancellation returns `too_late` and never claims execution stopped; one protected mutex and frozen precedence serialize the race | Cancellation and lifecycle races at every transition, crash point, late response, stale session, and restart | OS scheduling races still require physical-device evidence |
| Crash after submission commit loses the identity of a failed operation | The fully synced commit record stores exact packed operation bytes, local and official hashes, EntryPoint/sender/nonce, target pre-state, and scan-start block; reconciliation verifies one exact official event/receipt and never resubmits ambiguity | Crash before/during/after submit, successful and failed official events, no/multiple events, reorged anchor, unavailable chain, and late exact evidence | A destroyed local chain can leave a permanently honest outcome-unknown result |
| Deletion failure resumes authority after a committed or indeterminate wipe | An authenticated OS-protected deletion marker is the commit point; a failure known to precede it is retryable, while marker-present, committed, or indeterminate failure permanently poisons the live product and restart completes cleanup | Pre-commit failure/retry, authenticated and unauthenticated markers, interrupted committed cleanup, lifecycle serialization, and post-commit poison tests | Filesystem and OS-protection behavior still requires packaged-product evidence |
| Corrupt enrollment or runtime provisioning failure is mistaken for first use | Only exact `ROUTINE_ENROLLMENT_NOT_FOUND` selects enrollment; every protection, validation, configuration, and runtime error propagates and leaves the feature unavailable | Falsey/corrupt enrollment records plus injected runtime-provisioning failure and no-enrollment-fallback tests | User-facing diagnosis remains intentionally coarse to avoid leaking protected state |
| EntryPoint-shaped harness or copied code hides real ERC-4337 behavior | Normally deploy pinned official EntryPoint v0.7 on chain `31337`; bind actual address, code, deterministic SenderCreator, constructor reentrancy slot, empty state, deposit, and exact static simulation before `handleOps` | Constructor/storage/code/dependency, deposit, nonce, simulation, event, fee, and beneficiary assertions | Local deployment does not prove Base code/address authenticity or live bundler policy |
| Frozen catalog or policy accidentally makes the account single-operation | Catalog kind 6 binds a stable method/code/value schema rather than the nonce-bearing action hash; the stable capability binds that schema; a constructor-frozen 24-hour policy contains independently signed 120-second requests | Failed nonce `n` then fresh successful `n+1` with changed action/request/time/signature hashes and byte-identical schema/capability/catalog/policy hashes | The disposable local profile expires after 24 hours and has no production policy-renewal ceremony |
| Missing prefund, gas, validity, or nonce behavior differs from Step 6B | Account deposit makes missing funds zero; official EntryPoint keyed nonce is the sole sequence; no second account sequence survives; failed execution must be followed by a fresh successful next nonce | Insufficient deposit, wrong EntryPoint nonce, gas/fee/request-window/policy-window substitutions, replay, and failed-then-fresh liveness | Production gas volatility and bundler admission are unmeasured |
| Simulation passes but a different operation executes | Coordinator freezes the serialized operation and hash after approval; execution consumes that exact object; receipt rebinds UserOp hash, Phil authorization hash, target event, and state | Mutation-between-simulation-and-handleOps and receipt-substitution tests | Same-block external state races are not modeled by a single local target |
| Execution cannot emit or binds the wrong official UserOperation hash | Successful actual validation stores the exact EntryPoint-supplied `requestId -> userOpHash` handoff; execution requires it, emits it, and deletes it after success; failed-call residue is request-specific audit state and never gates another nonce | Different hash under one request ID, simulation non-persistence, failed target, fresh next nonce, successful deletion, and direct-call negatives | Failed local requests retain a harmless mapping entry until disposable-profile deletion |
| Off-chain action and account calldata authorize different calls | One named account-action tuple and sole `executeAuthorized` selector map exact PackedUserOperation fields and raw target calldata back to the full SDK action; exact 68-byte target calldata must decode/re-encode to the frozen selector/value and canonical boolean; the account recomputes the complete graph and exposes no generic execution surface | ABI round-trip plus selector, tuple, gas/fee, nonce, calldata length/value/boolean/trailing bytes, target, method, revert, and fallback substitutions | Later action codecs and multi-call support require separate versioned admission |
| Approved target address contains different runtime code | Signed configuration, policy, catalog, and presentation bind target address plus runtime code hash; account stores and checks `target.codehash` at validation/execution; receipt compares the same admitted hash | Wrong/empty/replaced target runtime before validation, between validation/execution, and at receipt | Production upgrade/proxy semantics are intentionally absent and require separate admission |
| Target reentrancy, revert, or misleading return data corrupts state | Only one immutable harmless target/method; EntryPoint nonce remains authoritative across failed execution; receipt requires exact events/state, not merely non-revert | Revert, no-event, wrong/duplicate event, reentry, rollback, and next-nonce liveness tests | General malicious application targets require later capability-specific review |
| Legacy Alpha identity is silently treated as V1 | New storage namespace, schema, IDs, and creation path; reject legacy file/provider/validator formats | Import, path, schema, and provider substitution tests | A user-facing migration ceremony remains unimplemented |
| Routine key becomes recovery or unrestricted account authority | No recovery APIs on routine signer; no generic signing API; account admits only canonical routine call; key rotation must be a later exceptional operation | Interface and reachability checks plus recovery/generic-call negatives | Step 6C account remains immutable and lacks a production rotation/recovery lifecycle |
| Version drift silently changes trust | Pin package/version, source hashes, normally deployed EntryPoint/environment, constructor state, suite/provider/wire IDs, local V2 registry, protocol version, contract bytecode, and artifact manifest | Deterministic regeneration and clean-tree reproduction | Advisories or upstream changes after acceptance require active monitoring and a new admission decision |
| Caller-selected manifest hashes falsely claim reviewed code | Version IDs are exact label hashes; implementation identity is derived from a frozen ordered source set; audit identity derives from status, implementation hash, and an exact review-report hash without including generated artifacts | Reorder/add/remove/content/status/report substitutions and regeneration from a clean exact tree | Dependency advisories after acceptance still require active monitoring and re-admission |
| UI overstates assurance | Evidence-derived assurance labels with fail-closed default; local, source-reviewed, physical-device, testnet, production, and PQ claims are separate | Snapshot/accessibility tests for every state and failure | Users can still misinterpret technically accurate labels; product research remains necessary |

## Error And State Rules

The product must never collapse a security failure into a generic success or a
retry that reuses authority. The terminal categories are:

```text
cancelled       expired          transport_failed
device_locked   desktop_locked   authentication_failed
request_changed policy_changed   device_changed
signature_invalid simulation_failed execution_failed
receipt_invalid submission_outcome_unknown
too_late_submission_committed deleted completed
```

Only `completed` may show success. It requires the expected EntryPoint event,
account authorization-consumed event, harmless-target event/state, and audit
receipt to agree. `handleOps` returning without the expected events is not
success.

Every non-completed terminal state destroys in-memory transport and signing
state, marks the session non-reusable, and preserves only sanitized audit
metadata. `submission_outcome_unknown` may move only to `execution_failed` when
later exact evidence proves the official failed event, or to receipt
verification when later exact evidence proves successful execution; it is never
resubmitted. Private keys, raw session secrets, recovery material,
Phil root material, unredacted authentication errors, and full transport
plaintext never enter logs or renderer-visible inspection.

## Corrective Basis

Independent review rejected exact first candidate `fdf3c2e` for a cyclic hash
graph, insufficient iPhone reconstruction data and unsigned environment
classification, conflicting nonces, in-place Step 5 registry mutation,
non-constructor-faithful EntryPoint installation, contradictory cancellation/
restart behavior, and incomplete cross-language/receipt bytes. The exact
findings are in
[the rejection record](../reference/PHIL_V1_STEP6C_DEFINITION_INDEPENDENT_REVIEW_FDF3C2E.md).

The corrective packet makes the terminal request signature cover an acyclic
raw-record graph, introduces a separate signed chain-`31337` environment and
local V2 registry while preserving Step 5 epoch 1, uses only the EntryPoint
nonce, normally deploys EntryPoint, and freezes the durable point of no return,
journal/restart rules, encodings, clocks, logs, state and receipt.
The final preflight also required—and the packet now freezes—application/
principal/scope and epoch anchors, the literal account execution ABI and target
calldata, non-circular response AAD, and deterministic version,
implementation, and audit-manifest identities.

Fresh independent review rejected exact corrective candidate `a24873e` because
target runtime code was not signed, the journal lacked exact official-operation
crash evidence, nested Solidity calldata bytes remained ambiguous, and QR/
HTTP/frame/journal-AAD bytes remained incomplete. The full findings are in
[the corrective rejection record](../reference/PHIL_V1_STEP6C_CORRECTIVE_DEFINITION_INDEPENDENT_REVIEW_A24873E.md).
The second correction binds the target runtime end to end, persists exact local
and official operation evidence before submission, publishes the complete
Solidity tuple signature/selector, and freezes every local transport/frame byte.

Fresh independent review accepted exact second corrective candidate `227bd48`,
tree `cd5a734`, with no critical/high finding after reproducing all prior
finding closures and local evidence. See
[the acceptance record](../reference/PHIL_V1_STEP6C_SECOND_CORRECTIVE_DEFINITION_INDEPENDENT_REVIEW_227BD48.md).

Separately authorized implementation then exposed a further contradiction:
the constructor-frozen catalog and capability-policy hashes transitively
contained the nonce-bearing action hash and per-request validity window, so the
same account could not reliably admit the mandatory fresh next-nonce request.
No weakened implementation was retained. The blocker and mechanical witness
are in
[the implementation-blocker record](../reference/PHIL_V1_STEP6C_IMPLEMENTATION_BLOCKER_NONCE_CATALOG.md).

The third correction keeps the action hash fully signed but removes request
and nonce fields from stable constructor identities. It freezes a parameter
schema and deterministic capability, exact constructor-admitted catalog label
hashes, strict target-calldata semantics, dynamic summaries derived from raw
calldata, and a stable 24-hour profile-policy window containing independent
120-second requests. It requires explicit hash-stability and hash-change
vectors across failed `n` and successful `n+1`. Exact status-correction
candidate `fcc0103`, tree `209df24`, was independently accepted with no
remaining blocker. The user's separate continuation instruction authorizes
Step 6C-1 synthetic local implementation to resume. Exact candidate `22b5cf3`,
tree `2b0ff7f`, was subsequently independently accepted. Independent review
then rejected initial Step 6C-2 candidate `021e703`, tree `47efec7`, for
incomplete iPhone graph reconstruction, missing scene invalidation and
authenticated enrollment, non-durable restart inputs, unsafe deletion, stale
listener routing, and related evidence overclaims. The first corrective source
candidate `c40fa2c`, tree `86b92e9`, added complete V2 enrollment and proof of
possession, protected request discovery, real product-host composition,
same-chain receipt reconstruction, fail-safe lost-chain reconciliation, and
serialized deletion, but independent review rejected its remaining fee/clock,
package-root/configuration, replacement, protected-time, atomic-deletion, and
evidence gaps. Second corrective `75785f3`, tree `03008b5`, closed those items
but was rejected for an initialization/deletion race, falsey enrollment
overwrite, non-transactional iPhone rotation, generation-range drift,
unauthenticated deletion recovery, and missing replacement evidence. Third
corrective `965f9ed`, tree `76c5821`, closed those findings but was rejected
because an empty unauthenticated `204` could split iPhone/Desktop replacement
generation after lost delivery, a pre-commit deletion failure permanently
poisoned the product lifecycle, and runtime-provisioning failure incorrectly
started enrollment. The fourth-corrective source candidate adds QR-bound
Desktop-signed acceptance with idempotent replay and ambiguous pending-key
retention, distinguishes deletion pre/post-commit failure, and propagates
non-missing runtime failures.
Fourth corrective `09e5a9e`, tree `1da89d0`, materially closed those findings
but was rejected because Swift double-hashed Desktop's already-derived
acceptance digest, Desktop retained its ephemeral acknowledgement key and
replayed past expiry, and replacement left the displayed key fingerprint stale.
The fifth-corrective source candidate uses Security framework prehashed
verification against the exact generated Desktop response, canonical low-S
acceptance on both sides, immediate key destruction with expiry-bounded replay,
and post-acceptance active-record refresh.
Exact candidate `8a2d906`, tree `f7e1b4a`, was rejected solely because the
implementation report later contradicted its accurate source ordering by
claiming signing occurred after persistence. The sixth correction is
documentation-only and consistently records that signing and key destruction
precede persistence while response release follows it.
Exact candidate `4a81b08`, tree `188d7d0`, is independently accepted. Step
6C-2 is complete as a local source gate; physical-device evidence remains
deferred to Step 6C-3.

## Evidence Ladder

Step 6C uses four non-interchangeable evidence levels:

1. deterministic unit and property evidence;
2. synthetic local end-to-end product-composition evidence;
3. independent source acceptance of an exact commit and tree; and
4. bounded physical-iPhone evidence bound to the accepted source.

Physical evidence cannot repair a source defect. Synthetic evidence cannot be
relabeled as Secure Enclave evidence. An implementer-run matrix cannot replace
independent review. None of these establishes a public network or production
claim.

## Required Independent Review Focus

The independent reviewer must pay special attention to:

- V1/V2 scheme non-aliasing and the exact SHA-256 prehash bytes;
- DER minimality, integer range, and low-S behavior;
- independently derived human presentation on both devices;
- stable parameter-schema/capability/catalog/policy identities versus changing
  per-operation action, time, session, request, and signature identities;
- exact catalog labels, strict target-calldata semantics, dynamic parameter
  summary derivation, and request containment within the profile-policy window;
- application/principal/scope/account binding and every authority epoch;
- renderer, IPC, transport, session, and lifecycle authority boundaries;
- official EntryPoint source, normal-constructor state, SenderCreator, code,
  and separate local-environment classification;
- sole EntryPoint-nonce ownership, replay behavior, and failed-then-fresh
  liveness;
- acyclic hash construction and complete raw iPhone reconstruction inputs;
- exact off-chain-action to account-calldata reconstruction and the absence of
  any alternate execution selector;
- response decryption/AAD/hash ordering and manifest identity derivation;
- signed target runtime admission and replacement checks;
- exact post-commit official-event recovery from the durable operation bytes,
  hashes, sender/nonce, target pre-state, and scan anchor;
- numerical Solidity selector/tuple parity and literal QR/base64url/HTTP/frame/
  journal-AAD vectors;
- durable journal, cancellation point of no return, crash reconciliation, and
  frozen error precedence;
- receipt success criteria;
- absence of STWO, root-proof, recovery, legacy, RPC, deployment, and generic-
  execution reachability; and
- completeness of the committed negative-test matrix against every documented
  fail-closed branch.

## Residual Security Interpretation

Passing Step 6C would show that Phil's intended device-first routine approval
model can work as one local vertical slice. It would not show that Phil is a
finished web3 identity product, that Base or a live bundler accepts the path,
that account enrollment/recovery is solved, that arbitrary applications are
safe, that the proof backend is production-ready, that post-quantum protection
is enforced, or that meaningful assets should be entrusted to it.
