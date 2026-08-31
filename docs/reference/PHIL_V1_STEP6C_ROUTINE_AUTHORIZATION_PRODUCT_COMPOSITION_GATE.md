# Phil V1 Step 6C Routine Authorization Product Composition Gate

Status: Step 6C complete as a bounded local architecture/composition gate; exact complete physical evidence 0461ac7/tree c14838c independently accepted; public-network and production authority remain false

Date: 2026-08-22

## Decision

Step 6C is the final local composition gate in the six-step efficient route.
It must prove one complete routine authorization from an untrusted application
request to an official local ERC-4337 EntryPoint execution, with the approval
created by a real iPhone Secure Enclave key only after the person sees the
exact action and passes Face ID or passcode.

```text
STEP 6C FIRST DEFINITION CANDIDATE: REJECTED
STEP 6C FIRST CORRECTIVE DEFINITION: REJECTED
STEP 6C SECOND CORRECTIVE DEFINITION: ACCEPTED
STEP 6C THIRD CORRECTIVE EXACT CANDIDATE: REJECTED
STEP 6C THIRD CORRECTIVE STATUS CORRECTION: ACCEPTED
STEP 6C CURRENT CORRECTED DEFINITION INDEPENDENTLY ACCEPTED: YES
STEP 6C-1 INITIAL FINAL CANDIDATE: REJECTED AND SUPERSEDED
STEP 6C-1 FIRST CORRECTIVE FINAL CANDIDATE: REJECTED AND SUPERSEDED
STEP 6C-1 CORRECTIVE SOURCE CANDIDATE: INDEPENDENTLY ACCEPTED
STEP 6C-1 EXACT CANDIDATE: 22B5CF3 / 2B0FF7F
STEP 6C IMPLEMENTATION INDEPENDENTLY ACCEPTED: NO
STEP 6 COMPLETE: NO
PUBLIC NETWORK OR RPC: NO
PUBLIC DEPLOYMENT OR TRANSACTION: NO
MEANINGFUL ASSET AUTHORITY: NO
ROOT PROOF OR STWO IN ROUTINE PATH: FORBIDDEN
RECOVERY KEY AS ROUTINE SIGNER: FORBIDDEN
LEGACY ALPHA IDENTITY REINTERPRETATION: FORBIDDEN
PHYSICAL IPHONE WORK: REQUIRES A LATER SEPARATE CEREMONY AUTHORIZATION
```

If Step 6C is implemented and independently accepted, Step 6 and the current
six-step architecture route may be described as complete **as a local V1
architecture and product-composition gate only**. Testnet admission, public
deployment, meaningful assets, production release, additional applications,
and additional networks remain separate future decisions.

## Product Outcome

The bounded user journey is:

```text
harmless Phil application request
  -> protected Desktop runtime canonicalizes the exact action
  -> accepted local capability and policy are evaluated
  -> deterministic human presentation is created
  -> authenticated local request reaches the paired iPhone
  -> iPhone independently recomputes and displays the presentation
  -> user presence unlocks one Secure Enclave P-256 signature
  -> Desktop validates the response and unchanged request
  -> packed UserOperation is simulated through official EntryPoint v0.7 code
  -> handleOps executes one zero-value allowlisted local target call
  -> receipt and audit record are bound to the original request
```

The person must see, at minimum, the requesting app, network classification,
account, target label and address, action, value, maximum total fee, and
expiration. The iPhone must derive those fields from canonical protected bytes;
it must not sign renderer-provided display text.

The bounded action is a zero-value call to a disposable local target that
records one disclosed synthetic `bytes32` value. It transfers no token, grants
no allowance, creates no account, deploys no contract, changes no validator,
changes no policy, and carries no meaningful authority.

## Frozen Architecture Decisions

### 1. Routine and exceptional paths remain separate

Step 6C is a routine capability action. Its authorization envelope must carry
the routine operation class, a zero root-proof nullifier, no proof descriptor,
and no proof bytes. The quarantined STWO path and every exceptional root-proof
backend are unreachable from this flow.

First public account enrollment, root/device/recovery rotation, major policy
change, deliberate cross-scope linking, and high-risk capability issuance are
exceptional operations. They remain blocked until the separately admitted
witness-hiding proof path and exceptional-operation ceremony exist.

### 2. Device approval and recovery authority remain different keys

The iPhone routine approval key is replaceable P-256 Secure Enclave material.
It can authorize only the exact routine digest and cannot unwrap the identity
recovery package or satisfy a recovery role. Recovery credentials cannot
approve a routine UserOperation. No code may expose a generic `sign(bytes)`
handle to the renderer, an application, an adapter, or an AI agent.

### 3. The real iPhone signature profile is a new versioned profile

The accepted Step 2 iPhone record names
`p256-secure-enclave-sha256-digest-v1`; its Apple API returns DER X9.62. The
accepted Step 6B synthetic account names `phil-signature-p256-sha256-v1` and
expects two raw low-S `bytes32` values. Those records are not silently treated
as the same scheme.

Step 6C must introduce these exact identities:

```text
PHIL_DEVICE_APPROVAL_SIGNING_PREHASH_V2
  = keccak256("PHIL_DEVICE_APPROVAL_SIGNING_PREHASH_V2")

platformSigningDigest
  = sha256(
      PHIL_DEVICE_APPROVAL_SIGNING_PREHASH_V2 || requestId
    )

signatureSuiteName
  = "phil-signature-p256-sha256-prehash-raw-rs-low-s-v2"

providerProfileName
  = "apple-secure-enclave-p256-x962-sha256-digest-der-v1"

wireEncodingName
  = "phil-p256-signature-rs-64-low-s-v1"
```

Each ID is `keccak256(utf8(exact name))`. `requestId` is the terminal Keccak
digest of an acyclic graph binding the session, separate local environment,
admitted registry/device/catalog/account/policy state, raw action/calldata,
presentation, envelope, and unsigned approval. Apple signs the 32-byte
`platformSigningDigest` with
`SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256`. The native DER result is
strictly parsed, normalized to low-S, and encoded as `r || s`, where both
integers are unsigned 32-byte big-endian values. The account recomputes the
same SHA-256 prehash and verifies the canonical raw signature.

Existing V1 scheme and public-record IDs remain historical synthetic or Step 2
evidence. Their meanings and hashes do not change. Step 6C requires a new
versioned routine-device enrollment record; it never mutates a V1 record in
place.

### 4. EntryPoint v0.7 is normally deployed under a separate local identity

The repository pins `@account-abstraction/contracts` `0.7.0`. Step 6C retains
that source version to compose the accepted local work, but it does not reuse
Base chain ID `8453`, the Base network hash, or the canonical public EntryPoint
address.

The test environment uses chain ID `31337` and the signed identity
`phil-local:step6c:31337`. It normally deploys official v0.7 `EntryPoint`
source from the pinned package and binds the actual address, runtime code,
constructor-created `SenderCreator`, reentrancy storage, and initially empty
deposit/nonce state. Runtime-code copying and `hardhat_setCode` are forbidden.

The account must be prefunded through the EntryPoint deposit so
`missingAccountFunds == 0`. Before `handleOps`, the exact operation must pass a
non-mutating local `eth_call`/static simulation through that EntryPoint. The
receipt must prove both successful `UserOperationEvent` execution and the
expected harmless target event/state.

ERC-4337 v0.9 uses a different privileged singleton address even though the
upstream project describes its ABI as compatible with v0.7. Any move to v0.8,
v0.9, or another EntryPoint is a security-significant adapter-manifest and
account migration. It requires a later version-admission gate with an exact
address, code hash, audit/advisory review, bundler compatibility evidence, and
explicit migration semantics. Product UI never chooses the EntryPoint.

The official EntryPoint keyed nonce is the sole account-operation sequence.
Step 6C does not retain Step 6B's second stored sequence. Failed execution
consumes the EntryPoint nonce; a fresh request uses the next nonce and must
remain live.

### 5. Legacy Desktop Alpha identities are not V1 identities

The current Desktop Alpha passphrase identity, local ECDSA validator, and
legacy encrypted files remain compatibility/history surfaces. Step 6C must
use a new versioned disposable V1 local-composition profile. It must not derive
new authority by relabeling existing Alpha bytes, importing an existing
validator, or treating account recovery as Phil identity/data recovery.

A future migration from an Alpha identity is an explicit user ceremony that
creates a new V1 profile and records provenance. It is not part of Step 6C.

### 6. Existing local pairing code is transport infrastructure, not authority

The repository already has a bounded native iPhone local-network pairing and
recovery transport. Step 6C may reuse reviewed framing, authenticated key
agreement, encryption, expiry, replay, endpoint allowlisting, and comparison-
fingerprint primitives. It must use a new protocol context, endpoint, message
types, session keys, and state machine. It must not reuse a recovery approval,
recovery credential, recovery transcript, or recovery endpoint as routine
authorization evidence.

The Desktop renderer and every requesting app remain untrusted. Only the
protected main-process coordinator may select an admitted manifest, create the
canonical request, persist replay state, accept a device response, build the
UserOperation, invoke the local EntryPoint, or write the final audit record.

## First Independent Review And Corrective Decisions

Independent review rejected exact candidate `fdf3c2e0263d66e6381ed9e16caf01d2d80c5718`
for seven blocking definition defects. The full findings are preserved in
[the review record](./PHIL_V1_STEP6C_DEFINITION_INDEPENDENT_REVIEW_FDF3C2E.md).

The corrective definition:

- removes `requestId` from the presentation and publishes one literal acyclic
  derivation order ending in a signature over the terminal request ID;
- transports the raw environment, adapter, registry, device enrollment,
  account configuration, catalog, capability/policy, action, calldata,
  envelope, unsigned approval, and presentation so the iPhone recomputes
  rather than trusts display text;
- signs a separate chain-`31337` local environment and rejects Base/public
  identities;
- uses only the official EntryPoint keyed nonce and requires liveness after a
  failed execution;
- preserves the accepted Step 5 epoch-1 registry and creates a new local V2
  profile without migrating existing authority;
- normally deploys EntryPoint so constructor storage and `SenderCreator` are
  real; and
- freezes literal encodings, time/log/receipt rules, a durable journal, an
  atomic submission point of no return, restart reconciliation, and error
  precedence in the primary implementation packet;
- binds the application principal and scope identity plus all six authority
  epochs through the account configuration, policy, presentation, envelope,
  and constructor storage;
- distinguishes the complete off-chain action from the exact account calldata
  tuple, freezes the sole execution selector and harmless target calldata, and
  requires the account to reconstruct the complete action and request graph;
- removes the response-hash/AAD contradiction by hashing the response only
  after decrypting under the one frozen direction/session/request AAD; and
- derives EntryPoint/adapter versions, implementation source-set identity, and
  candidate/accepted audit identity mechanically with no caller-selected
  manifest field or hash cycle.

A second strictly read-only working-draft preflight confirmed these four final
corrections closed with no new critical/high inconsistency. That preflight is
not the final exact-commit verdict.

Fresh independent review then rejected exact corrective candidate
`a24873eb4ead424748c94ac7df9c38bbaf096a18` for four remaining high-severity
definition gaps. The findings are preserved in
[the corrective rejection record](./PHIL_V1_STEP6C_CORRECTIVE_DEFINITION_INDEPENDENT_REVIEW_A24873E.md).

The second corrective definition:

- signs the normally deployed target runtime code hash through configuration,
  policy, catalog, presentation, account constructor storage, validation,
  execution, and receipt;
- commits exact packed operation bytes, local and official operation hashes,
  EntryPoint/sender/nonce, target pre-state, and a block scan anchor before
  submission so crash recovery can identify an exact failed official event;
- publishes every Solidity calldata struct, the complete canonical function
  signature, selector `0x5a99466a`, field mapping, and strict decode/re-encode
  equality; and
- freezes the 216-byte QR bootstrap, canonical unpadded base64url, HTTP
  methods/content/status rules, binary encrypted frame, and exact journal AAD.

Fresh independent review accepted exact second corrective candidate
`227bd48d92c84672c50f2d19f47b9a24e5b17786`, tree
`cd5a734c5ca1ce486d55024befa85424aefefb42`, with no critical/high finding.
The reviewer independently reproduced the literal selector/tuple, target,
journal, transport, 43-test, artifact, link, and unchanged-baseline evidence.
See [the acceptance record](./PHIL_V1_STEP6C_SECOND_CORRECTIVE_DEFINITION_INDEPENDENT_REVIEW_227BD48.md).

Separately authorized Step 6C-1 implementation then stopped before a source
candidate was frozen. Mechanical construction proved that the per-operation
action hash included the EntryPoint nonce, while catalog kind 6 bound that
action hash and the constructor froze both the resulting catalog and policy
hashes. The same account therefore could not satisfy the mandatory failed
nonce `n` followed by fresh successful nonce `n+1` path. The exact witness is
preserved in
[the implementation-blocker record](./PHIL_V1_STEP6C_IMPLEMENTATION_BLOCKER_NONCE_CATALOG.md).

This third corrective definition closes that implementation contradiction
without weakening the signed action:

- catalog kind 6 binds a stable parameter-schema identity for the one admitted
  target method, runtime code, recorded value, and canonical boolean encoding;
- a deterministic stable capability ID binds application, scope, target,
  target code, action type, and parameter schema;
- the complete nonce-bearing action hash remains independently signed as the
  presentation `parametersHash`, envelope `parametersHash`, and core
  `actionHash`;
- the dynamic human summary is reconstructed from the decoded success/failure
  boolean rather than accepted from a caller;
- six exact catalog strings and their hashes are constructor-admitted so the
  account can reconstruct presentation labels instead of trusting calldata;
  and
- the constructor-frozen capability policy uses one exact 24-hour disposable-
  profile window, while each request keeps an independently signed 120-second
  interval wholly contained within that policy window.

The required liveness vector now changes nonce, target calldata, session,
nonce seed, request time, action/presentation/envelope/core/request hashes, and
signature between the failed and successful operations while requiring the
parameter-schema, capability, catalog, and policy hashes to remain identical.
No second nonce, mutable policy, caller-selected label, or unsigned action is
introduced.

Independent review rejected exact third corrective candidate
`b8069746f4620c0ae96bfd297478bf7cf0515359`, tree
`b3be2e67dd71fb216d0922660879b50abf241b21`, because this decision block still
reported implementation as not started and the current definition as accepted,
and because the verification summary retained the second-corrective link count.
The reviewer independently reproduced the substantive nonce/catalog correction,
all frozen hashes and selectors, the failed-`n`/successful-`n+1` liveness witness,
43 focused tests, and all four artifact verifiers without another security
blocker. This bounded status correction grants no implementation acceptance.

Fresh independent review accepted exact status-correction candidate
`fcc0103a61c051ad8507de79536978928b0e3e3f`, tree
`209df24d5cd3567668b69548235cb2064d7ab710`, after reproducing both closures and
finding no new blocker. See
[the acceptance record](./PHIL_V1_STEP6C_THIRD_CORRECTIVE_DEFINITION_STATUS_CORRECTION_INDEPENDENT_REVIEW_FCC0103.md).

## Implementation Sequence

Step 6C is deliberately split so a real device is not used to debug basic
composition defects.

### Step 6C-1: synthetic local composition candidate

- implement the V2 signing-prehash, strict DER/raw codec, public-key codec,
  routine request/response records, protected coordinator, official local
  EntryPoint environment, Step 6C account, harmless target, and deterministic
  audit receipt;
- use only a disclosed synthetic P-256 key and injected in-memory transport;
- add the complete positive, negative, replay, cancellation, expiry,
  simulation, prefund, and rollback matrix;
- add deterministic artifacts and an integrity manifest;
- keep normal Desktop and iPhone product UI disconnected; and
- obtain independent read-only acceptance of the exact candidate.

### Step 6C-2: iPhone and Desktop product wiring candidate

- add a dedicated routine-approval screen and V2 routine-device enrollment;
- add the separate authenticated local transport context;
- expose only typed, narrow preload/IPC operations;
- keep the existing Alpha action/STWO workflow quarantined and visibly
  classified as unavailable;
- prove synthetic transport, lifecycle, UI, background, lock, cancellation,
  substitution, and timeout behavior without a physical device; and
- obtain independent read-only acceptance of the exact source candidate.

### Step 6C-3: bounded physical-iPhone ceremony

This stage starts only after separate user authorization. It uses no public
network and no real Phil identity. It must demonstrate enrollment, exact
presentation, Face ID/passcode approval, DER-to-low-S conversion, Desktop
verification, local simulation, `handleOps`, receipt binding, cancellation,
background/lock invalidation, replay rejection, persistence after interruption,
and deletion of the disposable routine key/profile.

### Step 6C-4: final independent acceptance

An independent reviewer must bind the exact source candidate and physical
evidence envelope, reproduce all credential-free lanes, classify any physical-
only evidence honestly, and issue one final verdict. No implementer may
self-accept Step 6C.

## Required User-Facing States

The UI must distinguish:

```text
local prototype       reviewed source       physical-device verified
testnet admitted      production admitted   post-quantum enforced
```

Only the first state is true when implementation begins. A later state may be
shown only when an exact accepted evidence record establishes it. “Face ID
approved” means a user-present device key signed the exact displayed request;
it does not mean the app, network, contract, or asset is generally safe.

Cancellation, dismissal, transport loss, backgrounding, device lock, Desktop
lock, identity switch, session replacement, policy/epoch change, simulation
failure, receipt mismatch, or timeout must end in a visible non-success state
and invalidate the pending request. Retry always creates a new session,
approval nonce, and digest.

The enrollment transport has one narrow exception: after the iPhone has
published a signed enrollment, ambiguous response delivery must retain the
activated-pending key and may retry the same frozen enrollment session. It may
commit only after verifying Desktop's QR-bound signed acceptance. This does not
permit reuse of a routine authorization request or approval nonce.

## Exit Contract

Step 6C is complete only when all of the following are true:

```text
exact Step 6C source and tree independently accepted
official pinned EntryPoint v0.7 source executed locally
synthetic and real-iPhone signatures verify across Swift, TypeScript, and Solidity
strict DER and low-S conversion independently reproduced
deterministic presentation hash matches Desktop and iPhone fields
local simulation and handleOps both pass for the exact accepted request
harmless target event/state and EntryPoint receipt bind the same request
all documented substitutions, replay, expiry, cancellation, lock, and rollback cases fail closed
legacy Alpha, recovery, STWO, root proof, RPC, deployment, and public-network paths remain unreachable
disposable device key and local profile deletion are evidenced
STEP 6 COMPLETE AS LOCAL ARCHITECTURE/COMPOSITION GATE: YES
PRODUCTION OR PUBLIC-NETWORK AUTHORITY: NO
```

## Deliberate Non-Claims

Step 6C does not establish Base availability, Base P-256 gas, live bundler
compatibility, a production EntryPoint choice, account factories,
counterfactual deployment, account upgrades, device rotation, recovery-driven
validator replacement, capability issuance/revocation administration,
multi-target execution, tokens, credentials, applications, agents, Starknet
publication, a production proof backend, post-quantum enforcement, external
audit, release signing, or production readiness.

## Definition-Candidate Verification

The documentation candidate was checked with:

```text
npm run typecheck
npm run compile:phil-v1-step6b-account
npm run test:phil-v1-step6b-account
npm run test:phil-v1-step6a-base-adapter
npm run verify:phil-v1-step6a-artifacts
npm run test:phil-v1-step5-pq-migration
npm run verify:phil-v1-step5-artifacts
npm run test:phil-v1-step4-composed-account
npm run verify:phil-v1-step4-artifacts
npm run test:phil-v1-step3-root-proof-adapter
npm run verify:phil-v1-step3-artifacts
changed-document local-link validation
git diff --check
```

Type checking, all four deterministic artifact verifiers, 403 local links
across eleven changed Markdown files, and all 43 focused Step 3-through-6B tests
passed. The classification validator separately reproduces
an existing baseline inventory defect: seventeen already-committed Step 3-
through-6B scripts/tests are not listed in its classification registry. This
definition candidate changes none of those scripts, tests, package scripts, or
classification rules. The baseline failure is not treated as a Step 6C
regression or as a passing gate.

## Current Authority And Next Move

The third-corrective definition is independently accepted. Step 6C-1
candidates `a158688`, `aea7359`, `591f6b6`, and `5ab4650` were independently
rejected and are superseded. Corrective source commit `6f048eb`, tree
`a9032b2`, is frozen with 37 focused passing tests and reproducible disclosed-synthetic artifacts. It is
independently accepted as exact candidate `22b5cf3`, tree `2b0ff7f`, for the
bounded Step 6C-1 local gate.

Step 6C-2 initial candidate `021e703`, first corrective `c40fa2c`, second
corrective `75785f3`, third corrective `965f9ed`, fourth corrective `09e5a9e`,
and fifth corrective `8a2d906` were independently rejected and are superseded.
The sixth-corrective source candidate retains
authenticated, idempotently replayable Desktop enrollment acceptance,
activated-pending iPhone recovery after ambiguous publication, retryable
pre-commit deletion failure, post-commit deletion poisoning, and exact
propagation of non-missing runtime failures. It also uses true prehashed Swift
verification of the exact Desktop fixture, expires cached replay after
immediately destroying the acknowledgement private key, rejects high-S
acceptance, and refreshes the displayed replacement fingerprint. It also
corrects the fifth candidate's contradictory report sentence about the
signing/persistence order. Exact candidate `4a81b08`, tree `188d7d0`, is
independently accepted, completing the bounded Step 6C-2 local source gate.

The first physical ceremony stopped on scanner and product-state defects. Exact
corrective source `c32d8f8`, tree `12eb24e`, was independently accepted. The
fresh retest exposed one additional Desktop packaging omission, corrected at
`41d9ab8`, tree `320fbc4`. The rebuilt package completed the real-iPhone
approval, verified the harmless local receipt, and then removed both the iPhone
routine key and Desktop routine profile without changing identity or recovery
state. Exact complete physical evidence `0461ac7`, tree `c14838c`, was
independently accepted. Step 6C is complete as the bounded local
architecture/composition gate.

The superseded verdict and findings are retained in
[the A158688 independent review](./PHIL_V1_STEP6C_INDEPENDENT_REVIEW_A158688.md).
The later lifecycle/evidence rejection is retained in
[the AEA7359 independent review](./PHIL_V1_STEP6C_INDEPENDENT_REVIEW_AEA7359.md).
The restart-chain and nonce-binding rejection is retained in
[the 591F6B6 independent review](./PHIL_V1_STEP6C_INDEPENDENT_REVIEW_591F6B6.md).
The authenticated-frame, transition, race, and reentry rejection is retained in
[the 5AB4650 independent review](./PHIL_V1_STEP6C_INDEPENDENT_REVIEW_5AB4650.md).
The exact accepted replacement is recorded in
[the 22B5CF3 independent review](./PHIL_V1_STEP6C_INDEPENDENT_REVIEW_22B5CF3.md).
The exact accepted Step 6C-2 candidate is recorded in
[the 4A81B08 independent review](./PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_4A81B08.md).
Only the exact recorded disposable physical ceremony is admitted. Additional
physical-device work, network/RPC activity, deployment, transaction,
publication, meaningful-asset, public-chain, and production work remain
unauthorized.

The exact implementation contract is in
[the Step 6C implementation packet](./PHIL_V1_STEP6C_IMPLEMENTATION_PACKET.md).
Candidate evidence is in
[the Step 6C-1 implementation report](./PHIL_V1_STEP6C_IMPLEMENTATION_REPORT.md)
and [artifact manifest](./PHIL_V1_STEP6C_ARTIFACT_MANIFEST.json).
Threats and residual risk are in
[the Step 6C threat model](../security/PHIL_V1_STEP6C_ROUTINE_AUTHORIZATION_THREAT_MODEL.md).

## Primary Standards References

- [Apple Security `SecKeyAlgorithm`](https://developer.apple.com/documentation/security/seckeyalgorithm)
- [Apple `SecKeyCreateSignature`](https://developer.apple.com/documentation/security/seckeycreatesignature(_:_:_:_:))
- [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337)
- [ERC-7769 bundler JSON-RPC](https://eips.ethereum.org/EIPS/eip-7769)
- [Account Abstraction releases](https://github.com/eth-infinitism/account-abstraction/releases)
