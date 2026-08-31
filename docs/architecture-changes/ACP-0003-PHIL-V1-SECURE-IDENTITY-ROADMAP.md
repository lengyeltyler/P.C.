# ACP-0003: Phil V1 Secure Identity Architecture And Ordered Roadmap

Review status: Accepted

Implementation status: Steps 1-5, Step 6A, Step 6B, and Step 6C complete as accepted bounded local gates; exact Step 6C complete physical evidence 0461ac7/tree c14838c independently accepted; the six-step efficient local architecture/composition route is complete; public-network and production authority remain false

Next milestone: exact cross-device Desktop/iPhone visual candidate, local package freeze, independent review, and public-source release-readiness gate; publication and all network mutation remain separately authorized

## Problem Observed

Phil's product goal is a device-first personal security operating system that
lets a person control identity, encrypted data, wallets, credentials,
applications, and AI-agent authority across multiple networks without exposing
the identity root.

The accepted architecture coupled too much of that goal to a specific
`stwo-unlock-keccak-v1` proof and a Starknet-to-L1-to-Base fact route. Security
review established that the current STWO artifact exposes its witness through
queried trace openings. Structural quarantine correctly stops that artifact,
but it leaves the repository without an accepted replacement architecture or
an ordered route from the secure device foundation to cross-network execution.

Additional feasibility evidence identifies four corrections:

1. A proof backend is a replaceable security component, not the Phil identity.
2. A universal public owner commitment would make a user's cross-network and
   cross-application activity correlatable.
3. Account recovery alone does not recover the Phil identity secret and
   encrypted user data.
4. Generating an expensive root proof for every routine action is neither the
   most efficient nor the most maintainable authorization design.

## Implementation Evidence

The evidence is summarized in the
[Phil V1 Architecture Feasibility Gate](../reference/PHIL_V1_ARCHITECTURE_FEASIBILITY_GATE.md).

Material results:

- the current STWO artifact is non-witness-hiding and remains quarantined;
- an exact synthetic Noir/Barretenberg identity/nullifier relation proved and
  verified with all tested wrong-input cases rejected;
- native arm64 proving succeeded in an iPhone Simulator, while physical-iPhone
  proving remains unverified;
- a generated Garaga Cairo verifier compiled and accepted the packed proof in
  a read-only Starknet Sepolia state-fork test, but its measured cost is not
  appropriate for every transaction;
- an isolated `2-of-3` encrypted recovery prototype restored the same identity
  and data with every valid share pair and rejected the tested corruption,
  mismatch, and insufficient-share cases; and
- current platform and network cryptography does not support a truthful claim
  of complete hardware-isolated post-quantum security.

This evidence is sufficient to accept the architecture correction. It is not
sufficient to select a production backend, deploy a verifier, connect a
physical device, or authorize public-network mutation.

## Recommended Change

Adopt the following product architecture through the six ordered gates below:

```text
Private Phil identity root
  -> encrypted user-controlled identity and data vault
  -> user-controlled identity/data recovery
  -> hardware-backed enrolled device approvals
  -> domain-separated scoped identities and commitments
  -> policy and revocable capability engine
  -> network-specific account and execution adapters
  -> wallets, credentials, applications, and AI agents
```

The private Phil identity root provides continuity. It is independent of any
chain, account address, device key, validator algorithm, proof system, storage
provider, application, credential, or AI agent.

### Required architecture principles

1. **Private stable root.** `phil_secret` and root-derived secret material never
   leave the protected runtime in plaintext.
2. **Scoped public identity.** Each network, app, credential relationship,
   persona, or agent receives a domain-separated public identifier or
   commitment. Cross-scope linking is explicit, never the default.
3. **User-controlled encrypted data.** Phil controls data-encryption keys,
   authenticated encrypted records, portable export, and encrypted recovery.
   Public networks receive minimal commitments or proofs, not personal data.
4. **Device approval separate from root proof.** A hardware-backed enrolled
   device signature establishes device/user approval and can rotate without
   replacing the Phil identity.
5. **Capabilities for routine actions.** Normal actions use narrow, expiring,
   revocable, policy-bound device/session capabilities. Apps and agents request
   authority; they do not receive root or unrestricted signing authority.
6. **Root proof for exceptional actions.** Witness-hiding proof is reserved for
   enrollment, recovery, validator rotation, major policy changes, deliberate
   cross-scope linking, and high-risk capability issuance unless measurements
   justify a broader use.
7. **Network adapters, not a network identity.** Starknet, Ethereum/Base, and
   later networks enforce the strongest semantics each supports without
   becoming the Phil identity layer.
8. **Algorithm agility.** Identity, authorization, recovery, validator, and
   proof records carry versioned algorithm and verifier identifiers with
   explicit migration and retirement rules.
9. **Evidence-backed user trust.** Secure hardware, isolated runtime
   boundaries, deterministic human-readable intents, policy simulation,
   fail-closed behavior, signed/reproducible releases, provenance, independent
   audits, verifier pinning, advisories, and revocation carry the verification
   burden that ordinary users cannot perform themselves.
10. **No security overclaim.** Platform attestation, recovery, proof privacy,
    network enforcement, post-quantum properties, and production readiness are
    claimed only at the level directly established by evidence.

## Ordered Implementation Roadmap

The steps are strictly sequential. A later step may be researched in isolation,
but it may not become product authority or deployment scope until every prior
step's exit gate is accepted.

| Step | Gate | Status | Required outcome |
| --- | --- | --- | --- |
| 1 | Freeze product architecture, not proof backend | Complete | Accepted exact identity, scoped-privacy, data, device, capability, recovery, adapter, and algorithm-agility contracts while leaving the backend unselected |
| 2 | Finish device and recovery foundation | Complete | Establish physical-device behavior, hardware-backed approval/wrapping, encrypted identity/data recovery, lifecycle, and threat-model evidence |
| 3 | Build Starknet reference private-proof adapter | Complete | Integrate a reviewed candidate verifier as a network adapter for exceptional root operations, not as Phil's identity or every-action path |
| 4 | Pass one composed account authorization gate | Complete; exact candidate 3377606 independently accepted | Prove `root proof + enrolled device signature + policy + nonce + expiry + revocation` as one fail-closed account action before deployment |
| 5 | Lock post-quantum migration fields and ceremonies | Complete; exact second corrective candidate d1de608 independently accepted | Registry-bound schemes, proof/verifier compatibility, exact trusted capability/policy identities, hybrid-AND rules, capability migration, retirement, recovery independence, and honest network records without claiming current PQ security |
| 6 | Expand adapters without changing identity | Complete as a bounded local architecture/composition gate; Step 6A and Step 6B accepted; Step 6C exact complete physical evidence 0461ac7/c14838c independently accepted | Add Ethereum/Base and later network adapters using the same private root and scoped public identities; each public network still requires separate admission |

### Step 1: Freeze product architecture, not proof backend

Step 1 must produce an accepted, internally consistent source-of-truth set.
It must:

- decide the exact distinction between the canonical internal root commitment
  and public scoped commitments;
- define stable scope-domain inputs and deliberate cross-scope linking;
- define which encrypted identity, derivation, credential, policy, audit, and
  user-data state must survive recovery;
- separate account recovery from identity/data recovery;
- define hardware-backed device approval and rotation independently from the
  proof backend;
- define exceptional root-proof operations versus routine capability actions;
- define the chain-agnostic authorization envelope fields that every adapter
  must bind, including network, account, action, parameters, policy, nonce,
  expiry, device/recovery/capability epochs, and scheme/verifier identifiers;
- define adapter isolation for wallets, credentials, apps, and AI agents;
- define proof-backend admission, migration, and retirement requirements;
- preserve STWO only as quarantined non-private research unless a future
  independently reviewed witness-hiding mode passes a new gate;
- update the four accepted architecture/specification documents and their
  active identity, proof, recovery, device, data, and PQ references; and
- mechanically scan current public docs for stale universal-commitment,
  STWO-authority, proof-every-action, account-only-recovery, and premature
  deployment claims.

Step 1 exit contract:

```text
ACP-0003 accepted or replaced by an accepted narrower proposal
all accepted source-of-truth documents reconciled
no production proof backend selected
no runtime, contract, proof, deployment, or physical-device mutation
Steps 2-6 remain unauthorized
```

Step 1 result: **passed**. The exact contracts are accepted in
[Phil V1 Secure Identity Architecture](../PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md),
the accepted source-of-truth set and active boundary references are reconciled,
no production proof backend was selected, and no product or external-system
mutation was performed.

### Step 2: Finish device and recovery foundation

Required evidence includes:

- physical-iPhone proving benchmark if local root proving remains required;
- supported-device, memory, battery, thermal, interruption, and failure limits;
- Secure Enclave-generated device approval/wrapping key with explicit user
  presence and no claim that an imported Phil root lives in the enclave;
- protected runtime isolation from UI renderers, dapps, adapters, plugins, and
  agents;
- App Attest, if used, treated as optional server-side app-instance evidence
  rather than identity or recovery authority;
- authenticated encrypted identity/data package with user-controlled `2-of-3`
  key unwrapping;
- all share-pair, single-share, mixed-set, corruption, rollback, replacement,
  revocation, lost-device, and lost-share cases;
- recovery notifications, delays, audit events, and explicit destructive
  approvals; and
- independent device/recovery threat review.

Current Step 2 result:

- exact scoped identity and encrypted-data records are implemented locally;
- an authenticated encrypted continuity package and exact pairwise `2-of-3`
  `K_backup` unwrapping suite pass every pair and the targeted single,
  duplicate, mixed-set, corruption, rollback, delay, cancellation,
  replacement, revocation, lost-device, and lost-share tests;
- the device-approval contract binds envelope, presentation, device, key,
  suite, epoch, nonce, and validity window;
- a bounded iPhone 17/iOS 26.6 ceremony passed Secure Enclave creation,
  cancellation, signing, wrapping/unwrapping, non-exportability, lock/reboot
  persistence, and exact candidate deletion after correcting cancellation
  classification; and
- App Attest is not used as identity or recovery authority.

Step 2 is accepted and complete. Its executable fail-closed admission policy
admits
only the exact physically observed device/resource envelope and grants no
production authority; all broader profiles and conditions remain unadmitted.
Independent reviews rejected `ac49f01` and `786ab61`. The final exact source
candidate `fe583b6aef84a8636736b2041db2a56046a5972e` uses atomic update/add
metadata persistence without a delete/add gap and received
`ACCEPT_STEP_2_EXACT_CANDIDATE`. Step 2 is complete.
See the
[implementation report](../reference/PHIL_V1_STEP2_DEVICE_RECOVERY_IMPLEMENTATION_REPORT.md)
and
[threat model](../security/PHIL_V1_STEP2_DEVICE_RECOVERY_THREAT_MODEL.md), plus
the
[physical-iPhone evidence](../reference/PHIL_V1_STEP2_PHYSICAL_IPHONE_EVIDENCE.md).
The rejected review and adjudication are preserved in the
[independent review record](../reference/PHIL_V1_STEP2_INDEPENDENT_REVIEW_AC49F01.md).
The second rejection is preserved in the
[786ab61 review record](../reference/PHIL_V1_STEP2_INDEPENDENT_REVIEW_786AB61.md).
The exact acceptance is preserved in the
[fe583b6 review record](../reference/PHIL_V1_STEP2_INDEPENDENT_REVIEW_FE583B6.md).

### Step 3: Build Starknet reference private-proof adapter

The adapter must:

- use only a backend admitted by the Step 1 rules, while keeping proof
  generation separate from the Step 2 hardware-backed device-signature role;
- bind the exact scoped identity and authorization envelope;
- reserve the root proof for exceptional lifecycle/authority operations;
- pin circuit, verifier, toolchain, codec, and dependency identities;
- measure proof size, calldata, verifier class size, L2 gas, fees, and failure
  behavior;
- reject wrong witness, scope, action, policy, nullifier, account, chain,
  scheme, verifier, and epoch inputs;
- obtain independent cryptographic and Cairo/account review; and
- remain local/read-only until a separately approved deployment gate.

Noir/Barretenberg plus Garaga is the leading engineering candidate from the
current evidence, not a production selection. RISC Zero remains a fallback
comparator. STWO remains prohibited for private identity authorization.

The active Step 3 boundary and exact exit contract are recorded in the
[Step 3 Starknet reference-adapter gate](../reference/PHIL_V1_STEP3_STARKNET_REFERENCE_ADAPTER_GATE.md).
Step 3 preflight also corrected a pre-deployment digest cycle: the authorization
envelope digest now excludes only `rootProofNullifier`, which the exceptional
proof derives from that digest and binds separately. Every other envelope field
remains committed in the accepted order.

### Step 4: Pass one composed account authorization gate

Before any public deployment, one reference account action must enforce as one
composition:

```text
valid exceptional root proof
+ currently enrolled hardware-backed device signature
+ exact human-approved intent and policy
+ correct network/account/action/parameters binding
+ nonce and replay protection
+ validity window and fee/value limits
+ current device, recovery, validator, and capability epochs
+ revocation and emergency-stop state
```

Every omitted, stale, duplicated, corrupted, mismatched, expired, revoked, or
replayed component must fail closed. Proof validity alone must never authorize
an action.

### Step 5: Lock post-quantum migration fields and ceremonies

Step 5 must specify:

- signature, key-establishment, hash, proof, and verifier scheme identifiers;
- per-network supported-scheme records and downgrade prevention;
- hybrid classical/PQ enrollment and authorization where the network supports
  it;
- key rotation, algorithm retirement, emergency migration, and recovery
  independence;
- the limitation that current admitted Phil Secure Enclave authorization uses
  P-256 signatures even though Apple CryptoKit now documents Secure Enclave
  ML-DSA-65 signing and ML-KEM key establishment on supported iOS 26+
  platforms; Phil integration and physical evidence remain required;
- the limitation that the current leading Noir/Honk candidate is not
  post-quantum; and
- explicit evidence required before any network or whole-system PQ claim.

### Step 6: Expand adapters without changing identity

After the reference composition passes, add adapters in bounded increments:

1. Ethereum/Base using a narrow smart-account validator/capability surface.
2. Additional networks only after their native account, replay, fee, recovery,
   signature, and PQ capability differences are specified and tested.
3. Credential, application, and AI-agent adapters using the same scoped,
   revocable capability model.

Networks without programmable accounts or PQ validation receive only the
security those networks can enforce. Phil may improve local custody and policy,
but must not claim unsupported on-chain guarantees.

The final local composition increment is the
[Step 6C routine authorization product composition gate](../reference/PHIL_V1_STEP6C_ROUTINE_AUTHORIZATION_PRODUCT_COMPOSITION_GATE.md).
Its exact definitions `fdf3c2e` and `a24873e` were independently rejected. The
first corrective closed the original seven defects but retained four high-
severity target-runtime, crash-evidence, literal-calldata, and transport-byte
gaps. The second corrective definition freezes one harmless
vertical slice using an acyclic raw-record signing graph, independently derived
iPhone presentation, a separate chain-`31337` local environment, new versioned
Secure Enclave P-256/SHA-256-prehash profile, normally deployed official local
EntryPoint v0.7, its keyed nonce as the sole sequence, durable submission/
restart semantics, a signed target runtime, exact local/official operation
crash evidence, selector `0x5a99466a` and all tuples, literal QR/HTTP/frame/
journal bytes, and a bound receipt. It preserves Step 5 epoch 1 and does
not alias Step 2 DER evidence with Step 6B synthetic raw evidence. Legacy Alpha,
recovery signing, STWO/root proofs, public RPC, deployment, and meaningful
assets remain excluded.

Exact second corrective Step 6C definition `227bd48`, tree `cd5a734`, was
independently accepted with no critical/high finding. Its separately authorized
implementation was separately authorized but stopped before a candidate after
the nonce-bound frozen catalog contradicted the required next-nonce liveness.
The exact third-corrective status correction `fcc0103`, tree `209df24`, is
independently accepted, and the user's separate continuation instruction
authorizes bounded Step 6C-1 synthetic local implementation. Work remains
staged: synthetic local composition, independent
review, iPhone/Desktop product wiring, independent source review, a separately
authorized physical-iPhone ceremony, and final independent acceptance. If all
of those gates pass, the six-step route is complete as a local V1 architecture
and product-composition gate only; testnet and production remain separate.

## Affected Documents

Step 1 is expected to reconcile at least:

- `docs/PHILCORE_CORE_BOUNDARY.md`
- `docs/PHILCORE_RUNTIME_LIFECYCLE.md`
- `docs/PHILCORE_FUNCTIONAL_SPEC_V1.md`
- `docs/PHILCORE_TECHNICAL_SPEC_V1.md`
- `docs/ARCHITECTURE_CHANGE_CONTROL.md`
- `docs/reference/PHIL_IDENTITY_MODEL.md`
- `docs/reference/ACTION_UNLOCK_PROOF_SPEC.md`
- `docs/reference/PROOF_INPUT_SCHEMA.md`
- `docs/reference/STARK_ROLE_AND_BINDINGS.md`
- `docs/reference/WITNESS_HIDING_PROVING_STACK_REQUIREMENTS.md`
- `docs/reference/PQ_MIGRATION_READINESS.md`
- active device, recovery, capability, account, and adapter references
- `README.md`, `ARCHITECTURE.md`, `STATUS.md`, and `SECURITY.md`

Step 1 performed this reconciliation. Historical implementation reports remain
preserved but are subordinate to the accepted secure-identity architecture for
new product authority.

## Affected Modules

Potential later implementation scope includes:

- identity, authorization, proof, capability, device, vault, and recovery
  modules under `apps/phil-device-sdk/`;
- native iOS companion and future mobile secure-hardware providers;
- desktop protected-runtime and approval boundaries;
- proof code under `proving/` and any separately admitted proving backend;
- Starknet/Cairo verifier and account adapter packages;
- Ethereum/Base account, validator, and adapter contracts; and
- future credential, application, agent, and additional network adapters.

Step 1 modified no product module. Step 2 module changes require separate
explicit approval.

## Affected Invariants

Preserved with exact Step 1 wording:

- `phil_secret` remains private root material;
- identity remains independent of chain accounts and validator keys;
- applications create intents and do not receive authority;
- policy and authorization gate every sensitive action;
- adapters cannot access root secrets;
- recovery cannot silently bypass identity or policy binding;
- Ethereum smart accounts remain the preferred Ethereum authority model; and
- full post-quantum security is not claimed today.

Accepted in Step 1:

- retain `phil_secret -> identityRoot -> rootOwnerCommitment`, preserving the
  existing `ownerCommitment` bytes as an internal compatibility alias while
  prohibiting universal public reuse;
- add deterministic domain-separated scoped public commitments;
- replace the fixed production role of `proofType =
  "stwo-unlock-keccak-v1"` with a versioned, algorithm-agile proof descriptor;
- classify the current STWO route as research-only rather than accepted
  production proof architecture;
- replace proof-every-action assumptions with exceptional root proof plus
  routine device/capability authorization; and
- add encrypted identity/data recovery independent of account recovery.

Exact encodings, domains, schemas, and migration rules are frozen in
`docs/PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md`.

## Security Impact

Positive impact:

- removes a known secret-bearing artifact from the product authorization plan;
- prevents cross-network tracking through one universal public identifier;
- keeps root, device, account, proof, and recovery authority independently
  rotatable;
- limits expensive and complex proof verification to high-value operations;
- makes routine app and agent authority narrow, revocable, and auditable;
- restores identity and user data rather than only rotating an account
  validator; and
- creates an explicit migration path for future network-native PQ signatures.

Residual risks:

- no production witness-hiding backend is selected;
- physical-device performance and secure composition are unverified;
- the Step 2 scoped-identity, device, and recovery candidate was independently
  accepted but is not yet composed with a proof-backed account action;
- the bounded recovery/device ceremony does not by itself establish production
  operations, distribution, incident response, or ongoing custody quality;
- the Starknet verifier path is expensive and not Phil-audited;
- supply-chain, release, app-attestation, audit, incident-response, and
  revocation operations remain incomplete; and
- users cannot technically revoke plaintext that a recipient has already
  copied or erase deliberately public on-chain data.

## Migration Impact

- Current STWO source and tests remain only as explicitly labeled synthetic
  research and regression evidence.
- Existing account, cross-domain relay, and V2 recovery work remains useful
  evidence but cannot be treated as complete Phil identity/data recovery or as
  a selected cross-network production route.
- Existing global `ownerCommitment` fixtures remain versioned compatibility
  material; the accepted architecture prohibits them from creating new scoped
  V1 product authority.
- Current public-network preparation and deployment plans remain paused.
- No deployed identity or account migration is authorized by this proposal.

## Rejected Alternatives

1. **Repair STWO locally and continue the old plan.** Rejected because the
   pinned stack has no reviewed application-appropriate witness-hiding mode;
   adding one is a new proof-system security project.
2. **Make Starknet the Phil identity.** Rejected because a network adapter must
   not own the user's cross-network identity or encrypted data continuity.
3. **Publish one owner commitment everywhere.** Rejected because it creates a
   durable cross-context correlation identifier.
4. **Verify a root proof for every action.** Rejected because measured verifier
   cost and composition complexity are unnecessary for routine bounded actions.
5. **Treat the product as a multisig.** Rejected because threshold recovery is
   only one subsystem; it does not replace identity, encrypted data, device
   trust, policy, credentials, capabilities, adapters, or agent authority.
6. **Anchor identity to one network's current signature scheme.** Rejected
   because it prevents clean cross-network and post-quantum migration.
7. **Implement all networks immediately.** Rejected because one reference
   adapter and one complete account composition must pass before expansion.

## Review And Authorization Boundary

This accepted proposal records the new direction and the required sequence.

Current authorization:

- preserve the accepted architecture and feasibility evidence in the public
  candidate;
- keep the production proof backend unselected;
- preserve the independently accepted Steps 3-5 local/read-only candidates and
  their synthetic evidence; and
- implement and independently review only the bounded Step 6A local/read-only
  Base/ERC-4337 adapter binding.

Not authorized:

- protected-product or contract wiring that gives the local candidate
  production authority;
- proof-backend production selection, Step 5 runtime activation, or Step 6 work
  beyond the bounded Step 6A local/read-only adapter candidate;
- any additional physical-device connection without a separate explicit
  authorization and disposable-evidence plan;
- secrets, external provers, signing, deployment, RPC mutation, or chain
  transactions; or
- any external prover or network-based verification service.

Step 1 is complete. Step 2 local implementation and one bounded physical
ceremony were separately authorized and completed; any further physical-device
work still requires separate explicit approval.

## Review Status

Accepted architecture. Step 1 passed. The Step 2 local, bounded physical, and
restricted admission candidate passed; `ac49f01` and `786ab61` were
independently rejected and corrected; `fe583b6aef84a8636736b2041db2a56046a5972e`
was independently accepted. Step 2 is complete. The user separately authorized
the bounded Step 3 local implementation. Exact candidate
`11234ea623a6b8883eed0036f3d95174cef90627` received
`ACCEPT_STEP_3_EXACT_CANDIDATE`; Step 3 is complete as local reference evidence.
The user separately authorized Step 4 after Step 3 acceptance. Exact candidate
`895320f4060ab809b9dab564fcedc1118dfb5780` passed its implementer-run tests but
was independently rejected because the verifier identity was configurable,
zero approval nonces were admitted, failure precedence and replay coverage were
incomplete, and unusable immutable configurations were possible. First
corrective candidate `eaaae447a01bf901fc4183338da88b7406981a4e` closed those
findings but was independently rejected because Cairo still admitted a zero
approval timestamp and the required policy-ceiling branches lacked executed
tests. Second corrective exact candidate
`3377606d404312ef7f7dcfec37a11c046f2c907e` rejects both zero approval
timestamps, executes both exact policy-ceiling rejection branches, passes its
implementer-run local matrix, and received
`ACCEPT_STEP_4_SECOND_CORRECTIVE_EXACT_CANDIDATE` with no unresolved finding.
Step 4 is complete. The user separately authorized Step 5. Exact first
candidate `fc6514394f5f1ff540c10ac87704a3c24e5f3a4b` was independently
rejected for stale Apple ML-DSA classification, impossible capability-record
migration, missing complete-registry binding, missing proof/verifier
compatibility, and caller-relative freshness/provenance. The bounded corrective
candidate closed three findings but was independently rejected for inaccurate
implementation bindings, an unknown-future policy-epoch bypass, and trusted-
state format tampering. A second bounded correction names and binds the actual
implementations, pins the exact policy epoch/hash, and checks the supplied
trusted-state format. Exact candidate
`d1de6082f01756d68f7c732d0c3e8fe3d47d6c96` received
`ACCEPT_SECOND_CORRECTIVE_STEP_5_EXACT_CANDIDATE` with no unresolved finding.
Step 5 is complete as a local architecture gate. The user separately authorized
Step 6. The bounded Step 6A Base/ERC-4337 adapter candidate is implemented for
independent review; it creates no UserOperation, verifies no signature, uses no
RPC, and grants no production or network authority. Production backend
selection and later Step 6 increments remain unauthorized.

Independent review rejected exact Step 6A candidate `33570bb` because the
committed negative-test matrix omitted documented manifest/action substitution
branches and this ordered table retained a stale pre-authorization status. The
reviewer independently reproduced the omitted source branches as fail-closed;
no executable-authority or source-bypass finding was identified. A bounded
corrective Step 6A candidate and another independent review are required.

The bounded correction adds every omitted deterministic manifest/action,
overflow, malformed-input, and derived-field-tampering test while leaving the
adapter source unchanged. Current status documents then agreed that Step 6 had
started, Step 6A remained unaccepted before review, and Step 6B was
unauthorized. The exact corrective candidate then required independent review.

Exact corrective candidate `671936805d511cca0aa4f5754cc8a00693adf71d`
received `ACCEPT_STEP_6A_CORRECTIVE_EXACT_CANDIDATE` with no unresolved
finding. Step 6A is complete as the local Base binding gate. Step 6 remains
incomplete. The user separately authorized Step 6B, and one isolated local
ERC-4337 account candidate now consumes the Step 6A binding, verifies a
synthetic P-256 approval, pins one capability/policy/target surface, and
enforces exact-once execution. It awaits independent review. Official
EntryPoint integration, production wiring, signing, RPC, deployment, and
network activity remain outside this candidate.

Independent review of exact Step 6B candidate `8b72646` found no source-level
authorization bypass or unsigned mutable UserOperation field, but rejected the
candidate because its committed seven-test suite omitted documented negative
branches. The bounded correction expands the suite to fourteen focused tests
and adds only test-harness reachability for exact validation and execution
branches. The production account source remains byte-for-byte unchanged. The
corrective candidate awaits independent re-review; Step 6 remains incomplete.

Independent re-review of exact corrective candidate `58731cf` confirmed every
other coverage category but rejected one timestamp-shadowed test. Its setup
block was mined at `validAfter - 1`, causing the actual transaction to land at
`validAfter` and reach the later approval-start check. The second bounded
correction leaves both production account and harness source unchanged,
schedules the actual transaction for `validAfter - 1`, and asserts the mined
block timestamp. Independent read-only review reproduced that actual transaction
timing and accepted exact candidate
`d65aa5d734de8dd93a524d5a45eb31de7a012ceb`, tree
`0e451a219cff96d91fd40453866e3de784b2d11c`. Step 6B is complete as a local
synthetic gate; Step 6 remains incomplete. Independent review rejected exact
Step 6C definition `fdf3c2e` for a cyclic hash graph, insufficient iPhone and
local-environment binding, conflicting nonce ownership, in-place registry
mutation, non-constructor-faithful EntryPoint setup, contradictory durable
lifecycle rules, and incomplete cross-language/receipt bytes. The bounded
first corrective definition addressed those findings but exact candidate
`a24873e` was independently rejected for four remaining target runtime, crash
evidence, Solidity ABI, and transport-byte gaps. The bounded second correction
addresses them in the primary gate, packet, threat model, and review record.
Step 6C-1 implementation was separately authorized and started, then stopped
before a source candidate was frozen. Mechanical implementation showed that
the packet's catalog kind-6 entry binds the nonce-bearing action hash while the
constructor freezes both catalog and policy hashes, contradicting its required
failed-`n` then successful-`n+1` liveness test. Candidate `227bd48`, tree
`cd5a734`, is therefore not implementable unchanged. The bounded third
corrective definition separates stable schema/capability/catalog/policy
identities from changing signed operation identities. Exact status-correction
candidate `fcc0103`, tree `209df24`, was independently accepted, and bounded
Step 6C-1 synthetic local implementation resumed. Candidates `a158688`,
`aea7359`, `591f6b6`, and `5ab4650` were independently rejected and are
superseded. Corrective source commit `6f048eb`, tree `a9032b2`, is frozen with
reproducible disclosed-synthetic evidence; exact candidate `22b5cf3`, tree
`2b0ff7f`, is independently accepted for Step 6C-1. Separately authorized Step 6C-2 source work
then added the dedicated routine iPhone UI and V2 key boundary, authenticated
local transport, protected Desktop host/storage, and narrow product bridge.
The initial and first five corrective source candidates were independently
rejected. The sixth-corrective source candidate retains Desktop-signed enrollment
acceptance with safe replay, ambiguous-publication key retention, deletion
pre/post-commit distinction, and runtime-failure propagation, while correcting
Swift prehashed verification, acknowledgement-key lifetime, replay expiry, and
replacement-fingerprint refresh. It also corrects the fifth candidate's sole
remaining contradictory report sentence about the signing/persistence order.
Exact candidate `4a81b08`, tree `188d7d0`, is independently accepted. Step
6C-2 is complete as a local source gate. A separately authorized Step 6C-3
physical ceremony stopped on product defects; accepted corrective source and a
fresh bounded ceremony then completed real-iPhone routine authorization,
verified the harmless local receipt, and deleted both disposable sides without
changing identity or recovery state. Exact complete physical evidence
`0461ac7`, tree `c14838c`, was independently accepted. Step 6C and the bounded
six-step local architecture/composition route are complete; public-network and
production authority remain false.
