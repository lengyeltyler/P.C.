# P.C. — Phil Controlled Sepolia Beta 0.1.0

This clean public-source candidate was exported from the accepted PhilCore
engineering source at commit `7fd7ade7b992e9b5b4b6029b3938e1294f372e73`, tree
`7489b116f05d5c44635ea58b45f55824c69941ba`. It begins a new history and does
not preserve the complete historical engineering Git ancestry. Deliberate
exclusions and release-only metadata changes are recorded in the
[clean-source manifest](./config/release/clean-public-source-manifest.json).
This local preparation is not a publication, tag, new physical acceptance or
repository-transition authorization.

P.C. is the public home of PhilCore, a personal security operating system for user-owned digital identity and authorization. P.C. can stand for PhilCore and Personal Computer: the long-term goal is a user-owned personal computing and security layer that connects a person to networks and applications without giving those systems unrestricted control of identity.

PhilCore establishes a private, user-owned cryptographic identity root,
protects encrypted identity and user-data continuity, exposes pairwise scoped
identities, and gates sensitive actions through replaceable device approval,
policy, capabilities, exceptional proofs, isolated adapters, and audit.

Ethereum/Base is the first execution path. It is not the identity layer.

## Local Phil naming and future ENS

The Desktop lets a person choose a local Phil profile name. The name is display metadata only and does not alter the Phil identity root, owner commitment, signing authority, account address, or proof semantics. ENS remains future Mainnet work in the Ethereum adapter. This Beta performs no ENS lookup, reservation, registration, mint, or transaction, and Phil identity does not depend on ENS. See the [final UI boundaries](docs/PHIL_FINAL_BETA_UI.md).

## Current Milestone

Controlled Sepolia Beta technical and UI development are complete within the
accepted owner-operated testnet scope. P2 and P3 completed and reconciled the
first two composed actions. P4 public recovery execution remains deferred by
accepted scope. P5 attempt 2 succeeded and reconciled: one send, zero retries,
zero additional funding, final account nonce `3`, zero native account balance,
and the two existing harmless passes retained. Its transaction is
[`0xceb0…f5c2d`](https://sepolia.etherscan.io/tx/0xceb00a759a8347aa7d70299afb46f7fd18e2f0ba4b3e41ea379b15bca21f5c2d).
The rejected P5 attempt 1 remains permanently consumed; this success does not
reclassify it or authorize another submission.

The final Desktop release from product source `7fd7ade` was Developer ID signed,
notarized, stapled, and Gatekeeper verified. Its distribution archive SHA-256 is
`831f59cf1a0d67e49e69a179cb32e2e579f25f6ea4f778d27e498f6f4ab1883d`. iOS version `0.1.0`, build `58`, was
accepted in the final owner-present physical session. That session passed under
the owner's revised three-request scope: Q1 approved and executed, Q2 was
accidentally approved and executed, and separately authorized Q3 supplied the
authenticated rejection without execution. It was not a pass of the original
exactly-two-request protocol. User presence passed; the evidence does not
separately attest Face ID rather than another permitted local presence method.

The final UI and native-notice engineering candidate has a frozen signed,
notarized Desktop distribution. This clean source excludes the uncleared
historical chain-mark blobs and private physical-observation record; it does
not claim those marks are licensed. Publication still requires the clean-source
audit and explicit owner repository-transition authority. Previously accepted
physical evidence remains bound to its original artifacts, not a new physical
acceptance of this source export or notice-corrected package.
There is no mainnet or production-custody approval, no current post-quantum
security claim, and no professional-audit claim. Noir and iPhone P-256 were
locally verified, not Ethereum-verified. V2 recovery is not deployed. STWO is
quarantined research and is not the production authorization prover.

See the [final release status](./docs/PHILCORE_CONTROLLED_SEPOLIA_BETA_FINAL_RELEASE_STATUS.md)
and [execution history](./docs/PHILCORE_BETA_EXECUTION_STATUS.md).

## Read This First

Current source of truth:

- [Canonical Documentation](./docs/CANONICAL_DOCS.md)
- [PhilCore Core Boundary](./docs/PHILCORE_CORE_BOUNDARY.md)
- [PhilCore Runtime Lifecycle](./docs/PHILCORE_RUNTIME_LIFECYCLE.md)
- [PhilCore Functional Specification v1](./docs/PHILCORE_FUNCTIONAL_SPEC_V1.md)
- [PhilCore Technical Specification v1](./docs/PHILCORE_TECHNICAL_SPEC_V1.md)
- [Phil V1 Secure Identity Architecture](./docs/PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md)
- [Architecture Change Control](./docs/ARCHITECTURE_CHANGE_CONTROL.md)
- [Canonical Repository And Alpha Proof Route](./docs/CANONICAL_REPOSITORY_AND_ALPHA_PROOF_ROUTE.md)
- [Repository Map](./docs/REPOSITORY_MAP.md)
- [PhilCore Beta Readiness Plan](./docs/PHILCORE_BETA_READINESS_PLAN.md)
- [Controlled Sepolia Beta Operations](./docs/PHILCORE_CONTROLLED_SEPOLIA_BETA_OPERATIONS.md)
- [Controlled Sepolia Beta Gate Approval Packet](./docs/PHILCORE_CONTROLLED_SEPOLIA_BETA_GATE_APPROVAL_PACKET.md)
- [PhilCore Beta Execution Status](./docs/PHILCORE_BETA_EXECUTION_STATUS.md)
- [Final Open-Source Release Gate](./docs/OPEN_SOURCE_FINAL_RELEASE_GATE.md)

Technical references:

- [Phil Identity Model](./docs/reference/PHIL_IDENTITY_MODEL.md)
- [Phil Device Identity v1](./docs/reference/PHIL_DEVICE_IDENTITY_V1.md)
- [Proof Input Schema](./docs/reference/PROOF_INPUT_SCHEMA.md)
- [ACTION_UNLOCK Proof Spec](./docs/reference/ACTION_UNLOCK_PROOF_SPEC.md)
- [Phil V1 Architecture Feasibility Gate](./docs/reference/PHIL_V1_ARCHITECTURE_FEASIBILITY_GATE.md)
- [Accepted Phil V1 Secure Identity Roadmap](./docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md)
- [Phil V1 Step 5 Post-Quantum Migration Gate](./docs/reference/PHIL_V1_STEP5_POST_QUANTUM_MIGRATION_GATE.md)
- [Phil V1 Step 6A Base Network Adapter Gate](./docs/reference/PHIL_V1_STEP6A_BASE_NETWORK_ADAPTER_GATE.md)
- [Phil V1 Step 6B Local Smart-Account Enforcement Gate](./docs/reference/PHIL_V1_STEP6B_LOCAL_SMART_ACCOUNT_GATE.md)
- [Phil V1 Step 6C Routine Authorization Product Composition Gate](./docs/reference/PHIL_V1_STEP6C_ROUTINE_AUTHORIZATION_PRODUCT_COMPOSITION_GATE.md)

Application references:

- [PhilCore Desktop Alpha Foundation](./docs/application/PHILCORE_DESKTOP_ALPHA_FOUNDATION.md)
- [PhilCore Desktop Alpha Product Journey](./docs/application/PHILCORE_DESKTOP_ALPHA_PRODUCT_JOURNEY.md)
- [PhilCore Desktop Local Identity And Device Vault](./docs/application/PHILCORE_DESKTOP_LOCAL_IDENTITY_AND_VAULT.md)
- [PhilCore Desktop Platform Authentication](./docs/application/PHILCORE_DESKTOP_PLATFORM_AUTHENTICATION.md)
- [PhilCore Desktop Approval And Presentation](./docs/application/PHILCORE_DESKTOP_APPROVAL_AND_PRESENTATION.md)
- [PhilCore Desktop Real Local Authorization](./docs/application/PHILCORE_DESKTOP_REAL_LOCAL_AUTHORIZATION.md)
- [PhilCore Desktop Packaging](./docs/application/PHILCORE_DESKTOP_PACKAGING.md)
- [PhilCore Desktop Local Alpha Release](./docs/application/PHILCORE_DESKTOP_LOCAL_ALPHA_RELEASE.md)
- [PhilCore Desktop Security Boundary](./docs/application/PHILCORE_DESKTOP_SECURITY_BOUNDARY.md)
- [PhilCore Local Authorization Demo](./docs/application/PHILCORE_LOCAL_AUTHORIZATION_DEMO.md)
- [Phil Cross-Device Local Alpha Recording Demo](./docs/reference/PHIL_LOCAL_ALPHA_DEMO.md)
- [PhilCore Desktop Testing](./docs/application/PHILCORE_DESKTOP_TESTING.md)

## Core Model

The identity invariant is:

```text
phil_secret -> identityRoot -> rootOwnerCommitment
```

The private `phil_secret` is root material. `identityRoot` and
`rootOwnerCommitment` are protected by default; existing `ownerCommitment`
bytes remain a compatibility alias. Public relationships use scoped
commitments. The root is not an Ethereum wallet, EOA, passkey, credential,
device, chain account, or value staged on-chain.

PhilCore applications create intents. The PhilCore Runtime API evaluates intents. Trust Manager evaluates trusted credentials/devices. Security Policy Engine and Authorization Engine gate sensitive actions. Adapters execute only approved authorization packages.

## Ethereum-First Execution

Ethereum Net is the first user-facing execution application.

Ethereum Adapter is the first internal execution adapter. Base remains a profile/config under Ethereum Adapter unless future complexity justifies a separate Base Adapter.

PhilCore's preferred Ethereum authority model is ERC-4337 Account Abstraction using PhilCore-controlled Smart Accounts. EOAs, including MetaMask-style wallets, are compatibility paths. Existing EOAs may connect, fund PhilCore accounts, migrate assets, and participate in interoperability, but PhilCore cannot become final authority over an EOA while that EOA's private key remains the controlling signer.

### Current V2 smart-account model

`PhilCoreV2MinimalAccountV2` is the current narrow, security-critical
smart-account model. It deliberately exposes typed actions instead of generic
execution: no arbitrary call, delegatecall, batch, token approval, module,
session-key, proxy-upgrade, or paymaster extension is part of V2. Legacy V1
and N-series account material is compatibility/history scope and does not
define current V2 authority.

V2 recovery uses three fixed roles and exact 2-of-3 authority. The active
execution validator is not a recovery factor and cannot veto a valid recovery
quorum. The design assumes the three roles are independently custodied and
failure-separated; co-locating or cloud-synchronizing factors under one
practical custody domain weakens the intended threshold, and protocol
cryptography cannot prove every real-world custody domain is independent.

Start with the [V2 implementation report](./docs/reference/O37_10_V2_MINIMAL_ACCOUNT_IMPLEMENTATION_REPORT.md),
the [current recovery semantics](./docs/reference/O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md),
and the [V2 formal threat model](./docs/security/O30_V2_FORMAL_THREAT_MODEL.md).

### Controlled Sepolia Beta account

The public introduction Beta deliberately uses a narrower account than the
general V2 research model. `PhilCore4337Account` is non-upgradeable, reusable,
bound to one immutable ActionGate, rejects paymasters and non-zero ordinary
actions, supports validator rotation and delayed independent recovery, and
provides a current-owner-only route for returning disposable test funds. Its
exact testnet-only scope and ceilings are frozen in
[ACP-0004](./docs/architecture-changes/ACP-0004-CONTROLLED-SEPOLIA-BETA.md).
This does not supersede V2 recovery research or authorize production custody.

The legacy account's public P2/P3 evidence must not be presented as V2 recovery
evidence. Any public V2 deployment, recovery, validator rotation,
recovery-authority configuration rotation, or V2 ActionGate exercise is a new,
separately reviewed milestone.

```text
P4: DEFERRED — NOT PART OF THIS BETA'S PUBLIC EXECUTION EXIT CRITERIA
V2 PUBLIC DEPLOYMENT/RECOVERY EXECUTION IN THIS BETA: NOT PERFORMED
P3 CANONICAL STATUS: COMPLETE AND RECONCILED
PHILCORE CONTROLLED SEPOLIA BETA READY: NO
```

## Locked Compatibility Surfaces

These current surfaces remain byte stable for tests and migration analysis,
but do not define new V1 product authority:

- `phil_secret -> identityRoot -> ownerCommitment`
- `ACTION_UNLOCK`
- proof public input tuple
- `proofInputHash`
- `proofType = "stwo-unlock-keccak-v1"`
- `[fact_high, fact_low]`
- WebAuthn/passkey provider architecture
- encrypted registry and key lifecycle work
- current STARK/proof work

PhilCore does not claim full post-quantum security yet. Current WebAuthn and Ethereum/Base execution depend on non-post-quantum primitives.

## What Exists Today

The repository currently contains:

- TypeScript SDK code for Phil identity, authorization helpers, device identity, WebAuthn/passkey verification, credential lifecycle, encrypted storage, IndexedDB/WebCrypto storage, and key lifecycle.
- Solidity contracts for Base-side authorization hashing, mirrored fact verification, action gating, mint-pass consumption, and L1/Base message boundaries.
- Rust proving core and fixtures for the locked `ACTION_UNLOCK` statement.
- Cairo/Starknet spike and integration packages that preserve the locked proof input hash and two-felt fact shape.
- Local Ethereum/Base artifact builders and no-send smart-account deploy/session drills.
- A local-only Electron desktop Alpha with durable encrypted Phil identity, encrypted registry/Device Vault records, macOS protected unlock, digest-bound approvals, a real Noir/Barretenberg UltraKeccakZK root-proof gate, separate signing approval, fresh user presence, and one harmless local Ethereum fixture execution. The old secret-bearing STWO route remains quarantined.
- Local device-signing and Device Identity demo flows.
- A bounded public Sepolia Alpha demonstration using a restricted ERC-4337
  smart account, physical iPhone approval, three-dimensional on-chain replay
  consumption, and a zero-value non-transferable test pass.
- Unit/regression tests for contracts, identity, proof schema parity, local signing, and local session matrices.

This is not production-ready security software or an externally audited
system. The deployed Sepolia contracts are disposable Alpha demonstration
infrastructure and must not be treated as Beta custody or production protocol
deployments.

## Accepted Efficient Route Forward

The current STWO authorization path remains quarantined. The local Alpha now
selects and executes the exact Noir/Barretenberg/Garaga-compatible route
recorded in the
[canonical repository and Alpha proof decision](./docs/CANONICAL_REPOSITORY_AND_ALPHA_PROOF_ROUTE.md).
This is an Alpha backend selection, not a production-backend claim. The broader
replacement architecture is recorded in the
[secure identity architecture](./docs/PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md)
and
[ACP-0003](./docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md)
and is intentionally gated one step at a time:

1. Freeze the product architecture, not a proof backend.
2. Finish the device and identity/data recovery foundation.
3. Build Starknet as the reference private-proof adapter for exceptional root
   operations.
4. Pass one composed account gate covering proof, enrolled device signature,
   policy, nonce, expiry, and revocation before deployment.
5. Lock post-quantum migration fields and ceremonies without claiming current
   PQ security.
6. Expand Ethereum/Base and later network adapters without changing the
   private Phil identity.

Steps 1-5 are complete as independently reviewed local gates. The user
separately authorized Step 5, and its local
post-quantum migration-control candidate is implemented. The candidate freezes
scheme IDs, blocks candidate algorithms from activation, requires hybrid-AND
semantics, binds per-network evidence, and defines rotation/recovery
ceremonies. The first exact candidate was independently rejected; a bounded
correction now adds current Apple ML-DSA classification, complete-registry and
proof/verifier binding, trusted freshness/provenance, and same-network
capability migration. Independent review rejected that first correction for
three residual binding/trust defects. A second bounded correction binds the
actual implementations, the exact current policy epoch/hash, and the supplied
trusted-state format. Exact second corrective candidate
`d1de6082f01756d68f7c732d0c3e8fe3d47d6c96` was independently accepted with no
unresolved finding, completing the local Step 5 architecture gate. This does
not make Phil post-quantum. The user separately authorized Step 6, and the first
bounded Step 6A candidate now binds one routine scoped envelope to an exact
Base/ERC-4337 v0.7 single-call profile. It remains local-policy-only and does
not verify a signature or create a UserOperation. Independent review rejected
exact candidate `33570bb` for incomplete committed negative-test coverage and
a contradictory roadmap status; the omitted source branches independently
failed closed. A bounded correction added every omitted deterministic test and
reconciled current status without changing adapter source. Exact corrective
candidate `6719368` was independently
accepted with no unresolved finding, completing the Step 6A local binding
gate. The separately authorized Step 6B local smart-account candidate now
recomputes those bindings, verifies a synthetic low-S P-256 device approval,
enforces an immutable narrow capability policy, and executes exactly once
through an EntryPoint-shaped local harness. It does not establish official
EntryPoint or Base integration. Independent review
found no source bypass but rejected incomplete committed negative coverage. A
bounded correction now executes those omitted branches without changing the
production account source. Re-review confirmed every category except one
timestamp-shadowed before-action test. A second bounded correction now mines
the actual transaction at `validAfter - 1`, asserts that observed timestamp,
and changes no production account or harness source. Exact candidate
`d65aa5d734de8dd93a524d5a45eb31de7a012ceb` was independently accepted after
the actual transaction timing and intended action-start rejection were
reproduced. Step 6B is complete as a local synthetic gate; Step 6 as a whole is
not complete. Independent review rejected exact Step 6C definition candidates
`fdf3c2e` and `a24873e`; the latter materially closed the first seven findings
but still left target runtime admission, official-operation crash evidence,
the nested Solidity selector/tuples, and local transport bytes incomplete. The
bounded second correction retains the acyclic signed chain-`31337` design and
normally deployed official EntryPoint, while signing the target code hash,
durably committing exact local/official operation evidence, publishing selector
`0x5a99466a` and every tuple, and freezing QR/base64url/HTTP/frame/journal-AAD
bytes. Step 6C-1 implementation was started after separate authorization and
stopped before a source candidate was frozen because the accepted definition
freezes a nonce-bound catalog/policy while also requiring the same account to
accept the next official EntryPoint nonce. The contradiction and smallest
corrective direction are recorded in the Step 6C-1 implementation-blocker
report. A bounded third corrective definition now separates stable parameter-
schema/capability/catalog/24-hour-policy identities from each nonce-bearing,
120-second signed request. Exact status-correction candidate `fcc0103`, tree
`209df24`, was independently accepted, and bounded Step 6C-1 synthetic local
implementation resumed. Source candidates `a158688`, `aea7359`, `591f6b6`,
and `5ab4650` were independently rejected and are superseded. Corrective source
commit `6f048eb`, tree `a9032b2`, is now frozen with 37 focused passing cases and reproducible
disclosed-synthetic artifacts. Exact candidate `22b5cf3`, tree `2b0ff7f`, is
independently accepted for Step 6C-1 disclosed-synthetic local composition.
The initial Step 6C-2 source candidate and its first five corrective candidates
were independently rejected. Exact sixth-corrective candidate `4a81b08`, tree
`188d7d0`, is independently accepted as the historical Step 6C-2 local source
gate. The first separately authorized Step 6C-3 physical ceremony exposed
repeat-scanner and product-state defects and was stopped. Exact bounded
corrective source candidate `c32d8f8`, tree `12eb24e`, was independently
accepted for a fresh disposable physical retest. That retest then exposed and
corrected a Desktop packaging omission at `41d9ab8`, tree `320fbc4`; the rebuilt
package completed the enrolled iPhone approval and verified the harmless local
receipt. The rebuilt package was generated from `cc35294`, tree `65a9d0d`.
Exact complete physical evidence `0461ac7`, tree `c14838c`, was independently
accepted after both the iPhone routine key and Desktop routine profile were
deleted without changing identity or recovery state. Step 6C and the bounded
six-step local architecture/composition route are complete. This grants no
public-network or production authority.
The second corrective definition
remains historical exact candidate `227bd48`, tree `cd5a734`; it is not
implementable unchanged. The roadmap
selects no production proof backend and authorizes no
physical-device work, deployment, or public-network mutation.

- [Step 2 implementation report](./docs/reference/PHIL_V1_STEP2_DEVICE_RECOVERY_IMPLEMENTATION_REPORT.md)
- [Step 5 implementation report](./docs/reference/PHIL_V1_STEP5_IMPLEMENTATION_REPORT.md)
- [Step 5 second corrective implementation report](./docs/security/PHIL_V1_STEP5_SECOND_CORRECTIVE_IMPLEMENTATION_REPORT.md)
- [Step 5 independent acceptance](./docs/reference/PHIL_V1_STEP5_SECOND_CORRECTIVE_INDEPENDENT_REVIEW_D1DE608.md)
- [Step 6A implementation report](./docs/reference/PHIL_V1_STEP6A_IMPLEMENTATION_REPORT.md)
- [Step 6A threat model](./docs/security/PHIL_V1_STEP6A_BASE_NETWORK_ADAPTER_THREAT_MODEL.md)
- [Step 6C-3 rejected corrective review of 6670b93](./docs/reference/PHIL_V1_STEP6C3_CORRECTIVE_REVIEW_6670B93.md)
- [Step 6C-3 rejected successor review of caf077e](./docs/reference/PHIL_V1_STEP6C3_SUCCESSOR_REVIEW_CAF077E.md)
- [Step 6C-3 accepted corrective review of c32d8f8](./docs/reference/PHIL_V1_STEP6C3_CORRECTIVE_ACCEPTANCE_C32D8F8.md)
- [Step 6C-3 physical success evidence](./docs/reference/PHIL_V1_STEP6C3_PHYSICAL_SUCCESS_EVIDENCE.md)
- [Step 6C-3 accepted complete physical evidence](./docs/reference/PHIL_V1_STEP6C3_PHYSICAL_SUCCESS_ACCEPTANCE_0461AC7.md)
- [Step 6A independent review packet](./docs/reference/PHIL_V1_STEP6A_INDEPENDENT_REVIEW_PACKET_33570BB.md)
- [Step 6A independent rejection](./docs/reference/PHIL_V1_STEP6A_INDEPENDENT_REVIEW_33570BB.md)
- [Step 6A bounded corrective implementation](./docs/security/PHIL_V1_STEP6A_CORRECTIVE_IMPLEMENTATION_REPORT.md)
- [Step 6A corrective independent review packet](./docs/reference/PHIL_V1_STEP6A_CORRECTIVE_INDEPENDENT_REVIEW_PACKET_6719368.md)
- [Step 6A corrective independent acceptance](./docs/reference/PHIL_V1_STEP6A_CORRECTIVE_INDEPENDENT_REVIEW_6719368.md)
- [Step 6B local smart-account gate](./docs/reference/PHIL_V1_STEP6B_LOCAL_SMART_ACCOUNT_GATE.md)
- [Step 6B threat model](./docs/security/PHIL_V1_STEP6B_LOCAL_SMART_ACCOUNT_THREAT_MODEL.md)
- [Step 6B artifact manifest](./docs/reference/PHIL_V1_STEP6B_ARTIFACT_MANIFEST.json)
- [Step 6B independent rejection](./docs/reference/PHIL_V1_STEP6B_INDEPENDENT_REVIEW_8B72646.md)
- [Step 6B corrective implementation](./docs/security/PHIL_V1_STEP6B_CORRECTIVE_IMPLEMENTATION_REPORT.md)
- [Step 6B corrective independent rejection](./docs/reference/PHIL_V1_STEP6B_CORRECTIVE_INDEPENDENT_REVIEW_58731CF.md)
- [Step 6B second corrective implementation](./docs/security/PHIL_V1_STEP6B_SECOND_CORRECTIVE_IMPLEMENTATION_REPORT.md)
- [Step 6B second corrective independent acceptance](./docs/reference/PHIL_V1_STEP6B_SECOND_CORRECTIVE_INDEPENDENT_REVIEW_D65AA5D.md)
- [Step 6C routine authorization product composition gate](./docs/reference/PHIL_V1_STEP6C_ROUTINE_AUTHORIZATION_PRODUCT_COMPOSITION_GATE.md)
- [Step 6C exact implementation packet](./docs/reference/PHIL_V1_STEP6C_IMPLEMENTATION_PACKET.md)
- [Step 6C threat model](./docs/security/PHIL_V1_STEP6C_ROUTINE_AUTHORIZATION_THREAT_MODEL.md)
- [Step 6C independent rejection of fdf3c2e](./docs/reference/PHIL_V1_STEP6C_DEFINITION_INDEPENDENT_REVIEW_FDF3C2E.md)
- [Step 6C corrective-definition rejection of a24873e](./docs/reference/PHIL_V1_STEP6C_CORRECTIVE_DEFINITION_INDEPENDENT_REVIEW_A24873E.md)
- [Step 6C second-corrective definition acceptance of 227bd48](./docs/reference/PHIL_V1_STEP6C_SECOND_CORRECTIVE_DEFINITION_INDEPENDENT_REVIEW_227BD48.md)
- [Step 6C-1 nonce/catalog implementation blocker](./docs/reference/PHIL_V1_STEP6C_IMPLEMENTATION_BLOCKER_NONCE_CATALOG.md)
- [Step 6C third corrective definition](./docs/reference/PHIL_V1_STEP6C_THIRD_CORRECTIVE_DEFINITION.md)
- [Step 6C third-corrective status-correction acceptance](./docs/reference/PHIL_V1_STEP6C_THIRD_CORRECTIVE_DEFINITION_STATUS_CORRECTION_INDEPENDENT_REVIEW_FCC0103.md)
- [Step 6C-1 rejected A158688 independent review](./docs/reference/PHIL_V1_STEP6C_INDEPENDENT_REVIEW_A158688.md)
- [Step 6C-1 rejected AEA7359 independent review](./docs/reference/PHIL_V1_STEP6C_INDEPENDENT_REVIEW_AEA7359.md)
- [Step 6C-1 rejected 591F6B6 independent review](./docs/reference/PHIL_V1_STEP6C_INDEPENDENT_REVIEW_591F6B6.md)
- [Step 6C-1 rejected 5AB4650 independent review](./docs/reference/PHIL_V1_STEP6C_INDEPENDENT_REVIEW_5AB4650.md)
- [Step 6C-1 accepted 22B5CF3 independent review](./docs/reference/PHIL_V1_STEP6C_INDEPENDENT_REVIEW_22B5CF3.md)
- [Step 6C-1 synthetic implementation report](./docs/reference/PHIL_V1_STEP6C_IMPLEMENTATION_REPORT.md)
- [Step 6C-1 disclosed synthetic fixture](./config/adapters/PHIL_V1_STEP6C_LOCAL_COMPOSITION_FIXTURE.json)
- [Step 6C-1 artifact manifest](./docs/reference/PHIL_V1_STEP6C_ARTIFACT_MANIFEST.json)
- [Step 6C-2 product wiring implementation report](./docs/reference/PHIL_V1_STEP6C2_PRODUCT_WIRING_IMPLEMENTATION_REPORT.md)
- [Step 6C-2 artifact manifest](./docs/reference/PHIL_V1_STEP6C2_ARTIFACT_MANIFEST.json)
- [Step 6C-2 rejected third-corrective review](./docs/reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_965F9ED.md)
- [Step 6C-2 rejected fourth-corrective review](./docs/reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_09E5A9E.md)
- [Step 6C-2 rejected fifth-corrective review](./docs/reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_8A2D906.md)
- [Step 6C-2 accepted sixth-corrective review](./docs/reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_4A81B08.md)
- [Step 2 device/recovery threat model](./docs/security/PHIL_V1_STEP2_DEVICE_RECOVERY_THREAT_MODEL.md)
- [Cross-device PhilUI visual-integration candidate](./docs/reference/PHIL_V1_DESKTOP_VISUAL_INTEGRATION_CANDIDATE.md)
- [Black-and-white interface with full-color Philenator world](./docs/reference/PHIL_3D_MONOCHROME_PHILENATOR_CANDIDATE.md)
- [Frozen cross-device Local Alpha release candidate](./docs/reference/PHIL_LOCAL_ALPHA_CROSS_DEVICE_RELEASE_CANDIDATE_2A2D1AB.md)
- [Cross-device Local Alpha corrective candidate](./docs/reference/PHIL_LOCAL_ALPHA_CROSS_DEVICE_CORRECTIVE_CANDIDATE_80E5379.md)

The Rust/STWO prover remains available only for explicit process-local synthetic
research. Its output is labeled `EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT`.
Never use it with a real Phil secret or transmit its proof bytes.

Do not use PhilCore to custody meaningful assets, production funds, or
operationally important accounts. No current public-network deployment is
approved, and the repository's public-network submission scripts are excluded
from the credential-free deterministic gate.

## Repository Map

- `apps/phil-device-sdk/`: identity, device identity, Trust Manager-adjacent lifecycle/storage, authorization, hashes, proof helpers.
- `apps/philcore-desktop/`: local-only Electron desktop Alpha shell with a narrow preload bridge, durable local identity/Device Vault, fail-closed Runtime authorization, and quarantined proof/ERC-4337 regression boundaries.
- `contracts/base/`: Base-side authorization, mirror, verifier, action gate, and consumer contracts.
- `contracts/l1/`: L1 trust-anchor and Base messenger adapter contracts.
- `proving/`: Rust proving/verifying core, fixtures, and proof/fact harnesses.
- `scripts/base/`: Ethereum/Base local artifact builders, local runners, bundler stub, signing, and deploy-session integrations.
- `test/unit/`: Hardhat unit and regression coverage.
- `starknet_*`, `cairo_air_adapter_spike/`, `merkle_parity_spike/`: active proof/Starknet/Cairo research packages.
- `docs/`: current specifications, security boundaries, and selected technical references. Internal phase archives and experimental research logs are intentionally excluded from this public candidate.

Generated outputs live under `proving/out/` and are intentionally ignored by git.

## License and Public-Source Scope

Phil-owned software is licensed under the [MIT License](./LICENSE), except
where a file or component carries a different license. Third-party code and
visual assets are not relicensed by Phil. See
[Third-Party Notices](./THIRD_PARTY_NOTICES.md), the
[Asset Rights classification](./docs/reference/ASSET_RIGHTS.md), and the
[Public Phil Source Boundary](./docs/reference/PUBLIC_SOURCE_BOUNDARY.md).

The root package remains marked `private` to prevent accidental npm
publication; that packaging safeguard does not mean Phil is proprietary.

## Local Development

Requirements:

- Node.js 26.0.0 (exact; see `.node-version` and `package.json`)
- npm 11.12.1 (exact; see `package.json`)
- Rust with the toolchain specified in `proving/rust-toolchain.toml`
- the checksum-pinned Noir, Barretenberg, Cairo, Scarb, Starknet Foundry, and
  Universal Sierra Compiler versions installed by
  `npm run ci:install-starknet-toolchain` for proof-package work

Basic setup:

```bash
npm ci
npm run ci:validate-classification
npm run ci:lane:product-runtime
npm run ci:lane:solidity
```

The complete credential-free lane sequence, pinned proof-toolchain installation,
and the explicit separation of local integration tests are documented
in [Local Development](./LOCAL_DEVELOPMENT.md#public-deterministic-validation).
The broad `test:unit` aggregate is not the public deterministic gate because it
also includes classified local-integration and manual tests.

The public CI targets `main`, grants only read access to repository contents,
and exposes no secrets or publication authority to pull-request code. The
macOS Desktop lane is maintainer/manual-only to bound hosted-runner cost for
untrusted forks.

Useful local flows:

```bash
npm run generate:local-fixtures
npm run demo:device-identity
npm run demo:runtime-alpha0
npm run demo:runtime-alpha0-shell
npm run desktop:dev
npm run desktop:test
npm run desktop:test:e2e
npm run desktop:demo-real-local-authorization
npm run desktop:test-sepolia-userop-preparation
npm run desktop:diagnose-local-proof
npm run desktop:diagnose-local-4337
npm run desktop:user-presence:build
npm run desktop:user-presence:test
npm run desktop:package-local
npm run desktop:package-adhoc
npm run desktop:verify-package
npm run desktop:test-packaged
npm run test:unit
npm run --silent run:local-smart-account-deploy-signing
npm run --silent run:local-device-signing-session-matrix-integration
```

`demo:runtime-alpha0` runs the local non-authoritative Runtime/Trust/Policy/Approval/Candidate orchestration demo. `demo:runtime-alpha0-shell` opens a local diagnostic shell for the same scenarios. Neither command authenticates, authorizes, persists, proves, or executes adapters. See [PhilCore Alpha 0 Non-Authoritative Demo](./docs/reference/PHILCORE_ALPHA0_NON_AUTHORITATIVE_DEMO.md).

`desktop:dev` launches the local-only PhilCore Desktop Alpha shell. The current
product path is organized around Home, Identity, Trust, Recovery, Ethereum,
Activity, Settings, and a separated Developer mode. It can create or open an
encrypted local Phil identity, authenticate with a local Alpha passphrase,
unlock an encrypted local Device Vault, and expose sanitized summaries. The
former protected-action and Ethereum test-account workflows now stop at the
proof quarantine: ordinary and Device Vault witnesses are rejected, so the
secret-bearing STWO artifact cannot reach finalization, signing, UserOperation
export, or local execution. Developer diagnostics may exercise only the
explicit process-local synthetic research boundary and its guarded rejection
paths; Developer mode is not alternate authority. The app exposes no public
submitter, public RPC mutation, paymaster, private key, vault key, wrapping
key, decrypted registry plaintext, reusable approval authority, generic wallet
control, Starknet/L1/Base publication, or public bundler submission.

For details, see [Local Development](./LOCAL_DEVELOPMENT.md).

## Documentation Hygiene

Internal phase reports, decision logs, prompts, and research work logs are not
part of this public candidate. For current direction, start with
[Canonical Documentation](./docs/CANONICAL_DOCS.md) and
[Pre-MVP Security Findings](./docs/security/PRE_MVP_SECURITY_FINDINGS.md).
