# Canonical Documentation

This is the current documentation index for PhilCore.

PhilCore is a Personal Security Operating System. Ethereum/Base is the first execution path, not the identity layer.

The accepted source-of-truth documents remain at the top level of `docs/`.
Selected current supporting material is organized under `docs/reference/` and
`docs/security/`. Internal research logs and historical archives are excluded
from the public candidate.

## 1. Current Source Of Truth

Read these first. These documents define the accepted product, runtime, functional, and technical model.

- [PhilCore Core Boundary](./PHILCORE_CORE_BOUNDARY.md)
- [PhilCore Runtime Lifecycle](./PHILCORE_RUNTIME_LIFECYCLE.md)
- [PhilCore Functional Specification v1](./PHILCORE_FUNCTIONAL_SPEC_V1.md)
- [PhilCore Technical Specification v1](./PHILCORE_TECHNICAL_SPEC_V1.md)
- [Phil V1 Secure Identity Architecture](./PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md)
- [Architecture Change Control](./ARCHITECTURE_CHANGE_CONTROL.md)
- [Canonical Repository And Alpha Proof Route](./CANONICAL_REPOSITORY_AND_ALPHA_PROOF_ROUTE.md)
- [Repository Map](./REPOSITORY_MAP.md)
- [PhilCore Beta Readiness Plan](./PHILCORE_BETA_READINESS_PLAN.md)
- [PhilCore Beta Execution Status](./PHILCORE_BETA_EXECUTION_STATUS.md)
- [Controlled Sepolia Beta Architecture](./architecture-changes/ACP-0004-CONTROLLED-SEPOLIA-BETA.md)
- [Controlled Sepolia Beta Operations](./PHILCORE_CONTROLLED_SEPOLIA_BETA_OPERATIONS.md)
- [Final Open-Source Release Gate](./OPEN_SOURCE_FINAL_RELEASE_GATE.md)

Current milestone evidence:

- [Completed Phil Sepolia Mint Alpha Evidence](./reference/PHIL_SEPOLIA_MINT_ALPHA_EVIDENCE_2026-08-25.md)
- [Controlled Sepolia Beta P1 Infrastructure Evidence](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P1_EVIDENCE_2026-08-25.md)
- [Controlled Sepolia Beta P2 Composed-Action Evidence](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P2_EVIDENCE_2026-08-26.md)
- [Controlled Sepolia Beta P3 Runner Implementation](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P3_IMPLEMENTATION_REPORT_2026-08-26.md)
- [Controlled Sepolia Beta P3 Confirmed Execution Evidence](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P3_EVIDENCE_2026-08-27.md)
- [Controlled Sepolia Beta P4 Public-Execution Scope Closure](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P4_SCOPE_CLOSURE_2026-08-27.md)
- [Controlled Sepolia Beta P3 Exact-Source Audit Prompt](./security/PHILCORE_CONTROLLED_SEPOLIA_BETA_P3_RUNNER_AUDIT_PROMPT.md)
- [Phil Sepolia Mint Composed Demo Design](./reference/PHIL_SEPOLIA_MINT_COMPOSED_DEMO_V1.md)

Current source-of-truth concepts:

- PhilCore is a Personal Security Operating System.
- `phil_secret -> identityRoot -> rootOwnerCommitment` is the protected root
  invariant; existing `ownerCommitment` bytes are a compatibility alias.
- Public relationships use pairwise scoped commitments.
- Applications create intents.
- PhilCore Runtime API evaluates intents.
- Trust Manager evaluates trusted credentials/devices.
- Security Policy Engine and Authorization Engine gate sensitive actions.
- Ethereum Net is the first user-facing execution application.
- Ethereum Adapter is the first execution adapter.
- ERC-4337 Smart Accounts are the preferred Ethereum authority model.
- EOAs are compatibility paths.
- STARK/proof work supports proof-backed authorization.
- PhilCore does not claim full post-quantum security yet.

### Accepted secure-identity architecture

The current STWO proof remains structurally quarantined. ACP-0003 Step 1 keeps Phil's private
identity root independent of any proof backend or network, introduces scoped
public identities, separates device approval from exceptional root proofs,
adds encrypted identity/data recovery, and orders future Starknet,
post-quantum, and multi-network work behind explicit gates.

This direction is **accepted**. Step 1 reconciled the source-of-truth set and
selected no production proof backend. A later bounded decision now selects the
exact Noir/Barretenberg/Garaga-compatible route for the functioning local
Alpha only; production backend selection and public deployment remain open.
The Step 2 local device-and-recovery candidate is implemented
and its bounded physical-iPhone ceremony passed with corrective cancellation
handling. A fail-closed policy now admits only that exact evidence envelope;
independent reviews rejected `ac49f01` and `786ab61`; the final exact source
candidate `fe583b6aef84a8636736b2041db2a56046a5972e` corrected those findings
and received `ACCEPT_STEP_2_EXACT_CANDIDATE`. Step 2 is complete. Step 3 exact
candidate `11234ea623a6b8883eed0036f3d95174cef90627` was independently accepted.
Step 4 candidates `895320f4060ab809b9dab564fcedc1118dfb5780` and
`eaaae447a01bf901fc4183338da88b7406981a4e` were independently rejected.
The bounded second corrective candidate closes the remaining timestamp-parity
and policy-ceiling-test findings. Exact candidate
`3377606d404312ef7f7dcfec37a11c046f2c907e` passed its implementer-run matrix,
was independently accepted with no unresolved finding, and completes Step 4.
The user separately authorized Step 5. Its local migration-control candidate
freezes scheme identities, candidate non-activation, hybrid-AND and downgrade
rules, network capability records, and rotation/recovery ceremonies. It makes
no PQ security claim. Exact first candidate `fc65143` was independently
rejected. A bounded corrective candidate now adds accurate Apple ML-DSA
classification, complete-registry and proof/verifier binding, trusted
freshness/provenance, and same-network capability migration. That candidate
was also independently rejected for three residual implementation-binding and
policy-trust defects. A second bounded correction addresses only those defects
and exact candidate `d1de6082f01756d68f7c732d0c3e8fe3d47d6c96` was independently
accepted with no unresolved finding. Step 5 is complete as a local architecture
gate. Phil remains algorithm-agile only. The user separately authorized Step 6;
the bounded Step 6A Base/ERC-4337 local adapter candidate was implemented and
exact candidate `33570bb` was independently rejected for incomplete committed
negative-test evidence and a stale contradictory roadmap status. The omitted
source branches independently failed closed. It grants no runtime, signature,
transaction, or network authority. A bounded correction added the omitted
deterministic rejection coverage and reconciled current status without changing
adapter source. Exact corrective candidate `6719368` was independently accepted with no
unresolved finding, completing the Step 6A local binding gate. Step 6 remains
incomplete. The separately authorized Step 6B local smart-account candidate is
implemented. It verifies a synthetic P-256
approval and enforces one immutable local capability surface, but establishes
no official EntryPoint integration, Base network path, or production authority.
Independent review found no source bypass but rejected incomplete committed
negative coverage. A bounded test-evidence correction is implemented without
changing the production account source. Re-review confirmed all but one
timestamp-shadowed action-start test. A second bounded correction schedules
and observes the actual transaction before `validAfter` and changes neither the
production account nor harness. Exact candidate `d65aa5d734de8dd93a524d5a45eb31de7a012ceb`
was independently accepted after that execution timing was reproduced. Step 6B
was complete as a local synthetic gate while Step 6 remained incomplete. Independent
review rejected exact Step 6C definitions `fdf3c2e` and `a24873e`. The first
corrective candidate closed the original seven defects but left four high-
severity gaps in target runtime admission, crash evidence, literal Solidity
calldata, and local transport bytes. The second correction keeps the acyclic
chain-`31337`/normally deployed EntryPoint/sole-nonce design, signs target code,
commits exact local and official operation evidence, publishes every tuple and
selector `0x5a99466a`, and freezes QR/HTTP/frame/journal-AAD bytes. Legacy
Alpha, recovery, STWO/root proofs, public RPC, deployment, and meaningful
assets remain outside the routine path. Exact candidate
`227bd48d92c84672c50f2d19f47b9a24e5b17786`, tree
`cd5a734c5ca1ce486d55024befa85424aefefb42`, was independently accepted with
no critical/high finding. Separately authorized Step 6C-1 implementation then
stopped before a source candidate because its nonce-bearing action hash also
changes a catalog and policy hash that the account constructor must freeze,
contradicting the required next-nonce liveness test. Definition `227bd48` is
historical accepted evidence but is not implementable unchanged. A bounded
third corrective definition now freezes stable parameter-schema, capability,
catalog, and 24-hour policy identities while keeping every nonce-bearing
120-second action fully signed. Exact status-correction candidate `fcc0103`,
tree `209df24`, was independently accepted; bounded Step 6C-1 synthetic local
implementation resumed. Source candidates `a158688`, `aea7359`, `591f6b6`,
and `5ab4650` were independently rejected and are superseded. Corrective source
commit `6f048eb`, tree `a9032b2`, is frozen with 37 focused passing cases and reproducible
disclosed-synthetic artifacts. Exact candidate `22b5cf3`, tree `2b0ff7f`, is
independently accepted for Step 6C-1 disclosed-synthetic local composition.
Initial Step 6C-2 candidate `021e703`, tree `47efec7`, first corrective
`c40fa2c`, tree `86b92e9`, and second corrective `75785f3`, tree `03008b5`,
third corrective `965f9ed`, tree `76c5821`, fourth corrective `09e5a9e`, tree
`1da89d0`, and fifth corrective `8a2d906`, tree `f7e1b4a`, were independently
rejected and are superseded. A sixth-corrective documentation-only
iPhone/Desktop source candidate, exact commit `4a81b08`, tree `188d7d0`, is
independently accepted as the historical local source gate. The first Step
6C-3 physical ceremony exposed repeat-scanner and product-state defects and was
stopped. Exact corrective source `c32d8f8`, tree `12eb24e`, was independently
accepted. The fresh physical retest then exposed a pruned Desktop runtime
artifact, corrected at `41d9ab8`, tree `320fbc4`. The rebuilt package completed
the enrolled iPhone approval and verified the harmless local receipt. The
package was generated from `cc35294`, tree `65a9d0d`; its exact physical-success
evidence and two-sided disposable cleanup were recorded at exact commit
`0461ac7`, tree `c14838c`, and independently accepted. Step 6C and the bounded
six-step local architecture/composition route are complete. Public-network and
production authority remain false.

- [Phil V1 Architecture Feasibility Gate](./reference/PHIL_V1_ARCHITECTURE_FEASIBILITY_GATE.md)
- [Phil V1 Step 6C-1 Synthetic Implementation Report](./reference/PHIL_V1_STEP6C_IMPLEMENTATION_REPORT.md)
- [Phil V1 Step 6C-1 Rejected A158688 Independent Review](./reference/PHIL_V1_STEP6C_INDEPENDENT_REVIEW_A158688.md)
- [Phil V1 Step 6C-1 Rejected AEA7359 Independent Review](./reference/PHIL_V1_STEP6C_INDEPENDENT_REVIEW_AEA7359.md)
- [Phil V1 Step 6C-1 Rejected 591F6B6 Independent Review](./reference/PHIL_V1_STEP6C_INDEPENDENT_REVIEW_591F6B6.md)
- [Phil V1 Step 6C-1 Rejected 5AB4650 Independent Review](./reference/PHIL_V1_STEP6C_INDEPENDENT_REVIEW_5AB4650.md)
- [Phil V1 Step 6C-1 Accepted 22B5CF3 Independent Review](./reference/PHIL_V1_STEP6C_INDEPENDENT_REVIEW_22B5CF3.md)
- [Phil V1 Step 6C-2 Product Wiring Implementation Report](./reference/PHIL_V1_STEP6C2_PRODUCT_WIRING_IMPLEMENTATION_REPORT.md)
- [Phil V1 Step 6C-3 Physical Failure And Corrective Report](./reference/PHIL_V1_STEP6C3_PHYSICAL_FAILURE_AND_CORRECTIVE_REPORT.md)
- [Phil V1 Step 6C-3 Rejected 6670B93 Corrective Review](./reference/PHIL_V1_STEP6C3_CORRECTIVE_REVIEW_6670B93.md)
- [Phil V1 Step 6C-3 Rejected CAF077E Successor Review](./reference/PHIL_V1_STEP6C3_SUCCESSOR_REVIEW_CAF077E.md)
- [Phil V1 Step 6C-3 Accepted C32D8F8 Corrective Review](./reference/PHIL_V1_STEP6C3_CORRECTIVE_ACCEPTANCE_C32D8F8.md)
- [Phil V1 Step 6C-3 Physical Success Evidence](./reference/PHIL_V1_STEP6C3_PHYSICAL_SUCCESS_EVIDENCE.md)
- [Phil V1 Step 6C-3 Accepted Complete Physical Evidence](./reference/PHIL_V1_STEP6C3_PHYSICAL_SUCCESS_ACCEPTANCE_0461AC7.md)
- [Phil V1 Cross-Device Visual Integration Candidate](./reference/PHIL_V1_DESKTOP_VISUAL_INTEGRATION_CANDIDATE.md)
- [Phil Local Alpha Cross-Device Release Candidate 2A2D1AB](./reference/PHIL_LOCAL_ALPHA_CROSS_DEVICE_RELEASE_CANDIDATE_2A2D1AB.md)
- [Phil Local Alpha Cross-Device Corrective Candidate 80E5379](./reference/PHIL_LOCAL_ALPHA_CROSS_DEVICE_CORRECTIVE_CANDIDATE_80E5379.md)
- [Phil V1 Step 6C-2 Artifact Manifest](./reference/PHIL_V1_STEP6C2_ARTIFACT_MANIFEST.json)
- [Phil V1 Step 6C-2 Rejected 021E703 Independent Review](./reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_021E703.md)
- [Phil V1 Step 6C-2 Rejected C40FA2C Independent Review](./reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_C40FA2C.md)
- [Phil V1 Step 6C-2 Rejected 75785F3 Independent Review](./reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_75785F3.md)
- [Phil V1 Step 6C-2 Rejected 965F9ED Independent Review](./reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_965F9ED.md)
- [Phil V1 Step 6C-2 Rejected 09E5A9E Independent Review](./reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_09E5A9E.md)
- [ACP-0003: Phil V1 Secure Identity Architecture And Ordered Roadmap](./architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md)
- [Phil V1 Step 2 Device And Recovery Implementation Report](./reference/PHIL_V1_STEP2_DEVICE_RECOVERY_IMPLEMENTATION_REPORT.md)
- [Phil V1 Step 2 Device And Recovery Threat Model](./security/PHIL_V1_STEP2_DEVICE_RECOVERY_THREAT_MODEL.md)
- [Phil V1 Step 2 Disposable Physical-iPhone Ceremony Plan](./security/PHIL_V1_STEP2_PHYSICAL_IPHONE_CEREMONY_PLAN.md)
- [Phil V1 Step 2 Physical-iPhone Evidence](./reference/PHIL_V1_STEP2_PHYSICAL_IPHONE_EVIDENCE.md)
- [Phil V1 Step 2 Finalization Gate](./reference/PHIL_V1_STEP2_FINALIZATION_GATE.md)
- [Phil V1 Step 2 Independent Review Packet](./reference/PHIL_V1_STEP2_INDEPENDENT_REVIEW_PACKET.md)
- [Phil V1 Step 2 Independent Review of ac49f01](./reference/PHIL_V1_STEP2_INDEPENDENT_REVIEW_AC49F01.md)
- [Phil V1 Step 2 Independent Review of 786ab61](./reference/PHIL_V1_STEP2_INDEPENDENT_REVIEW_786AB61.md)
- [Phil V1 Step 2 Independent Acceptance of fe583b6](./reference/PHIL_V1_STEP2_INDEPENDENT_REVIEW_FE583B6.md)
- [Phil V1 Step 3 Starknet Reference Adapter Gate](./reference/PHIL_V1_STEP3_STARKNET_REFERENCE_ADAPTER_GATE.md)
- [Phil V1 Step 3 Root-Proof Threat Model](./security/PHIL_V1_STEP3_ROOT_PROOF_THREAT_MODEL.md)
- [Phil V1 Step 3 Implementation Report](./reference/PHIL_V1_STEP3_IMPLEMENTATION_REPORT.md)
- [Phil V1 Step 3 Artifact Manifest](./reference/PHIL_V1_STEP3_ARTIFACT_MANIFEST.json)
- [Phil V1 Step 3 Independent Review Packet for 11234ea](./reference/PHIL_V1_STEP3_INDEPENDENT_REVIEW_PACKET_11234EA.md)
- [Phil V1 Step 3 Independent Acceptance of 11234ea](./reference/PHIL_V1_STEP3_INDEPENDENT_REVIEW_11234EA.md)
- [Phil V1 Step 4 Composed Account Authorization Gate](./reference/PHIL_V1_STEP4_COMPOSED_ACCOUNT_AUTHORIZATION_GATE.md)
- [Phil V1 Step 4 Composed Account Threat Model](./security/PHIL_V1_STEP4_COMPOSED_ACCOUNT_THREAT_MODEL.md)
- [Phil V1 Step 4 Composed Account Implementation Evidence](./security/PHIL_V1_STEP4_COMPOSED_ACCOUNT_IMPLEMENTATION_EVIDENCE.md)
- [Phil V1 Step 4 Independent Rejection of 895320f](./reference/PHIL_V1_STEP4_INDEPENDENT_REVIEW_895320F.md)
- [Phil V1 Step 4 Corrective Implementation Report](./security/PHIL_V1_STEP4_CORRECTIVE_IMPLEMENTATION_REPORT.md)
- [Phil V1 Step 4 Independent Rejection of eaaae44](./reference/PHIL_V1_STEP4_INDEPENDENT_REVIEW_EAAAE44.md)
- [Phil V1 Step 4 Second Corrective Implementation Report](./security/PHIL_V1_STEP4_SECOND_CORRECTIVE_IMPLEMENTATION_REPORT.md)
- [Phil V1 Step 4 Independent Acceptance of 3377606](./reference/PHIL_V1_STEP4_INDEPENDENT_REVIEW_3377606.md)
- [Phil V1 Step 4 Reference Manifest Maintenance](./reference/PHIL_V1_STEP4_REFERENCE_MANIFEST_MAINTENANCE.md)
- [Phil V1 Step 5 Post-Quantum Migration Gate](./reference/PHIL_V1_STEP5_POST_QUANTUM_MIGRATION_GATE.md)
- [Phil V1 Step 5 Threat Model](./security/PHIL_V1_STEP5_POST_QUANTUM_MIGRATION_THREAT_MODEL.md)
- [Phil V1 Step 5 Implementation Report](./reference/PHIL_V1_STEP5_IMPLEMENTATION_REPORT.md)
- [Phil V1 Step 5 Artifact Manifest](./reference/PHIL_V1_STEP5_ARTIFACT_MANIFEST.json)
- [Phil V1 Step 5 Independent Rejection of fc65143](./reference/PHIL_V1_STEP5_INDEPENDENT_REVIEW_FC65143.md)
- [Phil V1 Step 5 Bounded Corrective Implementation Report](./security/PHIL_V1_STEP5_CORRECTIVE_IMPLEMENTATION_REPORT.md)
- [Phil V1 Step 5 Corrective Independent Rejection of fb5fb7b](./reference/PHIL_V1_STEP5_CORRECTIVE_INDEPENDENT_REVIEW_FB5FB7B.md)
- [Phil V1 Step 5 Second Bounded Corrective Implementation Report](./security/PHIL_V1_STEP5_SECOND_CORRECTIVE_IMPLEMENTATION_REPORT.md)
- [Phil V1 Step 5 Independent Acceptance of d1de608](./reference/PHIL_V1_STEP5_SECOND_CORRECTIVE_INDEPENDENT_REVIEW_D1DE608.md)
- [Phil V1 Step 6A Base Network Adapter Gate](./reference/PHIL_V1_STEP6A_BASE_NETWORK_ADAPTER_GATE.md)
- [Phil V1 Step 6A Threat Model](./security/PHIL_V1_STEP6A_BASE_NETWORK_ADAPTER_THREAT_MODEL.md)
- [Phil V1 Step 6A Implementation Report](./reference/PHIL_V1_STEP6A_IMPLEMENTATION_REPORT.md)
- [Phil V1 Step 6A Artifact Manifest](./reference/PHIL_V1_STEP6A_ARTIFACT_MANIFEST.json)
- [Phil V1 Step 6A Independent Review Packet for 33570bb](./reference/PHIL_V1_STEP6A_INDEPENDENT_REVIEW_PACKET_33570BB.md)
- [Phil V1 Step 6A Independent Rejection of 33570bb](./reference/PHIL_V1_STEP6A_INDEPENDENT_REVIEW_33570BB.md)
- [Phil V1 Step 6A Bounded Corrective Implementation Report](./security/PHIL_V1_STEP6A_CORRECTIVE_IMPLEMENTATION_REPORT.md)
- [Phil V1 Step 6A Corrective Independent Review Packet for 6719368](./reference/PHIL_V1_STEP6A_CORRECTIVE_INDEPENDENT_REVIEW_PACKET_6719368.md)
- [Phil V1 Step 6A Corrective Independent Acceptance of 6719368](./reference/PHIL_V1_STEP6A_CORRECTIVE_INDEPENDENT_REVIEW_6719368.md)
- [Phil V1 Step 6B Local Smart-Account Enforcement Gate](./reference/PHIL_V1_STEP6B_LOCAL_SMART_ACCOUNT_GATE.md)
- [Phil V1 Step 6B Local Smart-Account Threat Model](./security/PHIL_V1_STEP6B_LOCAL_SMART_ACCOUNT_THREAT_MODEL.md)
- [Phil V1 Step 6B Artifact Manifest](./reference/PHIL_V1_STEP6B_ARTIFACT_MANIFEST.json)
- [Phil V1 Step 6B Independent Rejection of 8b72646](./reference/PHIL_V1_STEP6B_INDEPENDENT_REVIEW_8B72646.md)
- [Phil V1 Step 6B Bounded Corrective Implementation](./security/PHIL_V1_STEP6B_CORRECTIVE_IMPLEMENTATION_REPORT.md)
- [Phil V1 Step 6B Corrective Independent Rejection of 58731cf](./reference/PHIL_V1_STEP6B_CORRECTIVE_INDEPENDENT_REVIEW_58731CF.md)
- [Phil V1 Step 6B Second Bounded Corrective Implementation](./security/PHIL_V1_STEP6B_SECOND_CORRECTIVE_IMPLEMENTATION_REPORT.md)
- [Phil V1 Step 6B Independent Acceptance of d65aa5d](./reference/PHIL_V1_STEP6B_SECOND_CORRECTIVE_INDEPENDENT_REVIEW_D65AA5D.md)
- [Phil V1 Step 6C Routine Authorization Product Composition Gate](./reference/PHIL_V1_STEP6C_ROUTINE_AUTHORIZATION_PRODUCT_COMPOSITION_GATE.md)
- [Phil V1 Step 6C Exact Implementation Packet](./reference/PHIL_V1_STEP6C_IMPLEMENTATION_PACKET.md)
- [Phil V1 Step 6C Routine Authorization Threat Model](./security/PHIL_V1_STEP6C_ROUTINE_AUTHORIZATION_THREAT_MODEL.md)
- [Phil V1 Step 6C Independent Rejection of fdf3c2e](./reference/PHIL_V1_STEP6C_DEFINITION_INDEPENDENT_REVIEW_FDF3C2E.md)
- [Phil V1 Step 6C Corrective Rejection of a24873e](./reference/PHIL_V1_STEP6C_CORRECTIVE_DEFINITION_INDEPENDENT_REVIEW_A24873E.md)
- [Phil V1 Step 6C Second Corrective Definition Acceptance of 227bd48](./reference/PHIL_V1_STEP6C_SECOND_CORRECTIVE_DEFINITION_INDEPENDENT_REVIEW_227BD48.md)
- [Phil V1 Step 6C-1 Nonce/Catalog Implementation Blocker](./reference/PHIL_V1_STEP6C_IMPLEMENTATION_BLOCKER_NONCE_CATALOG.md)
- [Phil V1 Step 6C Third Corrective Definition](./reference/PHIL_V1_STEP6C_THIRD_CORRECTIVE_DEFINITION.md)
- [Phil V1 Step 6C Third-Corrective Status-Correction Acceptance](./reference/PHIL_V1_STEP6C_THIRD_CORRECTIVE_DEFINITION_STATUS_CORRECTION_INDEPENDENT_REVIEW_FCC0103.md)

### Current V2 account hierarchy

`PhilCoreV2MinimalAccountV2` is the current narrow smart-account/security
model. Its implementation report and current security rules are authoritative
for the shipped V2 account; earlier V2 design documents remain supporting
history where the current sources mark a supersession. V1 and N-series account
documents describe separate legacy/compatibility or historical contract
scopes and are not competing definitions of current V2 authority.

Read these V2 documents in this order:

1. [O.37.10 V2 Minimal Account Implementation Report](./reference/O37_10_V2_MINIMAL_ACCOUNT_IMPLEMENTATION_REPORT.md)
2. [O.36.1 Recovery And Cancellation Semantics](./reference/O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md)
3. [O.37.1 V2 Recovery Lifecycle Update](./reference/O37_1_RECOVERY_LIFECYCLE_UPDATE.md)
4. [O.30 V2 Formal Threat Model](./security/O30_V2_FORMAL_THREAT_MODEL.md)

V2 intentionally forbids generic execution and unsafe extensibility. Recovery
uses fixed roles and exact 2-of-3 authority; the execution validator is not a
recovery factor and cannot veto a valid validator-recovery quorum. Independent
custody of the three roles is an operational assumption that protocol
cryptography cannot establish by itself.

## 2. Technical Reference Documents

These documents remain active references for locked identity, proof, and device-identity behavior.

Application references:

- [PhilCore Desktop Alpha Foundation](./application/PHILCORE_DESKTOP_ALPHA_FOUNDATION.md)
- [PhilCore Desktop Alpha Product Journey](./application/PHILCORE_DESKTOP_ALPHA_PRODUCT_JOURNEY.md)
- [PhilCore Desktop Local Identity And Device Vault](./application/PHILCORE_DESKTOP_LOCAL_IDENTITY_AND_VAULT.md)
- [PhilCore Desktop Platform Authentication](./application/PHILCORE_DESKTOP_PLATFORM_AUTHENTICATION.md)
- [PhilCore Desktop Approval And Presentation](./application/PHILCORE_DESKTOP_APPROVAL_AND_PRESENTATION.md)
- [PhilCore Desktop Real Local Authorization](./application/PHILCORE_DESKTOP_REAL_LOCAL_AUTHORIZATION.md)
- [PhilCore Desktop Proof And Execution UI](./application/PHILCORE_DESKTOP_PROOF_AND_EXECUTION_UI.md)
- [PhilCore Desktop Packaging](./application/PHILCORE_DESKTOP_PACKAGING.md)
- [PhilCore Desktop Local Alpha Release](./application/PHILCORE_DESKTOP_LOCAL_ALPHA_RELEASE.md)
- [PhilCore Desktop Security Boundary](./application/PHILCORE_DESKTOP_SECURITY_BOUNDARY.md)
- [PhilCore Local Authorization Demo](./application/PHILCORE_LOCAL_AUTHORIZATION_DEMO.md)
- [PhilCore Desktop Testing](./application/PHILCORE_DESKTOP_TESTING.md)
- [PhilCore Desktop Release-Candidate Hardening](./application/PHILCORE_DESKTOP_RELEASE_CANDIDATE_HARDENING.md)
- [PhilCore Desktop O.8 Signing Remediation](./application/PHILCORE_DESKTOP_O8_SIGNING_REMEDIATION.md)
- [PhilCore Desktop Trusted-Tester Policy](./application/PHILCORE_DESKTOP_TRUSTED_TESTER_POLICY.md)
- [PhilCore Desktop Alpha QA Checklist](./application/PHILCORE_DESKTOP_ALPHA_QA_CHECKLIST.md)
- [PhilCore Desktop User-First Shell](./application/PHILCORE_DESKTOP_USER_FIRST_SHELL.md)

- [Phil Identity Model](./reference/PHIL_IDENTITY_MODEL.md)
- [Phil Device Identity v1](./reference/PHIL_DEVICE_IDENTITY_V1.md)
- [Proof Input Schema](./reference/PROOF_INPUT_SCHEMA.md)
- [ACTION_UNLOCK Proof Spec](./reference/ACTION_UNLOCK_PROOF_SPEC.md)
- [Current STARK Role And Bindings](./reference/STARK_ROLE_AND_BINDINGS.md)
- [Witness-Hiding Proving-Stack Requirements](./reference/WITNESS_HIDING_PROVING_STACK_REQUIREMENTS.md)
- [Ethereum Sepolia Network Profile](./reference/ETHEREUM_SEPOLIA_NETWORK_PROFILE.md)
- [Ethereum Sepolia Account Model](./reference/ETHEREUM_SEPOLIA_ACCOUNT_MODEL.md)
- [Ethereum Sepolia Contract Audit](./reference/ETHEREUM_SEPOLIA_CONTRACT_AUDIT.md)
- [UserOperation Authorization Bindings](./reference/USEROP_AUTHORIZATION_BINDINGS.md)
- [Authorization Composition Review](./reference/AUTHORIZATION_COMPOSITION_REVIEW.md)
- [Ethereum Sepolia Bundler Requirements](./reference/ETHEREUM_SEPOLIA_BUNDLER_REQUIREMENTS.md)
- [Ethereum Sepolia Funding And Custody](./reference/ETHEREUM_SEPOLIA_FUNDING_AND_CUSTODY.md)
- [Ethereum Sepolia Public Submission Approval](./reference/ETHEREUM_SEPOLIA_PUBLIC_SUBMISSION_APPROVAL.md)
- [Ethereum Sepolia First UserOperation](./reference/ETHEREUM_SEPOLIA_FIRST_USEROP.md)
- [Sepolia Fact-Enforcement Decision](./reference/SEPOLIA_FACT_ENFORCEMENT_DECISION.md)
- [Local-Proof-Gated Account Model](./reference/LOCAL_PROOF_GATED_ACCOUNT_MODEL.md)
- [Local-Proof-Gated Signature Format](./reference/LOCAL_PROOF_GATED_SIGNATURE_FORMAT.md)
- [Local-Proof-Gated First UserOperation](./reference/LOCAL_PROOF_GATED_FIRST_USEROP.md)
- [Local-Proof-Gated Sepolia Preflight](./reference/LOCAL_PROOF_GATED_SEPOLIA_PREFLIGHT.md)
- [Local-Proof-Gated Architecture Approval Checklist](./reference/LOCAL_PROOF_GATED_ARCHITECTURE_APPROVAL_CHECKLIST.md)
- [Local-Proof-Gated Scoped Architecture Approval](./reference/LOCAL_PROOF_GATED_SCOPED_ARCHITECTURE_APPROVAL.md)
- [Ethereum Sepolia Read-Only Preflight](./reference/ETHEREUM_SEPOLIA_READ_ONLY_PREFLIGHT.md)
- [Local-Proof-Gated Deployment Plan](./reference/LOCAL_PROOF_GATED_DEPLOYMENT_PLAN.md)
- [Local-Proof-Gated Funding Plan](./reference/LOCAL_PROOF_GATED_FUNDING_PLAN.md)
- [Local-Proof-Gated Mutation Commands](./reference/LOCAL_PROOF_GATED_MUTATION_COMMANDS.md)
- [Local-Proof-Gated Human Approval Checklist](./reference/LOCAL_PROOF_GATED_HUMAN_APPROVAL_CHECKLIST.md)
- [Local-Proof-Gated Preparation Evidence](./reference/LOCAL_PROOF_GATED_PREPARATION_EVIDENCE.md)
- [O.21.1 Runtime Connected Local Proof Preparation](./reference/RUNTIME_CONNECTED_LOCAL_PROOF_PREPARATION.md)
- [O.21.2 Device Vault Bound Ethereum Sepolia Signing](./reference/DEVICE_VAULT_SIGNING_BOUNDARY_REVIEW.md)
- [O.21.3 Final Ethereum Submission Boundary Review](./reference/O21_3_FINAL_ETHEREUM_SUBMISSION_BOUNDARY_REVIEW.md)
- [O.22 Current-Source Deployment And Funding Review](./reference/O22_CURRENT_SOURCE_DEPLOYMENT_AND_FUNDING_REVIEW.md)
- [O.25 Counterfactual Account Prefund And Bundler Readiness](./reference/O25_COUNTERFACTUAL_ACCOUNT_PREFUND_AND_BUNDLER_READINESS.md)
- [O.26 Bundler And Exact Prefund Readiness](./reference/O26_BUNDLER_AND_EXACT_PREFUND_READINESS.md)
- [O.26.1 Live Alchemy Bundler Estimation Review](./reference/O26_1_LIVE_BUNDLER_ESTIMATION_REVIEW.md)
- [O.27 Account 2 Direct Prefunding](./reference/O27_ACCOUNT2_DIRECT_PREFUNDING.md)
- [O.28 Recovery-Aware Live-Operation Readiness](./reference/O28_RECOVERY_AWARE_LIVE_OPERATION_READINESS.md)
- [O.29 Recovery-Capable Account V2 Architecture Design](./reference/O29_RECOVERY_CAPABLE_ACCOUNT_V2_ARCHITECTURE.md)
- [O.29 V2 Account Capability Matrix](./reference/O29_V2_ACCOUNT_CAPABILITY_MATRIX.md)
- [O.30 V2 Account Specification And Threat Model Refinement](./reference/O30_V2_ACCOUNT_SPECIFICATION_AND_THREAT_MODEL_REFINEMENT.md)
- [O.30 V2 Account Interface Specification](./reference/O30_V2_ACCOUNT_INTERFACE_SPECIFICATION.md)
- [O.30 V2 Capability Matrix](./reference/O30_V2_CAPABILITY_MATRIX.md)
- [O.31 V2 Account Implementation Architecture And Module Design](./reference/O31_V2_IMPLEMENTATION_ARCHITECTURE_AND_MODULE_DESIGN.md)
- [O.31 V2 Three-Domain Recovery Architecture](./reference/O31_V2_RECOVERY_ARCHITECTURE.md)
- [O.31 V2 Conceptual Interface Specification](./reference/O31_V2_INTERFACE_SPECIFICATION.md)
- [O.31 V2 Implementation Roadmap](./reference/O31_V2_IMPLEMENTATION_ROADMAP.md)
- [O.32 V2 Cryptographic Foundation And Intent Verification](./reference/O32_V2_CRYPTOGRAPHIC_FOUNDATION_AND_INTENT_VERIFICATION.md)
- [O.32 V2 Cryptographic Security Analysis](./security/O32_V2_CRYPTOGRAPHIC_SECURITY_ANALYSIS.md)
- [O.33 V2 Validator And Authorization Engine Architecture](./reference/O33_V2_VALIDATOR_AND_AUTHORIZATION_ENGINE_ARCHITECTURE.md)
- [O.33 V2 Authorization Failure Model](./security/O33_V2_AUTHORIZATION_FAILURE_MODEL.md)
- [O.34 V2 Account Core Architecture](./reference/O34_V2_ACCOUNT_CORE_ARCHITECTURE.md)
- [O.34 V2 Account Core Security Invariants](./security/O34_V2_ACCOUNT_CORE_SECURITY_INVARIANTS.md)
- [O.35 V2 Factory Architecture](./reference/O35_V2_FACTORY_ARCHITECTURE.md)
- [O.35 V2 Account Lifecycle](./reference/O35_V2_ACCOUNT_LIFECYCLE.md)
- [O.35 V2 Migration Design](./reference/O35_V2_MIGRATION_DESIGN.md)
- [O.35 V2 Factory And Lifecycle Security Analysis](./security/O35_V2_FACTORY_LIFECYCLE_SECURITY_ANALYSIS.md)
- [O.35 V2 Factory And Lifecycle Test Plan](./reference/O35_V2_FACTORY_LIFECYCLE_TEST_PLAN.md)
- [O.36 V2 Solidity Implementation Gate Review](./reference/O36_V2_SOLIDITY_IMPLEMENTATION_GATE_REVIEW.md)
- [O.36.1 Hardware Recovery Interface Specification](./reference/O36_1_HARDWARE_RECOVERY_SPECIFICATION.md)
- [O.36.1 Production Validator Interface Specification](./reference/O36_1_VALIDATOR_INTERFACE_SPECIFICATION.md)
- [O.36.1 Identity-Binding Commitment Specification](./reference/O36_1_IDENTITY_COMMITMENT_SPECIFICATION.md)
- [O.36.1 Recovery And Cancellation Semantics](./reference/O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md) — current V2 authority source (exact 2-of-3; actions 8–11)
- [PhilCore Recovery Authority Decision Record](./security/PHILCORE_RECOVERY_AUTHORITY_DECISION_RECORD.md) — current V2 authority decision record (July 31, 2026)
- [O.36.1 Solidity Implementation Freeze](./reference/O36_1_SOLIDITY_IMPLEMENTATION_FREEZE.md)
- [O.36.1 V2 Security Gate Resolution](./security/O36_1_SECURITY_GATE_RESOLUTION.md)
- [O.37 V2 Solidity Implementation Conflict Review](./reference/O37_V2_SOLIDITY_IMPLEMENTATION_CONFLICT_REVIEW.md)
- [O.37.1 V2 Cryptographic Descriptor Specification](./reference/O37_1_CRYPTOGRAPHIC_DESCRIPTOR_SPECIFICATION.md)
- [O.37.1 V2 Recovery Evidence Specification](./reference/O37_1_RECOVERY_EVIDENCE_SPECIFICATION.md)
- [O.37.1 V2 Recovery Lifecycle Update](./reference/O37_1_RECOVERY_LIFECYCLE_UPDATE.md) — current V2 authority source (exact 2-of-3; actions 8–11)
- [O.37.1 V2 Implementation Readiness Review](./reference/O37_1_IMPLEMENTATION_READINESS_REVIEW.md)
- [O.37.2 V2 Deterministic Fixture Specification](./reference/O37_2_DETERMINISTIC_FIXTURE_SPECIFICATION.md)
- [O.37.2 V2 Cryptographic Fixture Package](./reference/O37_2_CRYPTOGRAPHIC_FIXTURE_PACKAGE.md)
- [O.37.2 V2 Solidity Test Readiness Review](./reference/O37_2_SOLIDITY_TEST_READINESS_REVIEW.md)
- [O.37.3 V2 Solidity Implementation Conflict Review](./reference/O37_3_SOLIDITY_IMPLEMENTATION_CONFLICT_REVIEW.md)
- [O.37.4 V2 Authority Transport Specification](./reference/O37_4_AUTHORITY_TRANSPORT_SPECIFICATION.md)
- [O.37.4 ERC-4337 Integration Specification](./reference/O37_4_ERC4337_INTEGRATION_SPECIFICATION.md)
- [O.37.4 Recovery Configuration Rotation Specification](./reference/O37_4_RECOVERY_ROTATION_SPECIFICATION.md)
- [O.37.4 V2 ABI And Security Interface Freeze](./reference/O37_4_ABI_FREEZE.md)
- [O.37.4 Authority Transport Threat Analysis](./security/O37_4_AUTHORITY_TRANSPORT_THREAT_ANALYSIS.md)
- [O.37.5 V2 Solidity Implementation Conflict Review](./reference/O37_5_SOLIDITY_IMPLEMENTATION_CONFLICT_REVIEW.md)
- [O.37.6 V2 Code Size Architecture Review](./reference/O37_6_CODE_SIZE_ARCHITECTURE_REVIEW.md)
- [O.37.6 V2 Minimal Account Architecture](./reference/O37_6_MINIMAL_ACCOUNT_ARCHITECTURE.md)
- [O.37.6 V2 Factory Size Strategy](./reference/O37_6_FACTORY_SIZE_STRATEGY.md)
- [O.37.6 V2 Code Size Security Impact Review](./security/O37_6_CODE_SIZE_SECURITY_IMPACT_REVIEW.md)
- [O.37.6 V2 Minimal Solidity Implementation Roadmap](./reference/O37_6_IMPLEMENTATION_ROADMAP.md)
- [O.37.7 V2 Static Verifier Size Report](./reference/O37_7_STATIC_VERIFIER_SIZE_REPORT.md)
- [O.37.7 V2 Static Verifier ABI Report](./reference/O37_7_STATIC_VERIFIER_ABI_REPORT.md)
- [O.37.7 V2 Static Verifier Security Boundary](./security/O37_7_STATIC_VERIFIER_SECURITY_BOUNDARY.md)
- [O.37.8 V2 Minimal Account Core Implementation Conflict Review](./reference/O37_8_MINIMAL_ACCOUNT_IMPLEMENTATION_CONFLICT_REVIEW.md)
- [O.37.9 V2 Minimal Account Compression Review](./reference/O37_9_MINIMAL_ACCOUNT_COMPRESSION_REVIEW.md)
- [O.37.9 Verifier Binding Resolution](./reference/O37_9_VERIFIER_BINDING_RESOLUTION.md)
- [O.37.9 Compressed Account Storage Boundary](./reference/O37_9_STORAGE_BOUNDARY.md)
- [O.37.9 Compressed Account ABI Reduction Plan](./reference/O37_9_ABI_REDUCTION_PLAN.md)
- [O.37.10 V2 Minimal Account Implementation Report](./reference/O37_10_V2_MINIMAL_ACCOUNT_IMPLEMENTATION_REPORT.md)
- [O.37.10 Account ABI Report](./reference/O37_10_ACCOUNT_ABI_REPORT.md)
- [O.37.10 Account Storage Layout Report](./reference/O37_10_ACCOUNT_STORAGE_LAYOUT_REPORT.md)
- [O.37.10 Account and Factory Size Report](./reference/O37_10_ACCOUNT_FACTORY_SIZE_REPORT.md)
- [O.37.10 Factory and CREATE2 Report](./reference/O37_10_FACTORY_CREATE2_REPORT.md)
- [O.37.10 Local Lifecycle Report](./reference/O37_10_LOCAL_LIFECYCLE_REPORT.md)
- [O.37.10 Security Boundary Report](./reference/O37_10_SECURITY_BOUNDARY_REPORT.md)
- [O.37.10 Deployment Readiness Review](./reference/O37_10_DEPLOYMENT_READINESS_REVIEW.md)
- [O.38 Clean-Build Reproducibility Report](./reference/O38_CLEAN_BUILD_REPRODUCIBILITY_REPORT.md)
- [O.38 Dependency Integrity Report](./reference/O38_DEPENDENCY_INTEGRITY_REPORT.md)
- [O.38 Security And Fuzzing Report](./reference/O38_SECURITY_AND_FUZZING_REPORT.md)
- [O.38 Sepolia Infrastructure Plan](./reference/O38_SEPOLIA_INFRASTRUCTURE_PLAN.md)
- [O.38 Production Initialization Worksheet](./reference/O38_PRODUCTION_INITIALIZATION_WORKSHEET.md)
- [O.38 Recovery Enrollment Readiness](./reference/O38_RECOVERY_ENROLLMENT_READINESS.md)
- [O.38 Token And Residual-Asset Policy](./reference/O38_TOKEN_AND_RESIDUAL_POLICY.md)
- [O.38 Deployment Cost Analysis](./reference/O38_DEPLOYMENT_COST_ANALYSIS.md)
- [O.38 Guarded Deployment Tooling](./reference/O38_GUARDED_DEPLOYMENT_TOOLING.md)
- [O.38 Post-Deployment Verification Plan](./reference/O38_POST_DEPLOYMENT_VERIFICATION_PLAN.md)
- [O.38 Deployment Readiness Review](./reference/O38_DEPLOYMENT_READINESS_REVIEW.md)
- [O.39 Consumer Recovery Architecture](./security/O39_CONSUMER_RECOVERY_ARCHITECTURE.md)
- [O.39 Recovery Enrollment and Offline Guide](./reference/O39_RECOVERY_ENROLLMENT_AND_OFFLINE_GUIDE.md)
- [O.39 Solidity, Test, and Readiness Evidence](./reference/O39_SOLIDITY_TEST_AND_READINESS_EVIDENCE.md)
- [O.40 Recovery Enrollment Preflight and Readiness](./reference/O40_RECOVERY_ENROLLMENT_PREFLIGHT_AND_READINESS.md)
- [O.41 Consumer Recovery Enrollment Environment and Secure Ceremony UI](./reference/O41_RECOVERY_ENROLLMENT_ENVIRONMENT.md)
- [O.41 Recovery Enrollment Security Boundary](./security/O41_RECOVERY_ENROLLMENT_SECURITY_BOUNDARY.md)
- [O.41 Development Dependency Advisory Disposition](./security/O41_DEPENDENCY_ADVISORY_DISPOSITION.md)
- [Ethereum Fact-Transport Roadmap](./reference/ETHEREUM_FACT_TRANSPORT_ROADMAP.md)
- [Local-Proof-Gated Account Threat Model](./security/LOCAL_PROOF_GATED_ACCOUNT_THREAT_MODEL.md)
- [O.29 Recovery-Capable Account V2 Threat Model](./security/O29_RECOVERY_CAPABLE_ACCOUNT_V2_THREAT_MODEL.md)
- [O.30 V2 Formal Threat Model](./security/O30_V2_FORMAL_THREAT_MODEL.md)
- [Ethereum Sepolia Execution Runbook](./reference/ETHEREUM_SEPOLIA_EXECUTION_RUNBOOK.md)
- [Ethereum Sepolia Threat Model](./security/ETHEREUM_SEPOLIA_THREAT_MODEL.md)
- [Ethereum Sepolia External Audit Scope](./security/ETHEREUM_SEPOLIA_EXTERNAL_AUDIT_SCOPE.md)
- [Sepolia Account Readiness](./reference/SEPOLIA_ACCOUNT_READINESS.md)
- [Onchain STARK Verification Assessment](./reference/ONCHAIN_STARK_VERIFICATION_ASSESSMENT.md)
- [Post-Quantum Migration Readiness](./reference/PQ_MIGRATION_READINESS.md)
- [Guarded Base Sepolia Execution Plan (historical Base-specific plan)](./reference/SEPOLIA_EXECUTION_PLAN.md)
- [Hash Spec](./reference/HASH_SPEC.md)
- [World ID Onboarding Model](./reference/WORLD_ID_ONBOARDING_MODEL.md)
- [Phil Human Uniqueness and World ID Boundary](./reference/PHIL_HUMAN_UNIQUENESS_AND_WORLD_ID_BOUNDARY.md)
- [Trust Manager Evaluation Drafts](./reference/TRUST_MANAGER_EVALUATION_DRAFTS.md)
- [Trust Manager Public Metadata Evaluation](./reference/TRUST_MANAGER_PUBLIC_METADATA_EVALUATION.md)
- [Trust Manager Possession Verification Drafts](./reference/TRUST_MANAGER_POSSESSION_VERIFICATION_DRAFTS.md)
- [Trust Manager WebAuthn Fixture Verification](./reference/TRUST_MANAGER_WEBAUTHN_FIXTURE_VERIFICATION.md)
- [Trust Manager Possession Evaluation Results](./reference/TRUST_MANAGER_POSSESSION_EVALUATION_RESULTS.md)
- [Trust Manager Bounded Evaluation Results](./reference/TRUST_MANAGER_BOUNDED_EVALUATION_RESULTS.md)
- [Security Policy Engine Bounded Evaluation](./reference/SECURITY_POLICY_ENGINE_BOUNDED_EVALUATION.md)
- [User Approval Request Drafts](./reference/USER_APPROVAL_REQUEST_DRAFTS.md)
- [User Decision Fixture Artifacts](./reference/USER_DECISION_FIXTURE_ARTIFACTS.md)
- [Capability Activation Candidates](./reference/CAPABILITY_ACTIVATION_CANDIDATES.md)
- [PhilCore Alpha 0 Non-Authoritative Demo](./reference/PHILCORE_ALPHA0_NON_AUTHORITATIVE_DEMO.md)
- [User Session Lifecycle State Model](./reference/USER_SESSION_LIFECYCLE_STATE_MODEL.md)
- [Production Authentication Evidence Boundary](./reference/PRODUCTION_AUTHENTICATION_EVIDENCE_BOUNDARY.md)
- [Production Authentication Verification Boundary](./reference/PRODUCTION_AUTHENTICATION_VERIFICATION_BOUNDARY.md)
- [Production-Verified Partial Session Unlock](./reference/PRODUCTION_VERIFIED_PARTIAL_SESSION_UNLOCK.md)
- [Controlled Device Vault Unlock Boundary](./reference/CONTROLLED_DEVICE_VAULT_UNLOCK_BOUNDARY.md)
- [Protected State View Boundary](./reference/PROTECTED_STATE_VIEW_BOUNDARY.md)
- [Public Credential Directory Boundary](./reference/PUBLIC_CREDENTIAL_DIRECTORY_BOUNDARY.md)
- [Selected Credential Public Material Boundary](./reference/SELECTED_CREDENTIAL_PUBLIC_MATERIAL_BOUNDARY.md)
- [Trust Manager Verification Input Boundary](./reference/TRUST_MANAGER_VERIFICATION_INPUT_BOUNDARY.md)
- [Trust Manager Production Verification Boundary](./reference/TRUST_MANAGER_PRODUCTION_VERIFICATION_BOUNDARY.md)
- [Bounded Trust Decision Candidates](./reference/BOUNDED_TRUST_DECISION_CANDIDATES.md)
- [Credential Counter Persistence Boundary](./reference/CREDENTIAL_COUNTER_PERSISTENCE_BOUNDARY.md)
- [Authoritative Trust Decision Boundary](./reference/AUTHORITATIVE_TRUST_DECISION_BOUNDARY.md)
- [Authoritative Security Policy Decision Boundary](./reference/AUTHORITATIVE_SECURITY_POLICY_DECISION_BOUNDARY.md)
- [Platform User Approval Decision Boundary](./reference/PLATFORM_USER_APPROVAL_DECISION_BOUNDARY.md)
- [Authoritative Scoped Capability Grant Boundary](./reference/AUTHORITATIVE_CAPABILITY_GRANT_BOUNDARY.md)
- [Authorization Decision Candidate Boundary](./reference/AUTHORIZATION_DECISION_CANDIDATE_BOUNDARY.md)
- [Authorization Package Draft Boundary](./reference/AUTHORIZATION_PACKAGE_DRAFT_BOUNDARY.md)
- [ACTION_UNLOCK Proof Generation Boundary](./reference/ACTION_UNLOCK_PROOF_GENERATION_BOUNDARY.md)
- [ACTION_UNLOCK Proof Verification And Finalization Boundary](./reference/ACTION_UNLOCK_PROOF_VERIFICATION_AND_FINALIZATION_BOUNDARY.md)
- [Verified Fact Publication And Execution Readiness Boundary](./reference/VERIFIED_FACT_PUBLICATION_AND_EXECUTION_READINESS_BOUNDARY.md)
- [Verified Fact Cross-Domain Route](./reference/VERIFIED_FACT_CROSS_DOMAIN_ROUTE.md)
- [Starknet Verified-Fact Publication Boundary](./reference/STARKNET_VERIFIED_FACT_PUBLICATION_BOUNDARY.md)
- [Starknet Toolchain And Artifact Reproducibility](./reference/STARKNET_TOOLCHAIN_AND_ARTIFACT_REPRODUCIBILITY.md)
- [Starknet Publication Configuration Boundary](./reference/STARKNET_PUBLICATION_CONFIGURATION_BOUNDARY.md)
- [Starknet Fact Publication Transaction Preparation Boundary](./reference/STARKNET_FACT_PUBLICATION_TRANSACTION_PREPARATION_BOUNDARY.md)
- [Starknet Publisher Authorization And Signing Boundary](./reference/STARKNET_PUBLISHER_AUTHORIZATION_AND_SIGNING_BOUNDARY.md)
- [Starknet Fact Publication Submission And Monitoring Boundary](./reference/STARKNET_FACT_PUBLICATION_SUBMISSION_AND_MONITORING_BOUNDARY.md)
- [L1 Message Availability And Fact-Anchor Preparation Boundary](./reference/L1_MESSAGE_AVAILABILITY_AND_FACT_ANCHOR_PREPARATION_BOUNDARY.md)
- [L1 Fact-Anchor Signing, Submission, And Monitoring Boundary](./reference/L1_FACT_ANCHOR_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md)
- [L1-To-Base Fact Relay Preparation Boundary](./reference/L1_TO_BASE_FACT_RELAY_PREPARATION_BOUNDARY.md)
- [L1-To-Base Relay Signing, Submission, And Monitoring Boundary](./reference/L1_TO_BASE_RELAY_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md)
- [Base Authorization Execution Preparation Boundary](./reference/BASE_AUTHORIZATION_EXECUTION_PREPARATION_BOUNDARY.md)
- [Base Authorization Execution Signing, Submission, And Monitoring Boundary](./reference/BASE_AUTHORIZATION_EXECUTION_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md)
- [PhilCore ERC-4337 Smart Account Foundation](./reference/PHILCORE_ERC4337_SMART_ACCOUNT_FOUNDATION.md)
- [PhilCore ERC-4337 UserOperation Preparation Boundary](./reference/PHILCORE_ERC4337_USER_OPERATION_PREPARATION_BOUNDARY.md)
- [PhilCore ERC-4337 UserOperation Signing Boundary](./reference/PHILCORE_ERC4337_USER_OPERATION_SIGNING_BOUNDARY.md)
- [PhilCore ERC-4337 Bundler Submission And Monitoring Boundary](./reference/PHILCORE_ERC4337_BUNDLER_SUBMISSION_AND_MONITORING_BOUNDARY.md)
- [PhilCore ERC-4337 Security Review N.1](./security/PHILCORE_ERC4337_SECURITY_REVIEW_N1.md)
- [PhilCore Solidity Static Analysis N.6](./security/PHILCORE_SOLIDITY_STATIC_ANALYSIS_N6.md)
- [PhilCore N.7 Security Remediation And Audit Readiness](./security/PHILCORE_SECURITY_N7_REMEDIATION_AND_AUDIT_READINESS.md)
- [PhilCore External Audit Scope](./security/PHILCORE_EXTERNAL_AUDIT_SCOPE.md)
- [PhilCore Meaningful Assets Policy](./security/PHILCORE_MEANINGFUL_ASSETS_POLICY.md)
- [PhilCore Test-Fund Release Policy](./security/PHILCORE_TEST_FUND_RELEASE_POLICY.md)
- [PhilCore Base Sepolia Beta Security Gate](./security/PHILCORE_BASE_SEPOLIA_BETA_SECURITY_GATE.md) — N-series `PhilCore4337Account` separate contract scope (not V2 authority)
- [Device Vault ECDSA Custody Requirements](./security/DEVICE_VAULT_ECDSA_CUSTODY_REQUIREMENTS.md)
- [PhilCore Device Vault ECDSA Validator Custody](./security/PHILCORE_DEVICE_VAULT_ECDSA_CUSTODY.md)
- [PhilCore macOS Keychain Protection](./security/PHILCORE_MACOS_KEYCHAIN_PROTECTION.md)
- [PhilCore Desktop Fresh Authentication](./security/PHILCORE_DESKTOP_FRESH_AUTHENTICATION.md)
- [PhilCore macOS Release Hardening](./security/PHILCORE_MACOS_RELEASE_HARDENING.md)
- [PhilCore ERC-4337 Rotation And Recovery](./security/PHILCORE_ERC4337_ROTATION_AND_RECOVERY.md) — N-series `PhilCore4337Account` owner/recoveryAuthority (separate contract scope; not V2 authority)
- [PhilCore Recovery Authority Custody](./security/PHILCORE_RECOVERY_AUTHORITY_CUSTODY.md) — N-series separate contract scope
- [PhilCore Recovery Authority Rotation](./security/PHILCORE_RECOVERY_AUTHORITY_ROTATION.md) — N-series separate contract scope
- [PhilCore Recovery Authority Runbook](./security/PHILCORE_RECOVERY_AUTHORITY_RUNBOOK.md) — N-series separate contract scope
- [PhilCore ERC-4337 Consumer Trust Requirements](./security/PHILCORE_ERC4337_CONSUMER_TRUST_REQUIREMENTS.md)
- [Fixture Authentication Lifecycle Bridge](./reference/FIXTURE_AUTHENTICATION_LIFECYCLE_BRIDGE.md)
- [O.42.1 Platform WebAuthn Root Cause and Compatibility](./reference/O42_1_PLATFORM_WEBAUTHN_ROOT_CAUSE_AND_COMPATIBILITY.md)
- [O.42.1 macOS Identity and Certificate Migration](./reference/O42_1_MACOS_IDENTITY_AND_CERTIFICATE_MIGRATION.md)
- [O.42.1 Packaged WebAuthn and iPhone Readiness](./reference/O42_1_PACKAGED_WEBAUTHN_AND_IPHONE_READINESS.md)
- [O.42.1 WebAuthn Security and Contamination](./security/O42_1_WEBAUTHN_SECURITY_AND_CONTAMINATION.md)
- [O.43 Native iPhone Companion Implementation and Readiness](./reference/O43_NATIVE_IPHONE_COMPANION_IMPLEMENTATION_AND_READINESS.md)
- [O.43 Native iPhone Role 1 Protocol](./security/O43_NATIVE_IPHONE_ROLE1_PROTOCOL.md)
- [O.43 Native iPhone Security and Threat Analysis](./security/O43_NATIVE_IPHONE_SECURITY_AND_THREAT_ANALYSIS.md)

These are reference documents, not replacements for the current source-of-truth architecture/specification set.

## 3. Research implementation

Research code needed to verify proof, verifier, Starknet, Cairo, and adapter
claims remains public. Internal research work logs are not included.

Related active research/source directories:

- `starknet_integration/`
- `starknet_integration_runner/`
- `starknet_adapter_spike/`
- `starknet_spike/`
- `cairo_air_adapter_spike/`
- `merkle_parity_spike/`
- `vendor/stwo_cairo_verifier/`
- spike and harness binaries under `proving/src/bin/`

## 3.1 Architecture Change Proposals

Architecture Change Proposals are evidence-backed proposed changes or clarifications. They are not accepted source-of-truth changes until reviewed.

- [ACP-0001: Verified Fact Cross-Domain Route Clarification](./architecture-changes/ACP-0001-VERIFIED-FACT-ROUTE.md)
- [ACP-0002: PhilCore ERC-4337 Smart Account Foundation](./architecture-changes/ACP-0002-PHILCORE-ERC4337-SMART-ACCOUNT.md)
- [ACP-0003: Phil V1 Secure Identity Architecture And Ordered Roadmap](./architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md)

## 4. Historical material

Internal phase reports, decision logs, master reports, prompts, and temporary
audit artifacts are excluded. Current public security dispositions are in
[Pre-MVP Security Findings](./security/PRE_MVP_SECURITY_FINDINGS.md).
- `WALLET_*`
- `L1_*`
- `PRODUCTION_MESSENGER_*`

Do not delete historical design work without explicit approval.

## 5. Stale Or Superseded Docs

Internal stale/superseded documents, phase reports, and research work logs are
not part of the public source candidate. Their exclusion does not remove the
current implementation, tests, specifications, security boundaries, or
legally redistributable proof-system source needed for independent review.

## 6. Current Docs Structure

The normalized documentation structure is:

```text
docs/
  CANONICAL_DOCS.md
  PHILCORE_CORE_BOUNDARY.md
  PHILCORE_RUNTIME_LIFECYCLE.md
  PHILCORE_FUNCTIONAL_SPEC_V1.md
  PHILCORE_TECHNICAL_SPEC_V1.md
  reference/
    PHIL_IDENTITY_MODEL.md
    PHIL_DEVICE_IDENTITY_V1.md
    PROOF_INPUT_SCHEMA.md
    ACTION_UNLOCK_PROOF_SPEC.md
    ACTION_UNLOCK_PROOF_GENERATION_BOUNDARY.md
    ACTION_UNLOCK_PROOF_VERIFICATION_AND_FINALIZATION_BOUNDARY.md
    VERIFIED_FACT_PUBLICATION_AND_EXECUTION_READINESS_BOUNDARY.md
    VERIFIED_FACT_CROSS_DOMAIN_ROUTE.md
    STARKNET_VERIFIED_FACT_PUBLICATION_BOUNDARY.md
    STARKNET_TOOLCHAIN_AND_ARTIFACT_REPRODUCIBILITY.md
    STARKNET_FACT_PUBLICATION_SUBMISSION_AND_MONITORING_BOUNDARY.md
    L1_MESSAGE_AVAILABILITY_AND_FACT_ANCHOR_PREPARATION_BOUNDARY.md
    L1_FACT_ANCHOR_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md
    L1_TO_BASE_FACT_RELAY_PREPARATION_BOUNDARY.md
    L1_TO_BASE_RELAY_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md
    BASE_AUTHORIZATION_EXECUTION_PREPARATION_BOUNDARY.md
    BASE_AUTHORIZATION_EXECUTION_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md
    PHILCORE_ERC4337_SMART_ACCOUNT_FOUNDATION.md
    PHILCORE_ERC4337_USER_OPERATION_PREPARATION_BOUNDARY.md
    PHILCORE_ERC4337_USER_OPERATION_SIGNING_BOUNDARY.md
  application/
    PHILCORE_DESKTOP_RELEASE_CANDIDATE_HARDENING.md
  security/
    PHILCORE_MACOS_USER_PRESENCE_BOUNDARY.md
  architecture-changes/
    ACP-0001-VERIFIED-FACT-ROUTE.md
    ACP-0002-PHILCORE-ERC4337-SMART-ACCOUNT.md
    starknet/
```

## 7. Local Cleanup Candidates

These are local/generated cleanup candidates only:

- `.DS_Store`
- `node_modules/`
- `artifacts/`
- `cache/`
- `proving/out/`
- `proving/target/`
- `**/target/`

They are ignored by git and should be regenerated locally when needed.
