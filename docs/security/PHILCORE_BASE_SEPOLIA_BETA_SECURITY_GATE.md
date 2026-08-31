# PhilCore Base Sepolia Beta Security Gate

Status: `blocked`

Architecture status: Historical Ethereum/Base gate. It cannot resume under its
STWO/O.5 route. ACP-0003 Step 1 is accepted; any future network work must wait
for Steps 2-4 and use the accepted scoped authorization envelope and an
admitted exceptional-proof adapter. This document authorizes no deployment.

Phase: O.7

ACP-0002 status: `Proposed`

## Scope boundary — N-series PhilCore4337Account

This document describes the separate N-series `PhilCore4337Account` owner/recoveryAuthority model.
Its cancellation rules are not the authority model for `PhilCoreV2MinimalAccountV2`.
Current V2 actions 8–11 require the exact recovery-factor authority defined by
O.36.1/O.37.1. Actions 8, 9, and 11 use exact 2-of-3 current recovery factors.
Action 10 additionally requires the current validator plus exact 2-of-3 current
recovery factors. The validator never counts toward that recovery-factor
threshold, and validator-plus-one remains prohibited.

Canonical V2 sources:

- [O.36.1 Recovery And Cancellation Semantics](../reference/O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md)
- [O.37.1 V2 Recovery Lifecycle Update](../reference/O37_1_RECOVERY_LIFECYCLE_UPDATE.md)

## Decision


Base Sepolia Beta is not approved yet.

N.2 remediates the high-severity arbitrary-call risk by selecting the ActionGate-restricted account model for Beta and updating `PhilCore4337Account` so EntryPoint execution can target only the immutable approved `PhilBaseActionGate` with the `verifyAndConsume(...)` selector.

N.3 adds local Alpha Device Vault ECDSA custody and exact-hash M.10 signing-session support. N.4 adds restricted local Alpha owner rotation and delayed recovery. N.5 adds local Alpha recovery-authority custody, approval, and local EntryPoint recovery evidence. N.6 adds reproducible Slither analysis, custom PhilCore contract invariant checks, and dependency advisory triage. N.7 remediates the `PhilMintPassConsumer` value finding, formally accepts the remaining high npm advisories as development-tooling-only risk, and prepares the external-audit package. N.8 remediates the unsupported recovery-authority rotation limitation for local Alpha. O.1 adds a local-only desktop application shell. O.2 adds durable encrypted local identity and Device Vault records for the desktop normal path. O.3 adds a production-candidate macOS Keychain/safeStorage platform unlock boundary with passphrase fallback preserved. O.4 adds Runtime-generated digest-bound approval and fresh-authentication evidence for sensitive local desktop actions. O.5 wires one complete local authorization through real Runtime authority boundaries, real STWO proof generation and local verification, ERC-4337 preparation/signing, and local EntryPoint execution while keeping public fact publication and public bundler submission disabled. O.6 packages this local path as an unsigned, non-notarized macOS local Alpha with bundled proof binaries, package verification, SBOM generation, and packaged E2E/clean-environment tests. O.7 adds a narrow macOS LocalAuthentication user-presence helper boundary, release-candidate profile definitions, ad-hoc signing support, package minimization, and package-size audit evidence. The gate remains blocked because ACP acceptance, Beta-approved recovery custody, deployment verification, public-network operational controls, Developer ID signing/notarization, manual user-presence evidence, and external audit are not complete.

## Mandatory Criteria

| Criterion | Status | Evidence |
| --- | --- | --- |
| ACP-0002 accepted for Beta | blocked | ACP-0002 remains `Proposed`. |
| Arbitrary-call risk resolved | met | Account now enforces immutable ActionGate target and selector. |
| Account/factory tests cover restriction | met | `test/unit/philcore-erc4337-security-review-n1.test.cjs` and smart-account foundation tests. |
| Static analysis reproducible | met | `npm run security:setup-slither` creates the pinned local Slither 0.10.4 environment; `npm run security:slither` completed. |
| Static findings triaged | met | `docs/security/PHILCORE_SOLIDITY_STATIC_ANALYSIS_N6.md` and `config/security/philcore-solidity-static-analysis.json`. |
| Custom contract invariants passing | met | `npm run security:philcore-contract-invariants` passes 18 PhilCore-specific checks, including MintPass zero-value enforcement. |
| No unresolved critical contract findings | met | Slither reports 0 critical contract findings. |
| No unresolved high contract findings | met | Slither reports 0 high contract findings. |
| No unresolved high dependency findings | met with accepted tooling risk | `serialize-javascript`, `tmp`, and `undici` remain reported through Hardhat/local tooling and are formally accepted only as development-tooling risk. No high advisory is classified as production runtime exposure. |
| Device Vault key custody implemented | met for local Alpha | N.3 encrypted local validator custody and one-time exact-hash signing sessions. Not production-approved. |
| Recovery limitation disclosed | met | N.4 implements delayed recovery. N.5 implements local Alpha recovery-authority custody and workflow evidence. Beta still requires custody/audit/deployment acceptance and disposable testnet policy. |
| Recovery authority custody | met for local Alpha | Separate encrypted Device Vault ECDSA recovery authority record, one-time approval, and recovery-only signing sessions. Not Beta-approved. |
| Recovery authority rotation | met for local Alpha | N.8 implements bounded delayed recovery-authority rotation with other-authority cancellation and local tests. Not Beta-approved until audit and deployment gates pass. |
| Account/factory/EntryPoint deployments verified | blocked | No accepted Base Sepolia deployments in N.2. |
| Disposable funded testnet account policy | required | Required before any public testnet mutation. |
| Approved bundler | blocked | No accepted Base Sepolia bundler configuration. |
| Paymaster disabled | met | Runtime boundaries keep paymaster disabled. |
| Dependency advisories triaged | met with accepted tooling risk | N.7 classifies and accepts remaining high tooling advisories with controls in `config/security/philcore-dependency-exposure.json`. |
| Public-network mutation disabled by default | met | No public UserOperation submitted in N.2. |
| Desktop app local-only mode | met for local Alpha | O.1 Electron shell exposes only local fixture Runtime workflows and no public submitter or public RPC mutation controls. |
| Desktop durable local identity and vault | met for local Alpha | O.2 creates/reopens encrypted local Phil identity, registry, execution-validator custody, and optional recovery-authority custody records. Not production-approved. |
| Desktop platform unlock protection | met as production-candidate boundary | O.3 protects a random per-identity wrapping key through macOS Keychain-backed Electron safeStorage where available, preserves explicit passphrase fallback, and adds fixture/E2E/security tests. It does not claim Touch ID, Secure Enclave custody, or production approval. |
| Desktop digest-bound approval | met for local Alpha | O.4 creates Runtime-owned presentations, one-time approval artifacts, fresh-authentication evidence checks, approval history, and local demo/recovery approval tests. It does not approve public submission or production use. |
| Desktop real local authorization | met for local Alpha | O.5 runs real local Runtime/proof/ERC-4337/EntryPoint workflow with local fixture fact availability. It does not approve public submission or production use. |
| Desktop local Alpha package | met for local Alpha | O.6 creates and verifies an unsigned, non-notarized macOS `.app`/`.zip`; packaged O.5 and clean-environment tests pass. |
| Desktop signed/notarized package | blocked | O.7 prepares guarded Developer ID, ad-hoc, and notarization workflows, but no Developer ID signing or Apple notarization was performed. |
| Strong platform user presence | partially met for local Alpha | O.7 adds a macOS LocalAuthentication helper boundary and fixture tests. Real manual Touch ID/device-owner evidence and signed release-candidate validation remain required before Base Sepolia. |
| Meaningful assets prohibited | met for current state | Local Alpha only; Beta remains blocked. |

## Beta Authority Model

Selected for Base Sepolia Beta: ActionGate-restricted account.

Normal EntryPoint execution may only call the immutable approved ActionGate and only with `verifyAndConsume(...)` calldata. Account self-call execution is disabled for `execute(...)`, so a UserOperation cannot nest through `account.execute(account, ...)` to bypass target restrictions.

## Recovery Decision

In-contract restricted recovery is implemented for local Alpha. The recovery authority may request delayed recovery and complete recovery after the challenge period. It cannot execute ordinary actions, transfer assets, bypass ActionGate, or cancel its own pending recovery. Cancellation remains current-owner controlled.

Base Sepolia Beta is still not approved. Until recovery-authority custody, deployments, public-network operational controls, and external audit are complete, only local fixture accounts are acceptable. Remaining high npm advisory groups are accepted only as development-tooling risk and must not be shipped as production runtime dependencies.

## Current Gate Result

`base_sepolia_beta_blocked_pending_architecture_decision_deployment_and_external_audit`

Required next evidence:

- ACP-0002 review/acceptance for Beta scope;
- Beta approval for recovery-authority custody model;
- N.8 recovery-authority rotation reviewed for Beta scope;
- signed/notarized desktop packaging and stronger platform user-presence or reviewed WebAuthn/passkey evidence;
- remaining high dependency advisories excluded from production runtime packaging and revisited during Hardhat/toolchain migration;
- external audit package or independent review;
- accepted Base Sepolia account/factory/ActionGate deployments;
- explicit public testnet submission approval workflow.

## Phase N.6 Evidence

N.6 adds reproducible local static-analysis and dependency evidence:

- `npm run security:setup-slither` installs Slither 0.10.4 in `.security-tools/`;
- `npm run security:slither` completed with 0 high/critical Solidity findings;
- `npm run security:philcore-contract-invariants` passed all 17 custom checks;
- `npm run security:npm-audit` reduced advisories from 20 to 16 using non-forced lockfile remediation;
- `lodash` and Hardhat-nested `ws` high advisory groups are no longer reported;
- `serialize-javascript`, `tmp`, and `undici` remain high Hardhat/tooling advisory groups;
- `N6-MED-008` remains open for `PhilMintPassConsumer` locked ETH before any value-bearing deployment of that consumer.

## Phase N.7 Evidence

N.7 adds targeted remediation and audit package readiness:

- `PhilMintPassConsumer` rejects nonzero `msg.value` before mint state changes;
- `npm run security:philcore-contract-invariants` includes `N7-INV-018`;
- remaining high npm advisory groups are classified as development-tooling-only in `config/security/philcore-dependency-exposure.json`;
- `docs/security/PHILCORE_EXTERNAL_AUDIT_SCOPE.md` defines the external audit scope;
- `config/security/philcore-external-audit-manifest.json` lists source, tests, reports, and reproduction commands;
- `docs/security/PHILCORE_MEANINGFUL_ASSETS_POLICY.md` prohibits meaningful assets before audit and gate approval;
- `npm run security:audit-package-check` validates the local audit package and confirms the gate remains blocked.

## Phase N.8 Evidence

N.8 adds bounded recovery-authority rotation:

- `PhilCore4337Account` stores a mutable current recovery authority while preserving immutable EntryPoint, ActionGate, and `ownerCommitment`;
- current owner or current recovery authority can request rotation;
- the other authority can cancel;
- anyone can complete after the delay if the request is still valid;
- rotation performs no external calls, transfers no value, and does not execute ActionGate or consumer logic;
- `npm run security:philcore-contract-invariants` includes N.8 rotation invariants.

This remediates the previous local unsupported-rotation blocker. It does not approve ACP-0002, public deployment, public UserOperation submission, meaningful assets, or production recovery.

## Phase O.5 Evidence

O.5 adds one real local desktop authorization workflow:

- durable local identity and Device Vault unlock feed protected witness and validator signing boundaries only in the main process;
- Runtime Trust, Policy, approval, Capability Grant, Authorization Candidate, and Authorization Package boundaries are used;
- real Rust/STWO ACTION_UNLOCK proof generation and real local proof verification run in the local path;
- verified-fact availability is installed only into local fixture state and is labeled as such;
- ERC-4337 v0.7 UserOperation preparation/signing and local EntryPoint execution are exercised;
- ActionGate nullifier consumption and consumer event evidence are independently checked;
- identity reset now requires fresh authentication or passphrase reauthentication in addition to typed confirmation.

This is local Alpha evidence only. It does not approve ACP-0002, Base Sepolia Beta, public Starknet/L1/Base publication, public bundler submission, meaningful assets, or production use.

## Phase O.6 Evidence

O.6 adds macOS local Alpha packaging and release hardening:

- custom local Alpha packager produces a `.app` and `.zip`;
- bundled release-mode ACTION_UNLOCK prover/verifier binaries are integrity-hashed;
- packaged O.5 workflow runs without the PhilCore repository or Cargo at runtime;
- package verification checks renderer isolation, CSP, bridge allowlisting, proof binary hashes, public-network disablement, and production-approval status;
- SBOM and release manifest are generated under `config/release/`;
- signing and notarization commands are guarded and refuse missing credentials or approval.

This is local Alpha release evidence only. The package is unsigned and not notarized. O.6 does not approve ACP-0002, Base Sepolia Beta, public-network mutation, meaningful assets, or production use.

## Phase O.7 Evidence

O.7 adds native user-presence and release-candidate preparation:

- small Swift `LocalAuthentication` helper boundary;
- main-process-only invocation with helper hash validation;
- fixture tests for success, cancellation, malformed output, replay, wrong digest, and missing native provider;
- release profiles for unsigned local Alpha, ad-hoc local Alpha, signed release candidate, notarized release candidate, and disabled production;
- package minimization and package-size audit evidence;
- guarded Developer ID signing and notarization commands.

This is still local Alpha evidence. Developer ID signing and Apple notarization were not performed. Touch ID is not claimed unless the biometric-only policy succeeds in a real manual diagnostic. O.7 does not approve ACP-0002, Base Sepolia Beta, public-network mutation, meaningful assets, or production use.

## Phase O.1 Evidence

O.1 adds a local-only desktop Alpha shell:

- Electron static renderer with isolated preload bridge;
- renderer Node integration disabled and renderer sandbox enabled;
- local fixture Runtime host;
- no public submitters, public RPC mutation, paymasters, or generic wallet controls;
- local authorization demo and recovery demo surfaces;
- desktop bridge, Runtime host, security, and Electron E2E tests.

This improves local usability and reviewability. It does not approve ACP-0002, Base Sepolia Beta, public deployment, public UserOperation submission, meaningful assets, or production use.

## Phase O.9 Evidence

O.9 completes the macOS Apple trust pipeline for a guarded local trusted-tester
artifact:

- Developer ID signing and strict nested verification passed;
- Apple notarization was accepted;
- stapling and staple validation passed;
- Gatekeeper accepted the working app and extracted final ZIP copy;
- packaged launch, native user-presence helper availability, proof generation,
  proof verification, and clean-environment execution passed;
- repository-independent trusted-tester ZIP verification passed.

This removes the previous signed/notarized desktop packaging blocker for local
trusted-tester artifact production only. The Base Sepolia Beta gate remains
blocked because ACP-0002 is still Proposed, external audit is still required,
Beta deployment and public-network operational controls are not accepted, and
production approval remains false.

## Phase O.10 Evidence

O.10 rehearses controlled trusted-tester operations for the existing O.9
artifact:

- independent artifact revalidation and isolated installation rehearsal;
- fixture-backed acknowledgement, defect intake, update, rollback, and revocation
  controls;
- manually initiated diagnostic-export redaction checks;
- no-send distribution dry run;
- explicit bundle-identifier recommendation for the first controlled
  trusted-tester cohort only.

O.10 does not distribute the artifact, create real tester acceptance records,
submit to Apple, rebuild or resign the application, enable public-network
mutation, accept ACP-0002, satisfy external audit, or approve Base Sepolia Beta.

## Phase O.11 Evidence

O.11 records the repository operator as the first trusted tester for the existing
O.9 artifact:

- exact artifact verification passed again;
- real native macOS user-presence succeeded through the packaged helper;
- packaged local proof execution and relaunch checks passed;
- sanitized diagnostic export and redaction checks passed;
- app removal and isolated-state cleanup were exercised;
- one low-severity Finder-launch automation limitation was recorded;
- one external tester slot was prepared but remains pending;
- the external distribution gate remains blocked by default.

O.11 does not distribute the artifact externally, enable Base Sepolia mutation,
submit a public UserOperation, invoke a paymaster, accept ACP-0002, satisfy
external audit, grant Beta approval, or grant production approval.

## Phase O.2 Evidence

O.2 replaces the desktop normal fixture identity path with durable encrypted local identity and Device Vault state:

- `phil_secret -> identityRoot -> ownerCommitment` is generated and stored inside an encrypted private identity envelope;
- encrypted registry, execution-validator custody, and optional recovery-authority custody records are persisted under Electron app data;
- local Alpha passphrase authentication revalidates encrypted identity and registry binding;
- Device Vault unlock exposes only sanitized public state and summaries;
- app restart reopens the same identity and public key material;
- ciphertext tampering and identity-index tampering fail closed;
- reset requires a locked identity and exact confirmation;
- diagnostics remain local and sanitized.

O.2 does not add production platform authentication, Secure Enclave custody, public UserOperation submission, public chain mutation, or Beta approval.

## Phase O.3 Evidence

O.3 adds desktop platform unlock protection:

- O.2 encrypted records can be migrated to a random per-identity vault-wrapping key;
- on macOS, the wrapping key is protected through Electron `safeStorage`, which is Keychain-backed when Electron reports encryption availability;
- the passphrase fallback remains explicit and labeled as local Alpha fallback;
- platform unlock after restart, cancellation/denial/missing-item failures, disablement, and fresh-authentication evidence are covered by fixture tests;
- renderer IPC exposes a narrow `platformAuth` API only and never returns wrapping keys, vault keys, `phil_secret`, validator keys, or recovery keys;
- diagnostics are sanitized and distinguish fixture/CLI evidence from real Electron main-process macOS Keychain behavior.

O.3 is a production-candidate unlock boundary, not production approval. It does not claim Touch ID, Secure Enclave custody, guaranteed biometric user presence, signed/notarized packaging, public UserOperation submission, public chain mutation, or Beta approval.

## Phase O.4 Evidence

O.4 adds digest-bound sensitive-action approval:

- presentations and digests are generated by the Runtime host, not the renderer;
- approval artifacts are one-time, process-local, identity/session/action/digest-bound, and expiring;
- local authorization demo consumes execution approval, signing approval, and fresh-authentication evidence;
- recovery request/completion and rotation demos consume digest-bound approval and fresh evidence where required;
- platform unlock disablement requires approval and fresh evidence;
- local identity reset requires locked identity, exact presentation, and typed confirmation.

O.4 does not submit public UserOperations, deploy live accounts, invoke paymasters, accept ACP-0002, or pass the Base Sepolia Beta gate.
