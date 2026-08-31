# ACP-0002: PhilCore ERC-4337 Smart Account Foundation

Relationship to ACP-0003: This proposal describes a current Ethereum/Base
compatibility account. It does not control Phil V1 identity, encrypted data,
identity/data recovery, or the cross-network authorization envelope. Any
future product integration must follow the accepted ACP-0003 sequence.

Review status: Proposed

Scoped evidence status: Conditionally Approved for Disposable Sepolia
Preparation. This does not accept ACP-0002 as a whole.

## Problem Observed

Phase M.9 was stopped because the repository did not contain an accepted ERC-4337 stack that could safely wrap the Base `verifyAndConsume(...)` execution call into a `UserOperation`.

Implementation evidence showed:

- historical v0.6-style UserOperation scripts;
- historical EntryPoint v0.6 address `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`;
- no current PhilCore smart-account contract;
- no current smart-account factory;
- no accepted EntryPoint interface;
- no accepted account `execute(...)` ABI;
- no accepted `validateUserOp(...)` implementation;
- no accepted owner/validator binding.

## Implementation Evidence

M.9A added and tested a local foundation:

- `@account-abstraction/contracts@0.7.0` as a pinned EntryPoint/BaseAccount dependency;
- `@openzeppelin/contracts@5.0.0` pinned to match the repository Solidity compiler;
- `PhilCore4337Account`, a minimal non-upgradeable account inheriting the established v0.7 `BaseAccount`;
- `PhilCore4337AccountFactory`, a deterministic CREATE2 factory;
- local Hardhat tests using the actual v0.7 `EntryPoint` artifact;
- a real `handleOps(...)` execution path;
- a local `PhilBaseActionGate.verifyAndConsume(...)` execution through the smart account.

## Affected Documents

- `docs/CANONICAL_DOCS.md`
- `docs/reference/PHILCORE_ERC4337_SMART_ACCOUNT_FOUNDATION.md`
- `docs/reference/BASE_AUTHORIZATION_EXECUTION_PREPARATION_BOUNDARY.md`
- `docs/reference/BASE_AUTHORIZATION_EXECUTION_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md`
- `docs/reference/VERIFIED_FACT_CROSS_DOMAIN_ROUTE.md`
- `LOCAL_DEVELOPMENT.md`

## Affected Modules

- `contracts/base/erc4337/PhilCore4337Account.sol`
- `contracts/base/erc4337/PhilCore4337AccountFactory.sol`
- `contracts/base/mocks/PhilSmartAccountExecutionTarget.sol`
- `test/unit/philcore-erc4337-smart-account-foundation.test.cjs`
- `config/philcore-erc4337-smart-account-foundation.json`

## Affected Invariants

Preserved:

- `phil_secret -> identityRoot -> ownerCommitment`
- `ACTION_UNLOCK`
- `proofInputHash`
- proof public input tuple
- STARK/proof architecture
- WebAuthn/passkey architecture
- encrypted registry/key lifecycle
- ERC-4337 Smart Accounts as preferred Ethereum authority model
- EOAs as compatibility paths
- Ethereum/Base as first execution path
- no multi-chain implementation yet
- no full post-quantum security overclaim

The account stores `ownerCommitment` as public binding metadata. It does not derive, expose, or consume `phil_secret`.

## Security Impact

Positive:

- Establishes a real EntryPoint/account/factory boundary instead of continuing with script-only pseudo-UserOperations.
- Rejects direct owner calls to `execute(...)`; execution must come from EntryPoint or the account itself.
- Keeps paymasters, session keys, batch execution, live deployment, and bundler submission disabled.
- Makes the Beta ECDSA validator limitation explicit.

Risks:

- `PhilCore4337Account` is new local contract code and is unaudited.
- Initial validator is a conventional ECDSA owner, not PhilCore-native WebAuthn/P-256 validation.
- `ownerCommitment` is public metadata and not itself an on-chain validator.
- Key generation, Device Vault storage, rotation, recovery, and custody are not implemented in M.9A.

## Migration Impact

Historical v0.6 scripts remain archive evidence only. Future UserOperation preparation should use EntryPoint v0.7 `PackedUserOperation` semantics unless this ACP is rejected or superseded.

EOA compatibility execution remains available for local/testnet diagnostics, but it is not the preferred production path.

## Rejected Alternatives

1. Keep historical EntryPoint v0.6.
   - Rejected for Beta foundation because v0.7 has the newer packed UserOperation schema, current package support, and clearer future alignment.

2. Adopt upstream `SimpleAccount` directly.
   - Rejected because it allows the ECDSA owner to call `execute(...)` directly, which creates a bypass around PhilCore Runtime authorization.

3. Adopt a modular account standard immediately.
   - Rejected for M.9A because it increases the audit surface before PhilCore has a working single-call smart-account path.

4. Implement WebAuthn/P-256 validation on-chain now.
   - Rejected for M.9A because the prompt only requires the foundation, and on-chain WebAuthn validation would substantially expand scope.

5. Use a paymaster or sponsored gas path now.
   - Rejected because paymaster behavior is not required for the first controlled execution path and would add authorization/cost policy complexity.

## Recommended Change

Accept the M.9A local foundation as the proposed ERC-4337 Beta direction:

- EntryPoint version: v0.7
- UserOperation schema: `PackedUserOperation`
- Account implementation: minimal PhilCore account built on established v0.7 `BaseAccount`
- Factory: deterministic CREATE2 factory
- Validator: ECDSA owner for Beta/local/testnet only
- Identity binding: account stores `ownerCommitment` as public metadata, while the signing key remains protected by future Device Vault custody
- Disabled in this foundation: paymasters, session keys, batch execution, live deployment, UserOperation signing, bundler submission

## Review Status

Proposed. This ACP should remain proposed until the user explicitly accepts the ERC-4337 smart-account foundation as the implementation path for resuming M.9.

## M.9 Implementation Evidence

Phase M.9 added an unsigned preparation boundary that reuses this proposed foundation without accepting the ACP:

- reference: [PhilCore ERC-4337 UserOperation Preparation Boundary](../reference/PHILCORE_ERC4337_USER_OPERATION_PREPARATION_BOUNDARY.md)
- EntryPoint version: v0.7
- schema: `PackedUserOperation`
- inner call: exact `PhilCore4337Account.execute(address,uint256,bytes)` wrapping of the M.7 `PhilBaseActionGate.verifyAndConsume(...)` calldata
- hash parity: local TypeScript calculation checked against actual EntryPoint `getUserOpHash(...)`
- disabled: signing, bundler submission, paymaster invocation, live account deployment, nullifier consumption, consumer execution, live Base mutation

This evidence supports continuing toward an M.10 signing boundary, but ACP-0002 remains `Proposed`.

## M.10 Implementation Evidence

Phase M.10 added a controlled signing boundary without accepting this ACP:

- reference: [PhilCore ERC-4337 UserOperation Signing Boundary](../reference/PHILCORE_ERC4337_USER_OPERATION_SIGNING_BOUNDARY.md)
- signature semantics: EIP-191 personal-sign over EntryPoint v0.7 `getUserOpHash(PackedUserOperation)`
- signer: protected Beta ECDSA validator interface, with local `developer_fixture` implementation only
- approval: one-time presentation-bound approval
- artifact: signed but unsubmitted `PackedUserOperation`
- disabled: bundler submission, paymaster invocation, live account deployment, nullifier consumption, consumer execution, live Base mutation

This evidence supports evaluating an M.11 bundler-submission preparation boundary, but ACP-0002 remains `Proposed`.

## M.11 Implementation Evidence

Phase M.11 added a controlled bundler-submission and receipt-monitoring boundary without accepting this ACP:

- reference: [PhilCore ERC-4337 Bundler Submission And Monitoring Boundary](../reference/PHILCORE_ERC4337_BUNDLER_SUBMISSION_AND_MONITORING_BOUNDARY.md)
- bundler model: restricted client interface for capability checks, exact UserOperation submission, lookup, and receipt reads only
- serialization: exact packed EntryPoint v0.7 UserOperation shape
- approval: submission approval is separate from signing approval
- local evidence: a local fixture bundler can submit through actual EntryPoint `handleOps(...)` and monitor the resulting receipt path
- disabled: public Base Sepolia submission without prerequisites, Base mainnet, paymasters, arbitrary bundler RPC, generic transaction submission, and application-facing bundler access

This evidence supports a dedicated security review for ACP-0002 before Beta desktop UI integration, but ACP-0002 remains `Proposed`.

## N.1 Security Review Evidence

Phase N.1 performed an adversarial internal security review without accepting this ACP:

- reference: [PhilCore ERC-4337 Security Review N.1](../security/PHILCORE_ERC4337_SECURITY_REVIEW_N1.md)
- machine-readable findings: `config/security/philcore-erc4337-security-findings.json`
- tests added:
  - `test/unit/philcore-erc4337-security-review-n1.test.cjs`
  - `contracts/base/mocks/PhilAdversarialAuthorizationConsumer.sol`
- remediation applied:
  - M.11 receipt monitoring now requires explicit inner execution, nullifier, and consumer verifiers before producing a successful bounded execution receipt.

Review recommendation: `Accept for Local Alpha Only`

ACP classification from N.1: `recommended_for_local_alpha_only`

Important findings:

- A valid owner-signed EntryPoint UserOperation can execute arbitrary account targets. Direct owner calls are blocked, but on-chain account enforcement is not limited to ActionGate calls.
- Runtime restrictions can be bypassed by anyone who controls or misuses the configured owner key.
- Beta ECDSA owner custody and recovery are locally implemented; N.8 adds local recovery-authority rotation. Beta approval, deployment controls, production recovery, and audit remain incomplete.
- The custom account and factory remain unaudited.
- Dependency audit advisories remain partially unresolved in Hardhat/local tooling.

Required before Base Sepolia Beta:

- resolve or explicitly accept the owner-key arbitrary-call risk through Architecture Change Control;
- complete Beta review of custody/rotation/recovery and production recovery limitations;
- remediate or formally accept remaining high Hardhat/local-tooling dependency advisories;
- keep pinned static-analysis evidence reproducible;
- define public-network value limits and operational runbooks;
- complete at least one external review pass.

ACP-0002 remains `Proposed` and must not be treated as production-approved.

## N.2 Remediation Evidence

Phase N.2 selected the ActionGate-restricted account model for the Base Sepolia Beta direction, while keeping ACP-0002 `Proposed`.

Recommendation by environment:

- Local Alpha: current restricted account is acceptable with fixture/developer keys and no meaningful assets.
- Base Sepolia Beta: ActionGate-restricted execution is the required account model, but the Beta gate remains blocked until custody, recovery, audit/static-analysis, dependency, deployment, and ACP-review requirements are satisfied.
- Production: restricted or modular PhilCore validator with independent recovery authority remains required. The current custom account/factory are not production-approved.

Implemented N.2 changes:

- `PhilCore4337Account` now binds immutable `approvedActionGate`.
- EntryPoint-mediated `execute(...)` is restricted to the approved ActionGate and the `verifyAndConsume(...)` selector.
- `execute(...)` no longer permits account-self callers, closing the nested self-call bypass path.
- `PhilCore4337AccountFactory` is bound to an immutable approved ActionGate and includes that binding in CREATE2 derivation.
- Runtime M.9/M.10/M.11 account verification now checks the approved ActionGate as defense in depth.

Security impact:

- `N1-HIGH-001` is remediated for the selected Beta model.
- A stolen ECDSA owner key can still sign valid UserOperations for the approved ActionGate path if the attacker can assemble valid authorization/proof inputs. It cannot use the account as a general wallet or bypass directly to arbitrary targets.
- Device Vault ECDSA custody, recovery, external audit, and public deployment controls remain Beta blockers.

Migration impact:

- Account CREATE2 addresses change because the account constructor now includes `approvedActionGate`.
- Existing local fixture account addresses from M.9/M.10/M.11 are superseded.
- Factory deployments are ActionGate-specific. A different ActionGate requires a different factory/account address family.

Rejected models:

- General smart account for Beta: rejected because it cannot honestly enforce bounded PhilCore authorization if owner-signed UserOperations can call arbitrary targets.
- Dual-authority account for Beta: deferred because it introduces recovery/admin complexity before custody and audit are ready.
- Modular standard account before Beta: deferred as a production migration candidate, not a required N.2 remediation.

Required before accepting ACP-0002 for Beta:

- accept or revise the ActionGate-bound factory/account model;
- implement or approve Beta validator custody;
- define recovery/rotation policy;
- complete independent review and preserve pinned static-analysis evidence;
- satisfy the Base Sepolia Beta security gate.

## N.3 Custody Evidence

Phase N.3 adds local Alpha Device Vault ECDSA validator custody without accepting this ACP:

- reference: [PhilCore Device Vault ECDSA Validator Custody](../security/PHILCORE_DEVICE_VAULT_ECDSA_CUSTODY.md)
- runtime boundary: `apps/phil-device-sdk/src/runtime/deviceVaultEcdsaCustody.ts`
- validator key generation: random secp256k1 key, not derived from `phil_secret`, `identityRoot`, or `ownerCommitment`
- storage: AES-256-GCM encrypted validator records using the existing Device Identity registry key-provider/storage pattern
- signer integration: M.10 `PhilCore4337ValidatorSigner` support through one-time exact-hash signing sessions
- disabled: arbitrary message signing, arbitrary transaction signing, typed-data signing, private-key export, public UserOperation submission, paymasters, Base mainnet, and production approval

Security impact:

- `N1-MED-002` is partially remediated for local Alpha custody.
- On-chain owner rotation is still not implemented in `PhilCore4337Account`.
- Local validator revocation does not change the account owner on-chain.
- Recovery remains a Beta/production blocker.

ACP-0002 remains `Proposed`.

## O.19 Scoped Sepolia Preparation Decision

The human approved `local-proof-gated-v1` only for guarded preparation and
read-only inspection of one disposable Ethereum Sepolia experiment.

Accepted within that scope:

- local STWO verification gates Runtime and Device Vault signing;
- Ethereum verifies the account signature, exact UserOperation, EntryPoint,
  nonce, expiry, and fixed call restrictions;
- Ethereum does not independently verify STWO;
- only the separate experimental target, factory, and counterfactual account
  are in scope;
- the action is zero value, token free, and paymaster free;
- no meaningful assets, mainnet claim, Beta approval, or production claim;
- `ethereum-fact-enforced-v1` remains the stronger intended architecture.

Not approved:

- deployment-manifest acceptance;
- target or factory deployment;
- account funding;
- transaction or UserOperation signing/submission;
- any public-network mutation.

Implementation evidence also clarifies that
`PhilCore4337LocalProofAccountFactoryV1` directly deploys accounts with CREATE2.
There is no proxy-style implementation dependency, so O.19 prohibits a
redundant standalone account implementation deployment.

ACP-0002 remains `Proposed`.

## O.18 Ethereum Sepolia Fact-Enforcement Decision

O.18 records two non-interchangeable security models:

- `ethereum-fact-enforced-v1`: the existing `PhilCore4337Account` remains
  ActionGate-restricted and requires Ethereum-visible verifier evidence.
- `local-proof-gated-v1`: a separately named disposable-testnet account allows
  only one fixed zero-value confirmation action after Runtime and Device Vault
  have locally verified STWO and all authorization artifacts.

Proposed decisions requiring human review:

- use Ethereum Sepolia first, chain ID `11155111`, with canonical ERC-4337 v0.7 EntryPoint;
- permit `local-proof-gated-v1` only for one controlled disposable test;
- make no on-chain STARK or production claim;
- deploy a separate experimental account/factory/target, with no bypass in the
  existing account;
- use no paymaster and no meaningful assets;
- require explicit UI labeling and independent deployment/submission approval.

The experimental account does not replace the stronger fact-enforced
architecture. [Sepolia Fact-Enforcement Decision](../reference/SEPOLIA_FACT_ENFORCEMENT_DECISION.md)
contains the evidence and migration path.

Review status remains `Proposed`.

## O.17 Ethereum Sepolia Readiness Evidence

Phase O.17 selects Ethereum Sepolia (`chainId 11155111`) as the intended first
public experiment target without accepting this ACP or mutating a public
network.

Evidence:

- the account and factory remain compatible with EntryPoint v0.7
  `PackedUserOperation` semantics;
- the canonical proposed EntryPoint is
  `0x0000000071727De22E5E9d8BAf0edAc6f37da032`;
- the final readiness envelope adds an exact typed composition binding across
  identity, action, policy, approval, presence, proof, Runtime authority,
  account/factory/EntryPoint, nonce, target/value/calldata, gas/fees, expiry,
  nullifier, and UserOperation hash;
- a harmless zero-value confirmation target is locally tested;
- Ethereum Sepolia mutation guards and a proposed-only manifest fail closed;
- Base mirror/relay configuration is not silently reused.

Architecture mismatch requiring decision:

- the desired local-STWO-verification-only public signing model does not need
  verified-fact transport conceptually;
- the current ActionGate-restricted account implementation does require
  Ethereum-visible verifier evidence for `stwo-unlock-keccak-v1`;
- using local verification as an on-chain fact without a contract-enforced
  attestation model would weaken the selected restricted account architecture.

Before a public phase, reviewers must choose either the current
Ethereum-visible fact route or a separately proposed on-chain
Runtime/validator attestation design. ACP-0002 remains `Proposed`.

## O.1 Desktop Application Evidence

Phase O.1 adds a local-only Electron desktop shell without accepting this ACP:

- reference: [PhilCore Desktop Alpha Foundation](../application/PHILCORE_DESKTOP_ALPHA_FOUNDATION.md)
- security boundary: [PhilCore Desktop Security Boundary](../application/PHILCORE_DESKTOP_SECURITY_BOUNDARY.md)
- mode: `local_alpha`;
- renderer: isolated, sandboxed, no Node integration;
- bridge: allowlisted preload methods only;
- Runtime host: local fixture state and sanitized audit events;
- disabled: public UserOperation submission, public bundler/RPC mutation, paymasters, mainnet, generic wallet execution, private-key export, meaningful assets.

ACP impact:

- O.1 improves local review and product integration evidence for the proposed ERC-4337 path.
- It does not accept ACP-0002.
- Base Sepolia Beta remains blocked pending ACP acceptance, Beta custody approval, deployment evidence, public-network operational controls, and external audit.

ACP-0002 remains `Proposed`.

## N.5 Recovery Authority Custody Evidence

Phase N.5 adds local Alpha recovery-authority custody, approval, and local EntryPoint recovery workflow evidence without accepting this ACP:

- references:
  - [PhilCore Recovery Authority Custody](../security/PHILCORE_RECOVERY_AUTHORITY_CUSTODY.md)
  - [PhilCore Recovery Authority Runbook](../security/PHILCORE_RECOVERY_AUTHORITY_RUNBOOK.md)
- runtime boundary: `apps/phil-device-sdk/src/runtime/philcore4337RecoveryAuthorityCustody.ts`
- recovery authority records are separate purpose-bound encrypted Device Vault ECDSA records;
- recovery authority records may be generated before account address is known and bound after account creation;
- recovery signing sessions are one-time and exact-hash;
- recovery action presentations bind account, owner commitment, recovery authority, pending owner, selector, calldata hash, UserOperation hash, nonce, gas summary, expiry, and audit correlation;
- recovery authority may sign only `requestRecovery(address)` and `completeRecovery(bytes32,address)`;
- recovery authority cancellation is rejected;
- local EntryPoint tests cover lost-key recovery from request through completion and local validator revocation after verified owner rotation.

Security impact:

- `N1-MED-002` is further remediated for local Alpha.
- Base Sepolia Beta remains blocked until recovery-authority custody is approved for the selected Beta model.
- Recovery-authority rotation is remediated later by N.8 for local Alpha, but still requires Beta review and audit.
- Production still requires threshold or modular recovery and external audit.

ACP-0002 remains `Proposed`.

## N.6 Static Analysis and Dependency Evidence

Phase N.6 adds reproducible static-analysis and dependency triage evidence without accepting this ACP:

- Slither 0.10.4 runs from a repository-local Python virtual environment.
- `npm run security:slither` completes and records `config/security/philcore-solidity-static-analysis.json`.
- Slither reports 0 critical and 0 high Solidity findings.
- `npm run security:philcore-contract-invariants` passes 17 PhilCore-specific checks that preserve restricted account, recovery, mirror, and ActionGate invariants.
- One medium production-relevant finding remains open for `PhilMintPassConsumer` locked ETH before value-bearing deployment of that consumer.
- `npm run security:npm-audit` records `config/security/philcore-npm-audit-report.json`.
- N.6 reduces npm advisories from 20 to 16 without `npm audit fix --force`.
- `lodash` and Hardhat-nested `ws` high advisory groups are remediated by lockfile update.
- `serialize-javascript`, `tmp`, and `undici` remain high Hardhat/local-tooling advisory groups.

ACP impact:

- Static-analysis reproducibility is no longer a blocker for local evidence.
- ACP-0002 remains blocked for Beta acceptance by Beta custody approval, N.8 rotation review, deployment evidence, public-network operational controls, and external audit.

ACP-0002 remains `Proposed`.

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

## N.8 Recovery Authority Rotation Evidence

Phase N.8 adds bounded delayed recovery-authority rotation without accepting this ACP:

- reference: [PhilCore Recovery Authority Rotation](../security/PHILCORE_RECOVERY_AUTHORITY_ROTATION.md)
- account change: `recoveryAuthority()` now returns mutable current account state initialized from the factory-provided recovery authority;
- requesters: current execution owner or current recovery authority;
- cancellation: only the other authority may cancel a pending request;
- completion: permissionless after delay if the request is not expired and the pending authority matches;
- restrictions: one pending request, nonzero pending authority, pending authority different from current owner and current recovery authority;
- invariants preserved: account address, EntryPoint, ActionGate, ownerCommitment, execution owner, `ACTION_UNLOCK`, `proofInputHash`, and `[fact_high, fact_low]`;
- runtime boundary: exact maintenance calldata candidate only, with no signing, submission, vault mutation, or public UserOperation.

Security impact:

- The previous unsupported recovery-authority rotation blocker is remediated for local Alpha.
- Base Sepolia Beta remains blocked pending ACP acceptance, Beta custody approval, deployment evidence, public-network operational controls, and external audit.
- Production still requires threshold or modular recovery.

ACP-0002 remains `Proposed`.

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

## N.4 Rotation And Recovery Evidence

Phase N.4 adds restricted local Alpha validator rotation and delayed recovery without accepting this ACP:

- reference: [PhilCore ERC-4337 Rotation And Recovery](../security/PHILCORE_ERC4337_ROTATION_AND_RECOVERY.md)
- account change: `owner` is now mutable execution-owner state exposed by `owner()`
- immutable bindings preserved: EntryPoint, approved ActionGate, `ownerCommitment`
- normal execution remains ActionGate-only and `verifyAndConsume(...)`-only
- current owner may call `rotateExecutionOwner(address)` directly or through an owner-signed EntryPoint UserOperation
- independent recovery authority may request and complete delayed recovery
- recovery request freezes normal execution during the challenge period
- current owner can cancel recovery during the challenge window
- recovery authority cannot execute ordinary actions, transfer assets, change EntryPoint, change ActionGate, or change `ownerCommitment`

Security impact:

- lost-key recovery is possible in local Alpha if the recovery authority remains available.
- stolen-key containment is partial: the recovery authority can freeze and rotate after delay, but a stolen current owner may still cancel recovery or perform valid ActionGate-bounded actions until contained.
- recovery authority custody is not production-approved.
- threshold/modular recovery remains required for production consideration.

Factory/address impact:

- new account address derivation includes recovery authority and recovery timing configuration.
- after deployment, account address remains stable when execution owner rotates.

ACP-0002 remains `Proposed`.
