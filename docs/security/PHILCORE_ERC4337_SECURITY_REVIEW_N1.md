# PhilCore ERC-4337 Security Review N.1

Phase: N.1

Status: internal adversarial review, not an external audit.

Recommendation: `recommended_for_local_alpha_only`

ACP-0002 remains `Proposed`.

## Scope

Reviewed revision: `0f58add` with the local Phase M.9-M.11 working tree.

Reviewed components:

- `contracts/base/erc4337/PhilCore4337Account.sol`
- `contracts/base/erc4337/PhilCore4337AccountFactory.sol`
- EntryPoint v0.7 from `@account-abstraction/contracts@0.7.0`
- `contracts/base/PhilBaseActionGate.sol`
- `contracts/base/PhilUnlockConsumer.sol`
- `contracts/base/PhilBaseProofInputHashMirror.sol`
- `contracts/base/PhilBaseMirroredFactUnlockProofVerifier.sol`
- M.9 UserOperation preparation runtime boundary
- M.10 UserOperation signing runtime boundary
- M.11 bundler submission and receipt monitoring runtime boundary
- local ERC-4337 and Base execution tests/fixtures

Out of scope:

- production Device Vault custody approval;
- live Base Sepolia deployment;
- live bundler submission;
- paymasters;
- session keys;
- upgradeability;
- external audit certification.

## Architecture Reviewed

The local route is:

```text
Base execution preparation
  -> PackedUserOperation preparation
  -> UserOperation authorization and signing
  -> restricted local submission
  -> EntryPoint v0.7 handleOps(...)
  -> PhilCore4337Account.execute(...)
  -> PhilBaseActionGate.verifyAndConsume(...)
  -> nullifier consumption
  -> consumer execution
```

`PhilCore4337Account` is a minimal EntryPoint v0.7 account. Direct owner calls to `execute(...)` are blocked, but EntryPoint-mediated calls signed by the configured owner can call arbitrary targets. Runtime and signer custody therefore remain critical authorization boundaries.

## Threat Model

### Assets

- smart-account ETH and tokens;
- validator signing authority;
- owner address;
- `ownerCommitment` identity-binding metadata;
- Capability Grants;
- finalized Authorization Packages;
- public nullifiers;
- mirrored proof facts;
- consumer-controlled assets;
- Runtime audit records;
- account deployment salts and factory data.

### Adversaries

- malicious application;
- compromised application frontend;
- malicious bundler;
- malicious relayer;
- malicious RPC provider;
- malicious or compromised validator signer;
- stolen ECDSA validator key;
- compromised Device Vault;
- unauthorized direct caller;
- malicious smart-account owner;
- front-runner;
- replay attacker;
- factory front-runner;
- counterfeit account/factory deployment;
- wrong-chain attacker;
- cross-domain fact injector;
- malicious consumer contract;
- reentrant target;
- denial-of-service attacker.

### Trust Assumptions

Trusted or assumed-correct for local Alpha:

- local Hardhat chain;
- local EntryPoint v0.7 fixture;
- PhilCore Runtime test harness;
- fixture signer;
- local proof/fact fixtures.

Verified at boundary:

- EntryPoint address/version and `getUserOpHash(...)`;
- chain ID;
- account owner and `ownerCommitment`;
- nonce/gas/fee/prefund snapshots;
- paymaster-disabled state;
- mirrored fact state;
- nullifier state;
- consumer execution evidence;
- Base mirror messenger caller and remote sender.

Untrusted:

- applications;
- bundlers;
- RPC providers;
- relayers;
- consumers unless specifically authorized;
- user-supplied UserOperation fields;
- public-network deployment/configuration until separately accepted.

## N.3 Custody Update

Phase N.3 adds a local Alpha Device Vault ECDSA custody boundary:

- validator keys are generated randomly, not derived from `phil_secret`, `identityRoot`, or `ownerCommitment`;
- private keys are stored only in encrypted validator records;
- only public owner metadata and opaque key references are returned;
- M.10 signing is supported through one-time exact UserOperation-hash signing sessions;
- arbitrary message, transaction, and typed-data signing remain blocked.

This partially remediates `N1-MED-002`, but Base Sepolia Beta remains blocked because account-level owner rotation, production recovery, external audit, accepted deployments, and ACP-0002 acceptance are not complete.

## N.4 Rotation And Recovery Update

Phase N.4 adds restricted local Alpha owner rotation and delayed recovery:

- normal execution owner can rotate to a new owner through `rotateExecutionOwner(address)`;
- independent recovery authority can request recovery to a pending owner;
- recovery freezes normal ActionGate execution during the challenge period;
- current owner can cancel recovery;
- recovery authority cannot execute ordinary actions, transfer assets, change ActionGate, change EntryPoint, or change `ownerCommitment`.

This further remediates `N1-MED-002` for local Alpha. Production remains blocked until recovery-authority custody, threshold/modular recovery, static analysis, dependency review, deployment verification, and external audit are complete.

Phase N.5 adds local Alpha recovery-authority custody and workflow evidence:

- recovery authority keys are separate purpose-bound encrypted Device Vault records;
- recovery signing sessions are one-time and exact-hash;
- recovery authority signing is restricted to `requestRecovery(address)` and `completeRecovery(bytes32,address)`;
- recovery authority cancellation is rejected;
- local EntryPoint tests cover lost-key recovery through request, freeze, challenge delay, completion, owner rotation, unfreeze, and Device Vault state coordination.

This further remediates `N1-MED-002` for local Alpha. Base Sepolia Beta remains blocked until the Beta recovery custody model, deployment evidence, public-network controls, and external audit are resolved.

### Phase N.6 Update

N.6 establishes a repository-local Slither 0.10.4 environment, runs Solidity static analysis, adds 17 custom PhilCore contract invariant checks, and performs dependency advisory triage. Slither reports 0 critical and 0 high Solidity findings. One production-relevant medium finding remains open for `PhilMintPassConsumer` locked ETH before value-bearing deployment of that consumer.

N.6 also applies a non-forced lockfile remediation that reduces `npm audit` from 20 advisories to 16. The original high advisory groups for `lodash` and Hardhat-nested `ws` are no longer reported. `serialize-javascript`, `tmp`, and `undici` remain high transitive Hardhat/tooling advisories; none are classified as PhilCore production runtime exposure, but Base Sepolia Beta remains blocked until they are remediated or formally accepted.

### Phase N.7 Update

N.7 remediates the `PhilMintPassConsumer` value risk by making the consumer zero-value-only: nonzero `msg.value` now reverts before mint state changes. N.7 also adds an eighteenth custom invariant for this guard.

N.7 formally accepts the remaining `serialize-javascript`, `tmp`, and `undici` high advisory groups as development-tooling-only risk pending a reviewed Hardhat/toolchain migration. They remain excluded from production runtime exposure and must not be shipped in production runtime bundles.

### Phase N.8 Update

N.8 adds bounded recovery-authority rotation:

- current owner or current recovery authority may request a new recovery authority;
- the other authority may cancel during the challenge window;
- completion is permissionless after the delay;
- the pending recovery authority is inactive before completion;
- rotation cannot change EntryPoint, ActionGate, `ownerCommitment`, execution owner, or account address;
- rotation performs no external calls, value transfers, ActionGate execution, or consumer execution.

This further remediates `N1-MED-002` for local Alpha. Base Sepolia Beta remains blocked until ACP-0002 acceptance, Beta custody approval, deployment evidence, public-network operational controls, and external audit are complete. Production still requires threshold or modular recovery.

## Methodology

- Manual line-by-line review of account, factory, ActionGate, mirror, verifier, consumer, and Runtime boundaries.
- Deterministic adversarial tests for account execution, CREATE2 derivation, signed-field mutation, mirror caller restrictions, and ActionGate atomicity.
- Regression test for M.11 receipt verification strictness.
- Solidity compiler warning check through Hardhat compile.
- Dependency review with `npm ls` and `npm audit`.
- Dangerous-pattern grep for `delegatecall`, `selfdestruct`, `tx.origin`, assembly, low-level calls, paymaster use, and signature primitives.
- Slither 0.10.4 completed through the N.6 repository-local environment.
- Custom PhilCore contract invariant checks pass, including the N.7 MintPass zero-value invariant and N.8 recovery-authority rotation invariants.

## Contract Review Summary

### PhilCore4337Account

Positive findings:

- EntryPoint is immutable.
- Owner is mutable only through explicit bounded owner rotation and delayed recovery maintenance paths.
- `ownerCommitment` is immutable.
- zero EntryPoint and zero owner are rejected.
- direct owner calls to `execute(...)` revert.
- no proxy, upgrade, `delegatecall`, assembly, `tx.origin`, or `selfdestruct` pattern was found.
- signatures are domain-bound by EntryPoint v0.7 `userOpHash`, which includes EntryPoint and chain ID.
- OpenZeppelin ECDSA handles malformed/high-`s` signatures by failure/revert under EntryPoint validation.

Important limitation:

- the account can execute arbitrary calls when the configured owner signs a matching EntryPoint UserOperation. The account does not enforce ActionGate-only execution on-chain.

### PhilCore4337AccountFactory

Positive findings:

- EntryPoint is immutable.
- zero EntryPoint and zero owner are rejected.
- CREATE2 bytecode hash includes constructor arguments: EntryPoint, owner, and `ownerCommitment`.
- copied parameters can predeploy the same account, but cannot alter owner, EntryPoint, or `ownerCommitment`.
- duplicate deployment returns the existing account.
- no admin, proxy, implementation replacement, or upgrade control exists.

Limitation:

- public `createAccount(...)` allows third parties to deploy a predicted account for the intended owner. This is not ownership theft, but it can affect operational timing and funding assumptions.

### EntryPoint Integration

Positive findings:

- runtime hash calculation matches actual EntryPoint v0.7 `getUserOpHash(...)`.
- nonce replay is blocked by EntryPoint.
- signed-field mutation invalidates execution.
- paymaster data is rejected in runtime boundaries and expected empty in receipts.
- counterfactual deployment path is tested locally.

Limitations:

- Base Sepolia bundler compatibility is not proven.
- durable duplicate/ambiguous submission reconciliation is not implemented.

### ActionGate And Consumer

Positive findings:

- proof public inputs must match authorization fields.
- `proofInputHash` is recomputed on-chain.
- nullifier is checked before consumer call.
- nullifier is marked before consumer call, blocking same-nullifier reentrancy.
- consumer revert rolls back nullifier mutation.
- direct consumer access is blocked by `PhilUnlockConsumer`.

Limitations:

- authorized consumers are trusted execution modules. A malicious authorized consumer can define hostile semantics for its own `consumePhilAuthorization(...)`. Runtime must authorize only reviewed consumers for meaningful assets.

### Cross-Domain Fact Route

Positive findings:

- Base mirror requires the configured cross-domain messenger as `msg.sender`.
- Base mirror checks the authorized L1 remote sender.
- verifier composes `[fact_high, fact_low]` into the exact proof-input hash and checks mirror state.

Limitations:

- live Starknet/L1/Base deployment bindings are not accepted yet.
- public-network finality, relay, and monitoring behavior remain pre-Beta work.

## Tests Added

- `test/unit/philcore-erc4337-security-review-n1.test.cjs`
- `contracts/base/mocks/PhilAdversarialAuthorizationConsumer.sol`

Coverage added:

- direct owner calls blocked;
- valid owner signatures can execute arbitrary EntryPoint-mediated calls;
- signed UserOperation field mutation invalidates signatures;
- deterministic CREATE2 derivation fuzzing over owners, commitments, and salts;
- gas/fee packing overflow rejection;
- ActionGate same-nullifier reentrancy fails;
- consumer revert rolls back nullifier state;
- malicious consumer cannot directly call `account.execute(...)`;
- unauthorized Base mirror direct injection fails;
- wrong remote sender mirror update fails.

M.11 regression added:

- included UserOperation receipts are rejected unless explicit inner execution, nullifier, and consumer verifiers are supplied.

## Static And Dependency Results

Slither: unavailable locally (`slither: command not found`). Manual dangerous-pattern review was performed.

Compiler: Hardhat compile passed after adding adversarial fixture.

Dangerous-pattern grep:

- no `delegatecall`;
- no `selfdestruct`;
- no `tx.origin`;
- no assembly in reviewed contracts;
- low-level calls exist in:
  - `PhilCore4337Account.execute(...)`;
  - `PhilUnlockConsumer.consumePhilAuthorization(...)`;
  - local/mock messenger fixtures;
  - adversarial test fixture.

Dependency versions:

- `@account-abstraction/contracts@0.7.0`
- `@openzeppelin/contracts@5.0.0`
- `ethers@6.16.0`
- `hardhat@2.28.4`
- `starknet@10.0.2`

`npm audit --audit-level=low` reported 22 advisories, including high-severity advisories in transitive dev/test tooling and a moderate OpenZeppelin advisory affecting `@openzeppelin/contracts@5.0.0`. Dependencies were not updated in N.1.

## Findings Table

| ID | Severity | Title | Status | Production Blocking |
| --- | --- | --- | --- | --- |
| N1-HIGH-001 | High | Owner-signed EntryPoint calls can execute arbitrary account targets | Open | Yes |
| N1-MED-002 | Medium | Production custody, rotation, and recovery for Beta ECDSA owner are missing | Locally remediated; Beta review required | Yes |
| N1-MED-003 | Medium | Custom account/factory are unaudited | Open | Yes |
| N1-MED-004 | Medium | M.11 receipt monitoring allowed permissive default execution evidence | Fixed | No |
| N1-MED-005 | Medium | Dependency audit reports unresolved advisories | Open | Before public beta |
| N1-LOW-006 | Low | Slither/static analyzer unavailable in local review environment | Open | Before external audit package |
| N1-LOW-007 | Low | Authorized consumer contracts are trusted execution modules | Open | For unreviewed consumers |

## Detailed Findings

### N1-HIGH-001: Owner-signed EntryPoint calls can execute arbitrary account targets

Component: `PhilCore4337Account`

Description: `execute(address,uint256,bytes)` only requires the caller to be EntryPoint or the account itself. It does not restrict `target` to `PhilBaseActionGate`.

Attack scenario: an attacker obtains the owner key, tricks the signer, or bypasses Runtime signing controls, then submits a valid EntryPoint UserOperation that calls an arbitrary target from the account.

Impact: account funds and approvals can be used outside PhilCore Runtime policy.

Likelihood: medium until production custody is implemented; high if the owner key is exposed.

Evidence: `philcore-erc4337-security-review-n1.test.cjs` proves direct owner calls fail but valid owner-signed EntryPoint calls can invoke arbitrary targets.

Recommended remediation: before Base Sepolia Beta with meaningful assets, decide whether to accept this as a custody-bound Beta risk or revise the account to enforce ActionGate-only or module-restricted execution on-chain. This may require Architecture Change Control.

Status: open.

### N1-MED-002: Production custody, rotation, and recovery for Beta ECDSA owner are missing

Component: Runtime/Device Vault/Account authority

Description: the current signer is a Beta ECDSA model with local Device Vault custody, owner rotation, delayed recovery, recovery-authority custody, and N.8 recovery-authority rotation. Beta custody approval, public-network operations, external audit, threshold/modular production recovery, and stronger stolen-key response remain incomplete.

Impact: loss or theft of the owner key can permanently compromise or strand the smart account.

Recommended remediation: review and accept the local Device Vault-backed owner/recovery lifecycle for Beta, externally audit recovery-authority rotation, and define threshold or modular recovery before production.

Status: locally remediated for Alpha; Beta remains blocked.

### N1-MED-003: Custom account/factory are unaudited

Component: `PhilCore4337Account`, `PhilCore4337AccountFactory`

Description: the account and factory are intentionally minimal but custom and unaudited.

Impact: unknown smart-account implementation risk.

Recommended remediation: external review/audit before public-network deployment with value.

Status: open.

### N1-MED-004: M.11 receipt monitoring allowed permissive default execution evidence

Component: `philcore4337BundlerSubmission.ts`

Description: initial M.11 receipt monitoring could approve a successful included receipt without explicit inner execution, nullifier, and consumer verifiers.

Impact: a caller could treat inclusion as sufficient execution proof.

Remediation: fixed in N.1. Receipt monitoring now requires explicit verifiers before producing a successful bounded execution receipt.

Regression: `philcore-erc4337-bundler-submission.test.cjs` rejects included receipts without verifiers.

Status: fixed.

### N1-MED-005: Dependency audit reports unresolved advisories

Component: dependency stack

Description: `npm audit` reports unresolved advisories in OpenZeppelin, ethers/ws, Hardhat transitive dependencies, and dev tooling.

Impact: varies by package. The OpenZeppelin advisory should be reviewed before public deployments. Dev-tooling advisories affect local/build/test exposure.

Recommended remediation: dependency review/update plan in a dedicated remediation phase.

Status: open.

### N1-LOW-006: Slither unavailable

Component: static analysis

Description: Slither was not installed during N.1, so that review used compiler warnings and manual dangerous-pattern grep. N.6 supersedes this local tooling gap with a repository-local Slither 0.10.4 environment and machine-readable analysis reports.

Recommended remediation: keep the N.6 pinned static-analysis tooling reproducible locally and add an equivalent CI job before external audit preparation.

Status: remediated for local reproducibility; CI/external audit remain required.

### N1-LOW-007: Authorized consumer contracts are trusted execution modules

Component: ActionGate/consumer integration

Description: ActionGate authenticates proof/authorization and calls the authorized consumer, but the consumer defines its own semantics.

Impact: authorizing a malicious consumer can intentionally perform malicious behavior within the authorized action.

Recommended remediation: maintain a reviewed allowlist/catalog of consumer contracts and bind Runtime capabilities to consumer identities.

Status: open.

## Recovery And Rotation Gap Analysis

Missing before Base Sepolia Beta:

- production key generation;
- Device Vault custody for the owner key;
- unlock requirements for signing;
- key rotation;
- owner rotation/migration;
- stolen-key response;
- lost-key recovery;
- multi-device trust ceremony;
- recovery credential policy;
- emergency capability revocation.

Missing before production:

- external audit;
- operational runbooks;
- durable submission reconciliation;
- monitored deployment/configuration registries;
- tested recovery drills;
- explicit asset/value limits.

## ACP-0002 Decision

Classification: `recommended_for_local_alpha_only`

ACP-0002 should not be accepted for Base Sepolia Beta yet.

Required before Base Sepolia Beta:

- resolve N1-HIGH-001 by explicit Architecture Change Control decision or on-chain restriction;
- implement production custody/rotation/recovery plan for the Beta owner key;
- address M.11 verifier strictness, completed in N.1;
- preserve dependency advisory controls and production-runtime exclusion;
- add static-analysis tooling;
- define value limits and operational runbooks;
- perform at least one external review pass.

Production recommendation: not production-ready. External audit is required before meaningful assets are used.

## Architecture Self-Check

- Did N.1 violate Architecture Change Control? No.
- Is ACP-0002 still proposed? Yes.
- Is the account custom and unaudited? Yes.
- Can the account execute arbitrary calls with a valid owner signature? Yes, through EntryPoint.
- Can Runtime restrictions be bypassed by anyone possessing the owner key? Yes.
- Can direct owner calls execute without EntryPoint? No.
- Is signature domain separation correct? Local evidence says yes for EntryPoint v0.7 `userOpHash`, chain ID, and EntryPoint address.
- Is counterfactual deployment safe? Local evidence says altered owner/commitment/salt changes the predicted address; copied-parameter deployment cannot alter initialization.
- Can factory deployment be front-run maliciously? It can be predeployed with copied parameters, but not with altered initialization at the same address.
- Is nullifier atomicity preserved? Local evidence says yes.
- Can a malicious consumer reenter or redirect execution? Same-nullifier reentry fails; consumers remain trusted modules for their own semantics.
- Can the Base mirror be injected by unauthorized callers? Local evidence says no.
- Are paymasters, session keys, batching, and upgrades still disabled? Yes.
- Critical/high findings remaining: N1-HIGH-001.
- Acceptable for local Alpha? Yes.
- Acceptable for Base Sepolia Beta? Not yet.
- External audit required before meaningful assets? Yes.

## Commands Run

- `npm run compile`
- `npm run typecheck`
- `npx hardhat test test/unit/philcore-erc4337-bundler-submission.test.cjs test/unit/philcore-erc4337-security-review-n1.test.cjs`
- `npm audit --audit-level=low`
- `npm ls @account-abstraction/contracts @openzeppelin/contracts ethers hardhat starknet --depth=0`
- dangerous-pattern `rg` scan

Additional full-suite verification is tracked in the Phase N.1 final report.

## N.2 Targeted Remediation Update

N.2 selected the ActionGate-restricted account model for Base Sepolia Beta.

Implemented contract changes:

- `PhilCore4337Account` now stores immutable `approvedActionGate`.
- `execute(address,uint256,bytes)` may be called only by EntryPoint.
- `execute(...)` rejects any target other than `approvedActionGate`.
- `execute(...)` rejects calldata whose selector is not `PhilBaseActionGate.verifyAndConsume(...)`.
- Account-self execution through `execute(...)` is disabled, preventing `EntryPoint -> account.execute(account, ...) -> nested execute(...)` bypasses.
- `PhilCore4337AccountFactory` is bound to one immutable approved ActionGate and deploys accounts with that binding.

Runtime changes:

- M.9/M.10/M.11 account verification now checks the deployed account's approved ActionGate.
- Runtime preparation still requires the exact ActionGate target and `verifyAndConsume(...)` calldata. Contract enforcement does not replace Runtime policy checks.

Updated finding status:

- `N1-HIGH-001`: remediated for the selected ActionGate-restricted Beta model.
- `N1-MED-002`: deferred; Device Vault ECDSA custody remains required before Base Sepolia Beta.
- `N1-MED-003`: requires external audit.
- `N1-MED-004`: remediated in N.1 and preserved in N.2.
- `N1-MED-005`: partially remediated; direct `ethers` and OpenZeppelin patches applied, remaining advisories are primarily Hardhat/transitive tooling.
- `N1-LOW-006`: partially remediated; reproducible Slither command added, pinned tool still must be installed locally.
- `N1-LOW-007`: partially remediated through documented consumer trust requirements.

Base Sepolia Beta remains blocked. See [PhilCore Base Sepolia Beta Security Gate](./PHILCORE_BASE_SEPOLIA_BETA_SECURITY_GATE.md).
