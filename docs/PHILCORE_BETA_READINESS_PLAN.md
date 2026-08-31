# PhilCore Beta Readiness Plan

Status: **execution baseline; Beta is not yet authorized**

Target: **controlled Ethereum Sepolia Beta**

Mainnet: **prohibited during Beta**

The concrete address inventory, external-review lane, staged Sepolia approval
protocol, Apple distribution evidence, and physical/trusted-tester minimums
are defined in the
[Controlled Sepolia Beta Gate Approval Packet](./PHILCORE_CONTROLLED_SEPOLIA_BETA_GATE_APPROVAL_PACKET.md).

## Purpose

The Alpha proved that Phil can compose a private root proof, physical iPhone
approval, policy, protected execution signing, restricted ERC-4337 execution,
and replay protection into one successful Sepolia action. Beta must turn that
one-shot technical demonstration into a repeatable, supportable, reviewed
product experience for a small trusted-tester cohort. Public V2 recovery is a
separate future milestone, not a current-Beta exit criterion.

The public introduction demo should use the Beta product only after every gate
below passes. The completed Alpha remains engineering evidence rather than the
surface presented as the finished user experience.

## Alpha baseline

- Frozen source commit `010bbb791c3df080a0c7da5bbbc03158349410ad`,
  tree `2d7b5b3d7e98640dd0ef399ae20677e725b61ea1`.
- Real Desktop Noir proof generation and independent native verification.
- Real enrolled iPhone Secure Enclave P-256 approval with Face ID.
- Proof and phone approval composed against one canonical envelope.
- Protected Device Vault signature over one exact ERC-4337 v0.7 UserOperation.
- Restricted Sepolia account, ActionGate, and zero-value pass consumer deployed.
- Successful pass `1`, receipt reconciliation, nonce advance, and replay
  rejection recorded in the
  [Alpha evidence](./reference/PHIL_SEPOLIA_MINT_ALPHA_EVIDENCE_2026-08-25.md).

## Beta non-goals

- Ethereum mainnet or any other mainnet.
- Meaningful ETH, tokens, credentials, or recoverable user assets.
- Production approval or an unlimited public launch.
- A post-quantum-security claim.
- Calling local Noir/P-256 verification on-chain proof verification.
- Reusing the disclosed Alpha deployer key as a Beta authority or treating the
  disposable Alpha contracts as Beta custody. A separately approved, capped
  funding-only transfer from that address to the fresh Beta deployer is the
  sole owner-accepted exception.
- Public deployment or exercise of V2 recovery, recovery-configuration
  rotation, validator rotation, or the V2 ActionGate during this Beta.

## Current milestone sequence

P4 public recovery execution is closed by canonical scope disclosure and moved
out of the current Beta exit criteria. Recovery remains a long-term product
requirement and must return as a new separately reviewed and explicitly
authorized public V2 milestone.

```text
P4: DEFERRED — NOT PART OF THIS BETA'S PUBLIC EXECUTION EXIT CRITERIA
V2 PUBLIC DEPLOYMENT/RECOVERY EXECUTION IN THIS BETA: NOT PERFORMED
```

The remaining current-Beta milestones are:

1. Phase 7 — P5 restricted cleanup and final reconciliation;
2. Phase 8 — signed packages and physical acceptance; and
3. Phase 9 — final Beta and open-source release decision.

## Gate B0 — repository and evidence baseline

Acceptance criteria:

- Canonical PhilCore repository and documentation map are current.
- Alpha source, package identities, public transaction, receipts, trust
  boundary, and residual deposit are recorded without secrets.
- The protected `pqREADME.md` remains untracked and unchanged.
- Historical repositories and worktrees are classified without deleting their
  evidence.
- Public GitHub contains the accepted stopping-point branch through a reviewed
  pull request.

## Gate B1 — Beta architecture freeze

Implementation candidate: [ACP-0004 Controlled Sepolia Beta](./architecture-changes/ACP-0004-CONTROLLED-SEPOLIA-BETA.md),
with the exact machine-readable profile in
[`config/controlled-sepolia-beta-v1.json`](../config/controlled-sepolia-beta-v1.json).
This candidate still requires independent acceptance before B1 closes.

Decisions required:

- Select one recoverable Beta account model; do not extend the immutable
  one-shot Alpha account in place.
- Freeze validator, recovery, ActionGate, consumer, EntryPoint, nonce, fee,
  expiry, and upgrade/non-upgrade rules.
- Preserve the honest local-verification boundary or adopt an independently
  reviewed on-chain fact/verifier route. No trust-boundary wording may be
  changed without architecture review.
- Define which actions Beta permits. Start with one zero-value test-pass action;
  arbitrary calls, token approvals, delegatecalls, batches, paymasters, and
  generic signing remain forbidden.
- Accept a threat model and architecture change record for the exact Beta
  scope.

Exit evidence: accepted architecture record, exact contract/API surfaces, and
no unresolved critical or high design finding.

## Gate B2 — reusable account and recovery lifecycle

Implementation requirements:

- Operate an already-deployed smart account without replaying `initCode` or
  redeploying infrastructure for every action.
- Read and bind the current EntryPoint nonce before approval; support nonce `1`
  and later while rejecting stale or duplicate requests.
- Define capped prefund/deposit replenishment and a reviewed withdrawal or
  recovery policy so routine test funds are not silently stranded.
- Canonically distinguish the deployed legacy P2/P3 account from the intended
  V2 exact-2-of-3 recovery model and disclose the legacy recovery findings.
- Keep public V2 recovery, validator rotation, recovery-authority configuration
  rotation, and V2 ActionGate execution behind a separate future reviewed
  milestone.
- Reconcile restart, crash, timeout, ambiguous submission, rejected bundler,
  reverted UserOperation, and provider disagreement without automatic retry.

Exit evidence for this Beta: two sequential fresh Sepolia authorizations plus
the canonical P4 boundary disclosure. This is not public V2 recovery evidence.

## Gate B3 — proof, device, and policy hardening

- Freeze canonical bytes across TypeScript, Swift, Noir, Solidity, and bundler
  RPC representations.
- Independently audit proof public inputs, nullifier derivation, scoped identity
  binding, P-256 low-S verification, presentation reconstruction, epochs,
  expiry, revocation, and execution-signature release.
- Keep STWO structurally quarantined from every real-secret and product
  authorization path.
- Require current enrollment and fresh user presence for each Beta action.
- Add real-device negative ceremonies for denial, cancellation, expiry, wrong
  fingerprint, revoked device, changed account/contract/recipient, and restart.
- Establish a documented proof-backend update and vulnerability-response policy.

Exit evidence: no unresolved critical/high finding and accepted cross-language
conformance artifacts.

## Gate B4 — testnet infrastructure and operations

- Create fresh Beta-only deployer, validator, recovery, and provider
  credentials. Never reuse the Alpha key disclosed during testing as Beta
  authority; it may only make the owner-directed capped funding transfer to
  the fresh deployer under the exact staged approval.
- Approve one primary and one read-only reconciliation RPC provider.
- Approve a v0.7 bundler with explicit supported-method, timeout, fee, rate,
  receipt, and ambiguity behavior.
- Store provider and operator secrets outside tracked files and application
  logs; define rotation and revocation.
- Deploy exact reviewed Beta contracts to Sepolia and independently verify
  creation inputs, constructor bindings, runtime code, receipts, and explorer
  records.
- Enforce disposable-fund ceilings, no paymaster, no automatic retry, and a
  separately confirmed public-mutation plan.
- Add monitoring for RPC/bundler availability, stale fees, nonce drift,
  transaction ambiguity, and receipt mismatch without collecting identity
  secrets.

Exit evidence: two-provider reconciliation, an operations runbook, incident
drill, and one bounded successful Beta-candidate UserOperation.

## Gate B5 — external security and dependency review

The refreshed 2026-08-25 dependency triage records zero production-runtime
vulnerabilities and formally accepts the remaining high groups as pinned
development-tooling-only exposure under documented controls. Slither and the
custom invariant suite report zero Beta-blocking findings. These internal
results close the dependency-disposition prerequisite but do not substitute
for the independent external audit required by this gate.

- Freeze the exact contracts, Desktop runtime, iPhone app, SDK, proof circuit,
  public-submission runner, and release configuration for review.
- Complete an independent external audit of contract authority, local proof and
  device composition, Device Vault custody, local transport, recovery, replay,
  and public execution.
- Resolve every critical/high finding and repeat the audit on the corrective
  candidate.
- Re-run static analysis, contract invariants, mutation/fuzz tests, dependency
  review, SBOM generation, secret scanning, and reproducible packaging.
- Exclude development-only high advisories and tooling from distributed runtime
  packages or formally close the exposure with reproducible evidence.

Exit evidence: accepted audit report, zero unresolved critical/high findings,
and exact source/package hashes.

## Gate B6 — signed Beta packages

- Build the Desktop Beta from the frozen source with Developer ID signing,
  Apple notarization, stapling, Gatekeeper validation, and clean-machine launch
  evidence.
- Build the iPhone Beta from the same frozen source identity with an approved
  TestFlight or equivalent controlled distribution profile.
- Verify bundle identifiers, versions, entitlements, privacy strings, local
  network behavior, Keychain/Secure Enclave access, and update compatibility.
- Prove that release packages exclude source-only tools, test secrets, ignored
  local state, RPC credentials, signing material, and disposable evidence.
- Provide signed update, rollback, and revocation procedures.

Exit evidence: independently verified Desktop and iPhone package manifests.

## Gate B7 — physical acceptance and trusted testers

Required physical matrix on the frozen packages:

1. fresh install and enrollment;
2. first successful action;
3. second successful action on the already-deployed account;
4. denial and cancellation;
5. expiry and offline interruption;
6. app/Desktop restart and durable resume;
7. revoked-device rejection and replacement-device enrollment;
8. recovery-boundary disclosure review confirming that the legacy P2/P3 result
   is not represented as V2 recovery evidence;
9. provider/bundler outage and read-only reconciliation;
10. replay attempt rejected locally and on chain.

After the internal matrix passes, admit a small named trusted-tester cohort.
Each tester must receive clear testnet-only, no-meaningful-assets, privacy,
diagnostic, support, update, and revocation disclosures. Collect only sanitized
diagnostics and explicit feedback.

Exit evidence: zero unresolved release-blocking defect across the frozen
physical matrix and initial cohort.

## Gate B8 — public introduction demo

The introduction demo may be labeled **Phil Beta on Ethereum Sepolia** only
after B0-B7 pass. It should show:

1. local Phil identity unlock;
2. a clear zero-value test-pass request;
3. the private proof explanation without exposing root material;
4. iPhone fingerprint comparison and Face ID approval;
5. policy and replay checks;
6. restricted smart-account execution;
7. receipt, pass, account, and explorer result;
8. denial/replay safety in a prepared non-destructive example.

The presentation must say that Ethereum enforces the restricted account
signature and ActionGate while the current Beta verifies Noir and iPhone P-256
locally. It must not imply mainnet, production custody, post-quantum security,
or a completed external ecosystem audit beyond the exact reviewed scope.

## Beta entry verdict

Beta may begin only when every B0-B7 exit criterion is satisfied and a final
review records:

```text
PHILCORE CONTROLLED SEPOLIA BETA READY: YES
```

Until then the only honest verdict is:

```text
PHILCORE CONTROLLED SEPOLIA BETA READY: NO
```

## Separate future mainnet gate

Mainnet is a post-Beta production milestone, not a Beta prerequisite. It
requires a new authority review, production custody and recovery operations,
mainnet contract audit/deployment verification, meaningful-asset policy,
economic limits, incident response, staged rollout, and explicit final
approval. Nothing in this plan authorizes that work.
