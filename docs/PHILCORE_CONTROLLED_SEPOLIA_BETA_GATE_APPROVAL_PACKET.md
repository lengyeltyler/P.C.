# PhilCore Controlled Sepolia Beta Gate Approval Packet

Status: **P1-P3 confirmed; P4 public execution deferred; no P5 mutation is authorized**

Date: 2026-08-27

This packet turns the remaining Beta gates into explicit inputs, evidence, and
approval stages. It is governed by the
[Beta Readiness Plan](./PHILCORE_BETA_READINESS_PLAN.md), the
[controlled Beta profile](../config/controlled-sepolia-beta-v1.json), and the
[operations runbook](./PHILCORE_CONTROLLED_SEPOLIA_BETA_OPERATIONS.md).

Ethereum mainnet, meaningful assets, paymasters, automatic retries, and reuse
of the disclosed Alpha key for any Beta authority remain prohibited. By the
owner's 2026-08-25 direction, the disclosed Alpha address may serve only as a
capped external source for one exactly approved transfer to the fresh Beta
deployer. It is never a Beta role, recipient of released funds, or fallback
signer.

## Decision summary

- Claude may perform an independent **AI security review** of the frozen
  candidate. That is valuable evidence, but it is not represented as a
  professional external audit or third-party warranty.
- The owner accepted the AI-only route on 2026-08-25. The required disposition
  is `AI_REVIEW_PLUS_OWNER_RISK_ACCEPTANCE`; Claude review and corrective
  re-review remain required, while a professional-audit claim is prohibited.
- Closing B5 without qualification requires a named human security reviewer or
  audit firm to own the report and independently verify the corrective
  candidate. If the project instead accepts an AI-only review, the record must
  say `AI_REVIEW_PLUS_OWNER_RISK_ACCEPTANCE`; it must not say `EXTERNALLY_AUDITED`.
- Three distinct Ethereum addresses are the minimum for the current Beta
  deployment and actions. The two replacement addresses belong to the deferred
  recovery/authority-rotation matrix and are not current-Beta exit inputs.
- A plan template can be approved in principle, but no executable Sepolia plan
  is approvable until the fresh addresses, endpoint bindings, live nonce and
  fee observations, bytecode hashes, predicted addresses, exact operation,
  and external-review disposition are populated.
- Sepolia work is split into stages. Each mutating stage receives its own
  canonical plan digest and explicit approval after the preceding receipts are
  reconciled.

## Gate B5: independent review

### Claude review lane

Claude should receive a fresh, read-only checkout of one exact commit and tree,
with no implementation discussion beyond the frozen specifications. The
review must cover every file in
[`config/security/philcore-controlled-sepolia-beta-audit-scope-v1.json`](../config/security/philcore-controlled-sepolia-beta-audit-scope-v1.json)
and must report:

1. reviewer/model identity, date, source commit, source tree, and tool versions;
2. methodology and every file actually inspected;
3. contract authority, reentrancy, validation, nonce, replay, fee, recovery,
   freeze, and disposable-fund analysis;
4. Noir-public-input, P-256, canonical-byte, Device Vault, local transport,
   signing-release, and trust-boundary analysis;
5. deployment, bundler, provider disagreement, timeout, ambiguous submission,
   receipt reconciliation, and incident handling;
6. Desktop/iPhone release configuration, entitlement, contamination, secret,
   dependency, and package analysis;
7. findings with severity, exploit preconditions, exact source locations,
   remediation, and regression-test requirements;
8. explicit confirmation that STWO remains quarantined and that Ethereum does
   not verify the current Noir or iPhone P-256 evidence;
9. residual risks and a verdict with zero unresolved critical/high findings
   required for acceptance; and
10. a SHA-256 digest of the final report.

Claude must not edit the candidate it reviews. Any finding creates a separate
corrective candidate, followed by a fresh read-only re-review.

The copy-ready bounded instruction is
[Claude Controlled Sepolia Beta Audit Prompt](./security/PHILCORE_CONTROLLED_SEPOLIA_BETA_CLAUDE_AUDIT_PROMPT.md).

### Evidence required to close B5

The recommended release-quality route is:

1. Claude independent AI review;
2. corrective implementation and regression tests, if needed;
3. Claude re-review of the corrective commit;
4. named qualified human smart-contract/application-security review of the
   same final commit and packages; and
5. one acceptance record listing the exact source, package, report, SBOM, and
   test-evidence hashes.

An AI-only route is possible only as an explicit owner risk decision for this
harmless, capped Sepolia Beta. It lowers the gate and leaves the project unable
to claim an independent professional audit.

## Gate B4: credentials and addresses

### Required Ethereum addresses

| # | Role | Needed for | Custody rule |
| --- | --- | --- | --- |
| 1 | Beta deployer/operator | Contract deployment, capped funding, gas | Fresh Beta-only EOA; never embedded in source or logs |
| 2 | Initial execution validator | ERC-4337 UserOperation signatures and current-owner fund release | Device Vault or equivalent bounded signer; distinct from deployer and recovery |
| 3 | Initial recovery authority | Delayed freeze/recovery initiation and completion | Separately stored; cannot authorize ordinary actions |
| 4 | Replacement execution validator | Future separately reviewed V2 milestone | Not required or generated for current-Beta P4 closure |
| 5 | Replacement recovery authority | Future separately reviewed V2 milestone | Not required or generated for current-Beta P4 closure |

Addresses 1-3 are the current-Beta set. Addresses 4-5 remain a future recovery
design concern and are not required to close this Beta. The harmless pass
recipient is the current execution-owner address, so a sixth address is not
required. The bundler and RPC providers require service credentials, not
Ethereum signing addresses.

The disclosed Alpha address is not one of these five roles. It may fund only
the Beta deployer, within the total exposure cap and an exact P1 approval. The
fresh Beta deployer may later fund the counterfactual account under P2. The
execution and recovery authority addresses remain unfunded.

No private key, mnemonic, full credential-bearing endpoint, Apple signing
identity, or Secure Enclave private material may be added to this packet or any
tracked file.

### Non-address inputs

- one primary Sepolia JSON-RPC endpoint and API credential;
- one read-only Sepolia JSON-RPC endpoint operated independently from the
  primary provider;
- one ERC-4337 v0.7 bundler endpoint and API credential supporting the official
  EntryPoint at `0x0000000071727De22E5E9d8BAf0edAc6f37da032`;
- sanitized endpoint hostnames plus SHA-256 bindings of the complete endpoint
  values;
- no more than `0.05 ETH` total operator exposure, obtained for Sepolia only;
- a locally generated Phil identity secret/commitment and account salt;
- an enrolled iPhone Secure Enclave P-256 approval key and public fingerprint;
- protected Desktop Device Vault custody for the execution-validator key;
- a local secret store with backup, revocation, and deletion procedures; and
- a named operator responsible for ambiguity resolution and incident stops.

## Staged Sepolia approval plan

The machine-readable starting point is
[`config/ethereum-sepolia/PHILCORE_CONTROLLED_SEPOLIA_BETA_MUTATION_PLAN_TEMPLATE.json`](../config/ethereum-sepolia/PHILCORE_CONTROLLED_SEPOLIA_BETA_MUTATION_PLAN_TEMPLATE.json).
It is intentionally fail-closed and not itself approvable. The controlled P1
planner populates an ignored owner-only plan only after all P0 checks pass; it
cannot broadcast. The P1 executor remains unreachable until the owner provides
the exact digest-specific approval phrase produced by that plan.

### Stage P0 — read-only qualification

Public mutations: **zero**.

Populate and verify the exact source commit/tree, Solidity compiler settings,
creation/runtime bytecode hashes, the three current-Beta Ethereum role
addresses, the two explicitly future V2 recovery/rotation role inputs,
endpoint digests, chain ID, EntryPoint code hash, deployer nonce/balance, fees,
bundler methods, and predicted contract addresses. The two future inputs are
not deployed/live current-Beta addresses and are not current-Beta exit inputs.
Both RPC providers must agree. Complete the audit disposition before moving to
P1.

### Stage P1 — infrastructure deployment

Expected public mutations: **one capped transfer to the fresh Beta deployer
followed by three contract-creation transactions**.

The first transaction transfers no more than the approved requirement from the
disclosed Alpha funding source to the fresh Beta deployer. It grants no Beta
authority. Using one fresh deployer nonce sequence, precompute and independently
confirm:

1. `PhilSepoliaMintPassConsumerV1`, constructed with the predicted ActionGate;
2. `PhilSepoliaLocalComposedActionGateV1`, constructed with chain `11155111`,
   the predicted factory, the consumer, and the one predicted counterfactual
   Beta account it alone may authorize; and
3. `PhilCore4337AccountFactory`, constructed with the official EntryPoint, the
   ActionGate, the initial recovery authority, delay `172800`, and expiry
   `604800`.

The exact order may not change after approval. Reconcile each receipt and
runtime/constructor binding with both RPC providers before P2. A nonce change,
address collision, fee-cap breach, code mismatch, or provider disagreement
invalidates the stage.

If the capped funding transfer confirms but no deployment is accepted, a P1
approval may not be replayed. A `P1R` recovery plan must independently prove
the funding receipt, the rejected deployment hash's absence, unchanged deployer
nonce and balance, and vacant predicted addresses through both providers. It
may contain exactly the three remaining deployments, no funding transaction,
and requires a new exact `P1R` digest approval.

### Stage P2 — account funding and first action

Expected public mutations: **one capped funding transaction and one bundler
submission**.

Compute the counterfactual account from the initial execution validator,
owner commitment, and salt. Fund it with no more than the profile's `0.01 ETH`
native-account ceiling. Prepare one nonce-`0` ERC-4337 v0.7 UserOperation with
factory data, zero action value, empty paymaster data, one exact composed
authorization, and one submission attempt. The proof, phone approval, Device
Vault release, operation hash, expiry, gas, and fees must all be fixed before
P2 approval.

### Stage P3 — second action and replay proof

Completed public mutations: **one bundler submission**.

Implementation status: **complete and independently reconciled**.

After P2 reconciliation, the corrective P3 route used live keyed EntryPoint
nonce `1`, empty `initCode`, a new proof and phone approval, and a fresh
envelope, nullifier, and device nonce. The initial P3 hash was rejected before
acceptance and reconciled absent without retry. Phone-free lifecycle hardening,
exact-source/package review, and one later authorized physical ceremony then
preceded one exact digest-approved submission. UserOperation
`0x7cecc29755c1420f5844047b5c9f22d0f02adcb030db2157fb95bb74979def0d`
confirmed in transaction
`0x2e51d90bc1453cd7f56f906a5d5db375b06fc085913ad3678929142d01b314e0`,
block `11579252`, with zero automatic retries, zero manual resubmissions, and
zero additional funding. Alchemy bundler/primary and PublicNode reconciliation
agreed on final nonce `2`, pass `2`, next token `3`, and all replay/event
bindings. The exact sanitized record is
[Controlled Sepolia Beta P3 Evidence](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P3_EVIDENCE_2026-08-27.md).

### Stage P4 — public recovery and rotation (deferred)

Status:

```text
DEFERRED — NOT PART OF THIS BETA'S PUBLIC EXECUTION EXIT CRITERIA
V2 PUBLIC DEPLOYMENT/RECOVERY EXECUTION IN THIS BETA: NOT PERFORMED
```

Expected public mutations in this Beta: **zero**.

P2/P3 used the deployed legacy `PhilCore4337Account`, not the intended V2
exact-2-of-3 recovery design. The legacy account has three disclosed HIGH
findings: one EOA controls recovery, the current owner alone can cancel, and an
expired request can remain frozen until owner cancellation. V2 source and
substantial local tests exist, but public deployment is not Beta-ready because
of stale artifact pins, an incompatible selected target, incomplete real Beta
initialization/deployment inputs, and unsupported-token stranding risk.

The canonical details are in the
[P4 public-execution scope closure](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P4_SCOPE_CLOSURE_2026-08-27.md).
This is deliberate scope control, not public recovery validation. Any public
V2 deployment, recovery, cancellation, expiry cleanup, validator rotation,
recovery-authority configuration rotation, or V2 ActionGate exercise requires
a new separately reviewed milestone and approval.

### Phase 7 / Stage P5 — disposable-fund release and final reconciliation

Expected public mutations: **one or more separately enumerated cleanup
operations**.

Return the account native balance and EntryPoint deposit only to the current
execution owner using the restricted release method. Reconcile all remaining
balances, deposits, nonces, passes, events, and deployer exposure. No meaningful
asset may ever be sent to the Beta contracts.

### Approval rule

For every mutating stage, generate a canonical JSON body and SHA-256 digest.
The approval request must display:

- stage ID and exact public-mutation count;
- source commit/tree and contract bytecode hashes;
- all public addresses and constructor arguments;
- sanitized provider identities and endpoint digests;
- starting nonces, gas/fee caps, ETH amounts, and maximum total cost;
- exact transaction or UserOperation hashes where applicable;
- expiry and every stop condition; and
- the plan digest.

The literal approval format is:

```text
I_APPROVE_PHILCORE_CONTROLLED_SEPOLIA_BETA_<STAGE_ID>_<64_HEX_PLAN_DIGEST>
```

Approval of this template, a prior Alpha plan, or one stage does not authorize
another stage. Any field change invalidates approval. No automatic retry is
permitted.

## Gate B6: signed Desktop and iPhone packages

### Desktop Beta

Required work and evidence:

1. add a Beta release configuration and a Beta bundle identifier without
   replacing the existing Local Alpha identity;
2. freeze version/build number, source commit/tree, entitlements, embedded
   helpers, proof binaries, SBOM, and package manifest;
3. build on a clean machine with no development tools or secrets in the
   distributed package;
4. sign every nested executable and the application with a Developer ID
   Application certificate, hardened runtime, and secure timestamp;
5. prove `get-task-allow` is absent and explicitly review Electron's JIT,
   unsigned-executable-memory, and library-validation exceptions;
6. submit with Apple's current notarization workflow, retain the accepted log,
   staple the ticket, and verify signatures and Gatekeeper acceptance;
7. install the downloaded artifact on a second clean Mac or clean macOS VM and
   complete first launch, update, rollback, and revocation checks; and
8. publish the signed package manifest, checksums, SBOM, notarization identity,
   and sanitized verification evidence.

The Apple Account Holder must control the Developer ID certificate and
notarization credentials. They are never shared in chat or committed.

### iPhone Beta

Required work and evidence:

1. add a Beta bundle identifier and matching Keychain access group instead of
   distributing the current `.localalpha` configuration;
2. freeze the iOS 17-or-later deployment target, version/build number, source
   identity, entitlements, privacy strings, local-network behavior, and
   Secure Enclave/Keychain migration behavior;
3. create the App ID, distribution signing setup, and controlled provisioning
   through the owner's Apple Developer team;
4. archive and upload the exact Release build to App Store Connect, complete
   encryption/export-compliance answers, and retain build/hash evidence;
5. configure a private TestFlight group, beta description, features to test,
   feedback address, disclosures, and named testers;
6. complete any required Beta App Review before external testing; and
7. verify install, upgrade, revocation, and key persistence/deletion behavior
   on physical phones.

## Gate B7: physical matrix and trusted cohort

### Internal physical matrix

Use the exact notarized Desktop package and exact TestFlight iPhone build. At
minimum, test on one clean Mac and two physical Face ID-capable iPhones across
the supported iOS range where practical. Record package hashes, broad device
model, OS version, result, sanitized receipt/operation identifiers, and defect
ID—never serial numbers, private keys, proofs, identity roots, or raw logs.

The current frozen-package B7 matrix retains ten numbered cases. Case 8 is a
disclosure-boundary review, not recovery execution:

1. fresh install and enrollment;
2. first action and counterfactual account creation;
3. second action on the existing account with empty `initCode`;
4. denial and cancellation;
5. expiry and offline interruption;
6. Desktop/app restart and durable resume;
7. revoked-device rejection and replacement-device enrollment;
8. recovery-boundary disclosure review confirming that the legacy P2/P3 result
   is not represented as V2 recovery evidence;
9. provider/bundler outage and two-provider read-only reconciliation; and
10. local and on-chain replay rejection.

The former delayed-recovery execution case—delayed recovery with no
ordinary-action authority leakage—is **DEFERRED — FUTURE V2 RECOVERY
MILESTONE**. It requires the intended V2 recovery architecture and is not
required to close current B7 or this Beta. Preserving that future case does not
turn legacy-account recovery into evidence for V2 recovery.

Every release-blocking defect requires a corrected frozen build and a repeat of
the affected case plus the core success/replay cases.

### Trusted-tester cohort

Recommended minimum: **three named testers in addition to the operator**, with
at least two distinct iPhone models and one independently installed Desktop
environment across the cohort. This is a private cohort, not a public link.

Each tester receives testnet-only/no-meaningful-assets, local-verification,
privacy, diagnostics, support, update, and revocation disclosures. Each tester
must complete fresh install, enrollment, denial, two sequential actions,
restart/resume, and feedback. The provider-outage drill may remain operator-led
if its evidence covers the frozen packages. Public legacy recovery execution,
V2 recovery deployment, V2 delayed recovery, and V2 recovery-authority
rotation remain deferred and are not current-Beta tester or operator exit
requirements.

B7 closes only after every current frozen-package case above has evidence, all
release-blocking defects are resolved, and the initial cohort has no unresolved
critical/high security finding or data-loss/replay defect. The separately
preserved future V2 delayed-recovery case does not block current B7 or current
Beta completion.

## Current approval status

```text
CLAUDE INDEPENDENT AI REVIEW READY TO REQUEST: YES
AI_REVIEW_PLUS_OWNER_RISK_ACCEPTANCE RECORDED: YES
PROFESSIONAL EXTERNAL AUDIT COMPLETE: NO
BETA PROVIDER CREDENTIAL SET COMPLETE: YES
BETA AUTHORITY CREDENTIAL SET COMPLETE: YES
LEGACY ALPHA FUNDING-ONLY SOURCE ACCEPTED: YES
P2 FIRST COMPOSED ACTION CONFIRMED: YES
P3 RUNNER IMPLEMENTED: YES
P3 INITIAL SUBMISSION REJECTED AND RECONCILED: YES
P3 CORRECTIVE RUNNER IMPLEMENTED: YES
P3 CORRECTIVE EXACT-SOURCE INDEPENDENT REVIEW COMPLETE: YES
P3 PHONE-FREE CEREMONY RELIABILITY IMPLEMENTED: YES
P3 PHONE-FREE CEREMONY RELIABILITY INDEPENDENTLY ACCEPTED: YES
P3 CORRECTIVE PHONE CEREMONY COMPLETE: YES
P3 EXACT DIGEST-SPECIFIC MUTATION APPROVAL ACCEPTED: YES
P3 SINGLE SUBMISSION CONFIRMED AND RECONCILED: YES
P3 CANONICAL STATUS: COMPLETE AND RECONCILED
P4 PUBLIC EXECUTION STATUS: DEFERRED
LEGACY RECOVERY HIGH FINDINGS DISCLOSED: YES
V2 PUBLIC RECOVERY EXECUTED IN THIS BETA: NO
SIGNED BETA PACKAGES COMPLETE: NO
PHYSICAL MATRIX AND TRUSTED COHORT COMPLETE: NO
PHILCORE CONTROLLED SEPOLIA BETA READY: NO
```
