# PhilCore Beta Execution Status

Status date: 2026-08-31

Controlled Beta technical/UI development, P2/P3/P5, signed Desktop distribution,
and the revised final physical session are complete. P4 remains deferred.
Public-source release is still gated on final blocker remediation; completed
Beta development is not a production or mainnet approval.
See [final release status](./PHILCORE_CONTROLLED_SEPOLIA_BETA_FINAL_RELEASE_STATUS.md)
for the exact source/freeze binding, Q2 accidental approval, Q3 rejection,
iOS build 58, and security nonclaims.

## Historical execution log

The following entries preserve the chronological evidence and original stop
conditions. Earlier blocked states are superseded only by the final status
above; no failed attempt is relabeled successful.

## Work completed in this Beta pass

- Added explicit on-chain paymaster rejection.
- Added explicit zero-value enforcement for ordinary ActionGate execution.
- Added composed-gate selector compatibility to the reusable account.
- Registered reusable factory accounts for composed-gate authorization.
- Added current-owner-only release of disposable native balance and EntryPoint
  deposit; recovery authority and frozen accounts cannot use it.
- Added local tests for counterfactual first use, sequential nonce `1`, empty
  second `initCode`, replay rejection, non-zero rejection, recovery freeze,
  fund release, and paymaster rejection.
- Passed the exact Node 26.0.0/npm 11.12.1 product-runtime, Solidity,
  Desktop, proving, and deterministic-evidence lanes.
- Regenerated and reverified the Step 4, Step 6C, and Step 6C-2 deterministic
  manifests after the reviewed account/factory changes.
- Passed Slither triage with zero Beta-blocking findings, all 41 custom
  contract invariants, dependency triage, and the audit-package checker.
- Added the fail-closed Beta Gate Approval Packet: three current-Beta authority
  addresses plus two future recovery-role addresses, Claude/human review lanes,
  staged Sepolia mutation approvals, signed-package evidence, ten physical
  cases, and a three-tester minimum.
- Retired the obsolete Alpha public-mutation runner before any artifact,
  approval, secret, or network handling.
- Added the controlled P0/P1 runner: a no-send planner that freezes four exact
  transaction hashes and an executor that cannot read its plan or touch
  endpoints/Keychain until the digest-specific owner approval matches.
- Recorded Claude's clean corrective re-review of commit `8fac929`: accepted,
  zero unresolved critical/high findings, and no professional-audit claim.
- Recorded Claude's exact-source review of P1 runner commit `5e68d23`: accepted,
  zero unresolved critical/high findings, and no professional-audit claim.
- Executed the approved P1 funding mutation. Both providers confirm it in block
  `11567203`. The first deployment transaction was rejected before acceptance;
  the deployer nonce remains zero, all predicted addresses remain vacant, and
  the no-retry executor preserved a fail-closed incident receipt.
- Added a separately review- and approval-gated `P1R` recovery path that
  can submit only the three remaining deployment transactions after proving the
  original funding receipt and rejected deployment absence on both providers.
- Executed the exact approved P1R plan digest
  `0x2934e38a2e6ca80f6c7011a4c45b38b0943182ee8c2473541e2a0ec66467d673`.
  All three zero-value deployments confirmed once, with no retry, at the frozen
  addresses. Alchemy and Infura independently agree on receipts, runtime code,
  constructor bindings, deployer nonce `3`, and the still-counterfactual
  account address.
- Reconciled a post-deployment verifier stop to an ethers method-name collision,
  not an on-chain binding defect. The factory prediction query now selects the
  full Solidity signature and has regression coverage. The original stopped
  receipt remains preserved as incident evidence.
- Recorded the complete public evidence in
  [Controlled Sepolia Beta P1 Evidence](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P1_EVIDENCE_2026-08-25.md).
- Added a Beta-only P2 configuration and guarded workflow that rejects the
  retired Alpha account graph and stale account-as-recipient binding. The local
  composition path requires a fresh physical enrollment, real Noir proof,
  exact iPhone approval, durable replay reservation, and purpose-bound
  encrypted Device Vault signature before it writes a signed-unsubmitted
  artifact. The reviewed iOS app enforces Secure Enclave/user-presence locally,
  while P2 explicitly records that remote hardware/app attestation is not
  established and a malicious alternate client is outside this controlled
  owner-operated threat model.
- Completed P2 through separately approved, one-shot stages. The original P2
  funding transaction confirmed; rejected UserOperations were preserved and
  reconciled without retry; P2A deployed the exact prefunded account; and the
  final P2F factory-free nonce-`0` UserOperation confirmed in block `11573471`
  with no additional funding.
- Independently reconciled the final P2 state through Alchemy and PublicNode:
  account nonce `1`, all three replay fields consumed, pass token `1` owned by
  the execution validator, token balance `1`, next token ID `2`, and exactly
  one expected EntryPoint, gate, and pass event.
- Recorded the complete public sequence, incident boundaries, exact source,
  reviews, plan digests, receipt hashes, and trust-boundary nonclaims in
  [Controlled Sepolia Beta P2 Evidence](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P2_EVIDENCE_2026-08-26.md).
- Initially implemented the P3 second-action runner before phone or chain activity. It
  requires nonce `1`, empty `initCode`, fresh proof/device replay fields,
  exact P2 plan/receipt evidence, a read-only stale-P2 nonce rejection, one
  digest-approved bundler submission, a P3-only durable lock, zero funding,
  no retry, and two-provider final reconciliation to nonce `2` and pass `2`.
  See the
  [P3 implementation report](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P3_IMPLEMENTATION_REPORT_2026-08-26.md).
- Completed the initial P3 proof and physical-phone ceremony and obtained a
  digest-specific owner approval. The single bundler submission was rejected
  before acceptance because verification-gas efficiency was below the
  bundler's threshold. No automatic retry occurred.
- Reconciled the rejected P3 hash as absent from the bundler and confirmed
  through both providers that nonce `1`, next token `2`, account balance,
  EntryPoint deposit, P2 pass `1`, and all P2 replay fields were unchanged.
- Implemented a corrective P3-only `80000` verification-gas cap and a frozen
  rejected-hash absence gate. The accepted P2/P2F gas behavior is unchanged.
- Recorded the accepted corrective review of `fe5ae94` (zero unresolved
  critical/high, one LOW, two informational), then stopped after a later
  enrollment failed before accepted enrollment persistence. Phase 1 adds
  owner-only sanitized stage/counter evidence, explicit expiry/cancellation,
  safe-resume versus restart-invalidation rules, stale-attempt isolation, and
  companion version/build/source display. All Phase 1 evidence is phone-free;
  no P3 plan, signed artifact, approval, submission, or public mutation was
  created.
- Froze Phase 1 source commit
  `a5e38dba06dbc4c915ad1b640f617d758926009d`, tree
  `96608f943e551ef860f210e872fe3f910959cd7b`, and the fresh build-56 package.
  Independent Phase 2 source/package review found zero CRITICAL/HIGH/MEDIUM,
  two LOW, and four INFORMATIONAL findings; independent AI review is not a
  professional audit.
- Completed exactly one later authorized physical P3 attempt using the frozen
  package. Fresh enrollment, one preflight, accepted persistence, the distinct
  second authorization scan, user-presence P-256 approval, real local Noir
  proof verification, exact local composition, and Device Vault release
  produced exactly one signed-but-unsubmitted artifact and no public mutation.
- Created one no-send plan with digest
  `0x28b7ce5e86e39c24a692c7dd96420b0ad7f5ab44fd3e3eced46bf945d4d5c16a`.
  After a separate exact owner approval, the executor submitted UserOperation
  `0x7cecc29755c1420f5844047b5c9f22d0f02adcb030db2157fb95bb74979def0d`
  once, with zero automatic retries and zero manual resubmissions.
- Reconciled transaction
  `0x2e51d90bc1453cd7f56f906a5d5db375b06fc085913ad3678929142d01b314e0`
  in block `11579252` through the Alchemy bundler, Alchemy primary RPC, and
  PublicNode. Final state is nonce `2`, pass balance `2`, token `2` owned by
  the execution validator, next token ID `3`, fresh P3 replay consumption, and
  retained P2 replay consumption, with exactly one expected event of each kind.
- Reconciled the `355963906821700` wei UserOperation charge as
  `79825386307930` wei from the pre-existing EntryPoint deposit plus
  `276138520513770` wei supplied from the account's existing native balance as
  missing prefund. The separate bundler transaction gas cost was
  `280837609313392` wei. See the
  [canonical P3 evidence](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P3_EVIDENCE_2026-08-27.md).
- Closed current-Beta P4 scope through the canonical
  [P4 public-execution scope closure](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P4_SCOPE_CLOSURE_2026-08-27.md).
  P2/P3 used the legacy account, whose single-EOA recovery, owner-only
  cancellation, and expired-request freeze behavior are disclosed as HIGH
  findings. V2 exact-2-of-3 source remains local and undeployed; its public
  deployment and recovery require a separate future reviewed milestone.
- Preserved P5 attempt 1 as permanently consumed after its one submission was
  rejected before bundler acceptance. Exact-hash and two-provider
  reconciliation established zero chain mutation. The original provider
  rejection payload was not recovered, so observability remains MEDIUM and the
  exact root cause is not claimed.
- Corrected future P5 admission policy to select
  `max(ceil(raw priority fee * 5 / 4), 100000000)` within the unchanged
  `100000000` absolute priority cap. P2/P3 behavior and the P5 call/
  pre-verification gas ceilings are unchanged.
- Added a separate `actualValidationGas / verificationGasLimit >= 2 / 5`
  admission model. Exact P5 EntryPoint v0.7 simulation measured `37050`, giving
  the safety/efficiency interval `46313..92625`. The future planner
  integrity-binds that evidence and selects final `verificationGasLimit=80000`
  without applying the 125% margin a second time; the resulting status is
  `VERIFICATION_EFFICIENCY_PASS`. Missing or altered evidence fails closed.
- Added bounded, sanitized ethers-v6/JSON-RPC rejection evidence persisted
  around the single send result, plus isolated version-2 future lineages. The
  executor still has one send site and zero automatic retries. No real
  replacement plan or signature was created, and one consolidated independent
  review of PR #13 is required before replacement planning.

```text
P4: DEFERRED — NOT PART OF THIS BETA'S PUBLIC EXECUTION EXIT CRITERIA
V2 PUBLIC DEPLOYMENT/RECOVERY EXECUTION IN THIS BETA: NOT PERFORMED
P3 CANONICAL STATUS: COMPLETE AND RECONCILED
PHILCORE CONTROLLED SEPOLIA BETA READY: NO
```

## Non-automatable evidence

The following cannot be honestly manufactured by repository code:

- an independent external security opinion;
- Apple Developer ID signing, notarization, and TestFlight authority without
  the owner-controlled credentials and agreements;
- physical Face ID/Secure Enclave ceremonies without the enrolled device;
- feedback from real trusted testers; and
- public V2 deployment/recovery evidence, which belongs to a new separately
  reviewed milestone; and
- public Sepolia evidence for Phase 7 P5 before its exact mutation plan passes
  its own final authorization gate.
