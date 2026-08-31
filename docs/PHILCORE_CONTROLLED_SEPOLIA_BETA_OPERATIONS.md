# PhilCore Controlled Sepolia Beta Operations

Status: **P1/P2/P3/P5 confirmed and reconciled; public P4 recovery deferred.
Signed Desktop and iOS build 58 completed the revised final physical session.
Public release remains gated on final source/security/license remediation.**

See [final release status](./PHILCORE_CONTROLLED_SEPOLIA_BETA_FINAL_RELEASE_STATUS.md).
P5 attempt 2 was separately authorized and reconciled successfully at nonce `3`;
P5 attempt 1 remains rejected, consumed, and never retried. Q2's accidental
physical approval remains recorded; separately authorized Q3 provided rejection.

## Historical procedures and incident chronology

Earlier blocked states and instructions below describe the stage at which they
were recorded. They do not authorize another plan, signature, or submission.

This runbook applies only to the exact controlled Beta profile in
[`config/controlled-sepolia-beta-v1.json`](../config/controlled-sepolia-beta-v1.json)
and the review scope in
[`config/security/philcore-controlled-sepolia-beta-audit-scope-v1.json`](../config/security/philcore-controlled-sepolia-beta-audit-scope-v1.json).
Ethereum mainnet and meaningful assets are prohibited.

The exact credential inventory, staged public-mutation approval procedure,
signed-package requirements, and physical/trusted-tester matrix are frozen in
the [Beta Gate Approval Packet](./PHILCORE_CONTROLLED_SEPOLIA_BETA_GATE_APPROVAL_PACKET.md).
Its machine-readable mutation-plan template is intentionally non-executable
until every live field and stage digest is populated.

The earlier Alpha mint planner and executor are structurally retired and stop
before artifact, approval, secret, or network handling. They must not be used
for this Beta. The controlled P1 planner and executor implement P0/P1 of the
staged plan. P2 and P3 each used a distinct local-composition command, no-send
planner, digest-gated one-shot executor, and independent receipt/state
reconciliation. Public P4 recovery is deferred from this Beta. Phase 7 P5
cleanup infrastructure and its P5-specific gas and fee ceilings were
corrected. An early unsigned/unapproved candidate exposed a fail-closed
protected-file integrity defect and was superseded without signing or sending.
A later exact P5 plan was separately signed and approved, but its one allowed
submission was rejected before bundler acceptance with zero chain mutation.
That plan, signature, approval, lock, and submission authority are permanently
consumed. Phase 7H.2 corrects future bundler-admission and rejection-evidence
handling, but no replacement plan may be created until exact-operation
verification-efficiency evidence exists and the corrected source receives a
fresh independent exact-source review.

The P1 planner is read-only with respect to public networks. It queries both
RPC providers and the bundler, derives all four addresses, simulates the three
deployments, enforces the `0.05 ETH` exposure ceiling, and signs exact
transaction hashes locally without retaining raw transactions in the plan. It
has no transaction-broadcast or UserOperation-submission method.
It also refuses to prepare a plan unless an independent report digest records
acceptance of the exact current commit and tree with zero unresolved CRITICAL
or HIGH findings.

The P1 executor requires both the plan digest and this exact phrase before it
can read the plan, endpoints, network, or Keychain:

```text
I_APPROVE_PHILCORE_CONTROLLED_SEPOLIA_BETA_P1_<64_HEX_PLAN_DIGEST>
```

After approval it rechecks both providers, source identity, endpoint digests,
nonces, balances, fees, address vacancy, deployment data, transaction hashes,
and constructor bindings. It permits one broadcast call for each of the four
frozen transactions and never retries. Any timeout or disagreement produces a
stop receipt requiring read-only reconciliation.

On 2026-08-25, the approved funding mutation confirmed on both providers in
block `11567203`. The first deployment submission returned `INSUFFICIENT_FUNDS`
before either provider accepted it. The executor did not retry. Both providers
subsequently agreed that the deployer nonce remained zero, all predicted
contract addresses remained vacant, and the fresh deployer held the full
planned deployment balance.

The dedicated recovery planner is read-only and accepts only that exact
fail-closed state. It proves the original funding receipt on both providers,
proves the rejected deployment hash is absent, re-derives the same graph, and
freezes exactly three deployment transactions. Its executor requires a new
digest-specific approval before reading any plan, endpoint, network, or
Keychain state:

```text
I_APPROVE_PHILCORE_CONTROLLED_SEPOLIA_BETA_P1R_<64_HEX_PLAN_DIGEST>
```

The recovery executor contains no funding mutation and never retries.

On 2026-08-25 (America/Denver), the owner approved P1R plan digest
`0x2934e38a2e6ca80f6c7011a4c45b38b0943182ee8c2473541e2a0ec66467d673`.
The executor broadcast each of its three frozen deployment transactions once.
Both providers confirm all three successful receipts and matching runtime code.
The executor then stopped during constructor-binding verification because the
unqualified JavaScript `factory.getAddress(...)` call resolved to ethers'
contract-address helper instead of the Solidity factory prediction function.
Read-only reconciliation using the full
`getAddress(address,bytes32,uint256)` signature proved every planned binding,
including the predicted account. No transaction was retried. The verifier now
uses the full signature and regression coverage prevents recurrence. See the
[P1 evidence record](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P1_EVIDENCE_2026-08-25.md).

Operator commands:

```text
npm run prepare:philcore-controlled-sepolia-beta-p1
npm run execute:philcore-controlled-sepolia-beta-p1 -- --plan-digest <digest>
```

The executor command is prohibited until the exact phrase produced by the
planner has been separately supplied by the owner.

The completed P1/P1R approvals cannot authorize P2. Preparing P2 is read-only;
funding the counterfactual account or submitting its first UserOperation
requires a new exact P2 plan and digest-specific owner approval.

## P2 account funding and first composed action

P2 deliberately separates local authorization from public execution:

1. `prepare:philcore-controlled-sepolia-beta-p2-composition` first proves the
   exact P1 deployment and unused counterfactual account through both RPC
   providers. It then creates a Beta-only physical iPhone enrollment, produces
   and verifies the real Noir proof, obtains the exact P-256 approval from the
   enrolled PhilCore iOS app, durably reserves every replay field, binds the encrypted
   initial execution-validator record to the predicted account, and releases
   one exact Device Vault signature. It writes a signed-unsubmitted artifact
   and has no public-network mutation method.
2. `prepare:philcore-controlled-sepolia-beta-p2` revalidates the seven-argument
   Beta account constructor graph, execution-owner recipient, signature,
   nonce, replay state, P1 bindings, live fees, bundler estimate, endpoint
   digests, and all ceilings. It signs but does not retain the raw funding
   transaction and freezes exactly two mutations in a canonical plan.
3. `execute:philcore-controlled-sepolia-beta-p2` is unreachable until the owner
   supplies both the plan digest and the exact phrase below. It then permits
   one funding broadcast and one `eth_sendUserOperation` call after acquiring
   one durable exclusive execution-attempt lock. Any timeout,
   disagreement, or ambiguity stops without retry and requires read-only
   reconciliation.

The exact approval format is:

```text
I_APPROVE_PHILCORE_CONTROLLED_SEPOLIA_BETA_P2_<64_HEX_PLAN_DIGEST>
```

Operator commands, after exact-source review acceptance:

```text
npm run prepare:philcore-controlled-sepolia-beta-p2-composition
npm run prepare:philcore-controlled-sepolia-beta-p2
npm run execute:philcore-controlled-sepolia-beta-p2 -- --plan-digest <digest>
```

The composition command requires the phone only for the two displayed QR
ceremonies: fresh Beta enrollment and exact authorization. The planner and
executor do not require the phone. The executor is prohibited until the
planner-generated phrase is separately supplied by the owner. Ethereum
verifies the restricted account signature and on-chain replay/recipient
rules; it does not verify the Noir proof or iPhone P-256 signature.

The reviewed iOS app creates and queries its approval key with Apple's Secure
Enclave token and `privateKeyUsage | userPresence` controls. The desktop proves
possession of that P-256 key and verifies the exact approval signature, but it
does not receive an App Attest, DeviceCheck, or hardware-attestation chain.
Accordingly, every P2 artifact records that remote hardware/app attestation is
not established and that resistance to a malicious alternate phone client is
not claimed. This controlled Beta assumes the owner installs the reviewed
PhilCore app and physically scans the QR; that assumption is not suitable for
meaningful assets without a separately approved assurance design.

P2 restart safety is fail-closed. The composition command refuses any existing
P2 support directory, plan, receipt, or execution lock; the planner refuses to
overwrite an existing plan; and the executor refuses an existing receipt. No
P2 command automatically deletes or reuses prior ceremony state. After any
interruption, preserve and reconcile the old evidence, archive it explicitly,
and only then begin a newly reviewed fresh run. P2 and P2R signed artifacts,
plans, receipts, and execution locks are stored under the ignored
`.philcore-local/controlled-sepolia-beta/` evidence root, outside Hardhat's
generated `artifacts/` tree. Build, compiler, and ordinary cleanup operations
must not remove that private evidence root.

### P2 stopped-at-bundler recovery

On 2026-08-25, the owner approved the original P2 plan digest
`0x23467979ac3c95b6f7aa2c288292aa4718b4ae5c94e2998636ed7f9868ae0997`.
The funding transaction
`0x60029b4b50246fa4c318caaf61ea184b838d6c28e2c41be6782409ff15136c9a`
confirmed on both providers in block `11568484`. The executor then requested
submission of UserOperation
`0xff258b993d44b5d8729b1bee326887b9e65166b71bbf0337525f03be5e9e2cf6`,
but the bundler rejected it during precheck because its priority fee was
`1000000` wei and the bundler required at least `100000000` wei. Read-only
reconciliation found no bundler receipt or operation for that hash. Both
providers agreed that the account remained undeployed and fully funded, its
EntryPoint nonce and deposit remained zero, all replay fields remained unused,
and no pass was issued. No retry occurred.

P2R is a distinct recovery lane for only that exact stopped state. It raises
the signed priority-fee floor to `100000000` wei without increasing the
`0.005 ETH` maximum total fee, requires a fresh local proof and physical-phone
authorization, and binds the owner-approved original digest, exact tracked
incident constants, confirmed funding transaction, rejected operation hash,
and original replay fields. The original generated plan, receipt, execution
lock, and signed artifact are no longer locally available: validation exposed
that they had been stored inside Hardhat's replaceable generated `artifacts/`
tree. P2R therefore does not claim to verify their bytes. Instead, its
read-only planner and executor re-prove the recoverable incident state through
two independent providers and the bundler, including the exact funding
transaction and receipt, absence of the rejected operation, undeployed funded
account, zero nonce/deposit, and unused replay/pass mappings. The transcript-
preserved bundler rejection code and message are recorded as incident context,
not as independently retrievable network evidence. The executor permits
exactly one new `eth_sendUserOperation` call, performs no funding transaction,
records nested bundler error evidence, acquires a separate durable
execution-attempt lock, and never retries.

The iOS accepted screen now exposes an explicit second scan action after
enrollment, so the authorization QR can be scanned without relaunching the
app. A fresh reviewed build must be installed before the recovery ceremony.

The exact P2R approval format is:

```text
I_APPROVE_PHILCORE_CONTROLLED_SEPOLIA_BETA_P2R_<64_HEX_PLAN_DIGEST>
```

Operator commands, after exact-source P2R review acceptance:

```text
npm run prepare:philcore-controlled-sepolia-beta-p2-recovery-composition
npm run prepare:philcore-controlled-sepolia-beta-p2-recovery
npm run execute:philcore-controlled-sepolia-beta-p2-recovery -- --plan-digest <digest>
```

The recovery executor is prohibited until the recovery planner has completed
and the owner has separately supplied its exact digest-specific phrase. The
original P2 approval cannot authorize P2R.

### P2 completion

P2 ultimately completed through separately approved P2A and P2F stages after
the bundler rejected the counterfactual-operation route. P2A deployed the exact
prefunded account through the existing factory without retry. The P2F final
operation then used empty `initCode`, no factory RPC fields, a fresh Noir proof,
a fresh physical iPhone approval, a new Device Vault signature, and a P2F-only
bounded verification-gas limit.

Final P2F plan
`0xde6052b2b94b28118afa05d4cbc73b343b893171991818d020610ef7d0da836e`
submitted exactly one UserOperation and confirmed in transaction
[`0x24a3a28989e8707bc52ff66e1f0ed1b9a8d31a8b151cf6177320a8285eb0b934`](https://sepolia.etherscan.io/tx/0x24a3a28989e8707bc52ff66e1f0ed1b9a8d31a8b151cf6177320a8285eb0b934).
Both providers agreed on nonce `1`, the three consumed replay fields, pass
token `1`, its execution-validator owner, and the three exact success events.
No additional funding or automatic retry occurred. See the
[P2 evidence record](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P2_EVIDENCE_2026-08-26.md).

The P2 approvals were exhausted and did not authorize P3. P3 used a new proof,
physical phone approval, Device Vault signature, live nonce `1`, empty
`initCode`, fresh replay fields, one canonical no-send plan, independent
exact-source/package review, and a new digest-specific owner approval.

### P3 completed corrective sequence

The first P3 run completed proof and phone authorization, but its one permitted
bundler submission was rejected before acceptance because verification-gas
efficiency was below the bundler threshold. It was not retried. Its attempt
lock and stopped receipt remain historical evidence. Read-only reconciliation
confirmed the rejected hash absent, nonce `1`, next token `2`, and no public P3
mutation.

The corrective runner uses a P3-only `80000` verification-gas limit; P2F
remains `150000`. A later enrollment stopped before accepted persistence, so
repeated physical retries were halted. Phase 1 added owner-only lifecycle
evidence, restart invalidation, stale-attempt isolation, protected safe-resume
points, and a distinct second authorization scan. Phase 2 froze source
`a5e38dba06dbc4c915ad1b640f617d758926009d`, tree
`96608f943e551ef860f210e872fe3f910959cd7b`, and build-56 package identity,
then independently reviewed them before further physical work.

Exactly one later authorized physical ceremony produced exactly one
signed-but-unsubmitted artifact. One no-send plan froze UserOperation
`0x7cecc29755c1420f5844047b5c9f22d0f02adcb030db2157fb95bb74979def0d`
and full-plan digest
`0x28b7ce5e86e39c24a692c7dd96420b0ad7f5ab44fd3e3eced46bf945d4d5c16a`.
The owner's separate exact approval authorized one bundler submission. It
confirmed in transaction
[`0x2e51d90bc1453cd7f56f906a5d5db375b06fc085913ad3678929142d01b314e0`](https://sepolia.etherscan.io/tx/0x2e51d90bc1453cd7f56f906a5d5db375b06fc085913ad3678929142d01b314e0),
block `11579252`, with zero automatic retries, zero manual resubmissions, and
zero additional funding.

The Alchemy bundler, Alchemy primary RPC, and PublicNode independently agree on
the receipt and final nonce `2`, pass balance `2`, token `2`, next token ID `3`,
fresh P3 replay consumption, retained P2 replay consumption, and exactly one
expected event of each kind. The P3 commands are exhausted historical ceremony
interfaces and must not be rerun or treated as authority for future V2 work or
Phase 7 P5. See the
[canonical P3 evidence](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P3_EVIDENCE_2026-08-27.md)
for exact source, package, plan, receipt, gas/prefund, trust-boundary, and
residual-risk accounting.

## P4 public-recovery boundary

```text
P4: DEFERRED — NOT PART OF THIS BETA'S PUBLIC EXECUTION EXIT CRITERIA
V2 PUBLIC DEPLOYMENT/RECOVERY EXECUTION IN THIS BETA: NOT PERFORMED
P3 CANONICAL STATUS: COMPLETE AND RECONCILED
```

P2/P3 used the deployed legacy `PhilCore4337Account`. They did not deploy or
exercise the intended V2 exact-2-of-3 recovery account. The legacy account's
single-EOA recovery, owner-only cancellation, and expired-request freeze are
disclosed HIGH findings. V2 source and substantial local tests exist, but stale
runtime pins, an incompatible selected target, incomplete real initialization
and deployment inputs, and unsupported-token stranding risk block a Beta-ready
V2 deployment package.

See the canonical
[P4 public-execution scope closure](./reference/PHILCORE_CONTROLLED_SEPOLIA_BETA_P4_SCOPE_CLOSURE_2026-08-27.md).
This documentation does not authorize a recovery credential, phone ceremony,
deployment, funding, transaction, UserOperation, recovery transition,
validator rotation, recovery-authority configuration rotation, or V2
ActionGate call. Any such V2 public exercise is a new separately reviewed and
explicitly authorized milestone.

The remaining sequence requires direct exact-operation P5 validation-gas
evidence, fresh independent exact-source review of the Phase 7H.2 correction,
separately authorized replacement P5 no-send planning, new signing and
digest-specific execution approval, restricted cleanup and final
reconciliation, Phase 8 signed packages and physical acceptance, and Phase 9
the final Beta/open-source decision.

## Roles and custody

Use fresh Beta-only authority credentials. The deployer, execution validator,
and recovery authority must be distinct and must never reuse the disclosed
Alpha key as an authority. By explicit owner direction, the disclosed Alpha
address may be used only for one capped, separately approved transfer to the
fresh Beta deployer. The Beta deployer then funds the counterfactual account;
execution and recovery addresses remain unfunded. Provider and bundler
credentials belong in the local secret store, not in
tracked files, logs, screenshots, QR payloads, diagnostics, or release
packages. The recovery authority cannot authorize ordinary actions or release
funds.

The composed ActionGate is deployed for exactly one predicted counterfactual
Beta account. A different factory-created account must fail even if it copies
a pending operation's public envelope, nullifier, device nonce, expiry, and
recipient fields. The recipient must equal the authorized account's current
execution owner at consumption time.

## Provider and bundler acceptance

Before preparing a mutation plan, record one primary Sepolia RPC, one
independently operated read-only reconciliation RPC, and one ERC-4337 v0.7
bundler. Bind the complete credential-bearing endpoints by digest while
displaying only sanitized hostnames. Verify chain ID `11155111`, official
EntryPoint support, supported RPC methods, request and receipt timeouts, rate
limits, fee behavior, and the provider-disagreement stop condition.

The owner supplied fresh Beta-only Alchemy and Infura credentials on
2026-08-25. A local owner-only environment validated Alchemy as the primary RPC
and v0.7 bundler and Infura as the independent reconciliation RPC; no complete
endpoint or credential is tracked here.

The bundler may estimate and submit one already-signed operation. It may not
introduce a paymaster, change any UserOperation field, retry automatically, or
be treated as authorization authority.

## Frozen deployment graph

The deployment candidate consists of the reusable
`PhilCore4337AccountFactory`, `PhilSepoliaLocalComposedActionGateV1`, and
`PhilSepoliaMintPassConsumerV1`. Their circular constructor addresses must be
derived from one fresh deployer nonce sequence and independently recomputed
before signing. The factory binds the official EntryPoint and ActionGate; the
gate binds Sepolia, factory, consumer, and the one predicted counterfactual
account; the consumer binds the gate.

No transaction may be broadcast until all of the following are fixed in one
exact plan: source commit and tree, contract creation-code hashes, constructor
arguments, expected addresses, deployer and starting nonce, endpoint digests,
fee caps, gas limits, maximum total public cost, account salt and commitment,
recovery authority, operation hash, expiry, and ordered mutation list. A plan
change invalidates approval.

## Funding limits

- total operator exposure: at most `0.05 ETH`;
- native account balance: at most `0.01 ETH`;
- EntryPoint deposit: at most `0.01 ETH`;
- ordinary action value: exactly zero;
- meaningful assets and paymasters: forbidden.

Residual disposable funds must be reconciled after each drill. The account's
fixed-recipient release path can return native balance and EntryPoint deposit
only to the current execution owner, through an owner-authorized EntryPoint
maintenance operation, while no recovery is pending.

A future P5 lifecycle is strictly `PLAN -> SIGN -> EXECUTION APPROVAL ->
FINAL REVALIDATION -> LOCK -> ONE SEND -> RECONCILIATION`. The planner uses
fresh reconciled state, a read-only estimate seeded by the already reviewed
deployed-account gas profile, a fee reading, and the repository's established
125% planning margin for call gas, pre-verification gas, and fees bounded by
fixed P5 ceilings, plus an exact-operation evidence-selected verification gas
limit, to create an exact unsigned UserOperation (`signature: "0x"`) and an
unapproved plan. The ERC-4337 v0.7 signing hash excludes the signature field,
so later insertion of the owner signature cannot alter that frozen hash. The
planner cannot read a signed artifact, invoke custody, create a lock, or send.
The protected `pqREADME.md` identity comes from one canonical exported SHA-256
constant; both plan creation and integrity validation explicitly reject an
unavailable, malformed, or mismatched expected value.

Every corrected P5 plan also integrity-binds three owner-review structures: a
deterministic successful expected post-state; the still-open, fail-closed
`P5-R-L01 — LOW` multi-operation-bundle reconciliation limitation; and the
structural refund rule that unused prefund returns only after account execution,
so the final EntryPoint deposit is unknown before inclusion but must not exceed
the exact plan-selected maximum. The risk cannot create false success, authorize
retry, or authorize a second submission. Exact zero remains unpromised.

The call and pre-verification gas ceilings remain derived from the independently
observed cleanup estimate `300000/100000`: apply the mandatory ceiling-rounded
125% planning margin, then one further ceiling-rounded 125% step to define
review ceilings of `468750/156250`. Verification gas is specialized: exact P5
EntryPoint v0.7 simulation measured `37050`, producing a 125%-margin minimum of
`46313` and a 0.4-efficiency maximum of `92625`. The final selected
`verificationGasLimit` is `80000`; it is not margin-multiplied again. The fixed
verification/call/pre-verification caps are therefore
`80000/468750/156250`. At the P5-only `3000000000` wei maximum fee, those caps
bound maximum gas at `705000` and maximum prefund and terminal EntryPoint
residual at `2115000000000000` wei (`0.002115 ETH`), which is `52.17201377%`
of the Phase 7D starting exposure `4053897572664530` wei. At the selected
cleanup gas values `80000/375000/125000`, the same fee cap produces a lower
plan-selected maximum prefund and terminal-residual bound of
`1740000000000000` wei (`0.00174 ETH`), or `42.92165672%` of that exposure.
The fee ceiling admits a raw maximum fee no
higher than `2400000000` wei under the same 125% rule; higher transient fees
must stop read-only planning rather than expand the exposure ceiling. The
priority-fee ceiling remains `100000000` wei, and the shared P2/P3 maximum-fee
ceiling remains `2200000000` wei. Raising the P5 ceiling therefore increases
the possible residual ceiling, but a real plan still binds its exact selected
gas and fee values for owner acceptance; the fixed ceiling is not itself the
final owner-approved residual and exact-zero EntryPoint deposit is not
promised. The attempt-1 source and authority are superseded for execution use;
the integrity-bound exact-operation efficiency evidence and fresh consolidated
independent review of PR #13 are required before any replacement real P5 plan.

The later P5 signing path is a dependency-injected product-custody boundary,
not a standalone private-key shell command. It loads exactly one plan,
revalidates current source and exact two-provider state before invoking the
configured Device Vault signer, signs only the plan's frozen UserOperation
hash, verifies the current owner's signature, and exclusively creates one
signed-unsubmitted artifact bound to both the full plan digest and exact plan
bytes. Signing does not authorize submission. If state has drifted, signing
fails before custody is touched; it never refreshes or edits the plan.

The executor requires the separately supplied full-plan-digest approval and
exact plan/artifact equality. It requires exact two-provider equality with the
plan for owner, EntryPoint nonce, smart-account native balance,
EntryPoint deposit, frozen state, active recovery, and active
recovery-authority rotation immediately before its exclusive execution lock.
It permits one bundler submission and no retry; a timeout or uncertain result
is reconciled by exact UserOperation hash and cannot trigger resubmission.
Exact-zero terminal EntryPoint deposit is not promised because unused prefund
returns after the cleanup call. The later no-send plan must derive and bind its
maximum acceptable residual deposit from the planned maximum prefund and obtain
explicit owner acceptance of that bound.

## P5 attempt 1 and replacement-lineage admission

P5 attempt 1 used UserOperation
`0xade275d0de8db399a4f829e47b5b20b7212c84571762f70584567bbeee64503e`.
The bundler rejected the single submission before acceptance. Exact-hash and
two-provider reconciliation found zero chain mutation, and no automatic or
manual retry occurred. Its immutable plan, signed artifact, execution lock,
and stopped receipt have SHA-256 values
`49fa583c98a8c84bba2379d807788de274c4f7ace0d410e74bd22a6e903208f4`,
`0f536e21acb9cb5b2711907de3be58def11a321cc0fe92448c9cdec9b9934c8a`,
`43092cf69873b5132c406c1314b327bba58d2db891c2bdf6ba3bdc4fa9b54a90`,
and `353e9c0ad5c238aa7856c6fd26d18975d948198f9cf66d956ed2f560596277a5`.
The required disposition is `ATTEMPT CONSUMED / RESUBMISSION FORBIDDEN`; the
historical lock must never be cleared or replaced. The original provider
rejection payload was not retained and has not been recovered. Observability
for that incident is therefore **MEDIUM**, and the exact rejection cause is not
established.

Future P5 planning enforces a same-bundler priority-fee floor of `100000000`
wei/gas. Selection is
`max(ceil(rawMaxPriorityFeePerGas * 5 / 4), 100000000)`, bounded by the
unchanged absolute P5 priority cap of `100000000`; a requirement above the cap
fails closed. P2/P3 fee policy is unchanged.

Verification-gas efficiency is a separate admission gate from raw estimate
sufficiency, the mandatory 125% margin, and the absolute gas ceilings. The
known threshold model is
`actualValidationGas / verificationGasLimit >= 2 / 5`. A PASS requires direct,
exact-operation evidence from deterministic local EntryPoint simulation or a
supported read-only bundler simulation. Retained measurements from different
historical operations do not prove the P5 ratio. The bound evidence records
`actualValidationGas=37050`, safety interval `46313..92625`, selected limit
`80000`, the two exact measurement blocks, exact UserOperation/account/
EntryPoint identities, deployed code hashes, simulation-runtime hash, and
two-provider agreement. The selected ratio is `37050/80000 = 0.463125`, so the
planner records `VERIFICATION_EFFICIENCY_PASS`. Missing or altered evidence
fails closed before plan creation.

Replacement artifacts, if separately authorized after review and evidence,
use a future lineage such as `p5-attempt-0002` under
`.philcore-local/controlled-sepolia-beta/p5-lineages/<lineage-id>/`. Plan,
signed artifact, lock, and receipt are version 2 and bind the same lineage ID;
`p5-attempt-0001` is rejected as future authority. A legitimate replacement
also requires a new UserOperation hash, plan digest, signature, digest-specific
owner approval, and separate execution authorization.

The corrected executor still contains one send site and no retry. Around that
single result it can durably retain a bounded sanitized evidence record before
the generic fail-closed stop: provider role, RPC method and safe request ID,
attempt time, exact UserOperation hash, send disposition, ethers and JSON-RPC
codes, bounded message, detected `AAxx`, a bounded type/key/summary view plus
digest of that sanitized classification, and a derived rejection category.
Authenticated URLs, credentials, known secrets, private-key-labeled values,
raw request bodies, and signed-operation-like payloads are not retained.
Diagnostics do not add a send, fallback bundler, retry, unlock, or
resubmission path.

## Submission and ambiguity

Read the current keyed EntryPoint nonce immediately before approval. First use
may contain factory data; every later use must have empty `initCode`. Persist
the canonical envelope, proof nullifier, device-approval nonce, UserOperation
hash, provider bindings, and reservation before signing. One submission call
is allowed.

On timeout, disconnect, bundler error, or provider disagreement, do not retry.
Query the bundler and both providers by operation hash, sender, nonce, receipt,
code, and emitted events. If inclusion cannot be proved or disproved, mark the
operation ambiguous, keep its replay reservation consumed, and create no new
authority until a human incident review resolves it.

## Receipt reconciliation

For a successful candidate, independently verify:

1. deployed runtime code hashes and constructor bindings;
2. factory registration of the reusable account;
3. EntryPoint `UserOperationEvent` sender, nonce, success, and actual gas cost;
4. composed-gate envelope, nullifier, approval nonce, account, and recipient;
5. harmless pass ownership and non-transferability;
6. nonce advancement and empty `initCode` on the second fresh action;
7. stale replay rejection locally and on chain; and
8. balances and deposits remain within the frozen ceilings.

## Incident and revocation drills

Stop new actions for any unexpected code, nonce, fee, provider, signature,
receipt, replay-store, package, enrollment, or recovery state. Preserve
sanitized evidence; never copy secrets into an incident record. Revoke the
affected provider credential, validator, or device; freeze through delayed
recovery when owner compromise is suspected; reconcile all pending operations;
and require a new frozen candidate for any source or configuration change.

The Beta gate remains closed until the remaining review, signed-package,
physical-matrix, trusted-tester, and Phase 7 P5 requirements are complete.

```text
PHILCORE CONTROLLED SEPOLIA BETA READY: NO
```
