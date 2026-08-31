# Phil V1 Step 6C-1 Synthetic Local Composition Implementation Report

Status: Exact synthetic source candidate independently accepted

Date: 2026-08-22

## Outcome

Step 6C-1 now has a bounded local implementation candidate. It composes one
disclosed synthetic P-256 device approval with one stable routine capability,
one normally deployed official ERC-4337 v0.7 EntryPoint, one disposable local
account, and one zero-value harmless target action on an in-process Hardhat
chain.

The six production-source files are frozen by:

```text
source commit:       6f048eb69ac2ca4bcd6f9649b9a543cf17f0b62c
source tree:         a9032b29802bcd3f4bfc7a2de48f911e9b805063
accepted candidate:  22b5cf31d068104c762c411cd4fa6ad8e0485eae
accepted tree:       2b0ff7fdf25f6571852be23853a9ad9c6f3e064f
implementationHash: 0xe720efab153ef79687391c4502ceb3781592744e3e2a659cd4508f18ac68e598
auditStatusHash:     0x48c2c6d6f872835aacbdd3f50ccabfbb1995f065756825cd6cf469fe03d46142
```

Independent read-only review accepted that exact documentation-and-artifact
candidate and its frozen source identity with no Critical, High, Medium, or Low
findings. The review is recorded in
[the 22B5CF3 acceptance](./PHIL_V1_STEP6C_INDEPENDENT_REVIEW_22B5CF3.md).

The initial source freeze `008bd39` failed the inherited Step 3 reachability
sentinel because the journal imported a zero constant through the shared
authorization-envelope module. Source `8c382d3` removed that import and kept
the routine journal isolated. Its documentation-and-artifact candidate
`a158688` was then independently rejected because it trusted fabricated
receipt evidence, did not fully specify point-of-no-return recovery, admitted
non-strict records and caller-selected catalog labels, and overstated its test
and artifact coverage. Both candidates are superseded. Source `9ed8274` closed
those findings in isolation, but exact candidate
`aea7359` was independently rejected because the coordinator still trusted
summary hashes, did not bind the receipt to the durable submission record, and
did not implement authenticated state-6/7/8/25 reconciliation. Source
`15bf635` replaces it by requiring verifier-branded raw outcomes, durable flush
before publication, exact late-event evidence, pre-commit trusted-state and
pre-state re-reads, byte-exact event data, and expanded compiler/storage/ABI
evidence. Follow-up source `c5fda8a` additionally binds state-7 failed evidence
to the persisted transaction hash and covers restored state-7 receipt
re-verification. Exact candidate `591f6b6` was independently rejected because
restart discarded the stored record hash, the receipt nonce was not bound to
the committed operation nonce, literal coverage was incomplete, and two
artifact inventories omitted entries. Source `13a7859` authenticated the exact
full restart chain, binds both receipt nonces to the durable operation, adds the
missing inventories, implements verifier-controlled receipt-invalid handling,
and expands literal transition, crash, record, event, and sanitized-status
coverage. Exact candidate `5ab4650` was independently rejected because the
frame API still admitted caller nonces and arbitrary plaintext, encrypted
restart was not composed, three verifier transitions were not exercised, and
actual race/reentry evidence was incomplete. Source `6f048eb` replaces that
surface with strict record/frame JSON and a nonce-owning cipher, restores from
the encrypted chain, covers the missing transitions and two actual cancellation
races, and executes an adversarial target reentry attempt. It is the only
current review source. All earlier candidates are
superseded. The exact review records are the
[A158688 review](./PHIL_V1_STEP6C_INDEPENDENT_REVIEW_A158688.md),
[AEA7359 review](./PHIL_V1_STEP6C_INDEPENDENT_REVIEW_AEA7359.md), and
[591F6B6 review](./PHIL_V1_STEP6C_INDEPENDENT_REVIEW_591F6B6.md), and
[5AB4650 review](./PHIL_V1_STEP6C_INDEPENDENT_REVIEW_5AB4650.md).

## Implemented Boundary

The candidate adds:

- strict P-256 X9.63 public-key, DER, low-S, raw `r || s`, and terminal SHA-256
  prehash handling;
- an immutable local V2 routine-signature registry that retains the accepted
  Step 5 epoch-1 registry identity;
- canonical environment, enrollment, account configuration, stable catalog,
  24-hour capability policy, per-request action/presentation/core/approval,
  signed response, and receipt records;
- one account method, selector `0x5a99466a`, callable only through its stored
  EntryPoint and bound to one target, one selector, one disclosed value, zero
  ETH, exact gas/fee/nonce/time data, and one device signature;
- the official EntryPoint keyed nonce as the sole execution sequence;
- exact request-ID to official-user-operation-hash validation handoff;
- a failed target at nonce `n` followed by a fresh success at nonce `n+1`;
- a hash-chained CAS journal, evidence-complete submission point of no return,
  outcome-unknown terminal handling, strict record and outer-frame JSON,
  nonce-owning canonical AES-256-GCM frames, encrypted-chain restart, and a
  dependency-injected in-memory synthetic coordinator; and
- deterministic local fixture and artifact-manifest generation.

The in-memory coordinator demonstrates the protected lifecycle API only. It is
not the Step 6C-2 durable Desktop host and is not production persistence.

## Implementer-Run Evidence

The exact focused source passed:

```text
npm run typecheck
npm run compile:phil-v1-step6c-account
npm run test:phil-v1-step6c-wire                 4 passing
npm run test:phil-v1-step6c-records              7 passing
npm run test:phil-v1-step6c-entrypoint           5 passing
npm run test:phil-v1-step6c-journal              6 passing
npm run test:phil-v1-step6c-desktop             12 passing
npm run test:phil-v1-step6c-ios-synthetic        3 passing
npm run verify:phil-v1-step6c-artifacts
```

The 37 focused cases explicitly map all 20 required categories through positive
and hostile branches. The exact mapping, test files, and hashes are in
the artifact manifest. The repository classification validator retains its
exact 17 pre-existing unclassified Step 3-through-6B items and adds no Step 6C
classification failure; those inherited gaps are not reported as passing.

The final corrective gate also passed all 43 focused Step 3-through-6B cases,
all five deterministic Step 3, Step 4, Step 5, Step 6A, and Step 6C artifact
verifiers, three changed-JSON parses, 420 local links across ten changed
Markdown files, `git diff --check`, and TypeScript type checking. The
classification validator was run separately and reproduced exactly the same
17 inherited items with no Step 6C item.

## Deterministic Evidence

The disclosed fixture records both nonce-0 failure and nonce-1 success request
families, raw signatures, exact nine-field packed user-operation bytes, both
operation hashes, stable catalog/policy identities, code identities, and one
submission-commit journal vector. Its synthetic private key is deliberately
published and is never a production secret.

- fixture: `config/adapters/PHIL_V1_STEP6C_LOCAL_COMPOSITION_FIXTURE.json`
- manifest: `docs/reference/PHIL_V1_STEP6C_ARTIFACT_MANIFEST.json`
- generator: `scripts/security/generate-phil-v1-step6c-artifacts.cjs`

Verification mode regenerates the candidate in a new in-process local Hardhat
network and fails if either committed JSON file differs. It performs no
external RPC or network operation.

For the four shared-build compiled contracts, the manifest compares all 75
compiler-input sources in their build information to the current repository or
locked dependency bytes; it separately authenticates the reentry target's
single-source build. It also records 26 canonical ABI type inventories and 39
constructor-storage assertions, including the full application, scope,
capability, device, key, epoch, nonce, value, fee, target, and policy state.

## Honest Status

```text
STEP 6C DEFINITION: INDEPENDENTLY ACCEPTED
STEP 6C-1 SOURCE CANDIDATE: FROZEN AND ACCEPTED
STEP 6C-1 IMPLEMENTER CHECKS: PASS
STEP 6C-1 INDEPENDENTLY ACCEPTED: YES
STEP 6C-2 SYNTHETIC PRODUCT WIRING: NOT STARTED
STEP 6C-3 PHYSICAL IPHONE CEREMONY: NOT STARTED
STEP 6 COMPLETE: NO
PRODUCTION AUTHORITY: NO
PUBLIC NETWORK OR RPC: NO
PHYSICAL DEVICE USED: NO
SECURE ENCLAVE OR USER-PRESENCE EVIDENCE: NO
PROOF BACKEND SELECTED: NO
```

No real secret, physical device, external prover, public RPC, bundler,
transaction broadcast, production deployment, meaningful asset, recovery
credential, generic signer, STWO path, or proof backend participated. Step
6C-2 and final Step 6C remain separately authorized gates even if this exact
Step 6C-1 candidate is accepted.
