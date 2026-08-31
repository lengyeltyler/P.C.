# Claude Exact-Source Audit Prompt — Controlled Sepolia Beta P2 Recovery

Use this prompt only after the P2 recovery candidate commit and tree are frozen.

## Role and boundary

Act as an independent, adversarial security reviewer. This is an AI-only
review, not a professional audit. Review the exact supplied commit and tree
without editing source, accessing credentials, connecting a phone, signing,
or causing any public-network mutation.

Do not run a P1, P2, or P2R executor. Do not access Keychain, `.env` files,
encrypted identity/vault files, RPC or bundler credentials, or ignored
mutation artifacts. Do not run `ci:verify-clean-tree`; it may delete ignored
evidence. Do not modify, commit, merge, push, clean, or delete anything.
Preserve unrelated untracked `pqREADME.md` exactly; its expected SHA-256 is
`7702166308feec4d81733842f0d7da4034c64fab2381bb353bd2a769b99b24c8`.

## Exact candidate identity

Record the 40-hex commit and tree before review and confirm the working tree is
clean except optional `?? pqREADME.md`. Stop with a blocking finding if the
source identity changes.

## Required scope

- `config/ethereum-sepolia/PHILCORE_CONTROLLED_SEPOLIA_BETA_P2_V1.json`
- `scripts/ethereum-sepolia/philcore-controlled-sepolia-beta-p1-common.cjs`
- `scripts/ethereum-sepolia/philcore-controlled-sepolia-beta-p2-common.cjs`
- `scripts/ethereum-sepolia/prepare-philcore-controlled-sepolia-beta-p2-composition.cjs`
- `scripts/ethereum-sepolia/prepare-philcore-controlled-sepolia-beta-p2-recovery.cjs`
- `scripts/ethereum-sepolia/execute-philcore-controlled-sepolia-beta-p2-recovery.cjs`
- `scripts/ethereum-sepolia/execute-philcore-controlled-sepolia-beta-p2.cjs`
- `apps/philcore-ios-companion/PhilCoreCompanion/RootView.swift`
- `test/unit/philcore-controlled-sepolia-beta-p2-guard.test.cjs`
- P2 configuration, operations documentation, package scripts, audit scope,
  and CI classification touched by the candidate
- directly invoked composition, replay, P-256, Device Vault, account, factory,
  gate, consumer, and EntryPoint integration code needed to verify the claims

## Mandatory security questions

1. Does every P2R entry point fail closed on changed or unreviewed source?
2. Is recovery composition local-only, isolated from old state, and unable to
   mutate Sepolia?
3. Does it require a fresh real Noir proof, exact physical iPhone P-256
   approval, durable replay reservation, and Device Vault signature before it
   creates a signed-unsubmitted operation?
4. Is the iOS second-scan control reachable after enrollment while preserving
   the existing scanner and canonical verification path?
5. Does the signed operation enforce the `100000000` wei bundler priority-fee
   floor, the `0.005 ETH` total fee ceiling, zero action value, no paymaster,
   nonce zero, exact account graph, execution-owner recipient, and expiry?
6. Does the read-only planner honestly record that the original generated P2
   files are unavailable, bind the owner-approved digest and exact tracked
   incident constants, prove the confirmed funding transaction and receipt
   through both providers, and prove the rejected and replacement operation
   hashes absent from the bundler without claiming unavailable byte evidence?
7. Does it require the account to remain funded but undeployed, EntryPoint
   nonce/deposit zero, all replay and pass mappings unused, and both providers
   to agree before planning or execution?
8. Does the P2R plan freeze exactly one new UserOperation mutation and exactly
   zero additional funding?
9. Is the executor unable to read the plan, signed artifact, endpoint, or
   network before the exact digest-specific `P2R` approval matches?
10. After approval, does it revalidate all source, plan, compiler, endpoint,
    signed-artifact, tracked incident, live funding, fee, estimate, nonce,
    balance, and replay bindings before acquiring a separate durable recovery
    lock?
11. Is there exactly one `eth_sendUserOperation` call site, no funding or raw
    transaction broadcast route, and no automatic or concurrent retry?
12. Does the receipt persist `submission_requested` before the call and retain
    nested JSON-RPC code/message/data evidence on rejection without exposing
    credential-bearing URLs?
13. Does final reconciliation require the bundler receipt, matching receipt
    from both providers, successful EntryPoint event, exact account bindings,
    factory registration, nonce advancement, replay consumption, pass owner,
    and bounded balances/deposit?
14. Can any timeout, old operation, changed artifact, stale fee, changed nonce,
    provider disagreement, duplicate invocation, or ambiguous receipt be
    mistaken for success or retried?
15. Do focused tests cover approval order, read-only planning, the fee floor,
    one-call/no-funding structure, durable recovery lock, the honest missing-
    file boundary, exact incident constants and live reconciliation, private
    evidence paths, nested error preservation, provider options, and the iOS
    second-scan path?
16. After the first approved P2R executor invocation stopped before its
    execution lock and mutation boundary because the signed artifact used
    lowercase addresses while the plan used EIP-55 checksum casing, does the
    correction canonicalize only syntactically valid Ethereum addresses,
    preserve the exact address value and every other artifact byte binding,
    cover both P2 executors, and reject malformed addresses without creating
    an approval, replay, or substitution bypass?

Treat an approval bypass, evidence-binding gap, unintended funding/mutation
route, secret exposure, replay bypass, false-success reconciliation, or retry
path as at least HIGH.

## Allowed verification

Run only local, non-mutating checks that do not access secrets or devices:
syntax checks, the focused P2 guard suite, reusable Beta contract tests,
classification validation, `git diff --check`, and source searches. Report any
blocked check as unverified; do not weaken the gate.

## Required report

Produce one report with reviewed commit and tree, files reviewed, checks run,
findings grouped by CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL, explicit unresolved
CRITICAL and HIGH counts, and confirmation that no phone, secret, signing
authority, RPC credential, public mutation, or source edit was used.

End with exactly one line:

```text
CONTROLLED SEPOLIA BETA P2 RECOVERY BLOCKED BY THIS REVIEW: YES
```

or:

```text
CONTROLLED SEPOLIA BETA P2 RECOVERY BLOCKED BY THIS REVIEW: NO
```

`NO` is allowed only with zero unresolved CRITICAL and HIGH findings. Save the
finished report exactly, compute the SHA-256 of those bytes externally, and
bind acceptance through:

```text
PHILCORE_CONTROLLED_BETA_P2_RECOVERY_RUNNER_REVIEW_COMMIT=<reviewed commit>
PHILCORE_CONTROLLED_BETA_P2_RECOVERY_RUNNER_REVIEW_TREE=<reviewed tree>
PHILCORE_CONTROLLED_BETA_P2_RECOVERY_RUNNER_REVIEW_SHA256=0x<64 lowercase hex>
PHILCORE_CONTROLLED_BETA_P2_RECOVERY_RUNNER_REVIEW_DISPOSITION=ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH
```
