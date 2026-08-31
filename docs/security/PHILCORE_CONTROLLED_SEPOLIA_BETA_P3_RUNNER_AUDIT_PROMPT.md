# Independent Exact-Source Audit Prompt — Controlled Sepolia Beta P3

Use this prompt only after the P3 candidate commit and tree are frozen.

## Role and boundary

Act as an independent, adversarial security reviewer. This is an AI-only
review, not a professional audit. Review the exact supplied commit and tree
without editing source, touching credentials, connecting a phone, or causing
any public network mutation.

## Prohibited actions

- Do not run any executor or submit any transaction/UserOperation.
- Do not access RPC/bundler credentials, Keychain, encrypted identities,
  authority keys, proof witnesses, or ignored mutation artifacts.
- Do not connect, enroll, or request approval from an iPhone.
- Do not modify, commit, merge, push, clean, or delete files.
- Do not run `ci:verify-clean-tree`; it may delete ignored evidence.
- Preserve untracked `pqREADME.md` exactly; its expected SHA-256 is
  `7702166308feec4d81733842f0d7da4034c64fab2381bb353bd2a769b99b24c8`.

Record and continuously enforce:

```text
reviewed commit: <40 hex>
reviewed tree: <40 hex>
working tree: clean except optional ?? pqREADME.md
```

Stop with a blocking finding if the source identity changes.

## Required scope

- `scripts/ethereum-sepolia/philcore-controlled-sepolia-beta-p2-common.cjs`
- `scripts/ethereum-sepolia/prepare-philcore-controlled-sepolia-beta-p2-composition.cjs`
- `scripts/ethereum-sepolia/prepare-philcore-controlled-sepolia-beta-p2-final.cjs`
- `scripts/ethereum-sepolia/execute-philcore-controlled-sepolia-beta-p2-final.cjs`
- the three `philcore-controlled-sepolia-beta-p3` entry points
- `test/unit/philcore-controlled-sepolia-beta-p2-guard.test.cjs`
- `test/unit/philcore-controlled-sepolia-beta-p3-guard.test.cjs`
- the P2 configuration, confirmed P2 public evidence, P3 implementation
  report, operations, gate packet, package scripts, classification, and audit scope
- the account, factory, local composed gate, and mint-pass contracts
- composed Noir, iPhone request/transport, replay-store, and Device Vault code
  directly reached by P3 composition

## Mandatory questions

1. Does every P3 entry point require one accepted review matching the current
   commit and tree before phone, secret, RPC, or Keychain access?
2. Are P3 local artifacts and its durable attempt lock distinct from P2, and
   can no code delete, overwrite, silently reuse, or reinterpret old evidence?
3. Is the exact P2 plan digest reconstructed, its receipt bytes pinned to
   SHA-256 `821dfa...cec7`, and its UserOperation/transaction/state confirmed
   through the bundler and both providers?
4. Does P3 require the already-deployed account, live keyed nonce `1`, empty
   `initCode`, null factory fields, zero action value, no paymaster, and no funding?
5. Must P3 use a fresh real Noir proof, fresh physical iPhone P-256 approval,
   fresh envelope/nullifier/device nonce, and post-composition Device Vault
   signature? Is the no-remote-attestation boundary still stated honestly?
6. Does the parser bind nonce `1`, the exact EntryPoint hash, current execution
   owner, owner commitment, account/gate/recipient, expiry, signature, gas, and fees?
7. Is the stale P2 proof strictly read-only, using estimation rather than
   submission, and accepted only for a nonce-rejection result while both
   providers also show the P2 replay mappings consumed?
8. Does the P3 planner contain no mutation method and freeze exactly one
   factory-free nonce-`1` UserOperation with one allowed attempt?
9. Is the exact digest-specific P3 approval checked before plan, endpoint,
   network, or secret access?
10. After approval, are the P2 origin, current state, signed artifact, review,
    source, endpoint, fee, gas, and expiry bindings revalidated before a
    durable P3-only lock is created?
11. Is there exactly one `eth_sendUserOperation` call, no transaction/funding
    path, no retry, and durable ambiguity evidence persisted before submission?
12. Does success require two-provider agreement on nonce `2`, new replay
    consumption, pass `2`, balance `2`, next token ID `3`, preserved P2 replay
    state/pass `1`, and exactly one matching EntryPoint/gate/pass event?
13. Can timeout, provider disagreement, stale fees, expiry, changed balance or
    code, pre-existing P3 artifacts, a previously seen hash, or an ambiguous
    response be mistaken for success or automatically retried?
14. Did P3 introduce any regression in the accepted P2/P2A/P2F behavior?
15. Does corrective P3 use a stage-specific `80000` verification-gas limit,
    leave P2F's `150000` policy unchanged, and bind that limit into the signed
    operation, phone presentation, planner, and executor?
16. Does corrective P3 freeze the rejected plan digest
    `0x211ce78797e0c9a85d7b2071bfc280e4fa98c3de316ca565bacdc09bcceb7b45`
    and UserOperation hash
    `0x3cb1fffacce39bfdabce03f4636375f04f623f95c82aa0d445ea74f89e9ca843`,
    require both bundler lookup methods to return `null` during planning and
    execution, and fail closed if either lookup finds the old operation?
17. Is the exhausted initial approval structurally unable to authorize a new
    corrective UserOperation or plan digest?
18. Does the P3 plan serialize the exact confirmed starting EntryPoint deposit
    `779861479486230` wei, and does the executor reject both the old zero value
    and any other mismatch while P2F continues to require zero?
19. Do tests materially enforce these boundaries rather than only asserting
    labels or comments?

Treat an approval bypass, unintended mutation path, replay bypass, missing
P2-origin binding, secret exposure, false-success reconciliation, automatic
retry, wrong nonce/factory binding, or false security claim as at least HIGH.

## Allowed checks

Run only local non-mutating checks that do not access secrets or devices:

```text
npm run test:philcore-controlled-sepolia-beta-p2-guard
npm run test:philcore-controlled-sepolia-beta-p3-guard
npm run ci:validate-classification
npm run typecheck
npm run compile
git diff --check
```

Do not weaken a gate when a check is unavailable; report it as unverified.

## Required report

Report the reviewed commit/tree, files and checks, findings grouped by
CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL, unresolved CRITICAL/HIGH counts, and
confirmation that no phone, secret, signing authority, RPC credential, public
mutation, or source edit was used. End with exactly one line:

```text
CONTROLLED SEPOLIA BETA P3 BLOCKED BY THIS REVIEW: YES
```

or, only with zero unresolved CRITICAL and HIGH findings:

```text
CONTROLLED SEPOLIA BETA P3 BLOCKED BY THIS REVIEW: NO
```

Save the finished report unchanged and compute its SHA-256 externally. Bind an
accepted result with:

```text
PHILCORE_CONTROLLED_BETA_P3_RUNNER_REVIEW_COMMIT=<reviewed commit>
PHILCORE_CONTROLLED_BETA_P3_RUNNER_REVIEW_TREE=<reviewed tree>
PHILCORE_CONTROLLED_BETA_P3_RUNNER_REVIEW_SHA256=0x<64 lowercase hex>
PHILCORE_CONTROLLED_BETA_P3_RUNNER_REVIEW_DISPOSITION=ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH
```
