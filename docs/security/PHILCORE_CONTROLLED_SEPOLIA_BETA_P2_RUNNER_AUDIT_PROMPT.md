# Claude Exact-Source Audit Prompt — Controlled Sepolia Beta P2

Use this prompt only after the P2 candidate commit and tree are frozen.

## Role

Act as an independent, adversarial security reviewer. This is an AI-only review,
not a professional audit. Review the exact supplied commit and tree without
editing source, touching credentials, connecting a phone, or causing any public
network mutation.

## Prohibited actions

- Do not broadcast a transaction or submit a UserOperation.
- Do not run either P1 or P2 executor.
- Do not access macOS Keychain, local `.env` files, encrypted identity/vault
  files, RPC credentials, bundler credentials, or ignored mutation artifacts.
- Do not connect, enroll, or request approval from an iPhone.
- Do not modify, commit, merge, push, clean, or delete repository files.
- Do not run `ci:verify-clean-tree`; it may delete ignored evidence.
- Preserve the unrelated untracked `pqREADME.md` exactly.

## Exact candidate identity

Record before review:

```text
reviewed commit: <40 hex>
reviewed tree: <40 hex>
working tree: clean except optional ?? pqREADME.md
pqREADME.md SHA-256 if present: 7702166308feec4d81733842f0d7da4034c64fab2381bb353bd2a769b99b24c8
```

Stop with a blocking finding if the source identity changes during review.

## Required scope

- `config/ethereum-sepolia/PHILCORE_CONTROLLED_SEPOLIA_BETA_P2_V1.json`
- `scripts/ethereum-sepolia/philcore-controlled-sepolia-beta-p2-common.cjs`
- `scripts/ethereum-sepolia/prepare-philcore-controlled-sepolia-beta-p2-composition.cjs`
- `scripts/ethereum-sepolia/prepare-philcore-controlled-sepolia-beta-p2.cjs`
- `scripts/ethereum-sepolia/execute-philcore-controlled-sepolia-beta-p2.cjs`
- `test/unit/philcore-controlled-sepolia-beta-p2-guard.test.cjs`
- `test/unit/phil-beta-reusable-sepolia-contracts.test.cjs`
- `contracts/base/erc4337/PhilCore4337Account.sol`
- `contracts/base/erc4337/PhilCore4337AccountFactory.sol`
- `contracts/base/PhilSepoliaLocalComposedActionGateV1.sol`
- `contracts/base/PhilSepoliaMintPassConsumerV1.sol`
- the composed Noir, iPhone request/transport, replay, and Device Vault modules
  directly invoked by the P2 composition command
- the P1 common code reused by P2
- P2 documentation, package scripts, audit scope, and CI classification changes

## Mandatory security questions

1. Does every P2 entry point fail closed on a changed/unreviewed source identity?
2. Is the composition command incapable of public mutation, and does it verify
   P1 state through two providers before Keychain access or a phone ceremony?
3. Is the phone state Beta-only and isolated from the retired Alpha artifact?
   Does the reviewed PhilCore iOS source require a Secure Enclave key and user
   presence, while the desktop proves P-256 possession and records the honest
   boundary that remote hardware/app attestation is not established?
4. Can Device Vault signing occur only after a verified real Noir proof, exact
   P-256 approval, trusted-state checks, and durable replay reservation?
5. Are `phil_secret`, vault keys, validator private keys, endpoint credentials,
   proof witness material, and raw signed funding transactions excluded from
   tracked plans, logs, QR payloads, and returned artifacts?
6. Does the signed-artifact parser reconstruct the exact seven-argument Beta
   account constructor, factory calldata, counterfactual address, nonce `0`,
   EntryPoint hash, execution-owner signature, zero-value gate call, empty
   paymaster, expiry, and fee ceiling?
7. Does it require the harmless pass recipient to equal the initial/current
   execution owner, never the smart-account address or an arbitrary recipient?
8. Do both providers have to agree on chain, exact runtime hashes, constructor
   bindings, account vacancy, balance, EntryPoint deposit/nonce, factory
   registration, and all unused replay/pass mappings before planning/execution?
9. Does the planner contain no broadcast/submission path and freeze exactly one
   capped deployer-to-account funding transaction plus one exact signed v0.7
   UserOperation, including endpoint digests, expiry, fees, gas, maximum cost,
   source/review identity, proof/device digests, and stop conditions?
10. Is the executor unable to read the plan, endpoints, network, or Keychain
    before the exact digest-specific owner phrase matches?
11. After approval, does it rederive and recheck every security-relevant field,
    permit exactly one funding broadcast and one `eth_sendUserOperation` call,
    acquire one durable exclusive execution-attempt lock, never retry, and
    persist ambiguity evidence before each call?
12. Does final reconciliation independently prove the funding receipt, bundle
    receipt, EntryPoint event, account deployment/bindings, factory registration,
    nonce advance, gate replay consumption, harmless pass owner, deposits, and
    native balances through both providers?
13. Can any timeout, RPC disagreement, bundler error, duplicate submission,
    stale fee, expiry, dust balance, pre-existing code, or partial completion be
    mistaken for success or automatically retried? Do composition, planning,
    and execution refuse pre-existing local P2 state instead of silently
    reusing, deleting, or overwriting it, and does the generic project cleanup
    preserve the controlled-Sepolia Beta evidence directory?
14. Are the `0.005 ETH` ordinary fee ceiling, `0.01 ETH` account/deposit ceilings,
    `0.05 ETH` operator ceiling, zero action value, no-paymaster rule, and
    meaningful-asset prohibition enforced literally?
15. Do focused tests exercise the approval-order boundary, one-shot call sites,
    Alpha-recipient regression, Beta constructor graph, gas profile, source
    review gate, durable execution lock, exclusive evidence creation, cleanup
    preservation, bounded phone assurance, and mutation-disabled configuration?

## Controlled-Beta phone assurance boundary

This controlled owner-operated Beta deliberately does not claim App Attest,
DeviceCheck, or another remote cryptographic attestation of iPhone hardware or
application identity. The reviewed PhilCore iOS implementation creates and
queries the key with `kSecAttrTokenIDSecureEnclave` and requires
`privateKeyUsage | userPresence`; the desktop verifies the exact P-256
proof-of-possession and approval signatures plus the signed public-record
claims. The plan must record both
`remoteHardwareAttestationEstablished: false` and
`maliciousAlternateClientResistanceClaimed: false`.

Treat any false claim of remote attestation, acceptance of a record that does
not require both flags, or omission of this boundary as at least HIGH. Do not
treat the disclosed absence of remote hardware/app attestation itself as a
finding for this owner-installed, physically scanned, zero-value Sepolia Beta.
It remains a disclosed nonclaim and would have to be reconsidered before a
materially different threat model or meaningful assets.

Treat a missing check, fail-open ambiguity, secret exposure, incorrect account
graph, unintended mutation route, replay bypass, approval bypass, arbitrary
recipient, automatic retry, or false-success reconciliation as at least HIGH.

## Allowed verification

Run only local, non-mutating checks that do not access secrets or devices, such
as syntax checks, the focused P2 guard suite, the reusable Beta contract suite,
classification validation, `git diff --check`, and source searches. If a check
is blocked by the environment, report it as unverified; do not weaken the gate.

## Required report

Produce one report containing:

- reviewed commit and tree;
- files reviewed and checks run;
- findings grouped as CRITICAL, HIGH, MEDIUM, LOW, and INFORMATIONAL;
- explicit unresolved CRITICAL and HIGH counts;
- confirmation that no phone, secret, signing authority, RPC credential, public
  mutation, or source edit was used;
- exactly one final line:

```text
CONTROLLED SEPOLIA BETA P2 BLOCKED BY THIS REVIEW: YES
```

or

```text
CONTROLLED SEPOLIA BETA P2 BLOCKED BY THIS REVIEW: NO
```

`NO` is allowed only when unresolved CRITICAL and HIGH are both zero. Record
the accepted review for execution by first saving the finished report exactly
as reviewed, then computing the SHA-256 of those saved report bytes externally.
Do not place that digest inside the hashed report itself. Return the external
digest alongside the report and use it with:

```text
PHILCORE_CONTROLLED_BETA_P2_RUNNER_REVIEW_COMMIT=<reviewed commit>
PHILCORE_CONTROLLED_BETA_P2_RUNNER_REVIEW_TREE=<reviewed tree>
PHILCORE_CONTROLLED_BETA_P2_RUNNER_REVIEW_SHA256=0x<64 lowercase hex>
PHILCORE_CONTROLLED_BETA_P2_RUNNER_REVIEW_DISPOSITION=ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH
```
