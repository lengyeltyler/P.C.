# Phil Sepolia Mint Composed Demo V1

> **Retired Alpha runner:** the historical `prepare:phil-sepolia-mint-demo`,
> `prepare:phil-sepolia-mint-public-plan`, and public execution commands now
> stop immediately. They predate the controlled Beta's reusable account,
> staged approvals, single-account gate binding, and current-owner recipient
> enforcement. Only a future runner implementing the controlled P0-P5 plan may
> authorize a new public mutation.

Status: **bounded Alpha execution completed and independently reconciled**

This document is the source of truth for the bounded Sepolia mint design. The
completed execution is recorded in
[`PHIL_SEPOLIA_MINT_ALPHA_EVIDENCE_2026-08-25.md`](./PHIL_SEPOLIA_MINT_ALPHA_EVIDENCE_2026-08-25.md).
Neither document supersedes the production account or proof-backend decisions.

## Decision and trust boundary

The selected route is a **restricted smart-account execution signature released
only after local composed authorization**.

- PhilCore generates and independently verifies the Noir / Barretenberg root
  proof locally.
- The enrolled iPhone Secure Enclave P-256 key signs the approval digest after
  Face ID user presence.
- The proof public inputs and iPhone request are checked against the identical
  canonical authorization-envelope digest.
- Policy, device state, four epochs, time, zero value, maximum fee, account
  nonce, cancellation/denial state, and durable four-dimensional replay state
  are checked before Device Vault can sign.
- The Device Vault secp256k1 execution key is separate from `phil_secret` and
  signs only the exact ERC-4337 v0.7 UserOperation hash.

Ethereum **does not verify the Noir proof or iPhone P-256 signature**. No
Solidity proof verifier, P-256 verifier, accepted fact, trusted attestation,
bridge, or Cairo/Garaga verifier participates in this candidate. Calling this
"on-chain proof verification" is prohibited.

On chain, Ethereum enforces:

1. the canonical v0.7 EntryPoint and its account nonce;
2. the Device Vault execution signature over the packed UserOperation;
3. an immutable account target restricted to the ActionGate, zero value, and
   the single `verifyAndConsume` selector;
4. factory registration of the calling smart account;
5. Sepolia chain ID, expiry, and independent one-time consumption of the
   envelope digest, root nullifier, and device approval nonce;
6. a gate-only, non-transferable, zero-value test-pass consumer.

The local composition service is therefore a trusted security boundary. A
compromise of the unlocked Desktop runtime or Device Vault execution key could
bypass the proof/device policy because Ethereum cannot independently check
those artifacts. This is acceptable only for this disposable testnet demo.

## Canonical operation

The envelope binds:

- chain ID `11155111`;
- EntryPoint `0x0000000071727de22e5e9d8baf0edac6f37da032`;
- factory, counterfactual smart account, ActionGate, consumer, and recipient;
- account nonce, validity window, and maximum total fee;
- scoped owner commitment and scope epoch;
- Noir proof-descriptor hash;
- device, recovery, and validator epochs;
- intent, policy, parameters, account, network, and human-presentation hashes.

The root nullifier is finalized after the pre-proof envelope digest is derived,
because the proof derives that nullifier. The verified proof public inputs and
the final authorization object bind the nullifier separately before signing is
released. It cannot be changed without a new valid proof, and replay storage
plus the ActionGate consume it independently.

The iPhone displays and independently reconstructs the network, account,
recipient, consumer, action, zero value, fee ceiling, expiry, consequence, and
verification boundary. Its Secure Enclave key signs the exact device approval
digest, not an arbitrary renderer-provided digest.

The authorization envelope is valid for one hour. The iPhone approval request
remains limited to two minutes and never extends beyond the envelope expiry.
The one-hour envelope window leaves enough time to present the frozen public
mutation plan for a separate explicit confirmation; it does not authorize any
mutation by itself.

## Frozen read-only Sepolia preflight

The read-only preflight in
`config/ethereum-sepolia/PHIL_SEPOLIA_MINT_DEMO_READ_ONLY_PREFLIGHT.json`
verified chain `11155111`, EntryPoint bytecode, bundler EntryPoint support,
deployer nonce equality, unoccupied predicted addresses, creation bytecode, and
deployment gas estimates without a public mutation.

At the recorded nonce, the preflight predicted this infrastructure:

| Role | Predicted address |
|---|---|
| Account factory | `0xee49bdFeA3535D8d68edBE3b91c8AA8734A2B48A` |
| Local-composed ActionGate | `0xCbd3b73C257Fbe4ac4a1084163Aa4cA63ddE8AFA` |
| Harmless pass consumer | `0xb453815C2804BBB85fd6B10579b80b2E7Dc4fB32` |
| Proof verifier / attestation | **none** |
| EntryPoint v0.7 | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` |

The bounded Alpha executor subsequently deployed these exact addresses and
completed the approved UserOperation. The committed configuration remains the
immutable pre-execution input rather than being rewritten as post-execution
state. The final receipt and live-state reconciliation are recorded in the
Alpha evidence document.

## Completed Alpha execution

The five separately approved public mutations completed without automatic
retry: three exact contract deployments, one capped smart-account prefund, and
one signed UserOperation. Sepolia transaction
[`0x5b26...bedc`](https://sepolia.etherscan.io/tx/0x5b26b57ca7593acaf26f7d4c0e464d64f4cc6fabe576b94687495e7b4bdfbedc)
succeeded in block `11561486`, issued pass `1` to the Phil smart account,
advanced the EntryPoint nonce to `1`, and consumed the envelope digest, root
nullifier, and device approval nonce. A read-only replay was rejected with
`EnvelopeAlreadyConsumed`.

The committed preflight also pins the creation-code hashes for the factory,
counterfactual account, ActionGate, and harmless consumer. Both the read-only
planner and the executor reject ignored Hardhat artifacts unless all four match
those committed hashes exactly.

After the source and packages are frozen, use the non-writing form so this live
check cannot change their committed configuration or source identity:

```sh
npm run check:phil-sepolia-mint-demo
```

## Product state machine

1. The user unlocks the local Phil identity.
2. Desktop builds the exact counterfactual account and zero-value mint review.
3. Desktop proves and independently verifies the Noir relation without
   serializing the root secret or nullifier seed.
4. Desktop persists the encrypted request and proof context before showing the
   expiring QR code.
5. iPhone establishes the existing encrypted private-LAN transport, displays
   the exact review, compares the fingerprint, obtains Face ID, and signs.
6. Desktop durably persists the verified P-256 response before composition.
7. Desktop revalidates proof, device, policy, epochs, time, nonce, fee, value,
   revocation/current enrollment, cancellation/denial, and replay state.
8. Desktop durably reserves the exact envelope/nullifier/approval/account-nonce
   tuple before creating Device Vault signing authority.
9. Device Vault signs the exact UserOperation. Desktop persists it as mode-0600
   `signed-unsubmitted-v1.json` and marks the replay tuple consumed.
10. The UI stops at **Signed locally and ready for final testnet confirmation**.

An interruption after response persistence resumes from the approved ceremony.
An interruption after replay reservation may resume only the identical tuple.
Once the signed artifact is persisted, restart reuses that exact artifact and
does not create a different signature or authorization. Any changed tuple or
consumed operation fails closed.

There is deliberately no Desktop IPC channel for deployment, funding, bundler
submission, or arbitrary RPC. The only renderer channels are begin, status,
and cancel.

## Public mutation gate

Before the first mutation, present and receive explicit confirmation for this
literal ordered set:

1. deploy the factory from the reviewed disposable deployer nonce;
2. deploy the ActionGate from nonce + 1;
3. deploy the harmless pass consumer from nonce + 2;
4. fund only the exact counterfactual smart account with disposable Sepolia ETH
   up to the reviewed prefund ceiling;
5. submit exactly one reviewed, signed UserOperation to the approved v0.7
   bundler;
6. make no other transfer, deployment, approval, or call.

Approval for one step is not approval for a changed address, nonce, amount,
operation, endpoint, or retry. A failed or ambiguous mutation stops the run for
read-only reconciliation. Never automatically replace a transaction or resubmit
a UserOperation.

The external operator workflow is intentionally separate from Desktop IPC:

```sh
npm run prepare:phil-sepolia-mint-public-plan -- \
  --signed-artifact /absolute/path/to/signed-unsubmitted-v1.json
```

That command performs read-only checks, reconstructs and validates the signed
operation, pre-signs the four exact EIP-1559 transactions only to derive their
hashes, writes a mode-0600 plan, and reports `publicMutationOccurred: false`.
It contains no broadcast or bundler-submission method. The plan is invalid if
the frozen commit/tree, protected `pqREADME.md` hash, deployer nonce, predicted
addresses, EntryPoint code, fee cap, signed artifact, or expiry changes.
The plan digest also binds SHA-256 commitments to the complete RPC and bundler
URLs, so endpoint credentials are not displayed while any endpoint change
invalidates approval.

Only after the plan digest and all five ordered mutations have been shown and
explicitly confirmed may the operator invoke the executor with both the exact
plan digest and the literal one-shot approval phrase. The executor repeats all
read-only checks before reaching its first broadcast. The phrase is
`I_APPROVE_THE_EXACT_PHIL_SEPOLIA_MINT_PUBLIC_MUTATIONS_V1`.

The executor persists evidence before and after each mutation. A timeout,
unexpected hash, failed receipt, or bundler ambiguity records
`STOPPED_REQUIRES_READ_ONLY_RECONCILIATION` and never retries automatically.

## Failure and recovery procedure

- Before mutation: cancel or let the request expire; no public recovery is
  necessary.
- Deployment ambiguity: stop and reconcile nonce, transaction, receipt,
  bytecode, and constructor bindings read-only.
- Funding ambiguity: stop and reconcile balances and EntryPoint deposit state;
  never send a second transfer by assumption.
- Bundler timeout: query the UserOperation hash and EntryPoint events; do not
  submit again until absence is proven and a new explicit approval is obtained.
- Failed UserOperation: record the on-chain failure and remaining disposable
  balance; do not claim a mint.
- Successful UserOperation: independently verify transaction receipt,
  `UserOperationEvent` success, factory/account code, ActionGate consumption,
  pass event, token ID, recipient, nonces, and explorer link.

The demo account is immutable and intentionally has no on-chain owner rotation
or withdrawal surface. A small unused prefund can therefore be stranded. Fund
only the reviewed disposable ceiling and classify any remainder as expendable
Sepolia test ETH. This limitation blocks Beta and production use.

## Protocol sources

- [EIP-4337](https://eips.ethereum.org/EIPS/eip-4337) defines the account
  abstraction EntryPoint and UserOperation model used here.
- [ERC-7769](https://eips.ethereum.org/EIPS/eip-7769) defines the bundler JSON-RPC
  methods and receipt shape used by the guarded operator path.
- The local `@account-abstraction/contracts` dependency is pinned to `0.7.0`;
  the canonical EntryPoint address and deployed code hash are rechecked live
  before planning and again before execution.

## Security evidence and classification

- Real Noir proof plus real native verification and P-256 composition tests.
- Local canonical EntryPoint execution of the exact product-signed operation.
- Field mutation, wrong proof/device/key/network/account/gate/consumer/recipient,
  time, denial, cancellation, epoch, value, fee, nonce, high-S, malformed
  signature, restart, interrupted persistence, and replay tests.
- 48 deterministic post-signature mutation fuzz cases, six malformed execution
  signature lengths, and 32 gate replay/mint invariant cases.
- Slither `0.10.4`: no finding in the four new Sepolia contracts.
- 34 custom Solidity invariants pass.
- Production dependency audit: zero known vulnerabilities. Development tooling
  advisories remain and are a Beta blocker.
- STWO, synthetic secrets, public submission methods, paymasters, arbitrary
  targets, and unrestricted signing are unreachable from the product path.

Classification: **completed bounded Sepolia Alpha demonstration only**. It is
not a Beta candidate, production-ready, post-quantum secure, or externally
audited product. The next authority gate is the separate
[PhilCore Beta Readiness Plan](../PHILCORE_BETA_READINESS_PLAN.md).
