# O.30 V2 Formal Threat Model

Status: current V2 implementation-aligned threat model; not an external audit
or production approval.

## Current Recovery Authority Model

The shipped V2 model has three fixed recovery roles, in semantic order:

1. primary-device recovery;
2. hardware-security-key recovery; and
3. independent recovery factor.

The commitments are nonzero and pairwise distinct; they are not sorted by
numeric value or address. Exactly two roles must authorize a recovery action.
The only permitted factor bitmaps are `3` (roles 0+1), `5` (roles 0+2), and
`6` (roles 1+2). A one-factor or three-factor bitmap fails closed.

The active execution validator is not a recovery factor and never counts
toward the recovery-factor threshold. Actions 8, 9, and 11 use exact 2-of-3
current recovery factors. Action 10 additionally requires the current
validator plus exact 2-of-3 current recovery factors because it cancels a
recovery-configuration rotation; that extra signature does not give the
validator unilateral recovery-cancellation authority. A valid action-9
recovery quorum can cancel a pending validator recovery without validator
consent, so an active or compromised validator cannot veto recovery.

The earlier validator-plus-one-factor cancellation and numerically sorted
factor proposals are superseded. They remain historical rationale only and do
not describe current V2 behavior. Current authority is defined by
[O.36.1 Recovery And Cancellation Semantics](../reference/O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md)
and [O.37.1 V2 Recovery Lifecycle Update](../reference/O37_1_RECOVERY_LIFECYCLE_UPDATE.md).

## Assets

- Phil identity and immutable owner commitment;
- execution validator, key-ID binding, and validator epoch;
- three recovery factors, recovery configuration hash, and recovery epoch;
- native balance and EntryPoint deposit;
- ERC-20, ERC-721, and ERC-1155 holdings;
- exact intent, Runtime authorization, proof, approval, presence, and Device
  Vault signing authority;
- account/factory bytecode, CREATE2 salt, chain-adapter binding, nonce state,
  pending recovery state, receipts, events, and balance evidence.

## Attackers

- thief controlling a device;
- attacker holding an execution-validator key;
- malicious or compromised application/renderer;
- malicious bundler, relayer, paymaster, or RPC provider;
- one or more compromised recovery factors;
- social engineer targeting the user or recovery custodians;
- malicious token/NFT contract or callback recipient;
- chain-replay or wrong-account attacker;
- denial-of-service attacker;
- malicious future developer attempting to widen the account surface.

## Trust Boundaries

Trusted for local/test V2 implementation:

- protected local authentication and trusted presentation;
- Runtime policy, proof verification, and intent construction;
- Device Vault exact-purpose signing;
- reviewed V2 account/factory artifacts and local fixtures.

Untrusted:

- application requests;
- RPC and bundler responses;
- transaction ordering and public mempool;
- token contracts and recipients;
- recovery request relayers;
- public configuration until independently verified.

The initial local/test ECDSA validator cannot prove on-chain that Runtime
verified a STARK proof. Meaningful production assets remain blocked.

## Threat Register

| ID | Threat | Attacker capability and impact | Required mitigation | Residual risk |
| --- | --- | --- | --- | --- |
| O30-T01 | Stolen locked device | Attempts local unlock and validator use | Platform authentication, Device Vault encryption, fresh presence, short one-time session, recovery factors outside primary device | Device/platform compromise may defeat local controls |
| O30-T02 | Stolen unlocked device | Can operate Runtime until timeout | Exact trusted presentation, value policy, one-time signing, rapid 2-of-3 recovery freeze | Attacker may submit actions before freeze inclusion |
| O30-T03 | Validator key compromise | Can sign any ABI-permitted action and drain supported assets | Narrow typed ABI, no approvals/generic calls, epoch rotation, threshold recovery, production proof-backed/threshold validator gate | Initial ECDSA V2 remains vulnerable within its typed asset surface |
| O30-T04 | Validator service failure | Legitimate user cannot sign | Independent 2-of-3 recovery installs a new validator | Recovery delay creates availability loss |
| O30-T05 | Malicious application | Requests attacker recipient/amount or mislabels action | Application supplies intent request only; Runtime reconstructs fields and trusted UI displays exact effect | User may still approve a convincingly deceptive request |
| O30-T06 | Calldata substitution | Changes target, recipient, amount, token, ID, or data | Action-specific type hash, recomputed intent hash, full userOpHash signature, exact decoder | None if implementation and EIP-712 vectors are correct |
| O30-T07 | Malicious bundler | Reorders, delays, censors, duplicates, or substitutes UserOperation | Signed full userOpHash, keyed nonce, expiry, hash/receipt reconciliation, no retry authority reuse | Censorship and delayed inclusion |
| O30-T08 | Malicious RPC | Lies about code, nonce, balance, fees, simulation, or receipt | Restricted clients, block-pinned reads, independent derivation, source/code hash binding, post-state reconciliation | Coordinated provider eclipse remains an availability/information risk |
| O30-T09 | Paymaster manipulation | Adds sponsorship conditions or token liability | V2.0 rejects nonempty paymaster data | No V2.0 paymaster availability |
| O30-T10 | One recovery factor compromised | Attempts takeover or cancellation | Exact 2-of-3 threshold and distinct signatures | Social engineering may compromise another factor |
| O30-T11 | Two recovery factors compromised | Requests attacker validator | 48-hour delay, exact 2-of-3 cancellation by a recovery quorum, trusted alerts, and independent custody | Any colluding threshold can request, cancel, and complete takeover; the protocol intentionally cannot distinguish legitimate from compromised quorum |
| O30-T12 | Validator compromised during recovery | Attempts to cancel legitimate recovery or retain control | Validator is not a recovery factor, has no unilateral cancellation or veto authority, and ordinary execution freezes once recovery is pending | Compromised validator can still race ordinary actions before the recovery request is included |
| O30-T13 | Malicious recovery relayer | Changes request or completion outcome | Factor signatures bind exact request; completion accepts request ID only | Relayer can censor |
| O30-T14 | Recovery replay | Reuses old factors/signatures after rotation | Recovery nonce, request salt, account/chain, current config hash, recovery epoch, active-request consumption | Incorrect epoch implementation would be critical |
| O30-T15 | Chain replay | Reuses intent on another chain/account/EntryPoint | EIP-712 chain/account domain plus explicit chain, EntryPoint, account, userOpHash | Misconfigured adapters must fail closed |
| O30-T16 | User deception | User approves harmful but correctly encoded action | Display action type, account, network, recipient identity, asset, exact amount, fee cap, expiry, application, residual effect, recovery state | Trusted UI or user judgment can fail |
| O30-T17 | ERC-20 nonconformance | False return, fee transfer, rebasing, callback, misleading balances | Exact return and pre/post account/recipient delta checks, reentrancy lock, token acceptance policy | Malicious balance methods can lie or consume gas |
| O30-T18 | NFT callback/reentrancy | Recipient callback attempts nested action or denial of service | EntryPoint-only actions, execution lock, safe-transfer simulation, revert atomicity | Recipient can reject and cause operation failure |
| O30-T19 | Native recipient fallback | Reenters or consumes gas | Empty calldata, execution lock, EntryPoint-only actions, simulation | Recipient can force revert |
| O30-T20 | Storage corruption or layout error | Epoch/freeze/pending state overlaps | Declared layout, compiler layout artifact, fuzzing, invariants, non-upgradeable deployment | Implementation bug remains possible until audit |
| O30-T21 | Hidden administrator | Developer adds owner/admin/module/upgrade path | Prohibited ABI and source-pattern invariants, no proxy, independent audit | New version governance can still select unsafe code |
| O30-T22 | Stranded funds | Missing release path leaves native/token/deposit balance | Complete local/fork lifecycle guard before funding, exact residual and maximum-loss approval | Unsupported/malicious assets must not be funded |
| O30-T23 | Privacy linkage | Public account, factors, transfers, and recovery events link identity activity | Store only owner commitment and public key references; avoid private evidence/events | Public-chain linkage remains inherent |
| O30-T24 | Denial of service | Gas griefing, malicious return data, nonce blocking, repeated recovery attempts | Gas/return-data bounds, one pending request, expiry, permissionless expired-request cleanup, exact nonces, simulation | Chain congestion and censorship remain |

## Trusted Presentation Requirements

Before ordinary value movement, PhilCore displays:

- action type and purpose;
- chain/network and account;
- recipient address plus locally known identity label where available;
- asset contract, symbol as untrusted metadata, token ID, and exact raw amount;
- decimal display with raw integer value available;
- native value and maximum total fee separately;
- application identity/context;
- nonce lane and expiry;
- expected post-operation and residual balances;
- release route and maximum stranded amount.

Before recovery, PhilCore displays:

- account and chain;
- current and proposed validator public references;
- current/proposed epochs;
- participating recovery-factor safe references;
- exact freeze, delay, cancellation, and expiry times;
- statement that recovery moves no assets;
- statement that later asset movement requires a fresh approval.

Untrusted token names, symbols, URLs, application labels, and address-book
claims cannot replace raw identifiers.

## Security Invariants

1. Identity commitment, EntryPoint, factory binding, version, security model,
   recovery timing, and chain are immutable.
2. V2.0 exposes no generic call, approval, delegatecall, batch, paymaster,
   session-key, module, or upgrade path.
3. Every value movement is EntryPoint-only and action-specific.
4. Recovery and recovery-factor rotation move no value and make no external
   calls.
5. Exactly one validator is active and zero-validator state is impossible.
6. Validator epoch increases by one on rotation/recovery and never decreases.
7. Recovery epoch increases by one on recovery or factor rotation and never
   decreases.
8. Recovery commitments occupy fixed semantic roles, are pairwise distinct and
   nonzero, and are not numerically sorted.
9. Active recovery freezes ordinary and maintenance lanes.
10. Only factor bitmaps `3`, `5`, and `6` satisfy exact 2-of-3 recovery; the
    execution validator never counts toward that threshold.
11. The active validator cannot unilaterally cancel or veto an exact 2-of-3
    validator-recovery request. Action 10's validator signature is an
    additional condition for cancelling recovery-configuration rotation, not
    recovery-factor authority.
12. Completion installs only threshold-authorized pending state.
13. Recovery cannot settle before 172800 seconds (48 hours), and a request at
    or after 604800 seconds (7 days) expires and clears without installing its
    proposal.
14. Expired pending state can be cleared without installing proposed state.
15. Old, cancelled, expired, completed, wrong-chain, wrong-account, and
    wrong-epoch authority fails.
16. External action failure reverts state and event evidence.
17. Account 1 and Account 2 have no special role.
18. Funding is prohibited until the full release lifecycle passes.

## Recovery Custody Assumption

The three fixed roles are intended to be independently custodied and separated
across practical failure and administrative domains. Co-locating factors,
placing them under one operator, or synchronizing them through one cloud
account weakens the intended two-compromise threshold. Native/WebAuthn factor
policies restrict synchronized credentials where the implementation can
observe that property, but protocol cryptography cannot prove every real-world
custody domain is independent. Operational enrollment and ceremony review
remain required.

## Unresolved Production Risks

- exact proof-backed or threshold execution validator;
- operational validation of independent recovery custody;
- trusted recovery notification and ceremony;
- token acceptance/denylist governance without hidden administration;
- independent RPC observations for high-value operations;
- public chain-adapter version discovery;
- external audit and formal verification scope.

These risks block production meaningful assets but do not prevent a later
local Solidity implementation phase from using this specification.
