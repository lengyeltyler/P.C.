# O.29 Recovery-Capable Account V2 Architecture Design

Status: `ARCHITECTURE_DESIGN_COMPLETE_LOCAL_ONLY`.

O.29 defines a production-oriented direction for the next PhilCore Ethereum
account. It does not implement contracts, create executable authority, deploy
infrastructure, recover the O.27 prefund, or mutate any public chain.

## Design Goals

V2 should:

1. preserve Phil identity as a chain-independent device-first identity;
2. retain EntryPoint-only account execution and exact UserOperation binding;
3. support useful asset actions without exposing a generic wallet backdoor;
4. make ordinary fund release a normal, fully authorized action;
5. make lost-validator recovery a delayed authority-rotation process, not an
   asset-transfer privilege;
6. remain non-upgradeable and versioned through new factories and addresses;
7. allow reviewed chain adapters to evolve independently of identity;
8. require a complete fund lifecycle before any test funding.

The V1 source and deployed infrastructure remain frozen. The O.27 balance is
historical testnet learning data and is not a V2 migration source.

## Selected Account Model

The selected direction is a versioned, non-upgradeable ERC-4337 v0.7 account
with a small set of typed intent selectors. The account is not a generic
`execute(address,uint256,bytes)` wallet.

The first implementation specification should include typed actions for:

- fixed confirmation;
- native ETH transfer;
- ERC-20 transfer;
- ERC-721 transfer;
- ERC-1155 transfer;
- EntryPoint-deposit withdrawal;
- validator maintenance and recovery.

Contract calls should initially use reviewed capability adapters. An adapter
call must bind the adapter policy version, target, selector, value, calldata
hash, and action purpose. Raw arbitrary calls, delegatecall, proxy upgrades,
public sweeps, and direct EOA execution remain prohibited.

Bounded atomic batching is architecturally possible, but is disabled for the
first implementation. A later design must cap item count and total value and
bind every item plus the ordered batch root.

## Intent Authorization

Every action is represented by a typed intent. Its signed authorization must
bind:

- security-model and action versions;
- action type, purpose, and unique action ID;
- canonical Runtime authorization digest;
- chain ID, EntryPoint, account, and full Packed UserOperation hash;
- EntryPoint nonce key and sequence;
- active validator configuration epoch;
- exact recipient or target;
- native value;
- token, token ID, and token amount where relevant;
- calldata hash;
- ordered batch root and item count where relevant;
- maximum total fee;
- expiry.

Runtime must reject missing or irrelevant fields rather than silently treating
them as zero. Proof, approval, presence, Runtime authorization, Device Vault
signature, and UserOperation authority remain one-time.

The initial V2 prototype may continue the explicit
`local-proof-gated` responsibility split, in which Ethereum verifies the
validator and account rules while Runtime verifies the proof. Meaningful
production assets remain blocked until an on-chain proof-backed validator or
another formally reviewed production authorization composition is accepted.

## Responsibility Boundaries

### Account

The account:

- accepts execution only from its immutable EntryPoint;
- recognizes only versioned typed selectors;
- validates the full action shape, expiry, validator epoch, and recovery state;
- performs only the exact typed action;
- emits an action-specific event;
- cannot interpret application policy or silently widen intent.

### Runtime

Runtime:

- interprets the application request as a bounded PhilCore intent;
- applies Trust Manager, capability, policy, and value limits;
- resolves the reviewed chain adapter and capability adapter;
- simulates the exact operation and complete fund lifecycle;
- presents exact recipient, amount, target, calldata meaning, fees, and
  residual-fund behavior;
- obtains fresh proof, user approval, user presence, and Device Vault signing;
- constructs one exact UserOperation and reconciles its receipt and state.

Runtime authority is not reusable and is not exposed to applications.

### Validator

The execution validator remains a Device Vault-held chain-specific key or
future proof-backed validator. It signs one exact purpose-bound digest and
cannot sign arbitrary messages, raw transactions, typed data, or reusable
wallet sessions. The active validator key reference and configuration epoch
are explicit authorization inputs.

### Chain Adapter

The Ethereum adapter owns Ethereum-specific encoding, EntryPoint/bundler
allowlists, estimation, simulation, receipt decoding, and balance
reconciliation. It does not decide identity, policy, approval, or recovery.

Other chains use different adapters:

```text
Phil identity
  -> chain-independent authorization intent
  -> chain-specific adapter
  -> network-specific account or authorization mechanism
```

Ethereum account implementation details must not become Phil identity
semantics.

## Recovery Architecture

O.29 separates two commonly conflated operations.

### Ordinary Fund Release

An available validator releases residual funds through an ordinary typed
native, token, or deposit-withdrawal intent. It requires a new proof,
authorization, exact approval, user presence, Device Vault signature, nonce,
expiry, and separate public-mutation approval.

There is no public sweep and no special recovery recipient.

### Lost-Validator Recovery

Lost-validator recovery rotates execution authority only. It does not transfer
assets and cannot invoke ordinary execution.

The production direction is a threshold of independently held factors, such
as two approvals from three registered factors across:

- a second trusted PhilCore device;
- a hardware-backed recovery credential;
- an offline recovery credential or reviewed guardian.

A single recovery EOA is insufficient for production.
Recovery factors must not be derived from `phil_secret`, the identity root, or
the active execution validator. They require independent custody and failure
domains.

The delayed flow is:

```text
threshold factors authorize one exact new validator and recovery epoch
  -> account records the request and freezes ordinary execution
  -> cancellation/challenge window
  -> request expires unless completed in time
  -> permissionless completion after threshold and delay checks
  -> validator rotates and account unfreezes
  -> any asset release requires a separate ordinary authorization cycle
```

The request binds account, chain, owner commitment, current and proposed
validator configuration, recovery configuration epoch, nonce, request time,
delay, expiry, and purpose.

Recovery-configuration rotation is itself delayed and cross-authorized. It
cannot transfer value, change the owner commitment, change EntryPoint, enable
generic execution, or appoint Account 1 or Account 2.

## ERC-4337 Model

V2 retains EntryPoint v0.7 and `PackedUserOperation`.

Recommended keyed nonce lanes:

- key `0`: ordinary actions;
- key `1`: validator/configuration maintenance;
- key `2`: delayed recovery.

Recovery freeze blocks the ordinary lane. Keyed lanes improve operational
separation but do not replace action IDs, epochs, expiry, or replay tracking.

Paymaster compatibility may be designed, but is disabled by default. When
disabled, nonempty `paymasterAndData` must fail. Any future sponsorship policy
must bind the exact paymaster, validity interval, token charge, and maximum
user liability.

EntryPoint deposits are assets under the test-fund release policy. Withdrawal
requires a typed exact recipient/amount authorization. Bundlers and RPC
providers are untrusted for authorization and cannot alter signed fields.

## Migration Model

O.29 rejects proxy migration and attempts to retrofit V1.

The selected model is identity and chain-adapter version migration:

1. the same Phil identity and owner commitment select a reviewed V2 Ethereum
   adapter;
2. a new V2 factory derives a new counterfactual account;
3. local and fork lifecycle tests verify the exact V2 bytecode and release
   route;
4. a separate phase accepts the new infrastructure binding;
5. only then may a fresh funding proposal be considered.

For future recovery-capable accounts, assets migrate through fresh typed asset
actions. The canonical adapter record moves only after both old and new state
are verified. V1 cannot perform such an asset migration, and V2 cannot claim
or redirect the O.27 prefund.

## Fund Lifecycle

Every future funded test must complete:

```text
derive and verify account
  -> verify release route
  -> simulate funding, operation, and release
  -> approve and fund exact bounded amount
  -> execute exact operation
  -> separately approve and release exact residual
  -> verify final balances and consumed authority
```

Zero final account and deposit balances are preferred. Deliberate dust requires
an exact bound, reason, recipient plan, and approval before funding.

## Security Assumptions

- Device Vault and Runtime remain trusted local-computing boundaries until
  proof validation moves on-chain.
- A compromised validator can authorize whatever the account ABI permits;
  therefore the ABI remains typed and narrow.
- Threshold recovery is secure only when factors have independent failure
  domains and ceremonies resist social engineering.
- Applications, RPC providers, bundlers, paymasters, and capability adapters
  are untrusted until their exact behavior is verified.
- Non-upgradeability reduces administrator risk but makes version migration
  and lifecycle planning mandatory.

## Unresolved Questions

- Include NFT selectors in V2 or defer them to V2.1?
- What registry design permits reviewed capability adapters without a hidden
  administrator or permanent inflexibility?
- Which on-chain proof-backed or threshold validator is required before
  meaningful assets?
- Which recovery factors, threshold, delay, expiry, and cancellation policy
  are acceptable for production?
- Should bounded batching ship in V2 or a later audited version?
- Is paymaster compatibility needed for the first public V2 test?
- How should canonical chain-adapter versions be published and verified?

These questions require later, separately approved design and implementation
phases. O.29 does not answer them by creating code that could be deployed.

## O.30 Refinement

O.30 resolves the V2.0 implementation shape:

- ERC-721 and ERC-1155 safe-transfer selectors are included;
- contract adapters, arbitrary calls, batching, paymasters, allowances, and
  session keys are deferred to a new account version;
- initial local/test execution uses one Device Vault ECDSA validator with
  epochs, while meaningful production assets remain blocked on a stronger
  validator composition;
- recovery uses exact 2-of-3 independent secp256k1 factors, a 48-hour delay,
  and a 7-day expiry;
- chain-adapter publication remains durable/local until a separate public
  registry design is accepted.

The canonical refinement is
[O.30 V2 Account Specification And Threat Model Refinement](./O30_V2_ACCOUNT_SPECIFICATION_AND_THREAT_MODEL_REFINEMENT.md).

## Stop Boundary

O.29 adds architecture, policy, and local specification evidence only. No V1
contract or factory was modified. No V2 contract was implemented. No account,
factory, UserOperation, proof, Runtime authorization, user-presence event, or
Device Vault signature was created. Public mutations are zero.
