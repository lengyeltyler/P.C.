# ACP-0004: Controlled Sepolia Beta

Status: **implementation candidate; independent acceptance required**

Network: Ethereum Sepolia, chain ID `11155111`

Mainnet: prohibited

## Decision

The controlled Beta uses the non-upgradeable `PhilCore4337Account` and
`PhilCore4337AccountFactory`, composed with
`PhilSepoliaLocalComposedActionGateV1` and
`PhilSepoliaMintPassConsumerV1`.

The ActionGate is constructor-bound to one predicted counterfactual Beta
account and rejects every other factory-registered account. It also resolves
that account's current execution owner on chain and accepts no other mint
recipient. These checks prevent copied pending authorization fields from being
consumed first by a throwaway account.

This selection replaces the disposable one-shot Alpha account for Beta. It
does not select the broader `PhilCoreV2MinimalAccountV2` asset-action surface.
That contract remains separate recovery architecture evidence and is not the
public introduction account.

The exact machine-readable profile is
[`config/controlled-sepolia-beta-v1.json`](../../config/controlled-sepolia-beta-v1.json).

## Frozen authority model

```text
local Phil root proof
  + current enrolled iPhone P-256 approval with fresh user presence
  + current policy, epochs, expiry, account address, nonce, fee and recipient
  -> one canonical composed envelope
  -> Device Vault releases one ERC-4337 execution signature
  -> EntryPoint v0.7 validates the current execution owner and nonce
  -> reusable account permits only zero-value call to immutable ActionGate
  -> ActionGate admits only the one authorized account and its current owner
  -> ActionGate consumes envelope, nullifier and device nonce once
  -> harmless non-transferable Sepolia pass
```

Ethereum does not verify Noir or the iPhone P-256 approval in this Beta. Those
checks remain local preconditions to execution-signature release. Ethereum
enforces the EntryPoint signature, nonce, immutable account restrictions,
single-account gate, current-owner recipient, expiry, replay state, and
consumer call.

## Account lifecycle

- The first UserOperation may deploy the counterfactual account through the
  immutable factory.
- Every later operation reads `EntryPoint.getNonce(account, 0)` and uses empty
  `initCode`.
- Only nonce key `0` is admitted.
- No operation is retried automatically after timeout, provider disagreement,
  submission ambiguity, or missing receipt.
- The execution owner may rotate without changing the account address,
  identity commitment, EntryPoint, or ActionGate.
- An independent recovery authority may request delayed owner recovery but may
  not execute ordinary actions or release test funds.
- A pending recovery freezes ordinary execution. The current owner may cancel
  during the challenge window.
- Recovery-authority rotation uses the existing delayed, other-authority
  cancellation model.

The Beta delay is exactly 172,800 seconds and recovery expiry is exactly
604,800 seconds. This single independent recovery authority is accepted only
for a disposable, no-meaningful-assets Sepolia cohort. Production or mainnet
requires a new threshold/modular recovery decision.

## Permitted surfaces

Ordinary Beta execution permits exactly:

- `execute(address,uint256,bytes)` through EntryPoint;
- the immutable composed ActionGate as target;
- `value == 0`; and
- composed gate selector `0xfa724deb`.

The legacy generic gate selector remains supported for existing local
compatibility fixtures, but the frozen Beta gate bytecode exposes only the
composed selector. The Beta does not permit arbitrary targets, native/token
transfers, approvals, batches, delegatecall, upgrades, generic signing,
session keys, aggregators, or paymasters.

Maintenance selectors are separate from ordinary actions. The current owner
may rotate the execution key and may use `releaseTestFunds(uint256,uint256)`
through EntryPoint to return disposable native balance and EntryPoint deposit
to the current owner only. The recipient cannot be selected. Recovery freeze
blocks release.

## Funds and fees

- Maximum fee per ordinary authorization: `0.005` Sepolia ETH.
- Maximum native balance per account: `0.01` Sepolia ETH.
- Maximum EntryPoint deposit per account: `0.01` Sepolia ETH.
- Maximum total operator exposure: `0.05` Sepolia ETH.
- No meaningful assets, paymaster, automatic replenishment, or automatic
  retry.
- Any replenishment or public mutation uses a frozen plan and independent
  receipt reconciliation.

## Change control

Changing the chain, EntryPoint, account/factory, ActionGate, consumer,
selectors, recovery timing, recovery authority model, fund ceilings, local
verification boundary, or permitted action requires a new architecture change
record and a repeat of B1-B7. External review of the exact source and packages
is still required before this record can be marked accepted for Beta.
