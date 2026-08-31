# O.38 Token And Residual-Asset Policy

Status: `NATIVE_ETH_ONLY_ACCEPTED_LOSS_PROHIBITED_BY_DEFAULT`.

The V2 minimal account supports typed native ETH transfer and exact
EntryPoint deposit withdrawal. It has no arbitrary execution, token
interface, receiver advertisement, adapter, module, approval, or rescue
function.

## Required user warning

> This PhilCore V2 account supports native ETH only. ERC-20, ERC-721, and
> ERC-1155 assets sent directly to it may be permanently stranded. It does
> not advertise token receiver support and has no token rescue or arbitrary
> execution path. Do not send tokens to this address.

## Required operator warning

> Treat every token balance as unsupported and potentially unrecoverable.
> Do not test token transfers, approvals, safe transfers, airdrops, or rescue
> assumptions. Any future token support requires a new reviewed account
> version and Architecture Change Control.

## Native ETH lifecycle

- deployed-account balance: releasable only by an exact lane-0 authorized
  `transferNative` action;
- EntryPoint deposit: releasable only by an exact lane-0 authorized
  `withdrawEntryPointDeposit` action;
- failed account deployment: value must not be attached to factory
  `createAccount`; deployer gas loss is bounded separately;
- undeployed counterfactual account: never pre-fund during a deployment
  rehearsal;
- decommission: withdraw the entire EntryPoint deposit, transfer the exact
  native balance to an approved recipient, verify both balances are zero,
  then stop using the address. The contract is not destroyed.

The O.28 rule remains binding: no counterfactual or deployed account may be
funded without a proven release path or a separately explicit accepted-loss
approval. The first rehearsal plan proves both release paths locally and
includes only a bounded `0.001 ETH` native balance and `0.005 ETH` EntryPoint
deposit. Those are future ceilings, not O.38 funding authorization.

Any failed release test stops the rehearsal. No token movement, native
funding, deposit, or accepted-loss decision occurred in O.38.
