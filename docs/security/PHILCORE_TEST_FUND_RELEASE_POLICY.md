# PhilCore Test-Fund Release Policy

Status: active canonical security policy.

## Permanent Rule

Every testing flow that places native currency or tokens into a contract,
smart account, EntryPoint deposit, paymaster, escrow, or other address must
have a verified and explicitly authorized route to release, withdraw, sweep,
refund, or otherwise recover unused test funds.

Calling funds disposable is not a substitute for a safe release route in
normal development or test infrastructure.

## Funding Preconditions

Before any test funding:

1. identify the exact release mechanism and its callable contract path;
2. prove the path locally and on a fork when technically possible;
3. bind release authority to the canonical account authorization model;
4. identify the intended residual recipient, which must not be a hidden
   Account 1 or Account 2 administrator;
5. bind chain, account, nonce, purpose, recipient, and amount;
6. require fresh user approval, user presence, and Device Vault signing for
   every public release;
7. include expected residual funds and exact maximum exposure;
8. fund only the minimum plus a documented bounded margin;
9. record balances before and after funding and release;
10. obtain a separate exact approval for each public withdrawal, sweep,
    refund, or transfer.

Proof, Runtime authorization, approval, presence, signature, and UserOperation
authority are one-time. None may be reused for release.

## Required Release Properties

A verified release route must:

* be callable only through canonical PhilCore account validation;
* bind the exact residual recipient and exact amount in the signed
  UserOperation;
* use EntryPoint nonce replay protection and explicit chain/account binding;
* use a release-specific purpose or action type;
* emit an auditable event;
* prevent direct external invocation and disposable-wallet privilege;
* provide no unrestricted owner bypass, hidden super-admin, public sweep,
  `tx.origin` dependency, delegatecall escape, or reusable authorization.

A separately named withdrawal function is optional. A restricted authenticated
execution path is acceptable if it proves all properties above.

## Covered Holdings

This policy applies equally to:

* counterfactual and deployed smart-account native balances;
* EntryPoint deposits;
* paymaster deposits and stakes;
* contract and escrow native balances;
* ERC-20, ERC-721, ERC-1155, and other token holdings;
* refunds, change, residual dust, and protocol-held test value.

Never assume a counterfactual address can release funds merely because code
might later be deployed there. Never fund a new implementation until its
release route passes local and fork simulation.

## Unavoidable-Lock Exception

Knowingly locked test funds are permitted only when all of these are recorded:

1. the lock is unavoidable in the exact production design being tested;
2. the precise amount is explicitly expendable;
3. the user sees the exact maximum possible loss;
4. the user explicitly approves that exact loss before funding;
5. technical evidence explains why no safer recovery route exists.

The exception is fail-closed. Missing evidence prohibits funding.

## Post-Operation Duty

After the intended test operation, promptly sweep or refund unused funds
through a new exact authorization cycle. A deliberately retained dust amount
must be recorded and separately justified.

## Mandatory Lifecycle Gate

Every future funding phase must specify and test this complete state machine:

```text
derive and verify account
  -> verify the exact release route
  -> simulate create, fund, execute, release, and final state
  -> approve and fund the exact bounded amount
  -> execute the separately approved operation
  -> separately approve and release the exact residual
  -> verify final balances, receipts, nonces, and consumed authority
```

Before funding, the proposal must record:

- exact account implementation, factory, derivation, and chain binding;
- asset type and exact maximum funding;
- exact maximum amount that could remain stranded;
- intended residual recipient;
- callable release selector or adapter route;
- required authorization, approval, presence, signing, and nonce;
- expected balance after the intended operation;
- expected balance and EntryPoint deposit after release;
- local and fork simulation results when technically possible.

After testing, evidence must reconcile account balances, EntryPoint deposits,
token balances, nonces, receipts, and public-mutation count. The preferred
final balance is zero. Nonzero dust requires an exact pre-funding bound,
technical justification, intended later disposition, and explicit approval.

Recovery of validator authority is not a release route unless the recovered
account must still use a separately authorized exact asset-transfer or deposit
withdrawal action. Recovery authority must never carry an implicit sweep
privilege.

The machine guard for future funding plans is
`scripts/ethereum-sepolia/test-fund-release-policy.cjs`. A funding phase must
pass both `validateTestFundReleasePlan(...)` and
`validateTestFundLifecyclePlan(...)` before presenting a public funding
approval.
