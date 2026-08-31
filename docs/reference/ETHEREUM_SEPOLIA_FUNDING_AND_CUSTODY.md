# Ethereum Sepolia Funding and Custody

Status: plan only; no funds requested or transferred.

This reference is subordinate to the canonical
[PhilCore Test-Fund Release Policy](../security/PHILCORE_TEST_FUND_RELEASE_POLICY.md).
Every future funding proposal must identify and pretest its release route,
residual recipient, exact residual estimate, and separate release-approval
boundary. Disposable testnet classification alone is insufficient.

## Disposable Model

The first experiment uses:

- Sepolia ETH only;
- a disposable, nonvaluable funding source;
- a Device Vault execution validator that is not the deployer or funder;
- a separate recovery authority;
- no production treasury, user assets, valuable token, or mainnet key;
- no paymaster.

Roles remain separate:

| Role | Purpose | Prohibited use |
| --- | --- | --- |
| deployer | deploy accepted test contracts | Phil identity, valuable wallet |
| funder | transfer capped Sepolia ETH | validator signing, contract administration |
| execution validator | sign one exact UserOperation | deployment, arbitrary transfer |
| recovery authority | delayed maintenance | normal execution |

Private keys and endpoint credentials must remain in approved external custody.
They must not appear in source, docs, examples, process arguments, shell
history, logs, manifests, or test output.

## Prefunding

Without a paymaster, EntryPoint requires sufficient prefund for the packed
operation. A counterfactual account may receive ETH at its deterministic
address before code exists. Alternatively, an approved deposit/funding
mechanism may be used only after its exact semantics are reviewed.

The account's `receive()` accepts ETH. The restricted execution path does not
provide a generic withdrawal function. Any unused balance can therefore become
stranded unless a separately authorized zero-value/transfer policy is designed.
The first funding amount should be deliberately small.

## Estimation

O.17 does not quote a currency amount. A later read-only preflight must:

1. estimate each accepted deployment;
2. estimate verification plus first account execution;
3. read current Sepolia fee data;
4. apply explicit gas and fee caps;
5. calculate worst-case prefund;
6. present a conservative capped funding range for human approval.

Estimates do not guarantee inclusion or final cost. No stale gas-price estimate
may be treated as authorization.

## Human Actions

- approve disposable deployer, funder, validator, and recovery roles;
- obtain Sepolia ETH outside PhilCore;
- review the capped amount and recipient;
- transfer only after deployment/account addresses are accepted;
- verify balance read-only;
- approve the exact UserOperation separately.
