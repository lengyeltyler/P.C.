# Sepolia Account Readiness

> Historical Base Sepolia readiness record. Phase O.17 selects Ethereum
> Sepolia (`chainId 11155111`) as the first intended public target. See
> [Ethereum Sepolia Network Profile](./ETHEREUM_SEPOLIA_NETWORK_PROFILE.md) and
> [Ethereum Sepolia Account Model](./ETHEREUM_SEPOLIA_ACCOUNT_MODEL.md).

## Decision

PhilCore is ready for a dedicated, guarded Base Sepolia integration phase, but
it is not ready for public mutation. The local implementation has
production-shaped authority boundaries and exact ERC-4337 v0.7 semantics.
Deployment, provider, funding, bundler, cross-domain fact, operational approval,
and external-review evidence remain incomplete.

ACP-0002 remains `Proposed`. The Base Sepolia Beta security gate remains
`blocked`.

## Readiness Matrix

| Component | Status | Evidence or blocker |
| --- | --- | --- |
| EntryPoint | Selected, local verified | ERC-4337 v0.7 and `PackedUserOperation`; canonical address reference is documented. No accepted Base Sepolia verification in this phase. |
| PhilCore account | Production-shaped, unaudited | ActionGate-restricted, non-upgradeable custom account; local EntryPoint tests pass. |
| Factory | Production-shaped, unaudited | Deterministic CREATE2 behavior is locally tested. No accepted Sepolia deployment. |
| Validator | Local real | Device Vault stores a separate secp256k1 ECDSA validator; M.10 signs the exact EntryPoint userOp hash. Beta custody approval remains blocked. |
| Recovery | Local real | Delayed recovery and recovery-authority rotation are locally tested. Beta custody/operations acceptance remains blocked. |
| Runtime authority | Local real | Trust, policy, approval, capability, authorization, proof, and signing boundaries compose locally. |
| STARK proof | Local real | Rust/STWO generation and verification are exercised. Public verified-fact publication is not. |
| ActionGate and consumer | Local real | Exact call, nullifier atomicity, replay rejection, and consumer outcome are tested locally. |
| UserOperation preparation | Production-shaped | Exact v0.7 account, EntryPoint, chain, nonce, call, gas, fees, and expiry are bound. |
| Bundler boundary | Production-shaped, local fixture | Restricted M.11 interface exists; no approved Base Sepolia endpoint or operator. |
| Paymaster | Disabled | First testnet operation should use a disposable prefunded account. |
| RPC | Unconfigured for mutation | No approved endpoint, endpoint allowlist, rate/timeout policy, or live mutation approval is active. |
| Deployments | Missing | Account, factory, ActionGate, verifier, mirror, and consumer addresses are not accepted for Base Sepolia. |
| Fact availability | Missing publicly | Desktop uses local fixture state. Production route requires Starknet -> L1 -> Base evidence or an accepted architecture change. |
| External audit | Incomplete | Existing internal/static evidence does not replace independent review. |

## Account Status Semantics

The desktop uses the following honest account states:

- `none`
- `local-test`
- `prepared`
- `deployed-testnet`
- `deployed-mainnet`
- `unavailable`

No state may become `deployed-testnet` from configuration, counterfactual
address calculation, or a local fixture. It requires an independently verified
deployment receipt and code/configuration checks on the intended testnet.

## First Testnet Scope

The smallest credible first scope is:

- Base Sepolia only;
- one disposable, value-limited account;
- no meaningful assets;
- paymaster disabled;
- one reviewed ActionGate consumer and zero value;
- local STARK generation and verification;
- exact M.9/M.10 UserOperation authorization;
- explicit public submission approval;
- independently verified receipt, nullifier, and consumer evidence.

This scope does not establish production readiness and does not solve public
verified-fact transport. A full ActionGate test that relies on mirrored fact
availability must wait for accepted testnet fact-route deployments and
evidence.
