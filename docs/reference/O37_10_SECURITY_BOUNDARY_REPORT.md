# O.37.10 Security Boundary Report

Status: `LOCAL_IMPLEMENTATION_BOUNDARY_ACCEPTED`.

## Authority

`validateUserOp` is callable only by the immutable EntryPoint. It binds the
exact sender, chain, EntryPoint hash, factory, keyed nonce lane/sequence,
typed action, O.32 authorized-intent hash, epochs, fee ceiling, validity
range, lifecycle state, and O.37.4 authority envelope. Paymasters are
rejected.

The account obtains the verifier only from its immutable factory. It stores
no verifier and has no setter, registry, fallback, retry, or caller-selected
path. Both binding lookup and authority verification are `STATICCALL`.

The EntryPoint owns replay state. The account has no duplicate nonce or
consumed-hash mapping. Typed action functions are EntryPoint-only and cannot
be called directly.

## Recovery

Validator authority alone cannot select a recovery action because the fixed
verifier derives authority class from the onchain action. Recovery authority
cannot select ordinary execution. Validator recovery and configuration
rotation never make external calls or transfer value. Settlement accepts
only the exact stored request and deterministically completes during the
allowed window or expires at/after expiry.

Both permissionless settlement functions reject the execution lock. A
malicious native-transfer recipient therefore cannot complete a pending
configuration rotation during the external call after the UserOperation was
validated against the prior epoch.

Recovery remains exactly 2-of-3 with valid bitmaps `3`, `5`, and `6`.
Configuration rotation changes exactly one ordered role and advances the
recovery epoch only on completion.

## Forbidden Surfaces

There is no administrator, owner override, proxy, implementation, upgrade,
delegatecall, arbitrary execution, batching, module, plugin, session,
mutable verifier, paymaster, aggregator, token transfer/approval, receiver,
recovery asset movement, factory execution authority, or factory recovery
authority.

The native-transfer and EntryPoint-deposit-withdrawal calls are the only
asset release surfaces. Unsolicited tokens may be stranded permanently.

## Local-Only Boundary

All accounts, signatures, UserOperations, balances, and deployments used by
the tests are deterministic or ephemeral test material on Hardhat chain
`31337`. No credential, protected witness, Runtime authorization, Device
Vault material, production signature, external RPC, public chain, or public
fund is used.

Repository-local Slither `0.10.4` analysis completed with all findings
triaged. It prompted explicit binding-interface inheritance, complete
EIP-1559 fee-word validation, and settlement reentrancy protection. The
remaining detector families describe intentional guarded calls, fixed
timestamp lifecycle, sentinel views, bounded assembly, and the closed action
decoder. No unmitigated high or critical finding remains. This internal
analysis is not an external audit. Deterministic triage is in
`config/solidity/O37_10_STATIC_ANALYSIS_TRIAGE.json`.
