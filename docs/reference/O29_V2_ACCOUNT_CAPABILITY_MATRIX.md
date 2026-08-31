# O.29 V2 Account Capability Matrix

Status: local architecture specification; no V2 implementation exists.

`Required` means the capability belongs in the first implementation
specification. It does not mean it is implemented or approved for deployment.

| Capability | V1 | V2 direction | Required control | Initial status |
| --- | --- | --- | --- | --- |
| Fixed confirmation | One immutable target and zero-value call | Preserve as a typed confirmation intent | Exact action ID, authorization digest, target, nonce, chain, account, expiry | Required |
| Native ETH receive | Unrestricted receive | Preserve | Balance and lifecycle accounting | Required |
| Native ETH transfer | Unsupported | Typed exact transfer | Recipient, amount, purpose, fee, nonce, chain, account, expiry | Required |
| Residual native release | Unsupported | Ordinary native-transfer intent with release purpose | Separate approval and complete fund lifecycle | Required |
| ERC-20 transfer | Unsupported | Typed token transfer | Token, recipient, amount, return-value handling, no approval widening | Required |
| ERC-20 approval | Unsupported | Avoid by default | If later needed, exact spender/amount with zero-reset and allowance reconciliation | Deferred |
| ERC-721 transfer | Unsupported | Typed safe transfer | Collection, account as source, recipient, token ID, callback risk simulation | Required or V2.1 decision |
| ERC-1155 transfer | Unsupported | Typed safe transfer | Collection, recipient, token ID, amount, data hash, callback risk simulation | Required or V2.1 decision |
| Arbitrary contract call | Unsupported | No raw generic call | Reviewed capability adapter, exact target/selector/value/calldata hash | Adapter-gated |
| Delegatecall | Unsupported | Prohibited | Contract invariant | Prohibited |
| Batch operations | Unsupported | Bounded atomic typed batch | Ordered root, per-item binding, item/value/gas caps, all-or-nothing result | Deferred |
| EntryPoint prefund | Inherited automatic payment | Preserve with explicit accounting | Maximum prefund and post-operation balance/deposit reconciliation | Required |
| EntryPoint deposit withdrawal | Unsupported | Typed maintenance action | Exact recipient/amount, EntryPoint binding, separate approval | Required |
| Paymaster | Rejected | Compatible only behind explicit policy | Exact paymaster, validity, token charge, maximum liability | Disabled by default |
| Validator rotation | Unsupported in V1 experiment | Typed maintenance action | Current validator authorization, new key ID/config epoch, no value movement | Required |
| Delayed recovery | Unsupported | Threshold authority rotation only | Independent factors, freeze, delay, cancellation, expiry, no asset transfer | Required architecture |
| Recovery-config rotation | Unsupported | Delayed and cross-authorized | Epoch binding, threshold, challenge period, no value movement | Required architecture |
| Direct owner execution | Rejected | Continue rejecting | EntryPoint-only enforcement | Prohibited |
| Public sweep | Unsupported | Continue rejecting | Release only through ordinary typed intent | Prohibited |
| Upgradeability | None | New implementation/factory/address per version | Explicit migration and infrastructure acceptance | Prohibited |
| Session keys | Unsupported | Separate future capability design | Narrow scope, value/time limits, revocation, no recovery authority | Deferred |
| Migration | Impossible from V1 | Identity/adapter version migration; typed asset migration where old account supports it | Same owner commitment, old/new state verification, fresh approval | Required architecture |
| Other chain support | Outside account | Chain-specific adapter under the same Phil identity | No Ethereum semantics in identity core | Required architecture |

## Selected Initial Surface

The first V2 implementation design should remain smaller than a conventional
wallet:

```text
confirm exact action
transfer exact native amount
transfer exact standardized token or NFT
withdraw exact EntryPoint deposit
rotate validator through exact maintenance intent
run delayed threshold recovery that rotates authority only
```

Contract calls, batching, paymasters, and session keys each require a separate
threat review before activation. Unsupported features must fail closed rather
than silently routing through a generic execution function.

## Cross-Chain Capability Boundary

The capability vocabulary may be shared across adapters, but encoding and
network execution are not:

| Layer | Shared | Chain-specific |
| --- | --- | --- |
| Phil identity | Identity ID, owner commitment, session and approval evidence | None |
| Intent | Purpose, recipient concept, asset/action semantics, limits, expiry | Network and adapter profile |
| Ethereum adapter | None | Account, EntryPoint, nonce, UserOperation, gas, receipt |
| Bitcoin adapter | None | UTXOs, script/policy, fee rate, transaction |
| Solana adapter | None | Program accounts, instructions, recent blockhash, fee payer |

No chain adapter may convert a broad application request into execution
authority without the normal PhilCore policy, proof, approval, presence, and
signing boundaries.

O.30 replaces the directional decisions in this matrix with the exact
[O.30 V2 Capability Matrix](./O30_V2_CAPABILITY_MATRIX.md). O.29 remains the
historical architecture selection.
