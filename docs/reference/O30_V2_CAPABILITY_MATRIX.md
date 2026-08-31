# O.30 V2 Capability Matrix

Status: exact V2.0 specification; no implementation or deployment approval.

## Superseded recovery-cancellation authority

Historical text in this document is preserved as design/audit history.
Current V2 actions 8–11 require the exact recovery-factor authority defined by
O.36.1/O.37.1. Actions 8, 9, and 11 use exact 2-of-3 current recovery factors.
Action 10 additionally requires the current validator plus exact 2-of-3 current
recovery factors. The validator never counts toward that recovery-factor
threshold, and validator-plus-one remains prohibited.

Canonical sources:

- [O.36.1 Recovery And Cancellation Semantics](./O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md)
- [O.37.1 V2 Recovery Lifecycle Update](./O37_1_RECOVERY_LIFECYCLE_UPDATE.md)

| Capability | V1 | O.29 direction | O.30 V2.0 decision | Exact boundary |
| --- | --- | --- | --- | --- |
| Confirmation | Fixed zero-value target | Typed intent | Included | Immutable target, exact digest, key 0 |
| Native receive | Included | Preserve | Included | `receive()` only; no authority |
| Native transfer | Absent | Required | Included | Exact recipient/amount, empty calldata, key 0 |
| Residual release | Absent | Ordinary transfer | Included | Native transfer with release purpose and separate approval |
| ERC-20 receive | Passive | Cover holdings | Passive | Balance accounting only |
| ERC-20 transfer | Absent | Required | Included | Transfer only, exact account/recipient balance deltas |
| ERC-20 approve/revoke | Absent | Avoid/defer | Deferred | No allowance selector or storage |
| ERC-721 receive | Absent interface | Required | Included | ERC721Receiver only |
| ERC-721 transfer | Absent | Decide V2/V2.1 | Included | Safe transfer, exact token/recipient/ID/data hash |
| ERC-1155 receive | Absent interface | Required | Included | Single and batch receiver interfaces |
| ERC-1155 transfer | Absent | Decide V2/V2.1 | Included, single only | Safe transfer, exact token/recipient/ID/amount/data hash |
| Native contract call | Absent | Adapter-gated | Deferred | No selector in V2.0 |
| Capability adapter | Absent | Resolve registry | Deferred to new account version | No mutable registry/root or dormant hook |
| Allowlisted target calls | Fixed target only | Evaluate | Deferred | New version required |
| Arbitrary execution | Absent | Reject | Prohibited | No generic execute |
| Delegatecall | Absent | Reject | Prohibited | Invariant |
| Batch execution | Absent | Deferred | Deferred | No outward batch action |
| EntryPoint prefund | Inherited | Preserve | Included | Bounded missing prefund only |
| EntryPoint deposit withdrawal | Absent | Required | Included | Exact recipient/amount, key 0 |
| Paymaster | Rejected | Disabled initially | Deferred | Nonempty paymaster data rejected |
| Validator creation | Immutable V1 validator | Device Vault | Included | Random non-derived key, epoch 1 |
| Validator rotation | Absent | Required | Included | Current validator, next epoch, key 1 |
| Validator revocation | Absent | After rotation | Included operationally | Never zero validator; revoke locally after verified state |
| Recovery | Absent | Delayed threshold | Included | 2-of-3, 48-hour delay, 7-day expiry, key 2 |
| Recovery cancellation | Absent | Challenge window | Included | 2 factors or validator plus 1 factor |
| Recovery-factor rotation | Absent | Required | Included | Validator plus 2 factors; delayed |
| Recovery asset movement | Absent | Reject | Prohibited | Recovery rotates authority only |
| Direct validator/owner call | Rejected | Reject | Prohibited | EntryPoint-only actions |
| Permissionless completion | Absent | Possible | Included narrowly | Exact pending recovery/config request only |
| Upgradeability | Absent | Reject | Prohibited | New implementation/factory/address |
| Migration | Impossible | Identity/adapter | Specified | Typed asset movement where old account supports it |
| Session keys | Absent | Deferred | Deferred | New architecture/version required |
| Other chains | Outside V1 | Adapter boundary | Preserved | No Ethereum state in Phil identity |

## Capability Closure

The V2.0 implementation is complete only if unsupported behavior is
unreachable, not merely undocumented.

No combination of included functions may synthesize:

- arbitrary calldata execution;
- standing ERC-20 allowance;
- batch execution;
- recovery-authority asset movement;
- direct validator calls;
- account-self privilege escalation;
- mutable implementation or capability installation.

Any later capability requires a new matrix, threat model, implementation
version, migration analysis, and funding lifecycle.
