# O.37.10 Account ABI Report

Status: `ACCEPTED_EXACT_O37_9_SURFACE`.

`PhilCoreV2MinimalAccountV2` exposes exactly 15 functions:

| Family | Functions |
| --- | --- |
| ERC-4337 | `validateUserOp` |
| Typed actions | `confirmIntent`, `transferNative`, `withdrawEntryPointDeposit`, `rotateValidator` |
| Validator recovery | `requestRecovery`, `cancelRecovery`, `settleRecovery` |
| Configuration recovery | `requestRecoveryConfigRotation`, `cancelRecoveryConfigRotation`, `settleRecoveryConfigRotation` |
| Aggregate views | `accountConfiguration`, `accountSecurityState`, `pendingRecovery`, `pendingRecoveryConfigRotation` |

All selectors equal the O.37.9 freeze, including `0x19822f7c` for
`validateUserOp`, `0x2a44a457` for confirmation, `0x1bc0b4cd` for native
transfer, and `0x686e6c02` for deposit withdrawal.

The account has one payable empty `receive` entry point and a reverting
fallback. It has no generic execution, batch, token, receiver, approval,
module, session, paymaster, aggregator, administrator, verifier setter, or
upgrade function.

The factory exposes only:

- `createAccount`;
- `getAddress`;
- `deploymentSalt`;
- `accountCreationCodeHash`;
- `verifierBinding`.

Canonical ABI bytes and hashes are recorded in
`config/solidity/O37_10_ABI_REPORT.json`.
