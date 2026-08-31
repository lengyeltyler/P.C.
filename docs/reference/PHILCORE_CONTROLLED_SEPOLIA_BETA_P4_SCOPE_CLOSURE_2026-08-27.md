# PhilCore Controlled Sepolia Beta P4 Scope Closure

Status date: 2026-08-27

Classification: `DOCUMENTATION_ONLY_SCOPE_CLOSURE`

```text
P4 PUBLIC EXECUTION STATUS: DEFERRED
V2 PUBLIC DEPLOYMENT/RECOVERY EXECUTION IN THIS BETA: NOT PERFORMED
```

This record closes P4 for the current controlled Sepolia Beta by documenting
the boundary, not by exercising recovery. No recovery credential was created
or used, no phone was used, no contract was deployed, and no public-chain
mutation occurred. This is deliberate scope control, not public validation of
recovery.

## Public Beta account identity

P2 and P3 used the already-deployed legacy `PhilCore4337Account` selected by
the controlled Beta profile. They did not deploy or exercise
`PhilCoreV2MinimalAccountV2`. The canonical P2 evidence identifies the deployed
account runtime hash, and the P3 evidence records reuse of that same account
for the second composed action.

The public P2/P3 result therefore proves two sequential restricted actions on
the legacy Beta account. It does not prove the intended V2 exact-2-of-3
recovery design.

## Legacy recovery findings disclosed for P2/P3

The following HIGH findings apply to `PhilCore4337Account`, the legacy account
used publicly in P2/P3. They do not describe the V2 source model.

### P4-H1 — HIGH — recovery is controlled by one EOA

The account stores one `_recoveryAuthority`. A request and completion are
authorized by that single address directly, or through an EntryPoint
UserOperation whose expected signer is that address. There is no threshold
quorum in this account.

Source: [`PhilCore4337Account.sol`, recovery request and completion](../../contracts/base/erc4337/PhilCore4337Account.sol#L230), and
[`_validateSignature`](../../contracts/base/erc4337/PhilCore4337Account.sol#L465).

### P4-H2 — HIGH — the current owner alone can cancel recovery

While recovery is pending, `cancelRecovery` accepts the current owner directly
or an EntryPoint UserOperation signed by the current owner. The recovery
authority does not have an independent cancellation right.

Source: [`PhilCore4337Account.sol`, cancellation](../../contracts/base/erc4337/PhilCore4337Account.sol#L264), and
[`_validateSignature`](../../contracts/base/erc4337/PhilCore4337Account.sol#L475).

### P4-H3 — HIGH — expired recovery can remain frozen

An expired recovery cannot complete, but the request remains active and the
account remains frozen until the owner invokes cancellation. The legacy
account has no permissionless expired-request cleanup path.

Source: [`PhilCore4337Account.sol`, completion expiry and cancellation](../../contracts/base/erc4337/PhilCore4337Account.sol#L264), and
[`_requireRecoveryActive`](../../contracts/base/erc4337/PhilCore4337Account.sol#L434).

These findings are now part of the public Beta disclosure. They are not being
remediated in the legacy account during this documentation-only phase.

## V2 source boundary

Substantial V2 source and local tests exist, but V2 has not been deployed or
publicly exercised in this Beta. The current source model provides:

- exact 2-of-3 recovery with only factor bitmaps `3`, `5`, and `6`;
- recovery request and cancellation authorized by recovery factors rather than
  the validator alone;
- a fixed 48-hour (`172800` second) delay and 7-day (`604800` second) expiry;
- permissionless settlement that clears an expired request;
- validator and recovery epochs;
- recovery-authority configuration rotation;
- an immutable factory binding to a stateless verifier and its runtime code
  hash; and
- a closed typed-action surface with no generic `execute`, `delegatecall`,
  module, plugin, or session-key authority.

Source: [`PhilCoreV2MinimalAccountV2.sol`](../../contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol),
[`PhilCoreV2StaticAuthorityVerifier.sol`](../../contracts/base/erc4337/v2/PhilCoreV2StaticAuthorityVerifier.sol),
and the [V2 minimal-account architecture](./O37_6_MINIMAL_ACCOUNT_ARCHITECTURE.md).

## V2 Beta-readiness blockers

The V2 source is not a Beta-ready deployment package. The Phase 6B review
recorded these unresolved blockers:

### P6B-H1 — HIGH — stale artifact/runtime pins fail closed

The O.40 dry-run template and current pinned compiler artifacts disagree:

| Contract | O.40 pinned runtime hash | Current compiled runtime hash |
| --- | --- | --- |
| Verifier | `0x665910b9989f3b83c3f025314fb127755d5abfc46e66ee386fbcbbfefc864dd7` | `0xa1936c0e1a5ad05b5e894cb8575d38e264d5f0827098398217b63ad32eab62b6` |
| Account | `0x4681ca917e3b5c3fff72bb6020f3fb278a43ab893beb05e36865b50422f64519` | `0x52ecf1069646a3d157e949ff534ea13598dc5e5f6ca5b347fb46f72ab1910505` |
| Factory | `0x15eca82e16f99f3ea5d9f8443871fc059bb050a8f30856d017be49d0e97c0d95` | `0xb618bfe69fd8025464235b1272c382e26e3b21c1c98de1a53b3bcb2cbc6e86c1` |

The preparation guard rejects this mismatch before initialization or
deployment.

Source: [O.40 deployment template](../../config/ethereum-sepolia/O40_V2_DEPLOYMENT_CANDIDATE_TEMPLATE.json) and
[`prepare-o40-v2-deployment.cjs`](../../scripts/ethereum-sepolia/prepare-o40-v2-deployment.cjs#L237).

### P6B-H2 — HIGH — selected live target is not V2-compatible

The selected address `0x334577B0feB9e1f49d4ca4ff6dAcc6f8732594D7`
is the older local-proof confirmation target. It does expose
`confirmPhilCoreAction(bytes32,bytes32)`, but that implementation casts its
caller to the legacy account interface and calls `securityModelId()`,
`approvedConfirmationTarget()`, and `expectedChainId()`. The V2 account uses a
different configuration interface and exposes none of those legacy getters,
so the old target's confirmation call path cannot be reused directly by V2.

Source: [O.40 deployment template](../../config/ethereum-sepolia/O40_V2_DEPLOYMENT_CANDIDATE_TEMPLATE.json#L11) and
[`PhilCoreLocalProofConfirmationTargetV1.confirmPhilCoreAction`](../../contracts/base/PhilCoreLocalProofConfirmationTargetV1.sol#L31),
the [legacy account interface](../../contracts/base/interfaces/IPhilCoreLocalProofAccountV1.sol#L4), and
[`IPhilCoreV2ConfirmationTarget`](../../contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol#L26).

### P6B-M1 — MEDIUM — deployment inputs are not the Beta identity package

The O.40 tool pins owner commitment
`0xabab9766da60e39c0c69fc6ecd7e0f31d116c626c8ea36c6401e331d99f4a9b1`
and validator `0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa`. P2/P3 used
owner commitment
`0x51913d802ac498f0277510d5d01c21521bd4042a90c436b112bc18c25c0a8d74`
and validator `0xCCFdf0a8172A8B10529a48F77F75941A1FB7aA81`. The O.40
template's three real recovery commitments, recovery configuration hash,
verifier/factory addresses, user salt, and deployment gas ceiling are unset.
It is a guarded dry-run template, not an executable V2 Beta deployment
configuration.

Source: [O.40 deployment template](../../config/ethereum-sepolia/O40_V2_DEPLOYMENT_CANDIDATE_TEMPLATE.json#L14),
[P2/P3 Beta account configuration](../../config/ethereum-sepolia/PHILCORE_CONTROLLED_SEPOLIA_BETA_P2_V1.json#L19), and
[`missingFields`](../../scripts/ethereum-sepolia/prepare-o40-v2-deployment.cjs#L97).

### P6B-M2 — MEDIUM — unsupported tokens can be stranded

The minimal V2 account exposes native ETH transfer and EntryPoint deposit
withdrawal, but no arbitrary token-release or rescue surface and no ERC-721 or
ERC-1155 receiver support. ERC-20, ERC-721, or ERC-1155 assets sent to the
address can therefore become stranded. No asset in the current Beta is
affected; meaningful assets remain prohibited.

Source: [O.38 token and residual-asset policy](./O38_TOKEN_AND_RESIDUAL_POLICY.md) and
[V2 minimal-account deferred capabilities](./O37_6_MINIMAL_ACCOUNT_ARCHITECTURE.md#deferred-capabilities).

## Milestone disposition

P4 previously required public recovery and rotation drills as a current Beta
exit condition. It now closes only when the legacy/V2 distinction, the three
legacy HIGH findings, the V2 source boundary, the four deployment-readiness
blockers, and the future-milestone requirement are canonical and consistent.

```text
P4: DEFERRED — NOT PART OF THIS BETA'S PUBLIC EXECUTION EXIT CRITERIA
```

Recovery remains a long-term product requirement. Any public V2 deployment,
recovery, cancellation, expiry cleanup, validator rotation, recovery-authority
configuration rotation, or V2 ActionGate exercise requires a new, separately
reviewed and explicitly authorized milestone.

The remaining sequence is:

1. Phase 7 — P5 restricted cleanup and final reconciliation;
2. Phase 8 — signed packages and physical acceptance; and
3. Phase 9 — final Beta and open-source release decision.

This scope closure does not change the completed P3 evidence and does not make
the controlled Sepolia Beta ready.

```text
P3 CANONICAL STATUS: COMPLETE AND RECONCILED
PHILCORE CONTROLLED SEPOLIA BETA READY: NO
```
