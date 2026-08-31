# PhilCore Recovery Authority Rotation

Status: local Alpha boundary implemented; Base Sepolia Beta blocked; production not approved.

Phase: N.8

## Scope boundary — N-series PhilCore4337Account

This document describes the separate N-series `PhilCore4337Account` owner/recoveryAuthority model.
Its cancellation rules are not the authority model for `PhilCoreV2MinimalAccountV2`.
Current V2 actions 8–11 require the exact recovery-factor authority defined by
O.36.1/O.37.1. Actions 8, 9, and 11 use exact 2-of-3 current recovery factors.
Action 10 additionally requires the current validator plus exact 2-of-3 current
recovery factors. The validator never counts toward that recovery-factor
threshold, and validator-plus-one remains prohibited.

Canonical V2 sources:

- [O.36.1 Recovery And Cancellation Semantics](../reference/O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md)
- [O.37.1 V2 Recovery Lifecycle Update](../reference/O37_1_RECOVERY_LIFECYCLE_UPDATE.md)

## Purpose

N.8 remediates the previous recovery-authority rotation blocker by adding a bounded delayed rotation path to `PhilCore4337Account`.

Recovery-authority rotation changes only the recovery authority. It does not change `ownerCommitment`, EntryPoint, ActionGate, execution owner, account address, proof semantics, fact transport, or authorization execution.

## Custody And Rotation Models Evaluated

| Model | Result | Reason |
| --- | --- | --- |
| Owner-only recovery-authority rotation | rejected | A lost or stolen owner can permanently block recovery maintenance. |
| Recovery-authority-only self-rotation | rejected | A stolen recovery key could entrench itself without current-owner review. |
| Owner or recovery authority requests, other authority cancels, anyone completes after delay | selected | Provides liveness while preserving a challenge window and review by the other authority. |
| Disposable-Beta acceptance without remediation | rejected for N.8 | Useful as a fallback policy, but it leaves a known account-lifecycle gap. |
| Threshold/modular recovery authority | deferred | Better production direction, but it requires broader contract architecture and audit scope. |

## Selected Model

```text
current owner OR current recovery authority
  -> requests new recovery authority
  -> exactly one pending request
  -> challenge delay
  -> the other authority may cancel
  -> anyone may complete after delay
  -> current recovery authority changes
```

The pending recovery authority must be nonzero, different from the current recovery authority, and different from the current execution owner.

The current owner can cancel a request proposed by the recovery authority. The current recovery authority can cancel a request proposed by the owner. The proposer cannot cancel its own request through the rotation path.

## Contract Boundary

New maintenance methods:

- `requestRecoveryAuthorityRotation(address pendingRecoveryAuthority, address expectedProposer)`
- `cancelRecoveryAuthorityRotation(bytes32 requestId, address expectedCanceller)`
- `completeRecoveryAuthorityRotation(bytes32 requestId, address expectedPendingRecoveryAuthority)`
- `recoveryAuthorityRotationRequest()`

The rotation path:

- stores exactly one pending authority;
- enforces delay and expiry;
- rejects replay, cancelled, expired, and mismatched completion;
- performs no external calls;
- transfers no value;
- cannot execute ActionGate calls;
- cannot change EntryPoint, ActionGate, ownerCommitment, or execution owner;
- preserves the account address.

The factory still binds the initial recovery configuration into CREATE2 address derivation. Post-deployment recovery-authority rotation changes mutable account state only and does not redeploy or readdress the account.

## Runtime Boundary

N.8 adds a preparation-only Runtime boundary for exact rotation maintenance calldata.

Runtime rotation candidates:

- are immutable/defensive objects;
- contain no signing key or private material;
- submit no UserOperation;
- do not mutate Device Vault state;
- do not activate the new recovery key;
- do not revoke the old recovery key;
- do not grant ordinary execution authority.

Public-network signing and submission remain out of scope for N.8.

## Device Vault Coordination

Device Vault recovery-authority records should coordinate with the on-chain/local-chain state in this order:

```text
register or generate new recovery authority
  -> mark new record pending_rotation
  -> prepare exact rotation request
  -> sign/submit only through an approved future boundary
  -> verify rotation completion receipt/state
  -> activate new recovery authority record
  -> revoke or archive old recovery authority record
```

Local Device Vault state must not claim recovery authority changed until receipt/state verification confirms completion.

## Compromise Scenarios

Lost recovery key:

- current owner can request rotation to a new recovery authority;
- old lost recovery key can no longer block completion after the delay unless it is recovered and cancels during the challenge window.

Stolen recovery key:

- attacker can request rotation or recovery, creating denial-of-service pressure;
- current owner can cancel within the challenge window;
- stolen recovery key cannot execute ordinary actions, transfer assets, or bypass ActionGate.

Stolen owner key:

- stolen owner can request recovery-authority rotation and can cancel recovery;
- recovery authority can cancel owner-proposed recovery-authority rotation during the challenge window;
- stronger production response still requires threshold/modular recovery and monitoring.

Both keys lost:

- account may remain inaccessible under the local Alpha/Beta model.

Both keys compromised:

- the current model is insufficient for production asset protection.

## Disposable Beta Decision

N.8 does not choose the disposable-Beta exception path. Disposable testnet accounts and no-meaningful-assets policy remain required, but recovery-authority rotation is now locally implemented rather than accepted as a known unsupported limitation.

## World ID Separation

World ID remains an identity/human-uniqueness signal. It is not a signing key, recovery authority, sole recovery factor, or account-maintenance authority.

## Release Recommendations

Local Alpha:

- sufficient for local recovery-authority rotation testing;
- no public UserOperations;
- no meaningful assets.

Base Sepolia Beta:

- recovery-authority rotation blocker is remediated at the local contract/runtime boundary;
- Beta still requires ACP-0002 acceptance, recovery custody approval, accepted deployments, public-network operational controls, and external review.

Production:

- not sufficient alone;
- requires threshold or modular recovery, multi-device/hardware custody, monitoring, and external audit.

## Invariants Preserved

- `phil_secret -> identityRoot -> ownerCommitment`;
- `ACTION_UNLOCK`;
- `proofInputHash`;
- proof public input tuple;
- `[fact_high, fact_low]`;
- STARK/proof architecture;
- ActionGate-restricted execution;
- no public UserOperation submission in N.8;
- no live Base state mutation.
