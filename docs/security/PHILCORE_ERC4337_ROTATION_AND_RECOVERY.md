# PhilCore ERC-4337 Rotation And Recovery

Phase: N.8

Status: local Alpha implementation; Base Sepolia Beta remains blocked; production not approved.

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

## Selected Model

N.4 selected a restricted delayed-recovery model for the proposed PhilCore ERC-4337 account. N.5 adds local Alpha recovery-authority custody and approval evidence. N.8 adds bounded delayed recovery-authority rotation.

```text
executionOwner
  -> validates normal EntryPoint UserOperations
  -> may rotate itself to a new execution owner
  -> may cancel an active recovery request

recoveryAuthority
  -> may request recovery to a new execution owner
  -> may complete recovery only after the challenge delay
  -> may request recovery-authority rotation to a new recovery authority
  -> may cancel owner-proposed recovery-authority rotation
  -> may not cancel its own recovery request
  -> may not execute ActionGate calls
  -> may not transfer assets
  -> may not change EntryPoint, ActionGate, or ownerCommitment

frozen account
  -> blocks normal ActionGate execution
  -> allows current-owner cancellation and recovery-authority completion paths
```

The model preserves the N.2 ActionGate restriction. `execute(...)` remains EntryPoint-only and can target only the immutable approved ActionGate with the `verifyAndConsume(...)` selector.

## Release-Stage Recommendations

Local Alpha:

- current-owner rotation is supported;
- delayed recovery is available for local fixtures;
- recovery keys are separate purpose-bound encrypted recovery authority records;
- no meaningful assets.

Base Sepolia Beta:

- minimum acceptable model is current-owner rotation plus independent delayed recovery authority;
- current owner can cancel a malicious recovery during the challenge window;
- recovery authority cannot execute ordinary actions;
- recovery authority custody must be approved for the selected Beta model;
- recovery-authority rotation is locally implemented but still requires Beta acceptance and audit;
- only disposable testnet accounts until audit, deployment, and operational gates pass.

Production:

- requires threshold or modular recovery;
- requires multiple trusted devices/credentials or reviewed guardian model;
- requires external audit and recovery ceremony;
- should consider future modular/STARK-native validator architecture.

## Owner Commitment Continuity

Validator rotation does not change `ownerCommitment`.

```text
phil_secret -> identityRoot -> ownerCommitment
```

remains the PhilCore identity invariant. Rotation changes the Ethereum validator key only; it does not create a second canonical identity.

## Device Vault Coordination

N.5 recovery authority workflow:

```text
generate/register recovery authority
  -> bind to account
  -> exact recovery action presentation
  -> one-time approval
  -> recovery-only signing session
  -> local EntryPoint inclusion
  -> receipt/state verification
  -> Device Vault state update
```

Safe local rotation order:

```text
generate new encrypted validator
  -> mark old key pending_rotation
  -> prepare on-chain rotation
  -> execute local fixture rotation
  -> verify account owner changed
  -> activate new key
  -> revoke/archive old key
```

If on-chain rotation fails, the old key must remain usable. Local revocation alone does not alter on-chain authority.

The recovery signer may sign only `requestRecovery(address)` and `completeRecovery(bytes32,address)`. It rejects `execute(...)`, ActionGate calls, transfers, arbitrary messages, arbitrary transactions, and cancellation.

N.8 adds recovery-authority rotation coordination:

```text
new recovery authority record
  -> pending_rotation
  -> exact rotation maintenance calldata
  -> verified rotation completion
  -> new record active
  -> old record revoked or archived
```

Local state must not activate the new recovery authority until verified account state confirms completion.

O.4 desktop coordination:

- recovery request, completion, owner rotation, and recovery-authority rotation use Runtime-generated digest-bound presentations;
- approval artifacts are one-time, process-local, identity/session/action-bound, and expiring;
- fresh-authentication evidence is required for recovery-sensitive actions;
- cancellation remains separate from ordinary execution authority;
- O.4 does not submit public UserOperations or approve Beta recovery.

## Recovery Authority Rotation

N.8 selects a bounded delayed model:

```text
owner or current recovery authority requests rotation
  -> exactly one pending request
  -> other authority may cancel during challenge window
  -> anyone may complete after delay
  -> account recovery authority changes
```

The pending recovery authority must be nonzero, different from the current recovery authority, and different from the execution owner. Rotation cannot change `ownerCommitment`, EntryPoint, ActionGate, execution owner, or account address, and it performs no external calls or value transfers.

The factory still binds the initial recovery configuration into CREATE2 address derivation. Post-deployment recovery-authority rotation changes only mutable account state.

## Future Direction

Long-term PhilCore goal:

```text
STARK proof or STARK-backed validator becomes execution-validation authority
across supported chain adapters.
```

The current ERC-4337 ECDSA validator is a compatibility and device-possession layer for today’s Ethereum account model. N.8 does not change STARK proof semantics, `ACTION_UNLOCK`, `proofInputHash`, public inputs, or the cross-domain fact route.

## Remaining Blockers

- ACP-0002 remains `Proposed`.
- The custom account/factory require renewed static analysis and external review.
- Recovery authority custody is implemented for local Alpha only.
- Recovery authority rotation is locally implemented but unaudited and not Beta-approved.
- Threshold recovery is not implemented.
- Public Base Sepolia deployment is not accepted.
- No live UserOperation was submitted.
