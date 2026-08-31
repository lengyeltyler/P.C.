# PhilCore Recovery Authority Custody

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

This document defines the recovery-authority custody boundary for the restricted `PhilCore4337Account` recovery model.

Recovery authority is separate from the execution owner. It may request delayed recovery and complete recovery after the challenge period. It must not execute ordinary actions, transfer assets, bypass ActionGate, change EntryPoint, change ActionGate, change `ownerCommitment`, or become a generic Ethereum wallet key.

## Custody Models Evaluated

| Model | Local Alpha | Base Sepolia Beta | Production |
| --- | --- | --- | --- |
| Separate Device Vault ECDSA recovery key | accepted for local fixture validation | acceptable only with disposable accounts and clear operator approval | insufficient alone |
| Recovery key on second trusted device | recommended Beta direction | preferred Beta model once enrollment exists | useful as one threshold participant |
| Hardware security key / hardware wallet | optional | strong Beta candidate if ECDSA signing is supported | useful as one threshold participant |
| Threshold recovery authority | too broad for N.5 | future requirement | recommended production direction |
| Managed testnet operator recovery | acceptable for controlled Beta only | acceptable only for disposable testnet accounts | not production-suitable |

## Selected Model

Local Alpha uses a separate encrypted Device Vault ECDSA recovery key. The key is generated with secure randomness, stored as a purpose-bound encrypted record, and is not derived from `phil_secret`, `identityRoot`, `ownerCommitment`, or the execution validator key.

Base Sepolia Beta recommendation:

- execution key: primary Device Vault validator;
- recovery key: second trusted device, hardware signer, or approved testnet operator custody;
- recovery completion: explicit authenticated approval, challenge delay, and complete audit trail;
- assets: disposable testnet accounts only, no meaningful assets.
- recovery-authority rotation: locally implemented in N.8, still subject to Beta approval and audit.

Production recommendation: threshold or modular recovery with independent signers and external audit.

## Runtime Boundary

N.5 adds recovery-specific runtime helpers:

- recovery authority record generation/registration;
- account binding for generated recovery records;
- exact recovery UserOperation preparation;
- immutable recovery action presentation;
- one-time approval artifact;
- short-lived recovery signing session;
- recovery-only signing for `requestRecovery(address)` and `completeRecovery(bytes32,address)`.

The recovery signer rejects:

- `execute(...)`;
- ActionGate calls;
- ETH/token transfers;
- arbitrary account calls;
- cancellation;
- EntryPoint, ActionGate, or `ownerCommitment` changes;
- arbitrary messages or transactions.

## Device Vault Coordination

Execution validator records and recovery authority records are separate purpose-bound records.

During recovery:

1. Old execution validator remains locally active until verified completion, though account freeze blocks normal execution after recovery is requested.
2. New execution validator remains pending.
3. After verified local-chain/on-chain completion, the new validator may become active.
4. Old validator may then be revoked or archived locally.
5. Local state must not claim account authority changed until receipt/state verification confirms the new owner.

## Contract Behavior

`ownerCommitment`, EntryPoint, and approved ActionGate remain immutable.

`requestRecovery(address)` and `completeRecovery(bytes32,address)` may be called directly by the recovery authority or through EntryPoint with a recovery-authority signature.

`cancelRecovery(bytes32)` remains current-owner/EntryPoint-owner controlled. Recovery authority cancellation is rejected.

## Compromise Scenarios

- Lost execution key: recovery authority can request recovery, wait through the challenge period, and complete to a new owner.
- Stolen execution key: attacker may cancel recovery and may perform bounded ActionGate execution before freeze; monitoring and escalation remain required.
- Lost recovery key: normal execution still works, and N.8 allows current-owner requested recovery-authority rotation after the delay/challenge path.
- Stolen recovery key: attacker can request recovery and freeze the account, but cannot execute ordinary actions or drain assets; current owner can cancel during the challenge period.
- Both keys lost: account may be permanently inaccessible under the Beta model.
- Both keys compromised: current model may not protect assets; production threshold recovery is required.

## Beta Gate Status

N.5 provides local Alpha custody and workflow evidence. Base Sepolia Beta remains blocked until:

- ACP-0002 is accepted for Beta scope;
- recovery authority custody is approved for the selected Beta model;
- recovery-authority rotation receives Beta acceptance and external review;
- N.6 Slither/static-analysis evidence remains reproducible;
- remaining high tooling dependency advisories are remediated or formally accepted;
- Base Sepolia deployments and bundler/submission controls are accepted;
- external audit or independent review is complete.

## Invariants Preserved

- `phil_secret -> identityRoot -> ownerCommitment`;
- `ACTION_UNLOCK`;
- `proofInputHash`;
- proof public input tuple;
- STARK/proof architecture;
- ActionGate-restricted account execution;
- no public UserOperation submission in N.5;
- no live Base state mutation.

## Phase N.8 Recovery Authority Rotation Update

N.8 adds a local contract/runtime boundary for bounded recovery-authority rotation:

- current owner or current recovery authority may request rotation;
- the other authority may cancel;
- completion is permissionless after the delay;
- the pending recovery authority is inactive until completion;
- Device Vault records must remain pending until verified completion;
- the old recovery authority record is revoked or archived only after verified completion.

This removes the previous unsupported-rotation blocker for local Alpha, but it does not approve Base Sepolia Beta or production custody.
