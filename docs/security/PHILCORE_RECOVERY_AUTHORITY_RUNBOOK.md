# PhilCore Recovery Authority Runbook

Status: local Alpha procedure; Beta and production require approval.

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

## Scope

This runbook covers restricted PhilCore ERC-4337 recovery authority operations. It does not approve public-network deployment, public bundler submission, production recovery, or meaningful-asset custody.

## Initial Enrollment

Local Alpha:

1. Unlock the Device Vault in a local fixture environment.
2. Generate a separate recovery authority ECDSA key.
3. Confirm the recovery address differs from the execution owner.
4. Deploy/create the local account with that recovery address.
5. Bind the encrypted recovery authority record to the account and chain.
6. Record sanitized audit evidence.

Base Sepolia Beta:

1. Use a second trusted device, hardware signer, or approved testnet operator signer.
2. Use disposable testnet accounts only.
3. Require explicit operator/user approval before any public submission.
4. Keep the Beta gate blocked until deployment, audit, static analysis, and dependency criteria pass.

Production:

Use threshold or modular recovery after audit. A single same-device ECDSA recovery key is not sufficient.

## Health Check

- Verify recovery authority record status is `active`.
- Verify key custody is separate from execution-owner custody.
- Verify no raw private key export is possible.
- Verify recovery signer rejects `execute(...)`, ActionGate calls, transfers, and arbitrary messages.
- Verify account recovery delay and expiry are configured as expected.

## Lost Primary Device

1. Generate or select a new execution validator key.
2. Prepare a `requestRecovery(newOwner)` presentation.
3. Obtain one-time recovery approval.
4. Sign the exact recovery UserOperation.
5. Submit only through the approved local/testnet path.
6. Verify account is frozen and pending owner/request ID are correct.
7. Wait through the challenge period.
8. Prepare and approve `completeRecovery(requestId,newOwner)`.
9. Verify owner changed and account unfroze.
10. Activate the new local validator only after receipt/state verification.
11. Revoke or archive the old local validator.

## Stolen Primary Device

- Treat cancellation by the current owner as possible.
- Watch for repeated cancellation or suspicious ActionGate usage.
- Request recovery to freeze normal execution.
- Escalate to operational response if cancellation repeats.
- Do not assume this single-recovery-authority model fully protects meaningful assets.

## Suspicious Recovery Request

1. Review account, owner commitment, pending owner, request ID, challenge times, and calldata hash.
2. If unauthorized, current owner cancels with `cancelRecovery(requestId)`.
3. Confirm account unfroze and recovery state cleared.
4. Suspend or rotate the recovery authority operationally.
5. Review audit events.

## Completion

Completion requires:

- active pending recovery;
- challenge period elapsed;
- request not expired;
- exact request ID;
- exact pending owner;
- one-time approval;
- recovery authority signature;
- receipt/state verification.

## Lost Recovery Device

Normal execution continues. N.8 supports bounded recovery-authority rotation, so the current owner may request a new recovery authority, wait through the challenge window, and complete rotation if the old recovery authority does not cancel. For Beta this still requires custody approval, deployment evidence, and audit.

## Compromised Recovery Authority

The attacker may request recovery and freeze the account, but cannot execute ordinary actions or transfer assets. The current owner should cancel promptly and operationally revoke/suspend the recovery authority. Production needs threshold recovery.

## Account Freeze Investigation

Check:

- active recovery request;
- request ID;
- pending owner;
- recovery authority;
- requested/executable/expiry timestamps;
- caller/signature evidence;
- owner cancellation evidence;
- ActionGate and EntryPoint immutability.

## Known Limitations

- A stolen current owner can cancel recovery during the challenge period.
- Repeated cancellation may delay recovery.
- A stolen recovery key can cause temporary freeze/DoS.
- Both keys lost can make the account inaccessible.
- Recovery-authority rotation is not implemented at contract level.
- External audit is still required.

## Explicit Non-Goals

N.8 does not:

- deploy to Base Sepolia or mainnet;
- submit public UserOperations;
- invoke paymasters;
- enable session keys;
- change `ACTION_UNLOCK`, `proofInputHash`, proof schemas, public inputs, or fact ordering;
- activate production recovery authority.
