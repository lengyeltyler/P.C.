# Ethereum Sepolia External Audit Scope

Status: proposed review scope.

## Scope

- `PhilCore4337Account` and factory;
- v0.7 hash, nonce, initCode, signature, prefund, and EntryPoint integration;
- execution and recovery validator behavior;
- ActionGate, proof verifier, UnlockConsumer, confirmation target;
- nullifier atomicity and replay;
- STWO public-input to Runtime/approval/presence/UserOperation composition;
- Device Vault custody and one-time signing session;
- RPC/bundler restrictions, fee caps, submission, and receipt reconciliation;
- deployment manifest, role separation, and operational recovery.

## Required Review by Stage

| Stage | Required evidence |
| --- | --- |
| one disposable zero-value Sepolia experiment | internal adversarial tests, static analysis, dependency triage, exact human review, disposable custody/funding; an external full audit is recommended but not automatically mandatory unless repository policy/ACP approval requires it |
| trusted external Alpha | independent focused review of account/gate/composition/custody plus operational runbook |
| public Beta | independent contract and application boundary review, remediation verification, deployment/monitoring review |
| mainnet/production | full external audit, production custody/recovery review, incident response, economic and infrastructure review |

Any critical/high finding affecting signature validation, call restriction,
proof composition, nullifier atomicity, custody, or mutation guards blocks the
first public mutation. Material medium findings require explicit disposition.

## Exclusions

O.17 does not approve:

- production/mainnet;
- meaningful assets;
- paymasters;
- generic wallet execution;
- public fact transport;
- a live RPC or bundler vendor;
- ACP-0002.

