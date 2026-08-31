# Ethereum Sepolia Contract Audit

Status: internal readiness audit, not an external audit or production approval.

## Canonical Candidates

| Contract | Purpose | Constructor/binding | Privilege and replay | Readiness |
| --- | --- | --- | --- | --- |
| `PhilCore4337Account` | v0.7 smart account | EntryPoint, owner, owner commitment, ActionGate, recovery authority/timing | owner validates normal UserOps; recovery authority is maintenance-only; EntryPoint nonce; non-upgradeable | locally tested, unaudited |
| `PhilCore4337AccountFactory` | deterministic account deployment | EntryPoint, ActionGate, recovery authority/timing | permissionless `createAccount`; immutable family configuration | locally tested, unaudited |
| `PhilBaseActionGate` | proof validation, nullifier consumption, consumer dispatch | immutable proof verifier | no owner/admin; nullifier mapping; consumer call atomicity | chain-independent code with Base name; locally tested |
| `PhilL1FactUnlockProofVerifier` | Ethereum-visible fact check | immutable L1 fact anchor | view-only; no admin | Ethereum compatible; deployment missing |
| `PhilL1ProofInputHashAnchor` | consumes exact Starknet L2 message and anchors fact | immutable messaging core and L2 sender | permissionless trigger, messenger authenticates source; fact mapping | Ethereum compatible; live route/deployment missing |
| `PhilUnlockConsumer` | exact account/target/value/calldata binding | immutable ActionGate | gate-only; forwards exact bounded target call | locally tested |
| `PhilCoreAuthorizationConfirmationTarget` | harmless first action | immutable UnlockConsumer | no owner/admin/withdraw/upgrade; zero-value nonpayable action | O.17 local tests pass |

Base mirror and L1-to-Base messenger contracts are not part of the Ethereum
Sepolia profile.

## Account Review

The account inherits v0.7 `BaseAccount` and overrides:

- `entryPoint()` with an immutable `IEntryPoint`;
- `_validateSignature(PackedUserOperation,userOpHash)` using EIP-191 ECDSA;
- `_requireFromEntryPoint()` with exact caller validation.

The factory deploys accounts with CREATE2 and returns an already-deployed
account for duplicate requests. Counterfactual and deployed account tests use
the actual dependency EntryPoint artifact.

Security properties:

- chain replay: prevented by EntryPoint `userOpHash` chain ID;
- EntryPoint replay: prevented by EntryPoint address in `userOpHash`;
- account replay: prevented by sender in `userOpHash`;
- nonce replay: prevented by EntryPoint nonce;
- target/calldata/value mutation: changes UserOp hash and protected action
  commitments;
- expired authorization: rejected by ActionGate and Runtime expiry checks;
- direct execution: rejected unless EntryPoint calls the immutable gate;
- nullifier replay: rejected by ActionGate.

## Confirmation Target

`PhilCoreAuthorizationConfirmationTarget.onPhilUnlock(...)`:

- is callable only by its immutable `PhilUnlockConsumer`;
- is nonpayable;
- accepts one nonzero `actionId`;
- records account, nullifier, and action ID;
- rejects duplicate action IDs;
- emits one confirmation event;
- has no owner, administrator, token movement, withdrawal, upgrade, delegatecall,
  self-destruct, or arbitrary-call function.

The smart account does not call this target directly. The receipt must prove
the complete account -> ActionGate -> UnlockConsumer -> target chain.

## Deployment and Audit Status

No O.17 contract is deployed on Ethereum Sepolia. No address is accepted.
Bytecode hashes in the proposed manifest are local compile evidence only.

The custom account, factory, gate, fact components, consumer, target, Runtime
composition, Device Vault signer, and public submission controls require
independent review at the level specified in
`ETHEREUM_SEPOLIA_EXTERNAL_AUDIT_SCOPE.md`.

