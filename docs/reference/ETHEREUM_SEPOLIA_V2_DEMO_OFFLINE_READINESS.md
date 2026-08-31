# Ethereum Sepolia V2 Demo — Offline Readiness

Status: Offline preparation package only. Live deployment, funding, device
signing, and UserOperation submission remain prohibited and separately gated.

## Purpose

This document describes the offline PhilCore V2 Sepolia demo-preparation path
for a **zero-value `confirmIntent`** first UserOperation against the current
deployable consumer-recovery account. It does not authorize any network,
hardware, credential, or evidence-generation activity.

## Why zero-value `transferNative` is impossible

`PhilCoreV2MinimalAccountV2` rejects native transfers that move zero value as
part of its fail-closed value-transfer rules. A “do nothing” first operation
therefore cannot be expressed as `transferNative(0)`. The first Sepolia
UserOperation for this demo must be a zero-value `confirmIntent` that records
an authorization/confirmation digest through the bound confirmation target.

## Why `confirmIntent` was selected

`confirmIntent` is the current V2 account’s intentional confirmation surface:

- It is EntryPoint-gated on the account.
- It forwards `(actionId, confirmationDigest)` to the bound confirmation target.
- It does not move assets.
- It exercises the current typed-intent / local-proof-gated security model
  without requiring a productive transfer.

The offline preparation module builds **unsigned** PackedUserOperation calldata
for that path only. Signature and proof-approval fields remain empty and are
explicitly marked incomplete until a separately authorized device stage.

## Why the V1 target and V1 deployment-preparation module are incompatible

| V1 component | Why it cannot be reused |
| --- | --- |
| `PhilCoreLocalProofConfirmationTargetV1` | Validates `securityModelId() == keccak256("local-proof-gated-v1")` plus V1 `approvedConfirmationTarget()` / `expectedChainId()`. Current V2 accounts expose `accountConfiguration()` and use `philcore-v2-typed-intent-local-proof-gated-v1`. |
| `localProofGatedDeploymentPreparation.ts` | Uses V1 factory ABI `createAccount(address,bytes32,bytes32,uint256)`, raw-uint salt, and V1 constructor/layout. Current V2 factory uses `createAccount(PhilCoreV2AccountInitializationV1,bytes32)` and domain-separated CREATE2 salts. |

`PhilCoreV2ConfirmationTargetV1` and `v2DeploymentPreparation.ts` replace those
components for the current deployable account. They do not claim migration of
any V1 balance or layout.

## Historical vs current account-version IDs

| Identity | Label | ID |
| --- | --- | --- |
| **Current deployable** | `philcore-v2-minimal-account-v3-consumer-recovery` | `0xa271e70f3c567c6a54a81e455de89f98cc067a931ac70816c6016e9b9ca1fd1f` |
| Historical cryptographic domain in `v2Intent.ts` | `philcore-v2-account-v1` (`PHILCORE_V2_ACCOUNT_VERSION_ID`) | `0x21fa156a…` |

`PHILCORE_V2_ACCOUNT_VERSION_ID` in `v2Intent.ts` remains a historical domain
separator. It must not be changed, aliased, or used as the deployable account
version for Sepolia demo preparation. The offline module rejects it.

Current security model (unchanged between historical intent domain and
deployable account):

- Label: `philcore-v2-typed-intent-local-proof-gated-v1`
- ID: `keccak256(label)` = `0xbfded32375d70119930c009b80e9a3774335bb0ae2fc4d3b7133fd8713753f44`

## Locked Sepolia / EntryPoint facts

- Chain ID: `11155111`
- Canonical EntryPoint v0.7: `0x0000000071727De22E5E9d8BAf0edAc6f37da032`
- Factory ABI: `createAccount(PhilCoreV2AccountInitializationV1,bytes32)`
- Recovery delay: `172800` seconds (48 hours)
- Recovery expiry: `604800` seconds (7 days)
- Initial recovery configuration requires **three nonzero, pairwise-distinct**
  recovery commitments and a matching V3 recovery configuration hash.
- This package **never** selects, generates, stores, or defaults recovery
  commitments. Callers must supply them explicitly.

## Current V2 initialization and deployment path (offline)

1. Assemble the exact 20-field `PhilCoreV2AccountInitializationV1` tuple with
   current account/security IDs, EntryPoint, chain ID, confirmation target,
   validator bindings, and the three recovery commitments.
2. Derive the factory CREATE2 deployment salt from
   `PHILCORE_V2_CREATE2_SALT_V1` plus chain, account version, security model,
   owner commitment, identity-binding commitment, and nonzero `userSalt`.
3. Predict the counterfactual account address from factory address, salt, and
   the account creation-code hash (creation bytecode ‖ abi-encoded init must be
   supplied explicitly; the offline module reads no artifacts from disk).
4. Encode `createAccount(initialization, userSalt)` and form ERC-4337
   `initCode = factory ‖ calldata`.
5. Encode zero-value `confirmIntent(intent, confirmationDigest)` calldata for
   the first UserOperation.
6. Emit an **unsigned** PackedUserOperation proposal marked
   `signed: false`, `submitted: false`, and
   `incompleteUntilDeviceApproval: true`.

No environment variables, private keys, providers, signers, RPCs, bundlers, or
filesystem reads are used by the preparation module.

## Confirmation target trust boundary

`PhilCoreV2ConfirmationTargetV1` is an **evidence sink**, not an independent
proof or authorization authority.

It:

- accepts calls only from contracts;
- reads the caller’s `accountConfiguration()`;
- requires matching chain ID, `confirmationTarget == address(this)`, current
  account version ID, and current security-model ID;
- rejects zero action IDs / digests and duplicate `(caller, actionId)` pairs;
- scopes recorded state to `msg.sender`;
- emits a deterministic confirmation event;
- has no owner, upgrade path, payable entry, asset transfer, or arbitrary
  execution surface.

A malicious contract can imitate `accountConfiguration()` and record
meaningless state **under its own address**. The target does **not** prove that
an arbitrary caller is a genuine PhilCore account. Meaningful evidence still
depends on the calling account’s own authorization path (EntryPoint + account
rules + separately authorized approvals).

## Local proof versus on-chain verification

Offline preparation constructs deterministic calldata and addresses for review.
It does not verify a local proof on-chain, does not approve an intent, and does
not replace device attestation. On-chain verification remains the account’s and
EntryPoint’s responsibility after a separately authorized signing/submission
stage.

## Evidence policy

- Schema-v1 evidence artifacts (including O.39–O.43 and related locks) are
  permanently frozen. This package must not modify or regenerate them.
- Future Sepolia ceremony evidence must use **schema-v2 provenance** under
  Package 6A/6B rules.
- Observation and attestation digests are not signatures and provide no
  non-repudiation.

## Explicit non-claims

This package does **not** claim:

- quantum resistance;
- production readiness;
- recovery readiness;
- public deployment;
- that any Sepolia transaction has been or will be submitted;
- that any device credential, biometric ceremony, or funding step occurred.

## Separately gated follow-ons

The following remain out of scope and require independent authorization:

- deploying the factory, verifier, or confirmation target;
- funding the counterfactual account or deployer;
- device approval / signing of the UserOperation;
- bundler submission and receipt monitoring;
- schema-v2 physical-ceremony provenance for a live Sepolia gate.
