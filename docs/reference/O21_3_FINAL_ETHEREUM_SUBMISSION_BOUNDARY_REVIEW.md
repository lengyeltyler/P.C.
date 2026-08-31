# O.21.3 Final Ethereum Submission Boundary Review

Status: review complete; deployment, funding, bundler contact, and submission
remain blocked.

## Verdict

O.21.1 and O.21.2 form a coherent local authorization and signing chain. The
current signed artifact is correct for its exact, short-lived inputs, but it is
not eligible for public submission.

The first public operation requires new evidence after the target and factory
are deployed: an accepted source-bound manifest, fresh CREATE2 verification,
fresh nonce and prefund reads, a compatible ERC-4337 v0.7 bundler simulation,
approved gas and fee limits, a new proof and Runtime authorization, a new
Device Vault signature, and a separate submission approval. The existing
O.21.2 artifact must not be reused.

No O.21 submission transport is implemented. The existing mutation command is
a fail-closed dry-run guard.

## Authorization Chain

| Stage | Exact binding | Review result |
| --- | --- | --- |
| PhilCore identity | identity reference, owner commitment, Device Vault validator reference | bound in the Runtime authorization; validator key is independent of `phil_secret` |
| STARK proof | `stwo-unlock-keccak-v1`, proof digest, `proofInputHash`, action digest | generated and verified locally; Ethereum does not verify it |
| Runtime authority | identity, session, approval, nullifier, proof, target, chain, expiry | bound into the Runtime authorization digest |
| User approval | exact presentation digest, action, identity, session, expiry | one-time preparation approval plus separate signing approval |
| Device Vault signature | purpose, validator, account, EntryPoint, chain, UserOperation hash, call hash, expiry | one-time purpose-bound signing session; no arbitrary signing API |
| PackedUserOperation | sender, nonce, initCode, callData, gas, fees, paymaster data | canonical v0.7 hash covers every field except the signature |
| Account validation | model/version envelope, action, Runtime digest, expiry, validator key ID, ECDSA owner | exact 288-byte custom envelope; paymasters and alternate calls fail |
| EntryPoint execution | nonce, counterfactual deployment, account validation, bounded call | locally tested; no Sepolia execution has occurred |

Changing sender, nonce, initCode, calldata, gas, fees, paymaster data, chain,
EntryPoint, account, action, Runtime digest, expiry, or validator binding
changes a checked digest or fails an equality check. No signed field may be
updated in place. A necessary update starts a new preparation, approval,
presence, and signing cycle.

## 1. Signed Artifact Correctness

The O.21.2 artifact contains both unsigned and signed PackedUserOperations,
the custom signature envelope, canonical UserOperation hash, account-signature
digest, Runtime authorization digest, validator public binding, proof hashes,
signing approval digest, user-presence digest, and expiry. It explicitly marks
submission, deployment, ETH movement, public mutation, and Ethereum STARK
verification false.

Creation verifies the Device Vault signature recovers the expected validator.
Artifact validation recomputes the UserOperation and account-signature hashes
and checks that only the signature changed.

Submission must add a load-time cryptographic check. The current standalone
artifact validator does not recover the persisted envelope signature again,
and the compact signed artifact does not contain the full identity, session,
approval, and audit evidence required to independently reconstruct every
Runtime correlation. A future submission eligibility package must consume:

* the signed artifact;
* its original unsigned preparation artifact;
* the correlated Runtime audit evidence;
* the accepted deployment manifest;
* fresh chain, bundler, nonce, gas, fee, prefund, and expiry observations.

Disk possession of a signed artifact is not submission authority.

## 2. ERC-4337 v0.7 Compatibility

The repository pins `@account-abstraction/contracts` `0.7.0`. The account
inherits the v0.7 `BaseAccount`, accepts `PackedUserOperation`, and implements
the expected `validateUserOp` path through `_validateSignature`. The canonical
EntryPoint is:

```text
0x0000000071727De22E5E9d8BAf0edAc6f37da032
```

The TypeScript hash uses the v0.7 packed hash layout and binds the EntryPoint
and chain ID. Contract tests execute the operation through the actual v0.7
EntryPoint artifact. The custom account signature is intentionally not the
SimpleAccount format; compatibility depends on this account's exact 288-byte
envelope.

The remaining compatibility gate is a live, approved bundler simulation of
the final operation. It must use the final envelope length, not an empty
signature, when calculating pre-verification gas.

## 3. Smart Account Deployment Assumptions

The first operation is not merely "create an account." It atomically:

1. asks the deployed factory to CREATE2 the account through `initCode`;
2. validates the bounded signature in the new account;
3. calls `executeLocalProofAuthorization(...)`;
4. records one zero-value confirmation in the immutable target.

Before that operation, two ordinary Sepolia deployments are required:

1. `PhilCoreLocalProofConfirmationTargetV1`;
2. `PhilCore4337LocalProofAccountFactoryV1`.

The factory directly deploys the account. There is no proxy or separately
deployed implementation. Target and factory addresses depend on the disposable
deployer nonce and remain proposed, unaccepted, and undeployed.

## 4. Factory CREATE2 Address Correctness

The factory's `getAddress(...)` derives CREATE2 from:

* factory address and account salt;
* account creation bytecode;
* canonical EntryPoint;
* validator owner address;
* owner commitment;
* immutable confirmation target;
* validator key ID;
* chain ID.

The TypeScript preparation code uses the same constructor encoding and CREATE2
formula. Existing contract tests compare the factory's returned address with
the deployed account and execute a counterfactual first operation.

Immediately before signing a future operation, Runtime must independently:

* call the accepted factory's `getAddress(...)`;
* compare it with `sender`;
* decode `initCode` and compare every factory argument;
* verify the factory and target deployed-code hashes and immutable getters;
* reject any deployer-nonce or accepted-address change.

The signed artifact validator alone does not recompute CREATE2 from deployed
factory state.

## 5. EntryPoint Compatibility

The proposal is bound to Ethereum Sepolia chain `11155111` and the canonical
v0.7 EntryPoint. O.20 observed code and `getNonce` support through a read-only
RPC, but that observation is stale evidence, not an execution authorization.

Before public mutation, verify again:

* chain ID and EntryPoint code hash;
* `eth_supportedEntryPoints` from the selected bundler;
* EntryPoint `getNonce(sender, 0)`;
* final `getUserOpHash` parity;
* bundler simulation against the exact EntryPoint.

No alternate EntryPoint is allowed without regenerating the deployment,
account address, operation, approval, and signature.

## 6. Nonce Handling

The counterfactual first account expects nonce key `0`, value `0`. The
EntryPoint is authoritative. The nonce must be read during preparation and
again immediately before submission.

If the nonce changes or the account unexpectedly has code, stop. Do not patch
the signed operation. Reconcile existing UserOperation and transaction hashes,
then start a fresh authorization cycle. After an ambiguous bundler response,
never submit a replacement until EntryPoint nonce and receipt state are known.

## 7. Gas, Fees, And Prefund

O.21.1 used bounded conservative fields, but no approved bundler estimate
exists. A public attempt requires:

* `eth_estimateUserOperationGas` against the final counterfactual operation;
* a signature stub with the exact envelope length during estimation;
* explicit verification, call, and pre-verification gas limits;
* fresh EIP-1559 fee data and a human-approved maximum total exposure;
* sufficient counterfactual-account prefund before submission;
* no paymaster.

Any gas or fee change changes the UserOperation hash and invalidates approval
and signature. Estimation is not a success guarantee. The disposable account
has no withdrawal or recovery path, so prefunding is potentially stranded and
must be the separately approved minimum.

## 8. Bundler Trust Boundary

No bundler is selected, approved, configured, or contacted. A future restricted
client may expose only:

* capability and EntryPoint checks;
* exact-operation gas estimation;
* submission of one approved signed operation;
* lookup and receipt monitoring for its exact hash.

A bundler can censor, delay, log, simulate incorrectly, or return ambiguous
status. It cannot alter signed fields. PhilCore must recompute any returned
UserOperation hash and independently verify the transaction receipt and
EntryPoint event through a separately approved Ethereum RPC. No blind retry,
replacement, paymaster coupling, or renderer bundler access is allowed.

## 9. RPC Trust Boundary

The existing preparation RPC is read-only and method-allowlisted. A malicious
RPC can lie about chain, code, nonce, balances, fees, and receipts.

The first execution requires:

* an approved endpoint whose credentials remain external;
* chain and code-hash pinning;
* block references on all freshness-sensitive reads;
* independent receipt and event verification separate from the bundler;
* fail-closed behavior on provider disagreement;
* no generic mutation RPC in Runtime, preload, or renderer.

For the first disposable test, a second independent read provider is
recommended for deployment code, nonce, transaction receipt, and final event
reconciliation.

## 10. Failure And Recovery

| Failure | Required behavior |
| --- | --- |
| target or factory deployment mismatch | abandon the proposed address set; do not sign |
| account address or initCode mismatch | regenerate from accepted factory state |
| nonce, gas, fee, or expiry change | invalidate approval and signature; restart |
| insufficient prefund | stop before submission; do not guess funding |
| bundler simulation rejection | preserve sanitized reason; do not submit |
| ambiguous submission | reconcile hash, nonce, bundler lookup, RPC receipt, and EntryPoint event |
| expired operation | generate a fresh proof, Runtime authorization, approval, presence, and signature |
| included but account validation failed | record failure and inspect EntryPoint reason; no success claim |
| account execution reverted | verify no target confirmation; do not claim action success |
| validator loss | abandon the disposable account and any stranded test ETH |
| provider or bundler outage | wait or switch only through a newly approved configuration |

There is no chain rollback. Confirmed deployments and funding are immutable.
Before mutation, rollback means discarding local proposals and signed artifacts.
After a bad deployment, use a new disposable deployment set. No meaningful
assets are permitted.

## First Sepolia Execution Plan

Each numbered mutation is a separate human stop:

1. Freeze the reviewed source commit and regenerate the proposed manifest.
2. Re-run compile, static analysis, contract tests, bytecode hashing, read-only
   chain checks, and address collision checks.
3. Accept the exact source, bytecode, deployer nonce, target, factory, account,
   constructor values, roles, and maximum exposure.
4. Approve and deploy only the confirmation target. Verify its receipt, code,
   and source binding. Stop.
5. Recalculate the factory address if the deployer nonce changed. Approve and
   deploy only the factory. Verify code and immutable EntryPoint, target, and
   chain values. Stop.
6. Independently confirm factory `getAddress(...)` equals the proposed account.
7. Select and approve one v0.7 Sepolia bundler and independent read RPC. Run
   capability checks and final-operation simulation without submission.
8. Calculate and approve the minimum disposable account prefund and hard fee
   ceiling. Fund only the exact counterfactual account. Verify balance. Stop.
9. Generate a fresh local proof and O.21.1 unsigned artifact using deployed,
   accepted configuration and current nonce, gas, fees, prefund, and expiry.
10. Present the exact operation, require fresh approval and user presence, and
    produce a new O.21.2 signed artifact.
11. Cryptographically reload and validate the signature envelope, recover the
    validator, recompute CREATE2 and EntryPoint hashes, repeat nonce, fee,
    prefund, deployment, and expiry checks, and simulate the exact signed
    operation.
12. Obtain a separate one-time public submission approval bound to the
    UserOperation hash, bundler, maximum fee, and expiry.
13. A future approved boundary may submit exactly once, then monitor and
    independently reconcile. O.21.3 stops before this step.

## Exact First Operation Proposal

The machine-readable proposal is
`config/ethereum-sepolia/O21_3_FIRST_SEPOLIA_EXECUTION_PROPOSAL.json`.

Its exact fixed shape is:

```text
EntryPoint v0.7 on chain 11155111
  -> initCode:
       proposed factory.createAccount(
         Device Vault validator,
         ownerCommitment,
         validatorKeyId,
         accepted salt
       )
  -> counterfactual account.executeLocalProofAuthorization(
       actionId,
       fresh Runtime authorization digest,
       short expiry
     )
  -> immutable target.confirmPhilCoreAction(
       actionId,
       Runtime authorization digest
     )
```

Value is zero. Token movement, batching, delegatecall, paymaster use, generic
execution, and Ethereum STARK verification are absent.

The proposal deliberately does not freeze action ID, proof, Runtime digest,
expiry, UserOperation hash, gas, or fees. Those values must be fresh after
deployment and simulation. Calling stale placeholders "exact" would create an
unsafe approval surface.

## Human Approvals

Separate approvals are required for:

1. source commit, compiler settings, bytecode, and immutable architecture;
2. disposable deployer and proposed address set;
3. target deployment;
4. factory deployment;
5. RPC and bundler providers, privacy, retention, and credentials;
6. disposable funder, prefund amount, and maximum total exposure;
7. final fresh proof-backed UserOperation presentation;
8. Device Vault signing;
9. exact public UserOperation submission.

No approval implies another. Environment gates are necessary but never
sufficient.

## Current Blocking Evidence

The local inspection reports:

* contract bytecode still matches the proposed manifest;
* the manifest remains `proposed`;
* its source binding is stale because O.21.1 and O.21.2 changed Runtime signing
  files after the recorded source commit;
* addresses are not accepted or deployed;
* prefund and bundler estimates are unresolved;
* no bundler is approved;
* no submission transport exists;
* no mutation approval is present.

O.21.3 therefore authorizes no deployment, funding, signing, or submission.

## O.22 Refresh

O.22 rebuilds the current-source deployment proposal and provisional funding
readiness while preserving all mutation stops. See
[O.22 Current-Source Deployment And Funding Review](./O22_CURRENT_SOURCE_DEPLOYMENT_AND_FUNDING_REVIEW.md).
