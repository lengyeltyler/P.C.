# O.35 V2 Account Lifecycle

Status: `LOCAL_ACCOUNT_LIFECYCLE_DESIGN_ONLY`.

O.37.1 compatibility: factor registration remains a protected local
predeployment activity. Descriptor/configuration version `2` commitments are
placed into the existing complete constructor tuple, so atomic deployment,
activation verification, and the prohibition on partially initialized or
counterfactually funded accounts remain unchanged.

This document defines how one Phil identity progresses from local identity
readiness to a verified V2 chain adapter, and later through migration and
retirement. It is a lifecycle design, not a deployment procedure or
authorization artifact.

## Lifecycle Principles

1. The Phil identity exists independently of any account.
2. Counterfactual derivation creates an address prediction, not an account.
3. Deployment and all required security initialization are atomic.
4. A deployed account is not accepted until independently verified.
5. Funding is a separate later action after lifecycle, release, and loss
   checks.
6. Recovery changes validator authority, not identity or asset ownership.
7. Migration creates a new account and uses fresh typed asset actions.
8. Retirement never destroys the identity or gives the factory authority.

## State Model

```text
LOCAL_IDENTITY_READY
  -> LOCAL_CONFIGURATION_COMPLETE
  -> COUNTERFACTUAL_DERIVATION_VERIFIED
  -> DEPLOYMENT_ELIGIBLE_UNFUNDED
  -> DEPLOYED_PENDING_VERIFICATION
  -> ACTIVE_UNFUNDED
  -> ACTIVE_FUNDED
  -> MIGRATION_PENDING
  -> RETIREMENT_PENDING
  -> RETIRED
```

The states before deployment are local reviewed records. The states after
deployment combine observed chain state with local adapter acceptance. They
are not mutable factory roles and do not imply hidden onchain pause or
administration.

`ACTIVE_FUNDED` is included to define future lifecycle behavior. O.35 creates
no account and moves no funds.

## State Transitions

| From | Required evidence | To | Prohibited shortcut |
| --- | --- | --- | --- |
| no account record | canonical identity and chain-adapter request | `LOCAL_IDENTITY_READY` | treating a wallet address as identity |
| `LOCAL_IDENTITY_READY` | complete validator, recovery, version, chain, EntryPoint, timing, and public commitments | `LOCAL_CONFIGURATION_COMPLETE` | missing or placeholder security inputs |
| `LOCAL_CONFIGURATION_COMPLETE` | two independent CREATE2 derivations and exact creation tuple | `COUNTERFACTUAL_DERIVATION_VERIFIED` | trusting only factory `getAddress` |
| `COUNTERFACTUAL_DERIVATION_VERIFIED` | code-free, balance-free, nonce-zero, deposit-zero checks plus accepted factory/version manifest | `DEPLOYMENT_ELIGIBLE_UNFUNDED` | prefunding the address |
| `DEPLOYMENT_ELIGIBLE_UNFUNDED` | separate future deployment authorization and successful atomic creation | `DEPLOYED_PENDING_VERIFICATION` | claiming activation from receipt status alone |
| `DEPLOYED_PENDING_VERIFICATION` | source/runtime code, immutable, validator, recovery, epochs, nonce, balance, deposit, and event verification | `ACTIVE_UNFUNDED` | factory/deployer attestation |
| `ACTIVE_UNFUNDED` | later exact funding approval plus complete release lifecycle | `ACTIVE_FUNDED` | funding based only on deployability |
| active state | reviewed new version and exact migration manifest | `MIGRATION_PENDING` | automatic adapter switch |
| `MIGRATION_PENDING` | all separately authorized asset actions and reconciliation | `RETIREMENT_PENDING` | factory sweep or broad migration call |
| `RETIREMENT_PENDING` | zero or explicitly approved residuals, no pending operations, destination accepted, adapter record updated | `RETIRED` | selfdestruct or identity revocation |

Any unexpected code, balance, deposit, nonce, factory, version, commitment,
epoch, or deployment history blocks the transition that relied on its prior
state.

## Identity Readiness

`LOCAL_IDENTITY_READY` requires a single canonical Phil identity record with:

- identity continuity and owner commitment;
- selected chain-adapter request;
- no mixing of identity, validator, or recovery fields from another record;
- no private identity, validator, recovery, credential, or witness material
  in the lifecycle record.

The human-readable identity ID and display name remain offchain. They may
appear in sanitized repository evidence but are not constructor fields.
Onchain identity continuity uses reviewed public commitments.

An account address never replaces the canonical identity identifier.

## Configuration Assembly

`LOCAL_CONFIGURATION_COMPLETE` requires:

- accepted version-specific factory manifest;
- exact account-version and security-model IDs;
- chain, canonical EntryPoint, and confirmation target;
- owner and identity-binding commitments;
- initial validator address, supported verifier kind, key-ID binding, and
  recomputed validator commitment;
- validator epoch exactly `1`;
- exactly one nonzero, unique, role-bound commitment for each recovery role;
- recomputed recovery-configuration hash;
- recovery epoch exactly `1`;
- canonical recovery delay and expiry;
- nonzero public deployment salt;
- no admin, upgrade, module, paymaster, session, or generic execution input.

The primary-device recovery credential is purpose-separated from the daily
validator. The hardware-security-key role is an independent external hardware
domain. The third factor is separately controlled recovery custody. The
factory sees commitments only and does not verify private factor witnesses.

## Counterfactual Derivation

`COUNTERFACTUAL_DERIVATION_VERIFIED` requires two implementations of the exact
CREATE2 formula to agree:

1. the future factory's pure/view derivation;
2. an independent local implementation using factory address, domain salt,
   exact creation bytecode, and constructor encoding.

A third reproduction from published build artifacts is recommended for
release acceptance.

Before deployment, the public record may contain:

- predicted address;
- chain, EntryPoint, factory, version, and security-model identifiers;
- source, build, creation-code, runtime-code, constructor, salt, and
  initialization-tuple hashes;
- owner/identity, validator, and recovery commitments;
- fixed recovery timing;
- a sanitized lifecycle status and expiry.

It must never contain:

- `phil_secret`, identity passphrase, or recovery secret;
- private validator/factor material;
- raw credential identifiers, attestation objects, or WebAuthn assertions;
- protected proof witnesses;
- reusable approval, presence, signature, or UserOperation authority;
- credential-bearing RPC or bundler URLs.

The user salt is not secret. Treating it as a security factor is prohibited.

## Deployment Eligibility

`DEPLOYMENT_ELIGIBLE_UNFUNDED` is reached only after fresh read-only checks
prove:

- expected chain and EntryPoint;
- accepted factory code and immutable version binding;
- predicted address still matches independent derivation;
- no code at the address;
- native balance zero;
- EntryPoint nonce zero on all relevant initial lanes;
- EntryPoint deposit zero;
- no conflicting creation/deployment evidence;
- lifecycle proposal is current and unexpired.

An unexpected native balance fails closed even if a third party sent it. A
counterfactual balance is not proof the account can release funds. The next
phase must reconcile the balance and revisit O.28 before deployment or
funding.

Deployment eligibility creates no approval. Deployment requires a separate
phase, fresh state, exact transaction or UserOperation envelope, and explicit
authorization.

## Atomic Initialization

The future factory creates the account with one constructor call. The
constructor atomically:

1. confirms its executing chain;
2. fixes EntryPoint, chain, owner/identity commitments, factory binding,
   version IDs, confirmation target, and recovery timing;
3. validates initial validator address, verifier kind, key-ID binding,
   commitment, and epoch `1`;
4. validates three nonzero unique role commitments;
5. recomputes the exact threshold-2 recovery configuration and fixes recovery
   epoch `1`;
6. initializes recovery to `NORMAL`;
7. initializes execution lock false;
8. leaves every keyed nonce at EntryPoint sequence zero;
9. leaves every pending recovery/configuration field empty;
10. rejects value and makes no external call.

No intermediate onchain state is observable. If a check fails, creation
reverts, no account code remains, and no retry with modified inputs is
automatic.

Missing validator, missing role, duplicate role commitment, zero binding,
unsupported verifier, wrong epoch, wrong version, wrong chain, wrong
EntryPoint, wrong factory, wrong timing, or config-hash mismatch all fail
creation.

## Activation

Successful contract creation enters local state
`DEPLOYED_PENDING_VERIFICATION`. The account's constructor state is already
security-complete; there is no separate onchain `activate` function.

Independent verification must confirm:

- deployment receipt, created address, factory event, and zero value;
- runtime bytecode and reviewed build binding;
- every immutable getter;
- validator address, key binding, commitment, verifier kind, and epoch `1`;
- three recovery role commitments, configuration hash, threshold, state, and
  recovery epoch `1`;
- no pending recovery or config rotation;
- execution lock false;
- EntryPoint lanes at sequence zero;
- EntryPoint deposit and account balances equal expected zero;
- factory has no account role or callback;
- no unexpected external effects.

Only then does the chain adapter become `ACTIVE_UNFUNDED`.

Activation is an acceptance decision by PhilCore Runtime and operators based
on evidence. It does not create account authority, alter chain state, or
replace the account's validation rules.

## Active Operation And Recovery

An active account accepts only the O.32/O.33/O.34 authorization and typed
execution model.

The factory has no further role. Validator rotation, recovery request,
cancellation, completion, and recovery-configuration rotation occur only
through account rules. Recovery stays exact 2-of-3:

```text
Primary Device
        +
Hardware Security Key
        +
Recovery Factor
```

Recovery completion installs only the committed pending validator and
increments epochs. It cannot move assets. Post-recovery execution requires a
fresh ordinary intent, approval, presence, validator authority, nonce, and
fund-lifecycle binding.

Recovery-configuration rotation uses the delayed account state machine. It
does not redeploy the account and does not change its address.

## Funding Gate

The lifecycle permits consideration of funding only at `ACTIVE_UNFUNDED`.
Before any future funding proposal:

1. account lifecycle and post-deployment verification are complete;
2. validator and recovery configuration are active and coherent;
3. every intended asset has a typed release route;
4. local create/fund/execute/release/final-state simulation passes;
5. fork simulation passes or a technical unavailability reason is accepted;
6. maximum funding, maximum stranded value, residual recipient, expected
   operation cost, and final balance are exact;
7. funding, operation, and residual release each have separate approvals.

The factory is never a release path. Deployability, a receive hook, recovery
authority, or a counterfactual address is never sufficient evidence that
funds are recoverable.

## Migration And Retirement

Migration is covered in the companion design. Lifecycle rules are:

- destination reaches `ACTIVE_UNFUNDED` before any asset movement;
- source and destination identity continuity is independently verified;
- every asset movement is a fresh typed source-account action;
- no broad sweep or automatic migration exists;
- old and new balances, deposits, nonces, and receipts are reconciled;
- canonical adapter selection changes only after verified movement;
- retirement preserves the old account's code and history.

`RETIRED` means PhilCore no longer selects the account for new ordinary
activity. It does not selfdestruct the account, revoke the Phil identity, give
the factory control, or make remaining assets recoverable by another account.
Any residual release must be authorized under the old account's own rules.

## Failure And Restart Rules

Every failure is fail-closed:

- malformed local configuration returns to configuration review;
- derivation disagreement invalidates the proposal;
- predeployment collision requires investigation, not alternate salt
  selection;
- reverted/ambiguous deployment requires exact transaction-hash
  reconciliation before any later attempt;
- post-deployment mismatch prevents activation;
- incomplete release lifecycle prevents funding;
- migration mismatch leaves the current adapter unchanged;
- residual balances prevent retirement unless explicitly bounded and
  approved.

No failure authorizes an automatic retry, alternate factory, substitute
version, new salt, weaker recovery configuration, or broader execution.

## O.35 Boundary

This document creates no local account object, deployment request, signature,
UserOperation, or transaction. It performs no live read and no public
mutation.
