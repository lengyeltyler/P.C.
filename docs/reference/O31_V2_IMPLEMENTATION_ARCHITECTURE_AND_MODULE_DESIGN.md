# O.31 V2 Account Implementation Architecture and Module Design

Status: `IMPLEMENTATION_ARCHITECTURE_COMPLETE_LOCAL_ONLY`.

O.31 translates the O.30 V2.0 specification into a contract and Runtime
engineering design. It fixes module boundaries, trust boundaries, storage
ownership, nonce interactions, recovery-factor roles, and the order in which a
later Solidity phase must proceed.

O.31 is design evidence only. It adds no Solidity, deployable bytecode,
UserOperation, signature, proof, account, factory, funding action, or live
contract call. Public mutations are zero.

## Baseline And Scope

The O.31 baseline is repository HEAD
`978e6d1169d536d7b0a014338799d8abb2b43630` on
`codex/device-identity-v1`.

The following remain authoritative:

- `phil_secret -> identityRoot -> ownerCommitment`;
- Phil identity is device-first and chain-independent;
- Ethereum is an execution adapter, not the identity layer;
- V1 account and factory source remain frozen;
- V2 is non-upgradeable and versioned through a new implementation, factory,
  and counterfactual address;
- V2 exposes only the O.30 typed action surface;
- O.27 funds are not a V2 migration source;
- production meaningful assets remain blocked until stronger execution
  validation, recovery operations, audit, and lifecycle gates pass.

The full baseline suite also confirms that the historical O.22 deployment
proposal is no longer current-source evidence. O.26.1 later changed
`localProofGatedDeploymentPreparation.ts` to add restricted Alchemy
RPC/bundler behavior without regenerating O.22. The O.22 source-binding test
therefore fails closed on its recorded pre-O.26.1 hash. O.31 does not refresh
or authorize that deployment proposal. Continuing this local-only design phase
is safe because it creates no deployment artifact or public authority and
does not depend on O.22 readiness.

O.31 refines O.30's three generic recovery-factor slots into three mandatory
roles. It does not weaken O.30's 2-of-3 threshold:

```text
PRIMARY_DEVICE + HARDWARE_SECURITY_KEY + RECOVERY_FACTOR
```

Each role is a separate security domain. The primary-device recovery
credential is purpose-separated from the daily execution validator. Reusing
the execution-validator key or its key reference in a recovery slot is
prohibited.

## Component Model

```text
Application (untrusted intent request)
  -> PhilCore Runtime API
      -> Trust Manager / Security Policy / Authorization / Proof
      -> Recovery Manager
      -> trusted presentation and fresh user presence
      -> Device Vault and hardware-factor adapters
      -> Ethereum Adapter
          -> one exact PackedUserOperation
          -> ERC-4337 EntryPoint v0.7
              -> PhilCoreV2Account
                  -> IntentValidation
                  -> ValidatorVerification
                  -> RecoveryStateMachine
                  -> TypedExecution
```

The names above are conceptual implementation units. They are not approval to
create source files or deploy contracts.

## Contract Composition

### `PhilCoreV2Account`

The account is the only state-owning account contract. It is concrete,
non-proxy, and non-upgradeable.

It owns:

- immutable EntryPoint, deployment chain, owner commitment, factory binding,
  account-version ID, security-model ID, confirmation target, recovery delay,
  and recovery expiry;
- active validator reference, validator key-ID binding, and validator epoch;
- fixed-role recovery commitments and recovery epoch;
- recovery freeze and pending-request state;
- the execution reentrancy lock;
- the typed receive and execution surface.

It enforces:

- EntryPoint-only validation and action entry;
- exact O.30 action selector, payload, purpose, nonce lane, epochs, validity,
  fee bound, account, chain, and EntryPoint;
- no arbitrary call, delegatecall, proxy upgrade, module installation,
  unrestricted withdrawal, approval, batch, paymaster, session key, owner
  shortcut, or administrator;
- recovery/config transitions with no external calls or value movement.

### `PhilCoreV2IntentValidation`

This is a compiled-in stateless library or internal unit. It is not an
installable validator module.

It:

- computes the exact O.30 EIP-712 domain, header, action-specific intent,
  authorized-intent, and authority digests;
- decodes each selector with canonical length and type checks;
- validates action/purpose/nonce-lane relationships;
- validates chain, account, EntryPoint, epochs, validity, and fee ceiling;
- returns a typed validation context consumed by account execution.

It does not own state, call applications, decide policy, accept optional
fields, or validate arbitrary calldata.

### `PhilCoreV2ValidatorVerification`

This is a fixed verifier unit compiled into the account. “Module” means source
separation, not runtime pluggability.

It:

- verifies the active execution-validator envelope for ordinary and
  maintenance actions;
- verifies low-`s`, canonical recovery-byte secp256k1 signatures for the
  initial local/test validator;
- verifies fixed recovery-factor witness kinds selected for the account
  version;
- binds the active validator commitment, key-ID binding, and epoch;
- rejects duplicate factor roles, duplicate witnesses, wrong commitments,
  wrong verifier kinds, stale epochs, and noncanonical encodings.

It cannot register a new verifier, call a verifier chosen from calldata, or
delegatecall into another contract. A future cryptographic verifier requires a
new reviewed account version.

### `PhilCoreV2RecoveryStateMachine`

This is a fixed state-transition unit compiled into the account. The account
remains the storage owner.

It:

- verifies exact 2-of-3 role-bound recovery authorization;
- records one exact proposed validator and next epoch;
- freezes ordinary and validator-maintenance lanes;
- enforces challenge delay, cancellation, expiry, and permissionless exact
  completion;
- rotates the validator and recovery epochs;
- performs delayed recovery-configuration replacement;
- emits commitments and transition evidence, never private factor metadata.

It cannot transfer assets, withdraw deposits, invoke typed execution, change
identity/EntryPoint/factory/version, or install arbitrary logic.

### `PhilCoreV2TypedExecution`

This is a fixed set of private/internal action handlers:

- typed confirmation;
- exact native transfer with empty calldata;
- exact ERC-20 transfer with return and balance-delta checks;
- exact ERC-721 safe transfer;
- exact single ERC-1155 safe transfer;
- exact EntryPoint-deposit withdrawal.

Each handler accepts only its typed validation context. There is no generic
target/value/data handler and no shared primitive callable with arbitrary
calldata.

### `PhilCoreV2AccountFactory`

A later implementation requires a new non-upgradeable factory. It:

- embeds or otherwise source-binds the exact V2 creation code;
- accepts a complete initial account configuration only;
- binds EntryPoint, chain, owner commitment, initial validator, all three
  role commitments, timing, version, and security model into account creation
  and CREATE2 derivation;
- rejects incomplete, duplicate, zero, or role-incompatible commitments;
- grants no post-deployment authority.

The factory is not an administrator and cannot change a deployed account.

## Off-Chain Components

### PhilCore Runtime

Runtime remains outside the contract and owns:

- application capability evaluation;
- trust and policy decisions;
- proof generation and verification;
- trusted human-readable presentation;
- approval and fresh-presence orchestration;
- value/risk classification and hardware step-up policy;
- canonical intent construction and Runtime authorization;
- recovery ceremony coordination;
- receipt, event, balance, epoch, and authority reconciliation.

The account does not parse application policy, labels, proof witnesses,
passphrases, `phil_secret`, local approval artifacts, or audit records.

For local/test V2, Ethereum still verifies the Device Vault validator and
account rules, not the STARK proof. Runtime must require the external hardware
key for policy-classified high-value actions. Until a production validator
also enforces the required second factor on-chain, compromise of the execution
validator can bypass that local step-up within the typed ABI. This is an
explicit production blocker.

### Device Vault

Device Vault remains outside the contract and owns:

- protected execution-validator generation and exact-digest signing;
- the separate primary-device recovery credential;
- local public factor references and lifecycle state;
- hardware-backed secret operations;
- pending/active/rotated/revoked coordination after verified chain state;
- one-time, non-serializable signing sessions.

It never exposes raw private material, derives a validator or recovery
credential from `phil_secret`, or marks rotation complete before verified
account state.

### Trust Manager And Hardware Adapters

Trust Manager owns WebAuthn/FIDO2 registration and assertion verification,
attestation policy, origin/RP binding, user-presence/user-verification
requirements, counters, credential status, and independence evidence.

The external hardware security key must use a cross-platform authenticator or
other separately held hardware signer. A passkey synchronized through the
same platform account is not sufficient evidence of an independent hardware
domain.

### Ethereum Adapter

The Ethereum Adapter owns chain-specific encoding, EntryPoint nonce reads,
gas/fee construction, bundler allowlists, simulation, submission boundaries,
and receipt reconciliation. It never decides identity, factor independence,
approval, recovery policy, or factor custody.

## Trust Boundaries

| Boundary | Trusted for | Not trusted for |
| --- | --- | --- |
| Account bytecode | typed enforcement and state transitions after audit | human meaning, application identity, local proof truth |
| EntryPoint | canonical nonce and ERC-4337 dispatch semantics | user intent or application policy |
| Runtime | policy, proof, presentation, one-time authorization | changing account ABI or chain state without adapter gates |
| Device Vault | protected exact-purpose signing | application policy or unrestricted wallet signing |
| Hardware authenticator | independent confirmation and factor signature | account selection, recipient meaning, recovery proposal construction |
| Application | requesting an intent | authorization, signing, factor access, adapter access |
| Bundler/RPC/relayer | transport and observations | authorization, canonical state without reconciliation |

## Storage Architecture

### Immutable configuration

The later account constructor must fix:

1. canonical EntryPoint address;
2. deployment chain ID;
3. owner commitment;
4. factory binding;
5. account version ID;
6. security-model ID;
7. confirmation target;
8. recovery delay (`172800` seconds);
9. recovery expiry (`604800` seconds after request).

None can be changed through recovery or maintenance.

### Mutable logical layout

The implementation phase must preserve this declared order and publish the
compiler storage-layout artifact:

1. active validator address/reference, validator verifier kind, validator
   epoch, frozen flag, and execution lock;
2. validator key-ID binding;
3. validator commitment;
4. security-configuration hash;
5. primary-device recovery-factor commitment;
6. hardware-security-key commitment;
7. independent recovery-factor commitment;
8. recovery epoch and recovery state discriminator;
9. active recovery request ID;
10. pending validator address/reference and key-ID binding;
11. pending validator commitment and proposed validator epoch;
12. request source epochs, requested-at, executable-after, and expires-at;
13. recovery authorization evidence commitment;
14. pending recovery-config request ID and proposed security-config hash;
15. three proposed role commitments;
16. proposed recovery epoch, timing, and active flag.

No general mapping, storage gap, module registry, implementation slot,
administrator slot, arbitrary capability root, or allowance table is allowed.
Reserved bits and fields must remain zero.

`securityConfigurationHash` commits to the three ordered roles, verifier kinds,
factor commitments, recovery threshold, WebAuthn policy identifiers, and
configuration version. It cannot enable new selectors or change immutable
timing. Its only transition is delayed recovery-config rotation.

### Factor privacy

Only role-specific commitments and verifier-kind identifiers are stored in
account state. The account does not store credential labels, local key IDs,
attestation certificates, AAGUIDs, device names, origins, recovery-package
locations, or public identity metadata.

A factor witness reveals the public verification material necessary to verify
that use. Because transaction calldata is public forever, commitment storage
reduces passive linkage before first use but does not provide post-use
anonymity. Events contain request/config commitments and role bitmaps, not
factor witness bytes.

## Nonce And Epoch Architecture

EntryPoint v0.7 owns the keyed nonce sequence:

```text
nonce = (uint256(uint192 key) << 64) | uint64(sequence)
```

| Key | Use | While recovery is active |
| --- | --- | --- |
| `0` | ordinary typed execution | rejected |
| `1` | validator maintenance | rejected |
| `2` | recovery and recovery-config maintenance | available subject to exact state |

The account does not duplicate EntryPoint sequence storage. Every intent binds
the exact key and sequence.

Epoch rules:

- validator rotation increments validator epoch by exactly one;
- recovery completion increments validator epoch and recovery epoch by
  exactly one;
- recovery-config completion increments recovery epoch by exactly one;
- cancellation and expiry do not increment an epoch;
- every signed action binds both current epochs;
- old-epoch authority fails even when its EntryPoint nonce remains unused;
- permissionless completion is replay-protected by exact active request ID and
  state consumption.

A recovery request freezes keys `0` and `1` when its EntryPoint execution is
included. It cannot retroactively reorder an earlier operation in the same
block. Runtime and monitoring must treat inclusion ordering as adversarial.

## Migration Requirements

V2 is not a proxy upgrade and does not retrofit V1.

Migration requires:

1. a new implementation and factory;
2. a new deterministic account address;
3. owner-commitment continuity;
4. complete three-role enrollment before derivation acceptance;
5. independent source, bytecode, factory, EntryPoint, and CREATE2 verification;
6. full local and fork lifecycle before any funding;
7. typed asset movement from a prior recovery-capable account only;
8. verified zero or explicitly approved residual balances before adapter
   version selection changes.

The funded V1 counterfactual address cannot move its balance and is excluded
from V2 migration.

## Security Closure

The implementation is nonconforming if any code path introduces:

- hidden administrator or owner shortcut;
- upgrade key, proxy slot, module installation, or arbitrary verifier;
- generic call, delegatecall, unrestricted withdrawal, sweep, approval, or
  batch;
- a recovery path that transfers value or invokes external code;
- one-factor recovery or same-domain double counting;
- direct Account 1 or Account 2 authority;
- reuse of the daily validator as the primary-device recovery credential;
- funding before the complete lifecycle suite passes.

## Stop Boundary

O.31 stops at engineering design. No V2 contract or factory is implemented.
No proof, Runtime authorization, approval, user-presence event, Device Vault
signature, UserOperation, deployment, funding, live call, or other public
mutation is created.
