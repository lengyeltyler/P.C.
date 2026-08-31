# O.30 V2 Account Specification and Threat Model Refinement

Status: `V2_SPECIFICATION_COMPLETE_LOCAL_ONLY`.

## Superseded recovery-cancellation authority

Historical text in this document is preserved as design/audit history.
Current V2 actions 8–11 require the exact recovery-factor authority defined by
O.36.1/O.37.1. Actions 8, 9, and 11 use exact 2-of-3 current recovery factors.
Action 10 additionally requires the current validator plus exact 2-of-3 current
recovery factors. The validator never counts toward that recovery-factor
threshold, and validator-plus-one remains prohibited.

Canonical sources:

- [O.36.1 Recovery And Cancellation Semantics](./O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md)
- [O.37.1 V2 Recovery Lifecycle Update](./O37_1_RECOVERY_LIFECYCLE_UPDATE.md)

O.30 converts the O.29 direction into an implementation-ready local
specification. It resolves the V2.0 action surface, intent hashing, validator
and recovery lifecycles, storage and nonce models, migration boundary, and
acceptance tests.

It does not implement Solidity, alter V1, create a UserOperation or protected
authorization, deploy infrastructure, fund an address, or mutate a public
chain.

## Scope Decision

V2.0 is a recovery-capable asset account, not a general-purpose programmable
wallet.

Included:

- typed confirmation;
- native transfer and residual release;
- exact ERC-20 transfer;
- ERC-721 safe transfer;
- ERC-1155 safe transfer;
- exact EntryPoint-deposit withdrawal;
- validator rotation;
- delayed 2-of-3 validator recovery;
- delayed recovery-factor rotation.

Deferred to a new account version:

- ERC-20 allowance creation or modification;
- arbitrary contract calls;
- capability adapters and allowlists;
- batching;
- paymasters;
- session keys;
- new token standards.

The deferred features do not have dormant selectors or storage in V2.0.
Adding them requires a new reviewed implementation, factory, counterfactual
address, migration plan, and acceptance phase.

## Canonical Intent Model

V2 uses action-specific EIP-712 intents. It does not use a fixed superset with
optional fields, JSON hashing, packed encoding, or application-provided
calldata.

### EIP-712 Domain

```text
name              = "PhilCore V2 Account"
version           = "1"
chainId           = current deployment chain
verifyingContract = V2 account address
```

The account rejects a header whose explicit chain or account fields differ
from the EIP-712 domain, `block.chainid`, or `address(this)`.

### Intent Core Header

Every action-specific core type contains this header in exactly this order:

```text
uint8   specificationVersion
bytes32 securityModelId
uint8   actionType
bytes32 actionId
bytes32 purpose
bytes32 ownerCommitment
uint256 chainId
address entryPoint
address account
uint192 nonceKey
uint64  nonceSequence
uint64  validatorEpoch
uint64  recoveryEpoch
bytes32 applicationContextHash
bytes32 fundLifecycleDigest
uint256 maxTotalFeeWei
uint48  validAfter
uint48  validUntil
```

Security model equals the account's immutable V2.0 value. `actionId`, owner
commitment, application context, fund-lifecycle digest, and maximum total fee
are nonzero. Every action carries a lifecycle digest. For a non-asset action,
it commits to zero asset effect and unchanged expected balances rather than
using an absent or zero field. Ordinary and maintenance intents live for at
most 600 seconds. Recovery submission authority lives for at most 3600
seconds; the resulting pending recovery has a separate delay and expiry.

There are no optional fields. Each action has its own type hash and payload.
Unknown fields, alternate field order, packed encoding, missing fields,
appended calldata, and noncanonical encodings fail.

Application context is:

```text
applicationIdHash
originHash
sessionIdHash
capabilityGrantIdHash
policyDecisionIdHash
```

Asset and deposit actions bind a fund-lifecycle hash covering account, asset,
token ID, maximum funding/holding, maximum stranded amount, residual
recipient, expected post-operation/final balances, release route, and
simulation evidence.

Canonical lifecycle asset encodings are: zero address/token ID for native;
EntryPoint address/token ID zero for deposits; token address/token ID zero for
ERC-20; and token address plus exact identifier for ERC-721/ERC-1155.
Non-asset actions use zero asset, token ID, balance, and exposure fields while
still committing a nonzero lifecycle digest asserting no asset effect.

### Hashes

```text
coreHeaderHash =
  keccak256(abi.encode(CORE_HEADER_TYPEHASH, ordered core header fields))

intentCoreHash =
  keccak256(abi.encode(ACTION_SPECIFIC_TYPEHASH, coreHeaderHash, action payload))

runtimeAuthorizationDigest =
  Runtime authorization over the exact intentCoreHash and local evidence chain

authorizedIntentHash =
  keccak256(abi.encode(
    AUTHORIZED_INTENT_TYPEHASH,
    intentCoreHash,
    runtimeAuthorizationDigest
  ))

authorizationStructHash =
  keccak256(abi.encode(
    AUTHORIZATION_TYPEHASH,
    authorizedIntentHash,
    userOpHash,
    activeValidator,
    validatorKeyIdBinding,
    validatorEpoch,
    recoveryEpoch
  ))

validatorDigest =
  keccak256(0x1901 || domainSeparator || authorizationStructHash)

recoveryAuthorizationStructHash =
  keccak256(abi.encode(
    RECOVERY_AUTHORIZATION_TYPEHASH,
    authorizedIntentHash,
    userOpHash,
    recoveryConfigHash,
    recoveryEpoch,
    factorBitmap
  ))

recoveryFactorDigest =
  keccak256(0x1901 || domainSeparator || recoveryAuthorizationStructHash)
```

This ordering avoids a circular dependency: Runtime first authorizes the
stable core intent, then the authorized-intent hash binds the resulting
Runtime digest, and only then does the Ethereum adapter construct the
UserOperation for Device Vault signing.

`abi.encodePacked` is prohibited. The initial local/test validator signs the
raw EIP-712 digest with canonical low-s secp256k1 ECDSA. No personal-sign
prefix is added. Device Vault exposes only the PhilCore V2 signing purpose; it
does not expose generic typed-data, message, or transaction signing.

The full ERC-4337 `userOpHash` binds calldata, nonce, gas, fees, init code,
paymaster data, EntryPoint, account, and chain. V2 additionally recomputes the
core intent and authorized-intent wrapper from calldata and binds both
explicitly.

### Purpose Values

Purpose is not an application string. It is the keccak256 hash of one exact
ASCII constant:

```text
PHILCORE_V2_PURPOSE_CONFIRM_ACTION
PHILCORE_V2_PURPOSE_TRANSFER_ASSET
PHILCORE_V2_PURPOSE_RELEASE_RESIDUAL
PHILCORE_V2_PURPOSE_MIGRATE_ASSET
PHILCORE_V2_PURPOSE_WITHDRAW_DEPOSIT
PHILCORE_V2_PURPOSE_ROTATE_VALIDATOR
PHILCORE_V2_PURPOSE_REQUEST_RECOVERY
PHILCORE_V2_PURPOSE_CANCEL_RECOVERY
PHILCORE_V2_PURPOSE_ROTATE_RECOVERY_CONFIG
PHILCORE_V2_PURPOSE_CANCEL_RECOVERY_CONFIG_ROTATION
```

Every action type has an explicit allowed-purpose set. A syntactically valid
but disallowed action/purpose combination fails.

Recovery cancellation using the validator plus one factor has its own
combined-cancellation type hash binding both current epochs, the validator,
recovery configuration hash, factor bitmap, authorized intent, and
UserOperation hash. A signature from one authorization kind cannot be parsed
as another kind.

Recovery-factor rotation uses another distinct authorization type binding the
current validator/epoch, current and proposed recovery configuration/epochs,
authorized intent, full UserOperation hash, and the two-factor bitmap. Its
envelope contains the validator signature plus exactly two current-factor
signatures.

### Fee Bound

With paymasters disabled:

```text
maximumUserOperationGas =
  verificationGasLimit + callGasLimit + preVerificationGas

feeUpperBoundWei =
  maximumUserOperationGas * maxFeePerGas
```

The account requires `feeUpperBoundWei <= maxTotalFeeWei` from the intent core,
and Runtime applies its own policy ceiling. All arithmetic is integer wei.

### Action Identifiers And Replay

Runtime generates a random nonzero `actionId` for audit correlation. It is not
derived from identity secrets and is not stored in an on-chain consumed-ID
mapping.

Replay protection comes from:

- EntryPoint keyed nonce and exact sequence;
- action-specific type and purpose;
- account, chain, and EntryPoint domain;
- validator and recovery epochs;
- validity window;
- one-time Runtime proof, approval, presence, and signing authority.

Epoch changes invalidate unused old-epoch signatures even when their nonce was
not consumed.

## Authorization Flow

```text
application requests a non-authoritative action
  -> Runtime resolves exactly one typed intent core and intentCoreHash
  -> policy and capability checks
  -> proof, exact presentation, approval, and presence bind intentCoreHash
  -> Runtime authorization digest and authorizedIntentHash
  -> Ethereum adapter constructs exact PackedUserOperation
  -> Device Vault signs the V2 authorization digest
  -> account recomputes intent and authorization hashes
  -> EntryPoint validates nonce and time range
  -> account performs one typed action
  -> event, receipt, balance, nonce, and authority reconciliation
```

Applications never supply executable account calldata and never receive
Runtime, proof, validator, or adapter authority.

## Capability Decisions

### Native ETH

The account accepts ETH through `receive()`.

A native transfer binds recipient and exact amount. Recipient cannot be zero
or the account itself, amount must be nonzero, and the external call carries
empty calldata. Contract recipients are allowed only after exact simulation
and user presentation.

Residual release is the same native-transfer action with a distinct
`RELEASE_RESIDUAL` purpose. It has no privileged caller or recovery shortcut.

### ERC-20

V2.0 supports transfer only. It does not support approve, permit, allowance
increase, or allowance decrease.

For accepted ERC-20 contracts, execution requires:

- nonzero token, recipient, and amount;
- recipient different from the account;
- successful canonical or empty return data;
- exact account-balance decrease;
- exact recipient-balance increase.

Fee-on-transfer, rebasing-during-call, malformed-return, and otherwise
nonconforming tokens fail. Token acceptance remains a Runtime policy decision.

### ERC-721 And ERC-1155

V2.0 supports safe transfers only. Token, recipient, identifier, amount, and
receiver-data hash are intent-bound. Receiver callback behavior must be
simulated.

The account implements receiver interfaces so assets can be delivered safely,
but receiver functions create no execution authority.

### EntryPoint Deposit

Deposit withdrawal is an ordinary value-bearing action on nonce key 0. It
binds the canonical EntryPoint, exact recipient and amount, fund-lifecycle
digest, fee limit, and separate approval.

### Contract Calls

V2.0 has no generic execution, contract-call, adapter, or allowlist selector.
This is deliberate:

- a generic exact call still gives a compromised validator the entire EVM
  call surface;
- a mutable allowlist creates administrator and configuration risk;
- an adapter registry adds code-substitution and schema-verification risk;
- dormant extensibility expands the initial audit surface.

A future adapter-capable account is a new version, not a V2.0 configuration
switch.

## Validator Lifecycle

V2.0 has exactly one active execution validator for local/test use.

### Creation

- generated randomly inside Device Vault;
- not derived from the identity root or identity secrets;
- nonzero address and key-ID binding;
- validator epoch starts at `1`;
- validator cannot equal any recovery factor;
- local Device Vault record remains inactive for account use until derivation
  and deployment state are verified.

### Normal Rotation

Rotation uses nonce key `1`, requires the current validator, is blocked during
active recovery, transfers no value, and sets:

```text
proposedValidatorEpoch == currentValidatorEpoch + 1
```

The previous Device Vault key remains active until the receipt and account
state prove rotation. Then the new key becomes active and the old key is
revoked or archived.

V2 never enters a zero-validator state.

### Compromise Or Failure

A lost, unavailable, or compromised validator uses threshold recovery. The
old key is not treated as revoked merely because local metadata changed.
On-chain recovery completion must be verified first.

One ECDSA validator is acceptable only for the local/test implementation.
Meaningful production assets require a separately accepted proof-backed,
threshold, or formally reviewed validator composition.

## Recovery Lifecycle

### Factors

V2.0 fixes:

- three secp256k1 recovery factors;
- threshold two;
- strictly increasing unique nonzero addresses;
- no factor equal to the execution validator;
- no factor derived from identity secrets or the execution key.

Recommended custody roles are a secondary PhilCore device, a hardware-held
recovery key, and an offline encrypted recovery credential. Account 1 and
Account 2 are prohibited by deployment policy.

Independent custody cannot be proven fully on-chain and remains an operational
security gate.

### Recovery Request

A request is an EntryPoint UserOperation on nonce key `2` and requires two
valid current-factor signatures over the exact request. It binds:

- account, chain, EntryPoint, owner commitment;
- current validator, validator key binding, and epoch;
- exact proposed validator, proposed key binding, and next epoch;
- current recovery configuration hash and epoch;
- recovery nonce sequence;
- random request salt;
- request submission validity.

Successful initiation freezes nonce keys `0` and `1` immediately. It transfers
no value and makes no external call.

Only one pending recovery or recovery-configuration rotation may exist.

### Delay, Cancellation, And Expiry

- delay: 172800 seconds (48 hours);
- pending request expiry: 604800 seconds (7 days) after request;
- completion before delay or after expiry fails.

Cancellation is a key-2 UserOperation and requires either:

- two current recovery factors; or
- the current validator plus one current recovery factor.

The validator alone cannot cancel. This prevents a single compromised
validator from indefinitely blocking legitimate recovery while still allowing
the legitimate validator and one independent factor to challenge a takeover.

Cancellation consumes the pending request, unfreezes the account, transfers
no value, and emits exact audit evidence.

Cancellation remains available while the request is active, including after
expiry. In addition, after expiry anyone may call the exact
`expireRecovery(requestId)` cleanup. Expiry cleanup clears the request and
unfreezes the account without installing the proposed validator. This prevents
an expired request from permanently freezing the account.

### Completion

After the delay and before expiry, anyone may call
`completeRecovery(requestId)`. Permissionless completion is safe because the
threshold-authorized request already fixes every result.

Completion:

1. verifies the exact active request and time window;
2. clears pending state before any later observable state;
3. installs the exact proposed validator and key binding;
4. increments validator epoch exactly once;
5. increments recovery epoch exactly once;
6. unfreezes the account;
7. emits request, old/new validator, and epoch evidence;
8. makes no external call and transfers no value.

Any asset movement after recovery requires a new ordinary intent, proof,
approval, presence, Device Vault signature, nonce, and public approval.

### Recovery-Factor Rotation

Factor rotation requires the current validator plus two current recovery
factors. It uses key `2`, the same delay and expiry, and is mutually exclusive
with account recovery.

Ordinary actions remain available while factor rotation is pending because
the execution validator is not being replaced. Normal validator rotation is
blocked until the pending factor rotation completes, is cancelled, or expires,
so the authorizing validator epoch cannot change underneath the request.
Completion is permissionless, installs exactly three sorted factors, and
increments recovery epoch once. Expired factor rotations also have a
permissionless exact-request cleanup path.

## Nonce Model

EntryPoint v0.7 composes:

```text
uint256 nonce = (uint256(uint192 key) << 64) | uint64 sequence
```

Namespaces:

- key `0`: confirmation, native/token/NFT transfers, deposit withdrawal;
- key `1`: normal validator maintenance;
- key `2`: recovery and recovery-factor maintenance.

Every selector has exactly one permitted key. Runtime reads the exact
EntryPoint sequence immediately before preparation and again before any future
submission approval.

An active recovery freezes keys `0` and `1`. Key `2` remains available only
for cancellation. Recovery completion is the narrowly bounded permissionless
state transition described above.

## Storage And Upgrade Policy

V2.0 is not a proxy and has no upgrade key.

Immutable state:

- EntryPoint;
- deployment chain ID;
- owner commitment;
- deploying factory binding;
- account version and security-model IDs;
- confirmation target;
- recovery delay and expiry.

Mutable state, in declared logical order:

1. active validator, validator epoch, frozen flag, execution lock;
2. validator key-ID binding;
3. three recovery factor addresses;
4. recovery configuration hash and epoch;
5. pending recovery ID, proposed validator/key binding, source/proposed
   epochs, timestamps, evidence hash, and active flag;
6. pending recovery-config rotation ID, proposed configuration/factors,
   epochs, timestamps, and active flag.

V2.0 stores no arbitrary capability mapping, allowance policy, session key,
paymaster setting, consumed action-ID mapping, or implementation address.
Reserved fields must remain zero.

Exact compiler storage layout becomes a reviewed artifact in the later
implementation phase. Any source change that alters layout, creation code, or
factory constructor binding creates a new artifact and address.

## Migration

Migration is identity and chain-adapter version migration, not proxy upgrade.

```text
review new account/factory
  -> derive new address under same owner commitment
  -> test complete fund lifecycle
  -> deploy and verify new infrastructure in a separate phase
  -> use fresh typed actions to move every known asset/deposit
  -> verify old and new balances
  -> update canonical chain-adapter record
```

The migration manifest enumerates native balance, EntryPoint deposit, ERC-20,
ERC-721, and ERC-1155 holdings. The old account should reach zero unless exact
dust is pre-approved.

V1 cannot perform asset migration. V2 does not create a route to the O.27
prefund.

## Fund Lifecycle

No address may be funded until native, deposit, token, and NFT release routes
have passed the canonical release and lifecycle guards. Every proposal records
the exact maximum stranded amount, expected residual, residual recipient, and
expected final state.

Local lifecycle simulation is mandatory. Fork simulation is mandatory when
available; otherwise the repository records a technical unavailability reason.
Funding, intended execution, and residual release always have separate exact
approval boundaries.

## Implementation Acceptance

Before any deployment phase, a future implementation must pass:

- independent EIP-712 test vectors;
- action-specific success and malformed-calldata tests;
- every domain, nonce, epoch, expiry, purpose, fee, recipient, amount, token,
  token ID, and data-hash mutation;
- validator rotation and old-epoch invalidation;
- every 2-of-3 recovery permutation, freeze, delay, cancellation, expiry,
  completion, and replay case;
- recovery-factor rotation tests;
- malicious token return, balance, callback, and reentrancy fixtures;
- EntryPoint deposit and complete fund-lifecycle tests;
- CREATE2/source/artifact binding;
- fuzzed storage and state-machine invariants;
- static analysis and external audit.

## Remaining Production Risks

O.30 resolves the V2.0 implementation shape but does not approve meaningful
assets. Remaining production decisions include the proof-backed or threshold
execution-validator composition, recovery ceremony operations, nonstandard
token acceptance, trusted presentation hardening, and public adapter-version
publication.

## Stop Boundary

No Solidity, factory, deployable bytecode, UserOperation, proof, Runtime
authorization, approval, user presence, Device Vault signature, funding, live
contract call, or public mutation was created in O.30.
