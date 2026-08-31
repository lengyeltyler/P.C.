# O.36.1 Recovery And Cancellation Semantics

Status: `FROZEN_WITH_O37_1_EVIDENCE_CORRECTION`.

O.37.1 preserves every authority, timing, state-transition, and no-value rule
in this document. Descriptor/configuration version `2` and recovery evidence
version `2` now supply the complete membership data that O.36.1 omitted.

This specification resolves the O.31 versus O.32/O.33 cancellation mismatch.
The selected rule is deliberately uniform:

> Every recovery request and every recovery cancellation requires any exact
> two of the three current recovery-factor roles.

The ordinary execution validator never counts as a recovery factor.

## Final Authority Matrix

| Action | Authority | Lane | External/value effect |
| --- | --- | ---: | --- |
| request validator recovery | exact 2-of-3 current factors | `2` | none |
| cancel validator recovery | exact 2-of-3 current factors | `2` | none |
| complete validator recovery | permissionless exact stored request after delay | none | none |
| expire validator recovery | permissionless exact stored request after expiry | none | none |
| request recovery-config rotation | current validator plus exact 2-of-3 current factors | `2` | none |
| cancel recovery-config rotation | exact 2-of-3 current factors | `2` | none |
| complete recovery-config rotation | permissionless exact stored request after delay | none | none |
| expire recovery-config rotation | permissionless exact stored request after expiry | none | none |

No validator-only or validator-plus-one-factor cancellation exists. The O.32
`PhilCoreV2CombinedCancellation` type remains a retired compatibility type for
negative-vector recognition only. O.37 must not expose a decoder or acceptance
path for it.

## Rationale

### Compromised validator

A compromised daily validator cannot request, cancel, complete, or alter
recovery. Combining it with one recovery factor still does not meet threshold.
This prevents two credentials in a potentially correlated primary-device
domain from controlling recovery.

### One compromised factor

One factor cannot request or cancel recovery. It cannot rotate factors or
move assets. A valid request still requires another independent domain.

### Recovery liveness

Loss of any one factor leaves two roles, which can request or cancel. Once a
valid request matures, anyone can complete only the validator already stored
by that request. Relayer or validator availability is not required for
completion.

If two factor domains are compromised, the attacker controls the canonical
threshold. The challenge delay provides detection time but cannot restore
security without two honest roles. This is an explicit residual risk, not a
hidden administrator problem.

Validator-plus-one cancellation was rejected because it adds a second
authority composition, makes a compromised validator materially stronger,
and is not represented by the accepted O.32 strict threshold evidence.

## Validator Recovery Lifecycle

States:

```text
NORMAL
  -> RECOVERY_ACTIVE
  -> RECOVERY_COMPLETED
  -> NORMAL operational state
```

or:

```text
NORMAL
  -> RECOVERY_ACTIVE
  -> RECOVERY_CANCELLED
  -> NORMAL operational state
```

Expiry also returns to normal operational state. Completed and cancelled are
audit outcomes; they do not create permanent authority states.

Request:

1. accepts only nonce lane `2` and exact recovery-request intent;
2. verifies exact current 2-of-3 authority;
3. requires proposed validator epoch `current + 1`;
4. records request ID, proposed validator/key binding/commitment, source
   epochs, factor bitmap, evidence commitment, and timing;
5. enters active recovery and immediately freezes lanes `0` and `1`;
6. emits commitment-only evidence;
7. makes no external call and moves no value.

Cancellation:

1. accepts only the exact active request ID and recovery-cancel intent;
2. verifies exact current 2-of-3 authority under the source configuration and
   epoch;
3. clears pending state and unfreezes;
4. changes no validator or recovery epoch;
5. makes no external call and moves no value.

Completion:

1. is callable by anyone after the delay and before expiry;
2. accepts only the exact active stored request ID;
3. installs only the stored proposed validator and key binding;
4. increments validator and recovery epochs exactly once;
5. clears pending state before returning to normal;
6. makes no external call and moves no value.

Expiry:

1. is callable by anyone only after expiry;
2. clears the exact pending request and unfreezes;
3. changes no validator or epoch;
4. makes no external call and moves no value.

## Recovery-Configuration Lifecycle

A configuration-rotation request requires the current execution validator
plus exact 2-of-3 current factors. The validator cannot double-count as the
primary-device role. All authorities bind the exact proposed ordered
configuration and next recovery epoch.

The request is delayed and mutually exclusive with validator recovery.
Maintenance lane `1` is frozen; ordinary lane `0` remains available because
the active execution validator has not changed.

Cancellation requires exact 2-of-3 current factors. Completion installs only
the stored three-role configuration and increments recovery epoch exactly
once. Expiry changes neither factors nor epoch. No path calls an asset or
moves value.

## Replay, Epoch, And Timing

- Request and cancellation use EntryPoint nonce lane `2`.
- Each intent binds unique action ID, exact nonce sequence, both epochs,
  validity, request ID, account, chain, EntryPoint, and full UserOperation
  hash.
- Current factor commitments and configuration hash are part of the recovery
  digest.
- Recovery authority is invalid after recovery epoch changes.
- Completion and expiry consume exact pending state and are idempotently
  unavailable afterward.
- Delay is exactly `172800` seconds.
- Request expiry is exactly `604800` seconds after request time.
- A completion at `expiresAt` is rejected; expiry cleanup is allowed at or
  after `expiresAt`.

## Security Invariants

1. One factor never changes validator or factor state.
2. The execution validator never counts toward recovery threshold.
3. Recovery authority never authorizes ordinary or maintenance execution.
4. Recovery paths have no recipient, amount, asset, target, or arbitrary data.
5. Active validator recovery freezes ordinary and maintenance lanes.
6. Completion installs only data fixed by the threshold-authorized request.
7. Cancellation and expiry never install proposed authority.
8. Epochs never decrease or skip.
9. Old factor evidence cannot become valid after a configuration change.
10. Factory, deployer, relayer, EntryPoint caller, and disposable wallets have
    no recovery privilege.

## Required Negative Tests

- all three one-factor bitmaps;
- zero, three-factor, duplicate-role, reordered, and unsupported bitmaps;
- validator only and validator plus each single factor;
- wrong account, chain, EntryPoint, request ID, nonce, action, purpose, epoch,
  configuration, proposed validator, or validity;
- cancel while normal, request while active, complete before delay, complete
  at/after expiry, expire before expiry, and replay after every terminal
  outcome;
- recovery evidence used for native/token/NFT/deposit execution;
- recovery/config paths containing or producing any external call or value
  movement.
