# O.37.4 Recovery Configuration Rotation Specification

Status: `COMPLETE_LOCAL_SECURITY_INTERFACE_FREEZE`.

This specification completes transport for changing one recovery factor. It
preserves the O.37.1 exact 2-of-3 model and delayed lifecycle.

## Request Authority

`requestRecoveryConfigRotation`, O.32 action type `10`, requires:

```text
current execution validator
  plus
exactly two distinct current recovery factors
```

The validator is never one of the two factors. Its O.36.1 envelope and the
O.37.1 two-factor envelope arrive inside the O.37.4 combined authority
envelope. A validator-only, recovery-only, single-factor, duplicate-factor,
or three-factor request fails.

## Factor Selection And Evidence

Only these bitmaps are valid:

- `3` (`0b011`): primary device plus hardware security key;
- `5` (`0b101`): primary device plus independent recovery factor;
- `6` (`0b110`): hardware security key plus independent recovery factor.

The first and second witnesses are ordered by ascending role ID. Each witness
contains its complete public descriptor and verification material. The
account recomputes its factor commitment, matches it to the selected context
slot and current stored role commitment, and verifies the signature over the
recovery digest. Bitmap order, evidence order, and descriptor roles must all
agree.

## Proposal And Epoch Rules

A request rotates exactly one role. Runtime validates the proposed full
descriptor before authority is produced, including registration or key
derivation, public point, RP/origin policy, attestation/attachment/backup
policy, custody-domain independence, credential uniqueness, and generation
monotonicity.

The authorized intent binds all proposed factor commitments. The account:

1. requires current validator and recovery epochs;
2. requires proposed recovery epoch to equal current recovery epoch plus one;
3. recomputes the version-2 proposed configuration hash at threshold `2`;
4. requires exactly one role commitment to change;
5. requires the changed descriptor generation to increase and unchanged
   roles to remain exact;
6. records one complete pending request with its request ID, proposal,
   executable time, and expiry.

The request ID is the exact authorized-intent hash. Evidence cannot choose
the delay (`172800` seconds) or expiry (`604800` seconds).

## Cancellation, Completion, And Expiry

`cancelRecoveryConfigRotation`, action type `11`, requires a fresh direct
O.37.1 exact-2-of-3 recovery envelope bound to the exact stored request ID and
proposal. The current validator is not required for cancellation and cannot
substitute for a factor.

Completion and expiry are permissionless transitions over exact pending
state and accept only the stored request ID. Completion is allowed only after
the delay and before expiry; it installs the committed role set and advances
the recovery epoch exactly once. Expiry is allowed only after the fixed
window. Neither path can alter the proposal, transfer assets, or make an
arbitrary call.

While the lifecycle is pending, the O.36.1/O.37.1 recovery freezes remain in
force. A stale epoch, replayed request, expired request, mismatched pending
ID, altered commitment, or alternate configuration hash fails.

## Privacy Boundary

The chain receives only public descriptors, commitments, public verification
material, and one-time evidence needed for verification. Runtime retains raw
credential IDs, private keys, biometrics, attestation trust material, proof
witnesses, presence records, and local approval records. No O.37.4 fixture is
a credential or production authority.
